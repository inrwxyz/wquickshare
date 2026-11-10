use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use p256::ecdh::diffie_hellman;
use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

// Hardware (AES-NI) AES-256-CBC. Much faster than the old software `libaes`.
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
use prost::Message;
use rand::RngCore;

use crate::protos::securegcm::{
    ukey2_client_init, ukey2_message, DeviceToDeviceMessage, GcmMetadata, Ukey2ClientFinished,
    Ukey2ClientInit, Ukey2HandshakeCipher, Ukey2Message, Ukey2ServerInit, Ukey2Alert,
};
use crate::protos::securemessage::{
    EncScheme, GenericPublicKey, Header, HeaderAndBody, PublicKeyType,
    SecureMessage, SigScheme, EcP256PublicKey,
};

type HmacSha256 = Hmac<Sha256>;

const D2D_SALT: [u8; 32] = [
    0x82, 0xAA, 0x55, 0xA0, 0xD3, 0x97, 0xF8, 0x83, 0x46, 0xCA, 0x1C, 0xEE, 0x8D, 0x39, 0x09, 0xB9,
    0x5F, 0x13, 0xFA, 0x7D, 0xEB, 0x1D, 0x4A, 0xB3, 0x83, 0x76, 0xB8, 0x25, 0x6D, 0xA8, 0x55, 0x10,
];

pub struct Ukey2HandshakeSession {
    secret_key: SecretKey,
    public_key: PublicKey,
    pub server_init_raw: Vec<u8>,
}

impl Ukey2HandshakeSession {
    pub fn new() -> Self {
        let secret_key = SecretKey::random(&mut rand::rngs::OsRng);
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
            server_init_raw: Vec::new(),
        }
    }

    /// Processes client_init message (Frame 2) and builds server_init message
    pub fn process_client_init(
        &mut self,
        client_init_msg_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let msg = Ukey2Message::decode(client_init_msg_bytes)?;
        let client_init_data = msg.message_data.ok_or("Missing message_data in client_init")?;
        let client_init = Ukey2ClientInit::decode(&client_init_data[..])?;

        if client_init.version.unwrap_or(0) != 1 {
            return Err("Unsupported UKEY2 version".into());
        }

        // Build generic public key for server with two's complement coordinates
        let encoded_point = self.public_key.to_encoded_point(false);
        let x_raw = encoded_point.x().ok_or("Missing x coordinate")?;
        let y_raw = encoded_point.y().ok_or("Missing y coordinate")?;

        let x = encode_twos_complement(x_raw.as_ref());
        let y = encode_twos_complement(y_raw.as_ref());

        let generic_pub = GenericPublicKey {
            r#type: PublicKeyType::EcP256 as i32,
            ec_p256_public_key: Some(EcP256PublicKey {
                x,
                y,
            }),
            ..Default::default()
        };

        let mut server_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut server_random);

        let server_init = Ukey2ServerInit {
            version: Some(1),
            random: Some(server_random.to_vec()),
            handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512 as i32),
            public_key: Some(generic_pub.encode_to_vec()),
        };

        let server_init_msg = Ukey2Message {
            message_type: Some(ukey2_message::Type::ServerInit as i32),
            message_data: Some(server_init.encode_to_vec()),
        };

        let server_init_raw = server_init_msg.encode_to_vec();
        self.server_init_raw = server_init_raw.clone();

        Ok(server_init_raw)
    }

    /// Processes client_finish message (Frame 3) and derives secure channel keys
    pub fn process_client_finish(
        self,
        client_finish_msg_bytes: &[u8],
        client_init_msg_bytes: &[u8],
    ) -> Result<SecureSessionChannel, Box<dyn std::error::Error + Send + Sync>> {
        let msg = match Ukey2Message::decode(client_finish_msg_bytes) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[Quick Share] Failed to decode Ukey2Message from {} bytes: {:02x?}", client_finish_msg_bytes.len(), &client_finish_msg_bytes[..client_finish_msg_bytes.len().min(64)]);
                return Err(Box::new(e));
            }
        };

        if msg.message_type == Some(ukey2_message::Type::Alert as i32) {
            if let Some(data) = msg.message_data {
                if let Ok(alert) = Ukey2Alert::decode(&data[..]) {
                    eprintln!("[Quick Share] Phone sent UKEY2 Alert: type={:?}, error={:?}", alert.r#type, alert.error_message);
                    return Err(format!("UKEY2 Alert: {:?}", alert.r#type).into());
                }
            }
            return Err("UKEY2 Alert received from phone".into());
        }

        let client_finish_data = msg.message_data.ok_or("Missing client_finish data")?;
        let client_finish = match Ukey2ClientFinished::decode(&client_finish_data[..]) {
            Ok(cf) => cf,
            Err(e) => {
                eprintln!("[Quick Share] Failed to decode Ukey2ClientFinished from {} bytes: {:02x?}", client_finish_data.len(), &client_finish_data[..client_finish_data.len().min(64)]);
                return Err(Box::new(e));
            }
        };

        let peer_pub_bytes = client_finish.public_key.ok_or("Missing peer public key in client_finish")?;

        let (x_bytes, y_bytes) = if peer_pub_bytes.len() == 65 && peer_pub_bytes[0] == 0x04 {
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            x.copy_from_slice(&peer_pub_bytes[1..33]);
            y.copy_from_slice(&peer_pub_bytes[33..65]);
            (x, y)
        } else if let Ok(peer_generic) = GenericPublicKey::decode(&peer_pub_bytes[..]) {
            if let Some(ec_pub) = peer_generic.ec_p256_public_key {
                (normalize_coordinate(&ec_pub.x), normalize_coordinate(&ec_pub.y))
            } else {
                return Err("GenericPublicKey missing ec_p256_public_key".into());
            }
        } else if let Ok(ec_pub) = EcP256PublicKey::decode(&peer_pub_bytes[..]) {
            (normalize_coordinate(&ec_pub.x), normalize_coordinate(&ec_pub.y))
        } else {
            return Err(format!("Unable to parse peer public key of len {}", peer_pub_bytes.len()).into());
        };

        let encoded_point = EncodedPoint::from_affine_coordinates(
            (&x_bytes).into(),
            (&y_bytes).into(),
            false,
        );
        let peer_public_key = PublicKey::from_encoded_point(&encoded_point)
            .into_option()
            .ok_or("Invalid peer EC point")?;

        // 1. ECDH Diffie-Hellman secret (DHS)
        let shared_secret = diffie_hellman(self.secret_key.to_nonzero_scalar(), peer_public_key.as_affine());
        let dhs = shared_secret.raw_secret_bytes();

        // 2. UKEY2: derived secret = SHA256(ECDH shared secret), then HKDF-HMAC-SHA256.
        //    (P256_SHA512 only refers to the commitment hash in ClientInit, NOT to the KDF.)
        let derived_secret = Sha256::digest(&dhs[..]);

        let mut ukey_info = Vec::new();
        ukey_info.extend_from_slice(client_init_msg_bytes);
        ukey_info.extend_from_slice(&self.server_init_raw);

        let hkdf_auth = Hkdf::<Sha256>::new(Some(b"UKEY2 v1 auth"), &derived_secret);
        let mut auth_string = [0u8; 32];
        hkdf_auth.expand(&ukey_info, &mut auth_string)
            .map_err(|e| format!("HKDF auth expand error: {:?}", e))?;

        // 4-digit PIN for visual pairing confirmation
        let pin = pin_code_from_auth_key(&auth_string);

        let hkdf_next = Hkdf::<Sha256>::new(Some(b"UKEY2 v1 next"), &derived_secret);
        let mut next_secret = [0u8; 32];
        hkdf_next.expand(&ukey_info, &mut next_secret)
            .map_err(|e| format!("HKDF next expand error: {:?}", e))?;

        // 3. D2D client & server keys using SHA-256
        let hkdf_d2d = Hkdf::<Sha256>::new(Some(&D2D_SALT), &next_secret);
        let mut d2d_client_key = [0u8; 32];
        let mut d2d_server_key = [0u8; 32];
        hkdf_d2d.expand(b"client", &mut d2d_client_key)
            .map_err(|e| format!("HKDF d2d client expand error: {:?}", e))?;
        hkdf_d2d.expand(b"server", &mut d2d_server_key)
            .map_err(|e| format!("HKDF d2d server expand error: {:?}", e))?;

        // 4. SecureMessage salt = SHA256("SecureMessage")
        let mut smsg_hasher = Sha256::new();
        smsg_hasher.update(b"SecureMessage");
        let smsg_salt = smsg_hasher.finalize();

        // Server decrypts client messages with clientKey & verifies with clientHmacKey
        let hkdf_client = Hkdf::<Sha256>::new(Some(&smsg_salt), &d2d_client_key);
        let mut client_enc_key = [0u8; 32];
        let mut client_hmac_key = [0u8; 32];
        hkdf_client.expand(b"ENC:2", &mut client_enc_key)
            .map_err(|e| format!("HKDF client enc expand error: {:?}", e))?;
        hkdf_client.expand(b"SIG:1", &mut client_hmac_key)
            .map_err(|e| format!("HKDF client hmac expand error: {:?}", e))?;

        // Server encrypts responses with serverKey & signs with serverHmacKey
        let hkdf_server = Hkdf::<Sha256>::new(Some(&smsg_salt), &d2d_server_key);
        let mut server_enc_key = [0u8; 32];
        let mut server_hmac_key = [0u8; 32];
        hkdf_server.expand(b"ENC:2", &mut server_enc_key)
            .map_err(|e| format!("HKDF server enc expand error: {:?}", e))?;
        hkdf_server.expand(b"SIG:1", &mut server_hmac_key)
            .map_err(|e| format!("HKDF server hmac expand error: {:?}", e))?;

        Ok(SecureSessionChannel {
            pin,
            decrypt_key: client_enc_key,
            recv_hmac_key: client_hmac_key,
            encrypt_key: server_enc_key,
            send_hmac_key: server_hmac_key,
            in_seq: 0,
            out_seq: 0,
        })
    }
}

pub struct SecureSessionChannel {
    pub pin: String,
    decrypt_key: [u8; 32],
    recv_hmac_key: [u8; 32],
    encrypt_key: [u8; 32],
    send_hmac_key: [u8; 32],
    in_seq: i32,
    out_seq: i32,
}

impl SecureSessionChannel {
    /// Decrypts an inbound SecureMessage and extracts the inner OfflineFrame plaintext
    pub fn decrypt_secure_message(
        &mut self,
        raw_secure_msg: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let smsg = SecureMessage::decode(raw_secure_msg)?;
        let header_and_body_raw = smsg.header_and_body;
        let signature = smsg.signature;

        // Verify signature (constant-time) BEFORE touching the ciphertext
        let mut mac_recv = HmacSha256::new_from_slice(&self.recv_hmac_key)?;
        mac_recv.update(&header_and_body_raw);
        mac_recv
            .verify_slice(&signature)
            .map_err(|_| "SecureMessage HMAC mismatch (key derivation or direction wrong)")?;

        let hb = HeaderAndBody::decode(&header_and_body_raw[..])?;
        let iv = hb.header.iv.ok_or("Missing IV in Header")?;
        if iv.len() != 16 || hb.body.is_empty() || hb.body.len() % 16 != 0 {
            return Err("Invalid IV or ciphertext length".into());
        }

        let plaintext = Aes256CbcDec::new_from_slices(&self.decrypt_key, &iv)
            .map_err(|_| "Bad AES key/IV length")?
            .decrypt_padded_vec_mut::<Pkcs7>(&hb.body)
            .map_err(|_| "AES-CBC bad padding")?;
        let d2d_msg = DeviceToDeviceMessage::decode(&plaintext[..])?;

        let expected = self.in_seq + 1;
        if d2d_msg.sequence_number != Some(expected) {
            eprintln!("[Quick Share] Warning: unexpected seq {:?}, expected {}", d2d_msg.sequence_number, expected);
        }
        self.in_seq = d2d_msg.sequence_number.unwrap_or(expected);

        d2d_msg.message.ok_or_else(|| "Missing message in DeviceToDeviceMessage".into())
    }

    /// Encrypts an outbound OfflineFrame into a signed SecureMessage
    pub fn encrypt_secure_message(
        &mut self,
        offline_frame_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        self.out_seq += 1;
        let d2d_msg = DeviceToDeviceMessage {
            sequence_number: Some(self.out_seq),
            message: Some(offline_frame_bytes.to_vec()),
        };
        let d2d_bytes = d2d_msg.encode_to_vec();

        let mut iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut iv);

        // AES-256-CBC Encrypt with PKCS#7 padding via libaes
        let ciphertext = Aes256CbcEnc::new_from_slices(&self.encrypt_key, &iv)
            .map_err(|_| "Bad AES key/IV length")?
            .encrypt_padded_vec_mut::<Pkcs7>(&d2d_bytes);

        let metadata = GcmMetadata {
            r#type: 13, // GcmMetadata.Type.DEVICE_TO_DEVICE_MESSAGE = 13 (1 would be ENROLLMENT)
            version: Some(1),
        };

        let header = Header {
            signature_scheme: SigScheme::HmacSha256 as i32,
            encryption_scheme: EncScheme::Aes256Cbc as i32,
            iv: Some(iv.to_vec()),
            public_metadata: Some(metadata.encode_to_vec()),
            ..Default::default()
        };

        let hb = HeaderAndBody {
            header,
            body: ciphertext,
        };
        let hb_bytes = hb.encode_to_vec();

        // HMAC-SHA256 signature
        let mut mac = HmacSha256::new_from_slice(&self.send_hmac_key)?;
        mac.update(&hb_bytes);
        let signature = mac.finalize().into_bytes().to_vec();

        let smsg = SecureMessage {
            header_and_body: hb_bytes,
            signature,
        };

        Ok(smsg.encode_to_vec())
    }
}

pub struct Ukey2ClientSession {
    secret_key: SecretKey,
    public_key: PublicKey,
    client_init_raw: Vec<u8>,
    client_finish_raw: Vec<u8>,
}

impl Ukey2ClientSession {
    pub fn new() -> Self {
        let secret_key = SecretKey::random(&mut rand::rngs::OsRng);
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
            client_init_raw: Vec::new(),
            client_finish_raw: Vec::new(),
        }
    }

    pub fn build_client_init(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let encoded_point = self.public_key.to_encoded_point(false);
        let x_raw = encoded_point.x().ok_or("Missing x coordinate")?;
        let y_raw = encoded_point.y().ok_or("Missing y coordinate")?;

        let x = encode_twos_complement(x_raw.as_ref());
        let y = encode_twos_complement(y_raw.as_ref());

        let generic_pub = GenericPublicKey {
            r#type: PublicKeyType::EcP256 as i32,
            ec_p256_public_key: Some(EcP256PublicKey { x, y }),
            ..Default::default()
        };

        let client_finish = Ukey2ClientFinished {
            public_key: Some(generic_pub.encode_to_vec()),
        };
        let client_finish_msg = Ukey2Message {
            message_type: Some(ukey2_message::Type::ClientFinish as i32),
            message_data: Some(client_finish.encode_to_vec()),
        };
        let client_finish_raw = client_finish_msg.encode_to_vec();

        // The commitment in UKEY2 is the SHA-512 hash of the final ClientFinished wire message (including Ukey2Message framing)
        let mut hasher = Sha512::new();
        hasher.update(&client_finish_raw);
        let commitment = hasher.finalize().to_vec();

        self.client_finish_raw = client_finish_raw;

        let mut client_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut client_random);

        let client_init = Ukey2ClientInit {
            version: Some(1),
            random: Some(client_random.to_vec()),
            cipher_commitments: vec![
                ukey2_client_init::CipherCommitment {
                    handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512 as i32),
                    commitment: Some(commitment),
                }
            ],
            next_protocol: Some("AES_256_CBC-HMAC_SHA256".to_string()),
        };

        let client_init_msg = Ukey2Message {
            message_type: Some(ukey2_message::Type::ClientInit as i32),
            message_data: Some(client_init.encode_to_vec()),
        };

        let raw = client_init_msg.encode_to_vec();
        self.client_init_raw = raw.clone();
        Ok(raw)
    }

    pub fn process_server_init(
        &self,
        server_init_msg_bytes: &[u8],
    ) -> Result<(Vec<u8>, SecureSessionChannel), Box<dyn std::error::Error + Send + Sync>> {
        let msg = Ukey2Message::decode(server_init_msg_bytes)?;
        if msg.message_type == Some(ukey2_message::Type::Alert as i32) {
            return Err("UKEY2 Alert received from server".into());
        }

        let server_init_data = msg.message_data.ok_or("Missing server_init data")?;
        let server_init = Ukey2ServerInit::decode(&server_init_data[..])?;
        let peer_pub_bytes = server_init.public_key.ok_or("Missing public key in server_init")?;

        let (x_bytes, y_bytes) = if peer_pub_bytes.len() == 65 && peer_pub_bytes[0] == 0x04 {
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            x.copy_from_slice(&peer_pub_bytes[1..33]);
            y.copy_from_slice(&peer_pub_bytes[33..65]);
            (x, y)
        } else if let Ok(peer_generic) = GenericPublicKey::decode(&peer_pub_bytes[..]) {
            if let Some(ec_pub) = peer_generic.ec_p256_public_key {
                (normalize_coordinate(&ec_pub.x), normalize_coordinate(&ec_pub.y))
            } else {
                return Err("GenericPublicKey missing ec_p256_public_key".into());
            }
        } else if let Ok(ec_pub) = EcP256PublicKey::decode(&peer_pub_bytes[..]) {
            (normalize_coordinate(&ec_pub.x), normalize_coordinate(&ec_pub.y))
        } else {
            return Err(format!("Unable to parse peer public key of len {}", peer_pub_bytes.len()).into());
        };

        let encoded_point = EncodedPoint::from_affine_coordinates(
            (&x_bytes).into(),
            (&y_bytes).into(),
            false,
        );
        let peer_public_key = PublicKey::from_encoded_point(&encoded_point)
            .into_option()
            .ok_or("Invalid peer EC point")?;

        let shared_secret = diffie_hellman(self.secret_key.to_nonzero_scalar(), peer_public_key.as_affine());
        let dhs = shared_secret.raw_secret_bytes();
        let derived_secret = Sha256::digest(&dhs[..]);

        let mut ukey_info = Vec::new();
        ukey_info.extend_from_slice(&self.client_init_raw);
        ukey_info.extend_from_slice(server_init_msg_bytes);

        let hkdf_auth = Hkdf::<Sha256>::new(Some(b"UKEY2 v1 auth"), &derived_secret);
        let mut auth_string = [0u8; 32];
        hkdf_auth.expand(&ukey_info, &mut auth_string)
            .map_err(|e| format!("HKDF auth expand error: {:?}", e))?;

        let pin = pin_code_from_auth_key(&auth_string);

        let hkdf_next = Hkdf::<Sha256>::new(Some(b"UKEY2 v1 next"), &derived_secret);
        let mut next_secret = [0u8; 32];
        hkdf_next.expand(&ukey_info, &mut next_secret)
            .map_err(|e| format!("HKDF next expand error: {:?}", e))?;

        let hkdf_d2d = Hkdf::<Sha256>::new(Some(&D2D_SALT), &next_secret);
        let mut d2d_client_key = [0u8; 32];
        let mut d2d_server_key = [0u8; 32];
        hkdf_d2d.expand(b"client", &mut d2d_client_key)
            .map_err(|e| format!("HKDF d2d client expand error: {:?}", e))?;
        hkdf_d2d.expand(b"server", &mut d2d_server_key)
            .map_err(|e| format!("HKDF d2d server expand error: {:?}", e))?;

        let mut smsg_hasher = Sha256::new();
        smsg_hasher.update(b"SecureMessage");
        let smsg_salt = smsg_hasher.finalize();

        // Note: For client, out_encrypt_key is derived from d2d_client_key, in_decrypt_key is from d2d_server_key
        let hkdf_client = Hkdf::<Sha256>::new(Some(&smsg_salt), &d2d_client_key);
        let mut client_enc_key = [0u8; 32];
        let mut client_hmac_key = [0u8; 32];
        hkdf_client.expand(b"ENC:2", &mut client_enc_key).map_err(|e| format!("{:?}", e))?;
        hkdf_client.expand(b"SIG:1", &mut client_hmac_key).map_err(|e| format!("{:?}", e))?;

        let hkdf_server = Hkdf::<Sha256>::new(Some(&smsg_salt), &d2d_server_key);
        let mut server_enc_key = [0u8; 32];
        let mut server_hmac_key = [0u8; 32];
        hkdf_server.expand(b"ENC:2", &mut server_enc_key).map_err(|e| format!("{:?}", e))?;
        hkdf_server.expand(b"SIG:1", &mut server_hmac_key).map_err(|e| format!("{:?}", e))?;

        let channel = SecureSessionChannel {
            pin,
            decrypt_key: server_enc_key,
            recv_hmac_key: server_hmac_key,
            encrypt_key: client_enc_key,
            send_hmac_key: client_hmac_key,
            in_seq: 0,
            out_seq: 0,
        };

        Ok((self.client_finish_raw.clone(), channel))
    }
}

/// Matches the official Google Nearby Share pin calculation
fn pin_code_from_auth_key(key: &[u8; 32]) -> String {
    let mut hash: i32 = 0;
    let mut multiplier: i32 = 1;
    for &byte in key {
        let b = byte as i8 as i32;
        hash = (hash + b * multiplier) % 9973;
        multiplier = (multiplier * 31) % 9973;
    }
    format!("{:04}", hash.abs())
}

/// Normalizes an EC coordinate slice to exactly 32 bytes (handling leading 0x00 from ASN.1 / BigInt)
fn normalize_coordinate(coord: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    if coord.len() >= 32 {
        out.copy_from_slice(&coord[coord.len() - 32..]);
    } else {
        out[32 - coord.len()..].copy_from_slice(coord);
    }
    out
}

/// Encodes an EC coordinate in big-endian two's complement (prepends 0x00 if MSB >= 0x80)
fn encode_twos_complement(bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(bytes.len() + 1);
    if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
        v.push(0x00);
    }
    v.extend_from_slice(bytes);
    v
}



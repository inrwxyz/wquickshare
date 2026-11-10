use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use prost::Message;

use crate::console::{self, Command};
use crate::crypto::{Ukey2HandshakeSession, SecureSessionChannel};
use crate::protos::connections::{
    self, offline_frame, v1_frame, payload_transfer_frame,
    ConnectionResponseFrame as ConnResp, OfflineFrame, PayloadTransferFrame, V1Frame,
};
use crate::protos::nearby::{
    self, v1_frame as nearby_v1,
    connection_response_frame, paired_key_result_frame,
    ConnectionResponseFrame as NearbyConnResp, PairedKeyEncryptionFrame, PairedKeyResultFrame,
};

struct LastRxSession {
    remote_name: String,
    file_names: Vec<String>,
    timestamp: Instant,
}
static LAST_RX_SESSION: std::sync::Mutex<Option<LastRxSession>> = std::sync::Mutex::new(None);

pub struct QuickShareServer {
    pub port: u16,
    pub downloads_dir: PathBuf,
}

struct ReceivingFile {
    pub name: String,
    pub final_dir: PathBuf,
    pub safe_name: String,
    pub part_path: PathBuf,
    pub size: i64,
    pub file: BufWriter<File>,
    /// absolute offset received so far (includes bytes that were already in the .part file)
    pub received: i64,
    /// bytes that were already on disk when this session started (resume)
    pub base: i64,
    pub started: Instant,
    pub last_print: Instant,
}

enum Ev {
    Consent(bool),
    Timeout,
    Readable,
    Closed,
    KeepAlive,
    Cmd,
}

impl QuickShareServer {
    pub fn new(port: u16, downloads_dir: PathBuf) -> Self {
        Self {
            port,
            downloads_dir,
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.start_with_stop(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))).await
    }

    pub async fn start_with_stop(
        &self,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.port)).await?;
        println!("[Server] Listening for Quick Share on TCP 0.0.0.0:{}", self.port);

        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            match tokio::time::timeout(Duration::from_millis(500), listener.accept()).await {
                Ok(Ok((socket, addr))) => {
                    println!("\n[Server] Inbound connection established from: {}", addr);
                    let dir = self.downloads_dir.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(socket, dir).await {
                            eprintln!("[Server] Connection closed with error: {:?}", e);
                            crate::events::emit(serde_json::json!({
                                "type": "rx_interrupted", "error": format!("{}", e),
                            }));
                        }
                    });
                }
                Ok(Err(e)) => {
                    eprintln!("[Server] Accept error: {:?}", e);
                }
                Err(_) => {
                    // Periodic timeout to re-check stop condition
                }
            }
        }
        println!("[Server] Quick Share server stopped.");
        Ok(())
    }

    async fn handle_connection(
        mut socket: TcpStream,
        downloads_dir: PathBuf,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _ = socket.set_nodelay(true);
        // OS-level TCP keep-alive: phone lock / Wi-Fi power-save e connection more na
        let _ = socket2::SockRef::from(&socket)
            .set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(Duration::from_secs(10)));
        let _ = socket2::SockRef::from(&socket).set_send_buffer_size(512 * 1024);
        let _ = socket2::SockRef::from(&socket).set_recv_buffer_size(1024 * 1024);
        let mut len_buf = [0u8; 4];

        // -------------------------------------------------------------
        // Step 1: Read OfflineFrame (ConnectionRequest)
        // -------------------------------------------------------------
        socket.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut frame_bytes = vec![0u8; len];
        socket.read_exact(&mut frame_bytes).await?;

        let offline_req = OfflineFrame::decode(&frame_bytes[..])?;
        let v1_req = offline_req.v1.ok_or("Missing v1 in ConnectionRequest")?;
        let conn_req = v1_req.connection_request.ok_or("Expected ConnectionRequest frame")?;

        // Phone ja interval chaise (default 5s), amra-o oi interval e nijer KeepAlive pathabo
        let peer_ka_ms = conn_req.keep_alive_interval_millis.unwrap_or(5000);
        let ka_ms: u64 = peer_ka_ms.clamp(1000, 5000) as u64;

        let ep_info = conn_req.endpoint_info.unwrap_or_default();
        let remote_name = extract_device_name(&ep_info);
        println!("[Quick Share] >> Inbound Request from device: \"{}\"", remote_name);
        console::drain(); // forget old key presses / UI clicks
        crate::events::emit(serde_json::json!({ "type": "rx_connected", "device": remote_name }));

        // -------------------------------------------------------------
        // Step 2: Read Ukey2Message (ClientInit) & Send ServerInit
        // -------------------------------------------------------------
        socket.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut client_init_bytes = vec![0u8; len];
        socket.read_exact(&mut client_init_bytes).await?;

        let mut ukey2 = Ukey2HandshakeSession::new();
        let server_init_bytes = ukey2.process_client_init(&client_init_bytes)?;

        // Send ServerInit
        socket.write_all(&(server_init_bytes.len() as u32).to_be_bytes()).await?;
        socket.write_all(&server_init_bytes).await?;
        println!("[Quick Share] Handshake step 1/2: Sent ServerInit");

        // -------------------------------------------------------------
        // Step 3: Read Ukey2Message (ClientFinish) & Derive Keys
        // -------------------------------------------------------------
        socket.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut client_finish_bytes = vec![0u8; len];
        socket.read_exact(&mut client_finish_bytes).await?;

        let mut channel = ukey2.process_client_finish(&client_finish_bytes, &client_init_bytes)?;
        println!("============================================================");
        println!(" [Quick Share] SECURE CHANNEL VERIFIED!");
        println!(" [Quick Share] Device:       {}", remote_name);
        println!(" [Quick Share] Pairing PIN:  {}", channel.pin);
        println!("============================================================");

        // -------------------------------------------------------------
        // Step 4: Exchange UNENCRYPTED ConnectionResponse (Accept)
        // -------------------------------------------------------------
        #[allow(deprecated)]
        let accept_frame = OfflineFrame {
            version: Some(offline_frame::Version::V1 as i32),
            v1: Some(V1Frame {
                r#type: Some(v1_frame::FrameType::ConnectionResponse as i32),
                connection_response: Some(ConnResp {
                    response: Some(connections::connection_response_frame::ResponseStatus::Accept as i32),
                    status: Some(0),
                    os_info: Some(connections::OsInfo {
                        r#type: Some(connections::os_info::OsType::Windows as i32),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let accept_bytes = accept_frame.encode_to_vec();
        socket.write_all(&(accept_bytes.len() as u32).to_be_bytes()).await?;
        socket.write_all(&accept_bytes).await?;
        println!("[Quick Share] Handshake step 3/4: Sent unencrypted Accept frame to phone!");

        // Read unencrypted frames until mutual Accept is confirmed
        loop {
            socket.read_exact(&mut len_buf).await?;
            let flen = u32::from_be_bytes(len_buf) as usize;
            let mut fbytes = vec![0u8; flen];
            socket.read_exact(&mut fbytes).await?;

            if let Ok(frame) = OfflineFrame::decode(&fbytes[..]) {
                if let Some(v1) = frame.v1 {
                    if let Some(resp) = v1.connection_response {
                        println!("[Quick Share] Handshake step 4/4: Phone accepted connection (response: {:?})", resp.response);
                        break;
                    } else if v1.r#type == Some(v1_frame::FrameType::KeepAlive as i32) || v1.keep_alive.is_some() {
                        let ack = OfflineFrame {
                            version: Some(offline_frame::Version::V1 as i32),
                            v1: Some(V1Frame {
                                r#type: Some(v1_frame::FrameType::KeepAlive as i32),
                                keep_alive: Some(connections::KeepAliveFrame {
                                    ack: Some(true),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }),
                        };
                        let ack_b = ack.encode_to_vec();
                        socket.write_all(&(ack_b.len() as u32).to_be_bytes()).await?;
                        socket.write_all(&ack_b).await?;
                    }
                }
            } else {
                eprintln!("[Quick Share] Warning: unable to decode frame during mutual accept phase");
                break;
            }
        }
        println!("[Quick Share] Mutual acceptance complete! Encryption ACTIVATED.");

        // -------------------------------------------------------------
        // Step 5: PairedKey Verification (Now ENCRYPTED)
        // -------------------------------------------------------------
        let mut rand_salt = [0u8; 6];
        let mut rand_data = [0u8; 72];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rand_salt);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rand_data);

        let paired_enc = nearby::Frame {
            version: Some(nearby::frame::Version::V1 as i32),
            v1: Some(nearby::V1Frame {
                r#type: Some(nearby_v1::FrameType::PairedKeyEncryption as i32),
                paired_key_encryption: Some(PairedKeyEncryptionFrame {
                    secret_id_hash: Some(rand_salt.to_vec()),
                    signed_data: Some(rand_data.to_vec()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        send_encrypted_payload_frame(&mut socket, &mut channel, 1001, &paired_enc.encode_to_vec()).await?;
        println!("[Quick Share] Sent encrypted PairedKeyEncryption frame!");

        // NOTE: PairedKeyResult is sent only AFTER the phone's PairedKeyEncryption arrives (see loop below).

        // -------------------------------------------------------------
        // Step 5: Encrypted Message Loop (Transfers & Introduction)
        // -------------------------------------------------------------
        let mut byte_buffers: HashMap<i64, Vec<u8>> = HashMap::new();
        let mut active_files: HashMap<i64, ReceivingFile> = HashMap::new();
        let mut meta_files: Vec<(String, i64, i64, String)> = Vec::new(); // (name, size, payload_id, parent_folder)
        let mut total_batch_bytes: i64 = 0;
        let mut completed_bytes: i64 = 0;
        let mut completed_files: usize = 0;
        let mut awaiting_consent = false;
        let mut consent_deadline = tokio::time::Instant::now();
        let mut next_payload_id: i64 = 2000;
        let mut resumed_attachments: std::collections::HashMap<i64, nearby::AttachmentDetails> = std::collections::HashMap::new();
        let (consent_tx, mut consent_rx) = mpsc::unbounded_channel::<bool>();
        let mut consent_task: Option<tokio::task::JoinHandle<()>> = None;
        let mut paused = false;
        let mut pause_started: Option<Instant> = None;
        let mut cancelled = false;
        let mut cmd_tick = tokio::time::interval(Duration::from_millis(50));
        cmd_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut ka = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_millis(ka_ms),
            Duration::from_millis(ka_ms),
        );
        ka.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        'main: loop {
            // Wait for: your accept/reject decision, consent timeout, or incoming socket data.
            // (socket.readable() is cancel-safe, so keep-alives are still answered while you decide.)
            let ev = tokio::select! {
                biased;
                _ = cmd_tick.tick() => Ev::Cmd,
                Some(ok) = consent_rx.recv(), if awaiting_consent => Ev::Consent(ok),
                _ = tokio::time::sleep_until(consent_deadline), if awaiting_consent => Ev::Timeout,
                _ = ka.tick() => Ev::KeepAlive,
                // while paused we stop reading: TCP back-pressure slows the sender, keep-alives keep flowing
                r = socket.readable(), if !paused => {
                    if r.is_err() { Ev::Closed } else { Ev::Readable }
                }
            };

            match ev {
                Ev::Closed => {
                    println!("[Quick Share] Client closed connection socket.");
                    break 'main;
                }
                Ev::Consent(ok) => {
                    awaiting_consent = false;
                    if let Some(t) = consent_task.take() {
                        t.abort();
                    }
                    if let Ok(mut g) = CONSENT_TX.lock() {
                        *g = None;
                    }
                    crate::events::emit(serde_json::json!({ "type": "offer_closed" }));
                    next_payload_id += 1;
                    if ok {
                        send_response(
                            &mut socket,
                            &mut channel,
                            next_payload_id,
                            connection_response_frame::Status::Accept,
                            resumed_attachments.clone(),
                        ).await?;
                        println!("[Quick Share] You ACCEPTED. Receiving...");
                        crate::events::emit(serde_json::json!({ "type": "rx_accepted", "device": remote_name }));
                    } else {
                        send_response(
                            &mut socket,
                            &mut channel,
                            next_payload_id,
                            connection_response_frame::Status::Reject,
                            Default::default(),
                        ).await?;
                        println!("[Quick Share] You REJECTED the transfer.");
                        break 'main;
                    }
                    continue 'main;
                }
                Ev::Timeout => {
                    if let Some(t) = consent_task.take() {
                        t.abort();
                    }
                    if let Ok(mut g) = CONSENT_TX.lock() {
                        *g = None;
                    }
                    crate::events::emit(serde_json::json!({ "type": "offer_closed" }));
                    next_payload_id += 1;
                    let _ = send_response(&mut socket, &mut channel, next_payload_id, connection_response_frame::Status::TimedOut, Default::default()).await;
                    println!("[Quick Share] No answer in time. Transfer timed out.");
                    break 'main;
                }
                Ev::KeepAlive => {
                    // Real Quick Share er moto amra-o phone ke periodically ping pathai
                    let ping = OfflineFrame {
                        version: Some(offline_frame::Version::V1 as i32),
                        v1: Some(V1Frame {
                            r#type: Some(v1_frame::FrameType::KeepAlive as i32),
                            keep_alive: Some(connections::KeepAliveFrame {
                                ack: Some(false),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                    };
                    let enc = channel.encrypt_secure_message(&ping.encode_to_vec())?;
                    let mut out = Vec::with_capacity(4 + enc.len());
                    out.extend_from_slice(&(enc.len() as u32).to_be_bytes());
                    out.extend_from_slice(&enc);
                    if socket.write_all(&out).await.is_err() {
                        println!("[Quick Share] Could not send keep-alive (connection lost).");
                        break 'main;
                    }
                    continue 'main;
                }
                Ev::Cmd => {
                    while let Some(line) = console::try_line() {
                        match console::parse_command(&line) {
                            Command::Cancel => {
                                println!("\n[Quick Share] Cancelling...");
                                let _ = send_cancel_session(&mut socket, &mut channel, next_payload_id + 100).await;
                                cancelled = true;
                                println!("[Quick Share] Transfer CANCELLED by you.");
                                break 'main;
                            }
                            Command::Pause => {
                                if !paused {
                                    paused = true;
                                    pause_started = Some(Instant::now());
                                    println!("\n[Quick Share] PAUSED. Keeping connection alive...");
                                    crate::events::emit(serde_json::json!({ "type": "xfer_paused" }));
                                }
                            }
                            Command::Resume => {
                                if paused {
                                    paused = false;
                                    if let Some(p_start) = pause_started.take() {
                                        let dur = p_start.elapsed();
                                        for rf in active_files.values_mut() {
                                            rf.started += dur;
                                        }
                                    }
                                    println!("[Quick Share] RESUMED.");
                                    crate::events::emit(serde_json::json!({ "type": "xfer_resumed" }));
                                }
                            }
                            Command::Other => {}
                        }
                    }
                    continue 'main;
                }
                Ev::Readable => {}
            }

            if socket.read_exact(&mut len_buf).await.is_err() {
                println!("[Quick Share] Client closed connection socket.");
                break;
            }
            let smsg_len = u32::from_be_bytes(len_buf) as usize;
            if smsg_len == 0 || smsg_len > 10 * 1024 * 1024 {
                break;
            }
            let mut smsg_bytes = vec![0u8; smsg_len];
            socket.read_exact(&mut smsg_bytes).await?;

            let offline_frame = match channel.decrypt_secure_message(&smsg_bytes) {
                Ok(b) => match OfflineFrame::decode(&b[..]) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("[Quick Share] OfflineFrame decode error: {:?}", e);
                        continue;
                    }
                },
                Err(e) => {
                    eprintln!("[Quick Share] Decryption error: {:?}", e);
                    break;
                }
            };

            let v1 = match offline_frame.v1 {
                Some(v) => v,
                None => continue,
            };

            if v1.r#type == Some(v1_frame::FrameType::Disconnection as i32) {
                println!("[Quick Share] Phone sent DISCONNECTION. Closing session.");
                break;
            }

            if let Some(conn_resp) = v1.connection_response {
                println!("[Quick Share] Phone acknowledged connection (response: {:?})", conn_resp.response);
                continue;
            }

            if let Some(payload_transfer) = v1.payload_transfer {
                let header = payload_transfer.payload_header.unwrap_or_default();
                let chunk = payload_transfer.payload_chunk.unwrap_or_default();
                let p_id = header.id.unwrap_or(0);
                let p_type = header.r#type.unwrap_or(0);
                let is_last = (chunk.flags.unwrap_or(0) & 1) != 0;

                if p_type == payload_transfer_frame::payload_header::PayloadType::Bytes as i32 {
                    // Control payload (PairedKey*, Introduction, Cancel, ...)
                    let buf = byte_buffers.entry(p_id).or_insert_with(Vec::new);
                    if let Some(body) = chunk.body {
                        buf.extend_from_slice(&body);
                    }

                    if is_last {
                        if let Some(complete_data) = byte_buffers.remove(&p_id) {
                            match nearby::Frame::decode(&complete_data[..]) {
                                Ok(nearby_frame) => {
                                    if let Some(nv1) = nearby_frame.v1 {
                                        println!("[Quick Share] Control frame: {:?} ({} bytes)", nv1.r#type, complete_data.len());

                                        if nv1.r#type == Some(nearby_v1::FrameType::Cancel as i32) {
                                            println!("[Quick Share] Phone CANCELLED the transfer.");
                                            cancelled = true;
                                            break 'main;
                                        }

                                        if nv1.paired_key_encryption.is_some() {
                                            next_payload_id += 1;
                                            let result_frame = nearby::Frame {
                                                version: Some(nearby::frame::Version::V1 as i32),
                                                v1: Some(nearby::V1Frame {
                                                    r#type: Some(nearby_v1::FrameType::PairedKeyResult as i32),
                                                    paired_key_result: Some(PairedKeyResultFrame {
                                                        status: Some(paired_key_result_frame::Status::Unable as i32),
                                                        os_type: Some(4),
                                                    }),
                                                    ..Default::default()
                                                }),
                                            };
                                            send_encrypted_payload_frame(&mut socket, &mut channel, next_payload_id, &result_frame.encode_to_vec()).await?;
                                        } else if let Some(pkr) = nv1.paired_key_result {
                                            println!("[Quick Share] Phone PairedKeyResult: status={:?}", pkr.status);
                                        } else if let Some(intro) = nv1.introduction {
                                            let mut offer: Vec<(String, i64)> = Vec::new();
                                            resumed_attachments.clear();
                                            for f in &intro.file_metadata {
                                                let name = f.name.as_deref().unwrap_or("received_file").to_string();
                                                let size = f.size.unwrap_or(0);
                                                let payload_id = f.payload_id.unwrap_or(0);
                                                let aid = f.id.unwrap_or(0);
                                                let parent = f.parent_folder.clone().unwrap_or_default();
                                                let shown = if parent.is_empty() {
                                                    name.clone()
                                                } else {
                                                    format!("{}/{}", parent.replace('\\', "/"), name)
                                                };
                                                meta_files.push((name.clone(), size, payload_id, parent.clone()));
                                                offer.push((shown, size));

                                                // Resume check: if .part file already exists, tell sender our existing bytes
                                                let safe_name = sanitize_component(&name).unwrap_or_else(|| format!("quickshare_{}.bin", payload_id));
                                                let final_dir = downloads_dir.join(safe_relative_dir(&parent));
                                                let part_path = final_dir.join(format!("{}.part", safe_name));
                                                if let Ok(meta) = std::fs::metadata(&part_path) {
                                                    let existing = meta.len() as i64;
                                                    if existing > 0 && (size == 0 || existing < size) {
                                                        println!("[Quick Share] Found partial file for \"{}\": {} bytes already on disk. Ready to resume!", safe_name, existing);
                                                        let det = nearby::AttachmentDetails {
                                                            r#type: Some(nearby::attachment_details::Type::File as i32),
                                                            file_attachment_details: Some(nearby::FileAttachmentDetails {
                                                                receiver_existing_file_size: Some(existing),
                                                                attachment_hash_payloads: std::collections::HashMap::new(),
                                                            }),
                                                        };
                                                        resumed_attachments.insert(aid, det.clone());
                                                        if let Some(hash) = f.attachment_hash {
                                                            resumed_attachments.insert(hash, det);
                                                        }
                                                    }
                                                }
                                            }
                                            total_batch_bytes = meta_files.iter().map(|m| m.1).sum();

                                            if meta_files.is_empty() {
                                                // Text / link / Wi-Fi credentials etc. are not supported yet
                                                next_payload_id += 1;
                                                let _ = send_response(&mut socket, &mut channel, next_payload_id, connection_response_frame::Status::UnsupportedAttachmentType, Default::default()).await;
                                                println!("[Quick Share] Offer has no files (text/link not supported yet). Rejected.");
                                                break 'main;
                                            }

                                            // Reconnect check: if this is a reconnect from the same device (e.g. WiFi <-> Hotspot switch),
                                            // auto-accept and resume immediately without prompting the user again!
                                            let is_reconnect = if let Ok(g) = LAST_RX_SESSION.lock() {
                                                if let Some(ref prev) = *g {
                                                    prev.remote_name == remote_name
                                                        && prev.timestamp.elapsed() < Duration::from_secs(90)
                                                        && meta_files.iter().any(|(n, _, _, _)| prev.file_names.contains(n))
                                                } else {
                                                    false
                                                }
                                            } else {
                                                false
                                            };

                                            if is_reconnect {
                                                println!("[Quick Share] Reconnection detected from \"{}\"! Auto-resuming transfer...", remote_name);
                                                if let Ok(mut g) = LAST_RX_SESSION.lock() {
                                                    if let Some(ref mut prev) = *g {
                                                        prev.timestamp = Instant::now();
                                                    }
                                                }
                                                next_payload_id += 1;
                                                send_response(
                                                    &mut socket,
                                                    &mut channel,
                                                    next_payload_id,
                                                    connection_response_frame::Status::Accept,
                                                    resumed_attachments.clone(),
                                                ).await?;
                                                println!("[Quick Share] Auto-accepted reconnected session. Receiving...");
                                                crate::events::emit(serde_json::json!({ "type": "rx_resumed", "device": remote_name }));
                                            } else {
                                                if let Ok(mut g) = LAST_RX_SESSION.lock() {
                                                    *g = Some(LastRxSession {
                                                        remote_name: remote_name.clone(),
                                                        file_names: meta_files.iter().map(|m| m.0.clone()).collect(),
                                                        timestamp: Instant::now(),
                                                    });
                                                }
                                                // Ask the user, like Quick Share does. Answer arrives on consent_rx.
                                                consent_task = Some(spawn_consent_prompt(consent_tx.clone(), remote_name.clone(), channel.pin.clone(), offer));
                                                awaiting_consent = true;
                                                consent_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[Quick Share] Nearby Frame decode error: {:?}", e);
                                }
                            }
                        }
                    }
                } else if p_type == payload_transfer_frame::payload_header::PayloadType::File as i32 {
                    let chunk_offset = chunk.offset.unwrap_or(0);

                    if active_files.get(&p_id).is_none() {
                        let file_entry = meta_files.iter().find(|m| m.2 == p_id).or_else(|| if meta_files.len() == 1 { meta_files.first() } else { None });
                        let raw_name = file_entry
                            .map(|m| m.0.clone())
                            .or_else(|| header.file_name.clone())
                            .unwrap_or_else(|| format!("quickshare_{}.bin", p_id));
                        let raw_parent = file_entry
                            .map(|m| m.3.clone())
                            .filter(|p| !p.is_empty())
                            .or_else(|| header.parent_folder.clone())
                            .unwrap_or_default();
                        let fsize = file_entry.map(|m| m.1).unwrap_or(header.total_size.unwrap_or(0));

                        // Never trust names coming from the network: drop "..", drive letters, illegal characters.
                        let safe_name = sanitize_component(&raw_name).unwrap_or_else(|| format!("quickshare_{}.bin", p_id));
                        let final_dir = downloads_dir.join(safe_relative_dir(&raw_parent));
                        if let Err(e) = std::fs::create_dir_all(&final_dir) {
                            eprintln!("[Quick Share] Cannot create folder {:?}: {}", final_dir, e);
                            break 'main;
                        }
                        let part_path = final_dir.join(format!("{}.part", safe_name));

                        // Offset resume (Nearby Connections "send payload at offset"): if the first chunk starts
                        // exactly where our .part file ends, append instead of starting over.
                        let existing_len = std::fs::metadata(&part_path).map(|m| m.len() as i64).unwrap_or(-1);
                        let open_result = if chunk_offset > 0 {
                            if existing_len == chunk_offset {
                                println!("[Quick Share] RESUMING {} at {} bytes (.part file matched)", safe_name, chunk_offset);
                                std::fs::OpenOptions::new().append(true).open(&part_path)
                            } else {
                                eprintln!(
                                    "[Quick Share] Phone started {} at offset {}, but our .part file has {} bytes. Cannot merge, aborting.",
                                    safe_name, chunk_offset, existing_len
                                );
                                break 'main;
                            }
                        } else {
                            File::create(&part_path)
                        };

                        match open_result {
                            Ok(f) => {
                                println!("[Quick Share] Receiving: {:?}", final_dir.join(&safe_name));
                                active_files.insert(p_id, ReceivingFile {
                                    name: safe_name.clone(),
                                    final_dir,
                                    safe_name: safe_name.clone(),
                                    part_path,
                                    size: fsize,
                                    file: BufWriter::with_capacity(1024 * 1024, f),
                                    received: chunk_offset,
                                    base: chunk_offset,
                                    started: Instant::now(),
                                    last_print: Instant::now(),
                                });
                                let total_received_so_far = completed_bytes + chunk_offset;
                                let init_pct = if total_batch_bytes > 0 {
                                    (total_received_so_far as f64 / total_batch_bytes as f64 * 100.0).min(100.0)
                                } else {
                                    0.0
                                };
                                crate::events::emit(serde_json::json!({
                                    "type": "progress", "dir": "rx", "name": safe_name,
                                    "pct": init_pct, "mbps": 0.0, "file_index": completed_files + 1, "files": meta_files.len(),
                                }));
                            }
                            Err(e) => eprintln!("[Quick Share] Cannot create file: {:?}", e),
                        }
                    }

                    if let Some(rf) = active_files.get_mut(&p_id) {
                        if let Some(body) = chunk.body {
                            if !body.is_empty() && chunk_offset != rf.received {
                                eprintln!(
                                    "\n[Quick Share] Chunk offset {} does not match expected {} for {}. Aborting to avoid a corrupt file.",
                                    chunk_offset, rf.received, rf.name
                                );
                                break 'main;
                            }
                            if let Err(e) = rf.file.write_all(&body) {
                                eprintln!("\n[Quick Share] Disk write error: {:?}", e);
                                break 'main;
                            }
                            rf.received += body.len() as i64;
                            if rf.size > 0 && rf.last_print.elapsed() >= Duration::from_millis(300) {
                                let total_received_so_far = completed_bytes + rf.received;
                                let batch_pct = if total_batch_bytes > 0 {
                                    (total_received_so_far as f64 / total_batch_bytes as f64 * 100.0).min(100.0)
                                } else {
                                    (rf.received as f64 / rf.size.max(1) as f64 * 100.0).min(100.0)
                                };
                                let mbps = (rf.received - rf.base) as f64 / 1_048_576.0 / rf.started.elapsed().as_secs_f64().max(0.001);
                                print!("\r[Quick Share] {}: {:.1}% (total: {:.1}%)  {:.1} MB/s   ", rf.name, (rf.received as f64 / rf.size.max(1) as f64 * 100.0).min(100.0), batch_pct, mbps);
                                let _ = std::io::stdout().flush();
                                crate::events::emit(serde_json::json!({
                                    "type": "progress", "dir": "rx", "name": rf.name,
                                    "pct": batch_pct, "mbps": mbps, "file_index": completed_files + 1, "files": meta_files.len(),
                                }));
                                rf.last_print = Instant::now();
                            }
                        }
                    }

                    if is_last {
                        if let Some(mut rf) = active_files.remove(&p_id) {
                            let _ = rf.file.flush();
                            let secs = rf.started.elapsed().as_secs_f64().max(0.001);
                            let mb = (rf.received - rf.base) as f64 / 1_048_576.0;
                            if rf.size > 0 && rf.received != rf.size {
                                println!(
                                    "\n[Quick Share] INCOMPLETE: {} has {} of {} bytes. Kept as {:?}",
                                    rf.name, rf.received, rf.size, rf.part_path
                                );
                            } else {
                                drop(rf.file); // close the handle before renaming (Windows)
                                let final_path = resolve_unique_path(&rf.final_dir, &rf.safe_name);
                                match std::fs::rename(&rf.part_path, &final_path) {
                                    Ok(()) => {
                                        println!("\n[Quick Share] SUCCESS! Saved: {:?}", final_path);
                                        crate::events::emit(serde_json::json!({
                                            "type": "file_done", "name": rf.safe_name, "path": final_path.to_string_lossy(),
                                        }));
                                        println!("[Quick Share] {:.1} MB in {:.1}s = {:.1} MB/s ({:.0} Mbps)", mb, secs, mb / secs, mb / secs * 8.0);
                                        completed_bytes += rf.received.max(rf.size);
                                        completed_files += 1;
                                    }
                                    Err(e) => {
                                        eprintln!("\n[Quick Share] Could not rename to final name ({}). Data is in {:?}", e, rf.part_path);
                                    }
                                }
                            }
                        }
                        if completed_files >= meta_files.len() {
                            println!("[Quick Share] All files received successfully!");
                            break 'main;
                        }
                    }
                }
            } else if v1.keep_alive.is_some() || v1.r#type == Some(v1_frame::FrameType::KeepAlive as i32) {
                // Phone er ack-er uttore ack pathabo na (ping-pong bondho)
                let is_ack = v1.keep_alive.as_ref().and_then(|k| k.ack).unwrap_or(false);
                if is_ack {
                    continue;
                }
                let ack = OfflineFrame {
                    version: Some(offline_frame::Version::V1 as i32),
                    v1: Some(V1Frame {
                        r#type: Some(v1_frame::FrameType::KeepAlive as i32),
                        keep_alive: Some(connections::KeepAliveFrame {
                            ack: Some(true),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                };
                let enc = channel.encrypt_secure_message(&ack.encode_to_vec())?;
                socket.write_all(&(enc.len() as u32).to_be_bytes()).await?;
                socket.write_all(&enc).await?;
            }
        }

        if let Some(t) = consent_task.take() {
            t.abort();
        }

        // Unfinished files: keep the .part (can be resumed if the phone re-sends at an offset), or delete if cancelled.
        for (_, mut rf) in active_files.drain() {
            let _ = rf.file.flush();
            drop(rf.file);
            if cancelled {
                let _ = std::fs::remove_file(&rf.part_path);
                println!("\n[Quick Share] Cancelled: removed partial file {:?}", rf.part_path);
            } else {
                println!(
                    "\n[Quick Share] INCOMPLETE: {} of {} received ({:.1}/{:.1} MB). Partial data kept as {:?}",
                    rf.name,
                    rf.size,
                    rf.received as f64 / 1_048_576.0,
                    rf.size as f64 / 1_048_576.0,
                    rf.part_path
                );
            }
        }

        let is_ok = !meta_files.is_empty() && completed_files >= meta_files.len();
        if is_ok || cancelled {
            if let Ok(mut g) = LAST_RX_SESSION.lock() {
                *g = None;
            }
        }
        crate::events::emit(serde_json::json!({
            "type": "rx_session_end",
            "ok": is_ok,
            "cancelled": cancelled,
        }));
        println!("[Server] Transfer session ended.");
        Ok(())
    }
}

async fn send_encrypted_payload_frame(
    socket: &mut TcpStream,
    channel: &mut SecureSessionChannel,
    id: i64,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let total = data.len() as i64;

    // Packet 1: the data (flags = 0). Packet 2: empty body with LAST_CHUNK flag (flags = 1).
    let chunks: [(i64, i32, Vec<u8>); 2] = [
        (0, 0, data.to_vec()),
        (total, 1, Vec::new()),
    ];

    for (offset, flags, body) in chunks {
        let transfer = PayloadTransferFrame {
            packet_type: Some(payload_transfer_frame::PacketType::Data as i32),
            payload_header: Some(payload_transfer_frame::PayloadHeader {
                id: Some(id),
                r#type: Some(payload_transfer_frame::payload_header::PayloadType::Bytes as i32),
                total_size: Some(total),
                is_sensitive: Some(false),
                ..Default::default()
            }),
            payload_chunk: Some(payload_transfer_frame::PayloadChunk {
                flags: Some(flags),
                offset: Some(offset),
                body: Some(body),
                ..Default::default()
            }),
            ..Default::default()
        };

        let wrapper = OfflineFrame {
            version: Some(offline_frame::Version::V1 as i32),
            v1: Some(V1Frame {
                r#type: Some(v1_frame::FrameType::PayloadTransfer as i32),
                payload_transfer: Some(transfer),
                ..Default::default()
            }),
        };

        let enc = channel.encrypt_secure_message(&wrapper.encode_to_vec())?;
        socket.write_all(&(enc.len() as u32).to_be_bytes()).await?;
        socket.write_all(&enc).await?;
        let _ = socket.flush().await;
    }

    Ok(())
}

async fn send_response(
    socket: &mut TcpStream,
    channel: &mut SecureSessionChannel,
    id: i64,
    status: connection_response_frame::Status,
    attachment_details: std::collections::HashMap<i64, nearby::AttachmentDetails>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let frame = nearby::Frame {
        version: Some(nearby::frame::Version::V1 as i32),
        v1: Some(nearby::V1Frame {
            r#type: Some(nearby_v1::FrameType::Response as i32),
            connection_response: Some(NearbyConnResp {
                status: Some(status as i32),
                attachment_details,
                ..Default::default()
            }),
            ..Default::default()
        }),
    };
    let res = send_encrypted_payload_frame(socket, channel, id, &frame.encode_to_vec()).await;
    let _ = socket.flush().await;
    res
}

static CONSENT_TX: std::sync::Mutex<Option<mpsc::UnboundedSender<bool>>> = std::sync::Mutex::new(None);

pub fn send_consent_decision(accept: bool) {
    if let Ok(mut g) = CONSENT_TX.lock() {
        if let Some(tx) = g.take() {
            let _ = tx.send(accept);
        }
    }
}

/// Asks the user on the console / UI (like the Quick Share "Accept / Decline" dialog).
fn spawn_consent_prompt(
    tx: mpsc::UnboundedSender<bool>,
    device: String,
    pin: String,
    files: Vec<(String, i64)>,
) -> tokio::task::JoinHandle<()> {
    if let Ok(mut g) = CONSENT_TX.lock() {
        *g = Some(tx.clone());
    }
    console::drain(); // an old Enter press must not count as an answer
    tokio::spawn(async move {
        let total: i64 = files.iter().map(|f| f.1).sum();
        let shown: Vec<serde_json::Value> = files
            .iter()
            .take(12)
            .map(|(n, sz)| serde_json::json!({ "name": n, "size": sz }))
            .collect();
        crate::events::emit(serde_json::json!({
            "type": "offer", "device": device, "pin": pin, "files": shown,
            "more": files.len().saturating_sub(12), "count": files.len(), "total": total,
        }));
        println!("\n============================================================");
        println!(" [Quick Share] \"{}\" wants to share with you", device);
        println!(" [Quick Share] PIN: {}   (must match the PIN on the phone)", pin);
        for (name, size) in files.iter().take(12) {
            println!("   - {} ({:.2} MB)", name, *size as f64 / 1_048_576.0);
        }
        if files.len() > 12 {
            println!("   ... and {} more file(s)", files.len() - 12);
        }
        println!("   Total: {} file(s), {:.2} MB", files.len(), total as f64 / 1_048_576.0);
        println!("============================================================");
    })
}

/// Cancel from our side: sharing-layer CANCEL frame, then a DISCONNECTION frame.
async fn send_cancel_session(
    socket: &mut TcpStream,
    channel: &mut SecureSessionChannel,
    id: i64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cancel = nearby::Frame {
        version: Some(nearby::frame::Version::V1 as i32),
        v1: Some(nearby::V1Frame {
            r#type: Some(nearby_v1::FrameType::Cancel as i32),
            ..Default::default()
        }),
    };
    send_encrypted_payload_frame(socket, channel, id, &cancel.encode_to_vec()).await?;

    let disc = OfflineFrame {
        version: Some(offline_frame::Version::V1 as i32),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::Disconnection as i32),
            disconnection: Some(connections::DisconnectionFrame::default()),
            ..Default::default()
        }),
    };
    let enc = channel.encrypt_secure_message(&disc.encode_to_vec())?;
    let mut out = Vec::with_capacity(4 + enc.len());
    out.extend_from_slice(&(enc.len() as u32).to_be_bytes());
    out.extend_from_slice(&enc);
    socket.write_all(&out).await?;
    let _ = socket.flush().await;
    Ok(())
}

/// One path component from the network -> safe Windows file/folder name (or None if nothing usable is left).
fn sanitize_component(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() || t == "." || t == ".." {
        return None;
    }
    let mut cleaned: String = t
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if (c as u32) < 32 => '_',
            c => c,
        })
        .collect();
    while cleaned.ends_with(' ') || cleaned.ends_with('.') {
        cleaned.pop();
    }
    if cleaned.is_empty() {
        return None;
    }
    let stem = cleaned.split('.').next().unwrap_or("").to_uppercase();
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED.contains(&stem.as_str()) {
        cleaned.insert(0, '_');
    }
    Some(cleaned)
}

/// "Show/Season 1" (or with backslashes) -> relative PathBuf. ".." / empty / absolute parts are dropped,
/// so a malicious phone can never write outside the Downloads folder.
fn safe_relative_dir(parent: &str) -> PathBuf {
    let mut p = PathBuf::new();
    let mut depth = 0;
    for comp in parent.replace('\\', "/").split('/') {
        if let Some(c) = sanitize_component(comp) {
            p.push(c);
            depth += 1;
            if depth >= 32 {
                break;
            }
        }
    }
    p
}

fn extract_device_name(ep_info: &[u8]) -> String {
    if ep_info.len() >= 18 {
        let name_len = ep_info[17] as usize;
        if ep_info.len() >= 18 + name_len {
            if let Ok(s) = std::str::from_utf8(&ep_info[18..18 + name_len]) {
                return s.to_string();
            }
        }
    }
    String::from_utf8_lossy(ep_info).to_string()
}

fn resolve_unique_path(dir: &PathBuf, filename: &str) -> PathBuf {
    let mut candidate = dir.join(filename);
    if !candidate.exists() {
        return candidate;
    }

    let stem = PathBuf::from(filename).file_stem().and_then(|s| s.to_str()).unwrap_or("file").to_string();
    let ext = PathBuf::from(filename).extension().and_then(|s| s.to_str()).unwrap_or("").to_string();

    let mut counter = 1;
    loop {
        let new_name = if ext.is_empty() {
            format!("{} ({})", stem, counter)
        } else {
            format!("{} ({}).{}", stem, counter, ext)
        };
        candidate = dir.join(new_name);
        if !candidate.exists() {
            return candidate;
        }
        counter += 1;
    }
}

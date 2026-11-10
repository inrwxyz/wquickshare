use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use prost::Message;
use rand::{Rng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;


use crate::console::{self, Command};
use crate::crypto::{SecureSessionChannel, Ukey2ClientSession};
use crate::mdns::DiscoveredDevice;
use crate::protos::connections::{
    self, offline_frame, payload_transfer_frame, v1_frame,
    ConnectionRequestFrame, ConnectionResponseFrame as ConnResp, OfflineFrame,
    PayloadTransferFrame, V1Frame,
};
use crate::protos::nearby::{
    self, connection_response_frame as nearby_resp, v1_frame as nearby_v1,
    IntroductionFrame, PairedKeyEncryptionFrame, PairedKeyResultFrame,
};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// One file to send. `parent_folder` is the relative folder path ("Show/Season 1"), empty for a plain file.
#[derive(Debug, Clone)]
pub struct SendItem {
    pub path: PathBuf,
    pub parent_folder: String,
}

pub struct QuickShareClient {
    pub device_name: String,
    pub endpoint_id: [u8; 4],
}

impl QuickShareClient {
    pub fn new(device_name: String, endpoint_id: [u8; 4]) -> Self {
        Self {
            device_name,
            endpoint_id,
        }
    }

    pub fn endpoint_info_bytes(&self) -> Vec<u8> {
        let mut ep_info = Vec::new();
        ep_info.push(3 << 1); // 3 = Laptop / PC
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        ep_info.extend_from_slice(&salt);
        let name_bytes = self.device_name.as_bytes();
        let len = name_bytes.len().min(255) as u8;
        ep_info.push(len);
        ep_info.extend_from_slice(&name_bytes[..len as usize]);
        ep_info
    }

    pub async fn send_file(
        &self,
        target: &DiscoveredDevice,
        file_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_files(target, &[SendItem { path: file_path.to_path_buf(), parent_folder: String::new() }]).await
    }

    pub async fn send_files(
        &self,
        target: &DiscoveredDevice,
        items: &[SendItem],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if items.is_empty() {
            return Err("No files specified for sending".into());
        }

        struct OutgoingFile {
            path: PathBuf,
            name: String,
            size: u64,
            payload_id: i64,
            attachment_id: i64,
            file_type: i32,
            mime: &'static str,
            parent_folder: String,
        }

        let mut files_to_send = Vec::new();
        let mut total_all_bytes: u64 = 0;
        for it in items {
            let p = &it.path;
            let metadata = std::fs::metadata(p)?;
            if !metadata.is_file() {
                return Err(format!("Target path is not a valid file: {:?}", p).into());
            }
            let size = metadata.len();
            total_all_bytes += size;
            let name = p
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("shared_file")
                .to_string();
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            let (file_type, mime) = file_type_and_mime(&ext);
            let (payload_id, attachment_id) = {
                let mut rng = rand::thread_rng();
                (rng.gen_range(1_000_000_000..9_999_999_999), rng.gen_range(1_000_000..9_999_999))
            };

            files_to_send.push(OutgoingFile {
                path: p.clone(),
                parent_folder: it.parent_folder.clone(),
                name,
                size,
                payload_id,
                attachment_id,
                file_type,
                mime,
            });
        }

        println!("\n============================================================");
        println!(" [*] Target:        {} ({}:{})", target.name, target.ip, target.port);
        if files_to_send.len() == 1 {
            println!(" [*] File:          {} ({:.2} MB)", files_to_send[0].name, files_to_send[0].size as f64 / 1_048_576.0);
        } else {
            println!(" [*] Files ({}):     {:.2} MB total", files_to_send.len(), total_all_bytes as f64 / 1_048_576.0);
            for f in files_to_send.iter().take(10) {
                if f.parent_folder.is_empty() {
                    println!("     - {} ({:.2} MB)", f.name, f.size as f64 / 1_048_576.0);
                } else {
                    println!("     - {}/{} ({:.2} MB)", f.parent_folder, f.name, f.size as f64 / 1_048_576.0);
                }
            }
            if files_to_send.len() > 10 {
                println!("     ... and {} more file(s)", files_to_send.len() - 10);
            }
        }
        println!("============================================================");
        print!(" [Quick Share] Connecting to target via TCP... ");
        let _ = std::io::stdout().flush();

        let mut socket = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect((target.ip, target.port)))
            .await
            .map_err(|_| -> BoxErr { "Connection timed out (target unreachable or IP changed)".into() })??;
        let _ = socket.set_nodelay(true);
        // OS-level TCP keep-alive: phone lock / Wi-Fi power-save e connection more na
        let _ = socket2::SockRef::from(&socket)
            .set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(Duration::from_secs(10)));
        // TCP send buffer = 1 MB (1048576) to pipeline 512 KB chunks without wire stalls
        let _ = socket2::SockRef::from(&socket).set_send_buffer_size(1024 * 1024);
        println!("Connected!");
        if let Ok(la) = socket.local_addr() {
            println!("[Quick Share] Route: PC {} -> Phone {}:{}", la, target.ip, target.port);
        }

        let mut len_buf = [0u8; 4];

        // -------------------------------------------------------------
        // Step 1: Send ConnectionRequest (OfflineFrame)
        // -------------------------------------------------------------
        let nonce: i32 = rand::rngs::OsRng.gen_range(1..i32::MAX);
        let req_frame = OfflineFrame {
            version: Some(offline_frame::Version::V1 as i32),
            v1: Some(V1Frame {
                r#type: Some(v1_frame::FrameType::ConnectionRequest as i32),
                connection_request: Some(ConnectionRequestFrame {
                    endpoint_id: Some(std::str::from_utf8(&self.endpoint_id).unwrap_or("INEX").to_string()),
                    endpoint_name: Some(self.device_name.clone()),
                    endpoint_info: Some(self.endpoint_info_bytes()),
                    nonce: Some(nonce),
                    mediums: vec![connections::connection_request_frame::Medium::WifiLan as i32],
                    keep_alive_interval_millis: Some(5000),
                    keep_alive_timeout_millis: Some(30000),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let req_bytes = req_frame.encode_to_vec();
        socket.write_all(&(req_bytes.len() as u32).to_be_bytes()).await?;
        socket.write_all(&req_bytes).await?;
        println!("[Quick Share] Sent ConnectionRequest to \"{}\"", target.name);

        // -------------------------------------------------------------
        // Step 2: Send ClientInit (UKEY2 message 1)
        // -------------------------------------------------------------
        let mut ukey2 = Ukey2ClientSession::new();
        let client_init_bytes = ukey2.build_client_init()?;
        socket.write_all(&(client_init_bytes.len() as u32).to_be_bytes()).await?;
        socket.write_all(&client_init_bytes).await?;
        println!("[Quick Share] Handshake step 1/3: Sent ClientInit");

        // -------------------------------------------------------------
        // Step 3: Read ServerInit (UKEY2 message 2)
        // -------------------------------------------------------------
        socket.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut server_init_bytes = vec![0u8; len];
        socket.read_exact(&mut server_init_bytes).await?;
        println!("[Quick Share] Handshake step 2/3: Received ServerInit");

        // -------------------------------------------------------------
        // Step 4: Process ServerInit, Derive Keys, and Send ClientFinish (UKEY2 message 3)
        // -------------------------------------------------------------
        let (client_finish_bytes, mut channel) = ukey2.process_server_init(&server_init_bytes)?;
        socket.write_all(&(client_finish_bytes.len() as u32).to_be_bytes()).await?;
        socket.write_all(&client_finish_bytes).await?;
        println!("[Quick Share] Handshake step 3/3: Sent ClientFinish");

        println!("============================================================");
        println!(" [Quick Share] SECURE CHANNEL VERIFIED!");
        println!(" [Quick Share] Remote Device: {}", target.name);
        println!(" [Quick Share] Pairing PIN:   {}", channel.pin);
        crate::events::emit(serde_json::json!({ "type": "send_pin", "pin": channel.pin }));
        println!("============================================================");

        // -------------------------------------------------------------
        // Step 5: Exchange Unencrypted ConnectionResponse (Accept)
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
        let acc_bytes = accept_frame.encode_to_vec();
        socket.write_all(&(acc_bytes.len() as u32).to_be_bytes()).await?;
        socket.write_all(&acc_bytes).await?;

        // Read remote accept
        loop {
            socket.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut resp_bytes = vec![0u8; len];
            socket.read_exact(&mut resp_bytes).await?;

            if let Ok(frame) = OfflineFrame::decode(&resp_bytes[..]) {
                if let Some(v1) = frame.v1 {
                    if let Some(resp) = v1.connection_response {
                        println!("[Quick Share] Mutual handshake accepted (phone status: {:?}).", resp.response);
                        break;
                    } else if v1.keep_alive.is_some() || v1.r#type == Some(v1_frame::FrameType::KeepAlive as i32) {
                        continue;
                    }
                }
            } else if let Ok(msg) = crate::protos::securegcm::Ukey2Message::decode(&resp_bytes[..]) {
                if msg.message_type == Some(crate::protos::securegcm::ukey2_message::Type::Alert as i32) {
                    if let Some(data) = msg.message_data {
                        if let Ok(alert) = crate::protos::securegcm::Ukey2Alert::decode(&data[..]) {
                            eprintln!("[Quick Share] Phone sent UKEY2 Alert: {:?}", alert);
                        }
                    }
                    return Err("Phone rejected UKEY2 handshake with Alert".into());
                }
            }
        }

        // -------------------------------------------------------------
        // Step 6: PairedKey exchange (encrypted)
        //   both sides send PairedKeyEncryption, then each answers with PairedKeyResult
        // -------------------------------------------------------------
        let mut ctl = ControlReader::new();
        let mut next_payload_id: i64 = 1000;

        let mut secret_id_hash = [0u8; 6];
        let mut signed_data = [0u8; 72];
        rand::rngs::OsRng.fill_bytes(&mut secret_id_hash);
        rand::rngs::OsRng.fill_bytes(&mut signed_data);

        next_payload_id += 1;
        let pke_frame = nearby::Frame {
            version: Some(nearby::frame::Version::V1 as i32),
            v1: Some(nearby::V1Frame {
                r#type: Some(nearby_v1::FrameType::PairedKeyEncryption as i32),
                paired_key_encryption: Some(PairedKeyEncryptionFrame {
                    signed_data: Some(signed_data.to_vec()),
                    secret_id_hash: Some(secret_id_hash.to_vec()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        send_encrypted_payload_frame(&mut socket, &mut channel, next_payload_id, &pke_frame.encode_to_vec()).await?;
        println!("[Quick Share] Sent PairedKeyEncryption");

        let mut got_pke = false;
        let mut got_pkr = false;
        while !(got_pke && got_pkr) {
            let ev = match tokio::time::timeout(Duration::from_secs(15), ctl.next_event(&mut socket, &mut channel)).await {
                Ok(r) => r?,
                Err(_) => return Err("Timed out waiting for the phone's PairedKey frames".into()),
            };
            match ev {
                Event::Disconnect => return Err("Phone disconnected during PairedKey exchange".into()),
                Event::Nearby(nf) => {
                    if let Some(nv1) = nf.v1 {
                        if nv1.r#type == Some(nearby_v1::FrameType::Cancel as i32) {
                            return Err("Phone cancelled during PairedKey exchange".into());
                        }
                        if nv1.paired_key_encryption.is_some() {
                            got_pke = true;
                            next_payload_id += 1;
                            let pkr = nearby::Frame {
                                version: Some(nearby::frame::Version::V1 as i32),
                                v1: Some(nearby::V1Frame {
                                    r#type: Some(nearby_v1::FrameType::PairedKeyResult as i32),
                                    paired_key_result: Some(PairedKeyResultFrame {
                                        status: Some(nearby::paired_key_result_frame::Status::Unable as i32),
                                        os_type: Some(4),
                                    }),
                                    ..Default::default()
                                }),
                            };
                            send_encrypted_payload_frame(&mut socket, &mut channel, next_payload_id, &pkr.encode_to_vec()).await?;
                            println!("[Quick Share] Sent PairedKeyResult (UNABLE)");
                        } else if let Some(r) = nv1.paired_key_result {
                            got_pkr = true;
                            println!("[Quick Share] Phone PairedKeyResult: {:?}", r.status);
                        }
                    }
                }
            }
        }

        // -------------------------------------------------------------
        // Step 7: Introduction (file offer for all files)
        // -------------------------------------------------------------
        next_payload_id += 1;
        let mut file_metadata = Vec::new();
        for f in &files_to_send {
            file_metadata.push(nearby::FileMetadata {
                name: Some(f.name.clone()),
                r#type: Some(f.file_type),
                payload_id: Some(f.payload_id),
                size: Some(f.size as i64),
                mime_type: Some(f.mime.to_string()),
                id: Some(f.attachment_id),
                parent_folder: if f.parent_folder.is_empty() { None } else { Some(f.parent_folder.clone()) },
                ..Default::default()
            });
        }

        let intro_frame = nearby::Frame {
            version: Some(nearby::frame::Version::V1 as i32),
            v1: Some(nearby::V1Frame {
                r#type: Some(nearby_v1::FrameType::Introduction as i32),
                introduction: Some(IntroductionFrame {
                    file_metadata,
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };
        let intro_bytes = intro_frame.encode_to_vec();
        // Nearby Connections BYTES payloads are limited to ~1 MB: a giant folder must be split.
        if intro_bytes.len() > 900_000 {
            return Err(format!(
                "Offer too large ({} files, {} KB of metadata). Send the folder in smaller parts.",
                files_to_send.len(),
                intro_bytes.len() / 1024
            ).into());
        }
        send_encrypted_payload_frame(&mut socket, &mut channel, next_payload_id, &intro_bytes).await?;

        println!("\n[Quick Share] >>> File offer sent to \"{}\" <<<", target.name);
        println!("[Quick Share] Check your phone screen and tap 'ACCEPT' (or 'Receive')...");
        crate::events::emit(serde_json::json!({ "type": "send_waiting" }));

        // -------------------------------------------------------------
        // Step 8: Wait for the phone user's decision (keep-alives are sent automatically)
        // -------------------------------------------------------------
        let consent_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        let mut resumed_offsets: HashMap<i64, i64> = HashMap::new();
        loop {
            if let Some(line) = console::try_line() {
                if console::parse_command(&line) == Command::Cancel {
                    println!("[Quick Share] Cancelled by you while waiting for phone to accept.");
                    crate::events::emit(serde_json::json!({ "type": "send_finished", "cancelled": true }));
                    return Ok(());
                }
            }
            let ev = match tokio::time::timeout(Duration::from_millis(200), ctl.next_event(&mut socket, &mut channel)).await {
                Ok(r) => r?,
                Err(_) => {
                    if tokio::time::Instant::now() >= consent_deadline {
                        println!("[Quick Share] No answer from the phone within 120s. Giving up.");
                        crate::events::emit(serde_json::json!({ "type": "send_finished", "cancelled": true }));
                        crate::events::status("warn", "No answer from the phone within 2 minutes.");
                        return Ok(());
                    }
                    continue;
                }
            };
            match ev {
                Event::Disconnect => {
                    println!("[Quick Share] Phone ended the session before accepting (it sent DISCONNECTION).");
                    crate::events::emit(serde_json::json!({ "type": "send_finished", "cancelled": true }));
                    crate::events::status("warn", "The phone ended the session before accepting.");
                    return Ok(());
                }
                Event::Nearby(nf) => {
                    if let Some(nv1) = nf.v1 {
                        if nv1.r#type == Some(nearby_v1::FrameType::Cancel as i32) {
                            println!("[Quick Share] Phone CANCELLED the offer.");
                            crate::events::emit(serde_json::json!({ "type": "send_finished", "cancelled": true }));
                            crate::events::status("warn", "The phone cancelled the offer.");
                            return Ok(());
                        }
                        if let Some(resp) = nv1.connection_response {
                            let status = resp.status.unwrap_or(0);
                            if status == nearby_resp::Status::Accept as i32 {
                                println!("[Quick Share] Phone user tapped ACCEPT! Starting transfer...\n");
                                console::drain(); // old key presses must not pause/cancel this transfer
                                crate::events::emit(serde_json::json!({ "type": "send_accepted" }));

                                for (aid, details) in &resp.attachment_details {
                                    if let Some(fad) = &details.file_attachment_details {
                                        if let Some(sz) = fad.receiver_existing_file_size {
                                            if sz > 0 {
                                                resumed_offsets.insert(*aid, sz);
                                            }
                                        }
                                    }
                                }
                                break;
                            } else {
                                println!("[Quick Share] Phone declined the transfer (status: {}).", status);
                                crate::events::emit(serde_json::json!({ "type": "send_finished", "cancelled": true }));
                                crate::events::status("warn", "The phone declined the transfer.");
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }

        // -------------------------------------------------------------
        // Step 9: File streaming (512 KB chunks — Nearby protocol limit)
        // -------------------------------------------------------------
        let mut total_started = Instant::now();
        let mut cumulative_sent: u64 = 0;
        let total_files = files_to_send.len();
        println!(" [Quick Share] Live commands while sending: p = pause | r = resume | c = cancel  (type the letter, then Enter)");

        for (idx, f) in files_to_send.iter().enumerate() {
            println!("============================================================");
            println!(" [Quick Share] TRANSMITTING [{}/{}]: {}", idx + 1, total_files, f.name);
            println!("============================================================");

            let mut file = File::open(&f.path)?;
            let mut chunk_buf = vec![0u8; 512 * 1024];
            let mut file_sent: u64 = 0;

            let existing_offset = resumed_offsets.get(&f.attachment_id).copied().unwrap_or(0);
            if existing_offset > 0 && existing_offset < f.size as i64 {
                println!("[Quick Share] Phone already has {} bytes of \"{}\". Resuming transfer from byte {}!", existing_offset, f.name, existing_offset);
                use std::io::Seek;
                file.seek(std::io::SeekFrom::Start(existing_offset as u64))?;
                file_sent = existing_offset as u64;
                cumulative_sent += existing_offset as u64;
            }

            let mut file_started = Instant::now();
            let mut last_print = Instant::now();

            // Emit instant initial progress without dropping back to 0%
            let total_pct = if total_all_bytes > 0 {
                (cumulative_sent as f64 / total_all_bytes as f64 * 100.0).min(100.0)
            } else {
                0.0
            };
            crate::events::emit(serde_json::json!({
                "type": "progress", "dir": "tx", "name": f.name,
                "pct": total_pct,
                "mbps": 0.0, "file_index": idx + 1, "files": total_files,
            }));

            let mut chunks_since_poll: usize = 0;
            loop {
                // Live commands: p = pause, r = resume, c = cancel
                while let Some(line) = console::try_line() {
                    match console::parse_command(&line) {
                        Command::Cancel => {
                            println!("\n[Quick Share] Cancelling...");
                            let _ = send_cancel(&mut socket, &mut channel, f.payload_id, f.size as i64, file_sent as i64).await;
                            println!("[Quick Share] Transfer CANCELLED by you.");
                            crate::events::emit(serde_json::json!({ "type": "send_finished", "cancelled": true }));
                            return Ok(());
                        }
                        Command::Pause => {
                            println!("\n[Quick Share] PAUSED. Type 'r' + Enter to resume, 'c' + Enter to cancel.");
                            crate::events::emit(serde_json::json!({ "type": "xfer_paused" }));
                            let pause_started = Instant::now();
                            'paused: loop {
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                // keep the session alive and watch for the phone ending it
                                if let Some(ev) = ctl.poll_control(&mut socket, &mut channel).await? {
                                    match ev {
                                        Event::Disconnect => {
                                            return Err("Phone ended the session while paused".into());
                                        }
                                        Event::Nearby(nf) => {
                                            if nf.v1.as_ref().and_then(|x| x.r#type) == Some(nearby_v1::FrameType::Cancel as i32) {
                                                return Err("Phone CANCELLED the transfer".into());
                                            }
                                        }
                                    }
                                }
                                while let Some(l2) = console::try_line() {
                                    match console::parse_command(&l2) {
                                        Command::Resume => {
                                            println!("[Quick Share] RESUMED.");
                                            crate::events::emit(serde_json::json!({ "type": "xfer_resumed" }));
                                            break 'paused;
                                        }
                                        Command::Cancel => {
                                            let _ = send_cancel(&mut socket, &mut channel, f.payload_id, f.size as i64, file_sent as i64).await;
                                            println!("[Quick Share] Transfer CANCELLED by you.");
                                            crate::events::emit(serde_json::json!({ "type": "send_finished", "cancelled": true }));
                                            return Ok(());
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            let paused_for = pause_started.elapsed();
                            file_started += paused_for;
                            total_started += paused_for;
                            last_print = Instant::now();
                        }
                        _ => {}
                    }
                }

                let n = file.read(&mut chunk_buf)?;
                if n == 0 {
                    break;
                }

                // Phone control messages (keep-alive, cancel) checked every 4 chunks (~2 MB) or when KA is due
                chunks_since_poll += 1;
                if chunks_since_poll >= 4 || ctl.last_ka.elapsed() >= Duration::from_secs(4) {
                    chunks_since_poll = 0;
                    if let Some(ev) = ctl.poll_control(&mut socket, &mut channel).await? {
                        match ev {
                            Event::Disconnect => {
                                return Err("Phone ended the session during transfer (cancelled, or phone went to sleep)".into());
                            }
                            Event::Nearby(nf) => {
                                if nf.v1.as_ref().and_then(|x| x.r#type) == Some(nearby_v1::FrameType::Cancel as i32) {
                                    return Err("Phone CANCELLED the transfer".into());
                                }
                            }
                        }
                    }
                }

                // Direct streaming without per-chunk timer wheel overhead
                send_file_chunk(
                    &mut socket,
                    &mut channel,
                    f.payload_id,
                    f.size as i64,
                    file_sent as i64,
                    &chunk_buf[..n],
                    false,
                    &f.name,
                    &f.parent_folder,
                ).await?;
                file_sent += n as u64;
                cumulative_sent += n as u64;

                if last_print.elapsed() >= Duration::from_millis(400) {
                    let file_pct = if f.size > 0 { file_sent as f64 / f.size as f64 * 100.0 } else { 100.0 };
                    let total_pct = if total_all_bytes > 0 { cumulative_sent as f64 / total_all_bytes as f64 * 100.0 } else { 100.0 };
                    let secs = file_started.elapsed().as_secs_f64().max(0.001);
                    let speed = file_sent as f64 / 1_048_576.0 / secs;
                    crate::events::emit(serde_json::json!({
                        "type": "progress", "dir": "tx", "name": f.name,
                        "pct": total_pct.min(100.0), "mbps": speed, "file_index": idx + 1, "files": total_files,
                    }));

                    if total_files > 1 {
                        print!(
                            "\r[Quick Share] File: {:.1}% | Total: {:.1}% | {:.1} MB/s ({:.1}/{:.1} MB)   ",
                            file_pct.min(100.0),
                            total_pct.min(100.0),
                            speed,
                            cumulative_sent as f64 / 1_048_576.0,
                            total_all_bytes as f64 / 1_048_576.0
                        );
                    } else {
                        print!(
                            "\r[Quick Share] Sending: {:.1}%  {:.1} MB/s  ({:.1}/{:.1} MB)   ",
                            file_pct.min(100.0),
                            speed,
                            file_sent as f64 / 1_048_576.0,
                            f.size as f64 / 1_048_576.0
                        );
                    }
                    let _ = std::io::stdout().flush();
                    last_print = Instant::now();
                }
            }
            send_file_chunk(
                &mut socket,
                &mut channel,
                f.payload_id,
                f.size as i64,
                file_sent as i64,
                &[],
                true,
                &f.name,
                &f.parent_folder,
            ).await?;
            socket.flush().await?;

            let secs = file_started.elapsed().as_secs_f64().max(0.001);
            let mb = file_sent as f64 / 1_048_576.0;
            println!("\n [Quick Share] Finished {}: {:.2} MB in {:.2}s ({:.1} MB/s)", f.name, mb, secs, mb / secs);
        }

        let total_secs = total_started.elapsed().as_secs_f64().max(0.001);
        let total_mb = cumulative_sent as f64 / 1_048_576.0;
        println!("\n============================================================");
        if cumulative_sent == total_all_bytes {
            println!(" [Quick Share] All {} file(s) sent successfully.", total_files);
        } else {
            println!(" [Quick Share] WARNING: sent {} of {} bytes", cumulative_sent, total_all_bytes);
        }
        println!(" [*] Total Sent:  {:.2} MB in {:.2}s", total_mb, total_secs);
        println!(" [*] Avg Speed:   {:.1} MB/s ({:.0} Mbps)", total_mb / total_secs, (total_mb / total_secs) * 8.0);
        crate::events::emit(serde_json::json!({
            "type": "send_done", "mb": total_mb, "secs": total_secs, "mbps": total_mb / total_secs,
        }));
        println!("============================================================");

        // Gracefully notify phone that transfer is complete via official Google Nearby DISCONNECTION frame
        println!("[Quick Share] All files sent. Finalizing session with phone...");
        let _ = send_disconnection(&mut socket, &mut channel).await;
        // Wait briefly for the phone to process DISCONNECTION and close its socket
        let mut probe = [0u8; 16];
        let _ = tokio::time::timeout(Duration::from_millis(500), socket.read(&mut probe)).await;
        let _ = socket.shutdown().await;
        println!("[Quick Share] Done.");
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

enum Event {
    Nearby(nearby::Frame),
    Disconnect,
}

/// Reads encrypted frames, answers keep-alives, sends our own keep-alives every 5 s,
/// reassembles BYTES payloads and logs everything the phone sends (for debugging).
struct ControlReader {
    buffers: HashMap<i64, Vec<u8>>,
    last_ka: Instant,
}

impl ControlReader {
    fn new() -> Self {
        Self {
            buffers: HashMap::new(),
            last_ka: Instant::now(),
        }
    }

    async fn next_event(
        &mut self,
        socket: &mut TcpStream,
        channel: &mut SecureSessionChannel,
    ) -> Result<Event, BoxErr> {
        let ka_interval = Duration::from_secs(5);
        loop {
            let sleep_dur = ka_interval.saturating_sub(self.last_ka.elapsed());
            let tick = tokio::select! {
                _ = tokio::time::sleep(sleep_dur) => true,
                r = socket.readable() => { r?; false }
            };
            if tick {
                send_keepalive(socket, channel, false).await?;
                self.last_ka = Instant::now();
                continue;
            }

            let raw = read_frame(socket).await?;
            if let Some(ev) = self.handle_frame(socket, channel, raw).await? {
                return Ok(ev);
            }
        }
    }

    /// Transfer cholar somoy chunk-er majhe majhe call hoy: kono block kore na.
    /// Keep-alive due hole pathay, phone er pending frame gulo pore.
    async fn poll_control(
        &mut self,
        socket: &mut TcpStream,
        channel: &mut SecureSessionChannel,
    ) -> Result<Option<Event>, BoxErr> {
        if self.last_ka.elapsed() >= Duration::from_secs(5) {
            send_keepalive(socket, channel, false).await?;
            self.last_ka = Instant::now();
        }
        let mut probe = [0u8; 1];
        for _ in 0..4 {
            match tokio::time::timeout(Duration::ZERO, socket.peek(&mut probe)).await {
                Ok(Ok(n)) if n > 0 => {
                    let raw = read_frame(socket).await?;
                    if let Some(ev) = self.handle_frame(socket, channel, raw).await? {
                        return Ok(Some(ev));
                    }
                }
                Ok(Ok(_)) => return Err("Phone closed the connection (EOF) during transfer".into()),
                Ok(Err(e)) => return Err(map_eof(e)),
                Err(_) => break, // kichu pending nei
            }
        }
        Ok(None)
    }

    /// Ekta encrypted frame handle kore. Keep-alive ekhanei answer hoy.
    async fn handle_frame(
        &mut self,
        socket: &mut TcpStream,
        channel: &mut SecureSessionChannel,
        raw: Vec<u8>,
    ) -> Result<Option<Event>, BoxErr> {
        let plain = channel.decrypt_secure_message(&raw)?;
        let off = OfflineFrame::decode(&plain[..])?;
        let v1 = match off.v1 {
            Some(v) => v,
            None => return Ok(None),
        };

        if v1.r#type == Some(v1_frame::FrameType::Disconnection as i32) {
            println!("[debug] phone -> DISCONNECTION");
            return Ok(Some(Event::Disconnect));
        }

        if v1.r#type == Some(v1_frame::FrameType::KeepAlive as i32) || v1.keep_alive.is_some() {
            let is_ack = v1.keep_alive.and_then(|k| k.ack).unwrap_or(false);
            if !is_ack {
                send_keepalive(socket, channel, true).await?;
            }
            return Ok(None);
        }

        if let Some(pt) = v1.payload_transfer {
            let header = pt.payload_header.unwrap_or_default();
            let chunk = pt.payload_chunk.unwrap_or_default();
            let id = header.id.unwrap_or(0);
            let is_last = (chunk.flags.unwrap_or(0) & 1) != 0;

            if header.r#type == Some(payload_transfer_frame::payload_header::PayloadType::Bytes as i32) {
                let buf = self.buffers.entry(id).or_insert_with(Vec::new);
                if let Some(body) = chunk.body {
                    buf.extend_from_slice(&body);
                }
                if is_last {
                    let data = self.buffers.remove(&id).unwrap_or_default();
                    match nearby::Frame::decode(&data[..]) {
                        Ok(nf) => {
                            println!(
                                "[debug] phone -> nearby frame type {:?} ({} bytes)",
                                nf.v1.as_ref().and_then(|v| v.r#type),
                                data.len()
                            );
                            return Ok(Some(Event::Nearby(nf)));
                        }
                        Err(e) => {
                            println!("[debug] phone -> undecodable control payload ({} bytes): {:?}", data.len(), e);
                        }
                    }
                }
            }
            return Ok(None);
        }

        println!("[debug] phone -> other offline frame type {:?}", v1.r#type);
        Ok(None)
    }
}

fn map_eof(e: std::io::Error) -> BoxErr {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        "Phone closed the connection (EOF) without a Disconnection frame".into()
    } else {
        Box::new(e)
    }
}

async fn read_frame(socket: &mut TcpStream) -> Result<Vec<u8>, BoxErr> {
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await.map_err(map_eof)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 16 * 1024 * 1024 {
        return Err(format!("Bad frame length {}", len).into());
    }
    let mut buf = vec![0u8; len];
    socket.read_exact(&mut buf).await.map_err(map_eof)?;
    Ok(buf)
}

/// Writes length prefix + body without allocating a temporary 512 KB wrapper Vec.
async fn write_frame(socket: &mut TcpStream, body: &[u8]) -> Result<(), BoxErr> {
    socket.write_all(&(body.len() as u32).to_be_bytes()).await?;
    socket.write_all(body).await?;
    Ok(())
}

async fn send_keepalive(
    socket: &mut TcpStream,
    channel: &mut SecureSessionChannel,
    ack: bool,
) -> Result<(), BoxErr> {
    let frame = OfflineFrame {
        version: Some(offline_frame::Version::V1 as i32),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::KeepAlive as i32),
            keep_alive: Some(connections::KeepAliveFrame {
                ack: Some(ack),
                ..Default::default()
            }),
            ..Default::default()
        }),
    };
    let enc = channel.encrypt_secure_message(&frame.encode_to_vec())?;
    write_frame(socket, &enc).await
}

fn file_type_and_mime(ext: &str) -> (i32, &'static str) {
    match ext {
        "jpg" | "jpeg" => (1, "image/jpeg"),
        "png" => (1, "image/png"),
        "gif" => (1, "image/gif"),
        "webp" => (1, "image/webp"),
        "mp4" => (2, "video/mp4"),
        "mkv" => (2, "video/x-matroska"),
        "mov" => (2, "video/quicktime"),
        "avi" => (2, "video/x-msvideo"),
        "webm" => (2, "video/webm"),
        "apk" => (3, "application/vnd.android.package-archive"),
        "mp3" => (4, "audio/mpeg"),
        "flac" => (4, "audio/flac"),
        "wav" => (4, "audio/wav"),
        "aac" => (4, "audio/aac"),
        "ogg" => (4, "audio/ogg"),
        "pdf" => (5, "application/pdf"),
        "txt" => (5, "text/plain"),
        "zip" => (5, "application/zip"),
        "doc" => (5, "application/msword"),
        "docx" => (5, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        _ => (0, "application/octet-stream"),
    }
}

async fn send_file_chunk(
    socket: &mut TcpStream,
    channel: &mut SecureSessionChannel,
    payload_id: i64,
    total_size: i64,
    offset: i64,
    body: &[u8],
    last: bool,
    name: &str,
    parent_folder: &str,
) -> Result<(), BoxErr> {
    let frame = OfflineFrame {
        version: Some(offline_frame::Version::V1 as i32),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::PayloadTransfer as i32),
            payload_transfer: Some(PayloadTransferFrame {
                packet_type: Some(payload_transfer_frame::PacketType::Data as i32),
                payload_header: Some(payload_transfer_frame::PayloadHeader {
                    id: Some(payload_id),
                    r#type: Some(payload_transfer_frame::payload_header::PayloadType::File as i32),
                    total_size: Some(total_size),
                    is_sensitive: Some(false),
                    file_name: Some(name.to_string()),
                    parent_folder: if parent_folder.is_empty() { None } else { Some(parent_folder.to_string()) },
                    ..Default::default()
                }),
                payload_chunk: Some(payload_transfer_frame::PayloadChunk {
                    flags: Some(if last { 1 } else { 0 }),
                    offset: Some(offset),
                    body: Some(body.to_vec()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    };
    let enc = channel.encrypt_secure_message(&frame.encode_to_vec())?;
    write_frame(socket, &enc).await
}

/// Sends a BYTES control payload as two packets: data (flags=0), then empty LAST_CHUNK (flags=1).
async fn send_encrypted_payload_frame(
    socket: &mut TcpStream,
    channel: &mut SecureSessionChannel,
    payload_id: i64,
    data: &[u8],
) -> Result<(), BoxErr> {
    let total = data.len() as i64;
    let packets: [(i64, i32, Vec<u8>); 2] = [(0, 0, data.to_vec()), (total, 1, Vec::new())];

    for (offset, flags, body) in packets {
        let frame = OfflineFrame {
            version: Some(offline_frame::Version::V1 as i32),
            v1: Some(V1Frame {
                r#type: Some(v1_frame::FrameType::PayloadTransfer as i32),
                payload_transfer: Some(PayloadTransferFrame {
                    packet_type: Some(payload_transfer_frame::PacketType::Data as i32),
                    payload_header: Some(payload_transfer_frame::PayloadHeader {
                        id: Some(payload_id),
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
                }),
                ..Default::default()
            }),
        };
        let enc = channel.encrypt_secure_message(&frame.encode_to_vec())?;
        write_frame(socket, &enc).await?;
    }
    Ok(())
}

/// Cancels the current transfer the way Nearby Connections does:
///  1. connection layer: PAYLOAD_CANCELED control message for the file in flight,
///  2. sharing layer:   Frame{ type: CANCEL },
///  3. then a DISCONNECTION frame.
async fn send_cancel(
    socket: &mut TcpStream,
    channel: &mut SecureSessionChannel,
    payload_id: i64,
    total_size: i64,
    offset: i64,
) -> Result<(), BoxErr> {
    let ctrl = OfflineFrame {
        version: Some(offline_frame::Version::V1 as i32),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::PayloadTransfer as i32),
            payload_transfer: Some(PayloadTransferFrame {
                packet_type: Some(payload_transfer_frame::PacketType::Control as i32),
                payload_header: Some(payload_transfer_frame::PayloadHeader {
                    id: Some(payload_id),
                    r#type: Some(payload_transfer_frame::payload_header::PayloadType::File as i32),
                    total_size: Some(total_size),
                    is_sensitive: Some(false),
                    ..Default::default()
                }),
                control_message: Some(payload_transfer_frame::ControlMessage {
                    event: Some(payload_transfer_frame::control_message::EventType::PayloadCanceled as i32),
                    offset: Some(offset),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    };
    let enc = channel.encrypt_secure_message(&ctrl.encode_to_vec())?;
    write_frame(socket, &enc).await?;

    let cancel = nearby::Frame {
        version: Some(nearby::frame::Version::V1 as i32),
        v1: Some(nearby::V1Frame {
            r#type: Some(nearby_v1::FrameType::Cancel as i32),
            ..Default::default()
        }),
    };
    send_encrypted_payload_frame(socket, channel, payload_id.wrapping_add(1), &cancel.encode_to_vec()).await?;

    let _ = send_disconnection(socket, channel).await;
    Ok(())
}

/// Sends an encrypted DISCONNECTION frame to immediately transition the receiver's UI to "Done".
async fn send_disconnection(
    socket: &mut TcpStream,
    channel: &mut SecureSessionChannel,
) -> Result<(), BoxErr> {
    let disc = OfflineFrame {
        version: Some(offline_frame::Version::V1 as i32),
        v1: Some(V1Frame {
            r#type: Some(v1_frame::FrameType::Disconnection as i32),
            disconnection: Some(connections::DisconnectionFrame {
                request_safe_to_disconnect: Some(false),
                ack_safe_to_disconnect: Some(false),
            }),
            ..Default::default()
        }),
    };
    let enc = channel.encrypt_secure_message(&disc.encode_to_vec())?;
    write_frame(socket, &enc).await?;
    let _ = socket.flush().await;
    Ok(())
}

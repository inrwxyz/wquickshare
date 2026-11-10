use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::client::{QuickShareClient, SendItem};
use crate::events;
use crate::mdns::{self, DiscoveredDevice, MdnsAdvertiser};
use crate::server::{self, QuickShareServer};

pub struct QuickShareEngine {
    pub device_name: String,
    pub endpoint_id: [u8; 4],
    pub downloads_dir: PathBuf,
    pub running: AtomicBool,
    pub busy: AtomicBool,
    pub scan_stop: Mutex<Option<Arc<AtomicBool>>>,
    pub server_stop: Mutex<Option<Arc<AtomicBool>>>,
}

static ENGINE: OnceLock<Arc<QuickShareEngine>> = OnceLock::new();

pub fn get_engine() -> Arc<QuickShareEngine> {
    ENGINE
        .get_or_init(|| {
            let device_name = std::env::var("COMPUTERNAME")
                .unwrap_or_else(|_| "QuickShare-PC".to_string());
            let mut ep = [0u8; 4];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut ep);
            let downloads_dir = std::env::var("USERPROFILE")
                .map(|p| PathBuf::from(p).join("Downloads"))
                .unwrap_or_else(|_| PathBuf::from("C:\\Users\\Public\\Downloads"));
            Arc::new(QuickShareEngine {
                device_name,
                endpoint_id: ep,
                downloads_dir,
                running: AtomicBool::new(false),
                busy: AtomicBool::new(false),
                scan_stop: Mutex::new(None),
                server_stop: Mutex::new(None),
            })
        })
        .clone()
}

impl QuickShareEngine {
    pub fn new(device_name: Option<String>, downloads_dir: Option<PathBuf>) -> Self {
        let device_name = device_name.unwrap_or_else(|| {
            std::env::var("COMPUTERNAME").unwrap_or_else(|_| "QuickShare-PC".to_string())
        });
        let mut ep = [0u8; 4];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut ep);
        let downloads_dir = downloads_dir.unwrap_or_else(|| {
            std::env::var("USERPROFILE")
                .map(|p| PathBuf::from(p).join("Downloads"))
                .unwrap_or_else(|_| PathBuf::from("C:\\Users\\Public\\Downloads"))
        });

        Self {
            device_name,
            endpoint_id: ep,
            downloads_dir,
            running: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            scan_stop: Mutex::new(None),
            server_stop: Mutex::new(None),
        }
    }

    pub fn status(&self) -> serde_json::Value {
        let ip = mdns::current_lan_ip();
        let is_scanning = self.scan_stop.lock().map(|g| g.is_some()).unwrap_or(false);
        serde_json::json!({
            "running": self.running.load(Ordering::SeqCst),
            "busy": self.busy.load(Ordering::SeqCst),
            "device_name": self.device_name,
            "ip": ip.to_string(),
            "save_dir": self.downloads_dir.to_string_lossy(),
            "scanning": is_scanning,
        })
    }

    pub async fn start_server(&self, port: u16) -> Result<serde_json::Value, String> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(self.status());
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        if let Ok(mut g) = self.server_stop.lock() {
            *g = Some(stop_flag.clone());
        }

        let ip = mdns::current_lan_ip();

        let adv = Arc::new(MdnsAdvertiser::new(
            self.device_name.clone(),
            self.endpoint_id,
            port,
            ip,
        ));
        let adv_stop = stop_flag.clone();
        tokio::spawn(async move {
            let _ = adv.start_with_stop(adv_stop).await;
        });

        let srv = QuickShareServer::new(port, self.downloads_dir.clone());
        let srv_stop = stop_flag.clone();
        tokio::spawn(async move {
            let _ = srv.start_with_stop(srv_stop).await;
        });

        self.running.store(true, Ordering::SeqCst);

        events::emit(serde_json::json!({
            "type": "started",
            "name": self.device_name,
            "ip": ip.to_string(),
            "save_dir": self.downloads_dir.to_string_lossy(),
        }));

        Ok(self.status())
    }

    pub async fn stop_server(&self) -> Result<(), String> {
        if let Ok(mut g) = self.server_stop.lock() {
            if let Some(flag) = g.take() {
                flag.store(true, Ordering::SeqCst);
            }
        }
        self.stop_scan();
        self.running.store(false, Ordering::SeqCst);

        events::emit(serde_json::json!({ "type": "stopped" }));
        Ok(())
    }

    pub async fn start_scan(self: &Arc<Self>) -> Result<(), String> {
        let already = self.scan_stop.lock().map(|g| g.is_some()).unwrap_or(false);
        if !already {
            let flag = Arc::new(AtomicBool::new(false));
            if let Ok(mut g) = self.scan_stop.lock() {
                *g = Some(flag.clone());
            }
            let eng = self.clone();
            tokio::spawn(async move {
                events::emit(serde_json::json!({ "type": "scan_started" }));
                let ip = mdns::current_lan_ip();
                let _ = mdns::watch_devices(flag.clone(), ip, 52345, eng.device_name.clone()).await;
                if let Ok(mut g) = eng.scan_stop.lock() {
                    if g.as_ref().map(|f| Arc::ptr_eq(f, &flag)).unwrap_or(false) {
                        *g = None;
                    }
                }
                events::emit(serde_json::json!({ "type": "scan_stopped" }));
            });
        }
        Ok(())
    }

    pub fn stop_scan(&self) {
        if let Ok(mut g) = self.scan_stop.lock() {
            if let Some(f) = g.take() {
                f.store(true, Ordering::SeqCst);
            }
        }
    }

    pub fn respond_offer(accept: bool) {
        server::send_consent_decision(accept);
    }

    pub async fn send_files(
        self: &Arc<Self>,
        dev: DiscoveredDevice,
        paths: Vec<PathBuf>,
    ) -> Result<bool, String> {
        if self.busy.swap(true, Ordering::SeqCst) {
            return Err("Another transfer is currently in progress".into());
        }

        self.stop_scan();

        let eng = self.clone();
        tokio::spawn(async move {
            let mut items: Vec<SendItem> = Vec::new();
            for p in paths {
                if p.is_file() {
                    items.push(SendItem {
                        path: p,
                        parent_folder: String::new(),
                    });
                } else if p.is_dir() {
                    let root = p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("folder")
                        .to_string();
                    collect_folder_recursive(&p, &root, &mut items);
                }
            }

            if items.is_empty() {
                events::emit(serde_json::json!({
                    "type": "error", "message": "No valid files found to send."
                }));
                eng.busy.store(false, Ordering::SeqCst);
                return;
            }

            events::emit(serde_json::json!({
                "type": "send_started", "device": dev.name, "files": items.len()
            }));

            let client = QuickShareClient::new(eng.device_name.clone(), eng.endpoint_id);
            if let Err(e) = client.send_files(&dev, &items).await {
                events::emit(serde_json::json!({
                    "type": "error", "message": format!("{}", e)
                }));
            }
            events::emit(serde_json::json!({ "type": "send_finished" }));
            eng.busy.store(false, Ordering::SeqCst);
        });

        Ok(true)
    }
}

fn collect_folder_recursive(dir: &Path, rel_parent: &str, out: &mut Vec<SendItem>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                out.push(SendItem {
                    path: p,
                    parent_folder: rel_parent.to_string(),
                });
            } else if p.is_dir() {
                let sub = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("sub");
                let next_parent = format!("{}/{}", rel_parent, sub);
                collect_folder_recursive(&p, &next_parent, out);
            }
        }
    }
}

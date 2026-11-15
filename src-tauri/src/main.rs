// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::Ipv4Addr;
use std::path::PathBuf;
use tauri::{Emitter, Manager};
use wquickshare::console;
use wquickshare::engine::{get_engine, QuickShareEngine};
use wquickshare::events;
use wquickshare::mdns::DiscoveredDevice;

#[tauri::command]
fn get_status() -> serde_json::Value {
    let eng = get_engine();
    let mut st = eng.status();
    if let Some(obj) = st.as_object_mut() {
        obj.insert("port".to_string(), serde_json::json!(52345));
    }
    st
}

#[tauri::command]
async fn start_server() -> Result<serde_json::Value, String> {
    let eng = get_engine();
    eng.start_server(52345).await
}

#[tauri::command]
async fn stop_server() -> Result<(), String> {
    let eng = get_engine();
    eng.stop_server().await
}

#[tauri::command]
async fn start_scan() -> Result<(), String> {
    let eng = get_engine();
    eng.start_scan().await
}

#[tauri::command]
fn stop_scan() -> Result<(), String> {
    let eng = get_engine();
    eng.stop_scan();
    Ok(())
}

#[tauri::command]
fn respond_offer(accept: bool) {
    QuickShareEngine::respond_offer(accept);
}

#[tauri::command]
fn control_transfer(cmd: String) {
    if cmd == "p" || cmd == "r" || cmd == "c" {
        console::inject(&cmd);
    }
}

#[tauri::command]
async fn pick_files(window: tauri::WebviewWindow) -> Vec<String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("pick-files".into())
        .spawn(move || {
            let res = rfd::FileDialog::new()
                .set_title("Quick Share - Choose Files to Send")
                .set_parent(&window)
                .pick_files()
                .map(|paths| {
                    paths
                        .into_iter()
                        .map(|p| p.to_string_lossy().to_string())
                        .collect()
                })
                .unwrap_or_default();
            let _ = tx.send(res);
        })
        .ok();
    rx.await.unwrap_or_default()
}

#[tauri::command]
async fn pick_folder(window: tauri::WebviewWindow) -> Option<String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("pick-folder".into())
        .spawn(move || {
            let res = rfd::FileDialog::new()
                .set_title("Quick Share - Choose Folder to Send")
                .set_parent(&window)
                .pick_folder()
                .map(|p| p.to_string_lossy().to_string());
            let _ = tx.send(res);
        })
        .ok();
    rx.await.unwrap_or_default()
}

#[tauri::command]
async fn send_files(
    name: String,
    ip: String,
    port: u16,
    dev_type: u8,
    instance: String,
    paths: Vec<String>,
) -> Result<bool, String> {
    let eng = get_engine();
    let parsed_ip: Ipv4Addr = match ip.parse() {
        Ok(i) => i,
        Err(_) => return Err("Invalid IP address".into()),
    };
    if parsed_ip.is_unspecified() || port == 0 || paths.is_empty() {
        return Err("Missing target or paths".into());
    }

    let dev = DiscoveredDevice {
        name,
        ip: parsed_ip,
        port,
        device_type: dev_type,
        instance,
    };

    let pb_paths: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    eng.send_files(dev, pb_paths).await
}

#[tauri::command]
fn open_downloads() {
    let eng = get_engine();
    let dir = eng.downloads_dir.clone();
    let _ = std::process::Command::new("explorer").arg(dir).spawn();
}

#[cfg(windows)]
fn ensure_firewall() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    if let Ok(exe) = std::env::current_exe() {
        let exe_str = exe.to_string_lossy().to_string();
        let _ = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "add", "rule", "name=WQuickShare", "dir=in", "action=allow", &format!("program={}", exe_str), "enable=yes", "profile=any"])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
        let _ = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "add", "rule", "name=WQuickShare Port 52345", "dir=in", "action=allow", "protocol=TCP", "localport=52345", "enable=yes", "profile=any"])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
        let _ = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "add", "rule", "name=WQuickShare Port 5353", "dir=in", "action=allow", "protocol=UDP", "localport=5353", "enable=yes", "profile=any"])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
    }
}

fn main() {
    #[cfg(windows)]
    ensure_firewall();

    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle().clone();
            events::add_listener(move |evt| {
                let _ = handle.emit("qs-event", evt);
                if let Some(w) = handle.get_webview_window("main") {
                    if evt.get("type").and_then(|t| t.as_str()) == Some("offer") {
                        let _ = w.show();
                        let _ = w.unminimize();
                        let _ = w.set_focus();
                    }
                }
            });

            // Automatically start receiver server on launch
            tauri::async_runtime::spawn(async {
                let eng = get_engine();
                let _ = eng.start_server(52345).await;
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_server,
            stop_server,
            start_scan,
            stop_scan,
            respond_offer,
            control_transfer,
            pick_files,
            pick_folder,
            send_files,
            open_downloads
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

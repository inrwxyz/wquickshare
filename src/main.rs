use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncBufReadExt;

use wquickshare::console;
use wquickshare::engine::QuickShareEngine;
use wquickshare::events;
use wquickshare::mdns::{self, DiscoveredDevice};

#[derive(Parser, Debug)]
#[command(
    name = "wquickshare",
    about = "Native Windows Quick Share / Nearby Share CLI & Library (Pure Rust, Headless)",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Receive files from nearby devices (Android, Windows, ChromeOS)
    #[command(alias = "listen", alias = "rx")]
    Receive {
        /// Port to listen on
        #[arg(short, long, default_value_t = 52345)]
        port: u16,

        /// Custom visible device name (defaults to PC name)
        #[arg(short, long)]
        name: Option<String>,

        /// Destination directory for received files
        #[arg(short, long)]
        dir: Option<PathBuf>,

        /// Automatically accept all incoming transfers without confirmation prompt
        #[arg(long, default_value_t = false)]
        auto_accept: bool,
    },

    /// Scan for nearby Quick Share / Nearby Share devices
    Scan {
        /// Timeout in seconds to scan for devices (0 for indefinite)
        #[arg(short, long, default_value_t = 15)]
        timeout: u64,
    },

    /// Send files to a target device (ip:port)
    Send {
        /// Target device in format IP:PORT (e.g. 192.168.1.50:52345)
        target: String,

        /// Files or folders to send
        #[arg(required = true)]
        files: Vec<PathBuf>,

        /// Sender device name
        #[arg(short, long)]
        name: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Receive {
            port,
            name,
            dir,
            auto_accept,
        } => {
            run_receiver(port, name, dir, auto_accept).await?;
        }
        Commands::Scan { timeout } => {
            run_scanner(timeout).await?;
        }
        Commands::Send {
            target,
            files,
            name,
        } => {
            run_sender(target, files, name).await?;
        }
    }

    Ok(())
}

async fn run_receiver(
    port: u16,
    name: Option<String>,
    dir: Option<PathBuf>,
    auto_accept: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let engine = Arc::new(QuickShareEngine::new(name, dir));

    // Register event listener for pretty CLI output
    events::add_listener(move |evt| {
        if let Some(t) = evt.get("type").and_then(|v| v.as_str()) {
            match t {
                "started" => {
                    let dev = evt.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                    let ip = evt.get("ip").and_then(|v| v.as_str()).unwrap_or("0.0.0.0");
                    let save = evt.get("save_dir").and_then(|v| v.as_str()).unwrap_or("");
                    println!("\n=======================================================");
                    println!("🚀 Quick Share Server Running");
                    println!("   Device Name : {}", dev);
                    println!("   IP Address  : {}", ip);
                    println!("   Saving to   : {}", save);
                    println!("=======================================================");
                    println!("Waiting for incoming connections... (Press Ctrl+C to stop)\n");
                }
                "rx_pin" => {
                    if let Some(pin) = evt.get("pin").and_then(|v| v.as_str()) {
                        println!("🔑 Pairing PIN: [{}]", pin);
                    }
                }
                "offer" => {
                    let dev = evt.get("device").and_then(|v| v.as_str()).unwrap_or("Device");
                    let total_bytes = evt.get("total_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                    let mb = (total_bytes as f64) / (1024.0 * 1024.0);

                    println!("\n📥 Incoming transfer offer from: {}", dev);
                    if let Some(files) = evt.get("files").and_then(|v| v.as_array()) {
                        println!("   Files ({}):", files.len());
                        for f in files {
                            let fname = f.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                            let fsize = f.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                            let fmb = (fsize as f64) / (1024.0 * 1024.0);
                            println!("     • {} ({:.2} MB)", fname, fmb);
                        }
                    }
                    println!("   Total Size: {:.2} MB", mb);

                    if auto_accept {
                        println!("   ⚡ Auto-accepting transfer...");
                        QuickShareEngine::respond_offer(true);
                    } else {
                        print!("   👉 Accept transfer? [Y/n]: ");
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                    }
                }
                "progress" => {
                    let percent = evt.get("percent").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let speed = evt.get("speed_mbps").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let cur = evt.get("file_index").and_then(|v| v.as_u64()).unwrap_or(1);
                    let total = evt.get("file_count").and_then(|v| v.as_u64()).unwrap_or(1);
                    print!(
                        "\r⏳ Receiving [{}/{}]: {:5.1}% ({:6.2} MB/s) [p:pause, c:cancel] ",
                        cur, total, percent, speed
                    );
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
                "rx_finished" => {
                    println!("\n✅ Transfer completed successfully!");
                }
                "error" => {
                    let msg = evt.get("message").and_then(|v| v.as_str()).unwrap_or("Unknown error");
                    println!("\n❌ Transfer error: {}", msg);
                }
                "status" => {
                    let text = evt.get("text").and_then(|v| v.as_str()).unwrap_or("");
                    let level = evt.get("level").and_then(|v| v.as_str()).unwrap_or("info");
                    println!("[{}] {}", level.to_uppercase(), text);
                }
                _ => {}
            }
        }
    });

    // Start engine server
    engine.start_server(port).await?;

    // Interactive terminal line reader for accept/decline and pause/resume
    console::init();

    let mut stdin_reader = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            line = stdin_reader.next_line() => {
                match line {
                    Ok(Some(text)) => {
                        let trimmed = text.trim();
                        if trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes") || trimmed.is_empty() {
                            QuickShareEngine::respond_offer(true);
                        } else if trimmed.eq_ignore_ascii_case("n") || trimmed.eq_ignore_ascii_case("no") {
                            QuickShareEngine::respond_offer(false);
                        } else if trimmed.eq_ignore_ascii_case("p") {
                            console::inject("p");
                        } else if trimmed.eq_ignore_ascii_case("r") {
                            console::inject("r");
                        } else if trimmed.eq_ignore_ascii_case("c") {
                            console::inject("c");
                        }
                    }
                    _ => break,
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\n🛑 Shutting down server...");
                engine.stop_server().await?;
                break;
            }
        }
    }

    Ok(())
}

async fn run_scanner(timeout: u64) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Scanning for nearby Quick Share devices...");
    println!("Make sure Nearby Share / Quick Share is set to 'Everyone' on your phone/PC.\n");

    let flag = Arc::new(AtomicBool::new(false));
    let flag_clone = flag.clone();

    events::add_listener(|evt| {
        if let Some(t) = evt.get("type").and_then(|v| v.as_str()) {
            if t == "device_found" {
                let name = evt.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let ip = evt.get("ip").and_then(|v| v.as_str()).unwrap_or("0.0.0.0");
                let port = evt.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                let dev_type = evt.get("device_type").and_then(|v| v.as_u64()).unwrap_or(0);
                let type_str = match dev_type {
                    1 => "Phone",
                    2 => "Tablet",
                    3 => "Laptop/PC",
                    _ => "Device",
                };
                println!(" ✨ Found [{}]: {} ({}:{})", type_str, name, ip, port);
            }
        }
    });

    let ip = mdns::current_lan_ip();
    let scan_handle = tokio::spawn(async move {
        let _ = mdns::watch_devices(flag_clone, ip, 52345, "Scanner".to_string()).await;
    });

    if timeout > 0 {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(timeout)) => {
                flag.store(true, Ordering::SeqCst);
                println!("\n⏱️ Scan timeout reached.");
            }
            _ = tokio::signal::ctrl_c() => {
                flag.store(true, Ordering::SeqCst);
                println!("\n🛑 Scan stopped.");
            }
        }
    } else {
        println!("Press Ctrl+C to stop scanning.");
        let _ = tokio::signal::ctrl_c().await;
        flag.store(true, Ordering::SeqCst);
    }

    let _ = scan_handle.await;
    Ok(())
}

async fn run_sender(
    target: String,
    files: Vec<PathBuf>,
    name: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = target.split(':').collect();
    if parts.len() != 2 {
        return Err("Target must be in format IP:PORT (e.g. 192.168.1.50:52345)".into());
    }
    let ip: std::net::Ipv4Addr = parts[0].parse()?;
    let port: u16 = parts[1].parse()?;

    let device_name = name.unwrap_or_else(|| {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "QuickShare-PC".to_string())
    });

    let dev = DiscoveredDevice {
        name: format!("Target-{}", ip),
        ip,
        port,
        device_type: 1,
        instance: String::new(),
    };

    println!("📤 Preparing to send {} item(s) to {}:{}...", files.len(), ip, port);

    let engine = Arc::new(QuickShareEngine::new(Some(device_name), None));

    events::add_listener(|evt| {
        if let Some(t) = evt.get("type").and_then(|v| v.as_str()) {
            match t {
                "send_pin" => {
                    let pin = evt.get("pin").and_then(|v| v.as_str()).unwrap_or("----");
                    println!("🔑 Verification PIN: [{}]", pin);
                    println!("Please verify that this PIN matches on the receiving device.");
                }
                "send_waiting" => {
                    println!("⏳ Waiting for receiver to accept transfer...");
                }
                "send_accepted" => {
                    println!("✅ Transfer accepted! Sending data...");
                }
                "progress" => {
                    let percent = evt.get("percent").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let speed = evt.get("speed_mbps").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    print!("\r🚀 Sending: {:5.1}% ({:6.2} MB/s) ", percent, speed);
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
                "send_finished" => {
                    let cancelled = evt.get("cancelled").and_then(|v| v.as_bool()).unwrap_or(false);
                    if cancelled {
                        println!("\n⚠️ Transfer was cancelled or declined.");
                    } else {
                        println!("\n🎉 Transfer completed successfully!");
                    }
                }
                "error" => {
                    let msg = evt.get("message").and_then(|v| v.as_str()).unwrap_or("Error");
                    println!("\n❌ Transfer error: {}", msg);
                }
                _ => {}
            }
        }
    });

    engine.send_files(dev, files).await?;

    // Wait until send finished
    while engine.busy.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    Ok(())
}

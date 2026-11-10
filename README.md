# ⚡ wquickshare

A lightweight, native Rust implementation of Quick Share (Nearby Share) for Windows. Send and receive files between your PC and Android phones, fully compatible with the official Quick Share.

Use it as a command-line tool, or embed it in your own Rust app as a library.

> Unofficial project, not affiliated with Google. Quick Share is a trademark of Google LLC.

---

## Features

- Works with the official Quick Share on Android, Windows and ChromeOS
- Receive (`receive`) and send (`send`) files and whole folders
- End-to-end encrypted (UKEY2 handshake, AES-256-CBC, HMAC-SHA256)
- Device discovery over mDNS, plus BLE Fast Initiation to wake up nearby Android phones
- Live progress, transfer speed, pairing PIN prompt, and pause / resume / cancel
- Small single binary, no GUI, no WebView
- Event bus for integrating into your own apps and scripts

> **Note on speed:** transfers run over your existing Wi-Fi network (TCP) without the Wi-Fi Direct / hotspot bandwidth upgrade the official app uses, so speed is somewhat lower than the official Quick Share (typically around 2-3 MB/s in testing).

---

## Quick Start

### Build from source

Install [Rust](https://rustup.rs/), then:

```bash
cargo build --release
```

The binary will be at `target/release/wquickshare.exe`.

Pre-built binaries are available on the Releases page.

### Receive files

Make your PC visible to nearby Quick Share devices:

```bash
# Default port 52345, saves to ~/Downloads
wquickshare receive

# Custom device name and save folder
wquickshare receive --name "My Office PC" --dir "D:\Shared"

# Accept transfers without the confirmation prompt
wquickshare receive --auto-accept
```

### Scan for nearby devices

```bash
wquickshare scan --timeout 15
```

### Send files or folders

```bash
wquickshare send 192.168.1.150:52345 photo.jpg document.pdf "My Folder"
```

---

## Using as a Rust library

Add it to your `Cargo.toml`:

```toml
[dependencies]
wquickshare = { path = "../wquickshare" }
```

Example: start a receiver.

```rust
use std::path::PathBuf;
use std::sync::Arc;
use wquickshare::{QuickShareEngine, events};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Subscribe to events
    events::add_listener(|evt| {
        println!("QuickShare Event: {:?}", evt);
    });

    // Create the engine
    let engine = Arc::new(QuickShareEngine::new(
        Some("Rust Receiver".to_string()),
        Some(PathBuf::from(r"C:\Downloads")),
    ));

    // Start the server and mDNS advertising
    engine.start_server(52345).await?;

    tokio::signal::ctrl_c().await?;
    engine.stop_server().await?;

    Ok(())
}
```

---

## Project layout

```
wquickshare/
├── Cargo.toml
├── build.rs            # Compiles the protocol buffers
├── proto/              # Quick Share wire protocol definitions (Google, Apache-2.0)
└── src/
    ├── ble.rs          # BLE Fast Initiation advertiser (WinRT)
    ├── client.rs       # Outgoing file transfers
    ├── console.rs      # Terminal input (pause / resume / cancel)
    ├── crypto.rs       # UKEY2 handshake, ECDH, AES-256-CBC, HMAC-SHA256
    ├── engine.rs       # High-level QuickShareEngine API
    ├── events.rs       # Event bus
    ├── lib.rs          # Library exports
    ├── main.rs         # Command-line interface
    ├── mdns.rs         # mDNS advertiser and scanner
    ├── protos.rs       # Generated protobuf bindings
    └── server.rs       # Incoming connections and file receiver
```

---

## Third-party

The protocol definitions in `proto/` come from Google's Nearby project and are licensed under the Apache License 2.0. Their original license headers are kept unchanged.

---

## License

GPL-3.0-or-later. See the `LICENSE` file.

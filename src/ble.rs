//! BLE "Fast Initiation" beacon (service UUID 0xFE2C).
//!
//! What the open-source nearby repo tells us (sharing/internal/api/fast_init_ble_beacon.h):
//!   * service UUID  = 0xFE2C
//!   * model id      = fc 12 8e
//!   * metadata byte = [ version (3 bits) | type (3 bits) | uwb_supported (1) | sender_cert_supported (1) ]
//!                     type: kNotify = 0, kSilent = 1
//!   * then one byte "adjusted_tx_power"
//!
//! What it does NOT contain: the platform code that actually serialises the beacon on Windows.
//! So the exact bytes a phone reacts to are a hypothesis. We therefore rotate through a few
//! plausible profiles and print which one is on air, and you can force one with:
//!     set QS_FASTINIT_HEX=fc128e0000        (service data AFTER the 2-byte UUID, hex)
//!
//! The beacon only wakes up nearby phones; the actual file transfer still goes over Wi-Fi LAN.
//! If Bluetooth is missing/off, `start()` returns Err and the caller falls back to Wi-Fi-only discovery.

pub struct FastInitBeacon {
    stop_tx: Option<std::sync::mpsc::Sender<()>>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl FastInitBeacon {
    pub fn start() -> Result<FastInitBeacon, String> {
        imp::start()
    }
}

impl Drop for FastInitBeacon {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).ok()?;
        out.push(u8::from_str_radix(pair, 16).ok()?);
    }
    Some(out)
}

/// Service-data payloads (after the 2-byte UUID) that will be tried, in order.
fn profiles() -> Vec<(String, Vec<u8>)> {
    if let Ok(h) = std::env::var("QS_FASTINIT_HEX") {
        if let Some(bytes) = parse_hex(&h) {
            return vec![(format!("custom {}", h), bytes)];
        }
    }
    let model = [0xfc, 0x12, 0x8e];
    let mut v = Vec::new();
    // metadata: notify = 0x00, silent = 0x04 (type bits are shifted by 2)
    for (type_name, meta) in [("notify", 0x00u8), ("silent", 0x04u8)] {
        for tx in [0x00u8, 0xF2u8] {
            let mut b = model.to_vec();
            b.push(meta);
            b.push(tx);
            v.push((format!("{} / tx 0x{:02X}", type_name, tx), b));
        }
    }
    v
}

#[cfg(all(windows, feature = "ble"))]
mod imp {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    use windows::Devices::Bluetooth::Advertisement::{
        BluetoothLEAdvertisementDataSection, BluetoothLEAdvertisementPublisher,
        BluetoothLEAdvertisementPublisherStatus,
    };
    use windows::Storage::Streams::DataWriter;
    use windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED};

    fn build_publisher(payload: &[u8]) -> windows::core::Result<BluetoothLEAdvertisementPublisher> {
        let publisher = BluetoothLEAdvertisementPublisher::new()?;
        let section = BluetoothLEAdvertisementDataSection::new()?;
        section.SetDataType(0x16)?; // AD type: Service Data - 16-bit UUID
        let writer = DataWriter::new()?;
        let mut data = vec![0x2C, 0xFE]; // UUID 0xFE2C, little endian
        data.extend_from_slice(payload);
        writer.WriteBytes(&data)?;
        section.SetData(&writer.DetachBuffer()?)?;
        publisher.Advertisement()?.DataSections()?.Append(&section)?;
        Ok(publisher)
    }

    pub fn start() -> Result<FastInitBeacon, String> {
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();

        let join = std::thread::spawn(move || {
            // WinRT objects stay on this one thread.
            let _ = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };

            let profiles = super::profiles();
            let mut idx = 0usize;
            let mut announced_ready = false;

            loop {
                let (label, payload) = &profiles[idx % profiles.len()];
                idx += 1;

                let publisher = match build_publisher(payload) {
                    Ok(p) => p,
                    Err(e) => {
                        if !announced_ready {
                            let _ = ready_tx.send(Err(format!("BLE advertisement setup failed: {}", e)));
                        }
                        return;
                    }
                };
                if let Err(e) = publisher.Start() {
                    if !announced_ready {
                        let _ = ready_tx.send(Err(format!("BLE advertisement start failed: {}", e)));
                    }
                    return;
                }

                // Give Windows a moment, then check that the radio really accepted it.
                std::thread::sleep(Duration::from_millis(400));
                if let Ok(st) = publisher.Status() {
                    if st == BluetoothLEAdvertisementPublisherStatus::Aborted {
                        if !announced_ready {
                            let _ = ready_tx.send(Err("Bluetooth radio is off or unavailable (publisher aborted)".to_string()));
                        }
                        return;
                    }
                }
                if !announced_ready {
                    announced_ready = true;
                    let _ = ready_tx.send(Ok(()));
                }
                println!("\r[BLE] Fast-init beacon on air: {}                    ", label);

                // Stay on this profile for 3 s (or until told to stop).
                match stop_rx.recv_timeout(Duration::from_secs(3)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                        let _ = publisher.Stop();
                        return;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        let _ = publisher.Stop();
                    }
                }
            }
        });

        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(FastInitBeacon { stop_tx: Some(stop_tx), join: Some(join) }),
            Ok(Err(e)) => {
                let _ = join.join();
                Err(e)
            }
            Err(_) => Err("BLE beacon did not start in time".to_string()),
        }
    }
}

#[cfg(not(all(windows, feature = "ble")))]
mod imp {
    use super::*;

    pub fn start() -> Result<FastInitBeacon, String> {
        // `profiles` is used by the real build; reference it so this build stays warning-free.
        let _ = super::profiles();
        Err("BLE beacon is not compiled in (Windows + `ble` feature required)".to_string())
    }
}

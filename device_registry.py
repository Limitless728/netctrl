"""
device_registry.py
==================
Thread-safe state management for discovered LAN devices.

Tracks per-device:
 - ip, mac, name (hostname guess)
 - dl_bytes / ul_bytes  : cumulative byte counters (since registration)
 - dl_speed / ul_speed  : last-computed bytes/sec (refreshed by tick_speeds())
 - is_monitored         : whether the engine is currently ARP-spoofing this host
 - first_seen / last_seen

CRITICAL invariants:
 * All mutation goes through the internal Lock (`self._lock`).
 * Newly-registered devices default to is_monitored = True
   (per blueprint section 3.C "Auto-Start").
 * Lookups by IP and MAC are O(1) via secondary indexes so the
   hot path in l2_capture.py never has to iterate.
"""

import threading
import time
from typing import Dict, List, Optional


class DeviceRegistry:
    def __init__(self):
        # Primary store keyed by MAC (lowercase, canonical form)
        self._devices: Dict[str, dict] = {}
        # Secondary index: ip -> mac
        self._ip_index: Dict[str, str] = {}
        self._lock = threading.RLock()
        # Timestamp of the last tick_speeds() call, used to compute deltas
        self._last_tick = time.time()

    # ------------------------------------------------------------------
    # Registration / discovery
    # ------------------------------------------------------------------
    def register(self, ip: str, mac: str, name: str = "") -> bool:
        """
        Register a newly-discovered device. Returns True if this is a *new*
        device, False if it was already known.

        Per blueprint 3.C the device is auto-monitored on first sight.
        """
        mac = mac.lower()
        with self._lock:
            if mac in self._devices:
                # Already known – just refresh last_seen and IP (DHCP may move it)
                dev = self._devices[mac]
                if dev["ip"] != ip:
                    # IP changed – update reverse index
                    self._ip_index.pop(dev["ip"], None)
                    dev["ip"] = ip
                    self._ip_index[ip] = mac
                dev["last_seen"] = time.time()
                return False

            now = time.time()
            self._devices[mac] = {
                "ip": ip,
                "mac": mac,
                "name": name or f"device-{mac[-5:].replace(':', '')}",
                "dl_bytes": 0,
                "ul_bytes": 0,
                "_prev_dl": 0,
                "_prev_ul": 0,
                "dl_speed": 0.0,  # bytes/sec
                "ul_speed": 0.0,
                "is_monitored": True,
                "unmonitored_at": 0.0,  # Timestamp when monitoring was disabled
                "is_blocked": False,
                "speed_limit": None,    # bytes/sec
                "tokens": 0.0,          # Current tokens in bucket
                "last_update": now,     # Last time tokens were added
                "first_seen": now,
                "last_seen": now,
            }
            self._ip_index[ip] = mac
            print(f"[REGISTRY] NEW device registered: ip={ip} mac={mac} "
                  f"name={self._devices[mac]['name']} monitored=True (auto)")
            return True

    # ------------------------------------------------------------------
    # Lookups (hot path – keep these cheap)
    # ------------------------------------------------------------------
    def get_by_mac(self, mac: str) -> Optional[dict]:
        mac = mac.lower()
        with self._lock:
            d = self._devices.get(mac)
            return dict(d) if d else None

    def get_by_ip(self, ip: str) -> Optional[dict]:
        with self._lock:
            mac = self._ip_index.get(ip)
            if not mac:
                return None
            d = self._devices.get(mac)
            return dict(d) if d else None

    def get_all(self) -> List[dict]:
        with self._lock:
            # Return a snapshot of immutable copies
            return [dict(d) for d in self._devices.values()]

    def get_monitored(self) -> List[dict]:
        with self._lock:
            return [dict(d) for d in self._devices.values() if d["is_monitored"]]

    def is_monitored_mac(self, mac: str) -> bool:
        mac = mac.lower()
        with self._lock:
            d = self._devices.get(mac)
            return bool(d and d["is_monitored"])

    def is_monitored_ip(self, ip: str) -> bool:
        with self._lock:
            mac = self._ip_index.get(ip)
            if not mac:
                return False
            d = self._devices.get(mac)
            return bool(d and d["is_monitored"])

    def is_blocked_mac(self, mac: str) -> bool:
        mac = mac.lower()
        with self._lock:
            d = self._devices.get(mac)
            return bool(d and d["is_blocked"])

    def is_blocked_ip(self, ip: str) -> bool:
        with self._lock:
            mac = self._ip_index.get(ip)
            if not mac:
                return False
            d = self._devices.get(mac)
            return bool(d and d["is_blocked"])

    # ------------------------------------------------------------------
    # State toggling
    # ------------------------------------------------------------------
    def set_monitored(self, mac: str, monitored: bool) -> Optional[dict]:
        """Flip the is_monitored flag. Returns a snapshot of the device,
        or None if the MAC is unknown."""
        mac = mac.lower()
        with self._lock:
            d = self._devices.get(mac)
            if not d:
                print(f"[REGISTRY] set_monitored: unknown MAC {mac}")
                return None
            prev = d["is_monitored"]
            d["is_monitored"] = bool(monitored)
            print(f"[REGISTRY] set_monitored: mac={mac} "
                  f"{prev} -> {d['is_monitored']}")
            return dict(d)

    def set_blocked(self, mac: str, blocked: bool) -> Optional[dict]:
        """Set the is_blocked flag. Returns a snapshot of the device,
        or None if the MAC is unknown."""
        mac = mac.lower()
        with self._lock:
            d = self._devices.get(mac)
            if not d:
                print(f"[REGISTRY] set_blocked: unknown MAC {mac}")
                return None
            prev = d["is_blocked"]
            d["is_blocked"] = bool(blocked)
            print(f"[REGISTRY] set_blocked: mac={mac} "
                  f"{prev} -> {d['is_blocked']}")
            return dict(d)

    def set_speed_limit(self, mac: str, speed_limit: Optional[float]) -> Optional[dict]:
        """Set speed limit in bytes/sec. None = unlimited."""
        mac = mac.lower()
        with self._lock:
            d = self._devices.get(mac)
            if not d: return None
            d["speed_limit"] = speed_limit
            d["tokens"] = speed_limit if speed_limit else 0.0
            d["last_update"] = time.time()
            return dict(d)

    def allow_packet(self, mac: str, size: int) -> bool:
        """
        Check if a packet of `size` bytes is allowed under the speed limit.
        Implements a precise Token Bucket algorithm.
        """
        mac = mac.lower()
        with self._lock:
            d = self._devices.get(mac)
            if not d: return False
            
            limit = d["speed_limit"]
            if limit is None: return True  # No limit
            
            now = time.time()
            elapsed = now - d["last_update"]
            
            # Refill tokens: limit is bytes per second
            d["tokens"] += elapsed * limit
            d["last_update"] = now
            
            # Cap bucket size at 2x the limit (burst allowance)
            if d["tokens"] > limit * 2:
                d["tokens"] = limit * 2
                
            if d["tokens"] >= size:
                d["tokens"] -= size
                return True
            return False

    def set_unmonitored_timestamp(self, mac: str):
        """Record when a device was unmonitored for grace period."""
        mac = mac.lower()
        with self._lock:
            d = self._devices.get(mac)
            if d: d["unmonitored_at"] = time.time()

    def is_in_grace_period(self, mac: str, seconds: float = 10.0) -> bool:
        """Check if device is within the post-unmonitor grace period."""
        mac = mac.lower()
        with self._lock:
            d = self._devices.get(mac)
            if not d or d["unmonitored_at"] == 0: return False
            return (time.time() - d["unmonitored_at"]) < seconds

    # ------------------------------------------------------------------
    # Byte accounting (called from l2_capture.py on every forwarded frame)
    # ------------------------------------------------------------------
    def add_ul(self, mac: str, n: int) -> None:
        """Victim -> Internet byte counter."""
        mac = mac.lower()
        with self._lock:
            d = self._devices.get(mac)
            if d:
                d["ul_bytes"] += n

    def add_dl(self, mac: str, n: int) -> None:
        """Internet -> Victim byte counter."""
        mac = mac.lower()
        with self._lock:
            d = self._devices.get(mac)
            if d:
                d["dl_bytes"] += n

    # ------------------------------------------------------------------
    # Periodic speed calculation
    # ------------------------------------------------------------------
    def tick_speeds(self) -> None:
        """
        Should be called once per second by a background thread.
        Computes dl_speed / ul_speed (bytes/sec) from delta of cumulative
        counters since the last tick.
        """
        with self._lock:
            now = time.time()
            dt = max(now - self._last_tick, 1e-3)
            for d in self._devices.values():
                dl_delta = d["dl_bytes"] - d["_prev_dl"]
                ul_delta = d["ul_bytes"] - d["_prev_ul"]
                d["dl_speed"] = dl_delta / dt
                d["ul_speed"] = ul_delta / dt
                d["_prev_dl"] = d["dl_bytes"]
                d["_prev_ul"] = d["ul_bytes"]
            self._last_tick = now


# Module-level singleton – every other module imports this exact instance.
REGISTRY = DeviceRegistry()

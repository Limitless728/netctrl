"""
gui.py
======
tkinter GUI that talks to the local aiohttp server over HTTP.

Layout
------
+--------------------------------------------------------+
| [Rescan]   Local: 192.168.x.x   Gateway: 192.168.x.x  |
+--------------------------------------------------------+
| Name    | IP            | MAC            | DL  | UL  | Monitor |
| ...     | ...           | ...            | ... | ... |   [x]   |
+--------------------------------------------------------+
| status bar                                             |
+--------------------------------------------------------+

Why tkinter?
 - Ships with every Python install on Windows (no extra deps).
 - The whole app is single-process; we only need a data grid + a button.

Notes
 - We poll /api/devices every 1 s (REFRESH_MS). Clicking the "Monitor"
   cell flips the state via POST /api/monitor and the next refresh tick
   picks up the new value.
 - Network I/O happens in worker threads so the Tk main loop never blocks.
"""

import json
import os
import queue
import sys
import threading
import time
import tkinter as tk
import urllib.request
import urllib.error
from tkinter import ttk
from typing import Any, Optional

# Import subprocess for process management
import subprocess

API = "http://127.0.0.1:8765"
REFRESH_MS = 1000


# ----------------------------------------------------------------------
# Tiny HTTP helpers (kept dependency-free – stdlib only)
# ----------------------------------------------------------------------
def _http_get(path: str, timeout: float = 2.0):
    """Blocking helper – always called from a worker thread."""
    url = API + path
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else "(no body)"
        print(f"[ERROR] GET {url} → HTTP {e.code} {e.reason}  body={body}", file=sys.stderr)
        raise
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        print(f"[ERROR] GET {url} → {e!r}", file=sys.stderr)
        raise


def _http_post(path: str, body: dict, timeout: float = 2.0):
    data = json.dumps(body).encode("utf-8")
    url = API + path
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace") if e.fp else "(no body)"
        print(f"[ERROR] POST {url}  payload={body}  → HTTP {e.code} {e.reason}  body={err_body}", file=sys.stderr)
        raise
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        print(f"[ERROR] POST {url}  payload={body}  → {e!r}", file=sys.stderr)
        raise


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _fmt_speed(bps: float) -> str:
    """Render bytes/sec as KB/s with one decimal."""
    if bps <= 0:
        return "0.0"
    return f"{bps / 1024.0:.1f}"


def _fmt_size(total_bytes: int) -> str:
    """Render byte count as human-readable size (KB/MB/GB)."""
    if total_bytes <= 0:
        return "0 B"
    if total_bytes < 1024:
        return f"{total_bytes} B"
    if total_bytes < 1024 * 1024:
        return f"{total_bytes / 1024.0:.1f} KB"
    if total_bytes < 1024 * 1024 * 1024:
        return f"{total_bytes / (1024.0 * 1024.0):.1f} MB"
    return f"{total_bytes / (1024.0 * 1024.0 * 1024.0):.2f} GB"


def _load_device_names() -> dict[str, str]:
    """Load device_names.json from next to the executable.

    When running as a PyInstaller onefile .exe, ``sys.executable`` points
    to the exe itself; when running as a script, ``__file__`` is available.
    Returns the ``by_ip`` mapping (IP -> custom name), or an empty dict if
    the file is missing or unparseable.
    """
    if getattr(sys, "frozen", False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    json_path = os.path.join(base_path, "device_names.json")
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        by_ip = data.get("by_ip", data) if "by_ip" in data else data
        if isinstance(by_ip, dict):
            return {str(k): str(v) for k, v in by_ip.items() if k != "by_ip"}
        return {}
    except Exception:
        return {}


# ----------------------------------------------------------------------
# Main window
# ----------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self, local_ip: str, local_mac: str,
                 gateway_ip: str, gateway_mac: str,
                 backend_label: str = "",
                 rust_process: Any = None,
                 health_queue: Any = None):
        super().__init__()
        title = "NetCtrl  –  Layer-2 Network Manager"
        if backend_label:
            title += "  " + backend_label
        self.title(title)
        self.geometry("960x520")
        self.configure(bg="#1e1e22")

        self._rust_process = rust_process  # reference for graceful shutdown
        self._health_queue = health_queue  # queue for crash/error messages from main.py

        self._build_ui(local_ip, local_mac, gateway_ip, gateway_mac)

        # MAC -> row iid mapping for fast updates
        self._row_for_mac: dict[str, str] = {}

        # ---- Graceful close ----
        # On window close: restore ARP for ALL monitored devices,
        # then kill the Rust engine (if any), then exit.
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

        # Kick off the refresh loop
        self.after(500, self._refresh_tick)

        # Kick off the health-check queue drainer if we have a queue
        if self._health_queue is not None:
            self.after(2000, self._drain_health_queue)

        # Kick off background name resolution for devices (Feature #4)
        self._resolved_names: set = set()  # MACs we already attempted
        threading.Thread(target=self._name_resolution_loop, daemon=True).start()

        # Kick off periodic status poll for header updates (Feature #1)
        self._status_poll_interval = 10000  # every 10s
        self.after(2000, self._tick_status_poll)

    # ------------------------------------------------------------------
    def _update_header(self, local_ip: str, local_mac: str, gateway_ip: str, gateway_mac: str):
        """Update the top bar header label with current network info."""
        info = (f"   Local:  {local_ip}  ({local_mac})"
                f"     Gateway:  {gateway_ip}  ({gateway_mac})")
        self.after(0, lambda: self._header_label.config(text=info))

    def _tick_status_poll(self):
        """Periodically poll /api/status and update the header."""
        threading.Thread(target=self._poll_status, daemon=True).start()
        self.after(self._status_poll_interval, self._tick_status_poll)

    def _poll_status(self):
        """Fetch /api/status in background and update header with resolved gateway_mac."""
        try:
            status = _http_get("/api/status", timeout=2.0)
            if status.get("ok"):
                self._update_header(
                    status.get("local_ip", ""),
                    status.get("local_mac", ""),
                    status.get("gateway_ip", ""),
                    status.get("gateway_mac", ""),
                )
                iface = status.get("interface", "")
                if iface:
                    self.after(0, lambda: self.title(
                        f"NetCtrl  –  Layer-2 Network Manager  [{iface}]"
                    ))
        except Exception:
            pass  # best-effort

    # ------------------------------------------------------------------
    def _on_closing(self):
        """Graceful shutdown: restore ARP for all devices, then cleanly terminate engine."""
        print("\n[GUI] Window close requested – initiating graceful shutdown...")
        self._set_status("Shutting down: sending ARP restores to all monitored devices...")
        self.update_idletasks()

        # 1) Restore ARP for ALL monitored devices atomically via /api/restore-all
        try:
            resp = _http_post("/api/restore-all", {}, timeout=3.0)
            print(f"[GUI] ARP restore-all sent: {resp}")
        except Exception as e:
            print(f"[GUI] /api/restore-all failed or engine unreachable: {e}")
            # Fallback: try individual /api/monitor calls using correct index 6
            for mac, iid in list(self._row_for_mac.items()):
                if not self.tree.exists(iid):
                    continue
                vals = self.tree.item(iid, "values")
                if not vals or len(vals) < 7:
                    continue
                if vals[6] == "☑":  # is_monitored is at index 6
                    try:
                        _http_post("/api/monitor", {"mac": mac, "is_monitored": False}, timeout=1.0)
                    except Exception:
                        pass

        # 2) Wait 2 seconds for the ARP packets to actually transmit onto the network wire
        print("[GUI] Waiting 2s for ARP restore packets to transmit on the wire...")
        self._set_status("Waiting 2s for ARP transmit...")
        self.update_idletasks()
        time.sleep(2)

        # 3) Cleanly terminate the Rust engine process
        if self._rust_process is not None:
            try:
                self._rust_process.terminate()
                try:
                    self._rust_process.wait(timeout=1.0)
                except Exception:
                    self._rust_process.kill()
                print("[GUI] Rust engine process terminated.")
            except Exception as e:
                print(f"[GUI] !! Failed to stop rust engine: {e}")

        # 4) Destroy window and exit
        print("[GUI] Shutdown complete. Goodbye.")
        self.destroy()
        sys.exit(0)

    # ------------------------------------------------------------------
    def _build_ui(self, local_ip, local_mac, gateway_ip, gateway_mac):
        style = ttk.Style(self)
        # Use a dark-ish theme; fall back gracefully on Windows.
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview",
                        background="#2a2a30",
                        foreground="#e6e6e6",
                        fieldbackground="#2a2a30",
                        rowheight=26,
                        borderwidth=0)
        style.configure("Treeview.Heading",
                        background="#3a3a44",
                        foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"))
        style.map("Treeview",
                  background=[("selected", "#4a90e2")])

        # --- Top bar -------------------------------------------------
        top = tk.Frame(self, bg="#1e1e22")
        top.pack(fill="x", padx=10, pady=8)

        self.rescan_btn = tk.Button(
            top, text="Rescan LAN",
            command=self._on_rescan,
            bg="#4a90e2", fg="white",
            activebackground="#2f6fbd", activeforeground="white",
            relief="flat", padx=14, pady=6,
            font=("Segoe UI", 10, "bold"))
        self.rescan_btn.pack(side="left")

        self._header_label = tk.Label(top, text="", fg="#bdbdbd", bg="#1e1e22",
                                      font=("Consolas", 10))
        self._header_label.pack(side="left", padx=12)
        self._update_header(local_ip, local_mac, gateway_ip, gateway_mac)

        # --- Treeview ------------------------------------------------
        cols = ("name", "ip", "mac", "dl", "ul", "total", "monitor", "block", "speed", "sites")
        self.tree = ttk.Treeview(self, columns=cols, show="headings",
                                 selectmode="browse")
        self.tree.heading("name",    text="Name")
        self.tree.heading("ip",      text="IP")
        self.tree.heading("mac",     text="MAC")
        self.tree.heading("dl",      text="DL (KB/s)")
        self.tree.heading("ul",      text="UL (KB/s)")
        self.tree.heading("total",   text="Total Usage")
        self.tree.heading("monitor", text="Monitor")
        self.tree.heading("block",   text="Block")
        self.tree.heading("speed",   text="Speed Limit")
        self.tree.heading("sites",   text="Sites")

        self.tree.column("name",    width=130, anchor="w")
        self.tree.column("ip",      width=105, anchor="w")
        self.tree.column("mac",     width=135, anchor="w")
        self.tree.column("dl",      width=80, anchor="e")
        self.tree.column("ul",      width=80, anchor="e")
        self.tree.column("total",   width=90, anchor="e")
        self.tree.column("monitor", width=70, anchor="center")
        self.tree.column("block",   width=60, anchor="center")
        self.tree.column("speed",   width=110, anchor="center")
        self.tree.column("sites",   width=60, anchor="center")

        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 6))

        # Click handlers
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Double-1>", self._on_tree_double_click)
        self.tree.bind("<Button-3>", self._on_tree_right_click)

        # --- Status bar ---------------------------------------------
        self.status = tk.Label(self, text="Starting…",
                               anchor="w", bg="#15151a", fg="#9aa0a6",
                               font=("Segoe UI", 9), padx=10)
        self.status.pack(fill="x", side="bottom")

    # ------------------------------------------------------------------
    # Refresh loop
    # ------------------------------------------------------------------
    def _refresh_tick(self):
        # Do the HTTP call off the UI thread so Tk never freezes.
        threading.Thread(target=self._do_refresh, daemon=True).start()
        self.after(REFRESH_MS, self._refresh_tick)

    def _do_refresh(self):
        try:
            payload = _http_get("/api/devices")
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            print(f"[ERROR] _do_refresh: {e!r}", file=sys.stderr)
            self._set_status(f"API unreachable: {e}")
            return
        except Exception as e:
            print(f"[ERROR] _do_refresh: {e!r}", file=sys.stderr)
            self._set_status(f"refresh error: {e}")
            return

        devices = payload.get("devices", [])
        # Marshal back to the UI thread to mutate the Treeview.
        self.after(0, self._apply_devices, devices)

    def _apply_devices(self, devices: list):
        # Load custom names once per refresh tick — fail gracefully.
        name_map = _load_device_names()
        # Track which MAC -> iid mappings have been assigned the local-row tag
        needs_local_tag: set = set()

        seen_macs = set()
        for d in devices:  # preserve order from API (local first, then sorted by IP)
            mac = d["mac"]
            seen_macs.add(mac)

            is_local = d.get("is_local", False)

            # Use display_name from server if available; fall back to device_names.json, then name, then MAC
            disp = d.get("display_name")
            if disp:
                name = disp
            else:
                custom = name_map.get(d["ip"])
                if custom:
                    name = custom
                else:
                    name = d.get("name") or "-"
                if not name or name == "-":
                    name = mac

            if is_local:
                # Label it "This Device" unless display_name already says something
                if not d.get("display_name"):
                    name = "This Device"

            check = "☑" if d["is_monitored"] else "☐"
            block = "🚫" if d.get("is_blocked", False) else "✓"
            speed_str = f"{d.get('speed_limit_kbps', 'N/A')} KB/s" if d.get("speed_limit_kbps") else "Unlimited"
            sites_text = "Sites"
            total_bytes = d.get("total_ul_bytes", 0) + d.get("total_dl_bytes", 0)
            # For local device, show N/A for controls
            if is_local:
                check = "—"
                block = "—"
                speed_str = "—"
                sites_text = "—"

            values = (
                name,
                d["ip"],
                mac,
                _fmt_speed(d["dl_speed"]),
                _fmt_speed(d["ul_speed"]),
                _fmt_size(total_bytes),
                check,
                block,
                speed_str,
                sites_text,
            )
            iid = self._row_for_mac.get(mac)
            if iid is None or not self.tree.exists(iid):
                iid = self.tree.insert("", "end", values=values)
                self._row_for_mac[mac] = iid
                if is_local:
                    needs_local_tag.add(mac)
            else:
                self.tree.item(iid, values=values)
                if is_local:
                    needs_local_tag.add(mac)

            # Apply local device row style: light blue background, greyed-out controls
            if is_local and mac in needs_local_tag:
                self.tree.tag_configure("local_row", background="#2a3a4a")
                self.tree.item(iid, tags=("local_row",))

        # Drop rows for devices no longer present
        for mac in list(self._row_for_mac.keys()):
            if mac not in seen_macs:
                iid = self._row_for_mac.pop(mac)
                if self.tree.exists(iid):
                    self.tree.delete(iid)

        self._set_status(f"{len(devices)} devices   "
                         f"({sum(1 for d in devices if d['is_monitored'])} monitored)   "
                         f"updated {time.strftime('%H:%M:%S')}")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------
    def _on_tree_click(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        col = self.tree.identify_column(event.x)   # like '#6'
        row_iid = self.tree.identify_row(event.y)
        if not row_iid:
            return
        vals = self.tree.item(row_iid, "values")
        if not vals:
            return
        mac = vals[2]

        # Column #1 = Rename device (available for all devices including local)
        if col == "#1":
            print(f"[GUI] rename clicked for mac={mac}")
            self._show_rename_dialog(mac, vals[1], vals[0])
            return

        # Disable network controls for local device
        # Local device row has "—" in the monitor column (index 6)
        if vals[6] == "—":
            return

        # Column #7 = Monitor toggle
        if col == "#7":
            current = vals[6] == "☑"
            new_state = not current
            print(f"[GUI] toggle mac={mac} -> monitored={new_state}")
            # Optimistic UI update
            new_vals = list(vals)
            new_vals[6] = "☑" if new_state else "☐"
            self.tree.item(row_iid, values=new_vals)
            threading.Thread(target=self._post_toggle,
                             args=(mac, new_state), daemon=True).start()

        # Column #8 = Block toggle
        elif col == "#8":
            current = vals[7] == "🚫"
            new_state = not current
            print(f"[GUI] toggle mac={mac} -> blocked={new_state}")
            # Optimistic UI update
            new_vals = list(vals)
            new_vals[7] = "🚫" if new_state else "✓"
            self.tree.item(row_iid, values=new_vals)
            threading.Thread(target=self._post_block,
                             args=(mac, new_state), daemon=True).start()

        # Column #9 = Speed limit (open dialog)
        elif col == "#9":
            print(f"[GUI] speed limit clicked for mac={mac}")
            self._show_speed_dialog(mac, vals[8])

        # Column #10 = Sites Visited popup
        elif col == "#10":
            print(f"[GUI] sites clicked for mac={mac}")
            self._show_sites_window(mac)

    def _on_tree_double_click(self, event):
        row_iid = self.tree.identify_row(event.y)
        if not row_iid:
            return
        vals = self.tree.item(row_iid, "values")
        if not vals:
            return
        self._show_rename_dialog(vals[2], vals[1], vals[0])

    def _on_tree_right_click(self, event):
        row_iid = self.tree.identify_row(event.y)
        if not row_iid:
            return
        self.tree.selection_set(row_iid)
        vals = self.tree.item(row_iid, "values")
        if not vals:
            return
        mac = vals[2]
        ip = vals[1]
        name = vals[0]
        is_local = vals[6] == "—"

        menu = tk.Menu(self, tearoff=0, bg="#2a2a30", fg="#e6e6e6",
                       activebackground="#4a90e2", activeforeground="#ffffff")
        menu.add_command(label=f"Rename '{name}'",
                         command=lambda: self._show_rename_dialog(mac, ip, name))
        if not is_local:
            menu.add_separator()
            menu.add_command(label="View Visited Sites",
                             command=lambda: self._show_sites_window(mac))
            menu.add_command(label="Set Speed Limit",
                             command=lambda: self._show_speed_dialog(mac, vals[8]))
            current_blocked = vals[7] == "🚫"
            menu.add_command(label="Unblock Device" if current_blocked else "Block Device",
                             command=lambda: threading.Thread(target=self._post_block, args=(mac, not current_blocked), daemon=True).start())
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _show_rename_dialog(self, mac: str, ip: str, current_name: str):
        import tkinter.simpledialog as simpledialog
        prompt = f"Enter friendly name for {ip} ({mac}):"
        new_name = simpledialog.askstring("Rename Device", prompt, initialvalue=current_name)
        if new_name is None:
            return
        new_name = new_name.strip()
        if not new_name:
            return

        print(f"[GUI] Renaming {mac} ({ip}) -> {new_name}")
        # 1. Update in backend via API
        threading.Thread(target=self._post_set_name, args=(mac, new_name), daemon=True).start()

        # 2. Save persistently to device_names.json
        self._save_device_name(ip, new_name)

        # 3. Optimistic UI update
        iid = self._row_for_mac.get(mac)
        if iid and self.tree.exists(iid):
            vals = list(self.tree.item(iid, "values"))
            vals[0] = new_name
            self.tree.item(iid, values=vals)

    def _post_set_name(self, mac: str, name: str):
        try:
            resp = _http_post("/api/set-name", {"mac": mac, "display_name": name})
            print(f"[GUI] /api/set-name response: {resp}")
            self._set_status(f"Renamed {mac} to '{name}'")
        except Exception as e:
            print(f"[ERROR] _post_set_name {mac}: {e!r}", file=sys.stderr)
            self._set_status(f"Rename failed for {mac}: {e}")

    @staticmethod
    def _save_device_name(ip: str, name: str):
        if getattr(sys, "frozen", False):
            base_path = os.path.dirname(sys.executable)
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(base_path, "device_names.json")
        try:
            data = {}
            if os.path.isfile(json_path):
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            by_ip = data.setdefault("by_ip", {})
            by_ip[ip] = name
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"[GUI] Saved device name for {ip} to {json_path}")
        except Exception as e:
            print(f"[GUI] Failed to save device name to {json_path}: {e}")

    def _post_toggle(self, mac: str, monitored: bool):
        try:
            # Send both keys just to be safe, server.py handles both
            resp = _http_post("/api/monitor",
                              {"mac": mac, "monitored": monitored, "is_monitored": monitored})
            print(f"[GUI] [TOGGLE] /api/monitor response: {resp}")
            if monitored:
                self._set_status(f"Monitoring started for {mac}")
            else:
                self._set_status(f"Monitoring stopped (ARP restored) for {mac}")
        except Exception as e:
            print(f"[ERROR] _post_toggle {mac}: {e!r}", file=sys.stderr)
            self._set_status(f"toggle failed for {mac}: {e}")

    def _post_block(self, mac: str, blocked: bool):
        try:
            resp = _http_post("/api/block",
                              {"mac": mac, "blocked": blocked})
            print(f"[GUI] /api/block response: {resp}")
        except Exception as e:
            print(f"[ERROR] _post_block {mac}: {e!r}", file=sys.stderr)
            self._set_status(f"block toggle failed for {mac}: {e}")

    def _show_speed_dialog(self, mac: str, current_speed_str: str):
        """Open a dialog to set speed limit for a device."""
        import tkinter.simpledialog as simpledialog
        import tkinter.messagebox as messagebox

        # Parse current speed
        current_kbps = None
        if current_speed_str and current_speed_str != "Unlimited":
            try:
                current_kbps = float(current_speed_str.split()[0])
            except (ValueError, IndexError):
                pass

        prompt = f"Enter speed limit (KB/s) for {mac}\n(leave empty for unlimited)"
        result = simpledialog.askstring(
            "Speed Limit",
            prompt,
            initialvalue=str(current_kbps) if current_kbps else ""
        )

        if result is None:  # User cancelled
            return

        # Parse input
        speed_limit_kbps = None
        if result.strip():
            try:
                speed_limit_kbps = float(result.strip())
                if speed_limit_kbps <= 0:
                    messagebox.showerror("Invalid Input", "Speed must be positive")
                    return
            except ValueError:
                messagebox.showerror("Invalid Input", "Please enter a valid number")
                return

        print(f"[GUI] setting speed limit for {mac} to {speed_limit_kbps}")
        threading.Thread(target=self._post_speed_limit,
                         args=(mac, speed_limit_kbps), daemon=True).start()

    def _post_speed_limit(self, mac: str, speed_limit_kbps: Optional[float]):
        try:
            resp = _http_post("/api/speed",
                              {"mac": mac, "speed_limit_kbps": speed_limit_kbps})
            print(f"[GUI] /api/speed response: {resp}")
            if speed_limit_kbps:
                self._set_status(f"Speed limit set for {mac}: {speed_limit_kbps} KB/s")
            else:
                self._set_status(f"Speed limit removed for {mac}")
        except Exception as e:
            print(f"[ERROR] _post_speed_limit {mac}: {e!r}", file=sys.stderr)
            self._set_status(f"speed limit update failed for {mac}: {e}")

    def _show_sites_window(self, mac: str):
        """Open a Toplevel window showing visited sites for a device."""
        popup = tk.Toplevel(self)
        popup.title(f"Sites Visited – {mac}")
        popup.geometry("620x460")
        popup.configure(bg="#1e1e22")
        popup.transient(self)

        # --- Style for this popup (dark theme matching main window) ---
        style = ttk.Style(popup)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Sites.Treeview",
                        background="#2a2a30",
                        foreground="#e6e6e6",
                        fieldbackground="#2a2a30",
                        rowheight=24,
                        borderwidth=0)
        style.configure("Sites.Treeview.Heading",
                        background="#3a3a44",
                        foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"))
        style.map("Sites.Treeview",
                  background=[("selected", "#4a90e2")])

        # --- Top info bar ---
        top = tk.Frame(popup, bg="#1e1e22")
        top.pack(fill="x", padx=10, pady=(8, 4))

        tk.Label(top, text=f"Visited sites for {mac}",
                 fg="#e6e6e6", bg="#1e1e22",
                 font=("Segoe UI", 11, "bold")).pack(side="left")

        count_label = tk.Label(top, text="Loading...",
                               fg="#9aa0a6", bg="#1e1e22",
                               font=("Segoe UI", 9))
        count_label.pack(side="right")

        # --- Search / Filter bar ---
        search_frame = tk.Frame(popup, bg="#1e1e22")
        search_frame.pack(fill="x", padx=10, pady=(0, 6))

        tk.Label(search_frame, text="Filter: ", fg="#9aa0a6", bg="#1e1e22",
                 font=("Segoe UI", 9)).pack(side="left")

        search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=search_var,
                                bg="#2a2a30", fg="#ffffff",
                                insertbackground="white", relief="flat",
                                font=("Segoe UI", 9))
        search_entry.pack(side="left", fill="x", expand=True)

        # --- Treeview ---
        sites_cols = ("domain", "time")
        sites_tree = ttk.Treeview(popup, columns=sites_cols, show="headings",
                                  selectmode="browse", style="Sites.Treeview")
        sites_tree.heading("domain", text="Domain")
        sites_tree.heading("time", text="Time")
        sites_tree.column("domain", width=360, anchor="w")
        sites_tree.column("time", width=200, anchor="w")
        sites_tree.pack(fill="both", expand=True, padx=10, pady=(0, 4))

        # Scrollbar
        vsb = ttk.Scrollbar(popup, orient="vertical", command=sites_tree.yview)
        sites_tree.configure(yscrollcommand=vsb.set)
        vsb.place(relx=1.0, rely=0.0, relheight=1.0, anchor="ne",
                   x=-10, y=78, height=-140)

        # --- Bottom button bar ---
        bottom = tk.Frame(popup, bg="#1e1e22")
        bottom.pack(fill="x", padx=10, pady=(4, 8))

        # Cached visits for client-side search filtering
        popup_state = {"visits": []}

        clear_btn = tk.Button(
            bottom, text="Clear History",
            command=lambda: self._on_clear_sites(mac, sites_tree, popup, count_label, popup_state),
            bg="#d9534f", fg="white",
            activebackground="#c9302c", activeforeground="white",
            relief="flat", padx=12, pady=5,
            font=("Segoe UI", 10, "bold"))
        clear_btn.pack(side="left")

        def _copy_domain():
            sel = sites_tree.selection()
            if sel:
                val = sites_tree.item(sel[0], "values")
                if val:
                    popup.clipboard_clear()
                    popup.clipboard_append(val[0])
                    self._set_status(f"Copied domain to clipboard: {val[0]}")

        copy_btn = tk.Button(
            bottom, text="Copy Domain",
            command=_copy_domain,
            bg="#3a3a44", fg="white",
            activebackground="#4a4a54", activeforeground="white",
            relief="flat", padx=12, pady=5,
            font=("Segoe UI", 10))
        copy_btn.pack(side="left", padx=6)

        close_btn = tk.Button(
            bottom, text="Close",
            command=popup.destroy,
            bg="#4a4a4a", fg="white",
            activebackground="#5a5a5a", activeforeground="white",
            relief="flat", padx=12, pady=5,
            font=("Segoe UI", 10))
        close_btn.pack(side="right")

        def _render_tree():
            if not sites_tree.winfo_exists():
                return
            query = search_var.get().strip().lower()
            for item in sites_tree.get_children():
                sites_tree.delete(item)
            shown = 0
            for v in reversed(popup_state["visits"]):
                domain = v.get("domain", "")
                if query and query not in domain.lower():
                    continue
                ts = v.get("timestamp", 0.0)
                import datetime
                time_str = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                sites_tree.insert("", "end", values=(domain, time_str))
                shown += 1
            if count_label.winfo_exists():
                total = len(popup_state["visits"])
                if query:
                    count_label.config(text=f"{shown} / {total} entries")
                else:
                    count_label.config(text=f"{total} entries")

        search_var.trace_add("write", lambda *_: _render_tree())

        # --- Auto-refresh state ---
        cancel_refresh = threading.Event()
        popup.protocol("WM_DELETE_WINDOW", lambda: (cancel_refresh.set(), popup.destroy()))

        def _fetch_worker():
            try:
                resp = _http_get(f"/api/sites/{mac}", timeout=3.0)
            except Exception as e:
                print(f"[GUI] _fetch_sites {mac}: {e!r}", file=sys.stderr)
                return
            if resp.get("ok"):
                popup_state["visits"] = resp.get("visits", [])
                self.after(0, _render_tree)

        # Initial fetch
        threading.Thread(target=_fetch_worker, daemon=True).start()

        # Refresh loop (every 3 seconds)
        def _auto_refresh():
            if cancel_refresh.is_set():
                return
            threading.Thread(target=_fetch_worker, daemon=True).start()
            if popup.winfo_exists():
                popup.after(3000, _auto_refresh)

        popup.after(3000, _auto_refresh)

    def _on_clear_sites(self, mac: str, sites_tree: ttk.Treeview, popup: tk.Toplevel, count_label: tk.Label, popup_state: dict):
        """Clear all sites for a device via API."""
        import tkinter.messagebox as messagebox
        if not messagebox.askyesno("Confirm", f"Clear all visited sites history for {mac}?", parent=popup):
            return
        print(f"[GUI] Clearing sites for {mac}")
        def _go():
            try:
                resp = _http_post(f"/api/sites/{mac}/clear", {}, timeout=3.0)
                print(f"[GUI] /api/sites/{mac}/clear response: {resp}")
                self._set_status(f"Sites history cleared for {mac}")
                popup_state["visits"] = []
                def _done():
                    for item in sites_tree.get_children():
                        sites_tree.delete(item)
                    if count_label.winfo_exists():
                        count_label.config(text="0 entries")
                self.after(0, _done)
            except Exception as e:
                print(f"[ERROR] _post_clear_sites {mac}: {e!r}", file=sys.stderr)
                self._set_status(f"clear sites failed for {mac}: {e}")
        threading.Thread(target=_go, daemon=True).start()

    def _on_rescan(self):
        print("[GUI] Rescan clicked")
        self._set_status("Scanning ...")
        def _go():
            try:
                # BUG FIX #2: scanner.run_scan() does blocking pcap operations
                # (open capture + send 254 ARP requests + listen 1.5s ≈ 3+ s).
                # Default timeout was 2.0s, which caused HTTP timeout before scan
                # completed. Increased to 15s to provide ample headroom.
                resp = _http_post("/api/scan", {}, timeout=15.0)
                self._set_status(
                    f"Scan complete – {resp.get('new_devices', 0)} new")
            except Exception as e:
                print(f"[ERROR] _on_rescan: {e!r}", file=sys.stderr)
                self._set_status(f"scan failed: {e}")
        threading.Thread(target=_go, daemon=True).start()

    # ------------------------------------------------------------------
    def _set_status(self, text: str):
        # Always marshal back to UI thread
        self.after(0, lambda: self.status.config(text=text))

    def _drain_health_queue(self):
        """Periodically check for crash/error messages from the health-check daemon."""
        if self._health_queue is None:
            return
        try:
            while True:
                msg = self._health_queue.get_nowait()
                self._set_status(msg)
        except queue.Empty:
            pass
        self.after(2000, self._drain_health_queue)

    # ------------------------------------------------------------------
    # Background name resolution (Feature #4)
    # Priority: device_names.json → NetBIOS NS (UDP 137) → mDNS (UDP 5353) → MAC fallback
    # ------------------------------------------------------------------
    def _name_resolution_loop(self):
        """Periodically resolve device names in a background thread."""
        time.sleep(5)
        while True:
            try:
                payload = _http_get("/api/devices", timeout=3.0)
                devices = payload.get("devices", [])
                name_map = _load_device_names()
                for d in devices:
                    mac = d.get("mac", "")
                    ip = d.get("ip", "")
                    if not mac or not ip:
                        continue
                    if d.get("display_name"):
                        self._resolved_names.add(mac)
                        continue
                    if mac in self._resolved_names:
                        continue
                    resolved = self._resolve_device_name(ip, mac, name_map)
                    if resolved:
                        print(f"[GUI] Name resolved: {ip} ({mac}) -> {resolved}")
                        try:
                            _http_post("/api/set-name", {"mac": mac, "display_name": resolved})
                        except Exception:
                            pass
                    self._resolved_names.add(mac)
            except Exception:
                pass
            time.sleep(10)

    def _resolve_device_name(self, ip: str, mac: str, name_map: dict):
        """Try to resolve a device name. Returns None if all methods fail."""
        # 1) Check device_names.json (by IP)
        if ip in name_map:
            return name_map[ip]
        # 2) Try NetBIOS Name Service (UDP port 137)
        name = self._try_netbios(ip)
        if name:
            return name
        # 3) Try mDNS (multicast DNS, UDP port 5353)
        name = self._try_mdns(ip)
        if name:
            return name
        # 4) All failed -> None (GUI falls back to MAC)
        return None

    @staticmethod
    def _try_netbios(ip: str):
        """Attempt NetBIOS name resolution using Windows nbtstat."""
        try:
            result = subprocess.run(
                ["nbtstat", "-A", ip],
                capture_output=True, text=True, timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            if result.returncode != 0:
                return None
            for line in result.stdout.splitlines():
                line_stripped = line.strip()
                if "<00>" in line_stripped and "UNIQUE" in line_stripped:
                    parts = line_stripped.split()
                    if parts:
                        name = parts[0].strip()
                        if name and len(name) <= 15:
                            return name
            return None
        except Exception:
            return None

    @staticmethod
    def _try_mdns(ip: str):
        """Attempt mDNS reverse resolution by sending a PTR query to the device."""
        import socket
        import struct
        import random
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 8)
            octets = ip.split(".")
            if len(octets) != 4:
                sock.close()
                return None
            reversed_ip = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
            query_name = b""
            for label in reversed_ip.split("."):
                query_name += struct.pack("B", len(label)) + label.encode("ascii")
            query_name += b"\x00"
            txid = random.randint(0, 65535)
            header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
            question = query_name + struct.pack(">HH", 12, 0x0001)
            packet = header + question
            sock.sendto(packet, (ip, 5353))
            try:
                data, addr = sock.recvfrom(1024)
                if addr[0] == ip and len(data) > 12:
                    offset = 12
                    while offset < len(data) and data[offset] != 0:
                        offset += data[offset] + 1
                    offset += 1 + 4
                    if offset + 10 < len(data):
                        pos = offset + 2 + 2 + 2 + 4 + 2
                        if pos < len(data):
                            hostname = App._decode_mdns_name(data, pos)
                            if hostname and hostname.endswith(".local"):
                                sock.close()
                                return hostname[:-6]
            except socket.timeout:
                pass
            sock.close()
            return None
        except Exception:
            return None

    @staticmethod
    def _decode_mdns_name(data: bytes, offset: int):
        """Decode a DNS-style name from raw bytes at the given offset."""
        labels = []
        pos = offset
        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            if length >= 0xC0:
                if pos + 1 < len(data):
                    ptr = ((length & 0x3F) << 8) | data[pos + 1]
                    sub = App._decode_mdns_name(data, ptr)
                    if sub:
                        labels.append(sub)
                    return ".".join(labels) if labels else None
                break
            pos += 1
            if pos + length <= len(data):
                labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
                pos += length
        return ".".join(labels) if labels else None


def run_gui(local_ip: str, local_mac: str,
            gateway_ip: str, gateway_mac: str,
            backend_label: str = "",
            rust_process: Any = None,
            health_queue: Any = None) -> None:
    app = App(local_ip, local_mac, gateway_ip, gateway_mac, backend_label, rust_process, health_queue)
    app.mainloop()
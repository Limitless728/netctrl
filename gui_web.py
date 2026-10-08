"""
gui_web.py
==========
Modern Cyber Dark Dashboard for NetCtrl powered by PyWebView (Edge WebView2).
Provides a sleek, responsive, hardware-accelerated desktop UI that communicates
directly with the Rust engine HTTP API (127.0.0.1:8765).
"""

import json
import os
import sys
import time
import urllib.request
from typing import Any, Optional

try:
    import webview
    WEBVIEW_AVAILABLE = True
except ImportError:
    WEBVIEW_AVAILABLE = False


class DashboardBridge:
    """Python API bridge exposed directly to the JavaScript window (window.pywebview.api)."""

    def __init__(self, local_ip: str, local_mac: str,
                 gateway_ip: str, gateway_mac: str,
                 backend_label: str = ""):
        self.local_ip = local_ip
        self.local_mac = local_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.backend_label = backend_label

    def get_context(self) -> dict:
        """Return host network parameters for the webview UI."""
        return {
            "local_ip": self.local_ip,
            "local_mac": self.local_mac,
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "backend_label": self.backend_label,
        }

    def load_device_names(self) -> dict:
        """Load device_names.json from next to the executable or script."""
        base = (
            os.path.dirname(sys.executable)
            if getattr(sys, "frozen", False)
            else os.path.dirname(os.path.abspath(__file__))
        )
        json_path = os.path.join(base, "device_names.json")
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("by_ip", data) if "by_ip" in data else data
        except Exception:
            return {}

    def save_device_name(self, ip: str, name: str) -> bool:
        """Save a new custom device name mapping to device_names.json."""
        base = (
            os.path.dirname(sys.executable)
            if getattr(sys, "frozen", False)
            else os.path.dirname(os.path.abspath(__file__))
        )
        json_path = os.path.join(base, "device_names.json")
        try:
            data = {}
            if os.path.isfile(json_path):
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            if "by_ip" not in data or not isinstance(data.get("by_ip"), dict):
                data = {"by_ip": {}}
            data["by_ip"][ip] = name
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"[GUI-WEB] Could not save name to {json_path}: {e}")
            return False


def run_web_gui(local_ip: str, local_mac: str,
                gateway_ip: str, gateway_mac: str,
                backend_label: str = "",
                rust_process: Any = None,
                health_queue: Any = None):
    """Launch the PyWebView modern dashboard window."""
    if not WEBVIEW_AVAILABLE:
        print("[GUI-WEB] pywebview not installed, falling back to Tkinter GUI...")
        from gui import run_gui
        run_gui(local_ip, local_mac, gateway_ip, gateway_mac, backend_label, rust_process, health_queue)
        return

    # Locate the web assets directory
    if getattr(sys, "frozen", False):
        base_dir = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    html_path = os.path.join(base_dir, "web", "index.html")
    if not os.path.isfile(html_path):
        # Check next to executable as fallback
        html_path = os.path.join(os.path.dirname(sys.executable), "web", "index.html")

    if not os.path.isfile(html_path):
        print(f"[GUI-WEB] WARNING: web/index.html not found at {html_path}. Falling back to Tkinter.")
        from gui import run_gui
        run_gui(local_ip, local_mac, gateway_ip, gateway_mac, backend_label, rust_process, health_queue)
        return

    bridge = DashboardBridge(
        local_ip=local_ip,
        local_mac=local_mac,
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac,
        backend_label=backend_label,
    )

    title = "NetCtrl Pro  –  Layer-2 Network Manager"
    if backend_label:
        title += f"  {backend_label}"

    window = webview.create_window(
        title=title,
        url=html_path,
        js_api=bridge,
        width=1180,
        height=740,
        min_size=(960, 600),
        background_color="#0d1117",
    )

    def on_closing():
        print("[GUI-WEB] Window close requested — executing atomic LAN restore...")
        try:
            req = urllib.request.Request("http://127.0.0.1:8765/api/restore-all", method="POST")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                print(f"[GUI-WEB] Restore-all API replied: {resp.status}")
        except Exception as e:
            print(f"[GUI-WEB] Restore-all error: {e}")

        # Sleep to allow raw ARP restore frames to transmit cleanly
        time.sleep(1.5)

        if rust_process is not None:
            try:
                rust_process.terminate()
                try:
                    rust_process.wait(timeout=1.0)
                except Exception:
                    rust_process.kill()
                print("[GUI-WEB] Rust engine terminated.")
            except Exception as e:
                print(f"[GUI-WEB] Failed to terminate rust engine: {e}")
        return True

    window.events.closing += on_closing

    # Start WebView2 event loop (blocks until closed)
    print(f"[GUI-WEB] Launching modern web dashboard from: {html_path}")
    webview.start(debug=False)

    # Final cleanup after window destroy
    if rust_process is not None:
        try:
            rust_process.kill()
        except Exception:
            pass
    print("[GUI-WEB] Shutdown complete. Goodbye.")

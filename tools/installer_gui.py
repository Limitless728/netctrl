import os
import sys
import time
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


def register_windows_uninstaller(install_dir, version="2.1.2"):
    """Register NetCtrl Pro in Windows Add/Remove Programs (Registry)."""
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\NetCtrl"
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "NetCtrl Pro")
            winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, version)
            winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "Limitless728")
            winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, install_dir)
            icon_path = os.path.join(install_dir, "icon.ico")
            if os.path.exists(icon_path):
                winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, icon_path)
            uninst_bat = os.path.join(install_dir, "uninstall.bat")
            winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, f'cmd.exe /c "{uninst_bat}"')
            winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
    except Exception as e:
        print(f"[REGISTRY UNINSTALL WARNING] {e}")


def get_bundled_dir():
    """Return sys._MEIPASS when frozen by PyInstaller, or current script directory."""
    if getattr(sys, "frozen", False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def is_npcap_installed():
    """Check if Npcap / WinPcap packet driver is installed on Windows."""
    candidates = [
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Windows\System32\wpcap.dll",
        r"C:\Windows\System32\Npcap\Packet.dll",
        r"C:\Windows\System32\Packet.dll",
    ]
    return any(os.path.exists(p) for p in candidates)


def create_windows_shortcut(target_exe, lnk_path, icon_file=None, description="NetCtrl Pro"):
    """Create a Windows .lnk shortcut using PowerShell COM automation."""
    try:
        ps_script = f'''
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("{lnk_path}")
$Shortcut.TargetPath = "{target_exe}"
$Shortcut.WorkingDirectory = "{os.path.dirname(target_exe)}"
$Shortcut.Description = "{description}"
'''
        if icon_file and os.path.exists(icon_file):
            ps_script += f'$Shortcut.IconLocation = "{icon_file},0"\n'
        ps_script += '$Shortcut.Save()\n'

        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            creationflags=0x08000000,  # CREATE_NO_WINDOW
            check=True
        )
        return True
    except Exception as e:
        print(f"[SHORTCUT ERROR] {e}")
        return False


class NetCtrlInstallerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NetCtrl Pro – Setup Wizard")
        self.root.geometry("560x430")
        self.root.resizable(False, False)

        # Set window icon if available
        bundle_dir = get_bundled_dir()
        icon_path = os.path.join(bundle_dir, "icon.ico")
        if os.path.exists(icon_path):
            try:
                self.root.iconbitmap(icon_path)
            except Exception:
                pass

        # Styling
        self.root.configure(bg="#0d1117")
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Custom dark palette
        self.style.configure(".", background="#0d1117", foreground="#f0f6fc", font=("Segoe UI", 9))
        self.style.configure("TFrame", background="#0d1117")
        self.style.configure("TLabel", background="#0d1117", foreground="#f0f6fc", font=("Segoe UI", 9))
        self.style.configure("Header.TLabel", background="#161b22", foreground="#ffffff", font=("Segoe UI", 13, "bold"))
        self.style.configure("SubHeader.TLabel", background="#161b22", foreground="#8b949e", font=("Segoe UI", 9))
        self.style.configure("Action.TButton", font=("Segoe UI", 9, "bold"), background="#1f6feb", foreground="#ffffff", borderwidth=0)
        self.style.map("Action.TButton", background=[("active", "#388bfd"), ("pressed", "#1158c7")])
        self.style.configure("Secondary.TButton", font=("Segoe UI", 9), background="#21262d", foreground="#f0f6fc", borderwidth=1, relief="solid")
        self.style.map("Secondary.TButton", background=[("active", "#30363d"), ("pressed", "#161b22")])

        # State Variables
        default_dir = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "NetCtrl")
        self.install_dir_var = tk.StringVar(value=default_dir)
        self.shortcut_desktop_var = tk.BooleanVar(value=True)
        self.shortcut_startmenu_var = tk.BooleanVar(value=True)
        
        self.npcap_present = is_npcap_installed()
        self.install_npcap_var = tk.BooleanVar(value=not self.npcap_present)
        self.launch_after_var = tk.BooleanVar(value=True)

        self._build_ui()

    def _build_ui(self):
        # 1. Header Banner
        header_frame = tk.Frame(self.root, bg="#161b22", height=70, padx=20, pady=12)
        header_frame.pack(fill="x")

        lbl_title = ttk.Label(header_frame, text="NetCtrl Pro – Setup Wizard", style="Header.TLabel")
        lbl_title.pack(anchor="w")

        lbl_sub = ttk.Label(header_frame, text="Layer-2 LAN Bandwidth Manager & ARP Controller", style="SubHeader.TLabel")
        lbl_sub.pack(anchor="w", pady=(2, 0))

        # Thin separator line
        sep = tk.Frame(self.root, bg="#30363d", height=1)
        sep.pack(fill="x")

        # 2. Main Content Container
        self.content_frame = ttk.Frame(self.root, padding="20 16 20 16")
        self.content_frame.pack(fill="both", expand=True)

        # Step 1: Directory selection
        lbl_dir = ttk.Label(self.content_frame, text="Destination Folder:", font=("Segoe UI", 9, "bold"))
        lbl_dir.pack(anchor="w")

        dir_input_frame = ttk.Frame(self.content_frame)
        dir_input_frame.pack(fill="x", pady=(6, 14))

        self.txt_dir = tk.Entry(
            dir_input_frame,
            textvariable=self.install_dir_var,
            bg="#161b22",
            fg="#f0f6fc",
            insertbackground="#ffffff",
            relief="solid",
            bd=1,
            font=("Segoe UI", 9)
        )
        self.txt_dir.pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 8))

        btn_browse = ttk.Button(dir_input_frame, text="Browse...", style="Secondary.TButton", command=self._browse_dir)
        btn_browse.pack(side="right")

        # Step 2: Options
        lbl_opts = ttk.Label(self.content_frame, text="Installation Options:", font=("Segoe UI", 9, "bold"))
        lbl_opts.pack(anchor="w", pady=(0, 6))

        chk_desktop = tk.Checkbutton(
            self.content_frame,
            text="Create Desktop Shortcut",
            variable=self.shortcut_desktop_var,
            bg="#0d1117",
            fg="#f0f6fc",
            activebackground="#0d1117",
            activeforeground="#58a6ff",
            selectcolor="#161b22",
            font=("Segoe UI", 9),
            highlightthickness=0,
            bd=0,
            anchor="w",
            cursor="hand2"
        )
        chk_desktop.pack(fill="x", pady=3)

        chk_startmenu = tk.Checkbutton(
            self.content_frame,
            text="Create Start Menu Shortcut",
            variable=self.shortcut_startmenu_var,
            bg="#0d1117",
            fg="#f0f6fc",
            activebackground="#0d1117",
            activeforeground="#58a6ff",
            selectcolor="#161b22",
            font=("Segoe UI", 9),
            highlightthickness=0,
            bd=0,
            anchor="w",
            cursor="hand2"
        )
        chk_startmenu.pack(fill="x", pady=3)

        if self.npcap_present:
            npcap_label = "Npcap Driver: Already Installed on this PC ✓"
            chk_npcap = tk.Checkbutton(
                self.content_frame,
                text=npcap_label,
                variable=self.install_npcap_var,
                state="disabled",
                bg="#0d1117",
                fg="#6e7681",
                disabledforeground="#6e7681",
                activebackground="#0d1117",
                activeforeground="#6e7681",
                selectcolor="#161b22",
                font=("Segoe UI", 9),
                highlightthickness=0,
                bd=0,
                anchor="w"
            )
        else:
            npcap_label = "Install Npcap Network Driver (Required for packet capture - Auto Setup)"
            chk_npcap = tk.Checkbutton(
                self.content_frame,
                text=npcap_label,
                variable=self.install_npcap_var,
                bg="#0d1117",
                fg="#f0f6fc",
                activebackground="#0d1117",
                activeforeground="#58a6ff",
                selectcolor="#161b22",
                font=("Segoe UI", 9),
                highlightthickness=0,
                bd=0,
                anchor="w",
                cursor="hand2"
            )
        chk_npcap.pack(fill="x", pady=3)

        # Progress / Status Section (initially hidden)
        self.progress_frame = ttk.Frame(self.content_frame)
        self.progress_bar = ttk.Progressbar(self.progress_frame, mode="determinate", length=500)
        self.progress_bar.pack(fill="x", pady=(10, 4))
        self.lbl_status = ttk.Label(self.progress_frame, text="Ready to install.", foreground="#8b949e")
        self.lbl_status.pack(anchor="w")

        # 3. Bottom Action Bar
        bottom_sep = tk.Frame(self.root, bg="#30363d", height=1)
        bottom_sep.pack(fill="x", side="bottom")

        bottom_bar = tk.Frame(self.root, bg="#161b22", height=50, padx=20, pady=10)
        bottom_bar.pack(fill="x", side="bottom")

        self.btn_cancel = ttk.Button(bottom_bar, text="Cancel", style="Secondary.TButton", command=self.root.quit)
        self.btn_cancel.pack(side="right", padx=(8, 0))

        self.btn_install = ttk.Button(bottom_bar, text="Install Now >", style="Action.TButton", command=self._start_install)
        self.btn_install.pack(side="right")

    def _browse_dir(self):
        chosen = filedialog.askdirectory(initialdir=self.install_dir_var.get(), title="Select NetCtrl Installation Folder")
        if chosen:
            self.install_dir_var.set(os.path.normpath(chosen))

    def _start_install(self):
        target_dir = self.install_dir_var.get().strip()
        if not target_dir:
            messagebox.showerror("Error", "Please specify a valid installation directory.")
            return

        self.btn_install.config(state="disabled")
        self.btn_cancel.config(state="disabled")
        self.txt_dir.config(state="disabled")
        self.progress_frame.pack(fill="x", pady=(12, 0))

        # Run installation in background thread so UI stays responsive
        threading.Thread(target=self._run_install_thread, daemon=True).start()

    def _update_progress(self, val, text):
        self.progress_bar["value"] = val
        self.lbl_status.config(text=text)
        self.root.update_idletasks()

    def _run_install_thread(self):
        target_dir = self.install_dir_var.get().strip()
        bundle_dir = get_bundled_dir()

        try:
            # Terminate any running instances of NetCtrl or rust_engine to ensure file locks are released
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/IM", "NetCtrl.exe", "/IM", "rust_engine.exe"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                time.sleep(0.5)

            # 1. Create target directory
            self._update_progress(10, f"Creating directory: {target_dir}")
            os.makedirs(target_dir, exist_ok=True)

            # 2. Extract NetCtrl.exe
            self._update_progress(25, "Extracting NetCtrl Pro application...")
            src_exe = os.path.join(bundle_dir, "NetCtrl.exe")
            if not os.path.exists(src_exe):
                # Fallback check in dist folder if running from development script
                src_exe = os.path.join(bundle_dir, "dist", "NetCtrl.exe")
            
            dest_exe = os.path.join(target_dir, "NetCtrl.exe")
            if os.path.exists(src_exe):
                shutil.copy2(src_exe, dest_exe)
            else:
                raise FileNotFoundError(f"Source NetCtrl.exe not found in bundle: {src_exe}")

            # Copy icon and default config if present
            src_icon = os.path.join(bundle_dir, "icon.ico")
            dest_icon = os.path.join(target_dir, "icon.ico")
            if os.path.exists(src_icon):
                shutil.copy2(src_icon, dest_icon)

            src_names = os.path.join(bundle_dir, "device_names.json")
            dest_names = os.path.join(target_dir, "device_names.json")
            if os.path.exists(src_names) and not os.path.exists(dest_names):
                shutil.copy2(src_names, dest_names)

            # Write clean self-deleting uninstaller script
            uninstaller_path = os.path.join(target_dir, "uninstall.bat")
            with open(uninstaller_path, "w", encoding="utf-8") as f:
                f.write(r'''@echo off
setlocal EnableDelayedExpansion
title NetCtrl Pro Uninstaller

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\"\" %*' -Verb RunAs" 2>nul
    if %errorlevel% equ 0 exit /b 0
)

if /i "%1"=="/quiet" goto do_uninstall
if /i "%1"=="/silent" goto do_uninstall
if /i "%1"=="/y" goto do_uninstall

echo ============================================================
echo               Uninstalling NetCtrl Pro
echo ============================================================
echo.
set /p CONFIRM="Are you sure you want to completely remove NetCtrl Pro? (Y/N): "
if /i not "%CONFIRM%"=="Y" (
    echo Uninstallation cancelled.
    ping 127.0.0.1 -n 2 >nul
    exit /b 0
)

:do_uninstall
echo.
echo Stopping running processes...
taskkill /F /IM NetCtrl.exe /IM rust_engine.exe >nul 2>&1

echo Removing shortcuts...
del /f /q "%USERPROFILE%\Desktop\NetCtrl.lnk" 2>nul
del /f /q "%PUBLIC%\Desktop\NetCtrl.lnk" 2>nul
del /f /q "C:\Users\Public\Desktop\NetCtrl.lnk" 2>nul
del /f /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\NetCtrl.lnk" 2>nul
del /f /q "%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\NetCtrl.lnk" 2>nul

echo Removing registry entries...
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\NetCtrl" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\NetCtrl" /f >nul 2>&1

echo Cleaning application files...
set "TARGET_DIR=%~dp0"
if "%TARGET_DIR:~-1%"=="\" set "TARGET_DIR=%TARGET_DIR:~0,-1%"

cd /d "%TEMP%"
start "" powershell -NoProfile -WindowStyle Hidden -Command "$p = '%TARGET_DIR%'; for ($i = 0; $i -lt 15; $i++) { Start-Sleep -Milliseconds 500; if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue } else { break } }"

echo.
echo ============================================================
echo      NetCtrl Pro was successfully uninstalled!
echo ============================================================
ping 127.0.0.1 -n 3 >nul
exit /b 0
''')

            # Register in Windows Add/Remove Programs
            register_windows_uninstaller(target_dir)

            # 3. Optional Npcap installation
            if self.install_npcap_var.get() and not self.npcap_present:
                self._update_progress(50, "Installing Npcap network driver (WinPcap mode)...")
                npcap_src = os.path.join(bundle_dir, "npcap_installer.exe")
                if os.path.exists(npcap_src):
                    try:
                        # /winpcap_mode=yes enables legacy winpcap compatibility needed for raw packets
                        subprocess.run([npcap_src, "/winpcap_mode=yes"], check=False)
                    except Exception as e:
                        print(f"Npcap setup warning: {e}")

            # 4. Create Desktop Shortcut
            if self.shortcut_desktop_var.get():
                self._update_progress(75, "Creating Desktop shortcut...")
                desktop_dir = os.path.expanduser(r"~\Desktop")
                desktop_lnk = os.path.join(desktop_dir, "NetCtrl.lnk")
                create_windows_shortcut(dest_exe, desktop_lnk, dest_icon)

            # 5. Create Start Menu Shortcut
            if self.shortcut_startmenu_var.get():
                self._update_progress(90, "Creating Start Menu shortcut...")
                start_dir = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs")
                start_lnk = os.path.join(start_dir, "NetCtrl.lnk")
                create_windows_shortcut(dest_exe, start_lnk, dest_icon)

            self._update_progress(100, "Installation completed successfully! 🎉")
            self.root.after(400, lambda: self._show_finish_page(dest_exe))

        except Exception as err:
            self._update_progress(0, f"Installation failed: {err}")
            messagebox.showerror("Installation Error", f"An error occurred while installing NetCtrl Pro:\n\n{err}")
            self.btn_install.config(state="normal")
            self.btn_cancel.config(state="normal")

    def _show_finish_page(self, dest_exe):
        # Clear main content and show finish card
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        lbl_congrats = ttk.Label(
            self.content_frame,
            text="NetCtrl Pro is Ready!",
            font=("Segoe UI", 14, "bold"),
            foreground="#3fb950"
        )
        lbl_congrats.pack(anchor="w", pady=(10, 4))

        lbl_desc = ttk.Label(
            self.content_frame,
            text="The application has been installed and configured on your system.\nA shortcut has been placed on your Desktop for easy access.",
            font=("Segoe UI", 9)
        )
        lbl_desc.pack(anchor="w", pady=(0, 20))

        chk_launch = tk.Checkbutton(
            self.content_frame,
            text="Launch NetCtrl Pro now",
            variable=self.launch_after_var,
            bg="#0d1117",
            fg="#f0f6fc",
            activebackground="#0d1117",
            activeforeground="#58a6ff",
            selectcolor="#161b22",
            font=("Segoe UI", 9, "bold"),
            highlightthickness=0,
            bd=0,
            anchor="w",
            cursor="hand2"
        )
        chk_launch.pack(anchor="w", pady=(0, 10))

        # Update action buttons
        self.btn_cancel.pack_forget()
        self.btn_install.config(
            text="Finish",
            state="normal",
            command=lambda: self._finish_and_exit(dest_exe)
        )

    def _finish_and_exit(self, dest_exe):
        if self.launch_after_var.get():
            try:
                os.startfile(dest_exe)
            except Exception as e:
                print(f"Launch error: {e}")
        self.root.destroy()


def main():
    root = tk.Tk()
    app = NetCtrlInstallerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

"""
Polaris - Single-File Standalone Binary Packager with Custom Icon & Shell Refresh
Handles forceful cleanup of old instances, bundles all assets, embeds the HD icon, and creates Desktop shortcut.
"""

import os
import sys
import subprocess
import shutil
import time
import ctypes
from PIL import Image

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
MAIN_PY = os.path.join(BASE_DIR, "main.py")
ICON_PATH = os.path.join(BASE_DIR, "app_icon.ico")
LOGO_PNG = os.path.join(FRONTEND_DIR, "logo.png")

def ensure_clean_icon():
    print("[1/5] Generating multi-resolution HD Windows Icon...")
    if os.path.exists(LOGO_PNG):
        im = Image.open(LOGO_PNG).convert('RGBA')
        sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
        im.save(ICON_PATH, format='ICO', sizes=sizes)
        im.save(os.path.join(FRONTEND_DIR, "favicon.ico"), format='ICO', sizes=[(64, 64), (32, 32), (16, 16)])
        print(f"      Icon saved: {ICON_PATH} ({os.path.getsize(ICON_PATH)} bytes)")

def kill_running_instances():
    print("[2/5] Closing any running instances of Polaris.exe and MemPulse.exe...")
    try:
        subprocess.run(['taskkill', '/F', '/IM', 'Polaris.exe'], capture_output=True, check=False)
        subprocess.run(['taskkill', '/F', '/IM', 'MemPulse.exe'], capture_output=True, check=False)
        time.sleep(0.5)
    except Exception:
        pass

def build_single_file_exe():
    print("==================================================")
    print("  Building Polaris Standalone Enterprise EXE      ")
    print("==================================================")

    # Chart.js is the only third-party asset the UI loads (the stylesheet is
    # hand-written and needs no build step). Without it the charts are blank,
    # so fail loudly instead of shipping a broken build.
    vendor_dir = os.path.join(FRONTEND_DIR, "vendor")
    required_assets = ["chart.umd.js"]
    missing = [a for a in required_assets if not os.path.exists(os.path.join(vendor_dir, a))]
    if missing:
        print(f"[ERROR] Missing bundled assets in {vendor_dir}: {', '.join(missing)}")
        return

    ensure_clean_icon()
    kill_running_instances()

    print("[3/5] Running PyInstaller compilation (Native Desktop WebView & Backend with UAC Admin Manifest)...")
    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--name=Polaris",
        "--onefile",
        "--uac-admin",
        f"--icon={ICON_PATH}",
        f"--add-data={FRONTEND_DIR};frontend",
        f"--add-data={ICON_PATH};.",
        f"--add-data={os.path.join(BASE_DIR, 'CopilotToCtrl.exe')};.",
        f"--add-binary={os.path.join(BASE_DIR, 'bin', 'pdu.exe')};bin",
        "--collect-all=webview",
        "--hidden-import=webview",
        "--hidden-import=clr_loader",
        "--hidden-import=backend",
        "--hidden-import=backend.memory_analyzer",
        "--hidden-import=backend.process_manager",
        "--hidden-import=backend.diagnostic_engine",
        "--hidden-import=backend.knowledge_base",
        "--hidden-import=backend.system_revitalizer",
        "--hidden-import=backend.crash_analyzer",
        "--hidden-import=backend.copilot_remapper",
        "--hidden-import=backend.device_manager",
        "--hidden-import=backend.disk_health",
        "--hidden-import=backend.smart_engine",
        "--hidden-import=backend.smart_database",
        "--hidden-import=backend.event_log",
        "--hidden-import=backend.battery_analyzer",
        "--hidden-import=backend.uninstaller_engine",
        "--hidden-import=backend.storage_analyzer",
        "--hidden-import=backend.oem_update_manager",
        "--hidden-import=backend.onedrive_manager",
        "--hidden-import=backend.icon_cache_manager",
        "--hidden-import=backend.enterprise_it_manager",
        "--hidden-import=backend.windows_update_manager",
        "--hidden-import=backend.remote_control_manager",
        "--hidden-import=backend.minidump_parser",
        "--hidden-import=backend.driver_database",
        "--hidden-import=backend.driver_online_checker",
        "--hidden-import=backend.win_utils",
        "--hidden-import=backend.server",
        "--hidden-import=win32com",
        "--hidden-import=pythoncom",
        "--clean",
        "--noconfirm",
        MAIN_PY
    ]

    # A desktop app should not open a black console window behind its UI.
    # Build with `python package_exe.py --console` when you need the log output.
    if "--console" not in sys.argv:
        cmd.insert(4, "--noconsole")

    res = subprocess.run(cmd, cwd=BASE_DIR)
    
    if res.returncode == 0:
        src_exe = os.path.join(BASE_DIR, "dist", "Polaris.exe")
        target_root_exe = os.path.join(BASE_DIR, "Polaris.exe")
        
        print("[4/5] Copying standalone executable to project root...")
        if os.path.exists(src_exe):
            shutil.copy2(src_exe, target_root_exe)
            print(f"      Ready at: {target_root_exe}")

        print("[5/5] Refreshing Windows Explorer icon cache & creating Desktop shortcut...")
        try:
            # Refresh Windows Shell
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, 0, 0)
            
            # Create desktop shortcut via PowerShell
            ps_script = f"""
            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("$([Environment]::GetFolderPath('Desktop'))\\Polaris.lnk")
            $Shortcut.TargetPath = "{target_root_exe}"
            $Shortcut.WorkingDirectory = "{BASE_DIR}"
            $Shortcut.IconLocation = "{ICON_PATH}, 0"
            $Shortcut.Description = "Polaris - Windows Diagnostics & Stability Suite"
            $Shortcut.Save()
            """
            subprocess.run(['powershell', '-Command', ps_script], capture_output=True, check=False)
            print("      Desktop shortcut updated with HD Icon!")
        except Exception as e:
            print(f"      Shortcut note: {e}")

        print("\n==================================================")
        print("  [SUCCESS] Polaris Enterprise build is COMPLETE!  ")
        print("==================================================")
    else:
        print("\n[ERROR] Build failed with return code:", res.returncode)

if __name__ == "__main__":
    build_single_file_exe()

"""
Polaris - OEM / Manufacturer Update Manager.

Ported and enhanced from Limitless (WinAutomator/UpdateManager.cs):
  - Hardware & OEM Detection: WMI identification of vendor (Dell, Lenovo, HP, Universal/Other),
    model, and serial number.
  - Dell Command | Update (DCU):
      * Ensures .NET 8 / 10 runtimes are installed
      * Applies OOBE bypass in registry (IGNOREOOBE = 1)
      * Auto-downloads 5.7.1 from Dell CDN with Tier 2 Fail-Safe (5.7.0) and Winget fallback
      * Executes dcu-cli.exe unattended and streams execution logs
  - Lenovo System Update (TVSU):
      * Auto-installs via Winget (Lenovo.SystemUpdate) if missing
      * Applies silent EULA / license acceptance registry bypasses
      * Executes tvsu.exe in unattended mode (/CM -search A -action INSTALL -packagetypes 1,2,3)
      * Real-time output line parsing and child process tracking (tvsukernel, MapDrv, etc.)
  - HP Image Assistant (HPIA):
      * Auto-installs via Winget or downloads portable package from HP CDN
      * Executes HPIA analysis and unattended SoftPaq install
      * Real-time line parsing, inactivity watchdog, and child process management
  - Universal Driver Updates & Windows Optional Drivers:
      * SDIO (Snappy Driver Installer Origin) portable runner
      * Windows Update Agent COM API driver search & install
  - Multi-pass execution (Pass 1 -> 30s settle -> Pass 2 if updates installed)
  - Pending reboot detection (CBS, WindowsUpdate, PendingFileRenameOperations)
"""

import os
import sys
import time
import json
import queue
import shutil
import urllib.request
import subprocess
import threading
from datetime import datetime

from backend.win_utils import (
    IS_WINDOWS,
    run_hidden,
    popen_hidden,
    run_powershell_json,
    is_admin
)

if IS_WINDOWS:
    import winreg
else:
    winreg = None


# ---------------------------------------------------------------------------
# OEM Paths & Download URLs
# ---------------------------------------------------------------------------

DELL_PATHS = [
    r"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe",
    r"C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe",
]
DELL_WINGET_ID = "Dell.CommandUpdate.Universal"
DELL_DOWNLOAD_URL_571 = "https://dl.dell.com/FOLDER14847331M/2/Dell-Command-Update-Windows-Universal-Application_P0P70_WIN64_5.7.1_A00.EXE"
DELL_DOWNLOAD_URL_570 = "https://dl.dell.com/FOLDER14424601M/1/Dell-Command-Update-Windows-Universal-Application_FGK9X_WIN64_5.7.0_A00.EXE"

LENOVO_PATHS = [
    r"C:\Program Files (x86)\Lenovo\System Update\tvsu.exe",
    r"C:\Program Files\Lenovo\System Update\tvsu.exe",
    r"C:\Program Files (x86)\Lenovo\System Update\tvsukernel.exe",
    r"C:\Program Files\Lenovo\System Update\tvsukernel.exe",
]
LENOVO_WINGET_ID = "Lenovo.SystemUpdate"

HP_PATHS = [
    r"C:\HP_Image_Assistant\HPImageAssistant.exe",
    r"C:\Program Files\HP\HP Image Assistant\HPImageAssistant.exe",
    r"C:\Program Files (x86)\HP\HP Image Assistant\HPImageAssistant.exe",
]
HP_WINGET_ID = "HP.ImageAssistant"
HP_DOWNLOAD_URLS = [
    "https://hpia.hpcloud.hp.com/downloads/hpia/hp-hpia-5.3.6.exe",
    "https://ftp.ext.hp.com/pub/caps-softpaq/cmit/hp-hpia-5.3.6.exe",
]
HP_EXTRACT_FOLDER = r"C:\HP_Image_Assistant"
HP_SOFTPAQ_FOLDER = r"C:\HP_Softpaqs"

UNIVERSAL_DRIVER_PATHS = [
    r"C:\TechTools\SDIO\SDI_x64.exe",
    r"C:\TechTools\SDIO\SDIO_x64_R760.exe",
    r"D:\SDI\sdi.exe",
    r"D:\SDIO\SDIO_auto.bat",
    r"E:\SDI\sdi.exe",
]
SDIO_DOWNLOAD_URL = "https://github.com/SamLabs/SDI_Origin/releases/latest/download/SDI_x64.exe"

# ---------------------------------------------------------------------------
# Registry Helper Functions
# ---------------------------------------------------------------------------

def _set_reg_dword(root_key, subkey, name, value):
    if not IS_WINDOWS or not winreg:
        return False
    try:
        with winreg.CreateKeyEx(root_key, subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(value))
        return True
    except Exception:
        return False

def _set_reg_sz(root_key, subkey, name, value):
    if not IS_WINDOWS or not winreg:
        return False
    try:
        with winreg.CreateKeyEx(root_key, subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, str(value))
        return True
    except Exception:
        return False

def check_pending_reboot():
    """Checks Windows Registry to determine if a system reboot is pending."""
    if not IS_WINDOWS or not winreg:
        return False
    
    # 1. Component Based Servicing
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
                            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
            return True
    except OSError:
        pass

    # 2. Windows Update
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
                            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
            return True
    except OSError:
        pass

    # 3. Session Manager PendingFileRenameOperations
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control\Session Manager",
                            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            val, _ = winreg.QueryValueEx(k, "PendingFileRenameOperations")
            if val:
                return True
    except OSError:
        pass

    return False


# ---------------------------------------------------------------------------
# OemUpdateManager Class
# ---------------------------------------------------------------------------

class OemUpdateManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.is_running = False
        self.cancel_requested = False
        self.current_step = ""
        self.current_step_en = ""
        self.progress_percent = 0
        self.live_logs = []
        self.final_results = None

        self._log_uid = 0
        self._log_rev = 0
        self._started_at = None
        self._active_procs = []
        self._cached_system_info = None

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def log(self, message, level="INFO", step=None, replace_key=None):
        ts = time.strftime("%H:%M:%S")
        with self.lock:
            self._log_rev += 1
            if replace_key and self.live_logs:
                for entry in reversed(self.live_logs[-12:]):
                    if entry.get("key") == replace_key:
                        entry["time"] = ts
                        entry["text"] = message
                        entry["level"] = level
                        entry["rev"] = self._log_rev
                        return

            self._log_uid += 1
            self.live_logs.append({
                "uid": self._log_uid,
                "rev": self._log_rev,
                "time": ts,
                "level": level,
                "text": message,
                "step": step,
                "key": replace_key,
            })
            if len(self.live_logs) > 1200:
                self.live_logs = self.live_logs[-800:]

    @property
    def log_rev(self):
        return self._log_rev

    # ------------------------------------------------------------------
    # System & Manufacturer Detection
    # ------------------------------------------------------------------

    def detect_manufacturer(self):
        """
        Detects PC manufacturer and hardware model through multiple WMI tables.
        Normalizes to 'Dell', 'Lenovo', 'HP', or 'Other'.
        """
        if self._cached_system_info:
            return self._cached_system_info

        mfr_raw = ""
        model_raw = ""
        serial_raw = ""

        if IS_WINDOWS:
            ps_script = """
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
            $bb = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
            $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
            $enc = Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue

            [PSCustomObject]@{
                CsMfr   = [string]$cs.Manufacturer
                CsModel = [string]$cs.Model
                BbMfr   = [string]$bb.Manufacturer
                BbProd  = [string]$bb.Product
                BiosMfr = [string]$bios.Manufacturer
                BiosSerial = [string]$bios.SerialNumber
                EncMfr  = [string]$enc.Manufacturer
            } | ConvertTo-Json -Compress
            """
            data = run_powershell_json(ps_script, timeout=15)
            if data and isinstance(data, list) and len(data) > 0:
                row = data[0] if isinstance(data[0], dict) else {}
                candidates_mfr = [
                    row.get("CsMfr"), row.get("BbMfr"),
                    row.get("BiosMfr"), row.get("EncMfr")
                ]
                candidates_model = [row.get("CsModel"), row.get("BbProd")]
                serial_raw = (row.get("BiosSerial") or "").strip()

                for m in candidates_mfr:
                    if m and m.strip():
                        mfr_raw = m.strip()
                        break
                for mdl in candidates_model:
                    if mdl and mdl.strip():
                        model_raw = mdl.strip()
                        break

        normalized = self._normalize_manufacturer(mfr_raw, model_raw)
        info = {
            "normalized": normalized,
            "raw_manufacturer": mfr_raw or "Unknown",
            "model": model_raw or "Standard PC",
            "serial": serial_raw or "N/A",
        }
        self._cached_system_info = info
        return info

    def _normalize_manufacturer(self, mfr, model):
        combined = f"{mfr or ''} {model or ''}".upper().strip()

        if not combined:
            return "Universal"

        if "LENOVO" in combined or "THINKPAD" in combined or "IDEAPAD" in combined or "LEGION" in combined:
            return "Lenovo"
        if ("DELL" in combined or "ALIENWARE" in combined or "VOSTRO" in combined or
                "LATITUDE" in combined or "INSPIRON" in combined or "PRECISION" in combined or "XPS" in combined):
            return "Dell"
        if ("HP" in combined or "HEWLETT" in combined or "OMEN" in combined or
                "PAVILION" in combined or "ELITEBOOK" in combined or "PROBOOK" in combined or
                "VICTUS" in combined or "ENVY" in combined or "SPECTRE" in combined):
            return "HP"

        placeholders = [
            "TO BE FILLED", "SYSTEM MANUFACTURER", "DEFAULT STRING",
            "ALL SERIES", "CHASSIS MANUFACTURE", "NOT SPECIFIED",
            "UNKNOWN", "SYSTEM PRODUCT NAME", "BASE BOARD", "O.E.M"
        ]
        if any(p in combined for p in placeholders):
            return "Universal"

        return "Other"

    # ------------------------------------------------------------------
    # Tool Status Inspection
    # ------------------------------------------------------------------

    def get_tool_status(self, manufacturer=None):
        if not manufacturer:
            sys_info = self.detect_manufacturer()
            manufacturer = sys_info["normalized"]

        m_upper = (manufacturer or "").strip().upper()
        if m_upper == "DELL":
            man_norm = "Dell"
        elif m_upper == "LENOVO":
            man_norm = "Lenovo"
        elif m_upper in ("HP", "HEWLETT-PACKARD"):
            man_norm = "HP"
        else:
            man_norm = "Universal" if m_upper in ("UNIVERSAL", "OTHER", "") else manufacturer

        status = {
            "manufacturer": man_norm,
            "tool_name": "",
            "installed": False,
            "path": "",
            "version": "",
            "can_auto_install": True,
            "details_he": "",
            "details_en": ""
        }

        if man_norm == "Dell":
            status["tool_name"] = "Dell Command | Update"
            dot8 = self._is_dotnet_desktop_installed("8")
            dot10 = self._is_dotnet_desktop_installed("10")
            status["dotnet_8_installed"] = dot8
            status["dotnet_10_installed"] = dot10

            for p in DELL_PATHS:
                if os.path.exists(p):
                    status["installed"] = True
                    status["path"] = p
                    status["version"] = self._get_file_version(p)
                    break

            runtimes_missing_he = []
            runtimes_missing_en = []
            if not dot8:
                runtimes_missing_he.append(".NET 8.0")
                runtimes_missing_en.append(".NET 8.0")
            if not dot10:
                runtimes_missing_he.append(".NET 10.0")
                runtimes_missing_en.append(".NET 10.0")

            if status["installed"]:
                d_he = f"הכלי הרשמי מותקן (גרסה {status['version'] or 'קיימת'})."
                d_en = f"Official tool installed (v{status['version'] or 'detected'})."
            else:
                d_he = "הכלי אינו מותקן. פולאריס תוריד ותתקין אוטומטית משרתי Dell."
                d_en = "Tool not installed. Polaris will automatically download from Dell CDN."

            if runtimes_missing_he:
                d_he += f" נדרשים רכיבי ריצה: {' ו-'.join(runtimes_missing_he)} Desktop Runtime (מותקנים אוטומטית בעת הפעלה)."
                d_en += f" Required runtimes: {', '.join(runtimes_missing_en)} Desktop Runtime (will auto-install on run)."
            else:
                d_he += " רכיבי ריצה .NET 8 ו-.NET 10 מותקנים ומאומתים ✓."
                d_en += " .NET 8 & .NET 10 runtimes are installed ✓."

            status["details_he"] = d_he
            status["details_en"] = d_en

        elif man_norm == "Lenovo":
            status["tool_name"] = "Lenovo System Update"
            for p in LENOVO_PATHS:
                if os.path.exists(p):
                    status["installed"] = True
                    status["path"] = p
                    status["version"] = self._get_file_version(p)
                    break
            if status["installed"]:
                status["details_he"] = f"הכלי הרשמי מותקן (גרסה {status['version'] or 'קיימת'})"
                status["details_en"] = f"Official tool installed (v{status['version'] or 'detected'})"
            else:
                status["details_he"] = "הכלי אינו מותקן. פולאריס תתקין אוטומטית דרך Winget."
                status["details_en"] = "Tool not installed. Polaris will install via Winget."

        elif man_norm == "HP":
            status["tool_name"] = "HP Image Assistant (HPIA)"
            for p in HP_PATHS:
                if os.path.exists(p):
                    status["installed"] = True
                    status["path"] = p
                    status["version"] = self._get_file_version(p)
                    break
            if status["installed"]:
                status["details_he"] = f"הכלי הרשמי מותקן (גרסה {status['version'] or 'קיימת'})"
                status["details_en"] = f"Official tool installed (v{status['version'] or 'detected'})"
            else:
                status["details_he"] = "הכלי אינו מותקן. פולאריס תוריד ותחלץ אוטומטית משרתי HP."
                status["details_en"] = "Tool not installed. Polaris will download and extract from HP CDN."

        else:
            status["tool_name"] = "מנוע דרייברים אוניברסלי (SDIO / Windows Update)"
            for p in UNIVERSAL_DRIVER_PATHS:
                if os.path.exists(p):
                    status["installed"] = True
                    status["path"] = p
                    break
            if status["installed"]:
                status["details_he"] = "כלי דרייברים נייד (SDIO) זוהה מקומית."
                status["details_en"] = "Portable driver tool (SDIO) found locally."
            else:
                status["details_he"] = "שימוש בעדכוני דרייברים דרך Windows Update Agent ו-SDIO נייד."
                status["details_en"] = "Using Windows Update Agent & portable SDIO engine."

        return status

    def _get_file_version(self, file_path):
        if not IS_WINDOWS or not os.path.exists(file_path):
            return ""
        try:
            ps = f"(Get-Item '{file_path}').VersionInfo.FileVersion"
            res = run_hidden(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                             capture_output=True, text=True, timeout=5)
            return (res.stdout or "").strip()
        except Exception:
            return ""

    def get_oem_info(self, override_manufacturer=None):
        """Full info packet for the frontend UI."""
        sys_info = self.detect_manufacturer()
        target_mfr = override_manufacturer or sys_info["normalized"]
        tool_info = self.get_tool_status(target_mfr)
        reboot_needed = check_pending_reboot()
        admin = is_admin()

        return {
            "manufacturer": sys_info["normalized"],
            "selected_manufacturer": target_mfr,
            "raw_manufacturer": sys_info["raw_manufacturer"],
            "model": sys_info["model"],
            "serial": sys_info["serial"],
            "tool": tool_info,
            "pending_reboot": reboot_needed,
            "is_admin": admin,
            "is_running": self.is_running,
            "last_results": self.final_results
        }

    # ------------------------------------------------------------------
    # Asynchronous Execution Controller
    # ------------------------------------------------------------------

    def start_oem_updates_async(self, manufacturer=None, options=None):
        with self.lock:
            if self.is_running:
                return {"success": False, "error": "תהליך עדכוני יצרן כבר רץ כעת ברקע."}

            self.is_running = True
            self.cancel_requested = False
            self.progress_percent = 0
            self.current_step = "מאתחל עדכוני יצרן..."
            self.current_step_en = "Initializing OEM updates..."
            self.live_logs = []
            self.final_results = None
            self._started_at = time.time()
            self._active_procs = []

        opts = options or {}
        if not manufacturer or manufacturer == "Auto":
            manufacturer = self.detect_manufacturer()["normalized"]

        thread = threading.Thread(
            target=self._run_oem_updates_worker,
            args=(manufacturer, opts),
            daemon=True
        )
        thread.start()
        return {"success": True, "manufacturer": manufacturer}

    def cancel_updates(self):
        with self.lock:
            if not self.is_running:
                return {"success": True, "message": "No process running"}
            self.cancel_requested = True
            self.log("[!] בקשת ביטול התקבלה. עוצר תהליכים...", "WARN")

        # Terminate tracked child processes
        for p in list(self._active_procs):
            try:
                p.kill()
            except Exception:
                pass

        return {"success": True, "message": "Cancellation requested"}

    def get_progress(self, since_log_id=0):
        with self.lock:
            try:
                since = int(since_log_id or 0)
            except (TypeError, ValueError):
                since = 0

            logs = [dict(l) for l in self.live_logs if l.get("rev", 0) > since]
            elapsed = (time.time() - self._started_at) if self._started_at else 0

            return {
                "running": self.is_running,
                "is_running": self.is_running,
                "progress_percent": self.progress_percent,
                "progress": self.progress_percent,
                "current_step": self.current_step,
                "step": self.current_step,
                "current_step_en": self.current_step_en,
                "step_en": self.current_step_en,
                "elapsed_seconds": round(elapsed, 1),
                "log_rev": self._log_rev,
                "logs": logs,
                "new_logs": logs,
                "results": self.final_results,
                "final_results": self.final_results,
                "pending_reboot": check_pending_reboot(),
            }

    # ------------------------------------------------------------------
    # Worker Thread Implementation
    # ------------------------------------------------------------------

    def _run_oem_updates_worker(self, manufacturer, options):
        try:
            self.log(f"═══════════════════════════════════════════════════════", "INFO")
            self.log(f"🚀 התחלת עדכוני יצרן עבור: {manufacturer}", "SUCCESS")
            self.log(f"═══════════════════════════════════════════════════════", "INFO")

            if not is_admin():
                self.log("⚠ שים לב: פולאריס אינה רצה כמנהל מערכת (Administrator).", "WARN")
                self.log("התקנת דרייברים עשויה לדרוש אישור בחלון UAC או להיכשל.", "WARN")

            man_lower = manufacturer.lower()
            max_passes = 2 if options.get("two_passes", True) else 1
            include_win_optional = options.get("include_windows_optional", True)

            installed_any_updates = False

            for pass_num in range(1, max_passes + 1):
                if self.cancel_requested:
                    self.log("הפעולה בוטלה על ידי המשתמש.", "WARN")
                    break

                if max_passes > 1:
                    self.log(f"--- סבב {pass_num} מתוך {max_passes} ---", "INFO")
                self._set_progress(10 + (pass_num - 1) * 40, f"סבב {pass_num}: מעבד עדכוני {manufacturer}")

                had_activity = False

                if "dell" in man_lower:
                    had_activity = self._run_dell_updates()
                    self.install_dotnet_8()
                    self.install_dotnet_10()
                elif "lenovo" in man_lower:
                    had_activity = self._run_lenovo_updates()
                elif "hp" in man_lower or "hewlett" in man_lower:
                    had_activity = self._run_hp_updates()
                else:
                    self.log(f"נבחר יצרן כללי '{manufacturer}'. מפעיל עדכוני דרייברים אוניברסליים.", "INFO")
                    had_activity = self._run_universal_driver_updates()
                    break

                if had_activity:
                    installed_any_updates = True

                # If first pass had no updates, skip second pass
                if pass_num == 1 and not had_activity and max_passes > 1:
                    self.log("לא אותרו עדכונים נוספים בסבב 1. מדלג על סבב 2.", "INFO")
                    break

                # Settle delay between passes
                if pass_num < max_passes and not self.cancel_requested:
                    self.log("ממתין 20 שניות לסיום תהליכי רקע לפני סבב הבא...", "INFO")
                    for _ in range(20):
                        if self.cancel_requested:
                            break
                        time.sleep(1)

            # Optional Windows Update Driver pass
            if include_win_optional and not self.cancel_requested:
                self._set_progress(85, "סורק עדכוני דרייברים ב-Windows Update")
                self._run_windows_optional_driver_updates()

            # Final check
            self._set_progress(100, "הושלם בהצלחה")
            reboot_needed = check_pending_reboot()

            self.final_results = {
                "success": True,
                "manufacturer": manufacturer,
                "updates_applied": installed_any_updates,
                "reboot_required": reboot_needed,
                "completed_at": datetime.now().strftime("%H:%M:%S")
            }

            self.log("═══════════════════════════════════════════════════════", "INFO")
            if reboot_needed:
                self.log("🔄 עדכוני היצרן הושלמו! זוהה צורך בהפעלת המחשב מחדש להחלת השינויים.", "WARN")
            else:
                self.log(f"✅ עדכוני היצרן ({manufacturer}) הושלמו בהצלחה!", "SUCCESS")
            self.log("═══════════════════════════════════════════════════════", "INFO")

        except Exception as ex:
            self.log(f"✗ שגיאה בלתי צפויה בעדכוני יצרן: {ex}", "ERROR")
            self.final_results = {
                "success": False,
                "error": str(ex),
                "reboot_required": check_pending_reboot()
            }
        finally:
            with self.lock:
                self.is_running = False

    def _set_progress(self, pct, step_he, step_en=None):
        with self.lock:
            self.progress_percent = min(100, max(0, pct))
            self.current_step = step_he
            self.current_step_en = step_en or step_he

    # ------------------------------------------------------------------
    # DELL UPDATE PIPELINE
    # ------------------------------------------------------------------

    def _run_dell_updates(self):
        self.log("בודק רכיבי Dell Command | Update...", "INFO")

        # 1. Ensure required .NET runtimes (8.0 and 10.0.11) are installed first
        self.install_dotnet_8()
        self.install_dotnet_10()

        # 2. Registry OOBE bypass
        self._apply_dell_registry_bypass()

        # 3. Check for existing dcu-cli.exe
        dcu_path = None
        for p in DELL_PATHS:
            if os.path.exists(p):
                dcu_path = p
                break

        needs_install = False
        if not dcu_path:
            self.log("Dell Command Update אינו מותקן במערכת.", "WARN")
            needs_install = True
        else:
            ver = self._get_file_version(dcu_path)
            self.log(f"זוהה Dell Command Update קיים (גרסה {ver or 'לא ידועה'}).", "INFO")
            # If version is older than 5.7, attempt upgrade
            if ver and ver.startswith(("1.", "2.", "3.", "4.", "5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6")):
                self.log(f"הגרסה ישנה ({ver}). משדרג לגרסה 5.7...", "INFO")
                needs_install = True

        if needs_install:
            dcu_path = self._install_dell_command_update()

        if not dcu_path or not os.path.exists(dcu_path):
            self.log("⚠ לא ניתן להריץ Dell Command Update (הכלי לא נמצא). ממשיך ב-Windows Update...", "WARN")
            return False

        # Run dcu-cli.exe
        log_dir = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "Polaris_OEM_Logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"DellUpdate_{time.strftime('%H%M%S')}.log")

        cmd = [
            dcu_path,
            "/applyUpdates",
            "-reboot=disable",
            f'-outputLog={log_file}'
        ]
        self.log(f"מריץ Dell Command Update: {os.path.basename(dcu_path)}...", "INFO")
        self.log("סורק ומחיל עדכונים רשמיים מ-Dell (פעולה זו עשויה להימשך מספר דקות)...", "INFO")

        res_code = self._execute_and_stream(cmd, log_file, parser=self._parse_dell_line, timeout_secs=900)
        self.log(f"עדכוני Dell הסתיימו (Exit Code: {res_code})", "INFO")

        # Exit code 0: No updates; 1: Updates applied; 2: Reboot required; 5: Reboot needed
        return res_code in (1, 2, 5)

    def _apply_dell_registry_bypass(self):
        try:
            _set_reg_dword(
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Dell\UpdateService\Service\UpdateScheduler",
                "IGNOREOOBE",
                1
            )
            self.log("מעקף מסך הגדרה ראשונית (IGNOREOOBE) הוחל בהצלחה.", "INFO")
        except Exception:
            pass

    def _install_dell_command_update(self):
        temp_dir = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "DellUpdateSetup")
        os.makedirs(temp_dir, exist_ok=True)
        installer_571 = os.path.join(temp_dir, "DCU_5.7.1.exe")
        installer_570 = os.path.join(temp_dir, "DCU_5.7.0.exe")

        # Tier 1: Download 5.7.1 from Dell CDN
        self.log("🚀 [Tier 1] מוריד Dell Command Update 5.7.1 ישירות מ-Dell CDN...", "INFO")
        if self._download_file(DELL_DOWNLOAD_URL_571, installer_571):
            self.log("מפעיל התקנה שקטה של Dell Command Update 5.7.1...", "INFO")
            res = run_hidden([installer_571, "/s"], timeout=300)
            time.sleep(5)
            for p in DELL_PATHS:
                if os.path.exists(p):
                    self.log("התקנת Dell Command Update 5.7.1 הושלמה בהצלחה ✓", "SUCCESS")
                    return p

        # Tier 2: Fail-Safe 5.7.0
        self.log("⚡ [Tier 2 Fail-Safe] מנסה הורדת גרסה 5.7.0...", "WARN")
        if self._download_file(DELL_DOWNLOAD_URL_570, installer_570):
            self.log("מפעיל התקנה של גרסה 5.7.0...", "INFO")
            res = run_hidden([installer_570, "/s"], timeout=300)
            time.sleep(5)
            for p in DELL_PATHS:
                if os.path.exists(p):
                    self.log("התקנת Fail-Safe 5.7.0 הושלמה בהצלחה ✓", "SUCCESS")
                    return p

        # Tier 3: Winget
        self.log("מנסה התקנת Dell Command Update דרך Winget...", "INFO")
        self._run_winget_install(DELL_WINGET_ID)
        time.sleep(5)
        for p in DELL_PATHS:
            if os.path.exists(p):
                return p

        return None

    def _is_dotnet_desktop_installed(self, major_ver):
        major_str = str(major_ver).strip()
        # 1. Filesystem check
        for folder in (r"C:\Program Files\dotnet\shared\Microsoft.WindowsDesktop.App",
                       r"C:\Program Files (x86)\dotnet\shared\Microsoft.WindowsDesktop.App"):
            if os.path.isdir(folder):
                try:
                    for sub in os.listdir(folder):
                        if sub.startswith(f"{major_str}."):
                            return True
                except Exception:
                    pass

        # 2. Registry check
        if IS_WINDOWS and winreg:
            reg_paths = [
                r"SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.WindowsDesktop.App",
                r"SOFTWARE\dotnet\Setup\InstalledVersions\x86\sharedfx\Microsoft.WindowsDesktop.App",
                r"SOFTWARE\WOW6432Node\dotnet\Setup\InstalledVersions\x86\sharedfx\Microsoft.WindowsDesktop.App",
            ]
            for rp in reg_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rp, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                        idx = 0
                        while True:
                            sub = winreg.EnumKey(k, idx)
                            if sub.startswith(f"{major_str}."):
                                return True
                            idx += 1
                except OSError:
                    pass

        # 3. dotnet CLI check
        try:
            dotnet_exe = shutil.which("dotnet") or r"C:\Program Files\dotnet\dotnet.exe"
            if os.path.exists(dotnet_exe):
                res = run_hidden([dotnet_exe, "--list-runtimes"], capture_output=True, text=True, timeout=5)
                if res.returncode == 0 and f"Microsoft.WindowsDesktop.App {major_str}." in (res.stdout or ""):
                    return True
        except Exception:
            pass

        return False

    def install_dotnet_8(self):
        """
        Installs .NET 8.0 Desktop Runtime via winget (prerequisite for Dell Command Update).
        Checks if already installed before attempting installation.
        """
        self.log("בודק אם .NET 8.0 Desktop Runtime מותקן...", "INFO")
        if self._is_dotnet_desktop_installed("8"):
            self.log(".NET 8.0 Desktop Runtime כבר מותקן ✓", "SUCCESS")
            return True

        self.log("מתקין .NET 8.0 Desktop Runtime...", "INFO")
        success = self._run_winget_install("Microsoft.DotNet.DesktopRuntime.8")

        # Fallback direct download from Microsoft if winget failed
        if not success and not self._is_dotnet_desktop_installed("8"):
            self.log("מנסה התקנה ישירה של .NET 8.0 Desktop Runtime מ-Microsoft...", "INFO")
            direct_url = "https://aka.ms/dotnet/8.0/windowsdesktop-runtime-win-x64.exe"
            temp_installer = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "windowsdesktop-runtime-8-x64.exe")
            if self._download_file(direct_url, temp_installer):
                res = run_hidden([temp_installer, "/install", "/quiet", "/norestart"], timeout=300)
                time.sleep(3)

        if self._is_dotnet_desktop_installed("8"):
            self.log("התקנת .NET 8.0 Desktop Runtime הושלמה ✓", "SUCCESS")
            return True
        else:
            self.log("התקנת .NET 8.0 Desktop Runtime הסתיימה.", "INFO")
            return False

    def install_dotnet_10(self):
        """
        Installs .NET 10.0 (10.0.11) Desktop Runtime via winget (for Dell machines).
        Checks if already installed before attempting installation.
        """
        self.log("בודק אם .NET 10.0 Desktop Runtime מותקן...", "INFO")
        if self._is_dotnet_desktop_installed("10"):
            self.log(".NET 10.0 (10.0.11) Desktop Runtime כבר מותקן ✓", "SUCCESS")
            return True

        self.log("מתקין .NET 10.0 (10.0.11) Desktop Runtime...", "INFO")
        success = self._run_winget_install("Microsoft.DotNet.DesktopRuntime.10")

        if self._is_dotnet_desktop_installed("10"):
            self.log("התקנת .NET 10.0 (10.0.11) Desktop Runtime הושלמה ✓", "SUCCESS")
            return True
        else:
            self.log("התקנת .NET 10.0 Desktop Runtime הסתיימה.", "INFO")
            return False

    # ------------------------------------------------------------------
    # LENOVO UPDATE PIPELINE
    # ------------------------------------------------------------------

    def _run_lenovo_updates(self):
        self.log("מחפש Lenovo System Update...", "INFO")

        tvsu_path = None
        for p in LENOVO_PATHS:
            if os.path.exists(p) and p.lower().endswith("tvsu.exe"):
                tvsu_path = p
                break

        if not tvsu_path:
            self.log("Lenovo System Update אינו מותקן. מתקין דרך Winget...", "INFO")
            self._run_winget_install(LENOVO_WINGET_ID)
            time.sleep(8)
            for p in LENOVO_PATHS:
                if os.path.exists(p) and p.lower().endswith("tvsu.exe"):
                    tvsu_path = p
                    break

        if not tvsu_path or not os.path.exists(tvsu_path):
            self.log("⚠ Lenovo System Update לא נמצא לאחר ניסיון התקנה.", "WARN")
            return False

        # Apply EULA & License bypasses
        self._apply_lenovo_registry_bypass()

        log_dir = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "Polaris_OEM_Logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"LenovoUpdate_{time.strftime('%H%M%S')}.log")

        try:
            if os.path.exists(log_file):
                os.remove(log_file)
        except Exception:
            pass

        # Command for fully silent unattended execution (cmd /c start /wait handles GUI detachment)
        cmd = f'cmd.exe /c start /wait "" "{tvsu_path}" /CM -search A -action INSTALL -packagetypes 1,2,3 -includerebootpackages 3,4 -noreboot -noicon -nolicense -log "{log_file}"'

        self.log("מריץ Lenovo System Update (מצב שקט ומאומת רישיון)...", "INFO")
        self.log("סורק ומוריד חבילות עדכון עבור ה-ThinkPad / IdeaPad שלך...", "INFO")

        res_code = self._execute_and_stream(cmd, log_file, parser=self._parse_lenovo_line, timeout_secs=1200)

        # Wait for background processes like tvsukernel or MapDrv to finish
        self.log("ממתין לסיום תהליכי רקע של Lenovo...", "INFO")
        self._wait_for_processes(["tvsukernel", "tvsu", "MapDrv", "Lenovo.LSU"], max_secs=45)

        self.log(f"עדכוני Lenovo הסתיימו (Exit Code: {res_code})", "INFO")
        return res_code in (0, 1, 4, 3010)

    def _apply_lenovo_registry_bypass(self):
        try:
            _set_reg_sz(winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Policies\Lenovo\System Update\Consent\Simplification",
                        "Active", "YES")

            pref_keys = [
                r"SOFTWARE\Lenovo\System Update\Preferences\UserSettings\General",
                r"SOFTWARE\Wow6432Node\Lenovo\System Update\Preferences\UserSettings\General"
            ]
            for pk in pref_keys:
                _set_reg_sz(winreg.HKEY_LOCAL_MACHINE, pk, "AskBeforeDescription", "NO")
                _set_reg_sz(winreg.HKEY_LOCAL_MACHINE, pk, "DisplayLicenseNotice", "NO")
                _set_reg_sz(winreg.HKEY_LOCAL_MACHINE, pk, "QuestChannel", "Quest")

            self.log("מעקפי תנאי רישיון (EULA) של Lenovo הוחלו בהצלחה.", "INFO")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # HP UPDATE PIPELINE
    # ------------------------------------------------------------------

    def _run_hp_updates(self):
        self.log("מחפש HP Image Assistant (HPIA)...", "INFO")

        hpia_path = None
        for p in HP_PATHS:
            if os.path.exists(p):
                hpia_path = p
                break

        if not hpia_path:
            self.log("HPIA אינו מותקן מקומית. מנסה התקנה דרך Winget...", "INFO")
            self._run_winget_install(HP_WINGET_ID)
            time.sleep(5)
            for p in HP_PATHS:
                if os.path.exists(p):
                    hpia_path = p
                    break

        if not hpia_path:
            self.log("מוריד HP Image Assistant משרתי HP הרשמיים...", "INFO")
            temp_installer = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "hpia-installer.exe")
            downloaded = False
            for url in HP_DOWNLOAD_URLS:
                if self._download_file(url, temp_installer):
                    downloaded = True
                    break

            if downloaded:
                self.log("מחלץ את HP Image Assistant...", "INFO")
                os.makedirs(HP_EXTRACT_FOLDER, exist_ok=True)
                run_hidden([temp_installer, "/s", "/e", "/f", HP_EXTRACT_FOLDER], timeout=120)
                time.sleep(5)
                try:
                    os.remove(temp_installer)
                except Exception:
                    pass

                for p in HP_PATHS:
                    if os.path.exists(p):
                        hpia_path = p
                        break

        if not hpia_path or not os.path.exists(hpia_path):
            self.log("⚠ HP Image Assistant לא אותר. ממשיך בעדכונים אוניברסליים.", "WARN")
            return False

        log_dir = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "Polaris_OEM_Logs")
        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(HP_SOFTPAQ_FOLDER, exist_ok=True)

        log_file = os.path.join(log_dir, "HP Image Assistant.log")
        if os.path.exists(log_file):
            try:
                os.remove(log_file)
            except Exception:
                pass

        cmd = [
            hpia_path,
            "/Operation:Analyze",
            "/Category:All",
            "/Selection:All",
            "/Action:Install",
            "/Silent",
            "/Noninteractive",
            "/NoReboot",
            f"/SoftpaqDownloadFolder:{HP_SOFTPAQ_FOLDER}",
            f"/ReportFolder:{log_dir}",
            f"/LogFolder:{log_dir}",
            "/Debug"
        ]

        self.log("מריץ HP Image Assistant – מנתח חומרה ומתקין דרייברים מתאימים...", "INFO")
        res_code = self._execute_and_stream(cmd, log_file, parser=self._parse_hp_line, timeout_secs=1200)

        # Wait for HP background installers
        self.log("ממתין לסיום תהליכי רקע של HP...", "INFO")
        self._wait_for_processes(["HPImageAssistant", "HPSARedist", "hpsa_service", "setup", "InstallHPSA"], max_secs=60)

        self.log(f"עדכוני HP הסתיימו (Exit Code: {res_code})", "INFO")
        return res_code in (0, 1, 2, 3, 256, 257, 3010)

    # ------------------------------------------------------------------
    # UNIVERSAL DRIVER UPDATES (SDIO + WINDOWS UPDATE)
    # ------------------------------------------------------------------

    def _run_universal_driver_updates(self):
        sdio_path = None
        for p in UNIVERSAL_DRIVER_PATHS:
            if os.path.exists(p):
                sdio_path = p
                break

        if not sdio_path:
            self.log("מוריד SDI Origin נייד מ-GitHub עבור מחשב ללא כלי OEM ייעודי...", "INFO")
            sdio_folder = r"C:\TechTools\SDIO"
            os.makedirs(sdio_folder, exist_ok=True)
            target_exe = os.path.join(sdio_folder, "SDI_x64.exe")
            if self._download_file(SDIO_DOWNLOAD_URL, target_exe):
                sdio_path = target_exe

        if sdio_path and os.path.exists(sdio_path):
            self.log("מפעיל מנוע דרייברים אוניברסלי (SDI Origin)...", "INFO")
            cmd = [sdio_path, "-autoupdate", "-autoinstall", "-autoclose", "-nosplash"]
            self._execute_and_stream(cmd, None, parser=None, timeout_secs=900)
            return True

        return False

    def _run_windows_optional_driver_updates(self):
        self.log("בודק עדכוני דרייברים זמינים ב-Windows Update...", "INFO")
        ps_script = """
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()

        $allUpdates = New-Object -ComObject Microsoft.Update.UpdateColl
        $seenIds = @{}

        try {
            $r1 = $searcher.Search("IsInstalled=0 and Type='Driver'")
            foreach ($u in $r1.Updates) {
                if (-not $seenIds.ContainsKey($u.Identity.UpdateID)) {
                    $seenIds[$u.Identity.UpdateID] = $true
                    $allUpdates.Add($u) | Out-Null
                }
            }
        } catch { }

        try {
            $r2 = $searcher.Search("IsInstalled=0 and BrowseOnly=1")
            foreach ($u in $r2.Updates) {
                if (-not $seenIds.ContainsKey($u.Identity.UpdateID)) {
                    $seenIds[$u.Identity.UpdateID] = $true
                    $allUpdates.Add($u) | Out-Null
                }
            }
        } catch { }

        $count = $allUpdates.Count
        if ($count -eq 0) {
            Write-Output "INFO: לא נמצאו עדכוני דרייברים או תוכנות יצרן נוספות ב-Windows Update."
            exit 0
        }

        Write-Output "INFO: אותרו $count עדכוני דרייברים ותוכנות יצרן ב-Windows Update. מתחיל התקנה..."

        for ($i = 0; $i -lt $count; $i++) {
            $u = $allUpdates.Item($i)
            $idx = $i + 1
            $title = $u.Title
            Write-Output "INSTALL: מתקין [$idx/$count] - $title"

            $coll = New-Object -ComObject Microsoft.Update.UpdateColl
            $coll.Add($u) | Out-Null

            try {
                $downloader = $session.CreateUpdateDownloader()
                $downloader.Updates = $coll
                $downloader.Download() | Out-Null

                $installer = $session.CreateUpdateInstaller()
                $installer.Updates = $coll
                if ($u.EulaAccepted -eq $false) { $u.AcceptEula() }
                $res = $installer.Install()
                if ($res.ResultCode -eq 2) {
                    Write-Output "SUCCESS: $title הותקן בהצלחה ✓"
                } elseif ($res.ResultCode -eq 3) {
                    Write-Output "SUCCESS: $title הותקן (נדרש אתחול המחשב) ✓"
                } else {
                    Write-Output "WARN: $title הסתיים בקוד $($res.ResultCode)"
                }
            } catch {
                Write-Output "WARN: שגיאה בהתקנת $title - $_"
            }
        }
        """
        try:
            proc = popen_hidden(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            self._track_process(proc)

            for line in iter(proc.stdout.readline, ''):
                l = line.strip()
                if not l:
                    continue
                if l.startswith("INFO:"):
                    self.log(l[5:].strip(), "INFO")
                elif l.startswith("INSTALL:"):
                    self.log(f"  🔧 {l[8:].strip()}", "INFO")
                elif l.startswith("SUCCESS:"):
                    self.log(f"  ✓ {l[8:].strip()}", "SUCCESS")
                else:
                    self.log(f"  {l}", "INFO")

            proc.wait(timeout=10)
            self._untrack_process(proc)
        except Exception as ex:
            self.log(f"עדכון מ-Windows Update הסתיים: {ex}", "INFO")

    # ------------------------------------------------------------------
    # Subprocess Streaming & Parsing Helpers
    # ------------------------------------------------------------------

    def _execute_and_stream(self, cmd, log_file_to_tail=None, parser=None, timeout_secs=600):
        deadline = time.time() + timeout_secs
        proc = None
        try:
            proc = popen_hidden(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self._track_process(proc)
        except Exception as ex:
            self.log(f"כשל בהפעלת הפקודה: {ex}", "ERROR")
            return -1

        stop_tail = threading.Event()
        if log_file_to_tail and parser:
            t = threading.Thread(target=self._tail_log_file, args=(log_file_to_tail, parser, stop_tail), daemon=True)
            t.start()

        try:
            while proc.poll() is None:
                if self.cancel_requested:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    break
                if time.time() > deadline:
                    self.log(f"חריגה מזמן ההמתנה ({timeout_secs // 60} דק'). התהליך ייעצר.", "WARN")
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    break
                time.sleep(1)

            stop_tail.set()
            rc = proc.wait(timeout=15)
            self._untrack_process(proc)
            return rc
        except Exception as ex:
            self.log(f"שגיאה בהמתנה לסיום התהליך: {ex}", "WARN")
            stop_tail.set()
            return -1

    def _tail_log_file(self, log_path, parser, stop_event):
        wait_start = time.time()
        while not os.path.exists(log_path) and not stop_event.is_set():
            if time.time() - wait_start > 45:
                return
            time.sleep(1)

        last_pos = 0
        while not stop_event.is_set():
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(last_pos)
                        lines = f.readlines()
                        last_pos = f.tell()
                        for line in lines:
                            parsed = parser(line.strip())
                            if parsed:
                                self.log(parsed, "INFO")
                except Exception:
                    pass
            time.sleep(1.5)

    def _parse_lenovo_line(self, line):
        if not line:
            return None
        l = line.lower()
        if "installing package" in l:
            idx = l.find("installing package")
            return f"  🔧 מתקין: {line[idx+18:].strip()}"
        if "downloading package" in l:
            idx = l.find("downloading package")
            return f"  📥 מוריד: {line[idx+19:].strip()}"
        if "package name:" in l:
            idx = l.find("package name:")
            return f"  📦 עדכון: {line[idx+13:].strip()}"
        if "executing command" in l or "extracting package" in l:
            return "  ⚙️ מעבד חבילת עדכון Lenovo..."
        if "installation of package" in l and "succeeded" in l:
            return f"  ✓ עדכון הותקן בהצלחה"
        if "reboot is required" in l or "rebootrequired" in l:
            return "  🔄 נדרש אתחול לאחר עדכון Lenovo."
        return None

    def _parse_hp_line(self, line):
        if not line:
            return None
        l = line.lower()
        if "initializing hpia" in l or "initializing..." in l:
            return "  ⚙️ מאתחל את HP Image Assistant..."
        if "analyzing" in l:
            return "  🔍 מנתח תצורת חומרה ורכיבים..."
        if "downloading" in l:
            return f"  📥 מוריד חבילת דרייברים HP: {line.strip()}"
        if "extracting" in l:
            return f"  📦 מחלץ חבילה..."
        if "installing" in l:
            return f"  🔧 מתקין: {line.strip()}"
        if "successfully installed" in l or "installation succeeded" in l:
            return f"  ✓ {line.strip()}"
        if "failed to install" in l:
            return f"  ✗ {line.strip()}"
        return None

    def _parse_dell_line(self, line):
        if not line:
            return None
        l = line.lower()
        if "checking for updates" in l:
            return "  🔍 סורק שרתי Dell לאיתור עדכונים זמינים..."
        if "applying update" in l or "installing" in l:
            return f"  🔧 מתקין רכיב Dell: {line.strip()}"
        if "download" in l:
            return f"  📥 מוריד: {line.strip()}"
        if "reboot" in l:
            return "  🔄 נדרש אתחול להשלמת העדכון."
        return None

    def _wait_for_processes(self, proc_names, max_secs=45):
        if not IS_WINDOWS:
            return
        start = time.time()
        names_lower = [n.lower() for n in proc_names]
        while time.time() - start < max_secs:
            running = False
            try:
                ps = f"Get-Process -Name {','.join(proc_names)} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"
                res = run_hidden(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                                 capture_output=True, text=True, timeout=5)
                out = (res.stdout or "").strip().lower()
                for name in names_lower:
                    if name in out:
                        running = True
                        break
            except Exception:
                pass

            if not running:
                break
            time.sleep(2)

    def _run_winget_install(self, package_id):
        self.log(f"מתקין {package_id} דרך Winget (עלול לקחת מספר דקות)...", "INFO")
        cmd_str = f"winget install --id {package_id} --silent --accept-package-agreements --accept-source-agreements --force"

        # 1. PowerShell execution with up to 3 retries
        for attempt in range(1, 4):
            if self.cancel_requested:
                return False
            if attempt > 1:
                self.log(f"ניסיון חוזר {attempt}/3 להתקנת {package_id}...", "WARN")
                time.sleep(5)

            try:
                res = run_hidden(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd_str], timeout=300)
                if res.returncode == 0:
                    self.log(f"התקנת {package_id} דרך Winget הושלמה בהצלחה ✓", "SUCCESS")
                    return True
            except Exception as ex:
                self.log(f"ניסיון {attempt} נכשל: {ex}", "WARN")

        # 2. Fallback via CMD
        self.log(f"ניסיון חוזר (CMD) להתקנת {package_id}...", "INFO")
        try:
            res = run_hidden(["cmd.exe", "/c", cmd_str], timeout=300)
            if res.returncode == 0:
                self.log(f"התקנת {package_id} דרך CMD הושלמה בהצלחה ✓", "SUCCESS")
                return True
        except Exception:
            pass

        return False

    def _download_file(self, url, dest_path):
        try:
            self.log(f"מוריד: {os.path.basename(dest_path)}...", "INFO")
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                total_bytes = int(resp.headers.get("content-length", 0))
                downloaded = 0
                chunk_size = 1024 * 64
                last_report = time.time()

                with open(dest_path, "wb") as f:
                    while True:
                        if self.cancel_requested:
                            return False
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)

                        if time.time() - last_report > 3:
                            mb = downloaded / (1024 * 1024)
                            if total_bytes > 0:
                                total_mb = total_bytes / (1024 * 1024)
                                self.log(f"  📥 הורדה: {mb:.1f} מתוך {total_mb:.1f} MB...", "INFO", replace_key="dl_progress")
                            else:
                                self.log(f"  📥 הורדו {mb:.1f} MB עד כה...", "INFO", replace_key="dl_progress")
                            last_report = time.time()

            mb_final = os.path.getsize(dest_path) / (1024 * 1024)
            self.log(f"הקובץ הורד בהצלחה ({mb_final:.1f} MB) ✓", "SUCCESS")
            return True
        except Exception as ex:
            self.log(f"שגיאה בהורדת הקובץ מ-{url}: {ex}", "WARN")
            if os.path.exists(dest_path):
                try:
                    os.remove(dest_path)
                except Exception:
                    pass
            return False

    def _track_process(self, proc):
        with self.lock:
            self._active_procs.append(proc)

    def _untrack_process(self, proc):
        with self.lock:
            if proc in self._active_procs:
                self._active_procs.remove(proc)

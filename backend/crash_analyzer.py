"""
Polaris - BSOD & Windows Kernel Crash Diagnostic Engine
Scans Minidump files and Windows System Event Log to analyze Blue Screen crashes,
Kernel-Power sudden reboots, and unexpected shutdowns.
Translates BugCheck error codes and drivers into actionable Hebrew and English root-cause explanations.
"""

import os
import re
import sys
import glob
import json
import subprocess
from datetime import datetime

from backend.win_utils import run_hidden

# Comprehensive Knowledge Base of Windows BugCheck Codes
BUGCHECK_KNOWLEDGE = {
    0x0A: {
        "name": "IRQL_NOT_LESS_OR_EQUAL",
        "title_he": "שגיאת גישה בזיכרון דרייבר (IRQL Not Less Or Equal)",
        "title_en": "Driver Memory Access Fault (IRQL_NOT_LESS_OR_EQUAL)",
        "cause_he": "תהליך במצב קרנל או דרייבר לא תקין ניסה לגשת לכתובת זיכרון בלתי חוקית ברמת עדיפות (IRQL) גבוהה מדי.",
        "cause_en": "A kernel-mode process or driver attempted to access an invalid memory address at an elevated IRQL.",
        "solution_he": "עדכן את דרייבר החומרה האחרון שהותקן (במיוחד כרטיס רשת או כרטיס מסך). הרץ בדיקת זיכרון RAM.",
        "solution_en": "Update recently installed hardware drivers (especially network or GPU). Run a memory diagnostic.",
        "severity": "Critical"
    },
    0x1A: {
        "name": "MEMORY_MANAGEMENT",
        "title_he": "שגיאת ניהול זיכרון חומרה / RAM (Memory Management)",
        "title_en": "Memory Management Subsystem Error",
        "cause_he": "זוהתה שגיאת זיכרון חמורה. לרוב מעיד על כשל פיזי בסטיק של זיכרון ה-RAM, הגדרת XMP/DOCP לא יציבה ב-BIOS, או פגיעה בקובץ ה-Pagefile.",
        "cause_en": "A severe memory management error occurred. Most commonly indicates a failing RAM module, unstable XMP profile, or pagefile corruption.",
        "solution_he": "הפעל את כלי בדיקת הזיכרון של Windows (mdsched.exe) לבדיקת תקינות רכיבי ה-RAM. אם הופעל XMP ב-BIOS, נסה להחזיר לתדר ברירת מחדל.",
        "solution_en": "Run Windows Memory Diagnostic (mdsched.exe) to check for faulty RAM sticks. Reset RAM XMP overclocking in BIOS if enabled.",
        "severity": "Critical"
    },
    0x3B: {
        "name": "SYSTEM_SERVICE_EXCEPTION",
        "title_he": "חריגת שירות מערכת (System Service Exception)",
        "title_en": "System Service Exception",
        "cause_he": "חריגת קוד שבוצעה במרחב הקרנל. נגרם בדרך כלל מדרייבר גרפי (GPU), תוכנת אנטי-וירוס או דרייבר של תוכנת וירטואליזציה.",
        "cause_en": "An exception occurred while executing a system service routine. Commonly caused by graphics drivers, antivirus software, or virtualization drivers.",
        "solution_he": "עדכן את דרייבר כרטיס המסך (NVIDIA / AMD / Intel) בהתקנה נקייה. הרץ סריקת SFC לתיקון קבצי מערכת.",
        "solution_en": "Perform a clean install of your graphics driver (NVIDIA/AMD/Intel). Run SFC system file repair.",
        "severity": "High"
    },
    0x50: {
        "name": "PAGE_FAULT_IN_NONPAGED_AREA",
        "title_he": "גישה לא חוקית לזיכרון קבוע (Page Fault In Nonpaged Area)",
        "title_en": "Invalid Memory Access in Non-Paged Area",
        "cause_he": "המערכת ניסתה לגשת לזיכרון שאינו קיים או שוחרר. נגרם על ידי רכיב RAM פגום, דרייבר שירות פגום, או סקטורים פגומים בכונן ה-SSD/HDD.",
        "cause_en": "Invalid system memory was referenced. Caused by faulty hardware RAM, bad antivirus/system driver, or disk sectors corruption.",
        "solution_he": "בדוק את תקינות ה-RAM ושלמות הכונן (chkdsk /f). ודא שדרייברים של בקרי אחסון מעודכנים.",
        "solution_en": "Test RAM modules and check disk integrity using chkdsk. Ensure storage controller drivers are up to date.",
        "severity": "Critical"
    },
    0x7E: {
        "name": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        "title_he": "חריגת תהליך מערכת שלא טופלה (System Thread Exception)",
        "title_en": "System Thread Exception Not Handled",
        "cause_he": "תהליך רקע של קרנל Windows נתקל בשגיאה חמורה שלא טופלה. נגרם לרוב מחוסר תאימות דרייבר או קובץ DLL מערכתי פגום.",
        "cause_en": "A system thread generated an exception that the error handler did not catch. Often caused by driver incompatibility.",
        "solution_he": "בדוק את שם הקובץ שקרס (הדרייבר המופיע בדוח). הסר תוכנות דרייברים אחרונות והרץ תיקון DISM.",
        "solution_en": "Identify the crashing driver listed in the report. Reinstall or roll back the driver and run DISM repair.",
        "severity": "High"
    },
    0xD1: {
        "name": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        "title_he": "קריסת דרייבר בגישה לזיכרון (Driver IRQL Not Less Or Equal)",
        "title_en": "Driver IRQL Not Less Or Equal",
        "cause_he": "דרייבר ספציפי ניסה לגשת לכתובת זיכרון שגויה. אחת השגיאות הנפוצות ביותר בעקבות דרייבר Wi-Fi, בלוטוס, כרטיס רשת או כרטיס מסך מיושן.",
        "cause_en": "A specific device driver accessed pageable memory at DISPATCH_LEVEL or above. Very common with Wi-Fi, Ethernet, or GPU drivers.",
        "solution_he": "זהה את הדרייבר הספציפי ברשימה מטה והורד גרסה עדכנית מאתר היצרן (Intel / Realtek / NVIDIA).",
        "solution_en": "Identify the responsible driver and install the latest official release from the manufacturer.",
        "severity": "High"
    },
    0x116: {
        "name": "VIDEO_TDR_FAILURE",
        "title_he": "קריסת תגובת כרטיס מסך (Video TDR Failure)",
        "title_en": "Graphics Timeout Detection & Recovery Failure",
        "cause_he": "כרטיס המסך (GPU) הפסיק להגיב ולא הצליח להתאושש בזמן שהוגדר. נגרם מהתחממות יתר של המאיץ הגרפי, המהרה (Overclock) לא יציבה, או דרייבר מסך פגום.",
        "cause_en": "The GPU failed to respond within the timeout period. Caused by GPU overheating, unstable overclock, power delivery dip, or corrupted graphics driver.",
        "solution_he": "התקן מחדש את דרייבר כרטיס המסך בעזרת DDU או התקנה נקייה. בדוק טמפרטורות GPU וודא ספק כוח יציב.",
        "solution_en": "Perform a clean graphics driver reinstall (using DDU if needed). Monitor GPU temperatures and power stability.",
        "severity": "Critical"
    },
    0x124: {
        "name": "WHEA_UNCORRECTABLE_ERROR",
        "title_he": "שגיאת ארכיטקטורת חומרה קריטית (WHEA Uncorrectable Error)",
        "title_en": "Windows Hardware Error Architecture (WHEA) Failure",
        "cause_he": "שגיאת חומרה פיזית קריטית שזוהתה על ידי המעבד (CPU), לוח האם, או בקר ה-PCIe/NVMe. נגרם מחימום מעבד, תת-מתח, או כשל בכונן SSD NVMe.",
        "cause_en": "A fatal hardware error was detected by the CPU or motherboard. Usually caused by CPU instability, overheating, undervoltage, or failing NVMe SSD.",
        "solution_he": "בדוק טמפרטורות מעבד (CPU Thermal Throttling), בטל כל המהרה / Undervolt ב-BIOS, וודא קושחה (Firmware) מעודכנת לכונן ה-SSD.",
        "solution_en": "Check CPU temperatures and cooling. Remove BIOS overclocks/undervolts. Update SSD firmware and motherboard BIOS.",
        "severity": "Critical"
    },
    0x133: {
        "name": "DPC_WATCHDOG_VIOLATION",
        "title_he": "חריגת זמן תגובה DPC Watchdog",
        "title_en": "DPC Watchdog Violation",
        "cause_he": "שגרה של דרייבר (DPC) רצה זמן רב מדי וחסמה את המערכת. נפוץ מאוד עם דרייברים ישנים של בקרי SSD (כמו iastorA) או דרייברי Wi-Fi.",
        "cause_en": "A DPC routine hung or executed for too long at DISPATCH_LEVEL. Often caused by outdated SSD SATA/NVMe AHCI drivers or Wi-Fi drivers.",
        "solution_he": "עדכן את דרייבר בקר ה-Storage (Standard NVM Express Controller / Intel RST) ועדכן דרייבר כרטיס רשת.",
        "solution_en": "Update storage controller drivers (Standard NVM Express / Intel RST) and network drivers.",
        "severity": "High"
    },
    0x139: {
        "name": "KERNEL_SECURITY_CHECK_FAILURE",
        "title_he": "כשל בבדיקת אבטחת קרנל (Kernel Security Check)",
        "title_en": "Kernel Security Check Failure",
        "cause_he": "הקרנל זיהה פגיעה במבנה נתונים קריטי. נגרם בדרך כלל מדרייברים ישנים שאינם תואמים את עדכוני האבטחה האחרונים של Windows.",
        "cause_en": "The kernel detected corruption in a critical data structure. Caused by legacy or incompatible drivers modifying kernel memory.",
        "solution_he": "הרץ SFC ו-DISM לתיקון רכיבי Windows. ודא שכל הדרייברים מעודכנים לגרסה העדכנית ביותר.",
        "solution_en": "Run SFC and DISM to repair core Windows files. Ensure all third-party drivers are signed and updated.",
        "severity": "High"
    },
    0x9F: {
        "name": "DRIVER_POWER_STATE_FAILURE",
        "title_he": "כשל במעבר מצב צריכת חשמל / שינה (Driver Power State Failure)",
        "title_en": "Driver Power State Transition Failure",
        "cause_he": "דרייבר לא הגיב כראוי בעת מעבר למצב שינה (Sleep), יציאה משינה או כיבוי מחשב.",
        "cause_en": "A driver did not handle a power state transition properly (entering/exiting sleep or shutdown).",
        "solution_he": "עדכן דרייברים של שבבי לוח האם (Chipset), כרטיס רשת, ועדכן את קושחת ה-BIOS.",
        "solution_en": "Update Motherboard Chipset drivers, Wi-Fi drivers, and motherboard BIOS.",
        "severity": "High"
    },
    0xEF: {
        "name": "CRITICAL_PROCESS_DIED",
        "title_he": "סיום תהליך קריטי במערכת (Critical Process Died)",
        "title_en": "Critical System Process Died",
        "cause_he": "תהליך מערכת חיוני (כמו csrss.exe, wininit.exe או services.exe) הופסק באופן בלתי צפוי.",
        "cause_en": "A critical system process terminated unexpectedly.",
        "solution_he": "הרץ בדיקת SFC ו-DISM. סרוק את המחשב לאיתור תוכנות זדוניות ובדוק תקינות כונן מערכת.",
        "solution_en": "Run SFC and DISM tools. Run a malware scan and check system drive health.",
        "severity": "Critical"
    }
}

# Known Windows Drivers Knowledge Map
DRIVER_KNOWLEDGE = {
    "nvlddmkm.sys": {"name": "NVIDIA Graphics Driver", "desc_he": "דרייבר כרטיס מסך NVIDIA GeForce"},
    "amdkmdag.sys": {"name": "AMD Radeon Graphics Driver", "desc_he": "דרייבר כרטיס מסך AMD Radeon"},
    "atikmdag.sys": {"name": "AMD Radeon Graphics Driver", "desc_he": "דרייבר כרטיס מסך AMD Radeon"},
    "igdkmd64.sys": {"name": "Intel Graphics Driver", "desc_he": "דרייבר כרטיס מסך מובנה Intel HD/Iris/Arc"},
    "netwtw": {"name": "Intel Wi-Fi Driver", "desc_he": "דרייבר כרטיס רשת אלחוטי Intel Wi-Fi"},
    "rtwlane": {"name": "Realtek Wi-Fi Driver", "desc_he": "דרייבר כרטיס רשת אלחוטי Realtek Wi-Fi"},
    "e1d": {"name": "Intel Ethernet Driver", "desc_he": "דרייבר כרטיס רשת קווי Intel Ethernet"},
    "rt640": {"name": "Realtek Ethernet Driver", "desc_he": "דרייבר כרטיס רשת קווי Realtek PCIe"},
    "tcpip.sys": {"name": "Windows TCP/IP Stack", "desc_he": "מחסנית תקשורת ורשת Windows TCP/IP"},
    "ndu.sys": {"name": "Windows Network Data Usage", "desc_he": "דרייבר ניטור תעבורת רשת Windows"},
    "ntoskrnl.exe": {"name": "Windows NT Kernel", "desc_he": "ליבת מערכת ההפעלה Windows (הקריסה נבעה מחומרה או מדרייבר שפגע בזיכרון)"},
    "fltmgr.sys": {"name": "Filter Manager", "desc_he": "מנהל סינון קבצים (קשור לרוב לאנטי-וירוס או כונן אחסון)"},
    "storahci.sys": {"name": "MS AHCI Storage Driver", "desc_he": "דרייבר בקר כונני אחסון SATA/AHCI"},
    "iastor": {"name": "Intel RST Storage Driver", "desc_he": "דרייבר בקר אחסון Intel Rapid Storage"},
    "volsnap.sys": {"name": "Volume Shadow Copy Driver", "desc_he": "דרייבר צילומי נפח וגיבוי Windows"},
    "win32k.sys": {"name": "Multi-User Win32 Driver", "desc_he": "דרייבר ממשק חלונות וגרפיקה של Windows"},
}


class CrashAnalyzer:
    def __init__(self):
        self.is_windows = sys.platform.startswith('win')
        self.minidump_dir = os.path.expandvars(r"%SystemRoot%\Minidump")
        self.memory_dmp = os.path.expandvars(r"%SystemRoot%\MEMORY.DMP")

    def get_crash_history(self, limit=20):
        """
        Gathers complete crash history from Windows Event Logs and Minidump directory.
        Returns sorted list of crashes with deep root-cause explanations.
        """
        crashes = []

        if not self.is_windows:
            return {"crashes": [], "total_crashes": 0, "status": "Non-Windows environment"}

        # 1. Query Windows Event Log for BugCheck (BSOD), Kernel-Power (Event 41), and Unexpected Shutdown (Event 6008)
        event_crashes = self._query_event_log_crashes(limit=limit)
        crashes.extend(event_crashes)

        # 2. Check Minidump directory
        dump_crashes = self._scan_minidump_files()
        
        # Merge and deduplicate by time proximity (within 3 minutes)
        merged = self._merge_crash_records(crashes, dump_crashes)
        
        # Sort newest first
        merged.sort(key=lambda x: x.get('timestamp_raw', ''), reverse=True)

        bsod_count = sum(1 for c in merged if c.get('type') == 'BSOD')
        power_count = sum(1 for c in merged if c.get('type') == 'Kernel-Power')

        health_status = "Healthy"
        if bsod_count > 0:
            health_status = "Critical (BSOD Detected)"
        elif power_count > 2:
            health_status = "Warning (Sudden Power Losses Detected)"

        return {
            "crashes": merged[:limit],
            "total_crashes": len(merged),
            "bsod_count": bsod_count,
            "power_loss_count": power_count,
            "health_status": health_status,
            "has_minidumps": len(dump_crashes) > 0
        }

    def _query_event_log_crashes(self, limit=20):
        crashes = []
        ps_cmd = f"""
        $events = Get-WinEvent -FilterHashtable @{{LogName='System'; Id=41,1001,6008}} -MaxEvents {limit * 2} -ErrorAction SilentlyContinue | ForEach-Object {{
            [PSCustomObject]@{{
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Id = $_.Id
                ProviderName = $_.ProviderName
                Message = $_.Message
            }}
        }}
        if ($events) {{ $events | ConvertTo-Json -Depth 3 }} else {{ "[]" }}
        """
        try:
            p = run_hidden(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=12)
            if p.returncode == 0 and p.stdout.strip():
                data = json.loads(p.stdout)
                if isinstance(data, dict):
                    data = [data]
                
                for ev in data:
                    item = self._parse_event_record(ev)
                    if item:
                        crashes.append(item)
        except Exception as e:
            print("Error querying event log crashes:", e)

        return crashes

    def _parse_event_record(self, ev):
        ev_id = ev.get('Id')
        time_str = ev.get('TimeCreated', '')
        msg = ev.get('Message', '')
        provider = ev.get('ProviderName', '')

        # Event ID 1001 is reused by many providers (ordinary application crash
        # reports included). Only the BugCheck / WER-SystemErrorReporting
        # providers describe an actual Blue Screen, so the previous
        # `or "0x0" in msg` fallback reported normal app crashes as BSODs.
        if ev_id == 1001 and ("BugCheck" in provider or "WER-SystemErrorReporting" in provider):
            # Blue Screen Event
            bugcheck_code = self._extract_bugcheck_code(msg)
            driver = self._extract_driver_name(msg)
            info = self._get_bugcheck_info(bugcheck_code, driver)

            return {
                "id": f"bsod_{time_str.replace(' ', '_').replace(':', '')}",
                "timestamp": time_str,
                "timestamp_raw": time_str,
                "type": "BSOD",
                "event_id": 1001,
                "title_he": info["title_he"],
                "title_en": info["title_en"],
                "bugcheck_name": info["name"],
                "bugcheck_code": hex(bugcheck_code) if isinstance(bugcheck_code, int) else str(bugcheck_code),
                "responsible_driver": driver or info.get("likely_driver", "ntoskrnl.exe"),
                "cause_he": info["cause_he"],
                "cause_en": info["cause_en"],
                "solution_he": info["solution_he"],
                "solution_en": info["solution_en"],
                "severity": info.get("severity", "Critical"),
                "raw_message": msg.strip()[:300]
            }

        elif ev_id == 41:
            # Kernel-Power Sudden Reboot
            return {
                "id": f"pwr_{time_str.replace(' ', '_').replace(':', '')}",
                "timestamp": time_str,
                "timestamp_raw": time_str,
                "type": "Kernel-Power",
                "event_id": 41,
                "title_he": "כיבוי פתאומי / ניתוק מתח (Kernel-Power Loss)",
                "title_en": "Sudden System Reboot / Power Loss (Kernel-Power)",
                "bugcheck_name": "KERNEL_POWER_EVENT_41",
                "bugcheck_code": "Event 41",
                "responsible_driver": "Hardware / Power Supply / Thermal",
                "cause_he": "המחשב הופעל מחדש מבלי שביצע כיבוי מסודר. נגרם בדרך כלל מניתוק חשמל פתאומי, נפילת מתח בספק הכוח (PSU), התחממות יתר (Thermal Shutdown), או קפיאת חומרה מוחלטת.",
                "cause_en": "The system rebooted without cleanly shutting down first. Typically caused by a power cut, power supply (PSU) failure, thermal shutdown, or hard system freeze.",
                "solution_he": "בדוק שחיבורי החשמל והכבלים תקינים. בדוק טמפרטורות מעבד וכרטיס מסך. אם האירוע חוזר על עצמו בעומס משחקים, בדוק את ספק הכוח.",
                "solution_en": "Check power cables and PSU health. Monitor CPU/GPU temperatures under load. Ensure cooling fans are dust-free.",
                "severity": "High",
                "raw_message": msg.strip()[:300]
            }

        elif ev_id == 6008:
            # Dirty Shutdown
            return {
                "id": f"dirty_{time_str.replace(' ', '_').replace(':', '')}",
                "timestamp": time_str,
                "timestamp_raw": time_str,
                "type": "Unexpected-Shutdown",
                "event_id": 6008,
                "title_he": "כיבוי בלתי צפוי קודם (Dirty Shutdown)",
                "title_en": "Previous Unexpected Shutdown",
                "bugcheck_name": "DIRTY_SHUTDOWN",
                "bugcheck_code": "Event 6008",
                "responsible_driver": "System Watchdog",
                "cause_he": "מערכת ההפעלה זיהתה שכיבוי המחשב הקודם לא הושלם באופן מסודר.",
                "cause_en": "Windows detected that the previous shutdown sequence was terminated unexpectedly.",
                "solution_he": "ודא כיבוי תקין מתפריט 'התחל' ומנע כיבוי כפוי מכפתור ההדלקה.",
                "solution_en": "Ensure proper shutdown via Start Menu and avoid holding power button.",
                "severity": "Warning",
                "raw_message": msg.strip()[:300]
            }

        return None

    def _scan_minidump_files(self):
        crashes = []
        if not os.path.exists(self.minidump_dir):
            return crashes

        try:
            dump_files = glob.glob(os.path.join(self.minidump_dir, "*.dmp"))
            for f in dump_files:
                stat = os.stat(f)
                mtime = datetime.fromtimestamp(stat.st_mtime)
                time_str = mtime.strftime("%Y-%m-%d %H:%M:%S")
                filename = os.path.basename(f)

                crashes.append({
                    "id": f"dmp_{filename}",
                    "timestamp": time_str,
                    "timestamp_raw": time_str,
                    "type": "BSOD",
                    "filename": filename,
                    "size_bytes": stat.st_size,
                    "title_he": f"קובץ Minidump של מסך כחול ({filename})",
                    "title_en": f"Minidump Blue Screen Dump ({filename})",
                    "bugcheck_name": "MINIDUMP_CRASH_RECORD",
                    "bugcheck_code": "0x (Minidump Available)",
                    "responsible_driver": "Kernel Minidump",
                    "cause_he": "נוצר קובץ זיכרון בעקבות קריסת מסך כחול (BSOD).",
                    "cause_en": "A minidump memory crash file was generated during a Blue Screen event.",
                    "solution_he": "הרץ בדיקת קבצי מערכת SFC ובדיקת חומרת RAM.",
                    "solution_en": "Run SFC system file repair and RAM hardware diagnostic.",
                    "severity": "Critical"
                })
        except Exception as e:
            print("Error scanning minidumps:", e)

        return crashes

    def _extract_bugcheck_code(self, msg):
        match = re.search(r'0x[0-9a-fA-F]{1,8}', msg)
        if match:
            try:
                return int(match.group(0), 16)
            except ValueError:
                pass
        return 0x0

    def _extract_driver_name(self, msg):
        match = re.search(r'([a-zA-Z0-9_\-]+\.(?:sys|dll|exe))', msg, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return None

    def _get_bugcheck_info(self, code, driver=None):
        if code in BUGCHECK_KNOWLEDGE:
            info = dict(BUGCHECK_KNOWLEDGE[code])
        else:
            code_hex = hex(code) if isinstance(code, int) else str(code)
            info = {
                "name": f"BUGCHECK_{code_hex}",
                "title_he": f"קריסת מסך כחול ({code_hex})",
                "title_en": f"Blue Screen Crash ({code_hex})",
                "cause_he": "התרחשה קריסת ליבה (BugCheck) במערכת Windows.",
                "cause_en": "A kernel BugCheck occurred.",
                "solution_he": "עדכן דרייברים, בצע סריקת SFC ובדוק תקינות זיכרון RAM.",
                "solution_en": "Update hardware drivers, run SFC and verify RAM integrity.",
                "severity": "Critical"
            }

        # Enhance with driver knowledge
        if driver:
            for k, dinfo in DRIVER_KNOWLEDGE.items():
                if k in driver.lower():
                    info["driver_detail"] = dinfo["desc_he"]
                    info["cause_he"] += f" הדרייבר שגרם לקריסה: {driver} ({dinfo['desc_he']})."
                    info["cause_en"] += f" Crashing Driver: {driver} ({dinfo['name']})."
                    break

        return info

    def _merge_crash_records(self, event_crashes, dump_crashes):
        # Merge both sources
        all_crashes = list(event_crashes)
        seen_timestamps = set(c.get('timestamp', '')[:16] for c in all_crashes)

        for dc in dump_crashes:
            t_short = dc.get('timestamp', '')[:16]
            if t_short not in seen_timestamps:
                all_crashes.append(dc)
                seen_timestamps.add(t_short)

        return all_crashes

    def trigger_memory_diagnostic(self):
        """
        Triggers Windows Memory Diagnostic Tool (mdsched.exe)
        """
        if not self.is_windows:
            return {"success": False, "message": "Supported on Windows only"}

        try:
            # mdsched.exe shows a GUI dialog the user must interact with, so it
            # must NOT be launched hidden. (The old call used shell=True with an
            # argument list, which is meaningless on Windows and only spawned an
            # extra cmd.exe window.)
            subprocess.Popen(["mdsched.exe"])
            return {
                "success": True,
                "message": "Windows Memory Diagnostic tool launched. Follow the on-screen prompt to reboot and scan RAM."
            }
        except Exception as e:
            return {"success": False, "message": str(e)}

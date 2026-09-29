"""
Polaris - BSOD & Windows Kernel Crash Diagnostic Engine
Deep Minidump Binary Analysis, Driver Disambiguation Heuristics & Online Crash Intelligence.
Translates BugCheck error codes and culprit drivers into actionable Hebrew and English explanations.
"""

import os
import re
import sys
import glob
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional

from backend.win_utils import run_hidden
from backend.minidump_parser import MinidumpParser, analyze_dump_file_with_windbg_fallback
from backend.driver_database import (
    DRIVER_REGISTRY,
    BUGCHECK_DATABASE,
    CulpritResolver,
    CAT_GPU,
    CAT_NETWORK_WIFI,
    CAT_NETWORK_LAN,
    CAT_STORAGE,
    CAT_ANTI_CHEAT,
    CAT_RGB_OVERCLOCK,
    CAT_SECURITY_AV
)
from backend.driver_online_checker import DriverOnlineChecker


class CrashAnalyzer:
    """
    Complete Windows BSOD, Minidump and Kernel Power crash diagnostic engine.
    """

    def __init__(self):
        self.is_windows = sys.platform.startswith('win')
        self.minidump_dir = os.path.expandvars(r"%SystemRoot%\Minidump")
        self.memory_dmp = os.path.expandvars(r"%SystemRoot%\MEMORY.DMP")

    def get_crash_history(self, limit: int = 20) -> Dict[str, Any]:
        """
        Gathers complete crash history from Windows Event Logs and Minidump directory.
        Applies binary parsing and culprit heuristics to pinpoint the exact driver.
        """
        crashes: List[Dict[str, Any]] = []

        if not self.is_windows:
            return {"crashes": [], "total_crashes": 0, "status": "Non-Windows environment"}

        # 1. Parse all Minidump binary files in %SystemRoot%\Minidump
        dump_crashes = self._scan_and_parse_minidump_files()

        # 2. Query Windows Event Log for BugCheck (BSOD), Kernel-Power (Event 41), and Unexpected Shutdown (Event 6008)
        event_crashes = self._query_event_log_crashes(limit=limit)

        # 3. Merge minidump records and event logs with deduplication
        merged = self._merge_crash_records(dump_crashes, event_crashes)

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
            "has_minidumps": len(dump_crashes) > 0,
            "minidump_count": len(dump_crashes)
        }

    def analyze_custom_dump(self, file_path: str) -> Dict[str, Any]:
        """
        Deeply analyzes a user-selected .dmp file from any location on the system.
        """
        if not os.path.exists(file_path):
            return {"success": False, "error": f"File does not exist: {file_path}"}

        parsed = analyze_dump_file_with_windbg_fallback(file_path)
        if not parsed.get("success"):
            return parsed

        bugcheck_code = parsed.get("bugcheck_code_raw", 0)
        params = parsed.get("bugcheck_parameters_raw", [0, 0, 0, 0])
        exc_addr = int(parsed.get("exception_address", "0x0"), 16) if parsed.get("exception_address") else 0
        rip = int(parsed.get("context_rip", "0x0"), 16) if parsed.get("context_rip") else 0
        modules = parsed.get("modules", [])

        # Run heuristics to find culprit driver
        culprit_res = CulpritResolver.resolve(
            bugcheck_code=bugcheck_code,
            params=params,
            exception_address=exc_addr,
            context_rip=rip,
            modules=modules
        )

        driver_name = culprit_res["driver_name"]
        driver_info = culprit_res["driver_info"]
        bugcheck_info = culprit_res["bugcheck_info"]

        # Run online intelligence check
        online_intel = DriverOnlineChecker.enrich(
            driver_name=driver_name,
            bugcheck_code=bugcheck_code,
            bugcheck_name=bugcheck_info.get("name"),
            vendor=driver_info.get("vendor")
        )

        parsed["culprit_analysis"] = {
            "responsible_driver": driver_name,
            "confidence_score": culprit_res["confidence_score"],
            "confidence_label": culprit_res["confidence_label"],
            "resolution_method": culprit_res["resolution_method"],
            "evidence_chain": culprit_res["evidence_chain"],
            "driver_info": driver_info,
            "bugcheck_info": bugcheck_info,
            "online_intelligence": online_intel,
            "cause_he": f"{bugcheck_info.get('cause_he', '')} הדרייבר האשם שזוהה: {driver_name} ({driver_info.get('desc_he', '')}).",
            "cause_en": f"{bugcheck_info.get('cause_en', '')} Culprit driver: {driver_name} ({driver_info.get('name', '')}).",
            "solution_he": driver_info.get("solution_he") or bugcheck_info.get("solution_he"),
            "solution_en": driver_info.get("solution_en") or bugcheck_info.get("solution_en")
        }

        return parsed

    def lookup_driver_online(self, driver_name: str, bugcheck_code: Optional[int] = None) -> Dict[str, Any]:
        """
        Public endpoint method to perform live online lookup for any driver and bugcheck.
        """
        driver_entry = DRIVER_REGISTRY.get(driver_name.lower().strip())
        vendor = driver_entry.get("vendor") if driver_entry else None
        return DriverOnlineChecker.enrich(
            driver_name=driver_name,
            bugcheck_code=bugcheck_code,
            vendor=vendor
        )

    def _scan_and_parse_minidump_files(self) -> List[Dict[str, Any]]:
        """
        Scans %SystemRoot%\Minidump and MEMORY.DMP, parses them with MinidumpParser,
        and attaches resolved culprit driver analysis.
        """
        dump_records: List[Dict[str, Any]] = []
        candidate_files = []

        if os.path.exists(self.minidump_dir):
            try:
                candidate_files.extend(glob.glob(os.path.join(self.minidump_dir, "*.dmp")))
            except Exception:
                pass

        if os.path.exists(self.memory_dmp):
            candidate_files.append(self.memory_dmp)

        for f_path in candidate_files:
            try:
                stat = os.stat(f_path)
                mtime = datetime.fromtimestamp(stat.st_mtime)
                time_str = mtime.strftime("%Y-%m-%d %H:%M:%S")
                filename = os.path.basename(f_path)

                # Parse the minidump binary
                parser = MinidumpParser(f_path)
                parsed = parser.parse()

                if parsed.get("success"):
                    bugcheck_code = parsed.get("bugcheck_code_raw", 0)
                    params = parsed.get("bugcheck_parameters_raw", [0, 0, 0, 0])
                    exc_addr = int(parsed.get("exception_address", "0x0"), 16) if parsed.get("exception_address") else 0
                    rip = int(parsed.get("context_rip", "0x0"), 16) if parsed.get("context_rip") else 0
                    modules = parsed.get("modules", [])

                    # Resolve true culprit driver
                    res = CulpritResolver.resolve(
                        bugcheck_code=bugcheck_code,
                        params=params,
                        exception_address=exc_addr,
                        context_rip=rip,
                        modules=modules
                    )

                    driver_name = res["driver_name"]
                    d_info = res["driver_info"]
                    b_info = res["bugcheck_info"]

                    # Enrich with online intelligence
                    online_intel = DriverOnlineChecker.enrich(
                        driver_name=driver_name,
                        bugcheck_code=bugcheck_code,
                        bugcheck_name=b_info.get("name"),
                        vendor=d_info.get("vendor")
                    )

                    dump_records.append({
                        "id": f"dmp_{filename}",
                        "timestamp": parsed.get("crash_time") or time_str,
                        "timestamp_raw": time_str,
                        "type": "BSOD",
                        "filename": filename,
                        "file_path": f_path,
                        "size_bytes": stat.st_size,
                        "size_kb": round(stat.st_size / 1024, 1),
                        "title_he": f"קריסת מסך כחול - {b_info.get('title_he', filename)}",
                        "title_en": f"BSOD Crash - {b_info.get('title_en', filename)}",
                        "bugcheck_name": b_info.get("name", parsed.get("bugcheck_code")),
                        "bugcheck_code": parsed.get("bugcheck_code", "0x0"),
                        "bugcheck_parameters": parsed.get("bugcheck_parameters", []),
                        "responsible_driver": driver_name,
                        "confidence_score": res["confidence_score"],
                        "confidence_label": res["confidence_label"],
                        "resolution_method": res["resolution_method"],
                        "evidence_chain": res["evidence_chain"],
                        "driver_info": d_info,
                        "online_intelligence": online_intel,
                        "cause_he": f"{b_info.get('cause_he', '')} הדרייבר האשם: {driver_name} ({d_info.get('desc_he', '')}).",
                        "cause_en": f"{b_info.get('cause_en', '')} Culprit driver: {driver_name} ({d_info.get('name', '')}).",
                        "solution_he": d_info.get("solution_he") or b_info.get("solution_he"),
                        "solution_en": d_info.get("solution_en") or b_info.get("solution_en"),
                        "severity": b_info.get("severity", "Critical"),
                        "os_version": parsed.get("os_version"),
                        "architecture": parsed.get("architecture"),
                        "has_binary_dump": True,
                        "modules_count": len(modules)
                    })
                else:
                    # Generic fallback record if binary parsing hit unreadable structure
                    dump_records.append({
                        "id": f"dmp_{filename}",
                        "timestamp": time_str,
                        "timestamp_raw": time_str,
                        "type": "BSOD",
                        "filename": filename,
                        "file_path": f_path,
                        "size_bytes": stat.st_size,
                        "title_he": f"קובץ Minidump ({filename})",
                        "title_en": f"Minidump File ({filename})",
                        "bugcheck_name": "MINIDUMP_RECORD",
                        "bugcheck_code": "0x (Minidump Available)",
                        "responsible_driver": "ntoskrnl.exe",
                        "cause_he": "נוצר קובץ זיכרון בעקבות קריסת מסך כחול.",
                        "cause_en": "Minidump file generated during Blue Screen event.",
                        "solution_he": "הרץ בדיקת קבצי מערכת SFC ובדיקת זיכרון RAM.",
                        "solution_en": "Run SFC repair and RAM diagnostic.",
                        "severity": "Critical",
                        "has_binary_dump": False
                    })
            except Exception as e:
                print(f"Error parsing minidump {f_path}:", e)

        return dump_records

    def _query_event_log_crashes(self, limit: int = 20) -> List[Dict[str, Any]]:
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

    def _parse_event_record(self, ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ev_id = ev.get('Id')
        time_str = ev.get('TimeCreated', '')
        msg = ev.get('Message', '')
        provider = ev.get('ProviderName', '')

        if ev_id == 1001 and ("BugCheck" in provider or "WER-SystemErrorReporting" in provider):
            # Blue Screen Event
            bugcheck_code = self._extract_bugcheck_code(msg)
            driver_hint = self._extract_driver_name(msg)

            res = CulpritResolver.resolve(
                bugcheck_code=bugcheck_code,
                params=[],
                exception_address=0,
                context_rip=0,
                modules=[],
                raw_driver_hint=driver_hint
            )

            driver_name = res["driver_name"]
            d_info = res["driver_info"]
            b_info = res["bugcheck_info"]

            online_intel = DriverOnlineChecker.enrich(
                driver_name=driver_name,
                bugcheck_code=bugcheck_code,
                bugcheck_name=b_info.get("name"),
                vendor=d_info.get("vendor")
            )

            return {
                "id": f"bsod_{time_str.replace(' ', '_').replace(':', '')}",
                "timestamp": time_str,
                "timestamp_raw": time_str,
                "type": "BSOD",
                "event_id": 1001,
                "title_he": b_info.get("title_he"),
                "title_en": b_info.get("title_en"),
                "bugcheck_name": b_info.get("name"),
                "bugcheck_code": hex(bugcheck_code) if isinstance(bugcheck_code, int) else str(bugcheck_code),
                "responsible_driver": driver_name,
                "confidence_score": res["confidence_score"],
                "confidence_label": res["confidence_label"],
                "resolution_method": res["resolution_method"],
                "evidence_chain": res["evidence_chain"],
                "driver_info": d_info,
                "online_intelligence": online_intel,
                "cause_he": f"{b_info.get('cause_he', '')} הדרייבר שגרם לקריסה: {driver_name} ({d_info.get('desc_he', '')}).",
                "cause_en": f"{b_info.get('cause_en', '')} Crashing Driver: {driver_name} ({d_info.get('name', '')}).",
                "solution_he": d_info.get("solution_he") or b_info.get("solution_he"),
                "solution_en": d_info.get("solution_en") or b_info.get("solution_en"),
                "severity": b_info.get("severity", "Critical"),
                "raw_message": msg.strip()[:400]
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
                "responsible_driver": "ספק כוח / חומרה / התחממות",
                "confidence_score": 90,
                "confidence_label": "90% ודאות",
                "resolution_method": "Hardware Power Transition Monitor",
                "evidence_chain": ["Windows זוהתה כיבוי בלתי מבוקר ללא תהליך סגירה תקין."],
                "cause_he": "המחשב הופעל מחדש מבלי שביצע כיבוי מסודר. נגרם מניתוק חשמל פתאומי, נפילת מתח בספק הכוח (PSU), התחממות יתר (Thermal Shutdown), או קפיאת חומרה מוחלטת.",
                "cause_en": "The system rebooted without cleanly shutting down first. Typically caused by power loss, PSU failure, or thermal shutdown.",
                "solution_he": "בדוק שחיבורי החשמל והכבלים תקינים. בדוק טמפרטורות מעבד וכרטיס מסך. אם האירוע חוזר על עצמו בעומס משחקים, בדוק את ספק הכוח.",
                "solution_en": "Check power cables and PSU health. Monitor CPU/GPU temperatures under load.",
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
                "confidence_score": 80,
                "confidence_label": "80% ודאות",
                "cause_he": "מערכת ההפעלה זיהתה שכיבוי המחשב הקודם לא הושלם באופן מסודר.",
                "cause_en": "Windows detected that the previous shutdown sequence was terminated unexpectedly.",
                "solution_he": "ודא כיבוי תקין מתפריט 'התחל' ומנע כיבוי כפוי מכפתור ההדלקה.",
                "solution_en": "Ensure proper shutdown via Start Menu and avoid holding power button.",
                "severity": "Warning",
                "raw_message": msg.strip()[:300]
            }

        return None

    def _extract_bugcheck_code(self, msg: str) -> int:
        match = re.search(r'0x[0-9a-fA-F]{1,8}', msg)
        if match:
            try:
                return int(match.group(0), 16)
            except ValueError:
                pass
        return 0x0

    def _extract_driver_name(self, msg: str) -> Optional[str]:
        match = re.search(r'([a-zA-Z0-9_\-]+\.(?:sys|dll|exe))', msg, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return None

    def _merge_crash_records(self, dump_crashes: List[Dict[str, Any]], event_crashes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Prefer dump crashes because they contain richer binary stack and module data
        all_crashes = list(dump_crashes)
        seen_timestamps = set(c.get('timestamp_raw', '')[:16] for c in all_crashes)

        for ec in event_crashes:
            t_short = ec.get('timestamp_raw', '')[:16]
            if t_short not in seen_timestamps:
                all_crashes.append(ec)
                seen_timestamps.add(t_short)

        return all_crashes

    def trigger_memory_diagnostic(self) -> Dict[str, Any]:
        """
        Triggers Windows Memory Diagnostic Tool (mdsched.exe)
        """
        if not self.is_windows:
            return {"success": False, "message": "Supported on Windows only"}

        try:
            subprocess.Popen(["mdsched.exe"])
            return {
                "success": True,
                "message": "כלי בדיקת הזיכרון של Windows (mdsched.exe) הופעל בהצלחה. עקוב אחר ההנחיות במסך להפעלה מחדש ובדיקת תקינות ה-RAM."
            }
        except Exception as e:
            return {"success": False, "message": str(e)}

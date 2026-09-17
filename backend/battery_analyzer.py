"""
Polaris - Battery Health & Power Diagnostics Engine.

Automatically calculates:
  * Battery Health percentage: (FullChargeCapacity / DesignCapacity) * 100
  * Wear Level percentage: 100 - Health percentage
  * Hardware Cycle Count
  * Live charge state, AC connection, power draw and estimated battery runtime
  * Chemistry, manufacturer and hardware identifier

Gracefully handles desktop systems without a battery.
Caches heavy hardware diagnostics (powercfg / WMI) with a 60-second TTL while
updating live dynamic state (charge level, AC status) instantly on every call.
"""

import os
import time
import tempfile
import psutil
from xml.etree import ElementTree as ET

from backend.win_utils import IS_WINDOWS, run_hidden, run_powershell_json, ltr_isolate, NBSP

# Cache lifetime for static hardware battery specifications (seconds)
BATTERY_CACHE_TTL = 60.0


def _format_mwh(mwh):
    """Formats mWh to a readable Wh string, e.g. 52570 mWh -> '52.6 Wh'."""
    if mwh is None or mwh <= 0:
        return "--"
    # BiDi-isolated so the unit stays after the number in the Hebrew RTL UI.
    if mwh >= 1000:
        return ltr_isolate(f"{mwh / 1000.0:.1f}{NBSP}Wh")
    return ltr_isolate(f"{mwh}{NBSP}mWh")


def _format_time_remaining(secsleft, plugged, percent):
    """Returns human-readable remaining time in Hebrew and English."""
    if plugged:
        if percent is not None and percent >= 98:
            return "\u05de\u05d7\u05d5\u05d1\u05e8 \u05dc\u05d7\u05e9\u05de\u05dc (\u05d8\u05e2\u05d5\u05df \u05d1\u05de\u05dc\u05d5\u05d0\u05d5)", "Plugged in (Fully Charged)"
        return "\u05de\u05d7\u05d5\u05d1\u05e8 \u05dc\u05d7\u05e9\u05de\u05dc (\u05d1\u05d8\u05e2\u05d9\u05e0\u05d4)", "Plugged in (Charging)"

    if secsleft is None or secsleft < 0:
        return "\u05de\u05d7\u05e9\u05d1 \u05d6\u05de\u05df \u05e0\u05d5\u05ea\u05e8...", "Estimating time remaining..."

    if secsleft == psutil.POWER_TIME_UNLIMITED:
        return "\u05de\u05d7\u05d5\u05d1\u05e8 \u05dc\u05d7\u05e9\u05de\u05dc", "Plugged in"

    if secsleft == psutil.POWER_TIME_UNKNOWN:
        return "\u05d7\u05d9\u05e9\u05d5\u05d1 \u05d6\u05de\u05df \u05de\u05e9\u05d5\u05e2\u05e8...", "Calculating runtime..."

    hours = secsleft // 3600
    minutes = (secsleft % 3600) // 60

    if hours > 0:
        he = f"{hours} \u05e9\u05e2\u05d5\u05ea \u05d5-{minutes} \u05d3\u05e7'" if hours > 1 else f"\u05e9\u05e2\u05d4 \u05d5-{minutes} \u05d3\u05e7'"
        en = f"{hours}h {minutes}m"
    elif minutes > 0:
        he = f"{minutes} \u05d3\u05e7\u05d5\u05ea"
        en = f"{minutes} min"
    else:
        he = "\u05e4\u05d7\u05d5\u05ea \u05de\u05d3\u05e7\u05d4"
        en = "< 1 min"

    return he, en


class BatteryAnalyzer:
    def __init__(self):
        self._cached_data = None
        self._last_scan_time = 0.0

    def get_report(self, force=False):
        """
        Returns full battery health and power diagnostic report.
        If force=True or cache is older than BATTERY_CACHE_TTL, queries hardware.
        Always updates live dynamic metrics (percentage, AC plugged, runtime).
        """
        now = time.time()
        needs_full_scan = force or (self._cached_data is None) or ((now - self._last_scan_time) > BATTERY_CACHE_TTL)

        if needs_full_scan:
            base_report = self._scan_hardware_battery()
            self._cached_data = base_report
            self._last_scan_time = now
        else:
            base_report = dict(self._cached_data)

        # Update dynamic live metrics
        return self._inject_live_metrics(base_report)

    def _scan_hardware_battery(self):
        """Extracts hardware battery specs via powercfg /batteryreport or WMI."""
        # Quick pre-check with psutil: if None on Windows, likely desktop machine
        sb = psutil.sensors_battery() if hasattr(psutil, 'sensors_battery') else None
        if not IS_WINDOWS and sb is None:
            return {
                "has_battery": False,
                "message_he": "\u05dc\u05d0 \u05d6\u05d5\u05d4\u05ea\u05d4 \u05e1\u05d5\u05dc\u05dc\u05d4 (\u05de\u05d7\u05e9\u05d1 \u05e0\u05d9\u05d9\u05d7 / \u05dc\u05dc\u05d0 \u05e1\u05d5\u05dc\u05dc\u05d4)",
                "message_en": "No battery detected (Desktop PC or AC only)",
            }

        # Attempt 1: powercfg /batteryreport /xml (Authoritative Windows battery report)
        report = self._scan_powercfg_xml()
        if report and report.get("has_battery"):
            return report

        # Attempt 2: Fallback to WMI root\\wmi
        report = self._scan_wmi_fallback()
        if report and report.get("has_battery"):
            return report

        # Attempt 3: If psutil found a battery but hardware reports were inaccessible
        if sb is not None:
            return {
                "has_battery": True,
                "health_percent": None,
                "wear_percent": None,
                "health_tone": "neutral",
                "status_key": "active",
                "status_he": "\u05e1\u05d5\u05dc\u05dc\u05d4 \u05e4\u05e2\u05d9\u05dc\u05d4",
                "status_en": "Battery Active",
                "design_capacity_mwh": None,
                "full_charge_capacity_mwh": None,
                "cycle_count": None,
                "manufacturer": "Standard Battery",
                "chemistry": "--",
                "device_name": "--",
            }

        return {
            "has_battery": False,
            "message_he": "\u05dc\u05d0 \u05d6\u05d5\u05d4\u05ea\u05d4 \u05e1\u05d5\u05dc\u05dc\u05d4 (\u05de\u05d7\u05e9\u05d1 \u05e0\u05d9\u05d9\u05d7 / \u05dc\u05dc\u05d0 \u05e1\u05d5\u05dc\u05dc\u05d4)",
            "message_en": "No battery detected (Desktop PC or AC only)",
        }

    def _scan_powercfg_xml(self):
        """Runs powercfg /batteryreport /xml silently and parses design & full capacity."""
        if not IS_WINDOWS:
            return None

        temp_xml = os.path.join(tempfile.gettempdir(), f"polaris_bat_{os.getpid()}_{int(time.time())}.xml")
        try:
            res = run_hidden(
                ["powercfg", "/batteryreport", "/xml", "/output", temp_xml],
                capture_output=True,
                text=True,
                timeout=12,
            )
            if not os.path.exists(temp_xml):
                return None

            tree = ET.parse(temp_xml)
            root = tree.getroot()

            # Strip XML namespaces for clean tag lookups
            for el in root.iter():
                if '}' in el.tag:
                    el.tag = el.tag.split('}', 1)[1]

            batteries = root.findall('.//Batteries/Battery')
            if not batteries:
                return None

            # Aggregate if multiple batteries exist, prioritize primary
            total_design = 0
            total_full = 0
            primary_cycles = None
            primary_mfg = None
            primary_chem = None
            primary_id = None

            for b in batteries:
                def _get(tag):
                    el = b.find(tag)
                    return el.text.strip() if el is not None and el.text else None

                try:
                    d = int(_get('DesignCapacity') or 0)
                    f = int(_get('FullChargeCapacity') or 0)
                    c = int(_get('CycleCount') or 0) if _get('CycleCount') else None
                except (ValueError, TypeError):
                    d, f, c = 0, 0, None

                total_design += d
                total_full += f

                if primary_cycles is None and c is not None:
                    primary_cycles = c
                if primary_mfg is None:
                    primary_mfg = _get('Manufacturer')
                if primary_chem is None:
                    primary_chem = _get('Chemistry')
                if primary_id is None:
                    primary_id = _get('Id')

            if total_design <= 0 and total_full <= 0:
                return None

            health_pct = round((total_full / total_design * 100.0), 1) if total_design > 0 else 100.0
            health_pct = min(100.0, max(0.0, health_pct))
            wear_pct = round(max(0.0, 100.0 - health_pct), 1)

            tone, key, status_he, status_en = self._classify_health(health_pct, primary_cycles)

            return {
                "has_battery": True,
                "health_percent": health_pct,
                "wear_percent": wear_pct,
                "health_tone": tone,
                "status_key": key,
                "status_he": status_he,
                "status_en": status_en,
                "design_capacity_mwh": total_design,
                "full_charge_capacity_mwh": total_full,
                "design_capacity_formatted": _format_mwh(total_design),
                "full_charge_capacity_formatted": _format_mwh(total_full),
                "cycle_count": primary_cycles,
                "manufacturer": primary_mfg or "Unknown",
                "chemistry": primary_chem or "Li-ion",
                "device_name": primary_id or "Internal Battery",
            }
        except Exception:
            return None
        finally:
            if os.path.exists(temp_xml):
                try:
                    os.remove(temp_xml)
                except Exception:
                    pass

    def _scan_wmi_fallback(self):
        """Fallback to WMI root\\wmi classes BatteryStaticData & BatteryFullChargedCapacity."""
        script = """
        $static = Get-WmiObject -Namespace root\\wmi -Class BatteryStaticData -ErrorAction SilentlyContinue
        $full = Get-WmiObject -Namespace root\\wmi -Class BatteryFullChargedCapacity -ErrorAction SilentlyContinue
        if ($static -or $full) {
            [PSCustomObject]@{
                DesignCapacity = [int]$static.DesignedCapacity
                FullCapacity   = [int]$full.FullChargedCapacity
                DeviceName     = [string]$static.DeviceName
                Manufacturer   = [string]$static.ManufactureName
            } | ConvertTo-Json -Compress
        } else { '[]' }
        """
        results = run_powershell_json(script, timeout=8)
        if not results:
            return None

        row = results[0]
        design = int(row.get("DesignCapacity") or 0)
        full = int(row.get("FullCapacity") or 0)

        if design <= 0 and full <= 0:
            return None

        health_pct = round((full / design * 100.0), 1) if design > 0 else 100.0
        health_pct = min(100.0, max(0.0, health_pct))
        wear_pct = round(max(0.0, 100.0 - health_pct), 1)
        tone, key, status_he, status_en = self._classify_health(health_pct, None)

        return {
            "has_battery": True,
            "health_percent": health_pct,
            "wear_percent": wear_pct,
            "health_tone": tone,
            "status_key": key,
            "status_he": status_he,
            "status_en": status_en,
            "design_capacity_mwh": design,
            "full_charge_capacity_mwh": full,
            "design_capacity_formatted": _format_mwh(design),
            "full_charge_capacity_formatted": _format_mwh(full),
            "cycle_count": None,
            "manufacturer": row.get("Manufacturer") or "OEM",
            "chemistry": "Li-ion",
            "device_name": row.get("DeviceName") or "Internal Battery",
        }

    def _classify_health(self, health_pct, cycles):
        """Assigns health tone, key, and natural language description."""
        if health_pct < 50.0:
            return "danger", "degraded", "\u05e1\u05d5\u05dc\u05dc\u05d4 \u05e9\u05d7\u05d5\u05e7\u05d4 (\u05de\u05d5\u05de\u05dc\u05e5 \u05dc\u05d4\u05d7\u05dc\u05d9\u05e3)", "Degraded battery (Replacement recommended)"
        if health_pct < 70.0:
            return "warn", "moderate", "\u05e9\u05d7\u05d9\u05e7\u05d4 \u05d1\u05d9\u05e0\u05d5\u05e0\u05d9\u05ea (\u05e7\u05d9\u05d1\u05d5\u05dc\u05ea \u05de\u05d5\u05e4\u05d7\u05ea\u05ea)", "Moderate wear (Noticeably reduced capacity)"
        if health_pct < 85.0:
            return "ok", "good", "\u05de\u05e6\u05d1 \u05d8\u05d5\u05d1 (\u05e9\u05d7\u05d9\u05e7\u05d4 \u05e1\u05d1\u05d9\u05e8\u05d4)", "Good condition (Normal wear)"
        return "ok", "excellent", "\u05de\u05e6\u05d1 \u05de\u05e6\u05d5\u05d9\u05df (\u05d1\u05e8\u05d9\u05d0\u05d5\u05ea \u05d2\u05d1\u05d5\u05d4\u05d4)", "Excellent condition (High health)"

    def _inject_live_metrics(self, data):
        """Injects sub-millisecond psutil live metrics into the report."""
        if not data.get("has_battery"):
            return data

        res = dict(data)
        sb = psutil.sensors_battery() if hasattr(psutil, 'sensors_battery') else None

        if sb is not None:
            pct = round(sb.percent, 1)
            plugged = bool(sb.power_plugged)
            secsleft = sb.secsleft

            res["current_charge_percent"] = pct
            res["power_plugged"] = plugged
            res["is_charging"] = plugged and (pct < 98)
            res["is_discharging"] = not plugged

            time_he, time_en = _format_time_remaining(secsleft, plugged, pct)
            res["time_remaining_formatted_he"] = time_he
            res["time_remaining_formatted_en"] = time_en
            res["time_remaining_seconds"] = secsleft if secsleft and secsleft > 0 else None
        else:
            res["current_charge_percent"] = None
            res["power_plugged"] = True
            res["is_charging"] = False
            res["is_discharging"] = False
            res["time_remaining_formatted_he"] = "\u05de\u05d7\u05d5\u05d1\u05e8 \u05dc\u05d7\u05e9\u05de\u05dc"
            res["time_remaining_formatted_en"] = "Plugged in"
            res["time_remaining_seconds"] = None

        return res

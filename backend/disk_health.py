"""
Polaris - Physical drive health (S.M.A.R.T.) and capacity analysis.

Answers the question the memory analyser cannot: "my PC is slow / freezing -
is the drive itself dying?" A failing or nearly-full drive produces exactly the
symptoms users blame on RAM (stalls, long boots, unresponsive apps), so this
sits alongside the memory diagnostics rather than replacing them.

Data sources, in order of preference:
  1. Get-PhysicalDisk + Get-StorageReliabilityCounter - real S.M.A.R.T.
     counters (wear, temperature, uncorrected errors, power-on hours).
     The reliability counters require Administrator on most systems.
  2. Win32_DiskDrive - model, size and a coarse Status, available without
     elevation on every supported Windows version.

Everything is best-effort: a missing counter is reported as unknown rather
than guessed at, because a fabricated "healthy" verdict on a dying drive is
worse than no verdict.
"""

import time
import threading
import psutil

from backend.win_utils import IS_WINDOWS, run_powershell_json, format_bytes, is_admin
from backend.smart_engine import smart_engine

# Wear percentages above these thresholds start mattering to a user.
WEAR_WARN = 50
WEAR_CRITICAL = 80

# Drive temperatures in Celsius. NVMe drives idle warm, so the bar is high.
TEMP_WARN = 60
TEMP_CRITICAL = 70

# Free-space thresholds. Windows needs headroom for the pagefile, updates and
# defragmentation; below ~10% the whole machine degrades.
FREE_WARN_PERCENT = 15
FREE_CRITICAL_PERCENT = 8

# A mechanical drive past this many power-on hours (~5.7 years of uptime) is
# worth mentioning even when every counter still reads healthy.
HDD_AGE_NOTE_HOURS = 50000


_PHYSICAL_DISK_PS = """
$disks = Get-PhysicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
    $counter = $null
    try { $counter = $_ | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }
    [PSCustomObject]@{
        DeviceId          = [string]$_.DeviceId
        FriendlyName      = [string]$_.FriendlyName
        SerialNumber      = [string]$_.SerialNumber
        MediaType         = [string]$_.MediaType
        BusType           = [string]$_.BusType
        Size              = [int64]$_.Size
        HealthStatus      = [string]$_.HealthStatus
        OperationalStatus = [string]$_.OperationalStatus
        Wear              = $counter.Wear
        Temperature       = $counter.Temperature
        PowerOnHours      = $counter.PowerOnHours
        ReadErrors        = $counter.ReadErrorsUncorrected
        WriteErrors       = $counter.WriteErrorsUncorrected
    }
}
if ($disks) { $disks | ConvertTo-Json -Depth 3 -Compress } else { '[]' }
"""

_LEGACY_DISK_PS = """
$disks = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        DeviceId     = [string]$_.Index
        FriendlyName = [string]$_.Model
        SerialNumber = [string]$_.SerialNumber
        MediaType    = ''
        BusType      = [string]$_.InterfaceType
        Size         = [int64]$_.Size
        HealthStatus = if ($_.Status -eq 'OK') { 'Healthy' } else { [string]$_.Status }
    }
}
if ($disks) { $disks | ConvertTo-Json -Depth 3 -Compress } else { '[]' }
"""

_VOLUME_PS = """
$vols = Get-Partition -ErrorAction SilentlyContinue | ForEach-Object {
    $vol = $null
    try { $vol = $_ | Get-Volume -ErrorAction Stop } catch { }
    if ($vol -and $vol.DriveLetter) {
        [PSCustomObject]@{
            DiskNumber  = [int]$_.DiskNumber
            DriveLetter = [string]$vol.DriveLetter
            Label       = [string]$vol.FileSystemLabel
            FileSystem  = [string]$vol.FileSystem
            Size        = [int64]$vol.Size
            Remaining   = [int64]$vol.SizeRemaining
        }
    }
}
if ($vols) { $vols | ConvertTo-Json -Depth 3 -Compress } else { '[]' }
"""


def _as_int(value):
    """CIM counters arrive as ints, floats, numeric strings, or null."""
    if value is None or value == '':
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _finding(severity, title_he, title_en, desc_he, desc_en, action_he='', action_en=''):
    return {
        "severity": severity,
        "title_he": title_he, "title_en": title_en,
        "desc_he": desc_he, "desc_en": desc_en,
        "action_he": action_he, "action_en": action_en,
    }


class DiskHealthAnalyzer:
    """Collects and interprets physical drive health."""

    def __init__(self):
        self._cached_report = None
        self._cache_time = 0.0
        self._cache_ttl = 30.0
        self._lock = threading.Lock()

    def get_report(self, force=False):
        now = time.time()
        with self._lock:
            if not force and self._cached_report and (now - self._cache_time < self._cache_ttl):
                return dict(self._cached_report)

        if not IS_WINDOWS:
            return {
                "disks": [], "findings": [], "supported": False,
                "counters_available": False,
                "overall": "unknown", "overall_he": "לא נתמך", "overall_en": "Not supported",
            }

        # 1. Direct hardware query (CrystalDiskInfo engine)
        smart_drives = {}
        try:
            for s_disk in smart_engine.scan_physical_drives():
                s_id = str(s_disk.get("device_id", ""))
                smart_drives[s_id] = s_disk
        except Exception as exc:
            print(f"Direct SMART query exception: {exc}")

        # 2. Volumes
        volumes_by_disk = self._collect_volumes()

        # 3. OS disk inventory via PowerShell / CIM
        raw_disks = run_powershell_json(_PHYSICAL_DISK_PS, timeout=30)
        used_fallback = False
        if not raw_disks:
            raw_disks = run_powershell_json(_LEGACY_DISK_PS, timeout=20)
            used_fallback = True

        # If PowerShell returned nothing but smart_engine found drives:
        if not raw_disks and smart_drives:
            raw_disks = []
            for s_id, s_info in smart_drives.items():
                raw_disks.append({
                    "DeviceId": s_id,
                    "FriendlyName": s_info.get("name"),
                    "SerialNumber": s_info.get("serial"),
                    "MediaType": s_info.get("media_type"),
                    "BusType": s_info.get("bus_type"),
                    "Size": 0,
                    "HealthStatus": s_info.get("status"),
                })

        disks = []
        all_findings = []
        counters_available = False

        for raw in raw_disks:
            disk = self._build_disk(raw, volumes_by_disk, smart_drives)
            if disk["wear_percent"] is not None or disk["power_on_hours"] is not None or disk.get("temperature_c") is not None:
                counters_available = True
            disks.append(disk)
            all_findings.extend(disk["findings"])

        # Volumes on drives PowerShell did not report still deserve a capacity
        # check, so fold in anything psutil sees that we have not covered.
        covered = {v["letter"] for d in disks for v in d["volumes"]}
        orphans = [v for v in self._psutil_volumes() if v["letter"] not in covered]
        if orphans and not disks:
            disks.append(self._synthetic_disk(orphans))
            all_findings.extend(disks[-1]["findings"])

        overall = self._overall_tone(disks, all_findings)

        report = {
            "disks": disks,
            "findings": sorted(all_findings, key=lambda f: {"high": 0, "medium": 1, "low": 2}.get(f["severity"], 3)),
            "supported": True,
            "counters_available": counters_available,
            "limited_data": (not counters_available),
            "is_admin": is_admin(),
            "overall": overall[0],
            "overall_he": overall[1],
            "overall_en": overall[2],
        }

        with self._lock:
            self._cached_report = report
            self._cache_time = time.time()

        return report

    # ------------------------------------------------------------------ disks

    def _build_disk(self, raw, volumes_by_disk, smart_drives=None):
        device_id = str(raw.get("DeviceId", "")).strip()
        size = _as_int(raw.get("Size")) or 0
        media = (raw.get("MediaType") or "").strip()
        if media in ("", "Unspecified", "0"):
            media = "Unknown"

        health = (raw.get("HealthStatus") or "Unknown").strip() or "Unknown"
        operational = (raw.get("OperationalStatus") or "").strip()

        # Check smart_drives first for direct hardware counters
        s_info = (smart_drives or {}).get(device_id)

        wear = s_info.get("wear_percent") if s_info else _as_int(raw.get("Wear"))
        temperature = s_info.get("temperature_c") if s_info else _as_int(raw.get("Temperature"))
        power_on = s_info.get("power_on_hours") if s_info else _as_int(raw.get("PowerOnHours"))
        read_errors = _as_int(raw.get("ReadErrors"))
        write_errors = _as_int(raw.get("WriteErrors"))

        name = (s_info.get("name") if (s_info and s_info.get("name")) else (raw.get("FriendlyName") or "Unknown drive")).strip()
        serial = (s_info.get("serial") if (s_info and s_info.get("serial")) else (raw.get("SerialNumber") or "")).strip()
        firmware = (s_info.get("firmware") if s_info else "").strip()
        bus_type = (s_info.get("bus_type") if (s_info and s_info.get("bus_type")) else (raw.get("BusType") or "")).strip()

        if s_info and s_info.get("media_type") and media == "Unknown":
            media = s_info["media_type"]

        volumes = volumes_by_disk.get(device_id, [])
        if not size and volumes:
            size = sum(v.get("total_bytes", 0) for v in volumes)

        life_remaining = None
        if s_info and s_info.get("life_remaining_percent") is not None:
            life_remaining = s_info["life_remaining_percent"]
        elif wear is not None:
            life_remaining = max(0, min(100, 100 - wear))

        health_status = s_info.get("status", health) if s_info else health

        disk = {
            "device_id": device_id,
            "name": name,
            "serial": serial,
            "firmware": firmware,
            "media_type": media,
            "bus_type": bus_type,
            "is_nvme": s_info.get("is_nvme", False) if s_info else ("NVMe" in bus_type.upper()),
            "size_bytes": size,
            "size_formatted": format_bytes(size) if size else "--",
            "health_status": health_status,
            "operational_status": operational,
            "wear_percent": wear,
            "life_remaining_percent": life_remaining,
            "temperature_c": temperature,
            "power_on_hours": power_on,
            "power_on_years": round(power_on / 8760, 1) if power_on else None,
            "power_cycles": s_info.get("power_cycles") if s_info else None,
            "host_reads_formatted": s_info.get("host_reads_formatted") if s_info else None,
            "host_writes_formatted": s_info.get("host_writes_formatted") if s_info else None,
            "host_reads_bytes": s_info.get("host_reads_bytes") if s_info else None,
            "host_writes_bytes": s_info.get("host_writes_bytes") if s_info else None,
            "media_errors": s_info.get("media_errors") if s_info else None,
            "unsafe_shutdowns": s_info.get("unsafe_shutdowns") if s_info else None,
            "critical_warning": s_info.get("critical_warning") if s_info else None,
            "read_errors": read_errors,
            "write_errors": write_errors,
            "volumes": volumes,
            "attributes": s_info.get("attributes", []) if s_info else [],
            "smart_supported": bool(s_info and s_info.get("attributes")),
            "status_he": s_info.get("status_he", "תקין" if health_status in ("Healthy", "Good") else health_status),
            "status_en": s_info.get("status_en", "Good" if health_status in ("Healthy", "Good") else health_status),
        }

        disk["findings"] = self._analyze_disk(disk)
        disk["tone"] = self._disk_tone(disk)
        return disk


    def _synthetic_disk(self, volumes):
        """Used when no physical-disk data is available at all."""
        total = sum(v["total_bytes"] for v in volumes)
        disk = {
            "device_id": "", "name": "Storage volumes", "serial": "",
            "media_type": "Unknown", "bus_type": "", "size_bytes": total,
            "size_formatted": format_bytes(total) if total else "--",
            "health_status": "Unknown", "operational_status": "",
            "wear_percent": None, "life_remaining_percent": None,
            "temperature_c": None, "power_on_hours": None, "power_on_years": None,
            "read_errors": None, "write_errors": None, "volumes": volumes,
        }
        disk["findings"] = self._analyze_disk(disk)
        disk["tone"] = self._disk_tone(disk)
        return disk

    # --------------------------------------------------------------- analysis

    def _analyze_disk(self, disk):
        findings = []
        name = disk["name"]

        if disk["health_status"] not in ("Healthy", "Unknown", ""):
            findings.append(_finding(
                "high",
                f"Windows מדווח על מצב לא תקין בכונן {name}",
                f"Windows reports an unhealthy state on {name}",
                f"מצב הכונן לפי מערכת ההפעלה הוא \"{disk['health_status']}\". "
                "זהו דיווח של הכונן עצמו, לא הערכה של Polaris.",
                f"The operating system reports the drive state as \"{disk['health_status']}\". "
                "This comes from the drive itself, not from a Polaris estimate.",
                "גבה את הקבצים החשובים עכשיו, לפני כל פעולת תחזוקה אחרת.",
                "Back up important files now, before any other maintenance.",
            ))

        wear = disk["wear_percent"]
        if wear is not None:
            if wear >= WEAR_CRITICAL:
                findings.append(_finding(
                    "high",
                    f"בלאי גבוה מאוד ב-{name}",
                    f"Very high wear on {name}",
                    f"נוצלו {wear}% ממחזורי הכתיבה של הכונן. נותרו כ-{100 - wear}% מתוחלת החיים שהיצרן מגדיר.",
                    f"{wear}% of the drive's write endurance has been consumed, leaving about {100 - wear}%.",
                    "תכנן החלפה של הכונן ושמור גיבוי עדכני.",
                    "Plan a replacement and keep a current backup.",
                ))
            elif wear >= WEAR_WARN:
                findings.append(_finding(
                    "medium",
                    f"בלאי מורגש ב-{name}",
                    f"Noticeable wear on {name}",
                    f"נוצלו {wear}% ממחזורי הכתיבה. הכונן עדיין תקין, אך כדאי לעקוב.",
                    f"{wear}% of the write endurance has been consumed. Still healthy, but worth watching.",
                    "אין צורך בפעולה מיידית. בדוק שוב בעוד מספר חודשים.",
                    "No action needed now. Check again in a few months.",
                ))

        for label_he, label_en, count in (
            ("קריאה", "read", disk["read_errors"]),
            ("כתיבה", "write", disk["write_errors"]),
        ):
            if count:
                findings.append(_finding(
                    "high",
                    f"שגיאות {label_he} שלא תוקנו ב-{name}",
                    f"Uncorrected {label_en} errors on {name}",
                    f"הכונן דיווח על {count} שגיאות {label_he} שלא ניתן היה לתקן. "
                    "זהו סימן מובהק לסקטורים פגומים.",
                    f"The drive reported {count} uncorrectable {label_en} errors, a strong sign of failing sectors.",
                    "גבה מיד והרץ chkdsk. כונן עם שגיאות שלא תוקנו נוטה להידרדר במהירות.",
                    "Back up immediately and run chkdsk. A drive with uncorrected errors tends to degrade fast.",
                ))

        # Direct hardware media and data integrity errors
        media_errors = disk.get("media_errors")
        if media_errors and media_errors > 0:
            findings.append(_finding(
                "high",
                f"שגיאות שלמות מדיה ונתונים ({media_errors:,}) ב-{name}",
                f"Media and data integrity errors ({media_errors:,}) on {name}",
                f"בקר הכונן זיהה {media_errors:,} מקרים של שגיאות שלמות נתונים שלא תוקנו. קיים סיכון ממשי לקריאת קבצים פגומים או קריסת מערכת.",
                f"The drive controller reported {media_errors:,} unrecovered media and data integrity errors. High risk of data loss.",
                "בצע גיבוי של כל המידע היקר באופן מיידי והחלף את הכונן.",
                "Back up all important data immediately and replace the drive.",
            ))

        # Hardware critical warning
        crit_warning = disk.get("critical_warning")
        if crit_warning and crit_warning > 0:
            findings.append(_finding(
                "high",
                f"התרעת חומרה קריטית בבקר הכונן {name}",
                f"Critical controller hardware warning on {name}",
                f"דגל אזהרת החומרה הפנימי של הכונן מופעל (קוד 0x{crit_warning:02X}). בקר הכונן מדווח על כשל או שחיקה חמורה.",
                f"The drive's internal critical warning flag is active (code 0x{crit_warning:02X}), reporting severe degradation or imminent failure.",
                "הימנע ממאמץ כבד על הכונן והעבר את המידע לכונן חלופי.",
                "Avoid heavy workloads on this drive and migrate data to a replacement.",
            ))

        temp = disk["temperature_c"]
        if temp is not None and temp >= TEMP_WARN:
            severity = "high" if temp >= TEMP_CRITICAL else "medium"
            findings.append(_finding(
                severity,
                f"טמפרטורה גבוהה ב-{name}",
                f"High temperature on {name}",
                f"הכונן מדווח על {temp}°C. חום מתמשך מקצר את חיי הכונן ומאט אותו בעומס.",
                f"The drive reports {temp}°C. Sustained heat shortens its life and throttles it under load.",
                "בדוק זרימת אוויר בתוך המארז ושהכונן אינו צמוד למקור חום.",
                "Check case airflow and make sure the drive is not pressed against a heat source.",
            ))

        if (disk["media_type"] or "").upper() == "HDD" and (disk["power_on_hours"] or 0) >= HDD_AGE_NOTE_HOURS:
            findings.append(_finding(
                "low",
                f"{name} צבר ותק משמעותי",
                f"{name} has significant runtime",
                f"הכונן פעל {disk['power_on_hours']:,} שעות (כ-{disk['power_on_years']} שנים). "
                "כל המדדים תקינים, אך זהו כונן מכני ותיק.",
                f"The drive has {disk['power_on_hours']:,} power-on hours (about {disk['power_on_years']} years). "
                "All counters read healthy, but this is an aging mechanical drive.",
                "אין תקלה. ודא שיש גיבוי, כמו לכל כונן מכני ותיק.",
                "Nothing is wrong. Just make sure a backup exists, as with any aging mechanical drive.",
            ))

        for vol in disk["volumes"]:
            free_pct = vol["free_percent"]
            if free_pct is None:
                continue
            if free_pct <= FREE_CRITICAL_PERCENT:
                findings.append(_finding(
                    "high",
                    f"כונן {vol['letter']}: כמעט מלא",
                    f"Drive {vol['letter']}: almost full",
                    f"נותרו {vol['free_formatted']} בלבד ({free_pct}%). "
                    "Windows זקוקה למקום פנוי לקובץ ההחלפה ולעדכונים, ובמצב הזה כל המערכת מאטה.",
                    f"Only {vol['free_formatted']} left ({free_pct}%). "
                    "Windows needs free space for the pagefile and updates; the whole system slows down at this level.",
                    "הרץ ניקוי במסך התחזוקה ופנה קבצים גדולים.",
                    "Run the cleanup on the maintenance screen and remove large files.",
                ))
            elif free_pct <= FREE_WARN_PERCENT:
                findings.append(_finding(
                    "medium",
                    f"מעט מקום פנוי בכונן {vol['letter']}",
                    f"Low free space on drive {vol['letter']}",
                    f"נותרו {vol['free_formatted']} ({free_pct}%).",
                    f"{vol['free_formatted']} remaining ({free_pct}%).",
                    "שקול להריץ ניקוי קבצים זמניים במסך התחזוקה.",
                    "Consider running the temp-file cleanup on the maintenance screen.",
                ))

        return findings

    def _disk_tone(self, disk):
        severities = {f["severity"] for f in disk["findings"]}
        if "high" in severities:
            return "danger"
        if "medium" in severities:
            return "warn"
        if disk["health_status"] == "Healthy":
            return "ok"
        return "neutral"

    def _overall_tone(self, disks, findings):
        severities = {f["severity"] for f in findings}
        if "high" in severities:
            return ("danger", "אותרה בעיה בכונן", "Drive problem detected")
        if "medium" in severities:
            return ("warn", "דורש מעקב", "Worth watching")
        if not disks:
            return ("neutral", "אין נתונים", "No data")
        return ("ok", "כל הכוננים תקינים", "All drives healthy")

    # ---------------------------------------------------------------- volumes

    def _collect_volumes(self):
        """Maps physical disk number -> list of volume dicts."""
        usage_by_letter = {v["letter"]: v for v in self._psutil_volumes()}
        now = time.time()

        if hasattr(self, '_cached_volumes') and self._cached_volumes and (now - getattr(self, '_volumes_cache_time', 0) < 60.0):
            # Refresh live byte usage instantly from psutil without calling PowerShell
            for disk_num, vols in self._cached_volumes.items():
                for v in vols:
                    fb = usage_by_letter.get(v.get("letter"))
                    if fb:
                        v["used_bytes"] = fb["used_bytes"]
                        v["free_bytes"] = fb["free_bytes"]
                        v["used_formatted"] = fb["used_formatted"]
                        v["free_formatted"] = fb["free_formatted"]
                        v["used_percent"] = fb["used_percent"]
                        v["free_percent"] = fb["free_percent"]
            return self._cached_volumes

        by_disk = {}
        for raw in run_powershell_json(_VOLUME_PS, timeout=15):
            letter = (raw.get("DriveLetter") or "").strip().rstrip(':')
            if not letter:
                continue

            total = _as_int(raw.get("Size")) or 0
            remaining = _as_int(raw.get("Remaining")) or 0

            # psutil reports the space actually available to this user, which is
            # what matters; prefer it and fall back to the volume counters.
            fallback = usage_by_letter.get(letter)
            if fallback and fallback["total_bytes"]:
                total = fallback["total_bytes"]
                remaining = fallback["free_bytes"]

            used = max(total - remaining, 0)
            by_disk.setdefault(str(raw.get("DiskNumber", "")).strip(), []).append({
                "letter": letter,
                "label": (raw.get("Label") or "").strip(),
                "filesystem": (raw.get("FileSystem") or "").strip(),
                "total_bytes": total,
                "used_bytes": used,
                "free_bytes": remaining,
                "total_formatted": format_bytes(total),
                "used_formatted": format_bytes(used),
                "free_formatted": format_bytes(remaining),
                "used_percent": round(used / total * 100, 1) if total else 0,
                "free_percent": round(remaining / total * 100, 1) if total else None,
            })

        return by_disk

    def _psutil_volumes(self):
        """Cross-platform capacity read; also the fallback when PowerShell fails."""
        volumes = []
        for part in psutil.disk_partitions(all=False):
            if 'cdrom' in part.opts or not part.mountpoint:
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue

            letter = part.mountpoint.rstrip('\\/').rstrip(':')
            volumes.append({
                "letter": letter,
                "label": "",
                "filesystem": part.fstype,
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "total_formatted": format_bytes(usage.total),
                "used_formatted": format_bytes(usage.used),
                "free_formatted": format_bytes(usage.free),
                "used_percent": round(usage.percent, 1),
                "free_percent": round(100 - usage.percent, 1),
            })
        return volumes

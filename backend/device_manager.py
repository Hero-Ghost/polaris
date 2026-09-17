"""
Polaris - Device and driver inventory.

Two jobs:

  1. Surface devices Windows itself has flagged as broken (the yellow triangles
     in Device Manager), translated from a numeric problem code into an
     explanation and a suggested fix.

  2. Give the BSOD analyser somewhere to point. When a crash names
     `rt640x64.sys`, the user still has no idea what that is. `identify_driver`
     maps a driver file back to the hardware it belongs to and, where possible,
     to the installed driver package and its age.

The file-to-device mapping is deliberately a curated prefix table rather than a
live lookup: `Get-WindowsDriver -Online` needs Administrator and takes tens of
seconds, and Win32_PnPSignedDriver does not expose the .sys filename at all.
The table covers the drivers that actually appear in Windows bugchecks; when a
file is not in it, that is reported honestly instead of guessed at.
"""

import re
from datetime import datetime, timedelta

from backend.win_utils import IS_WINDOWS, run_powershell_json

# A driver older than this on an actively developed component (GPU, network,
# storage) is a common root cause of instability worth mentioning.
STALE_DRIVER_DAYS = 365 * 4

# Device classes where driver age genuinely matters. Age on a keyboard or a
# system timer driver is meaningless - Microsoft ships those once.
AGE_SENSITIVE_CLASSES = {
    'DISPLAY', 'NET', 'SCSIADAPTER', 'HDC', 'USB', 'BLUETOOTH', 'MEDIA', 'SYSTEM',
}

# Windows CM_PROB_* problem codes, limited to the ones a user can act on.
PROBLEM_CODES = {
    1:  ("ההתקן לא הוגדר כראוי", "The device is not configured correctly",
         "התקן מחדש את הדרייבר של ההתקן.", "Reinstall the device driver."),
    3:  ("הדרייבר עלול להיות פגום, או שהמערכת בחוסר משאבים",
         "The driver may be corrupted, or the system is low on resources",
         "התקן מחדש את הדרייבר ובדוק את צריכת הזיכרון.",
         "Reinstall the driver and check memory usage."),
    10: ("ההתקן אינו מצליח להתחיל", "The device cannot start",
         "עדכן את הדרייבר מאתר היצרן. אם ההתקן חיצוני, נסה חיבור אחר.",
         "Update the driver from the vendor. If the device is external, try another port."),
    12: ("ההתקן אינו מוצא מספיק משאבים פנויים",
         "The device cannot find enough free resources",
         "נטרל התקן אחר שאינו בשימוש, או שנה הגדרות משאבים ב-BIOS.",
         "Disable another unused device, or change resource settings in the BIOS."),
    14: ("ההתקן דורש הפעלה מחדש של המחשב", "The device requires a restart",
         "הפעל את המחשב מחדש.", "Restart the computer."),
    18: ("יש להתקין מחדש את הדרייברים של ההתקן",
         "The device drivers need to be reinstalled",
         "הסר את ההתקן מ-Device Manager והפעל מחדש כדי לזהות אותו מחדש.",
         "Remove the device in Device Manager and restart so Windows redetects it."),
    19: ("הרישום מחזיר מידע פגום עבור ההתקן",
         "The registry returned corrupted information for this device",
         "הסר והתקן מחדש את הדרייבר.", "Uninstall and reinstall the driver."),
    22: ("ההתקן מנוטרל", "The device is disabled",
         "הפעל את ההתקן דרך Device Manager.", "Enable the device in Device Manager."),
    24: ("ההתקן אינו נוכח, אינו פועל כראוי, או שחסרים לו דרייברים",
         "The device is not present, not working properly, or missing drivers",
         "בדוק חיבור פיזי והתקן דרייבר מתאים.",
         "Check the physical connection and install a matching driver."),
    28: ("הדרייברים של ההתקן אינם מותקנים",
         "The drivers for this device are not installed",
         "התקן דרייבר מאתר היצרן או דרך Windows Update.",
         "Install a driver from the vendor or via Windows Update."),
    31: ("ההתקן אינו פועל כראוי כיוון שווינדוס לא הצליח לטעון דרייבר",
         "Windows could not load the driver for this device",
         "עדכן את הדרייבר. אם הבעיה נמשכת, הסר את ההתקן והפעל מחדש.",
         "Update the driver. If it persists, remove the device and restart."),
    43: ("ווינדוס עצרה את ההתקן לאחר שדיווח על תקלה",
         "Windows stopped this device because it reported a problem",
         "זהו לרוב כשל חומרה או דרייבר. נסה חיבור אחר, ואם ההתקן פנימי - עדכן דרייבר או בדוק תקינות.",
         "This usually means a hardware or driver fault. Try another port; for internal devices update the driver or test the hardware."),
    45: ("ההתקן אינו מחובר כרגע", "The device is not currently connected",
         "אין תקלה אם ההתקן מנותק בכוונה.", "Not a fault if the device is intentionally disconnected."),
}

# Driver file prefixes seen in real Windows bugchecks, mapped to what they are.
# Ordered longest-first at match time so `nvlddmkm` wins over `nv`.
DRIVER_SIGNATURES = [
    ("nvlddmkm",  "NVIDIA", "כרטיס מסך NVIDIA", "NVIDIA graphics card", "DISPLAY"),
    ("nvoclock",  "NVIDIA", "בקרת ביצועים של NVIDIA", "NVIDIA performance control", "SYSTEM"),
    ("amdkmdag",  "AMD", "כרטיס מסך AMD Radeon", "AMD Radeon graphics card", "DISPLAY"),
    ("amdkmpfd",  "AMD", "כרטיס מסך AMD", "AMD graphics card", "DISPLAY"),
    ("igdkmd",    "Intel", "גרפיקה מובנית של Intel", "Intel integrated graphics", "DISPLAY"),
    ("igdkmdn",   "Intel", "גרפיקה מובנית של Intel", "Intel integrated graphics", "DISPLAY"),
    ("rt640x64",  "Realtek", "כרטיס רשת קווי Realtek", "Realtek wired network adapter", "NET"),
    ("rt630x64",  "Realtek", "כרטיס רשת קווי Realtek", "Realtek wired network adapter", "NET"),
    ("rtwlane",   "Realtek", "כרטיס רשת אלחוטי Realtek", "Realtek wireless adapter", "NET"),
    ("rtwlanu",   "Realtek", "מתאם WiFi USB של Realtek", "Realtek USB WiFi adapter", "NET"),
    ("netwtw",    "Intel", "כרטיס רשת אלחוטי Intel", "Intel wireless adapter", "NET"),
    ("netwbw",    "Intel", "כרטיס רשת אלחוטי Intel", "Intel wireless adapter", "NET"),
    ("e1d",       "Intel", "כרטיס רשת קווי Intel", "Intel wired network adapter", "NET"),
    ("e1r",       "Intel", "כרטיס רשת קווי Intel", "Intel wired network adapter", "NET"),
    ("athw",      "Qualcomm Atheros", "כרטיס רשת אלחוטי Atheros", "Atheros wireless adapter", "NET"),
    ("bcmwl",     "Broadcom", "כרטיס רשת אלחוטי Broadcom", "Broadcom wireless adapter", "NET"),
    ("kfilter",   "Killer", "כרטיס רשת Killer", "Killer network adapter", "NET"),
    ("killer",    "Killer", "כרטיס רשת Killer", "Killer network adapter", "NET"),
    ("ndu",       "Microsoft", "שירות ניטור רשת של Windows", "Windows network data usage monitor", "SYSTEM"),
    ("iastor",    "Intel", "בקר אחסון Intel RST", "Intel Rapid Storage controller", "SCSIADAPTER"),
    ("iastorac",  "Intel", "בקר אחסון Intel RST", "Intel Rapid Storage controller", "SCSIADAPTER"),
    ("stornvme",  "Microsoft", "בקר NVMe", "NVMe storage controller", "SCSIADAPTER"),
    ("storahci",  "Microsoft", "בקר AHCI/SATA", "AHCI/SATA storage controller", "SCSIADAPTER"),
    ("nvme",      "Microsoft", "בקר NVMe", "NVMe storage controller", "SCSIADAPTER"),
    ("usbxhci",   "Microsoft", "בקר USB 3.0", "USB 3.0 host controller", "USB"),
    ("usbhub",    "Microsoft", "רכזת USB", "USB hub", "USB"),
    ("hidclass",  "Microsoft", "התקן קלט (מקלדת/עכבר)", "Input device (keyboard/mouse)", "HIDCLASS"),
    ("rtkvhd",    "Realtek", "כרטיס קול Realtek", "Realtek audio codec", "MEDIA"),
    ("nvhda",     "NVIDIA", "שמע דרך HDMI של NVIDIA", "NVIDIA HDMI audio", "MEDIA"),
    ("atikmdag",  "AMD", "כרטיס מסך AMD", "AMD graphics card", "DISPLAY"),
    ("dxgkrnl",   "Microsoft", "תשתית הגרפיקה של Windows", "Windows graphics kernel", "DISPLAY"),
    ("win32kbase", "Microsoft", "ליבת ממשק המשתמש של Windows", "Windows UI kernel", "SYSTEM"),
    ("win32kfull", "Microsoft", "ליבת ממשק המשתמש של Windows", "Windows UI kernel", "SYSTEM"),
    ("ntoskrnl",  "Microsoft", "ליבת מערכת ההפעלה", "Windows kernel", "SYSTEM"),
    ("ntfs",      "Microsoft", "מערכת הקבצים NTFS", "NTFS file system", "SYSTEM"),
    ("volsnap",   "Microsoft", "צילומי מצב של אמצעי אחסון", "Volume shadow copies", "SYSTEM"),
    ("tcpip",     "Microsoft", "מחסנית הרשת של Windows", "Windows network stack", "NET"),
    ("wdfilter",  "Microsoft", "Microsoft Defender", "Microsoft Defender", "SYSTEM"),
    ("klif",      "Kaspersky", "אנטי-וירוס Kaspersky", "Kaspersky antivirus", "SYSTEM"),
    ("aswsp",     "Avast", "אנטי-וירוס Avast", "Avast antivirus", "SYSTEM"),
    ("bdselfpr",  "Bitdefender", "אנטי-וירוס Bitdefender", "Bitdefender antivirus", "SYSTEM"),
    ("vboxdrv",   "Oracle", "VirtualBox", "VirtualBox", "SYSTEM"),
    ("vmci",      "VMware", "VMware", "VMware", "SYSTEM"),
]

_PROBLEM_DEVICE_PS = """
$devices = Get-PnpDevice -ErrorAction SilentlyContinue |
    Where-Object { $_.Present -and $_.Status -ne 'OK' } |
    ForEach-Object {
        $problem = $null
        try {
            $problem = (Get-PnpDeviceProperty -InstanceId $_.InstanceId `
                        -KeyName 'DEVPKEY_Device_ProblemCode' -ErrorAction Stop).Data
        } catch { }
        [PSCustomObject]@{
            Name        = [string]$_.FriendlyName
            Class       = [string]$_.Class
            Status      = [string]$_.Status
            InstanceId  = [string]$_.InstanceId
            Manufacturer = [string]$_.Manufacturer
            ProblemCode = $problem
        }
    }
if ($devices) { $devices | ConvertTo-Json -Depth 3 -Compress } else { '[]' }
"""

_DRIVER_PS = """
$drivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
    Where-Object { $_.DeviceName -and $_.DriverVersion } |
    ForEach-Object {
        $date = $null
        try { if ($_.DriverDate) { $date = ([datetime]$_.DriverDate).ToString('yyyy-MM-dd') } } catch { }
        [PSCustomObject]@{
            DeviceName    = [string]$_.DeviceName
            DeviceClass   = [string]$_.DeviceClass
            DriverVersion = [string]$_.DriverVersion
            DriverDate    = $date
            Manufacturer  = [string]$_.Manufacturer
            Provider      = [string]$_.DriverProviderName
            InfName       = [string]$_.InfName
        }
    }
if ($drivers) { $drivers | ConvertTo-Json -Depth 3 -Compress } else { '[]' }
"""


def _as_int(value):
    if value is None or value == '':
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


class DeviceManager:
    """Device Manager problems plus a signed-driver inventory."""

    def __init__(self):
        self._driver_cache = None

    # ------------------------------------------------------------------ public

    def get_report(self, force_refresh=False):
        if not IS_WINDOWS:
            return {
                "problem_devices": [], "stale_drivers": [], "driver_count": 0,
                "supported": False, "overall": "unknown",
                "overall_he": "לא נתמך", "overall_en": "Not supported",
            }

        problems = [self._build_problem(raw) for raw in run_powershell_json(_PROBLEM_DEVICE_PS, timeout=30)]
        problems = [p for p in problems if p]

        drivers = self._get_drivers(force_refresh)
        stale = self._find_stale(drivers)

        if problems:
            overall = ("danger", "אותרו התקנים עם תקלה", "Devices reporting a fault")
        elif stale:
            overall = ("warn", "יש דרייברים ישנים", "Outdated drivers present")
        else:
            overall = ("ok", "כל ההתקנים תקינים", "All devices healthy")

        return {
            "problem_devices": problems,
            "stale_drivers": stale,
            "driver_count": len(drivers),
            "supported": True,
            "overall": overall[0], "overall_he": overall[1], "overall_en": overall[2],
        }

    def identify_driver(self, driver_file):
        """
        Explains a driver file named by a bugcheck.

        Returns a dict with what the file belongs to and, when a matching
        installed driver package is found, its version and date. `matched` is
        False when the file is not in the signature table - the caller should
        say so rather than present a guess.
        """
        result = {
            "file": driver_file or "",
            "matched": False,
            "vendor": "",
            "description_he": "",
            "description_en": "",
            "device_class": "",
            "installed": None,
        }
        if not driver_file:
            return result

        stem = re.sub(r'\.(sys|dll|exe)$', '', str(driver_file).strip(), flags=re.I).lower()
        if not stem:
            return result

        # Longest signature first, so nvlddmkm beats nv and iastorac beats iastor.
        for prefix, vendor, desc_he, desc_en, cls in sorted(
                DRIVER_SIGNATURES, key=lambda s: len(s[0]), reverse=True):
            if stem.startswith(prefix):
                result.update({
                    "matched": True, "vendor": vendor,
                    "description_he": desc_he, "description_en": desc_en,
                    "device_class": cls,
                })
                break

        if result["matched"]:
            result["installed"] = self._find_installed_driver(result["vendor"], result["device_class"])

        return result

    # ----------------------------------------------------------------- private

    def _build_problem(self, raw):
        name = (raw.get("Name") or "").strip()
        if not name:
            return None

        code = _as_int(raw.get("ProblemCode"))
        explain = PROBLEM_CODES.get(code)

        if explain:
            desc_he, desc_en, action_he, action_en = explain
        else:
            status = (raw.get("Status") or "Unknown").strip()
            desc_he = f"ווינדוס מדווח על מצב \"{status}\" עבור ההתקן."
            desc_en = f"Windows reports the device state as \"{status}\"."
            action_he = "פתח את Device Manager לפרטים נוספים ונסה לעדכן את הדרייבר."
            action_en = "Open Device Manager for details and try updating the driver."

        status = (raw.get("Status") or "").strip().upper()
        severity = "low" if code == 45 else ("medium" if status == "DEGRADED" else "high")

        return {
            "name": name,
            "device_class": (raw.get("Class") or "").strip(),
            "manufacturer": (raw.get("Manufacturer") or "").strip(),
            "status": (raw.get("Status") or "").strip(),
            "instance_id": (raw.get("InstanceId") or "").strip(),
            "problem_code": code,
            "severity": severity,
            "desc_he": desc_he, "desc_en": desc_en,
            "action_he": action_he, "action_en": action_en,
        }

    def _get_drivers(self, force_refresh=False):
        # Win32_PnPSignedDriver takes several seconds and the inventory does not
        # change while the app is open, so it is queried once per run.
        if self._driver_cache is None or force_refresh:
            self._driver_cache = [self._build_driver(raw)
                                  for raw in run_powershell_json(_DRIVER_PS, timeout=45)]
            self._driver_cache = [d for d in self._driver_cache if d]
        return self._driver_cache

    def _build_driver(self, raw):
        name = (raw.get("DeviceName") or "").strip()
        if not name:
            return None

        date_str = (raw.get("DriverDate") or "").strip()
        age_days = None
        if date_str:
            try:
                age_days = (datetime.now() - datetime.strptime(date_str, "%Y-%m-%d")).days
            except ValueError:
                age_days = None

        return {
            "name": name,
            "device_class": (raw.get("DeviceClass") or "").strip().upper(),
            "version": (raw.get("DriverVersion") or "").strip(),
            "date": date_str,
            "age_days": age_days,
            "age_years": round(age_days / 365.25, 1) if age_days else None,
            "manufacturer": (raw.get("Manufacturer") or "").strip(),
            "provider": (raw.get("Provider") or "").strip(),
            "inf_name": (raw.get("InfName") or "").strip(),
        }

    def _find_stale(self, drivers):
        stale = [
            d for d in drivers
            if d["device_class"] in AGE_SENSITIVE_CLASSES
            and d["age_days"] is not None
            and d["age_days"] >= STALE_DRIVER_DAYS
            # Microsoft's own inbox drivers are dated at release and are not
            # "outdated" in any actionable sense.
            and 'MICROSOFT' not in d["provider"].upper()
        ]
        stale.sort(key=lambda d: d["age_days"], reverse=True)
        return stale[:25]

    def _find_installed_driver(self, vendor, device_class):
        """Best-effort lookup of the installed package for a matched signature."""
        if not vendor:
            return None

        vendor_key = vendor.split()[0].upper()
        for driver in self._get_drivers():
            haystack = f"{driver['provider']} {driver['manufacturer']}".upper()
            if vendor_key in haystack and (not device_class or driver["device_class"] == device_class):
                return driver
        return None

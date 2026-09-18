"""
Polaris - S.M.A.R.T. Database and Health Evaluation.

Adapted from CrystalDiskInfo (hiyohiyo / MIT License):
  - Multilingual attribute definitions (Hebrew & English from Hebrew.lang)
  - NVMe SMART Log Page 0x02 specification
  - SSD vendor attribute mapping (Samsung, WD, Micron, Kingston, Intel, etc.)
  - Health assessment algorithm (CheckDiskStatus)
"""

# ---------------------------------------------------------------------------
# Standard SATA / HDD / SSD S.M.A.R.T. Attribute Dictionary
# ---------------------------------------------------------------------------
SMART_ATTRIBUTES = {
    0x01: {
        "name_he": "קצב שגיאות קריאה",
        "name_en": "Read Error Rate",
        "desc_he": "תדירות שגיאות הקריאה מהמשטח המגנטי/שבבי הפלאש.",
        "desc_en": "Rate of hardware read errors that occurred when reading from the disk surface.",
        "critical": True,
        "ideal": "low",
    },
    0x02: {
        "name_he": "ביצועי תפוקה",
        "name_en": "Throughput Performance",
        "desc_he": "ביצועי תפוקה כלליים של הכונן. ירידה מעידה על בעיה מכנית.",
        "desc_en": "Overall throughput performance of a hard disk drive.",
        "critical": False,
        "ideal": "high",
    },
    0x03: {
        "name_he": "זמן סיבוב (Spin-Up)",
        "name_en": "Spin-Up Time",
        "desc_he": "הזמן הממוצע שלוקח למנוע להגיע למהירות סיבוב מלאה.",
        "desc_en": "Average time of spindle spin up from zero RPM to fully operational.",
        "critical": False,
        "ideal": "low",
    },
    0x04: {
        "name_he": "ספירת הפעלות/כיבויים",
        "name_en": "Start/Stop Count",
        "desc_he": "מספר הפעמים שהמנוע הופעל ונעצר.",
        "desc_en": "Total number of spindle start/stop cycles.",
        "critical": False,
        "ideal": "low",
    },
    0x05: {
        "name_he": "סקטורים שהוקצו מחדש (Reallocated Sectors)",
        "name_en": "Reallocated Sectors Count",
        "desc_he": "סקטורים פגומים שהכונן זיהה והחליף בשטח רזרבי. ערך מעל 0 מעיד על תחילת כשל פיזי.",
        "desc_en": "Number of reallocated sectors. When bad sectors are found, they are remapped to spare area.",
        "critical": True,
        "ideal": "low",
    },
    0x07: {
        "name_he": "קצב שגיאות חיפוש (Seek Error Rate)",
        "name_en": "Seek Error Rate",
        "desc_he": "שגיאות במיקום ראשי הקריאה/כתיבה.",
        "desc_en": "Rate of seek errors of the magnetic heads.",
        "critical": False,
        "ideal": "low",
    },
    0x08: {
        "name_he": "ביצועי זמן חיפוש",
        "name_en": "Seek Time Performance",
        "desc_he": "יעילות פעולות החיפוש המכניות.",
        "desc_en": "Average performance of seek operations.",
        "critical": False,
        "ideal": "high",
    },
    0x09: {
        "name_he": "שעות פעילות מצטברות (Power-On Hours)",
        "name_en": "Power-On Hours",
        "desc_he": "סך השעות שהכונן היה מחובר לחשמל ופעל.",
        "desc_en": "Total count of hours in power-on state.",
        "critical": False,
        "ideal": "low",
    },
    0x0A: {
        "name_he": "ניסיונות סיבוב חוזרים (Spin Retry Count)",
        "name_en": "Spin Retry Count",
        "desc_he": "מספר הניסיונות החוזרים להגיע למהירות עבודה מלאה. מעיד על בעיה במנוע או באספקת חשמל.",
        "desc_en": "Count of physical spin-up attempts when initial attempt failed.",
        "critical": True,
        "ideal": "low",
    },
    0x0B: {
        "name_he": "ניסיונות כיול חוזרים (Recalibration Retries)",
        "name_en": "Recalibration Retries",
        "desc_he": "מספר הפעמים שנדרש כיול מחדש.",
        "desc_en": "Count of recalibrations requested when temperature drift occurred.",
        "critical": False,
        "ideal": "low",
    },
    0x0C: {
        "name_he": "מחזורי הפעלה (Power Cycles)",
        "name_en": "Power Cycle Count",
        "desc_he": "מספר הפעמים שהכונן הודלק ונכבה.",
        "desc_en": "Count of full hard power on/off cycles.",
        "critical": False,
        "ideal": "low",
    },
    0xAA: {
        "name_he": "בלוקים רזרביים שנותרו",
        "name_en": "Available Reserved Blocks",
        "desc_he": "אחוז או כמות הבלוקים הרזרביים שנשארו ב-SSD להחלפת תאים שחוקים.",
        "desc_en": "Available reserved blocks remaining on the SSD.",
        "critical": True,
        "ideal": "high",
    },
    0xAB: {
        "name_he": "ספירת שגיאות תוכנה/כתיבה",
        "name_en": "Program Fail Count",
        "desc_he": "מספר הניסיונות שנכשלו בכתיבת נתונים לתאי פלאש.",
        "desc_en": "Total count of flash program failures.",
        "critical": True,
        "ideal": "low",
    },
    0xAC: {
        "name_he": "ספירת שגיאות מחיקה (Erase Fail Count)",
        "name_en": "Erase Fail Count",
        "desc_he": "מספר הפעמים שנכשלה מחיקת בלוק פלאש.",
        "desc_en": "Total count of flash erase block failures.",
        "critical": True,
        "ideal": "low",
    },
    0xAD: {
        "name_he": "ספירת שחיקת בלוקים ממוצעת",
        "name_en": "Average Wear / Erase Count",
        "desc_he": "מספר מחזורי המחיקה והכתיבה הממוצעים לכל בלוק פלאש.",
        "desc_en": "Average erase count across all flash memory blocks.",
        "critical": False,
        "ideal": "low",
    },
    0xAE: {
        "name_he": "כיבויים פתאומיים (Unexpected Power Loss)",
        "name_en": "Unexpected Power Loss Count",
        "desc_he": "מספר הפעמים שנותק החשמל לכונן ללא איתות כיבוי מסודר מ-Windows.",
        "desc_en": "Number of times power was shut off without a clean shutdown command.",
        "critical": False,
        "ideal": "low",
    },
    0xAF: {
        "name_he": "שגיאות תיקון ECC בתוכנה",
        "name_en": "Program Fail Count (Chip)",
        "desc_he": "כשלים בכתיבה לשבב הפלאש.",
        "desc_en": "Program failure count at the chip level.",
        "critical": True,
        "ideal": "low",
    },
    0xB1: {
        "name_he": "ספירת שחיקה (Wear Leveling Count)",
        "name_en": "Wear Leveling Count",
        "desc_he": "מדד שחיקת ה-SSD (בכונני Samsung/WD - ערך נוכחי מייצג לרוב את אחוז החיים הנותר).",
        "desc_en": "Wear Leveling Count. In Samsung/WD SSDs, normalized value indicates life remaining.",
        "critical": False,
        "ideal": "high",
    },
    0xB7: {
        "name_he": "ספירת האטה בגלל מתח (SATA Downshift)",
        "name_en": "SATA Interface Downshift Count",
        "desc_he": "פעמים שהכונן נאלץ להוריד מהירות SATA בגלל הפרעות בכבל.",
        "desc_en": "SATA interface speed downshift count due to cable/signal noise.",
        "critical": False,
        "ideal": "low",
    },
    0xB8: {
        "name_he": "שגיאות בנתיב הנתונים מקצה לקצה (End-to-End Error)",
        "name_en": "End-to-End Error",
        "desc_he": "זיהוי שגיאות נתונים בין המטמון של הכונן לבקר.",
        "desc_en": "Data parity errors between the drive buffer and the controller.",
        "critical": True,
        "ideal": "low",
    },
    0xBB: {
        "name_he": "שגיאות בלתי ניתנות לתיקון (Reported Uncorrectable)",
        "name_en": "Reported Uncorrectable Errors",
        "desc_he": "שגיאות קריאה שלא ניתן היה לתקן באמצעות קוד תיקון השגיאות (ECC).",
        "desc_en": "Count of errors that could not be recovered using hardware ECC.",
        "critical": True,
        "ideal": "low",
    },
    0xBC: {
        "name_he": "פסקי זמן לפקודות (Command Timeout)",
        "name_en": "Command Timeout",
        "desc_he": "פקודות שהופסקו עקב חוסר מענה מהכונן (מעיד על כבל פגום או קפיאת בקר).",
        "desc_en": "Number of aborted operations due to drive timeout.",
        "critical": False,
        "ideal": "low",
    },
    0xBE: {
        "name_he": "טמפרטורת זרימת אוויר",
        "name_en": "Airflow Temperature",
        "desc_he": "טמפרטורת האוויר בתוך הכונן.",
        "desc_en": "Airflow temperature inside the drive.",
        "critical": False,
        "ideal": "low",
    },
    0xC2: {
        "name_he": "טמפרטורה (Temperature)",
        "name_en": "Temperature",
        "desc_he": "טמפרטורת העבודה הנוכחית של הכונן במעלות צלזיוס.",
        "desc_en": "Current internal temperature of the drive.",
        "critical": False,
        "ideal": "low",
    },
    0xC4: {
        "name_he": "אירועי הקצאה מחדש (Reallocation Event Count)",
        "name_en": "Reallocation Event Count",
        "desc_he": "מספר הניסיונות (המוצלחים והכושלים) להעביר נתונים מסקטורים פגומים.",
        "desc_en": "Count of remap operations transferring data from damaged sectors.",
        "critical": True,
        "ideal": "low",
    },
    0xC5: {
        "name_he": "סקטורים פגומים בהמתנה (Current Pending Sector)",
        "name_en": "Current Pending Sector Count",
        "desc_he": "סקטורים לא יציבים הממתינים לכתיבה חוזרת כדי להיבדק שוב. מעיד על סיכון קרוב לאובדן קבצים.",
        "desc_en": "Count of unstable sectors waiting to be remapped upon write.",
        "critical": True,
        "ideal": "low",
    },
    0xC6: {
        "name_he": "סקטורים בלתי ניתנים לתיקון (Offline Uncorrectable)",
        "name_en": "Off-Line Scan Uncorrectable Sector Count",
        "desc_he": "סקטורים פגומים לחלוטין שלא ניתן היה לקרוא או לתקן בסריקה עצמית.",
        "desc_en": "Uncorrectable sectors found during background/offline scanning.",
        "critical": True,
        "ideal": "low",
    },
    0xC7: {
        "name_he": "שגיאות תקשורת כבל (UltraDMA CRC Error Count)",
        "name_en": "UltraDMA CRC Error Count",
        "desc_he": "שגיאות בשידור נתונים בין לוח האם לכונן. נגרם ב-99% מכבל SATA רופף או פגום.",
        "desc_en": "CRC errors during data transfer. Usually caused by a damaged or loose SATA cable.",
        "critical": False,
        "ideal": "low",
    },
    0xE7: {
        "name_he": "אחוז חיי SSD נותרים (SSD Life Left)",
        "name_en": "SSD Life Left / Remaining",
        "desc_he": "הערכת תוחלת החיים הנותרת של שבבי הפלאש (0-100%).",
        "desc_en": "Estimated remaining endurance life of the SSD flash memory (0-100%).",
        "critical": True,
        "ideal": "high",
    },
    0xF1: {
        "name_he": "סך כתיבות מצטבר (Total Host Writes / TBW)",
        "name_en": "Total Host Writes (LBA)",
        "desc_he": "סך כמות הנתונים שנכתבו לכונן מאז ייצורו (בסקטורים או ב-GB).",
        "desc_en": "Total sectors or gigabytes written to the drive across its lifetime.",
        "critical": False,
        "ideal": "low",
    },
    0xF2: {
        "name_he": "סך קריאות מצטבר (Total Host Reads)",
        "name_en": "Total Host Reads (LBA)",
        "desc_he": "סך כמות הנתונים שנקראו מהכונן מאז ייצורו.",
        "desc_en": "Total sectors or gigabytes read from the drive across its lifetime.",
        "critical": False,
        "ideal": "low",
    },
}

# ---------------------------------------------------------------------------
# NVMe SMART Specification Log Page 0x02 Fields
# ---------------------------------------------------------------------------
NVME_LOG_FIELDS = {
    "critical_warning": {
        "id": 1,
        "name_he": "התרעה קריטית (Critical Warning)",
        "name_en": "Critical Warning",
        "desc_he": "דגלי אזהרת חומרה: 0=תקין. ביטים מסמנים: ירידה בספייר, חום קיצוני, מצב קריאה בלבד.",
        "desc_en": "Hardware warning flags: 0=Normal. Bits indicate low spare, extreme temp, or read-only.",
        "critical": True,
    },
    "temperature": {
        "id": 2,
        "name_he": "טמפרטורת עבודה (Temperature)",
        "name_en": "Composite Temperature",
        "desc_he": "טמפרטורת בקר הכונן ושבבי הפלאש.",
        "desc_en": "Current overall controller and flash temperature.",
        "critical": False,
    },
    "available_spare": {
        "id": 3,
        "name_he": "יתרת בלוקים רזרביים (Available Spare)",
        "name_en": "Available Spare",
        "desc_he": "אחוז השטח הרזרבי הנותר ב-SSD להחלפת תאים פגומים.",
        "desc_en": "Percentage of remaining spare flash memory blocks.",
        "critical": True,
    },
    "available_spare_threshold": {
        "id": 4,
        "name_he": "סף ספייר מינימלי (Available Spare Threshold)",
        "name_en": "Available Spare Threshold",
        "desc_he": "כאשר יתרת הספייר יורדת מתחת לסף זה, הכונן בסכנת כשל מיידית.",
        "desc_en": "When available spare drops below this threshold, reliability is critically degraded.",
        "critical": True,
    },
    "percentage_used": {
        "id": 5,
        "name_he": "אחוז ניצול בלאי (Percentage Used)",
        "name_en": "Percentage Used",
        "desc_he": "הערכת היצרן לאחוז השחיקה של הכונן. 0%=חדש, 100%=הגיע לתוחלת החיים המובטחת.",
        "desc_en": "Vendor estimate of SSD life consumed (0% = new, 100% = rated endurance reached).",
        "critical": True,
    },
    "data_units_read": {
        "id": 6,
        "name_he": "סך נתונים שנקראו (Data Units Read)",
        "name_en": "Data Units Read",
        "desc_he": "כמות הנתונים הכוללת שנקראה מהכונן מאז חיבורו הראשון.",
        "desc_en": "Total volume of data read from the controller (1 unit = 512,000 bytes).",
        "critical": False,
    },
    "data_units_written": {
        "id": 7,
        "name_he": "סך נתונים שנכתבו (Data Units Written / TBW)",
        "name_en": "Data Units Written",
        "desc_he": "סך כמות הנתונים שנכתבו לכונן במחזור חייו (TBW).",
        "desc_en": "Total volume of data written to the drive (TBW).",
        "critical": False,
    },
    "host_read_commands": {
        "id": 8,
        "name_he": "פקודות קריאה (Host Read Commands)",
        "name_en": "Host Read Commands",
        "desc_he": "מספר פקודות הקריאה שנשלחו לכונן על ידי מערכת ההפעלה.",
        "desc_en": "Total number of read commands processed by the controller.",
        "critical": False,
    },
    "host_write_commands": {
        "id": 9,
        "name_he": "פקודות כתיבה (Host Write Commands)",
        "name_en": "Host Write Commands",
        "desc_he": "מספר פקודות הכתיבה שנשלחו לכונן על ידי מערכת ההפעלה.",
        "desc_en": "Total number of write commands processed by the controller.",
        "critical": False,
    },
    "controller_busy_time": {
        "id": 10,
        "name_he": "זמן פעילות הבקר (Controller Busy Time)",
        "name_en": "Controller Busy Time",
        "desc_he": "משך הזמן (בדקות) שבו הבקר היה עסוק בביצוע פקודות I/O.",
        "desc_en": "Amount of time the controller was busy processing commands (in minutes).",
        "critical": False,
    },
    "power_cycles": {
        "id": 11,
        "name_he": "מחזורי הפעלה (Power Cycles)",
        "name_en": "Power Cycles",
        "desc_he": "מספר הפעמים שהכונן קיבל מתח והופעל.",
        "desc_en": "Number of power-on cycles.",
        "critical": False,
    },
    "power_on_hours": {
        "id": 12,
        "name_he": "שעות פעילות מצטברות (Power-On Hours)",
        "name_en": "Power-On Hours",
        "desc_he": "סך כל השעות שהכונן היה דלוק.",
        "desc_en": "Total operational power-on hours.",
        "critical": False,
    },
    "unsafe_shutdowns": {
        "id": 13,
        "name_he": "כיבויים פתאומיים (Unsafe Shutdowns)",
        "name_en": "Unsafe Shutdowns",
        "desc_he": "מספר הפעמים שהכונן כבה ללא פקודת כיבוי מסודרת (קריסות, ניתוק חשמל, BSOD).",
        "desc_en": "Number of shutdowns where power was cut off without a flush notification.",
        "critical": False,
    },
    "media_errors": {
        "id": 14,
        "name_he": "שגיאות שלמות נתונים ומדיה (Media & Data Integrity Errors)",
        "name_en": "Media & Data Integrity Errors",
        "desc_he": "מספר המקרים שבהם התגלתה שגיאת שלמות נתונים שלא תוקנה. ערך מעל 0 מחייב גיבוי מיידי.",
        "desc_en": "Number of occurrences where the controller detected unrecovered data integrity errors.",
        "critical": True,
    },
    "error_log_entries": {
        "id": 15,
        "name_he": "רשומות ביומן השגיאות (Error Log Entries)",
        "name_en": "Number of Error Information Log Entries",
        "desc_he": "מספר השגיאות שנרשמו ביומן התקלות הפנימי של הכונן.",
        "desc_en": "Total number of error information log entries across life of the drive.",
        "critical": False,
    },
}


# ---------------------------------------------------------------------------
# SSD Vendor Detection & Health Life Attribute Mapping
# ---------------------------------------------------------------------------
SSD_VENDORS = {
    "SAMSUNG": ["samsung", "pm981", "pm991", "pm9a1", "970 evo", "980 pro", "990 pro", "860 evo", "870 evo"],
    "WD_SANDISK": ["wdc", "western digital", "sandisk", "sn720", "sn750", "sn850", "sn550", "sn570", "sn770", "blue", "black"],
    "CRUCIAL_MICRON": ["crucial", "micron", "bx500", "mx500", "p1", "p2", "p3", "p5", "t500", "t700"],
    "KINGSTON": ["kingston", "a400", "kc600", "kc3000", "fury", "nv1", "nv2"],
    "INTEL": ["intel", "ssdpek", "ssdpe2", "optane", "660p", "670p"],
    "SK_HYNIX": ["sk hynix", "hynix", "gold p31", "platinum p41", "bc711", "bc511"],
    "KIOXIA_TOSHIBA": ["kioxia", "toshiba", "exceria", "bg4", "bg5", "xg6"],
    "SILICON_MOTION": ["sm2258", "sm2259", "sm2262", "sm2263", "sm2267", "smi"],
    "PHISON": ["phison", "ps5012", "ps5016", "ps5018"],
    "REALTEK": ["realtek", "rts5762", "rts5763", "rts5765"],
}


def detect_ssd_vendor(model_str):
    """Identifies the SSD vendor based on the model string."""
    if not model_str:
        return "GENERIC"
    m_lower = model_str.lower()
    for vendor, patterns in SSD_VENDORS.items():
        if any(p in m_lower for p in patterns):
            return vendor
    return "GENERIC"


# ---------------------------------------------------------------------------
# Health Assessment Engine (CrystalDiskInfo CheckDiskStatus adaptation)
# ---------------------------------------------------------------------------
def evaluate_disk_health(disk_info):
    """
    Evaluates physical drive condition based on CrystalDiskInfo's CheckDiskStatus logic.

    Returns:
      {
        "status": "Good" | "Caution" | "Bad" | "Unknown",
        "tone": "success" | "warn" | "danger" | "unknown",
        "status_he": "תקין" | "אזהרה" | "סכנה" | "לא ידוע",
        "status_en": "Good" | "Caution" | "Bad" | "Unknown",
        "life_remaining_percent": int (0-100) or None,
        "reasons_he": list[str],
        "reasons_en": list[str],
      }
    """
    is_nvme = disk_info.get("is_nvme", False) or disk_info.get("bus_type", "").upper() == "NVME"
    media_type = (disk_info.get("media_type") or "").upper()
    is_ssd = is_nvme or media_type == "SSD"

    reasons_he = []
    reasons_en = []
    status = "Good"
    tone = "success"

    # --- 1. NVMe Evaluation ---
    if is_nvme:
        crit_warning = disk_info.get("critical_warning", 0) or 0
        avail_spare = disk_info.get("available_spare")
        spare_thresh = disk_info.get("available_spare_threshold")
        pct_used = disk_info.get("wear_percent")
        media_errors = disk_info.get("media_errors", 0) or 0

        # Critical Warning byte flags
        if crit_warning > 0:
            status = "Bad"
            tone = "danger"
            if crit_warning & 0x01:
                reasons_he.append("יתרת הבלוקים הרזרביים ירדה מתחת לסף הקריטי")
                reasons_en.append("Available spare has fallen below critical threshold")
            if crit_warning & 0x02:
                reasons_he.append("טמפרטורת הכונן חרגה מעבר לסף הבטיחות של היצרן")
                reasons_en.append("Drive temperature exceeded critical threshold")
            if crit_warning & 0x04:
                reasons_he.append("אמינות הכונן נפגעה בצורה חמורה עקב שגיאות מדיה")
                reasons_en.append("Drive reliability severely degraded due to media errors")
            if crit_warning & 0x08:
                reasons_he.append("הכונן הועבר למצב קריאה בלבד (Read-Only) כדי למנוע אובדן נתונים")
                reasons_en.append("Drive media placed in read-only mode")
            if crit_warning & 0x10:
                reasons_he.append("התקן הגיבוי של זיכרון המטמון (Volatile Backup) כשל")
                reasons_en.append("Volatile memory backup device has failed")

        # Spare blocks comparison
        if avail_spare is not None and spare_thresh is not None:
            if avail_spare < spare_thresh:
                status = "Bad"
                tone = "danger"
                reasons_he.append(f"יתרת בלוקים רזרביים ({avail_spare}%) נמוכה מסף היצרן ({spare_thresh}%)")
                reasons_en.append(f"Available spare ({avail_spare}%) below threshold ({spare_thresh}%)")
            elif avail_spare == spare_thresh and spare_thresh != 100:
                if status != "Bad":
                    status = "Caution"
                    tone = "warn"
                    reasons_he.append(f"יתרת בלוקים רזרביים הגיעה לסף האזהרה ({avail_spare}%)")
                    reasons_en.append(f"Available spare reached threshold ({avail_spare}%)")

        # Media and Data Integrity Errors
        if media_errors > 0:
            if status != "Bad":
                status = "Caution"
                tone = "warn"
            reasons_he.append(f"זוהו {media_errors:,} שגיאות שלמות מדיה שלא ניתנו לתיקון")
            reasons_en.append(f"Detected {media_errors:,} unrecovered media integrity errors")

        # Percentage Used (Endurance life)
        life_remaining = None
        if pct_used is not None:
            life_remaining = max(0, min(100, 100 - pct_used))
            if pct_used >= 100:
                if status != "Bad":
                    status = "Caution"
                    tone = "warn"
                reasons_he.append("הכונן הגיע ל-100% שחיקה מתוחלת החיים המובטחת (TBW)")
                reasons_en.append("Drive reached 100% of rated endurance life (TBW)")
            elif pct_used >= 90:
                if status == "Good":
                    status = "Caution"
                    tone = "warn"
                reasons_he.append(f"בלאי גבוה: נוצלו {pct_used}% מתוחלת החיים (נותרו {life_remaining}%)")
                reasons_en.append(f"High wear: {pct_used}% consumed ({life_remaining}% remaining)")

        # Temperature check
        temp = disk_info.get("temperature_c")
        if temp is not None:
            if temp >= 75:
                if status != "Bad":
                    status = "Caution"
                    tone = "warn"
                reasons_he.append(f"טמפרטורה גבוהה מאוד ({temp}°C) - יש לבדוק קירור במארז")
                reasons_en.append(f"Very high temperature ({temp}°C) - check chassis airflow")
            elif temp >= 65 and status == "Good":
                reasons_he.append(f"טמפרטורה חמה ({temp}°C)")
                reasons_en.append(f"Warm temperature ({temp}°C)")

    # --- 2. SATA / HDD / SSD Attributes Evaluation ---
    else:
        attrs = disk_info.get("attributes_map", {})
        reallocated = attrs.get(0x05, {}).get("raw_value", 0)
        pending = attrs.get(0xC5, {}).get("raw_value", 0)
        uncorrectable = attrs.get(0xC6, {}).get("raw_value", 0)
        crc_errors = attrs.get(0xC7, {}).get("raw_value", 0)
        reported_uncorr = attrs.get(0xBB, {}).get("raw_value", 0)

        # Check critical failing sector attributes
        if reallocated > 0 or pending > 0 or uncorrectable > 0 or reported_uncorr > 0:
            if pending > 0 or uncorrectable > 0 or reallocated >= 10:
                status = "Bad"
                tone = "danger"
            else:
                status = "Caution"
                tone = "warn"

            if reallocated > 0:
                reasons_he.append(f"{reallocated} סקטורים פגומים הוקצו מחדש (Reallocated)")
                reasons_en.append(f"{reallocated} reallocated bad sectors")
            if pending > 0:
                reasons_he.append(f"{pending} סקטורים פגומים בהמתנה (Current Pending)")
                reasons_en.append(f"{pending} unstable pending sectors")
            if uncorrectable > 0:
                reasons_he.append(f"{uncorrectable} סקטורים שלא ניתנים לתיקון (Offline Uncorrectable)")
                reasons_en.append(f"{uncorrectable} uncorrectable sectors")
            if reported_uncorr > 0:
                reasons_he.append(f"{reported_uncorr} שגיאות קריאה שלא תוקנו")
                reasons_en.append(f"{reported_uncorr} uncorrected read errors")

        # CRC Errors (SATA cable warning)
        if crc_errors > 0 and status == "Good":
            reasons_he.append(f"זוהו {crc_errors} שגיאות תקשורת CRC (כדאי לבדוק/להחליף כבל SATA)")
            reasons_en.append(f"{crc_errors} UltraDMA CRC communication errors (check SATA cable)")

        # SSD Life Left
        life_attr = attrs.get(0xE7) or attrs.get(0xB1) or attrs.get(0xA9) or attrs.get(0xCA)
        life_remaining = None
        if life_attr:
            val = life_attr.get("current_value")
            if val is not None and 0 <= val <= 100:
                life_remaining = val
                if life_remaining <= 10:
                    if status != "Bad":
                        status = "Caution"
                        tone = "warn"
                    reasons_he.append(f"נותרו {life_remaining}% בלבד מתוחלת חיי ה-SSD")
                    reasons_en.append(f"Only {life_remaining}% SSD life remaining")

        temp = disk_info.get("temperature_c") or (attrs.get(0xC2, {}).get("raw_value", 0) & 0xFF)
        if temp and temp >= 60:
            if temp >= 68 and status != "Bad":
                status = "Caution"
                tone = "warn"
            reasons_he.append(f"טמפרטורת כונן גבוהה ({temp}°C)")
            reasons_en.append(f"High drive temperature ({temp}°C)")

    # Fallback status strings
    status_map_he = {"Good": "תקין", "Caution": "אזהרה", "Bad": "סכנה", "Unknown": "לא ידוע"}
    status_map_en = {"Good": "Good", "Caution": "Caution", "Bad": "Bad", "Unknown": "Unknown"}

    return {
        "status": status,
        "tone": tone,
        "status_he": status_map_he.get(status, "לא ידוע"),
        "status_en": status_map_en.get(status, "Unknown"),
        "life_remaining_percent": life_remaining,
        "reasons_he": reasons_he,
        "reasons_en": reasons_en,
    }

"""
Polaris - Recurring system error analysis.

The crash analyser answers "why did my PC blue-screen". This module answers the
question that comes before it: "something is wrong but the PC still boots".

Windows records those symptoms as Error and Critical entries in the System and
Application logs, but Event Viewer presents them as an undifferentiated wall of
thousands of rows, most of which are permanent harmless noise (DistributedCOM
10016 in particular fires constantly on a perfectly healthy machine).

So the raw log is grouped by (provider, event id), ranked by how often each
group recurs, and matched against a knowledge table that says - in plain
Hebrew - what the entry means, whether it matters, and what to do. Anything
recognised as background noise is tagged so the UI can hide it by default.
"""

from datetime import datetime

from backend.win_utils import IS_WINDOWS, run_powershell_json

DEFAULT_DAYS = 7
MAX_EVENTS = 1200

# (provider fragment, event id) -> explanation.
# `noise` marks entries that fire on healthy systems and mean nothing to a user.
EVENT_KNOWLEDGE = {
    ('disk', 7): {
        "severity": "high", "category": "storage",
        "title_he": "בלוק פגום בכונן",
        "title_en": "Bad block on a drive",
        "desc_he": "ווינדוס נתקלה בבלוק שאינו ניתן לקריאה. זהו סימן מובהק לכונן שמתחיל להיכשל.",
        "desc_en": "Windows hit an unreadable block. This is a strong indicator of a failing drive.",
        "action_he": "גבה מיד, ובדוק את מסך בריאות הכוננים.",
        "action_en": "Back up immediately and check the drive health screen.",
    },
    ('disk', 11): {
        "severity": "high", "category": "storage",
        "title_he": "שגיאת בקר בכונן",
        "title_en": "Drive controller error",
        "desc_he": "הבקר דיווח על שגיאה בגישה לכונן. הגורמים הם כבל SATA פגום, חיבור רופף או כונן שמתדרדר.",
        "desc_en": "The controller reported an error accessing the drive. Common causes are a faulty SATA cable, a loose connection, or a degrading drive.",
        "action_he": "בדוק חיבורים פיזיים, ואם השגיאה חוזרת - החלף כבל או כונן.",
        "action_en": "Check physical connections; if it recurs, replace the cable or the drive.",
    },
    ('disk', 51): {
        "severity": "medium", "category": "storage",
        "title_he": "שגיאת עימוד בגישה לכונן",
        "title_en": "Paging error while accessing a drive",
        "desc_he": "פעולת קריאה או כתיבה נכשלה וחזרה על עצמה. לעיתים חד-פעמי, אך חזרתיות מצביעה על בעיה.",
        "desc_en": "A read or write operation failed and was retried. Occasionally harmless, but repetition points to a real problem.",
        "action_he": "אם זה חוזר מדי יום, בדוק את בריאות הכונן.",
        "action_en": "If this recurs daily, check drive health.",
    },
    ('ntfs', 55): {
        "severity": "high", "category": "storage",
        "title_he": "פגיעה במבנה מערכת הקבצים",
        "title_en": "File system structure corruption",
        "desc_he": "NTFS זיהתה פגיעה במבנה הנתונים של הכונן.",
        "desc_en": "NTFS detected corruption in the volume's data structures.",
        "action_he": "הרץ chkdsk על הכונן המדובר, ולאחר מכן SFC במסך התחזוקה.",
        "action_en": "Run chkdsk on the affected volume, then SFC from the maintenance screen.",
    },
    ('ntfs', 137): {
        "severity": "medium", "category": "storage",
        "title_he": "כשל בכתיבת יומן העסקאות של NTFS",
        "title_en": "NTFS transaction log write failure",
        "desc_he": "מערכת הקבצים לא הצליחה לרשום פעולה ליומן. לרוב מלווה בעומס כבד על הכונן.",
        "desc_en": "The file system could not flush an operation to its log, usually alongside heavy drive load.",
        "action_he": "בדוק מקום פנוי ובריאות הכונן.",
        "action_en": "Check free space and drive health.",
    },
    ('service control manager', 7000): {
        "severity": "medium", "category": "services",
        "title_he": "שירות נכשל בהפעלה",
        "title_en": "A service failed to start",
        "desc_he": "שירות Windows לא הצליח לעלות. אם זה שירות של תוכנה שהוסרה, זו שארית לא מזיקה.",
        "desc_en": "A Windows service failed to start. If it belongs to uninstalled software, it is a harmless leftover.",
        "action_he": "בדוק בהודעה איזה שירות מדובר. אם התוכנה כבר לא מותקנת, אפשר להתעלם.",
        "action_en": "Check which service the message names. If the software is gone, this can be ignored.",
    },
    ('service control manager', 7009): {
        "severity": "medium", "category": "services",
        "title_he": "פסק זמן בהמתנה לשירות",
        "title_en": "Timed out waiting for a service",
        "desc_he": "שירות לא הגיב בזמן ההפעלה. מאט את זמן האתחול.",
        "desc_en": "A service did not respond in time during startup, which slows boot.",
        "action_he": "אם זה חוזר, שקול לנטרל את השירות אם אינו נחוץ.",
        "action_en": "If it recurs, consider disabling the service if it is not needed.",
    },
    ('service control manager', 7031): {
        "severity": "medium", "category": "services",
        "title_he": "שירות הסתיים באופן בלתי צפוי",
        "title_en": "A service terminated unexpectedly",
        "desc_he": "שירות קרס וווינדוס הפעילה אותו מחדש. חזרתיות מצביעה על תוכנה לא יציבה.",
        "desc_en": "A service crashed and Windows restarted it. Repetition indicates unstable software.",
        "action_he": "אם זה שירות של תוכנה מסוימת, שקול להתקין אותה מחדש או לעדכן.",
        "action_en": "If it belongs to a specific application, consider reinstalling or updating it.",
    },
    ('service control manager', 7034): {
        "severity": "medium", "category": "services",
        "title_he": "שירות קרס ללא התאוששות",
        "title_en": "A service crashed without recovery",
        "desc_he": "שירות הסתיים באופן בלתי צפוי ולא הופעל מחדש.",
        "desc_en": "A service terminated unexpectedly and was not restarted.",
        "action_he": "בדוק את התוכנה שאליה שייך השירות.",
        "action_en": "Investigate the application the service belongs to.",
    },
    ('application error', 1000): {
        "severity": "medium", "category": "apps",
        "title_he": "קריסת תוכנה",
        "title_en": "Application crash",
        "desc_he": "תוכנה קרסה. אם זו אותה תוכנה שוב ושוב, הבעיה בה ולא במערכת.",
        "desc_en": "An application crashed. If it is always the same one, the problem is in that app rather than the system.",
        "action_he": "עדכן או התקן מחדש את התוכנה. אם מדובר בתוכנות שונות - בדוק זיכרון ודרייברים.",
        "action_en": "Update or reinstall the application. If many different apps crash, check memory and drivers.",
    },
    ('application hang', 1002): {
        "severity": "low", "category": "apps",
        "title_he": "תוכנה הפסיקה להגיב",
        "title_en": "An application stopped responding",
        "desc_he": "תוכנה נתקעה והמשתמש או ווינדוס סגרו אותה.",
        "desc_en": "An application hung and was closed by the user or by Windows.",
        "action_he": "לרוב מקומי לתוכנה. אם זה קורה להרבה תוכנות, בדוק עומס זיכרון ודיסק.",
        "action_en": "Usually specific to that app. If it happens across many apps, check memory and disk load.",
    },
    ('.net runtime', 1026): {
        "severity": "low", "category": "apps",
        "title_he": "חריגה לא מטופלת בתוכנת .NET",
        "title_en": "Unhandled exception in a .NET application",
        "desc_he": "תוכנה מבוססת .NET קרסה עקב שגיאה בקוד שלה.",
        "desc_en": "A .NET application crashed due to an error in its own code.",
        "action_he": "עדכן את התוכנה. אין כאן תקלה במערכת ההפעלה.",
        "action_en": "Update the application. This is not an operating system fault.",
    },
    ('distributedcom', 10016): {
        "severity": "low", "category": "noise", "noise": True,
        "title_he": "הרשאות DCOM (רעש מוכר)",
        "title_en": "DCOM permissions (known noise)",
        "desc_he": "רכיב פנימי של ווינדוס ביקש הרשאה שאין לו. מיקרוסופט מגדירה זאת רשמית כלא מזיק, "
                   "וזה מופיע בכל מחשב Windows תקין.",
        "desc_en": "An internal Windows component requested a permission it lacks. Microsoft officially "
                   "classifies this as harmless; it appears on every healthy Windows machine.",
        "action_he": "אין צורך בפעולה. אפשר להתעלם.",
        "action_en": "No action needed. Safe to ignore.",
    },
    ('devicesetupmanager', 131): {
        "severity": "low", "category": "noise", "noise": True,
        "title_he": "כשל בגישה לשרת המטא-דאטה של התקנים (רעש מוכר)",
        "title_en": "Device metadata server unreachable (known noise)",
        "desc_he": "ווינדוס ניסתה להוריד מידע תיאורי על התקן ולא הצליחה. אינו משפיע על תפקוד ההתקן.",
        "desc_en": "Windows tried to download descriptive device metadata and failed. It does not affect how the device works.",
        "action_he": "אין צורך בפעולה.",
        "action_en": "No action needed.",
    },
    ('kernel-eventtracing', 2): {
        "severity": "low", "category": "noise", "noise": True,
        "title_he": "כשל בהפעלת מפגש מעקב (רעש מוכר)",
        "title_en": "Trace session failed to start (known noise)",
        "desc_he": "מנגנון האבחון הפנימי של ווינדוס לא הצליח לפתוח מפגש רישום.",
        "desc_en": "Windows' internal diagnostics could not open a logging session.",
        "action_he": "אין צורך בפעולה.",
        "action_en": "No action needed.",
    },
    ('schannel', 36871): {
        "severity": "low", "category": "network",
        "title_he": "כשל ביצירת ערוץ מאובטח (TLS)",
        "title_en": "Failed to create a secure TLS channel",
        "desc_he": "תוכנה ניסתה ליצור חיבור מוצפן ונכשלה במשא ומתן על גרסת ההצפנה.",
        "desc_en": "An application tried to open an encrypted connection and failed the TLS negotiation.",
        "action_he": "לרוב תוכנה ישנה שדורשת פרוטוקול מיושן. עדכן אותה.",
        "action_en": "Usually old software requesting an obsolete protocol. Update it.",
    },
    ('volmgr', 46): {
        "severity": "medium", "category": "storage",
        "title_he": "כשל באתחול קובץ ה-Dump",
        "title_en": "Crash dump file initialization failed",
        "desc_he": "ווינדוס לא הצליחה להכין את קובץ הדיווח לקריסות. אם יקרה מסך כחול, לא יישמר מידע לניתוח.",
        "desc_en": "Windows could not prepare the crash dump file. If a blue screen occurs, no diagnostic data will be saved.",
        "action_he": "ודא שקובץ ההחלפה (pagefile) מופעל על כונן המערכת.",
        "action_en": "Make sure the pagefile is enabled on the system drive.",
    },
    ('eventlog', 6008): {
        "severity": "medium", "category": "power",
        "title_he": "כיבוי לא צפוי",
        "title_en": "Unexpected shutdown",
        "desc_he": "המחשב כובה מבלי שווינדוס ביצעה סדר כיבוי תקין.",
        "desc_en": "The PC powered off without Windows completing a clean shutdown.",
        "action_he": "פירוט מלא נמצא במסך הקריסות.",
        "action_en": "Full detail is on the crashes screen.",
    },
}

CATEGORY_LABELS = {
    "storage": ("אחסון", "Storage"),
    "services": ("שירותים", "Services"),
    "apps": ("תוכנות", "Applications"),
    "network": ("רשת", "Network"),
    "power": ("חשמל ואתחול", "Power"),
    "noise": ("רעש מוכר", "Known noise"),
    "other": ("אחר", "Other"),
}

_EVENTS_PS = """
$start = (Get-Date).AddDays(-{days})
$events = Get-WinEvent -FilterHashtable @{{LogName='System','Application'; Level=1,2; StartTime=$start}} `
    -MaxEvents {max_events} -ErrorAction SilentlyContinue | ForEach-Object {{
        [PSCustomObject]@{{
            Time     = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            Id       = [int]$_.Id
            Provider = [string]$_.ProviderName
            Level    = [string]$_.LevelDisplayName
            Log      = [string]$_.LogName
            Message  = [string]$_.Message
        }}
    }}
if ($events) {{ $events | ConvertTo-Json -Depth 3 -Compress }} else {{ '[]' }}
"""


class EventLogAnalyzer:
    """Groups recurring Windows errors and explains what they mean."""

    def get_report(self, days=DEFAULT_DAYS):
        if not IS_WINDOWS:
            return {
                "groups": [], "supported": False, "days": days,
                "total_events": 0, "actionable_count": 0, "noise_count": 0,
                "overall": "unknown", "overall_he": "לא נתמך", "overall_en": "Not supported",
            }

        raw = run_powershell_json(
            _EVENTS_PS.format(days=int(days), max_events=MAX_EVENTS),
            timeout=45,
        )
        return self.build_report(raw, days)

    def build_report(self, raw_events, days=DEFAULT_DAYS):
        """Pure grouping/annotation step, kept separate so it can be tested."""
        buckets = {}

        for event in raw_events:
            provider = (event.get("Provider") or "").strip()
            event_id = event.get("Id")
            try:
                event_id = int(event_id)
            except (TypeError, ValueError):
                continue

            key = (provider.lower(), event_id)
            bucket = buckets.get(key)
            if bucket is None:
                bucket = buckets[key] = {
                    "provider": provider,
                    "event_id": event_id,
                    "log": (event.get("Log") or "").strip(),
                    "level": (event.get("Level") or "").strip(),
                    "count": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "sample_message": "",
                }

            bucket["count"] += 1

            timestamp = (event.get("Time") or "").strip()
            if timestamp:
                if not bucket["first_seen"] or timestamp < bucket["first_seen"]:
                    bucket["first_seen"] = timestamp
                if not bucket["last_seen"] or timestamp > bucket["last_seen"]:
                    bucket["last_seen"] = timestamp

            if not bucket["sample_message"]:
                bucket["sample_message"] = self._trim(event.get("Message") or "")

        groups = [self._annotate(b) for b in buckets.values()]

        # Actionable entries first, then by how often each recurs.
        rank = {"high": 0, "medium": 1, "low": 2}
        groups.sort(key=lambda g: (g["noise"], rank.get(g["severity"], 3), -g["count"]))

        total = sum(g["count"] for g in groups)
        noise = sum(g["count"] for g in groups if g["noise"])
        actionable = [g for g in groups if not g["noise"] and g["severity"] in ("high", "medium")]

        if any(g["severity"] == "high" for g in actionable):
            overall = ("danger", "אותרו שגיאות שדורשות טיפול", "Errors needing attention")
        elif actionable:
            overall = ("warn", "יש שגיאות שכדאי לבדוק", "Some errors worth reviewing")
        elif groups:
            overall = ("ok", "רק רעש מוכר ולא מזיק", "Only known, harmless noise")
        else:
            overall = ("ok", "יומן האירועים נקי", "The event log is clean")

        return {
            "groups": groups,
            "supported": True,
            "days": days,
            "total_events": total,
            "distinct_count": len(groups),
            "noise_count": noise,
            "actionable_count": len(actionable),
            "overall": overall[0], "overall_he": overall[1], "overall_en": overall[2],
        }

    # ----------------------------------------------------------------- private

    def _annotate(self, bucket):
        known = self._lookup(bucket["provider"], bucket["event_id"])

        if known:
            bucket.update({
                "severity": known["severity"],
                "category": known["category"],
                "noise": known.get("noise", False),
                "title_he": known["title_he"], "title_en": known["title_en"],
                "desc_he": known["desc_he"], "desc_en": known["desc_en"],
                "action_he": known["action_he"], "action_en": known["action_en"],
                "known": True,
            })
        else:
            critical = bucket["level"].lower() == "critical"
            bucket.update({
                # An unrecognised entry that repeats a lot is more likely to
                # matter than a one-off, but Polaris should not pretend to
                # know what it means.
                "severity": "medium" if (critical or bucket["count"] >= 10) else "low",
                "category": "other",
                "noise": False,
                "title_he": f"{bucket['provider']} (אירוע {bucket['event_id']})",
                "title_en": f"{bucket['provider']} (event {bucket['event_id']})",
                "desc_he": "אין ל-Polaris הסבר מובנה לאירוע הזה. ההודעה המקורית מוצגת למטה.",
                "desc_en": "Polaris has no built-in explanation for this entry. The original message is shown below.",
                "action_he": "חפש את מזהה האירוע ואת שם המקור כדי להבין את ההקשר.",
                "action_en": "Search the event id together with the provider name for context.",
                "known": False,
            })

        labels = CATEGORY_LABELS.get(bucket["category"], CATEGORY_LABELS["other"])
        bucket["category_he"], bucket["category_en"] = labels
        bucket["per_day"] = round(bucket["count"] / max(DEFAULT_DAYS, 1), 1)
        return bucket

    def _lookup(self, provider, event_id):
        provider_lc = (provider or "").lower()
        for (fragment, known_id), entry in EVENT_KNOWLEDGE.items():
            if known_id == event_id and fragment in provider_lc:
                return entry
        return None

    def _trim(self, message, limit=400):
        cleaned = " ".join(str(message).split())
        return cleaned[:limit] + ("..." if len(cleaned) > limit else "")

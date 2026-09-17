"""
Polaris - Deep Process & Windows Component Knowledge Base
Provides comprehensive, human-readable explanations in Hebrew and English for
Windows system processes, security daemons, background services, drivers, and user software.
"""

import csv
import sys

from backend.win_utils import run_hidden

# Comprehensive Dictionary of Windows Core Components and Common Applications
PROCESS_KNOWLEDGE = {
    "msmpeng.exe": {
        "title_he": "Windows Defender (מנוע האנטי-וירוס והאבטחה של מיקרוסופט)",
        "title_en": "Windows Defender (Antimalware Service Executable)",
        "category": "אבטחה והגנה (Security)",
        "description_he": "מנוע ההגנה בזמן אמת והאנטי-וירוס המובנה של Windows. בעת הדלקת המחשב או פתיחת תוכנות, הוא סורק קבצים, בודק חתימות וירוסים ומנטר פעילות חשודה. תקין שיצרוך בין 150MB ל-600MB של RAM בעת סריקה.",
        "description_en": "Microsoft's core built-in antivirus and real-time protection engine. On system startup and app launches, it scans memory and files for threats. Normal memory usage is 150MB-600MB.",
        "is_safe_to_kill": False,
        "kill_impact_he": "סגירת התהליך חסומה על ידי ווינדוס לשמירה על אבטחה. סגירתו תבטל את ההגנה מפני וירוסים ורוגלות.",
        "kill_impact_en": "Protected by Windows. Terminating it would disable real-time malware protection.",
        "why_in_memory_he": "נטען אוטומטית בכל הדלקה כדי לספק הגנה מתמדת על המחשב."
    },
    "nissrv.exe": {
        "title_he": "שירות בדיקת רשת של Windows Defender",
        "title_en": "Microsoft Network Realtime Inspection Service",
        "category": "אבטחה והגנה (Security)",
        "description_he": "רכיב של Windows Defender הסורק תעבורת רשת בזמן אמת כדי לחסום ניסיונות פריצה וחדירה דרך האינטרנט.",
        "description_en": "Windows Defender component that inspects network traffic in real-time to block exploits and unauthorized connections.",
        "is_safe_to_kill": False,
        "kill_impact_he": "פוגע בסינון מתקפות רשת.",
        "kill_impact_en": "Weakens network vulnerability protection.",
        "why_in_memory_he": "פועל ברקע לסינון רשת."
    },
    "securityhealthservice.exe": {
        "title_he": "מרכז האבטחה והבריאות של Windows",
        "title_en": "Windows Security Health Service",
        "category": "אבטחה והגנה (Security)",
        "description_he": "מנהל את מרכז האבטחה (אייקון המגן בשורת המשימות), ומציג את סטטוס חומת האש, ביצועי המכשיר והאנטי-וירוס.",
        "description_en": "Coordinates Windows Security Center UI, tray icon alerts, firewall status, and device health monitoring.",
        "is_safe_to_kill": False,
        "kill_impact_he": "יעלים את אייקון המגן ודוחות האבטחה.",
        "kill_impact_en": "Hides tray security notifications.",
        "why_in_memory_he": "מנטר את מצב האבטחה הכללי."
    },
    "smartscreen.exe": {
        "title_he": "Windows SmartScreen",
        "title_en": "Windows Defender SmartScreen",
        "category": "אבטחה והגנה (Security)",
        "description_he": "בודק קבצים שהורדו מהאינטרנט ואתרים לא מוכרים כדי למנוע הרצת תוכנות זדוניות.",
        "description_en": "Screens web downloads and unknown executables against Microsoft's cloud reputation database.",
        "is_safe_to_kill": False,
        "kill_impact_he": "יבטל הגנה מפני קבצים לא מוכרים שהורדו מהרשת.",
        "kill_impact_en": "Disables reputation checks on downloaded files.",
        "why_in_memory_he": "עולה לפי צורך בעת פתיחת קבצים מהרשת."
    },
    "svchost.exe": {
        "title_he": "מארח שירותי Windows (Host Process for Windows Services)",
        "title_en": "Host Process for Windows Services (svchost)",
        "category": "שירותי מערכת Windows (System Services)",
        "description_he": "תהליך מעטפת של מיקרוסופט המריץ שירותי מערכת שונים (כגון שמע, רשת, עדכוני Windows Update, SysMain, Bluetooth ועוד). ווינדוס מפצל שירותים למספר תהליכי svchost כדי שאם שירות אחד יקרוס, שאר המערכת תמשיך לפעול כרגיל.",
        "description_en": "Generic host process that runs Windows services from DLLs (like Windows Update, Audio, SysMain, Networking). Windows isolates services across multiple instances for stability.",
        "is_safe_to_kill": False,
        "kill_impact_he": "סגירת svchost עלולה להשבית שמע, אינטרנט או לגרום לקריסת המחשב (מסך כחול).",
        "kill_impact_en": "Terminating svchost instances can break networking, audio, or crash the OS.",
        "why_in_memory_he": "שירותי ליבה של ווינדוס שפועלים תמיד ברקע."
    },
    "dwm.exe": {
        "title_he": "מנהל חלונות שולחן העבודה (Desktop Window Manager)",
        "title_en": "Desktop Window Manager (dwm.exe)",
        "category": "ממשק גרפי ומסך (Graphics & GUI)",
        "description_he": "אחראי על ציור ורינדור כל החלונות במחשב, אפקטי שקיפות, הצללות, תצוגה מקדימה בשורת המשימות ותמיכה במסכים מרובים דרך כרטיס המסך (GPU). צריכת הזיכרון שלו גדלה ככל שיש יותר חלונות פתוחים או מסכי 4K.",
        "description_en": "Renders visual desktop elements, glass transparency, window animations, taskbar previews, and GPU compositing.",
        "is_safe_to_kill": False,
        "kill_impact_he": "יגרום למסך להבהב בשחור ולהיטען מחדש באופן מיידי.",
        "kill_impact_en": "Screen will blink black and restart the compositor.",
        "why_in_memory_he": "נדרש באופן רציף להצגת כל תמונה על המסך."
    },
    "explorer.exe": {
        "title_he": "סייר הקבצים ושולחן העבודה (Windows Explorer)",
        "title_en": "Windows Explorer (Shell & Desktop)",
        "category": "ממשק משתמש וקבצים (Shell & Desktop)",
        "description_he": "מנהל את שולחן העבודה, סמלי הקבצים, שורת המשימות, מרכז ההתראות וכל חלונות התיקיות הפתוחים.",
        "description_en": "Controls the Windows shell: desktop icons, taskbar, start menu, notification center, and folder windows.",
        "is_safe_to_kill": True,
        "kill_impact_he": "שורת המשימות והסמלים ייעלמו זמנית עד שייפתח מחדש.",
        "kill_impact_en": "Taskbar and desktop icons will vanish until restarted.",
        "why_in_memory_he": "המעטפת הראשית שדרכה אתה משתמש במחשב."
    },
    "searchindexer.exe": {
        "title_he": "שירות אינדוקס החיפוש של Windows (Search Indexer)",
        "title_en": "Windows Search Indexer",
        "category": "אינדוקס וחיפוש (Indexing)",
        "description_he": "סורק וממפה קבצים, מסמכים, אימיילים ותוכנות בכונן כדי לאפשר חיפוש מיידי ומהיר בתפריט התחל ובסייר הקבצים. לאחר הדלקת המחשב הוא מבצע סריקת עדכונים קצרה שצורכת RAM ומעבד.",
        "description_en": "Indexes files, documents, emails, and properties to provide instant search in Start Menu and Explorer. Temporarily uses more RAM/CPU right after boot.",
        "is_safe_to_kill": True,
        "kill_impact_he": "החיפוש בתפריט התחל יהיה איטי יותר עד שהשירות יופעל מחדש.",
        "kill_impact_en": "Start menu searches will be slower until restarted.",
        "why_in_memory_he": "שומר אינדקס קבצים מהיר ב-RAM לחיפוש מיידי."
    },
    "searchhost.exe": {
        "title_he": "ממשק החיפוש של Windows 10/11",
        "title_en": "Windows Search Experience Host",
        "category": "אינדוקס וחיפוש (Indexing)",
        "description_he": "הממשק הגרפי שנפתח כשלוחצים על זכוכית המגדלת או מקלידים בתפריט התחל.",
        "description_en": "The GUI flyout displayed when searching in Windows taskbar/Start menu.",
        "is_safe_to_kill": True,
        "kill_impact_he": "ייסגר וייטען מחדש בלחיצה הבאה על חיפוש.",
        "kill_impact_en": "Closes and reloads on next search query.",
        "why_in_memory_he": "מוכן ברקע לפתיחה מהירה של חלון החיפוש."
    },
    "startmenuexperiencehost.exe": {
        "title_he": "ממשק תפריט התחל של Windows",
        "title_en": "Start Menu Experience Host",
        "category": "ממשק משתמש (Shell)",
        "description_he": "מנהל את העיצוב, האריחים, והרשימה של תפריט התחל (Start Menu).",
        "description_en": "Hosts the modern Start menu UI and layout in Windows 10/11.",
        "is_safe_to_kill": True,
        "kill_impact_he": "תפריט התחל ייסגר וייטען מחדש בלחיצה הבאה.",
        "kill_impact_en": "Restarts Start menu UI on next click.",
        "why_in_memory_he": "מוכן לפתיחה מיידית של תפריט התחל."
    },
    "runtimebroker.exe": {
        "title_he": "מתווך הרשאות של אפליקציות Windows (Runtime Broker)",
        "title_en": "Runtime Broker (UWP Permissions)",
        "category": "אבטחה והרשאות (System Broker)",
        "description_he": "שומר סף של מיקרוסופט המוודא שאפליקציות Universal Windows Platform (UWP) ויישומי חנות לא חורגים מההרשאות שלהם (כגון גישה למצלמה, מיקרופון או קבצים).",
        "description_en": "Manages permissions for Windows Store / UWP apps, ensuring they adhere to declared privacy policies.",
        "is_safe_to_kill": True,
        "kill_impact_he": "ייסגר וייפתח מחדש אוטומטית לפי הצורך.",
        "kill_impact_en": "Terminates and restarts automatically as needed by apps.",
        "why_in_memory_he": "מתווך פעילויות של אפליקציות Windows מודרניות."
    },
    "system": {
        "title_he": "ליבת מערכת ההפעלה (Windows Kernel & Memory Compression)",
        "title_en": "Windows NT Kernel & System Threads",
        "category": "ליבת המערכת (Kernel)",
        "description_he": "הליבה הראשית של Windows (ntoskrnl.exe). אחראית על ניהול הזיכרון הפיזי, דרייברים, גישה לחומרה, וניהול זיכרון דחוס (Compressed RAM) המשפר את ביצועי המחשב.",
        "description_en": "Core Windows operating system kernel managing hardware, memory allocations, device drivers, and compressed memory.",
        "is_safe_to_kill": False,
        "kill_impact_he": "לא ניתן לסגור - זהו עמוד השדרה של כל מערכת ההפעלה.",
        "kill_impact_en": "Cannot be terminated. Crucial to system operation.",
        "why_in_memory_he": "מערכת ההפעלה עצמה."
    },
    "registry": {
        "title_he": "מאגר הגדרות המערכת בזיכרון (Registry in RAM)",
        "title_en": "Windows Registry Hive in Memory",
        "category": "ליבת המערכת (Kernel)",
        "description_he": "Windows מחזיקה עותק של קובצי ה-Registry ב-RAM כדי שכל התוכנות במחשב יוכלו לקרוא הגדרות מערכת במהירות שיא ללא צורך בפנייה מתמדת לדיסק.",
        "description_en": "In-memory cache of Windows Registry hives to provide instant read/write access to system settings.",
        "is_safe_to_kill": False,
        "kill_impact_he": "לא ניתן לסגור.",
        "kill_impact_en": "Cannot be terminated.",
        "why_in_memory_he": "ייעול קריאת הגדרות מערכת."
    },
    "csrss.exe": {
        "title_he": "מערכת משנה להרצת תהליכים (Client Server Runtime Process)",
        "title_en": "Client Server Runtime Process (csrss)",
        "category": "תהליך מערכת קריטי (Core System)",
        "description_he": "תהליך קריטי של מיקרוסופט האחראי על פקודות מערכת נמוכות, חלונות שורת פקודה (Console), וכיבוי מבוקר של תהליכים.",
        "description_en": "Critical user-mode subsystem responsible for console windows, process shutdown sequences, and thread creation.",
        "is_safe_to_kill": False,
        "kill_impact_he": "סגירתו תגרום מיידית למסך כחול (BSOD) וקריסת המחשב.",
        "kill_impact_en": "Terminating causes immediate Blue Screen (BSOD).",
        "why_in_memory_he": "תהליך ליבה שחייב לרוץ מודלק תמיד."
    },
    "lsass.exe": {
        "title_he": "מנהל אבטחה ואימות משתמשים (Local Security Authority)",
        "title_en": "Local Security Authority Subsystem Service (lsass)",
        "category": "אבטחה והרשאות (Security)",
        "description_he": "אחראי על אימות סיסמאות כניסה למחשב, פוליסות אבטחה, יצירת אסימוני גישה (Access Tokens) והצפנת נתונים.",
        "description_en": "Handles user login authentication, password changes, security audit logs, and access tokens.",
        "is_safe_to_kill": False,
        "kill_impact_he": "יגרום למערכת לדרוש אתחול מיידי של המחשב.",
        "kill_impact_en": "Triggers immediate system reboot.",
        "why_in_memory_he": "מבטיח שרק משתמשים מורשים ניגשים לקבצים."
    },
    "services.exe": {
        "title_he": "מנהל שירותי Windows (Service Control Manager)",
        "title_en": "Service Control Manager (services.exe)",
        "category": "תהליך מערכת קריטי (Core System)",
        "description_he": "המנוע הראשי שמתחיל, עוצר ומנהל את כל שירותי הרקע (Windows Services) של המערכת.",
        "description_en": "Manages starting, stopping, and monitoring all background Windows Services.",
        "is_safe_to_kill": False,
        "kill_impact_he": "קריסה של מערכת ההפעלה.",
        "kill_impact_en": "Crashes Windows.",
        "why_in_memory_he": "מנהל את שירותי הרקע."
    },
    "spoolsv.exe": {
        "title_he": "שירות ניהול הדפסה (Print Spooler)",
        "title_en": "Print Spooler Service",
        "category": "התקנים והדפסה (Devices)",
        "description_he": "מנהל תורי הדפסה ומעביר מסמכים למדפסות מחוברות או למדפסות PDF.",
        "description_en": "Manages print jobs and communication with physical/virtual printers.",
        "is_safe_to_kill": True,
        "kill_impact_he": "לא ניתן יהיה להדפיס מסמכים עד שהשירות יופעל מחדש.",
        "kill_impact_en": "Printing will be unavailable until restarted.",
        "why_in_memory_he": "פועל ברקע למוכנות הדפסה."
    },
    "onedrive.exe": {
        "title_he": "סנכרון ענן Microsoft OneDrive",
        "title_en": "Microsoft OneDrive Cloud Sync",
        "category": "אחסון וענן (Cloud Storage)",
        "description_he": "מסנכרן קבצים, שולחן עבודה ומסמכים עם ענן OneDrive של מיקרוסופט ברקע.",
        "description_en": "Syncs local files, Desktop, and Documents with Microsoft OneDrive cloud storage in the background.",
        "is_safe_to_kill": True,
        "kill_impact_he": "סנכרון הקבצים לענן ייעצר עד להפעלתו מחדש.",
        "kill_impact_en": "Cloud synchronization pauses until reopened.",
        "why_in_memory_he": "מוגדר כברירת מחדל לעלייה עם הפעלת המחשב (Startup)."
    },
    "chrome.exe": {
        "title_he": "דפדפן Google Chrome",
        "title_en": "Google Chrome Browser",
        "category": "דפדפנים (Browsers)",
        "description_he": "דפדפן האינטרנט הפופולרי של גוגל. מריץ ארכיטקטורת Multi-Process שבה כל טאב, תוסף (Extension), מנוע גרפי וסרטון מופרדים לתהליך נפרד ברקע לבידוד שגיאות.",
        "description_en": "Google Chrome web browser. Uses multi-process architecture where every tab, extension, and GPU canvas runs in an isolated process.",
        "is_safe_to_kill": True,
        "kill_impact_he": "הדפדפן או הטאב הספציפי ייסגר (ניתן לשחזר טאבים בפתיחה מחדש).",
        "kill_impact_en": "Closes the browser or specific tab.",
        "why_in_memory_he": "תוכנת משתמש פעילה."
    },
    "msedge.exe": {
        "title_he": "דפדפן Microsoft Edge",
        "title_en": "Microsoft Edge Browser",
        "category": "דפדפנים (Browsers)",
        "description_he": "דפדפן האינטרנט המובנה של מיקרוסופט. כולל מצב Startup Boost שבו הוא מחזיק תהליכי רקע קלים ב-RAM כדי שייפתח במהירות שיא.",
        "description_en": "Microsoft's Chromium-based browser with Startup Boost background caching.",
        "is_safe_to_kill": True,
        "kill_impact_he": "סוגר את הדפדפן.",
        "kill_impact_en": "Closes Edge.",
        "why_in_memory_he": "גלישה פעילה או מצב Startup Boost של ווינדוס."
    },
    "discord.exe": {
        "title_he": "אפליקציית תקשורת Discord",
        "title_en": "Discord Voice & Text App",
        "category": "תקשורת והודעות (Communication)",
        "description_he": "אפליקציית שיחות טקסט, קול ווידאו מבוססת Electron. פותחת מספר תהליכי רקע לרינדור, שמע ותקשורת רשת.",
        "description_en": "Electron-based voice, video, and chat app with multi-process rendering.",
        "is_safe_to_kill": True,
        "kill_impact_he": "סוגר את דיסקורד.",
        "kill_impact_en": "Closes Discord.",
        "why_in_memory_he": "תוכנת משתמש / עלייה באתחול."
    },
    "code.exe": {
        "title_he": "סביבת פיתוח Visual Studio Code",
        "title_en": "Visual Studio Code IDE",
        "category": "כלי פיתוח (Development)",
        "description_he": "עורך קוד של מיקרוסופט. מריץ תהליכי רקע עבור תוספים (Extension Host), שרתי שפה (Language Servers), וטרמינלים מובנים.",
        "description_en": "Microsoft code editor running multiple subprocesses for extension host, language servers, and terminals.",
        "is_safe_to_kill": True,
        "kill_impact_he": "סוגר את VS Code.",
        "kill_impact_en": "Closes VS Code.",
        "why_in_memory_he": "תוכנת פיתוח פעילה."
    }
}

# Windows Services Knowledge Base
SERVICE_KNOWLEDGE = {
    "sysmain": {
        "title_he": "שירות SuperFetch / SysMain (מטמון זיכרון חכם)",
        "desc_he": "לומד את התוכנות שאתה משתמש בהן הכי הרבה וטוען אותן מראש לזיכרון ה-RAM כדי שיעלו באופן מיידי. אם תוכנה אחרת זקוקה לזיכרון, הוא משחרר אותו מיד."
    },
    "wuauserv": {
        "title_he": "Windows Update (עדכוני מערכת ואבטחה)",
        "desc_he": "בודק, מוריד ומתקין עדכוני אבטחה ותיקונים של מיקרוסופט ברקע."
    },
    "wsearch": {
        "title_he": "Windows Search (אינדוקס חיפוש מהיר)",
        "desc_he": "ממפה קבצים ותוכן כדי לספק תוצאות חיפוש מיידיות בתפריט התחל ובסייר הקבצים."
    },
    "audiosrv": {
        "title_he": "Windows Audio (מנהל שמע וקול)",
        "desc_he": "מנהל את כל פעולות השמע, הרמקולים, האוזניות וכרטיס הקול במחשב."
    },
    "audioendpointbuilder": {
        "title_he": "בונה נקודות קצה לשמע (Audio Endpoint Builder)",
        "desc_he": "מזהה חיבור וניתוק של אוזניות, רמקולים ומיקרופונים."
    },
    "bits": {
        "title_he": "שירות העברת נתונים חכמה ברקע (BITS)",
        "desc_he": "מוריד ומעלה קבצים ברקע תוך שימוש ברוחב פס פנוי של הרשת מבלי להפריע לגלישה."
    },
    "dnscache": {
        "title_he": "מטמון לקוח DNS (DNS Client Cache)",
        "desc_he": "שומר בזיכרון את כתובות ה-IP של אתרי אינטרנט שביקרת בהם כדי להאיץ את הגלישה."
    },
    "wlansvc": {
        "title_he": "שירות רשת אלחוטית (WLAN AutoConfig)",
        "desc_he": "מנהל את חיבורי ה-Wi-Fi, סריקת רשתות אלחוטיות והתחברות אוטומטית."
    },
    "lanmanworkstation": {
        "title_he": "Workstation (שיתוף קבצים ברשת)",
        "desc_he": "יוצר ומנהל חיבורי רשת לכוננים משותפים ולמחשבים אחרים ברשת המקומית."
    },
    "spooler": {
        "title_he": "Print Spooler (ניהול הדפסות)",
        "desc_he": "טוען קבצים לזיכרון ושולח אותם למדפסת לפי תור."
    },
    "cryptsvc": {
        "title_he": "שירותי הצפנה ואבטחה (Cryptographic Services)",
        "desc_he": "מאמת חתימות דיגיטליות של קובצי מערכת ותוכנות כדי לוודא שלא חובלו."
    },
    "eventlog": {
        "title_he": "יומן אירועים של Windows (Windows Event Log)",
        "desc_he": "מתעד אירועי מערכת, שגיאות והודעות אבטחה לצורכי אבחון."
    },
    "plugplay": {
        "title_he": "התקן והפעל (Plug and Play)",
        "desc_he": "מזהה חיבור חומרה חדשה (כמו עכבר, מקלדת, כונן USB) ומתקין דרייברים אוטומטית."
    },
    "power": {
        "title_he": "שירות ניהול צריכת חשמל (Power Service)",
        "desc_he": "מנהל את מצבי השינה, בהירות המסך וחיסכון בסוללה."
    },
    "brokerinfrastructure": {
        "title_he": "תשתית תיווך הרקע (Background Tasks Infrastructure)",
        "desc_he": "מנהלת הרצת משימות רקע עבור אפליקציות מודרניות של Windows."
    },
    "dcomlaunch": {
        "title_he": "משגר שרתי DCOM (DCOM Server Process Launcher)",
        "desc_he": "מפעיל שרתי COM ו-DCOM הנדרשים לתקשורת בין תוכנות."
    },
    "diagtrack": {
        "title_he": "טלמטריה ואבחון (Connected User Experiences and Telemetry)",
        "desc_he": "שירות אופציונלי של מיקרוסופט האוסף נתוני שימוש ודוחות קריסה לשיפור המערכת."
    }
}


class ProcessKnowledgeBase:
    @staticmethod
    def get_service_map():
        """Returns mapping of PID to list of Windows Services using tasklist /svc."""
        if not sys.platform.startswith('win'):
            return {}

        service_map = {}
        try:
            cmd = ['tasklist', '/svc', '/fo', 'csv']
            res = run_hidden(cmd, capture_output=True, text=True, timeout=3, check=False)
            if res.returncode == 0:
                reader = csv.reader(res.stdout.strip().splitlines())
                header = next(reader, None)
                for row in reader:
                    if len(row) >= 3:
                        try:
                            pid = int(row[1])
                            raw_svcs = row[2].strip()
                            if raw_svcs and raw_svcs != "N/A":
                                svcs = [s.strip() for s in raw_svcs.split(',') if s.strip()]
                                service_map[pid] = svcs
                        except ValueError:
                            continue
        except Exception:
            pass

        return service_map

    @classmethod
    def explain_process(cls, name, pid=None, exe_path="", services=None):
        """
        Generates deep, intuitive explanation in Hebrew and English for any process.
        Combines dictionary lookup, service inspection, and heuristic analysis.
        """
        name_lower = name.lower()
        info = PROCESS_KNOWLEDGE.get(name_lower)

        if not info:
            # Heuristic generation
            is_windows_system = False
            if exe_path and ("\\windows\\system32\\" in exe_path.lower() or "\\windows\\syswow64\\" in exe_path.lower() or "\\windows\\systemapps\\" in exe_path.lower()):
                is_windows_system = True

            if is_windows_system:
                category = "רכיב מערכת Windows (Windows System)"
                title_he = f"תהליך מערכת של Windows ({name})"
                title_en = f"Windows System Process ({name})"
                desc_he = f"קובץ מערכת מקורי של מיקרוסופט הממוקם בנתיב המערכת {exe_path}. אחראי על פעולות רקע, תצוגה או תמיכה בחומרה."
                desc_en = f"Genuine Microsoft Windows system executable located at {exe_path}. Handles background OS maintenance or hardware support."
                safe_kill = False
                kill_impact_he = "סגירת תהליכי מערכת עלולה לפגוע ביציבות Windows."
                kill_impact_en = "Terminating system processes may destabilize Windows."
            else:
                category = "תוכנת משתמש / יישום צד שלישי (User App)"
                title_he = f"תוכנה או תהליך פעיל ({name})"
                title_en = f"Application Process ({name})"
                desc_he = f"תוכנה או שירות רקע המותקן במחשב בנתיב: {exe_path or 'לא זוהה'}. מופעל על ידי המשתמש או עולה בהפעלת המחשב."
                desc_en = f"User application or background utility installed at: {exe_path or 'Unknown'}. Launched by user or configured in Startup."
                safe_kill = True
                kill_impact_he = "התוכנה תיסגר. במידה ויש קבצים פתוחים ללא שמירה, שמור אותם קודם."
                kill_impact_en = "Process will terminate. Save any unsaved documents first."

            info = {
                "title_he": title_he,
                "title_en": title_en,
                "category": category,
                "description_he": desc_he,
                "description_en": desc_en,
                "is_safe_to_kill": safe_kill,
                "kill_impact_he": kill_impact_he,
                "kill_impact_en": kill_impact_en,
                "why_in_memory_he": "פועל בעקבות הפעלת המחשב או שימוש על ידי תוכנה מותקנת."
            }

        # Enrich with Windows Services info if available
        enriched = dict(info)
        enriched["services_list"] = []

        if services:
            for s in services:
                s_lower = s.lower()
                s_info = SERVICE_KNOWLEDGE.get(s_lower, {
                    "title_he": f"שירות Windows ({s})",
                    "desc_he": "שירות רקע של מערכת ההפעלה."
                })
                enriched["services_list"].append({
                    "service_name": s,
                    "title_he": s_info["title_he"],
                    "desc_he": s_info["desc_he"]
                })

        return enriched

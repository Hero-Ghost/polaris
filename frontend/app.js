/**
 * Polaris - System Observability, Diagnostics & Windows Revitalizer
 * Clean, professional, high-performance monitoring client.
 */

// -------------------------------------------------------------
// Authenticated transport
// -------------------------------------------------------------
// The backend rejects any /api/ request that does not carry the per-run
// session token which the server injects into index.html. Every fetch() in
// this file therefore goes through the wrapper below.
const API_TOKEN = (document.querySelector('meta[name="polaris-token"]') || {}).content || '';

(function installAuthenticatedFetch() {
  const nativeFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    if (url.startsWith('/api/')) {
      init = Object.assign({}, init);
      init.headers = new Headers(init.headers || {});
      init.headers.set('X-Polaris-Token', API_TOKEN);
      init.cache = 'no-store';
    }
    return nativeFetch(input, init).then(async (response) => {
      if (response.status === 403) {
        try {
          const clone = response.clone();
          const data = await clone.json();
          if (data && data.message && (data.message.includes('הושבתה') || data.message.includes('מפתח'))) {
            window._isAppKilled = true;
            if (typeof triggerKillSwitch === 'function') {
              triggerKillSwitch({ message_he: data.message });
            }
          }
        } catch (_) {}
      }
      return response;
    });
  };
})();

// -------------------------------------------------------------
// Safe rendering helpers
// -------------------------------------------------------------
// Process names, command lines and service names come straight from the OS and
// are fully attacker-controlled (anyone can name an executable
// `<img src=x onerror=...>`). Everything interpolated into innerHTML or into an
// inline handler must therefore be escaped.
function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// -------------------------------------------------------------
// BiDi helpers (the document is <html dir="rtl">)
// -------------------------------------------------------------
// In an RTL paragraph the Unicode BiDi algorithm resolves the digits of
// "8.20 GB" and the latin "GB" to their own runs, while the plain space between
// them falls back to the paragraph direction - so the runs get swapped and the
// user reads "GB 8.20". Wrapping the value in LRI ... PDI turns it into a single
// left-to-right atom that keeps its internal order wherever it is placed: in a
// table cell, or in the middle of a Hebrew sentence. The no-break space stops
// the number and its unit from being broken across two lines.
const LRI = '⁦';   // LEFT-TO-RIGHT ISOLATE
const PDI = '⁩';   // POP DIRECTIONAL ISOLATE
const NBSP = ' ';  // NO-BREAK SPACE

function ltrIsolate(value, nbsp) {
  if (value === null || value === undefined) return '';
  let text = String(value);
  if (!text || text.charAt(0) === LRI) return text;
  if (nbsp) text = text.replace(/ /g, NBSP);
  return LRI + text + PDI;
}

// Strips the BiDi controls again - for CSV/clipboard output, sorting and any
// string comparison.
function stripBidi(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[⁦-⁩‎‏]/g, '').replace(/ /g, ' ');
}

// -------------------------------------------------------------
// State Management
// -------------------------------------------------------------
let currentLang = 'he';
let currentScreen = 'overview'; // key of SCREENS
let refreshInterval = 2000;
let refreshTimer = null;
let isGroupedView = true;
let currentCategory = 'All';
let searchQuery = '';
let sortColumn = 'rss_bytes';
let sortDirection = 'desc';
let expandedGroups = new Set(['svchost.exe', 'chrome.exe', 'msedge.exe']);

let rawStats = null;
let rawDiagnostics = null;
let rawBattery = null;
let rawProcesses = [];
let procStore = new Map();

let currentCrashes = [];
let crashStore = new Map();

let currentModalProc = null;
let currentModalPid = 0;

let timelineChart = null;
let categoryChart = null;
let revitalizePollTimer = null;

// -------------------------------------------------------------
// Internationalization (Hebrew / English)
// -------------------------------------------------------------
// -------------------------------------------------------------
// Internationalization (Hebrew / English)
// -------------------------------------------------------------
// Static copy is applied declaratively: any element carrying data-i18n gets
// its textContent from the table below, data-i18n-ph fills a placeholder and
// data-i18n-title fills a tooltip. Adding a new label means adding a key here
// and an attribute in index.html - no new getElementById line.
const I18N = {
  he: {
    /* Navigation */
    navGroupMonitor: "ניטור",
    navOverview: "סקירה כללית",
    navProcesses: "תהליכים ושירותים",
    navMemory: "אבחון זיכרון",
    navGroupSystem: "מערכת",
    navMaintenance: "תחזוקה ותיקון",
    navUninstaller: "הסרת תוכנות",
    navStartup: "תוכנות אתחול",
    navCrashes: "קריסות ומסך כחול",
    navGroupTools: "כלים",
    navTools: "כלים שימושיים",
    navSettings: "הגדרות",

    /* Consolidated Categories */
    catPerformanceTitle: "משאבים וביצועים",
    catPerformanceDesc: "ניהול תהליכים, שירותי Windows ואבחון עומק של RAM והקרנל",
    catStorageTitle: "כוננים ואחסון",
    catStorageDesc: "בריאות כוננים לפי נתוני S.M.A.R.T, וסייר אחסון חזותי למציאת קבצים כבדים",
    catMaintenanceTitle: "תחזוקה ותוכנות",
    catMaintenanceDesc: "תיקון קבצי מערכת, ניקוי מטמון, הסרת תוכנות ושאריות, וניהול תוכנות אתחול",
    catDiagnosticsTitle: "אבחון ויציבות",
    catDiagnosticsDesc: "ניתוח קריסות ומסכים כחולים (BSOD), ויומן שגיאות Windows",
    catHardwareTitle: "חומרה והתקנים",
    catHardwareDesc: "מנהל ההתקנים, תקינות הדרייברים ובריאות הסוללה",
    catSettingsTitle: "כלים והגדרות",
    catSettingsDesc: "כלים שימושיים (איפוס OneDrive, מיפוי Copilot) והגדרות התוכנה",

    navPerformance: "משאבים וביצועים",
    navStorageGroup: "כוננים ואחסון",
    navMaintenanceGroup: "תחזוקה ותוכנות",
    navDiagnosticsGroup: "אבחון ויציבות",
    navHardwareGroup: "חומרה והתקנים",
    navSettingsGroup: "כלים והגדרות",
    navGroupCore: "ניהול ומשאבים",
    navGroupDiagnostics: "אבחון וחומרה",
    navBattery: "בריאות סוללה",
    navStorageTree: "סייר אחסון",

    /* Screen headers (topbar) */
    scrOverviewTitle: "סקירה כללית",
    scrOverviewDesc: "מצב הזיכרון והמערכת במבט אחד",
    scrProcessesTitle: "תהליכים ושירותים",
    scrProcessesDesc: "מה רץ עכשיו, כמה זיכרון הוא תופס, ומה אפשר לסגור",
    scrMemoryTitle: "אבחון זיכרון",
    scrMemoryDesc: "למה הזיכרון תפוס — ממצאים, מאגרי הקרנל והתפלגות",
    scrMaintenanceTitle: "תחזוקה ותיקון",
    scrMaintenanceDesc: "כלי Microsoft רשמיים לניקוי, תיקון ואיפוס",
    scrUninstallerTitle: "הסרת תוכנות ושאריות",
    scrUninstallerDesc: "הסרה נקייה עם נקודת שחזור, גיבוי Registry וסריקת שאריות מעמיקה",
    scrStartupTitle: "תוכנות אתחול",
    scrStartupDesc: "מה עולה יחד עם המחשב וכמה זה מאט את ההפעלה",
    scrCrashesTitle: "קריסות ומסך כחול",
    scrCrashesDesc: "פענוח BSOD, קודי BugCheck וכיבויי פתע",
    scrToolsTitle: "כלים שימושיים",
    scrToolsDesc: "איפוס Microsoft OneDrive, שחזור מטמון אייקונים וארגז כלי IT לארגונים",
    scrSettingsTitle: "הגדרות",
    scrSettingsDesc: "שפה, קצב רענון, ייצוא נתונים ופרטי גרסה",

    /* Shared */
    loading: "טוען...",
    btnRefresh: "רענן",
    btnClose: "סגור",
    btnCancel: "בטל",
    btnKill: "סיים תהליך",
    btnOptimize: "שחרר זיכרון",
    btnDeepScan: "סרוק מחדש",
    optimizing: "משחרר...",
    details: "פרטים",
    procsShort: "תהליכים",
    svcsShort: "שירותים",

    /* Privileges */
    privChecking: "בודק הרשאות...",
    privAdmin: "פועל כמנהל מערכת",
    privLimited: "הרשאות רגילות",
    privAdminTip: "כל כלי התיקון זמינים.",
    privLimitedTip: "כלי התיקון (DISM, SFC, רשת, הדפסה, TRIM) ידרשו אישור UAC נפרד או לא יפעלו.",

    /* Overview */
    scoreCap: "ציון",
    diagTitle: "מצב בריאות המערכת",
    diagScanning: "סורק תהליכי רקע, מאגרי זיכרון של הקרנל ושירותי מערכת פעילים",
    physicalRamTitle: "זיכרון פיזי בשימוש",
    memoryLoad: "עומס זיכרון:",
    usedRam: "בשימוש",
    availableRam: "פנוי וזמין",
    cachedRam: "מטמון (Standby)",
    totalRam: "סה״כ מותקן",
    loadNormal: "תקין",
    loadModerate: "בינוני",
    loadHigh: "גבוה",
    attentionTitle: "דורש תשומת לב",
    attentionDesc: "הממצאים המשמעותיים ביותר מהאבחון האחרון.",
    attentionFoot: "פירוט מלא, מאגרי הקרנל והתפלגות",
    attentionLink: "אבחון זיכרון מלא",
    attentionNone: "לא נמצאו ממצאים חריגים. הזיכרון מנוהל כרגיל.",
    timelineTitle: "היסטוריית שימוש בזיכרון",
    timelineDesc: "60 השניות האחרונות, דגימה כל שנייה.",
    legendUsed: "בשימוש (GB)",
    legendCached: "מטמון (GB)",
    topHogsTitle: "צרכני הזיכרון הגדולים",
    topHogsDesc: "התוכנות שתופסות את החלק הגדול ביותר מהזיכרון כרגע",
    topHogsLink: "לכל התהליכים",

    /* Battery Overview */
    batteryScoreCap: "בריאות",
    batteryCardTitle: "בריאות הסוללה וצריכת חשמל",
    batteryScanning: "מחשב קיבולת יצרן מול קיבולת מרבית עכשווית, רמת שחיקה ומחזורי טעינה.",
    btnRefreshBattery: "רענן סוללה",
    batteryChargeLevel: "רמת טעינה נוכחית",
    batteryStatusLabel: "מצב פעולה:",
    batteryFullCapacity: "קיבולת מלאה נוכחית",
    batteryDesignCapacity: "קיבולת יצרן מקורית",
    batteryWearLevel: "רמת שחיקה",
    batteryCycleCount: "מחזורי טעינה",
    batteryEstimatedTime: "זמן עבודה משוער",
    desktopNoBatteryTitle: "מחשב נייח / ללא סוללה",
    desktopNoBatteryDesc: "המערכת מחוברת ישירות למקור חשמל AC קבוע. לא נדרש ניטור שחיקת סוללה.",
    batteryStatusPlugged: "מחובר לחשמל",
    batteryStatusCharging: "בטעינה",
    batteryStatusDischarging: "בפריקה (על סוללה)",
    batteryCyclesUnit: "מחזורים",
    batteryGood: "מצב טוב",

    /* Processes */
    processExplorerTitle: "מנהל תהליכים ושירותי Windows",
    processExplorerDesc: "תהליכים פעילים, שיוך שירותי Windows פנימיים והקצאת משאבים.",
    btnGrouped: "מרוכז באפליקציות",
    btnFlat: "רשימת PID",
    searchPlaceholder: "חיפוש תהליך, שירות או PID...",
    catAll: "הכל",
    catBrowsers: "דפדפנים",
    catDevelopment: "פיתוח",
    catSystem: "שירותי מערכת",
    catApps: "תוכנות",
    thProcessName: "שם התהליך / התוכנה",
    thCategory: "קטגוריה",
    thRam: "זיכרון (RAM)",
    thRamPercent: "% מה-RAM",
    thCpu: "מעבד",
    thActions: "פעולות",
    noProcs: "לא נמצאו תהליכים תואמים",
    noProcsDesc: "נסה לנקות את החיפוש או לבחור קטגוריה אחרת.",
    confirmKillTitle: "סיום תהליך Windows",
    confirmKillGroupTitle: "סיום קבוצת תהליכים",

    /* Memory analysis */
    findingsTitle: "ממצאי אבחון",
    findingsDesc: "כל מה שהמנוע זיהה כגורם אפשרי לצריכת זיכרון גבוהה, עם המלצה לפעולה.",
    kernelTitle: "קרנל, דרייברים וקובץ החלפה",
    kernelDesc: "זיכרון שאינו שייך לאף תהליך גלוי - כאן מתגלות דליפות דרייברים.",
    descNonPaged: "זיכרון קבוע ב-RAM עבור דרייברים, לא ניתן להעברה לדיסק",
    descPaged: "זיכרון מערכת הניתן להעברה לקובץ ההחלפה",
    driverLeakNote: "ניטור דליפת דרייברים:",
    driverLeakOk: "תקין, ללא דליפה",
    driverLeakWarn: "עומס חריג בדרייבר",
    nppOk: "תקין",
    nppHigh: "גבוה",
    categoryDonutTitle: "התפלגות זיכרון לפי קטגוריה",
    categoryDonutDesc: "לאן הולך הזיכרון התפוס, מקובץ לפי סוג התוכנה.",

    /* Maintenance */
    repairSafetyTitle: "כל הפעולות כאן משתמשות בכלי Microsoft רשמיים",
    repairSafetyNote: "קבצים אישיים, מסמכים, תמונות, שולחן העבודה ותוכנות מותקנות נשמרים לחלוטין.",
    btnAuditScan: "סרוק מצב",
    lblAuditTemp: "קבצים זמניים ומטמון",
    lblAuditRecoverable: "ניתן לפינוי",
    lblAuditStartup: "יישומי אתחול",
    lblAuditTrim: "מיטוב כונן SSD",
    auditReady: "מוכן",
    auditTrimNote: "רענון בלוקים פנויים",
    lblAuditDism: "ספריית רכיבי Windows",
    auditDismNote: "צמצום WinSxS וגיבויי עדכונים",
    auditScanning: "סורק...",
    auditHighImpact: "השפעה גבוהה",
    txtActionCenterTitle: "בחירת פעולות תיקון ותחזוקה",
    txtActionCenterDesc: "סמן את המשימות שברצונך להריץ, והפעל הכל בלחיצה אחת.",
    btnRunRevitalize: "הפעל תחזוקה",
    runningMaintenance: "מבצע פעולות תחזוקה...",
    groupCleanup: "ניקוי ופינוי מקום",
    groupIntegrity: "תיקון שלמות מערכת",
    groupServices: "רשת ושירותים",
    lblChkCleanTemp: "ניקוי קבצי זבל זמניים ומטמון ישן",
    descChkCleanTemp: "מחיקת %TEMP%, SoftwareDistribution/Download ומטמון דוחות שגיאה רדום.",
    lblChkDism: "ניקוי ספריית רכיבי Windows",
    descChkDism: "סילוק גיבויי עדכונים ישנים וצמצום WinSxS. פעולה איטית — 4 עד 20 דקות. כבויה כברירת מחדל.",
    lblChkRetrim: "מיטוב ביצועי כונן SSD (TRIM)",
    descChkRetrim: "רענון בלוקים פנויים לשמירה על מהירות קריאה וכתיבה.",
    lblChkFlushRam: "שחרור זיכרון עבודה ודפים רדומים",
    descChkFlushRam: "החזרת מאות מגה-בייטים של RAM פנוי באופן מיידי.",
    lblChkDismRestore: "תיקון תמונת מערכת Windows",
    descChkDismRestore: "סריקה ושחזור של רכיבי Windows פגומים. עשוי להימשך מספר דקות.",
    lblChkSfc: "סריקה ותיקון קבצי מערכת פגומים",
    descChkSfc: "בדיקת כל קובצי המערכת המוגנים של Windows ושחזור גרסאות פגומות",
    lblChkFlushDns: "איפוס מטמון DNS",
    descChkFlushDns: "פתרון איטיות גלישה ואתרים שלא נטענים.",
    lblChkNetReset: "איפוס עמוק של מחסנית הרשת ו-Winsock",
    descChkNetReset: "תיקון ניתוקי אינטרנט חוזרים. דורש הפעלה מחדש.",
    lblChkWuReset: "איפוס שירותי Windows Update",
    descChkWuReset: "אתחול wuauserv, bits ו-cryptsvc ופינוי עדכונים תקועים.",
    lblChkSpoolerReset: "איפוס שירות הדפסה ופינוי התור",
    descChkSpoolerReset: "ניקוי תור הדפסה תקוע ואתחול spoolsv.exe.",
    liveOutput: "פלט פקודות חי",
    lblStepList: "שלבי התהליך",
    btnCopyLog: "העתק לוג",
    btnPreviewScan: "סרוק בלי להסיר",
    btnFinishAndClose: "סיים וסגור",
    totalFreed: "סה״כ פונו:",

    /* Startup */
    txtStartupExplorerTitle: "תוכנות שעולות עם המחשב",
    txtStartupExplorerDesc: "תוכנות שפועלות אוטומטית בעת עליית המחשב, מדורגות לפי השפעתן על זמן ההפעלה",
    startupSafeNote: "קריאה בלבד",
    noStartup: "לא נמצאו תוכנות אתחול פעילות ברישום המערכת.",
    impactSuffix: "השפעה",

    /* Crashes */
    lblTotalCrashes: "אירועי קריסה ב-30 יום",
    lblBsodCount: "מסכים כחולים (BSOD)",
    lblPowerLossCount: "כיבויי פתע (Kernel-Power)",
    txtCrashInspectorTitle: "היסטוריית קריסות ופענוח מסך כחול",
    txtCrashInspectorDesc: "פענוח אוטומטי של Minidump, קודי BugCheck וכיבויי פתע מיומן האירועים, עם אבחון שורש והמלצות.",
    txtBtnMemDiag: "בדיקת חומרת RAM",
    healthStable: "המערכת יציבה",
    healthBsod: "אותרו מסכים כחולים",
    healthPower: "אותרו כיבויי פתע",
    noCrashes: "לא אותרו קריסות או כיבויי פתע",
    noCrashesDesc: "יומן האירועים נקי משגיאות קרנל חמורות ב-30 הימים האחרונים",
    crashDetailsBtn: "פרטים ופתרון",
    crashCodeShort: "קוד:",
    crashDriverShort: "רכיב:",

    /* Keyboard tools */
    copilotKeyTitle: "מיפוי מקש Copilot ל-Ctrl ימני",
    copilotKeyDesc: "הופך את מקש ה-Copilot (שמשדר חומרתית Win+Shift+F23) למקש Ctrl ימני תקני. פועל אוטומטית בכל הפעלה של המחשב, ללא צורך להשאיר את Polaris פתוחה.",
    btnEnableCopilot: "הפעל מיפוי",
    btnDisableCopilot: "בטל מיפוי",
    openWinSettings: "פתח הגדרות מקלדת של Windows",
    copilotStatusActive: "פעיל ב-Startup",
    copilotStatusInactive: "כבוי",
    lblCopilotFeat1: "0% עומס מערכת",
    descCopilotFeat1: "שירות Hook שקוף וזעיר. נשמר ופועל אוטומטית לאחר כל הפעלה מחדש.",
    lblCopilotFeat2: "ללא נעילת קבצים",
    descCopilotFeat2: "מותקן ב-AppData בצורה מבודדת, כך שניתן למחוק או להעביר את קובץ ההתקנה בחופשיות.",
    lblCopilotFeat3: "קבוע לאחר הפעלה מחדש",
    descCopilotFeat3: "תומך בהחזקה רציפה: Ctrl+C, Ctrl+V, קיצורי עריכה וגיימינג.",

    /* OneDrive reset */
    onedriveTitle: "איפוס Microsoft OneDrive",
    onedriveDesc: "סוגר את OneDrive, מוחק את מפתח הרגיסטרי של החשבונות (Accounts) ומנקה מטמון הגדרות מקומי כדי לאפשר התחברות נקייה מחדש.",
    btnResetOneDrive: "איפוס ONE DRIVE",
    openOneDriveApp: "פתח את OneDrive",
    onedriveStatusRunning: "פעיל ברקע",
    onedriveStatusStopped: "סגור",
    lblOneDriveFeat1: "סגירת תהליך מיידית",
    descOneDriveFeat1: "עוצר בכפייה את תהליכי OneDrive.exe לשחרור נעילות קבצים ורגיסטרי.",
    lblOneDriveFeat2: "מחיקת Accounts ברגיסטרי",
    descOneDriveFeat2: "מוחק את HKCU\\Software\\Microsoft\\OneDrive\\Accounts ומנתק את כל החשבונות.",
    lblOneDriveFeat3: "ניקוי מטמון ואתחול נקי",
    descOneDriveFeat3: "מנקה הגדרות תקועות במטמון ומאפשר התחברות מחדש. קובצי המשתמש לא יימחקו.",
    confirmOneDriveTitle: "אישור איפוס Microsoft OneDrive",
    confirmOneDriveDesc: "פעולה זו תסגור את OneDrive, תמחק את כל הגדרות החשבונות המחוברים ברגיסטרי (Accounts) ותנקה את מטמון ההגדרות המקומי.\n\nקובצי המשתמש המסונכרנים בדיסק ובענן לא יימחקו.\n\nהאם להמשיך באיפוס?",
    btnConfirmReset: "אפס את OneDrive",

    /* Icon Cache Rebuild */
    iconCacheTitle: "בנייה מחדש של מטמון האייקונים (Icon Cache)",
    iconCacheDesc: "סוגר את סייר הקבצים, מוחק את מסדי הנתונים iconcache ו-thumbcache המושחתים, מפעיל מחדש את Explorer ומרענן את כל האייקונים והתצוגות המקדימות.",
    btnRebuildIconCache: "בנה מחדש מטמון אייקונים",
    lblIconCacheFeat1: "סגירת Explorer לשחרור נעילות",
    descIconCacheFeat1: "עוצר מבוקרת את explorer.exe כדי לאפשר מחיקה של קובצי המטמון הנעולים.",
    lblIconCacheFeat2: "מחיקת IconCache ו-Thumbcache",
    descIconCacheFeat2: "מוחק את קובצי מסד הנתונים של האייקונים ב-AppData ומאלץ את Windows ליצור אותם מחדש.",
    lblIconCacheFeat3: "רענון Shell מיידי (ללא אתחול)",
    descIconCacheFeat3: "משדר SHChangeNotify ומפעיל מחדש את שולחן העבודה. מתקן אייקונים לבנים באופן מיידי.",
    confirmIconCacheTitle: "אישור בנייה מחדש של מטמון האייקונים",
    confirmIconCacheDesc: "פעולה זו תסגור לרגע את סייר הקבצים (Explorer), תמחק את כל קובצי מטמון האייקונים והתמונות הממוזערות הפגומים, ותפעיל מחדש את שולחן העבודה.\n\nהמסך עשוי להבהב לרגע קל בלבד. האם להמשיך?",
    btnConfirmRebuildIcon: "בנה מחדש עכשיו",

    /* Enterprise IT Toolkit */
    enterpriseSuiteTitle: "ארגז כלי IT לארגונים (Enterprise IT Toolkit)",
    enterpriseSuiteDesc: "פתרונות מיידיים לתקלות IT נפוצות בארגונים מבוססי Active Directory, Entra ID, GPO, M365, שרתי קבצים ורשת ארגונית.",
    enterpriseBadge: "11 כלי עבודה",

    toolKerberosTitle: "איפוס כרטיסי Kerberos (שחרור הרשאות שיתוף)",
    toolKerberosBadge: "Active Directory",
    toolKerberosDesc: "מחיל הרשאות Active Directory חדשות לתיקיות רשת ללא צורך באתחול או התנתקות.",
    toolKerberosBtn: "אפס כרטיסי Kerberos",
    confirmKerberosTitle: "אישור איפוס כרטיסי Kerberos",
    confirmKerberosDesc: "פעולה זו תמחק את כרטיסי ה-Kerberos המאוחסנים במחשב (klist purge) ותרענן את טבלת השמות של NetBIOS.\n\nהפעולה מאפשרת למשתמש לקבל באופן מיידי הרשאות שיתוף חדשות שהוגדרו ב-Active Directory ללא צורך באתחול.\n\nהאם להמשיך?",

    toolGpoTitle: "איפוס וסנכרון מאולץ של Group Policy (GPO)",
    toolGpoBadge: "Group Policy",
    toolGpoDesc: "מוחק מטמון מקומי פגום ומבצע gpupdate /force מלא מול שרת ה-Domain Controller לאכיפת מדיניות עדכנית.",
    toolGpoBtn: "סנכרן GPO מחדש",
    confirmGpoTitle: "אישור סנכרון Group Policy",
    confirmGpoDesc: "פעולה זו תמחק קובצי GPO מקומיים פגומים ותפעיל פקודת gpupdate /force מלאה מול שרתי ה-Domain Controller.\n\nהאם להמשיך?",

    toolCredsTitle: "ניקוי סיסמאות ישנות למניעת נעילת משתמש (Account Lockout)",
    toolCredsBadge: "אבטחת חשבון",
    toolCredsDesc: "מוחק מ-Credential Manager סיסמאות דומיין ו-M365 ישנות שגורמות לנעילת חשבון חוזרת ונשנית.",
    toolCredsBtn: "נקה אישורים ישנים",
    confirmCredsTitle: "אישור ניקוי סיסמאות ישנות",
    confirmCredsDesc: "פעולה זו תמחק מנהל האישורים (Credential Manager) סיסמאות ישנות של רשת ארגונית, שרתי דומיין ושירותי Office.\n\nזהו הפתרון הנפוץ ביותר לתופעת Account Lockout חוזרת ונשנית בארגונים.\n\nהאם להמשיך?",

    toolEntraTitle: "תיקון לולאת אימות Entra ID / WAM Broker",
    toolEntraBadge: "Microsoft 365",
    toolEntraDesc: "פותר שגיאות CAA50021, CAA2000B ותקיעות של Teams ו-Office בלולאת התחברות באמצעות איפוס ה-BrokerPlugin.",
    toolEntraBtn: "אפס מנגנון אימות Entra",
    confirmEntraTitle: "אישור איפוס מנגנון אימות Entra ID",
    confirmEntraDesc: "פעולה זו תסגור תהליכי Teams ו-Office ותנקה את מטמון ה-WAM (Web Account Manager) של Entra ID.\n\nהפעולה מתקנת חלונות כניסה לבנים ריקים ושגיאות CAA50021. קובצי משתמש ומיילים לא יימחקו.\n\nהאם להמשיך?",

    toolTeamsTitle: "איפוס Microsoft Teams (שגיאה 894893981 / כשל כניסה)",
    toolTeamsBadge: "Microsoft Teams",
    toolTeamsDesc: "מתקן כשלים בהתחברות לחשבון מיקרוסופט, מסך לבן ושגיאה 894893981 (Keyset does not exist) ע\"י ניקוי מטמון Teams, WAM Broker ואסימוני OneAuth.",
    toolTeamsBtn: "אפס את Microsoft Teams",
    confirmTeamsTitle: "אישור איפוס Microsoft Teams",
    confirmTeamsDesc: "פעולה זו תסגור תהליכי Teams, תנקה את מטמון האפליקציה המקומי (New Teams ו-Classic), ותאפס את אסימוני ה-WAM TokenBroker, OneAuth ומפתחות אימות פגומים שגורמים לשגיאה 894893981 ולחוסר יכולת להתחבר לחשבון מיקרוסופט.\n\nקובצי משתמש והודעות בענן בטוחים לחלוטין. האם להמשיך?",

    toolOutlookTitle: "איפוס Microsoft Outlook (שגיאה 894893981 / פרופיל ואימות)",
    toolOutlookBadge: "Microsoft Outlook",
    toolOutlookDesc: "פותר שגיאות 894893981 (Keyset does not exist), בקשות סיסמה חוזרות ותקיעות בפרופיל ע\"י ניקוי SRS, RoamCache, WAM Broker ואסימוני OneAuth ללא פגיעה במיילים.",
    toolOutlookBtn: "אפס את Microsoft Outlook",
    confirmOutlookTitle: "אישור איפוס Microsoft Outlook",
    confirmOutlookDesc: "פעולה זו תסגור את Outlook ותנקה את קובצי ה-SRS (שליחה/קבלה), מטמון RoamCache, Autodiscover ואסימוני WAM TokenBroker ו-OneAuth הפגומים שגורמים לשגיאה 894893981.\n\nתיבות הדואר, קובצי ה-PST/OST והמיילים שמורים ובטוחים לחלוטין. האם להמשיך?",

    toolDrivesTitle: "שחרור כונני רשת תקועים ואיפוס SMB",
    toolDrivesBadge: "שיתוף קבצים",
    toolDrivesDesc: "מנתק כונני רשת תקועים עם איקס אדום (Ghost Drives) ומאתחל את ה-SMB Client לאחר התנתקות VPN.",
    toolDrivesBtn: "שחרר כונני רשת",
    confirmDrivesTitle: "אישור שחרור כונני רשת",
    confirmDrivesDesc: "פעולה זו תנתק כונני רשת ממופים תקועים (net use * /delete) ותאתחל את שירות שיתוף הקבצים המקומי (LanmanWorkstation).\n\nהאם להמשיך?",

    toolProxyTitle: "איפוס הגדרות Proxy ו-WinHTTP לאחר VPN",
    toolProxyBadge: "תקשורת ו-VPN",
    toolProxyDesc: "מחזיר גלישה ישירה ע\"י איפוס שרתי Proxy וקובצי PAC של VPN שנשארו תקועים בהגדרות המערכת.",
    toolProxyBtn: "אפס הגדרות Proxy",
    confirmProxyTitle: "אישור איפוס הגדרות Proxy",
    confirmProxyDesc: "פעולה זו תאפס את הגדרות ה-Proxy של Windows וה-WinHTTP לברירת מחדל של חיבור ישיר (Direct Connection).\n\nמתאים במיוחד כאשר הגישה לאינטרנט נחסמת לאחר התנתקות מחיבור VPN.\n\nהאם להמשיך?",

    toolIntuneTitle: "סנכרון מאולץ של סוכן Microsoft Intune (IME)",
    toolIntuneBadge: "ניהול מכשירים",
    toolIntuneDesc: "מפעיל מחדש את שירות IntuneManagementExtension ומאלץ בדיקת מדיניות והתקנת אפליקציות מיידית.",
    toolIntuneBtn: "סנכרן Intune כעת",
    confirmIntuneTitle: "אישור סנכרון Microsoft Intune",
    confirmIntuneDesc: "פעולה זו תפעיל מחדש את שירות Intune Management Extension ותריץ משימת בדיקת מדיניות והפצת תוכנות מיידית.\n\nהאם להמשיך?",

    toolSpoolerTitle: "איפוס שירות והורדת מסמכים תקועים (Spooler Purge)",
    toolSpoolerBadge: "מדפסות",
    toolSpoolerDesc: "סוגר את ה-Spooler, מוחק את כל קובצי ההדפסה התקועים בדיסק (*.spl, *.shd) ומפעיל אותו מחדש.",
    toolSpoolerBtn: "אפס תור מדפסות",
    confirmSpoolerTitle: "אישור איפוס תור מדפסות",
    confirmSpoolerDesc: "פעולה זו תעצור את שירות ההדפסה של Windows, תמחק את כל מסמכי ההדפסה התקועים בתור מהדיסק, ותפעיל את השירות מחדש.\n\nהאם להמשיך?",

    toolCertTitle: "איפוס מטמון תעודות אבטחה ורשימות ביטול (CRL / OCSP)",
    toolCertBadge: "אבטחה ותעודות",
    toolCertDesc: "מנקה את מטמון ה-CRL וה-OCSP של Windows לאימות מיידי של תעודות SSL ארגוניות שחודשו.",
    toolCertBtn: "נקה מטמון תעודות",
    confirmCertTitle: "אישור ניקוי מטמון תעודות אבטחה",
    confirmCertDesc: "פעולה זו תמחק את מטמון רשימות הביטול (certutil -urlcache * delete) כדי לאפשר ל-Windows לקבל תעודות SSL ארגוניות מחודשות.\n\nהאם להמשיך?",

    /* Settings */
    settingsGeneral: "העדפות תצוגה",
    settingsGeneralDesc: "שפת הממשק וקצב דגימת הנתונים החיים.",
    settingLang: "שפת ממשק",
    settingLangDesc: "מחליף בין עברית (ימין לשמאל) לאנגלית (שמאל לימין).",
    settingRefresh: "קצב רענון נתונים",
    settingRefreshDesc: "תדירות דגימת הזיכרון ורשימת התהליכים. קצב איטי יותר מפחית עומס מעבד.",
    rate1: "כל שנייה",
    rate2: "כל 2 שניות",
    rate5: "כל 5 שניות",
    rate0: "מושהה",
    settingsData: "נתונים ודוחות",
    settingsDataDesc: "ייצוא תמונת מצב של הזיכרון, האבחון והתהליכים.",
    settingExport: "ייצוא דוח תמונת מצב",
    settingExportDesc: "שומר קובץ JSON עם נתוני הזיכרון, ממצאי האבחון ו-30 התהליכים הכבדים.",
    btnExport: "ייצא",
    settingsAbout: "אודות",
    aboutVersion: "גרסה",
    aboutPrivileges: "הרשאות",
    aboutAuthor: "פותח על ידי",
    aboutPrivacy: "Polaris מאזין רק על 127.0.0.1, אינו נגיש מהרשת ואינו שולח נתונים החוצה. כל הנכסים ארוזים מקומית והתוכנה עובדת גם ללא אינטרנט.",

    /* Process modal */
    modalWhatIsIt: "מה התהליך הזה עושה",
    modalWhyMemory: "למה הוא בזיכרון:",
    modalKillStatus: "סיום התהליך",
    modalServices: "שירותי Windows שרצים בתוך התהליך",
    modalRss: "זיכרון פעיל",
    modalVms: "זיכרון וירטואלי",
    modalPct: "% מה-RAM",
    modalCpu: "מעבד",
    modalPath: "נתיב קובץ מלא",
    modalCmd: "שורת הפקודה",
    modalTrim: "שחרור זיכרון עבודה",
    safeToKill: "בטוח לסגירה",
    protectedProc: "רכיב מערכת מוגן",
    safeToKillDesc: "סגירת תהליך זה אינה פוגעת ביציבות Windows.",
    protectedProcDesc: "סגירתו עלולה לפגוע ביציבות מערכת ההפעלה.",
    loadingDeep: "טוען ניתוח מעמיק...",
    checkingDetails: "בודק פרטי מערכת...",
    groupOf: "קבוצה",

    /* Crash modal */
    crashRootCause: "אבחון שורש הבעיה",
    crashCode: "קוד שגיאה (BugCheck)",
    crashDriver: "דרייבר / רכיב אחראי",
    crashSolution: "המלצות מעשיות לפתרון",
    crashRaw: "יומן אירועים מקורי",

    /* Toasts */
    toastFreedTitle: "שחרור זיכרון הושלם",
    toastFreedSuccess: "שוחררו",
    toastFreedNothing: "הזיכרון כבר מיועל.",
    toastScanDone: "סריקה הושלמה",
    toastScanDoneMsg: "נתוני האבחון עודכנו.",
    toastMaintDone: "תחזוקה הושלמה",

    /* Theme */
    settingTheme: "ערכת נושא",
    settingThemeDesc: "בחירתך נשמרת ונטענת אוטומטית בהפעלה הבאה.",
    themeDark: "כהה",
    themeLight: "בהיר",

    /* Hardware navigation & screens */
    navGroupHardware: "חומרה",
    navDisks: "בריאות כוננים",
    navDevices: "דרייברים והתקנים",
    navEvents: "יומן שגיאות",
    scrDisksTitle: "בריאות כוננים",
    scrDisksDesc: "מה הכוננים עצמם מדווחים על מצבם, ולפני כמה זמן",
    scrDevicesTitle: "דרייברים והתקנים",
    scrDevicesDesc: "התקנים תקולים ודרייברים שעברו זמנם",
    scrEventsTitle: "יומן שגיאות מערכת",
    scrEventsDesc: "שגיאות חוזרות שמתעדת Windows, ממוינות לפי חשיבות",
    scanning: "סורק...",

    /* Drive health */
    disksVerdictTitle: "מצב הכוננים",
    disksVerdictDesc: "נתוני S.M.A.R.T. שהכוננים עצמם מדווחים: בלאי, טמפרטורה, סקטורים פגומים ושעות פעילות.",
    disksLimitedTitle: "נתוני S.M.A.R.T. חלקיים",
    disksLimitedDesc: "מוני האמינות של הכוננים (בלאי, טמפרטורה, סקטורים פגומים) דורשים הרשאות מנהל. הפעל את Polaris כמנהל כדי לראות אותם. נתוני הקיבולת מוצגים כרגיל.",
    disksNone: "לא אותרו כוננים",
    disksNoneDesc: "Windows לא החזירה מידע על כוננים פיזיים במחשב הזה",
    driveLife: "תוחלת חיים שנותרה",
    driveWear: "בלאי",
    driveTemp: "טמפרטורה",
    driveHours: "שעות פעילות",
    driveAbout: "כ-",
    driveYears: "שנים",
    driveErrors: "שגיאות שלא תוקנו",
    driveErrorsNote: "קריאה וכתיבה יחד",
    driveNoLabel: "ללא תווית",
    driveFreeOf: "פנוי מתוך",
    driveNoVolumes: "אין אמצעי אחסון עם אות כונן בכונן הזה.",
    driveHealthy: "תקין",
    driveUnknown: "לא ידוע",
    driveWrites: "סך כתיבות (TBW)",
    driveReads: "סך קריאות",
    drivePowerCycles: "מחזורי הפעלה",
    driveUnsafeShutdowns: "כיבויים פתאומיים",
    driveMediaErrors: "שגיאות מדיה",
    driveFirmware: "קושחה",
    btnShowSmart: "הצג מאפייני S.M.A.R.T. מלאים",
    btnHideSmart: "הסתר מאפייני S.M.A.R.T.",
    thSmartId: "מזהה",
    thSmartAttr: "מאפיין S.M.A.R.T.",
    thSmartCurrent: "נוכחי",
    thSmartWorst: "גרוע ביותר",
    thSmartThresh: "סף",
    thSmartRaw: "ערך גולמי",
    thSmartStatus: "מצב",
    smartGood: "תקין",
    smartCaution: "אזהרה",
    smartBad: "סכנה",

    /* Devices & drivers */
    devicesProblemTitle: "התקנים ש-Windows סימנה כתקולים",
    devicesProblemDesc: "אלה המשולשים הצהובים ב-Device Manager, מתורגמים מקוד תקלה מספרי להסבר ולפעולה מומלצת.",
    devicesStaleTitle: "דרייברים ישנים",
    devicesStaleDesc: "דרייברים בני יותר מארבע שנים לכרטיס מסך, רשת או אחסון. דרייברים מובנים של Microsoft אינם נכללים — התאריך שלהם הוא תאריך שחרור Windows ואינו מעיד על גיל.",
    devicesAllOk: "כל ההתקנים פועלים כשורה",
    devicesAllOkDesc: "Windows לא סימנה אף התקן כתקול או חסר דרייבר",
    deviceProblemCode: "קוד",
    deviceInstanceId: "מזהה ההתקן",
    driversInstalled: "דרייברים מותקנים",
    driversAllCurrent: "אין דרייברים ישנים במיוחד",
    driversAllCurrentDesc: "כל הדרייברים של כרטיס המסך, הרשת והאחסון עודכנו בארבע השנים האחרונות.",
    crashDriverMeans: "מה זה בפועל",
    crashDriverUnknown: "Polaris לא מזהה את קובץ הדרייבר הזה, ולכן לא ינחש למה הוא שייך.",
    crashDriverInstalled: "הגרסה המותקנת",

    /* Event log */
    eventsTotalLabel: "שגיאות בסך הכל",
    eventsActionableLabel: "דורשות טיפול",
    eventsNoiseLabel: "רעש מוכר ולא מזיק",
    eventsTitle: "שגיאות חוזרות ביומן האירועים",
    eventsDesc: "השגיאות מקובצות לפי מקור ומזהה אירוע ומדורגות לפי חשיבות, לא לפי כמות — כך ששגיאת דיסק בודדת לא נבלעת בין מאה הודעות רעש.",
    eventsShowNoise: "הצג גם רעש",
    events7: "7 ימים",
    events14: "14 ימים",
    events30: "30 ימים",
    eventsTimes: "פעמים",
    eventsLast: "אחרון:",
    eventsFirst: "ראשון:",
    eventsRaw: "ההודעה המקורית",
    eventsUnknown: "לא מזוהה",
    eventsClean: "יומן האירועים נקי",
    eventsCleanDesc: "לא נרשמו שגיאות או אירועים קריטיים בטווח הזמן שנבחר.",
    eventsOnlyNoise: "רק רעש מוכר ולא מזיק",
    eventsOnlyNoiseDesc: "כל השגיאות שנרשמו הן כאלה שמופיעות בכל מחשב Windows תקין. סמן \"הצג גם רעש\" כדי לראות אותן.",

    /* Uninstaller */
    lblTotalApps: "סה״כ תוכנות מותקנות",
    lblTotalSpace: "נפח דיסק תפוס משוער",
    lblWin32Apps: "תוכנות Desktop (Win32)",
    lblUwpApps: "אפליקציות חנות (UWP)",
    uninstallerCardTitle: "מסיר תוכנות וניקוי שאריות עמוק",
    uninstallerCardDesc: "הסרה מלאה של תוכנות, כולל נקודת שחזור, גיבוי Registry, סריקת שאריות מבוססת דפוסים (Safe/Moderate/Advanced), הסרה כפויה ומיקוד ידני",
    btnBackupCenter: "מרכז גיבויים ושחזור",
    btnHunterMode: "מיקוד ידני",
    btnUninstall: "הסר",
    btnForcedUninstall: "הסרה כפויה",
    btnBatchUninstall: "הסרה מרוכזת (Batch)",
    filterAll: "הכל",
    filterWin32: "תוכנות Desktop",
    filterUwp: "אפליקציות Windows",
    filterHeavy: "תוכנות כבדות (>500MB)",
    btnSelectAll: "בחר הכל",
    btnClearSelection: "נקה בחירה",
    chkSkipRpBatch: "דלג על יצירת נקודת שחזור",
    btnExecuteBatch: "הסר את כל הנבחרים ברצף",
    thAppName: "שם התוכנה",
    thAppPublisher: "יצרן / מפתח",
    thAppVersion: "גרסה",
    thAppDate: "תאריך התקנה",
    thAppSize: "גודל משוער",
    loadingApps: "טוען רשימת תוכנות מותקנות...",
    wizSafetyHeader: "שכבות אבטחה וגיבוי מקדים (Revo Safety Net)",
    wizRestorePointLabel: "נקודת שחזור מערכת (VSS)",
    wizRestorePointDesc: "יוצר נקודת שחזור מערכת רשמית של Windows למקרה של תקלה.",
    wizBtnSkipRpOnly: "דלג על שחזור מערכת זה",
    wizRegBackupLabel: "גיבוי מלא של ענפי ה-Registry",
    wizRegBackupDesc: "מייצא קובץ .reg וסקריפט שחזור Restore.bat לשחזור בלחיצה אחת.",
    wizScanModeHeader: "עומק סריקת השאריות",
    wizScanModeDesc: "בחר את האלגוריתם לאיתור שאריות רישום וקבצים שיישארו לאחר המסיר המקורי:",
    modeSafeTitle: "Safe (בטוח)",
    modeSafeDesc: "סריקה מהירה של מפתחות וקבצים וודאיים בלבד. אפס סיכון.",
    modeModerateTitle: "Moderate (בינוני - מומלץ)",
    modeModerateDesc: "כולל תיקיות התקנה, AppData, משתפי רישום ונתיבים נפוצים.",
    modeAdvancedTitle: "Advanced (מתקדם)",
    modeAdvancedDesc: "סריקה עמוקה של כל ה-Registry, CLSID, ושירותי מערכת נלווים.",
    wizSkipTip: "השלב מתעכב או אינו מגיב? ניתן לדלג עליו באופן מיידי:",
    btnSkipCurrentStep: "דלג על שלב זה (Skip)",
    wizBoldRuleBadge: "פריטים מודגשים בטוחים למחיקה",
    tabRegLeftovers: "רישום Windows (Registry)",
    tabFilesLeftovers: "קבצים ותיקיות (Files)",
    tabTasksLeftovers: "משימות מתוזמנות (Tasks)",
    btnSelectBoldOnly: "בחר רק מודגשים (Bold - בטוח)",
    wizDoneTitle: "ההסרה וניקוי השאריות הושלמו בהצלחה",
    lblRegKeysRemoved: "מפתחות רישום שנמחקו",
    lblTasksRemoved: "משימות מתוזמנות שנמחקו",
    lblFilesRemoved: "קבצים ותיקיות שנמחקו",
    wizRebootTitle: "קבצים תוזמנו למחיקה באתחול",
    wizRebootDesc: "חלק מהקבצים היו נעולים ע״י Windows ותוזמנו למחיקה אוטומטית בהפעלה מחדש באמצעות MoveFileEx",
    btnSkipRpAndStart: "דלג על שחזור והסר מיד",
    btnStartUninstall: "התחל הסרה מלאה",
    btnDeleteSelectedLeftovers: "מחק שאריות נבחרות",
    forcedModalTitle: "הסרה כפויה (Forced Uninstall)",
    forcedModalDesc: "הסרת תוכנות עיקשות, פגומות או כאלו שאינן מופיעות ברשימת ההסרה של Windows.",
    lblForcedTarget: "שם התוכנה או נתיב מלא לקובץ / תיקייה:",
    btnScanForced: "סרוק שאריות בכפייה",
    hunterModalTitle: "מיקוד ידני (Hunter Mode)",
    hunterModalDesc: "זיהוי מטרות ישיר לפי תהליך פעיל, חלון או נתיב קובץ וביצוע פעולות מיידיות.",
    hunterSelectProcess: "בחר תהליך פעיל או הקלד נתיב/PID:",
    btnHunterResolve: "זהה מטרה",
    hunterTargetLabel: "פרטי המטרה שזוהתה",
    hunterActionsHeader: "פעולות זמינות למטרה",
    btnHunterKill: "סיים תהליך (Kill Process)",
    btnHunterKillDelete: "סיים ומחק קובץ (Kill & Delete)",
    btnHunterForced: "הסרה כפויה מלאה (Forced Uninstall)",
    btnHunterDisableStartup: "בטל הפעלה באתחול (Disable Startup)",
    backupModalTitle: "מרכז גיבויים ושחזור (Backup Center)",
    backupModalDesc: "גיבויי Registry שנוצרו לפני הסרות. שחזור בלחיצה אחת או בסביבת WinRE במצב לא מקוון.",
    thBackupDate: "תאריך ושעה",
    thBackupApp: "תוכנה",
    thBackupFiles: "קבצי גיבוי",
    thBackupOffline: "שחזור WinRE",
    loadingBackups: "טוען היסטוריית גיבויים...",

    /* Storage Analyzer */
    navStorage: "סייר אחסון",
    scrStorageTitle: "סייר אחסון חכם",
    scrStorageDesc: "מציג מה תופס מקום בכונן: תרשים מעגלי אינטראקטיבי (Sunburst), מפת שטחים (Treemap) וסל איסוף למחיקה",
    storageTitle: "סייר אחסון חכם",
    storageSub: "מנתח מה תופס מקום בכונן ומאפשר למחוק ישירות מהתרשים: תרשים מעגלי, מפת שטחים ופילוח לפי סוג קובץ",
    storageHideSystem: "הסתר קבצי מערכת חיוניים",
    storageSystemBadge: "מערכת",
    storageSystemProtectedTooltip: "קובץ מערכת מוגן של Windows - לא ניתן למחיקה",
    storageOneDriveBadge: "OneDrive",
    storageOneDriveTooltip: "קובץ מסונכרן בענן של OneDrive",

    /* Terms of Use & EULA */
    termsTitle: "תקנון תנאי שימוש ורישיון (EULA)",
    termsSub: "הסכם רישיון משתמש קצה, מדיניות וזכויות בלעדיות ליקיר לביא",
    sidebarTerms: "תקנון ותנאי שימוש",
    btnViewTerms: "צפה בתקנון ובתנאי השימוש",
    termsModalTitle: "תקנון תנאי שימוש והסכם רישיון (EULA)",
    termsModalSub: "תוכנת Polaris • בעל הזכויות והמפתח: יקיר לביא",
    termsAgreementNote: "השימוש בתוכנה מהווה הסכמה מלאה ובלתי חוזרת לתנאים אלו.",
    storageBadgeSquirrel: "Sunburst & Collector",
    storageIdle: "ממתין לסריקה",
    storageScanning: "סורק כונן...",
    storagePaused: "מושהה",
    storageCompleted: "סריקה הושלמה",
    storageCancelled: "סריקה בוטלה",
    storageStartScan: "התחל סריקה",
    storageScanCustom: "סריקת תיקייה ספציפית:",
    loadingDrives: "טוען כוננים...",
    collectorTitle: "סל איסוף למחיקה (Collector)",
    collectorClear: "נקה בחירה",
    collectorDropPrompt: "גרור לכאן קבצים/תיקיות למחיקה או לחץ על ➕ ברשימה",
    collectorBtnDelete: "מחק פריטים (Recycle Bin)",
    storageScannedFiles: "קבצים:",
    storageScannedFolders: "תיקיות:",
    storageScannedSize: "גודל שנסרק:",
    storageScanRate: "מהירות:",
    storageTime: "זמן:",
    storageScannedSpace: "נסרק:",
    storageFreeSpace: "פנוי:",
    storageUnknownSpace: "שטח נסתר (<Unknown>):",
    storageTotalDrive: "סך הכונן:",
    storageTabSunburst: "🪐 תרשים מעגלי (Sunburst)",
    storageTabTreemap: "📊 עץ תיקיות ומפת שטחים (Treemap)",
    storageTabTop: "🏆 100 הקבצים הגדולים",
    storageTabDupes: "👯 איתור כפילויות",
    storageTabClean: "🧹 פעולות ניקוי מהירות",
    storageTreeTitle: "עץ התיקיות",
    storageExtTitle: "פילוח סיומות (מקרא צבעים)",
    storageColName: "שם",
    storageColProportion: "יחס גודל",
    storageColSize: "גודל",
    storageColFiles: "קבצים",
    storageColSubdirs: "תיקיות",
    storageColExt: "סיומת",
    storageColPath: "נתיב מלא",
    storageNoScanYet: "הפעל סריקה כדי לצפות בנתונים",
    storageNoExts: "אין נתוני סיומות עדיין",
    storageTopTitle: "100 הקבצים הגדולים ביותר בכונן",
    storageDupesTitle: "איתור קבצים כפולים (Duplicate Finder)",
    storageDupesSub: "סריקה מהירה בשני שלבים: בדיקת גודל זהה, גיבוב דליל (Sparse Hash), ואימות SHA-256 מלא.",
    storageMinSize: "גודל מינימלי:",
    storageBtnScanDupes: "חפש כפילויות עכשיו",
    storageDupesPrompt: "לחץ על 'חפש כפילויות עכשיו' כדי למצוא קבצים זהים שתופסים שטח כפול בדיסק.",
    storageExportCsv: "ייצא דו״ח CSV",

    /* OEM Updates */
    navOemUpdates: "עדכוני יצרן (OEM)",
    oemDesc: "סריקה והתקנה אוטומטית של דרייברים ועדכוני BIOS מכלי היצרן הרשמי",

    /* Windows Updates Show / Hide */
    navWuHide: "הסתרת עדכוני Windows",
    wuHideDesc: "חסימה ושחרור של עדכונים ספציפיים ודרייברים ב-Windows Update",
    bannerOemPromoTitle: "עדכון דרייברים וקושחה רשמיים",
    bannerOemPromoDesc: "הרץ סריקה והתקנה אוטומטית של דרייברים ועדכוני BIOS דרך כלי היצרן הרשמי (Dell, Lenovo, HP).",
    btnGoToOemUpdates: "עבור לעדכוני יצרן",
    oemHardwareTitle: "יצרן ומודל המחשב",
    oemHardwareSub: "זיהוי אוטומטי מלוח האם ו-BIOS",
    oemDetectedBrand: "מותג מזוהה",
    oemModel: "דגם / סדרה",
    oemOverride: "החלפה ידנית:",
    oemToolTitle: "כלי העדכון הרשמי",
    oemToolSub: "DCU / TVSU / HPIA / SDIO",
    oemToolName: "כלי נבחר",
    oemToolPath: "נתיב:",
    oemActionTitle: "הפעלת עדכונים",
    oemActionSub: "סריקה והתקנה אוטומטית מלאה",
    oemOptTwoPasses: "סבב השלמות כפול (2 Passes)",
    oemOptWinOptional: "כולל דרייברים מ-Windows Update",
    btnStartOemUpdates: "הפעל עדכוני יצרן",
    btnRunningOemUpdates: "עדכונים פועלים...",
    oemLiveLogTitle: "מסוף ביצוע חי",
    oemReady: "מוכן להפעלת עדכונים.",
    btnClearLog: "נקה מסוף",
    oemStatusInstalled: "מותקן ומוכן לשימוש",
    oemStatusMissing: "לא מותקן (יותקן אוטומטית)",
    oemStatusInstalling: "מתקין כלי יצרן...",
    oemCompleted: "סבב עדכוני היצרן הושלם בהצלחה!",
    oemError: "שגיאה במהלך עדכוני היצרן",
    oemCancelled: "עדכוני היצרן בוטלו על ידי המשתמש",
    oemRebootRequired: "נדרש אתחול של המחשב להשלמת התקנת הדרייברים/BIOS."
  },

  en: {
    /* Navigation */
    navGroupMonitor: "Monitor",
    navOverview: "Overview",
    navProcesses: "Processes & Services",
    navMemory: "Memory Analysis",
    navGroupSystem: "System",
    navMaintenance: "Maintenance & Repair",
    navUninstaller: "Uninstaller",
    navStartup: "Startup Apps",
    navCrashes: "Crashes & BSOD",
    navGroupTools: "Tools",
    navTools: "Useful Tools",
    navSettings: "Settings",

    /* Consolidated Categories */
    catPerformanceTitle: "Performance & Resources",
    catPerformanceDesc: "Managing active processes, Windows services, and in-depth RAM and kernel diagnostics",
    catStorageTitle: "Drives & Storage",
    catStorageDesc: "Drive health from S.M.A.R.T telemetry, plus a visual storage explorer for finding heavy files",
    catMaintenanceTitle: "Maintenance & Software",
    catMaintenanceDesc: "System file repair, cache cleanup, program removal with leftovers, and startup app management",
    catDiagnosticsTitle: "Diagnostics & Stability",
    catDiagnosticsDesc: "Crash analysis, Blue Screen of Death (BSOD) decoding, and the Windows error log",
    catHardwareTitle: "Hardware & Devices",
    catHardwareDesc: "Device Manager, driver health, and battery condition",
    catSettingsTitle: "Tools & Settings",
    catSettingsDesc: "Useful tools (OneDrive reset, Copilot remap) and app preferences",

    navPerformance: "Performance & Resources",
    navStorageGroup: "Drives & Storage",
    navMaintenanceGroup: "Maintenance & Software",
    navDiagnosticsGroup: "Diagnostics & Stability",
    navHardwareGroup: "Hardware & Devices",
    navSettingsGroup: "Tools & Settings",
    navGroupCore: "Core & Resources",
    navGroupDiagnostics: "Diagnostics & Hardware",
    navBattery: "Battery Health",
    navStorageTree: "Disk Explorer",

    /* Screen headers */
    scrOverviewTitle: "Overview",
    scrOverviewDesc: "Memory and system health at a glance",
    scrProcessesTitle: "Processes & Services",
    scrProcessesDesc: "What is running, how much it costs, and what you can close",
    scrMemoryTitle: "Memory Analysis",
    scrMemoryDesc: "Why memory is occupied - findings, kernel pools and breakdown",
    scrMaintenanceTitle: "Maintenance & Repair",
    scrMaintenanceDesc: "Official Microsoft tools for cleanup, repair and reset",
    scrUninstallerTitle: "Uninstaller & Leftover Cleaner",
    scrUninstallerDesc: "Clean uninstallation, restore points, registry backups & deep leftover cleaner",
    scrStartupTitle: "Startup Apps",
    scrStartupDesc: "What boots with Windows and how much it slows startup",
    scrCrashesTitle: "Crashes & BSOD",
    scrCrashesDesc: "Blue screen decoding, BugCheck codes and power-loss events",
    scrToolsTitle: "Useful Tools",
    scrToolsDesc: "Microsoft OneDrive reset, Icon Cache rebuild & Enterprise IT Toolkit",
    scrSettingsTitle: "Settings",
    scrSettingsDesc: "Language, refresh rate, data export and version details",

    /* Shared */
    loading: "Loading...",
    btnRefresh: "Refresh",
    btnClose: "Close",
    btnCancel: "Cancel",
    btnKill: "End Task",
    btnOptimize: "Trim Memory",
    btnDeepScan: "Rescan",
    optimizing: "Trimming...",
    details: "Details",
    procsShort: "procs",
    svcsShort: "svcs",

    /* Privileges */
    privChecking: "Checking privileges...",
    privAdmin: "Running as Administrator",
    privLimited: "Standard privileges",
    privAdminTip: "All repair tools are available.",
    privLimitedTip: "Repair tools (DISM, SFC, network, spooler, TRIM) will raise their own UAC prompt or silently fail.",

    /* Overview */
    scoreCap: "Score",
    diagTitle: "System Health",
    diagScanning: "Scanning background processes, kernel pools and active services.",
    physicalRamTitle: "Physical memory in use",
    memoryLoad: "Memory load:",
    usedRam: "In use",
    availableRam: "Available",
    cachedRam: "Standby cache",
    totalRam: "Installed",
    loadNormal: "Normal",
    loadModerate: "Moderate",
    loadHigh: "High",
    attentionTitle: "Needs attention",
    attentionDesc: "The most significant findings from the latest scan.",
    attentionFoot: "Full findings, kernel pools and breakdown",
    attentionLink: "Full memory analysis",
    attentionNone: "No unusual findings. Memory is being managed normally.",
    timelineTitle: "Memory usage history",
    timelineDesc: "Last 60 seconds, sampled every second.",
    legendUsed: "In use (GB)",
    legendCached: "Standby (GB)",
    topHogsTitle: "Largest memory consumers",
    topHogsDesc: "The programs holding the largest share of memory right now",
    topHogsLink: "All processes",

    /* Battery Overview */
    batteryScoreCap: "Health",
    batteryCardTitle: "Battery Health & Power",
    batteryScanning: "Calculating design capacity vs. full charge capacity, wear and cycle count.",
    btnRefreshBattery: "Refresh Battery",
    batteryChargeLevel: "Current Charge Level",
    batteryStatusLabel: "Power State:",
    batteryFullCapacity: "Full Charge Capacity",
    batteryDesignCapacity: "Design Capacity",
    batteryWearLevel: "Wear Level",
    batteryCycleCount: "Cycle Count",
    batteryEstimatedTime: "Estimated Runtime",
    desktopNoBatteryTitle: "Desktop PC / No Battery",
    desktopNoBatteryDesc: "System is connected directly to AC power. No battery wear monitoring required.",
    batteryStatusPlugged: "Plugged in",
    batteryStatusCharging: "Charging",
    batteryStatusDischarging: "Discharging (On Battery)",
    batteryCyclesUnit: "cycles",
    batteryGood: "Good condition",

    /* Processes */
    processExplorerTitle: "Process Manager & Windows Services",
    processExplorerDesc: "Active processes, Windows service mapping and resource allocation.",
    btnGrouped: "Grouped by app",
    btnFlat: "Flat PID list",
    searchPlaceholder: "Search process, service or PID...",
    catAll: "All",
    catBrowsers: "Browsers",
    catDevelopment: "Development",
    catSystem: "System services",
    catApps: "Applications",
    thProcessName: "Process / Application",
    thCategory: "Category",
    thRam: "Working set",
    thRamPercent: "% of RAM",
    thCpu: "CPU",
    thActions: "Actions",
    noProcs: "No matching processes",
    noProcsDesc: "Try clearing the search or picking a different category.",
    confirmKillTitle: "Terminate Process",
    confirmKillGroupTitle: "Terminate Application Group",

    /* Memory analysis */
    findingsTitle: "Diagnostic findings",
    findingsDesc: "Everything the engine identified as a possible cause of high memory usage, with a recommended action.",
    kernelTitle: "Kernel, drivers & pagefile",
    kernelDesc: "Memory that belongs to no visible process - this is where driver leaks surface.",
    descNonPaged: "Resident driver memory that can never be paged to disk",
    descPaged: "Kernel memory that can be moved to the pagefile",
    driverLeakNote: "Driver leak monitor:",
    driverLeakOk: "Healthy, no leak",
    driverLeakWarn: "Elevated driver pool",
    nppOk: "Normal",
    nppHigh: "High",
    categoryDonutTitle: "Memory breakdown by category",
    categoryDonutDesc: "Where the occupied memory goes, grouped by software type.",

    /* Maintenance */
    repairSafetyTitle: "Every action here uses official Microsoft tooling",
    repairSafetyNote: "Personal files, documents, photos, the desktop and installed software are fully preserved.",
    btnAuditScan: "Scan state",
    lblAuditTemp: "Temp & cache files",
    lblAuditRecoverable: "Recoverable",
    lblAuditStartup: "Startup applications",
    lblAuditTrim: "SSD optimization",
    auditReady: "Ready",
    auditTrimNote: "Re-align free blocks",
    lblAuditDism: "Windows component store",
    auditDismNote: "Shrink WinSxS and update backups",
    auditScanning: "Scanning...",
    auditHighImpact: "high impact",
    txtActionCenterTitle: "Select maintenance & repair tasks",
    txtActionCenterDesc: "Tick the tasks you want, then run them all in one click.",
    btnRunRevitalize: "Run maintenance",
    runningMaintenance: "Running maintenance...",
    groupCleanup: "Cleanup & disk space",
    groupIntegrity: "System integrity repair",
    groupServices: "Network & services",
    lblChkCleanTemp: "Clean temp files and stale cache",
    descChkCleanTemp: "Deletes %TEMP%, SoftwareDistribution/Download and dormant crash report caches.",
    lblChkDism: "Clean the Windows component store",
    descChkDism: "Removes superseded update backups and shrinks WinSxS. Slow — 4 to 20 minutes. Off by default.",
    lblChkRetrim: "Optimize SSD performance (TRIM)",
    descChkRetrim: "Re-aligns free blocks to preserve read and write speed.",
    lblChkFlushRam: "Trim working sets and standby pages",
    descChkFlushRam: "Instantly reclaims hundreds of megabytes of free RAM.",
    lblChkDismRestore: "Repair the Windows system image",
    descChkDismRestore: "Scans and restores corrupted Windows components. May take several minutes.",
    lblChkSfc: "Scan and repair corrupted system files",
    descChkSfc: "Checks every protected Windows core file and restores damaged copies.",
    lblChkFlushDns: "Flush the DNS cache",
    descChkFlushDns: "Resolves slow browsing and pages that will not load.",
    lblChkNetReset: "Deep reset of the network stack and Winsock",
    descChkNetReset: "Fixes repeated internet drops. Requires a restart.",
    lblChkWuReset: "Reset Windows Update services",
    descChkWuReset: "Restarts wuauserv, bits and cryptsvc and clears stuck downloads.",
    lblChkSpoolerReset: "Reset the print spooler and clear its queue",
    descChkSpoolerReset: "Clears a stuck print queue and restarts spoolsv.exe.",
    liveOutput: "Live command output",
    lblStepList: "Run steps",
    btnCopyLog: "Copy log",
    btnPreviewScan: "Scan without uninstalling",
    btnFinishAndClose: "Finish and close",
    totalFreed: "Total freed:",

    /* Startup */
    txtStartupExplorerTitle: "Programs that launch with Windows",
    txtStartupExplorerDesc: "Applications started automatically at boot, ranked by their impact on startup time.",
    startupSafeNote: "Read only",
    noStartup: "No active startup applications found in the registry.",
    impactSuffix: "impact",

    /* Crashes */
    lblTotalCrashes: "Crash events in 30 days",
    lblBsodCount: "Blue screens (BSOD)",
    lblPowerLossCount: "Power loss (Kernel-Power)",
    txtCrashInspectorTitle: "Crash history & blue screen decoder",
    txtCrashInspectorDesc: "Automatic analysis of minidumps, BugCheck codes and power-loss reboots from the event log, with root cause and recommendations.",
    txtBtnMemDiag: "RAM hardware test",
    healthStable: "System stable",
    healthBsod: "Blue screens detected",
    healthPower: "Power losses detected",
    noCrashes: "No crashes or power losses detected",
    noCrashesDesc: "The event log is clean of severe kernel errors over the last 30 days.",
    crashDetailsBtn: "Details & fix",
    crashCodeShort: "Code:",
    crashDriverShort: "Component:",

    /* Keyboard tools */
    copilotKeyTitle: "Remap the Copilot key to Right Ctrl",
    copilotKeyDesc: "Turns the hardware Copilot key (which emits Win+Shift+F23) into a standard Right Ctrl. Runs automatically on every boot without keeping Polaris open.",
    btnEnableCopilot: "Enable remap",
    btnDisableCopilot: "Disable remap",
    openWinSettings: "Open Windows keyboard settings",
    copilotStatusActive: "Active in Startup",
    copilotStatusInactive: "Inactive",
    lblCopilotFeat1: "0% system impact",
    descCopilotFeat1: "A tiny, invisible hook service. Persists and starts automatically after every restart.",
    lblCopilotFeat2: "No file lock",
    descCopilotFeat2: "Installed in isolation under AppData, so the original installer can be moved or deleted freely.",
    lblCopilotFeat3: "Survives restarts",
    descCopilotFeat3: "Supports continuous holding: Ctrl+C, Ctrl+V, editing shortcuts and gaming modifiers.",

    /* OneDrive reset */
    onedriveTitle: "Reset Microsoft OneDrive",
    onedriveDesc: "Closes OneDrive, deletes account configurations from the Windows Registry (Accounts), and clears local settings cache for a clean sign-in.",
    btnResetOneDrive: "Reset ONE DRIVE",
    openOneDriveApp: "Open OneDrive",
    onedriveStatusRunning: "Running in background",
    onedriveStatusStopped: "Stopped",
    lblOneDriveFeat1: "Immediate process termination",
    descOneDriveFeat1: "Forcefully stops OneDrive.exe to release file and registry locks.",
    lblOneDriveFeat2: "Registry Accounts deletion",
    descOneDriveFeat2: "Removes HKCU\\Software\\Microsoft\\OneDrive\\Accounts and unlinks all accounts.",
    lblOneDriveFeat3: "Cache clean & fresh boot",
    descOneDriveFeat3: "Cleans stuck settings caches for fresh setup. User synced files are never touched.",
    confirmOneDriveTitle: "Confirm Microsoft OneDrive Reset",
    confirmOneDriveDesc: "This will terminate OneDrive, delete all configured account settings in the Registry, and clear local settings cache.\n\nYour actual files on disk and in cloud will NOT be deleted.\n\nProceed with reset?",
    btnConfirmReset: "Reset OneDrive",

    /* Icon Cache Rebuild */
    iconCacheTitle: "Rebuild Icon & Thumbnail Cache",
    iconCacheDesc: "Restarts File Explorer, purges corrupted iconcache and thumbcache databases, and regenerates all file icons and previews.",
    btnRebuildIconCache: "Rebuild Icon Cache",
    lblIconCacheFeat1: "Explorer restart for lock release",
    descIconCacheFeat1: "Gracefully terminates explorer.exe to safely delete locked cache files.",
    lblIconCacheFeat2: "Purge IconCache & Thumbcache",
    descIconCacheFeat2: "Deletes icon database files in AppData, forcing Windows to regenerate clean icons.",
    lblIconCacheFeat3: "Instant Shell refresh (no reboot)",
    descIconCacheFeat3: "Broadcasts SHChangeNotify and restores desktop. Fixes blank icons immediately.",
    confirmIconCacheTitle: "Confirm Icon Cache Rebuild",
    confirmIconCacheDesc: "This will temporarily restart File Explorer, delete all corrupted icon and thumbnail databases, and reload the Windows shell.\n\nYour desktop may flicker briefly. Do you want to proceed?",
    btnConfirmRebuildIcon: "Rebuild Now",

    /* Enterprise IT Toolkit */
    enterpriseSuiteTitle: "Enterprise IT Toolkit",
    enterpriseSuiteDesc: "Instant remedies for high-impact enterprise IT issues across Active Directory, Entra ID, GPO, M365, file shares and network infrastructure.",
    enterpriseBadge: "11 Tools Available",

    toolKerberosTitle: "Purge Kerberos Tickets (Share Permissions)",
    toolKerberosBadge: "Active Directory",
    toolKerberosDesc: "Applies new Active Directory security group permissions to network shares without rebooting or logging off.",
    toolKerberosBtn: "Purge Kerberos Tickets",
    confirmKerberosTitle: "Confirm Kerberos Tickets Purge",
    confirmKerberosDesc: "This will purge locally cached Kerberos tickets (klist purge) and refresh NetBIOS names.\n\nNew AD permissions and security groups will take effect immediately without rebooting.\n\nDo you wish to proceed?",

    toolGpoTitle: "Force Sync & Reset Group Policy (GPO)",
    toolGpoBadge: "Group Policy",
    toolGpoDesc: "Purges corrupted local policy cache and executes full gpupdate /force against the Domain Controller.",
    toolGpoBtn: "Force GPO Sync",
    confirmGpoTitle: "Confirm Group Policy Sync",
    confirmGpoDesc: "This will clear corrupt local GPO caches and execute gpupdate /force against Domain Controllers.\n\nProceed?",

    toolCredsTitle: "Purge Stale Credentials (Prevent Account Lockout)",
    toolCredsBadge: "Account Security",
    toolCredsDesc: "Cleans stale domain and Microsoft 365 saved passwords from Credential Manager causing repeated AD lockouts.",
    toolCredsBtn: "Purge Stale Credentials",
    confirmCredsTitle: "Confirm Stale Credentials Purge",
    confirmCredsDesc: "This will remove stale saved enterprise and Office/M365 credentials from Credential Manager.\n\nThis stops repeated Active Directory account lockout loops. You may need to type your current password once.\n\nProceed?",

    toolEntraTitle: "Reset Entra ID / WAM Broker Loop",
    toolEntraBadge: "Microsoft 365",
    toolEntraDesc: "Resolves CAA50021 / CAA2000B loops and Teams/Outlook login failures by resetting BrokerPlugin token storage.",
    toolEntraBtn: "Reset Entra Auth Broker",
    confirmEntraTitle: "Confirm Entra ID WAM Broker Reset",
    confirmEntraDesc: "This closes Teams and Office processes, and resets the Entra ID WAM broker token cache.\n\nResolves blank login windows and CAA50021/CAA2000B errors. Synced files and emails are untouched.\n\nProceed?",

    toolTeamsTitle: "Reset Microsoft Teams (Fix Error 894893981 / Auth)",
    toolTeamsBadge: "Microsoft Teams",
    toolTeamsDesc: "Fixes Microsoft account sign-in failures, blank screens, and error 894893981 (Keyset does not exist) by resetting Teams cache, WAM Broker, and OneAuth.",
    toolTeamsBtn: "Reset Microsoft Teams",
    confirmTeamsTitle: "Confirm Microsoft Teams Reset",
    confirmTeamsDesc: "This will terminate Teams processes, clear local app caches (New Teams & Classic), and reset corrupted WAM TokenBroker and OneAuth tokens causing error 894893981 and sign-in loops.\n\nCloud chats and files are completely safe. Proceed?",

    toolOutlookTitle: "Reset Microsoft Outlook (Fix Error 894893981 / Profile)",
    toolOutlookBadge: "Microsoft Outlook",
    toolOutlookDesc: "Fixes error 894893981 (Keyset does not exist), password loops, and profile hangs by clearing SRS files, RoamCache, WAM Broker, and OneAuth without touching emails.",
    toolOutlookBtn: "Reset Microsoft Outlook",
    confirmOutlookTitle: "Confirm Microsoft Outlook Reset",
    confirmOutlookDesc: "This will close Outlook, remove corrupted Send/Receive (.SRS) files, RoamCache, Autodiscover, and reset corrupted WAM TokenBroker and OneAuth tokens causing error 894893981.\n\nMailbox data, PST/OST files, and emails are completely safe. Proceed?",

    toolDrivesTitle: "Reset Stuck Mapped Drives (SMB Client)",
    toolDrivesBadge: "File Shares",
    toolDrivesDesc: "Disconnects ghost red-X mapped drives and restarts the SMB workstation client after VPN disconnects.",
    toolDrivesBtn: "Reset Network Drives",
    confirmDrivesTitle: "Confirm Network Drives Reset",
    confirmDrivesDesc: "This will disconnect stuck mapped drives (net use * /delete) and restart the local SMB workstation service.\n\nProceed?",

    toolProxyTitle: "Reset Proxy & WinHTTP (Post-VPN)",
    toolProxyBadge: "Network & VPN",
    toolProxyDesc: "Restores direct connectivity by resetting WinHTTP system proxy and disabling leftover corporate VPN PAC files.",
    toolProxyBtn: "Reset Proxy / WinHTTP",
    confirmProxyTitle: "Confirm Proxy Reset",
    confirmProxyDesc: "This resets Windows system proxy and WinHTTP to direct connection.\n\nIdeal when Internet access fails after disconnecting from enterprise VPN.\n\nProceed?",

    toolIntuneTitle: "Force Microsoft Intune Agent Sync (IME)",
    toolIntuneBadge: "Endpoint Management",
    toolIntuneDesc: "Restarts Intune Management Extension service and triggers immediate policy & app evaluation.",
    toolIntuneBtn: "Force Intune Sync",
    confirmIntuneTitle: "Confirm Microsoft Intune Sync",
    confirmIntuneDesc: "This will restart the Intune Management Extension service and trigger immediate policy evaluation and app deployment.\n\nProceed?",

    toolSpoolerTitle: "Print Spooler & Queue Complete Purge",
    toolSpoolerBadge: "Printers",
    toolSpoolerDesc: "Stops spooler service, purges all locked print jobs from disk (*.spl, *.shd), and restarts cleanly.",
    toolSpoolerBtn: "Purge Print Queue",
    confirmSpoolerTitle: "Confirm Print Spooler Purge",
    confirmSpoolerDesc: "This will stop the Windows Print Spooler, delete all locked/stuck print spool files from disk, and restart the service.\n\nProceed?",

    toolCertTitle: "Purge Certificate Revocation List (CRL) Cache",
    toolCertBadge: "Certificates & SSL",
    toolCertDesc: "Flushes cached CRL and OCSP responses in Windows to immediately trust renewed internal SSL certs.",
    toolCertBtn: "Purge CRL Cache",
    confirmCertTitle: "Confirm Certificate Revocation Cache Purge",
    confirmCertDesc: "This will purge cached certificate revocation lists (certutil -urlcache * delete) so renewed SSL certs are trusted immediately.\n\nProceed?",

    /* Settings */
    settingsGeneral: "Display preferences",
    settingsGeneralDesc: "Interface language and live sampling rate.",
    settingLang: "Interface language",
    settingLangDesc: "Switches between Hebrew (right-to-left) and English (left-to-right).",
    settingRefresh: "Data refresh rate",
    settingRefreshDesc: "How often memory and the process list are sampled. A slower rate lowers CPU overhead.",
    rate1: "Every second",
    rate2: "Every 2 seconds",
    rate5: "Every 5 seconds",
    rate0: "Paused",
    settingsData: "Data & reports",
    settingsDataDesc: "Export a snapshot of memory, diagnostics and processes.",
    settingExport: "Export snapshot report",
    settingExportDesc: "Saves a JSON file with memory stats, diagnostic findings and the 30 heaviest processes.",
    btnExport: "Export",
    settingsAbout: "About",
    aboutVersion: "Version",
    aboutPrivileges: "Privileges",
    aboutAuthor: "Created by",
    aboutPrivacy: "Polaris listens only on 127.0.0.1, is unreachable from the network and sends nothing outbound. All assets are bundled locally, so it works fully offline.",

    /* Process modal */
    modalWhatIsIt: "What this process does",
    modalWhyMemory: "Why it is in memory:",
    modalKillStatus: "Terminating this process",
    modalServices: "Windows services hosted in this process",
    modalRss: "Working set",
    modalVms: "Virtual memory",
    modalPct: "% of RAM",
    modalCpu: "CPU",
    modalPath: "Full file path",
    modalCmd: "Command line",
    modalTrim: "Trim working set",
    safeToKill: "Safe to end",
    protectedProc: "Protected system process",
    safeToKillDesc: "Ending this process does not affect Windows stability.",
    protectedProcDesc: "Ending it may destabilize the operating system.",
    loadingDeep: "Loading deep analysis...",
    checkingDetails: "Checking system details...",
    groupOf: "Group",

    /* Crash modal */
    crashRootCause: "Root cause analysis",
    crashCode: "Error code (BugCheck)",
    crashDriver: "Responsible driver / component",
    crashSolution: "Recommended fixes",
    crashRaw: "Original event log entry",

    /* Toasts */
    toastFreedTitle: "Memory trimmed",
    toastFreedSuccess: "Reclaimed",
    toastFreedNothing: "Memory is already optimal.",
    toastScanDone: "Scan complete",
    toastScanDoneMsg: "Diagnostic data updated.",
    toastMaintDone: "Maintenance complete",

    /* Theme */
    settingTheme: "Theme",
    settingThemeDesc: "Your choice is saved and restored on the next launch.",
    themeDark: "Dark",
    themeLight: "Light",

    /* Hardware navigation & screens */
    navGroupHardware: "Hardware",
    navDisks: "Drive Health",
    navDevices: "Drivers & Devices",
    navEvents: "Error Log",
    scrDisksTitle: "Drive Health",
    scrDisksDesc: "What the drives themselves report about their condition, and for how long",
    scrDevicesTitle: "Drivers & Devices",
    scrDevicesDesc: "Faulty devices and drivers past their prime",
    scrEventsTitle: "System Error Log",
    scrEventsDesc: "Recurring errors Windows records, ranked by what matters",
    scanning: "Scanning...",

    /* Drive health */
    disksVerdictTitle: "Drive condition",
    disksVerdictDesc: "S.M.A.R.T. data reported by the drives themselves: wear, temperature, failing sectors and runtime.",
    disksLimitedTitle: "Partial S.M.A.R.T. data",
    disksLimitedDesc: "Drive reliability counters (wear, temperature, failing sectors) require Administrator. Run Polaris elevated to see them. Capacity data is shown normally.",
    disksNone: "No drives detected",
    disksNoneDesc: "Windows returned no information about physical drives on this machine.",
    driveLife: "Life remaining",
    driveWear: "Wear",
    driveTemp: "Temperature",
    driveHours: "Power-on hours",
    driveAbout: "about",
    driveYears: "years",
    driveErrors: "Uncorrected errors",
    driveErrorsNote: "read and write combined",
    driveNoLabel: "No label",
    driveFreeOf: "free of",
    driveNoVolumes: "No lettered volumes on this drive.",
    driveHealthy: "Healthy",
    driveUnknown: "Unknown",
    driveWrites: "Total Writes (TBW)",
    driveReads: "Total Reads",
    drivePowerCycles: "Power Cycles",
    driveUnsafeShutdowns: "Unsafe Shutdowns",
    driveMediaErrors: "Media Errors",
    driveFirmware: "Firmware",
    btnShowSmart: "Show Full S.M.A.R.T. Attributes",
    btnHideSmart: "Hide S.M.A.R.T. Attributes",
    thSmartId: "ID",
    thSmartAttr: "S.M.A.R.T. Attribute",
    thSmartCurrent: "Current",
    thSmartWorst: "Worst",
    thSmartThresh: "Threshold",
    thSmartRaw: "Raw Value",
    thSmartStatus: "Status",
    smartGood: "Good",
    smartCaution: "Caution",
    smartBad: "Bad",

    /* Devices & drivers */
    devicesProblemTitle: "Devices Windows flagged as faulty",
    devicesProblemDesc: "These are the yellow triangles in Device Manager, translated from a numeric problem code into an explanation and a suggested fix.",
    devicesStaleTitle: "Outdated drivers",
    devicesStaleDesc: "Drivers over four years old for graphics, network or storage. Microsoft inbox drivers are excluded — their date is the Windows release date and says nothing about age.",
    devicesAllOk: "Every device is working",
    devicesAllOkDesc: "Windows has not flagged any device as faulty or missing a driver.",
    deviceProblemCode: "Code",
    deviceInstanceId: "Device instance id",
    driversInstalled: "drivers installed",
    driversAllCurrent: "No unusually old drivers",
    driversAllCurrentDesc: "Every graphics, network and storage driver has been updated within the last four years.",
    crashDriverMeans: "What this actually is",
    crashDriverUnknown: "Polaris does not recognise this driver file and will not guess what it belongs to.",
    crashDriverInstalled: "Installed version",

    /* Event log */
    eventsTotalLabel: "Errors in total",
    eventsActionableLabel: "Need attention",
    eventsNoiseLabel: "Known harmless noise",
    eventsTitle: "Recurring errors in the event log",
    eventsDesc: "Errors are grouped by provider and event id and ranked by importance rather than volume, so a single disk error is not buried under a hundred noise messages.",
    eventsShowNoise: "Show noise too",
    events7: "7 days",
    events14: "14 days",
    events30: "30 days",
    eventsTimes: "times",
    eventsLast: "Last:",
    eventsFirst: "First:",
    eventsRaw: "Original message",
    eventsUnknown: "Unrecognised",
    eventsClean: "The event log is clean",
    eventsCleanDesc: "No errors or critical events were recorded in the selected period.",
    eventsOnlyNoise: "Only known, harmless noise",
    eventsOnlyNoiseDesc: "Every recorded error is one that appears on any healthy Windows machine. Tick \"Show noise too\" to see them.",

    /* Uninstaller */
    lblTotalApps: "Total Installed Apps",
    lblTotalSpace: "Estimated Disk Usage",
    lblWin32Apps: "Desktop Apps (Win32)",
    lblUwpApps: "Store Apps (UWP)",
    uninstallerCardTitle: "Software Uninstaller & Deep Leftover Cleaner",
    uninstallerCardDesc: "Complete program removal with a restore point, Registry backup, pattern-based leftover scanning (Safe/Moderate/Advanced), forced uninstall and manual targeting",
    btnBackupCenter: "Backup Center",
    btnHunterMode: "Hunter Mode",
    btnUninstall: "Uninstall",
    btnForcedUninstall: "Forced Uninstall",
    btnBatchUninstall: "Batch Uninstall",
    filterAll: "All",
    filterWin32: "Desktop Apps",
    filterUwp: "Windows Apps",
    filterHeavy: "Heavy Apps (>500MB)",
    btnSelectAll: "Select All",
    btnClearSelection: "Clear Selection",
    chkSkipRpBatch: "Skip Restore Point creation",
    btnExecuteBatch: "Uninstall Selected Apps",
    thAppName: "Program Name",
    thAppPublisher: "Publisher",
    thAppVersion: "Version",
    thAppDate: "Install Date",
    thAppSize: "Est. Size",
    loadingApps: "Loading installed programs list...",
    wizSafetyHeader: "Safety & Pre-Uninstall Backups (Revo Safety Net)",
    wizRestorePointLabel: "System Restore Point (VSS)",
    wizRestorePointDesc: "Creates an official Windows System Restore Point prior to uninstalling.",
    wizBtnSkipRpOnly: "Skip this Restore Point",
    wizRegBackupLabel: "Full Registry Key Backup",
    wizRegBackupDesc: "Exports .reg hive backups and offline Restore.bat script for 1-click rollback.",
    wizScanModeHeader: "Leftover Scan Depth",
    wizScanModeDesc: "Select scanning depth for post-uninstall registry keys and file remnants:",
    modeSafeTitle: "Safe",
    modeSafeDesc: "Fast scan of deterministic keys and directories. Zero risk.",
    modeModerateTitle: "Moderate (Recommended)",
    modeModerateDesc: "Includes installation folders, AppData, registry shared keys and common paths.",
    modeAdvancedTitle: "Advanced",
    modeAdvancedDesc: "Deep scan of full registry, CLSIDs, system variables, and related services.",
    wizSkipTip: "Step taking too long or unresponsive? You can skip it immediately:",
    btnSkipCurrentStep: "Skip Step",
    wizBoldRuleBadge: "Bold items are safe to delete",
    tabRegLeftovers: "Windows Registry",
    tabFilesLeftovers: "Files & Folders",
    tabTasksLeftovers: "Scheduled Tasks",
    btnSelectBoldOnly: "Select Bold Only (Safe)",
    wizDoneTitle: "Uninstallation & Leftover Cleanup Complete",
    lblRegKeysRemoved: "Registry keys deleted",
    lblFilesRemoved: "Files & directories removed",
    lblTasksRemoved: "Scheduled tasks removed",
    wizRebootTitle: "Locked files scheduled for reboot",
    wizRebootDesc: "Some files were locked by Windows and scheduled for automatic removal upon reboot (MoveFileEx).",
    btnSkipRpAndStart: "Skip Restore Point & Start",
    btnStartUninstall: "Start Full Uninstall",
    btnDeleteSelectedLeftovers: "Delete Selected Leftovers",
    forcedModalTitle: "Forced Uninstall",
    forcedModalDesc: "Remove stubborn, broken, or unlisted software directly.",
    lblForcedTarget: "Program name or full path to file / folder:",
    btnScanForced: "Scan Leftovers & Force",
    hunterModalTitle: "Hunter Mode",
    hunterModalDesc: "Target active processes, windows or files directly with one-click actions.",
    hunterSelectProcess: "Select running process or type path/PID:",
    btnHunterResolve: "Resolve Target",
    hunterTargetLabel: "Resolved Target Details",
    hunterActionsHeader: "Target Actions",
    btnHunterKill: "Kill Process",
    btnHunterKillDelete: "Kill & Delete Exe",
    btnHunterForced: "Forced Uninstall",
    btnHunterDisableStartup: "Disable Startup",
    backupModalTitle: "Backup & Restore Center",
    backupModalDesc: "Registry backups created before uninstalls. 1-click restore or WinRE offline recovery.",
    thBackupDate: "Date & Time",
    thBackupApp: "Application",
    thBackupFiles: "Backup Files",
    thBackupOffline: "WinRE Offline",
    loadingBackups: "Loading backup history...",

    /* Storage Analyzer */
    navStorage: "Disk Explorer",
    scrStorageTitle: "Smart Storage Explorer",
    scrStorageDesc: "Shows what's taking up space on the drive: an interactive Sunburst chart, a Treemap, and a deletion collector",
    storageTitle: "Smart Storage Explorer",
    storageSub: "Analyzes what's taking up space and lets you delete straight from the chart: Sunburst view, Treemap and file-type breakdown",
    storageHideSystem: "Hide Essential System Files",
    storageSystemBadge: "System",
    storageSystemProtectedTooltip: "Protected Windows system file - cannot be deleted",
    storageOneDriveBadge: "OneDrive",
    storageOneDriveTooltip: "File synced with Microsoft OneDrive",

    /* Terms of Use & EULA */
    termsTitle: "Terms of Use & License (EULA)",
    termsSub: "End User License Agreement, policies and exclusive rights to Yakir Lavi",
    sidebarTerms: "Terms & License (EULA)",
    btnViewTerms: "View Terms & License",
    termsModalTitle: "End User License Agreement & Terms of Use (EULA)",
    termsModalSub: "Polaris Software • Rights Holder & Developer: Yakir Lavi",
    termsAgreementNote: "Using this software constitutes full and irrevocable acceptance of these terms.",
    storageBadgeSquirrel: "Sunburst & Collector",
    storageIdle: "Idle",
    storageScanning: "Scanning drive...",
    storagePaused: "Paused",
    storageCompleted: "Scan Completed",
    storageCancelled: "Scan Cancelled",
    storageStartScan: "Start Scan",
    storageScanCustom: "Scan Specific Folder:",
    loadingDrives: "Loading drives...",
    collectorTitle: "Deletion Collector Basket",
    collectorClear: "Clear Selection",
    collectorDropPrompt: "Drag & drop files/folders here or click ➕ in the list",
    collectorBtnDelete: "Delete Items (Recycle Bin)",
    storageScannedFiles: "Files:",
    storageScannedFolders: "Folders:",
    storageScannedSize: "Scanned Size:",
    storageScanRate: "Speed:",
    storageTime: "Time:",
    storageScannedSpace: "Scanned:",
    storageFreeSpace: "Free:",
    storageUnknownSpace: "Unknown Space:",
    storageTotalDrive: "Total Drive:",
    storageTabSunburst: "🪐 Radial Chart (Sunburst)",
    storageTabTreemap: "📊 Directory Tree & Treemap",
    storageTabTop: "🏆 Top 100 Largest Files",
    storageTabDupes: "👯 Duplicate Files Finder",
    storageTabClean: "🧹 Quick Cleanups",
    storageTreeTitle: "Directory Tree",
    storageExtTitle: "Extension Breakdown (Legend)",
    storageColName: "Name",
    storageColProportion: "Proportion",
    storageColSize: "Size",
    storageColFiles: "Files",
    storageColSubdirs: "Folders",
    storageColExt: "Extension",
    storageColPath: "Full Path",
    storageNoScanYet: "Start a scan to explore disk usage",
    storageNoExts: "No extension statistics yet",
    storageTopTitle: "Top 100 Largest Files on Disk",
    storageDupesTitle: "Duplicate Files Finder",
    storageDupesSub: "Two-stage fast scan: identical file size filter, sparse hashing, and full SHA-256 validation.",
    storageMinSize: "Min File Size:",
    storageBtnScanDupes: "Find Duplicates Now",
    storageDupesPrompt: "Click 'Find Duplicates Now' to discover redundant duplicate files taking up storage.",
    storageExportCsv: "Export CSV Report",

    /* OEM Updates */
    navOemUpdates: "OEM Updates",
    oemDesc: "Automatic scan and installation of official drivers and BIOS updates from your vendor",

    /* Windows Updates Show / Hide */
    navWuHide: "Windows Update Blocker",
    wuHideDesc: "Show or hide specific Windows quality and driver updates",
    bannerOemPromoTitle: "Official Driver & Firmware Updates",
    bannerOemPromoDesc: "Run an automated scan and update of official drivers and BIOS updates via official vendor tools (Dell, Lenovo, HP).",
    btnGoToOemUpdates: "Go to OEM Updates",
    oemHardwareTitle: "Computer Manufacturer & Model",
    oemHardwareSub: "Automatically detected from motherboard & BIOS",
    oemDetectedBrand: "Detected Brand",
    oemModel: "Model / Series",
    oemOverride: "Manual Override:",
    oemToolTitle: "Official Update Tool",
    oemToolSub: "DCU / TVSU / HPIA / SDIO",
    oemToolName: "Selected Tool",
    oemToolPath: "Path:",
    oemActionTitle: "Run Updates",
    oemActionSub: "Full automated scan and installation",
    oemOptTwoPasses: "Double completion run (2 Passes)",
    oemOptWinOptional: "Include Windows Update optional drivers",
    btnStartOemUpdates: "Start OEM Updates",
    btnRunningOemUpdates: "Updates In Progress...",
    oemLiveLogTitle: "Live Execution Terminal",
    oemReady: "Ready to run updates.",
    btnClearLog: "Clear Log",
    oemStatusInstalled: "Installed & ready",
    oemStatusMissing: "Not installed (will auto-install)",
    oemStatusInstalling: "Installing vendor tool...",
    oemCompleted: "OEM updates completed successfully!",
    oemError: "Error during OEM updates",
    oemCancelled: "OEM updates cancelled by user",
    oemRebootRequired: "A computer restart is required to complete driver/BIOS installation."
  }
};

/** Shorthand for the active translation table. */
function t(key) {
  const table = I18N[currentLang] || I18N.he;
  return table[key] !== undefined ? table[key] : (I18N.he[key] !== undefined ? I18N.he[key] : key);
}

// -------------------------------------------------------------
// Category & Sub-tab Navigation
// -------------------------------------------------------------
const CATEGORIES = {
  overview:        { title: 'navOverview',            desc: 'scrOverviewDesc',    subTabs: [] },
  processes:       { title: 'navProcesses',           desc: 'scrProcessesDesc',   subTabs: [] },
  memory:          { title: 'navMemory',              desc: 'scrMemoryDesc',      subTabs: [] },
  disks:           { title: 'navDisks',               desc: 'scrDisksDesc',       subTabs: [] },
  storage:         { title: 'navStorage',             desc: 'scrStorageDesc',     subTabs: [] },
  maintenance:     { title: 'navMaintenance',         desc: 'scrMaintenanceDesc', subTabs: [] },
  uninstaller:     { title: 'navUninstaller',         desc: 'scrUninstallerDesc', subTabs: [] },
  startup:         { title: 'navStartup',             desc: 'scrStartupDesc',     subTabs: [] },
  crashes:         { title: 'navCrashes',             desc: 'scrCrashesDesc',     subTabs: [] },
  events:          { title: 'navEvents',              desc: 'scrEventsDesc',      subTabs: [] },
  devices:         { title: 'navDevices',             desc: 'scrDevicesDesc',     subTabs: [] },
  windows_updates: { title: 'navWuHide',              desc: 'wuHideDesc',         subTabs: [] },
  oem_updates:     { title: 'navOemUpdates',          desc: 'oemDesc',            subTabs: [] },
  battery:         { title: 'navBattery',             desc: 'batteryScanning',    subTabs: [] },
  tools:           { title: 'navTools',               desc: 'scrToolsDesc',       subTabs: [] },
  settings:        { title: 'navSettings',            desc: 'scrSettingsDesc',    subTabs: [] }
};

const SCREEN_TO_CATEGORY = {
  overview: 'overview',
  processes: 'processes',
  memory: 'memory',
  disks: 'disks',
  storage: 'storage',
  maintenance: 'maintenance',
  uninstaller: 'uninstaller',
  startup: 'startup',
  crashes: 'crashes',
  events: 'events',
  devices: 'devices',
  windows_updates: 'windows_updates',
  oem_updates: 'oem_updates',
  battery: 'battery',
  tools: 'tools',
  settings: 'settings',
  // Backward compatibility aliases:
  performance: 'processes',
  hardware: 'devices'
};

const SCREENS = {
  overview:        { title: 'navOverview',            desc: 'scrOverviewDesc',    onEnter: () => fetchBattery() },
  processes:       { title: 'navProcesses',           desc: 'scrProcessesDesc',   onEnter: () => fetchProcesses() },
  memory:          { title: 'navMemory',              desc: 'scrMemoryDesc',      onEnter: () => { if (timelineChart) timelineChart.resize(); if (categoryChart) categoryChart.resize(); } },
  disks:           { title: 'navDisks',               desc: 'scrDisksDesc',       onEnter: () => fetchDiskHealth() },
  storage:         { title: 'navStorage',             desc: 'scrStorageDesc',     onEnter: () => { initStorageScreen(); setTimeout(() => { if (typeof renderStorageSunburst === 'function') renderStorageSunburst(); }, 60); } },
  maintenance:     { title: 'navMaintenance',         desc: 'scrMaintenanceDesc', onEnter: () => refreshRepairAudit() },
  uninstaller:     { title: 'navUninstaller',         desc: 'scrUninstallerDesc', onEnter: () => fetchInstalledApps() },
  startup:         { title: 'navStartup',             desc: 'scrStartupDesc',     onEnter: () => refreshRepairAudit() },
  crashes:         { title: 'navCrashes',             desc: 'scrCrashesDesc',     onEnter: () => fetchCrashHistory() },
  events:          { title: 'navEvents',              desc: 'scrEventsDesc',      onEnter: () => fetchEventLog() },
  devices:         { title: 'navDevices',             desc: 'scrDevicesDesc',     onEnter: () => fetchDevices() },
  windows_updates: { title: 'navWuHide',              desc: 'wuHideDesc',         onEnter: () => { fetchWindowsUpdates(false); fetchWuServiceStatus(); } },
  oem_updates:     { title: 'navOemUpdates',          desc: 'oemDesc',            onEnter: () => fetchOemInfo() },
  battery:         { title: 'navBattery',             desc: 'batteryScanning',    onEnter: () => fetchBattery(true) },
  tools:           { title: 'navTools',               desc: 'scrToolsDesc',       onEnter: () => { fetchCopilotRemapStatus(); fetchOneDriveStatus(); fetchIconCacheStatus(); fetchEnterpriseTools(); } },
  settings:        { title: 'navSettings',            desc: 'scrSettingsDesc' }
};

let currentNavCategory = 'overview';
let activeSubTabs = {};

function goToCategory(catName) {
  if (!CATEGORIES[catName]) {
    catName = SCREEN_TO_CATEGORY[catName] || 'overview';
  }
  currentNavCategory = catName;
  currentScreen = catName;

  // 1. Toggle active screen section
  document.querySelectorAll('.screen').forEach(el => {
    el.classList.toggle('active', el.id === `screen-${catName}`);
  });

  // 2. Toggle active nav-item in sidebar
  document.querySelectorAll('.nav-item').forEach(btn => {
    const isMatching = (btn.getAttribute('data-category') === catName) ||
                       (btn.getAttribute('data-screen') === catName);
    btn.classList.toggle('active', isMatching);
  });

  // 3. Update header and trigger onEnter
  updateScreenHeader();
  if (SCREENS[catName]?.onEnter) SCREENS[catName].onEnter();

  const contentEl = document.querySelector('.content');
  if (contentEl) contentEl.scrollTop = 0;
}

function switchSubTab(catName, subTabId) {
  goToCategory(subTabId || catName);
}

// Backward compatibility: goToScreen(name) works for any screen, mapping to category & subtab
function goToScreen(name) {
  if (CATEGORIES[name]) {
    goToCategory(name);
    return;
  }
  const parentCat = SCREEN_TO_CATEGORY[name] || 'overview';
  goToCategory(parentCat, name);
}

function updateScreenHeader() {
  const catMeta = CATEGORIES[currentNavCategory] || CATEGORIES.overview;
  const screenMeta = SCREENS[currentScreen] || catMeta;
  const titleEl = document.getElementById('screenTitle');
  const descEl = document.getElementById('screenDesc');

  if (currentNavCategory !== 'overview' && currentScreen !== currentNavCategory) {
    if (titleEl) titleEl.textContent = t(catMeta.title) + " › " + t(screenMeta.title);
    if (descEl) descEl.textContent = t(screenMeta.desc);
  } else {
    if (titleEl) titleEl.textContent = t(catMeta.title);
    if (descEl) descEl.textContent = t(catMeta.desc);
  }
}

// -------------------------------------------------------------
// Initialization
// -------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
  applyStoredTheme();
  initCharts();
  applyStaticTexts();
  goToScreen('overview');

  // Check remote control immediately on load
  const controlData = await checkRemoteControlStatus(false);
  if (controlData && controlData.is_killed) {
    // If the app is killed, halt further initializations
    return;
  }

  fetchSystemInfo();
  fetchStats();
  fetchDiagnostics();
  fetchBattery();
  fetchProcesses();
  startPolling();
  refreshRepairAudit();
  fetchCrashHistory();
  fetchCopilotRemapStatus();
  fetchOneDriveStatus();
  fetchIconCacheStatus();
  fetchEnterpriseTools();

  // Periodically check remote kill switch and updates every 5 minutes
  setInterval(() => checkRemoteControlStatus(false), 5 * 60 * 1000);

  // Stagger hardware reports so we do not hammer the CPU/disk with simultaneous PowerShell queries.
  // The live overview paints instantly, and badges populate smoothly in sequence.
  setTimeout(() => fetchInstalledApps(), 1200);
  setTimeout(() => fetchDiskHealth(), 3000);
  setTimeout(() => fetchEventLog(), 5000);
  setTimeout(() => fetchDevices(), 7000);
  setTimeout(() => fetchOemInfo(), 8500);
  setTimeout(() => fetchWindowsUpdates(false), 9500);

  // Escape closes whichever modal is open.
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (window._isAppKilled) return; // Prevent closing kill switch modal
    if (window._isMandatoryUpdate) return;
    closeProcModal();
    closeCrashModal();
    closeConfirmModal();
    if (typeof closeCenterAlertModal === 'function') closeCenterAlertModal();
    closeTermsModal();
    closeBackupCenterModal();
    closeUpdateModal();
    if (typeof closeHunterModal === 'function') closeHunterModal();
    if (typeof closeForcedModal === 'function') closeForcedModal();
    if (typeof closeUninstallWizard === 'function') closeUninstallWizard();
    if (typeof closeStorageContextMenu === 'function') closeStorageContextMenu();
  });
});

let batteryPollTick = 0;
let isPollingActive = false;

function startPolling() {
  if (refreshTimer) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
  if (refreshInterval > 0) {
    scheduleNextPoll(refreshInterval);
  }
}

function scheduleNextPoll(delay) {
  if (refreshTimer) clearTimeout(refreshTimer);
  refreshTimer = setTimeout(runPollTick, delay);
}

async function runPollTick() {
  if (isPollingActive) return;
  isPollingActive = true;
  try {
    // Only poll process list if the user is looking at overview or processes tab.
    // When on Uninstaller, Storage, Crashes, or Tools, skip process polling to save CPU.
    const isProcessView = (currentNavCategory === 'overview' || currentScreen === 'processes' || currentNavCategory === 'performance');
    const tasks = [fetchStats()];
    if (isProcessView) {
      tasks.push(fetchProcesses());
    }
    batteryPollTick++;
    if (batteryPollTick % 10 === 0) {
      tasks.push(fetchBattery());
    }
    await Promise.allSettled(tasks);
  } catch (err) {
    console.warn("Poll tick error:", err);
  } finally {
    isPollingActive = false;
    if (refreshInterval > 0) {
      scheduleNextPoll(refreshInterval);
    }
  }
}

function changeRefreshRate(val) {
  refreshInterval = parseInt(val, 10);
  startPolling();
}

function toggleLanguage() {
  currentLang = currentLang === 'he' ? 'en' : 'he';
  document.documentElement.lang = currentLang;
  document.documentElement.dir = currentLang === 'he' ? 'rtl' : 'ltr';

  const langBtn = document.getElementById('langText');
  if (langBtn) langBtn.textContent = currentLang === 'he' ? 'English' : 'עברית';

  applyStaticTexts();
  updateScreenHeader();
  renderElevationBanner();
  renderPrivilegeRow();
  renderDiagnostics();
  renderProcessTable();
  renderCopilotStatus();
  renderCrashHistory(currentCrashes);
  if (diskReport) renderDiskHealth();
  if (deviceReport) renderDevices();
  if (eventReport) renderEventLog();
  if (oemInfo) renderOemInfo();
  if (rawStats) updateMemoryUI(rawStats);
  if (rawBattery) renderBattery(rawBattery);
  refreshRepairAudit();
}

// -------------------------------------------------------------
// Theme
// -------------------------------------------------------------
// Dark is the default. The choice lives in localStorage so it survives a
// restart, but every access is guarded: Polaris is served from a local origin
// where storage normally works, yet a locked-down browser profile can still
// make these throw, and a theme toggle must never take the app down with it.
const THEME_KEY = 'polaris.theme';
let currentTheme = 'dark';

function applyStoredTheme() {
  let stored = null;
  try {
    stored = localStorage.getItem(THEME_KEY);
  } catch (err) {
    stored = null;
  }
  setTheme(stored === 'light' ? 'light' : 'dark', { persist: false });
}

function setTheme(theme, options) {
  currentTheme = theme === 'light' ? 'light' : 'dark';

  if (currentTheme === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
  } else {
    document.documentElement.removeAttribute('data-theme');
  }

  const isLight = currentTheme === 'light';
  const btnDark = document.getElementById('btnThemeDark');
  const btnLight = document.getElementById('btnThemeLight');
  if (btnDark) btnDark.classList.toggle('active', !isLight);
  if (btnLight) btnLight.classList.toggle('active', isLight);

  // The topbar button shows where a click will take you, not where you are.
  const iconDark = document.getElementById('iconThemeDark');
  const iconLight = document.getElementById('iconThemeLight');
  if (iconDark) iconDark.classList.toggle('hidden', isLight);
  if (iconLight) iconLight.classList.toggle('hidden', !isLight);

  if (!options || options.persist !== false) {
    try {
      localStorage.setItem(THEME_KEY, currentTheme);
    } catch (err) {
      // Storage denied: the theme still applies for this session.
    }
  }

  repaintCharts();
}

function toggleTheme() {
  setTheme(currentTheme === 'light' ? 'dark' : 'light');
}

/**
 * Applies every data-i18n / data-i18n-ph / data-i18n-title attribute in the
 * document. This replaces the long chain of per-element getElementById calls
 * the previous version carried.
 */
function applyStaticTexts() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (I18N[currentLang][key] !== undefined) el.textContent = I18N[currentLang][key];
  });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => {
    const key = el.getAttribute('data-i18n-ph');
    if (I18N[currentLang][key] !== undefined) el.placeholder = I18N[currentLang][key];
  });
  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    const key = el.getAttribute('data-i18n-title');
    if (I18N[currentLang][key] !== undefined) el.title = I18N[currentLang][key];
  });
}


// -------------------------------------------------------------
// API Calls
// -------------------------------------------------------------

let systemInfo = null;

async function fetchSystemInfo() {
  try {
    const res = await fetch('/api/system_info');
    if (!res.ok) return;
    systemInfo = await res.json();
    renderElevationBanner();
  } catch (err) {
    console.error("Failed to fetch system info:", err);
  }
}

function renderElevationBanner() {
  renderPrivilegeRow();

  const banner = document.getElementById('elevationBanner');
  if (!banner || !systemInfo) return;

  if (systemInfo.is_admin) {
    banner.classList.add('hidden');
    return;
  }

  const title = document.getElementById('elevationBannerTitle');
  const desc = document.getElementById('elevationBannerDesc');

  if (currentLang === 'he') {
    title.textContent = 'Polaris פועל ללא הרשאות מנהל';
    desc.textContent = 'ניטור הזיכרון וניהול התהליכים עובדים כרגיל, אך כלי התיקון (DISM, SFC, איפוס רשת, שירות הדפסה, TRIM) ידרשו אישור UAC נפרד או לא יפעלו. להפעלה מלאה: לחץ לחיצה ימנית על Polaris ובחר ב״הפעל כמנהל״.';
  } else {
    title.textContent = 'Polaris is not running as Administrator';
    desc.textContent = 'Monitoring and process control work normally, but the repair tools (DISM, SFC, network reset, print spooler, SSD TRIM) will each raise their own UAC prompt or silently fail. For full access, right-click Polaris and choose "Run as administrator".';
  }

  banner.classList.remove('hidden');
}

/** Persistent privilege indicator in the sidebar footer. */
function renderPrivilegeRow() {
  const dot = document.getElementById('privDot');
  const text = document.getElementById('privText');
  const row = document.getElementById('privRow');
  const aboutVal = document.getElementById('aboutPrivValue');
  if (!dot || !text) return;

  const isAdmin = !!(systemInfo && systemInfo.is_admin);
  dot.classList.toggle('limited', !isAdmin);
  text.textContent = isAdmin ? t('privAdmin') : t('privLimited');
  if (row) row.title = isAdmin ? t('privAdminTip') : t('privLimitedTip');
  if (aboutVal) aboutVal.textContent = isAdmin ? t('privAdmin') : t('privLimited');
}

async function fetchStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();
    rawStats = data.stats;
    updateMemoryUI(data.stats);
    updateTimelineChart(data.history);
  } catch (err) {
    console.error("Failed to fetch stats:", err);
  }
}

async function fetchDiagnostics() {
  try {
    const res = await fetch('/api/diagnose');
    if (!res.ok) return;
    const data = await res.json();
    rawDiagnostics = data.diagnostics;
    renderDiagnostics();
    updateCategoryChart(data.diagnostics.category_breakdown);
  } catch (err) {
    console.error("Failed to fetch diagnostics:", err);
  }
}

// =============================================================================
// Windows Update Hide / Unhide
// =============================================================================

let _wuData = { available: [], hidden: [] };

/**
 * Fetch available and hidden Windows updates from the backend.
 * @param {boolean} online - true = full network scan, false = fast local cache
 */
async function fetchWindowsUpdates(online = false) {
  const btnScan   = document.getElementById('btnWuScan');
  const btnOnline = document.getElementById('btnWuScanOnline');
  const statusEl  = document.getElementById('wuScanStatus');

  // Disable buttons while scanning
  if (btnScan)   { btnScan.disabled = true;   btnScan.classList.add('is-busy'); }
  if (btnOnline) { btnOnline.disabled = true; }
  if (statusEl)  statusEl.textContent = online ? 'סורק מול שרתי Microsoft...' : 'טוען ממטמון מקומי...';

  try {
    const url = `/api/windows_updates/list?online=${online ? 1 : 0}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    _wuData = data;
    renderWindowsUpdates(data);
    if (statusEl) {
      const ts = new Date().toLocaleTimeString('he-IL');
      statusEl.textContent = `עודכן: ${ts}`;
    }
    if (data.error) showToast('שגיאת Windows Update: ' + data.error, 'error');
  } catch (e) {
    if (statusEl) statusEl.textContent = 'שגיאת טעינה';
    showToast('שגיאה בטעינת עדכוני Windows: ' + (e.message || e), 'error');
  } finally {
    if (btnScan)   { btnScan.disabled = false;   btnScan.classList.remove('is-busy'); }
    if (btnOnline) { btnOnline.disabled = false; }
  }
}

/**
 * Render both lists (available + hidden) to the DOM.
 */
function renderWindowsUpdates(data) {
  const available = data.available || [];
  const hidden    = data.hidden    || [];

  // Update counters and badges
  const availCountEl  = document.getElementById('wuAvailCount');
  const hiddenCountEl = document.getElementById('wuHiddenCount');
  const badgeAvail    = document.getElementById('wuBadgeAvail');
  const badgeHidden   = document.getElementById('wuBadgeHidden');
  const badgeNav      = document.getElementById('badgeWuHidden');

  if (availCountEl)  availCountEl.textContent  = available.length;
  if (hiddenCountEl) hiddenCountEl.textContent = hidden.length;

  if (badgeAvail) {
    badgeAvail.textContent = `${available.length} ממתינים`;
    badgeAvail.style.display = available.length ? '' : 'none';
  }
  if (badgeHidden) {
    badgeHidden.textContent = `${hidden.length} חסומים`;
    badgeHidden.style.display = hidden.length ? '' : 'none';
  }
  const navTag = document.getElementById('navTagWuHidden');
  if (navTag) {
    if (hidden.length > 0) {
      navTag.textContent = hidden.length;
      navTag.classList.remove('hidden');
      navTag.classList.add('warn');
    } else {
      navTag.textContent = '0';
      navTag.classList.add('hidden');
      navTag.classList.remove('warn');
    }
  }

  // Render available list
  const availEl = document.getElementById('wuAvailList');
  if (availEl) {
    if (!available.length) {
      availEl.innerHTML = '<p class="card-sub" style="padding:16px 20px; color:var(--muted);">אין עדכונים ממתינים שניתן להסתיר. 🎉</p>';
    } else {
      availEl.innerHTML = available.map(u => _wuUpdateRow(u, false)).join('');
    }
  }

  // Render hidden list
  const hiddenEl = document.getElementById('wuHiddenList');
  if (hiddenEl) {
    if (!hidden.length) {
      hiddenEl.innerHTML = '<p class="card-sub" style="padding:16px 20px; color:var(--muted);">אין עדכונים מוסתרים כרגע.</p>';
    } else {
      hiddenEl.innerHTML = hidden.map(u => _wuUpdateRow(u, true)).join('');
    }
  }
}

/**
 * Build an HTML row for a single update.
 * @param {object} u - update object
 * @param {boolean} isHidden - true if currently hidden
 */
function _wuUpdateRow(u, isHidden) {
  const cats = (u.categories || []).join(', ') || '—';
  const kbs  = (u.kb_numbers || []).join(', ') || '—';
  const size = u.size_mb > 0 ? `${u.size_mb} MB` : '';
  const btn  = isHidden
    ? `<button class="btn btn-sm btn-primary" onclick="unhideWindowsUpdate('${u.id}')" title="בטל הסתרה — Windows Update יחזור לסרוק ולהתקין עדכון זה">↩ בטל הסתרה</button>`
    : `<button class="btn btn-sm btn-danger" onclick="hideWindowsUpdate('${u.id}')" title="הסתר — Windows Update יתעלם מעדכון זה">🚫 הסתר</button>`;

  return `
    <div class="wu-row" style="display:flex; align-items:flex-start; gap:12px; padding:12px 18px; border-bottom:1px solid var(--border); flex-wrap:wrap;">
      <div style="flex:1; min-width:200px;">
        <div style="font-size:13px; font-weight:600; margin-bottom:3px; line-height:1.4;">${_escHtml(u.title)}</div>
        <div style="display:flex; flex-wrap:wrap; gap:6px; font-size:11.5px; color:var(--muted);">
          ${kbs !== '—' ? `<span class="badge badge-mono" style="font-size:10px;">${_escHtml(kbs)}</span>` : ''}
          ${cats !== '—' ? `<span class="badge" style="font-size:10px; background:var(--surface2);">${_escHtml(cats)}</span>` : ''}
          ${size ? `<span style="opacity:0.65;">${size}</span>` : ''}
        </div>
      </div>
      <div style="flex-shrink:0; margin-top:2px;">${btn}</div>
    </div>`;
}

/** Escape HTML special characters. */
function _escHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Hide a Windows update by ID.
 */
async function hideWindowsUpdate(updateId) {
  try {
    const res = await fetch('/api/windows_updates/hide', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ update_id: updateId })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.success) {
      showToast(data.message || 'העדכון הוסתר בהצלחה ✓', 'ok');
      await fetchWindowsUpdates(false);
    } else {
      showToast(data.message || 'הסתרת העדכון נכשלה', 'error');
    }
  } catch (e) {
    showToast('שגיאה בהסתרת העדכון: ' + (e.message || e), 'error');
  }
}

/**
 * Unhide (show) a previously hidden Windows update by ID.
 */
async function unhideWindowsUpdate(updateId) {
  try {
    const res = await fetch('/api/windows_updates/unhide', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ update_id: updateId })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.success) {
      showToast(data.message || 'הסתרת העדכון בוטלה בהצלחה ✓', 'ok');
      await fetchWindowsUpdates(false);
    } else {
      showToast(data.message || 'ביטול הסתרת העדכון נכשל', 'error');
    }
  } catch (e) {
    showToast('שגיאה בביטול הסתרת העדכון: ' + (e.message || e), 'error');
  }
}

// =============================================================================
// Windows Update Service Control (wuauserv)
// =============================================================================

let _wuServiceData = null;

async function fetchWuServiceStatus() {
  try {
    const res = await fetch('/api/windows_updates/service_status');
    if (!res.ok) return;
    const data = await res.json();
    _wuServiceData = data;
    renderWuServiceStatus(data);
  } catch (e) {
    console.warn("Error fetching WU service status:", e);
  }
}

function renderWuServiceStatus(data) {
  const badgeEl = document.getElementById('wuServiceBadge');
  const descEl = document.getElementById('wuServiceDesc');
  const btn = document.getElementById('btnToggleWuService');
  const btnText = document.getElementById('btnToggleWuServiceText');
  const iconBox = document.getElementById('wuServiceIconBox');

  if (!data) return;

  const isDisabled = !!data.is_disabled;
  const isRunning = !!data.is_running;

  if (isDisabled) {
    if (badgeEl) {
      badgeEl.className = 'badge badge-warn';
      badgeEl.textContent = 'מושבת (Disabled)';
    }
    if (descEl) {
      descEl.textContent = 'שירות העדכונים מושבת לחלוטין (Disabled). Windows לא יוכל להוריד או להתקין עדכונים ברקע.';
    }
    if (iconBox) {
      iconBox.style.background = 'rgba(239, 68, 68, 0.15)';
      iconBox.style.color = '#ef4444';
      iconBox.innerHTML = `
        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width:20px;height:20px;">
          <path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/>
        </svg>
      `;
    }
    if (btn) {
      btn.className = 'btn btn-sm btn-solid-success';
    }
    if (btnText) {
      btnText.textContent = 'הפעל והחזר שירות עדכונים';
    }
  } else {
    if (badgeEl) {
      badgeEl.className = isRunning ? 'badge badge-success' : 'badge badge-mono';
      badgeEl.textContent = isRunning ? 'פעיל ורץ (Running)' : 'זמין (Manual)';
    }
    if (descEl) {
      descEl.textContent = 'שירות העדכונים זמין/פעיל. השבתת השירות תעצור ותמנע מ-Windows להוריד או להתקין עדכונים.';
    }
    if (iconBox) {
      iconBox.style.background = 'rgba(16, 185, 129, 0.14)';
      iconBox.style.color = '#10b981';
      iconBox.innerHTML = `
        <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width:20px;height:20px;">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/>
        </svg>
      `;
    }
    if (btn) {
      btn.className = 'btn btn-sm btn-outline-danger';
    }
    if (btnText) {
      btnText.textContent = 'כבה והשבת שירות עדכונים';
    }
  }
}

async function toggleWuService() {
  const btn = document.getElementById('btnToggleWuService');
  const btnText = document.getElementById('btnToggleWuServiceText');

  const currentlyDisabled = _wuServiceData && _wuServiceData.is_disabled;
  const targetAction = currentlyDisabled ? 'enable' : 'disable';

  if (btn) {
    btn.disabled = true;
    btn.classList.add('is-busy');
  }
  if (btnText) {
    btnText.textContent = currentlyDisabled ? 'מפעיל שירות...' : 'משבית שירות...';
  }

  try {
    const res = await fetch('/api/windows_updates/service_toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: targetAction })
    });
    const data = await res.json();
    if (data.success) {
      showToast(data.message, 'ok');
      if (data.status_info) {
        _wuServiceData = data.status_info;
        renderWuServiceStatus(data.status_info);
      } else {
        await fetchWuServiceStatus();
      }
    } else {
      showToast(data.message || 'הפעולה נכשלה', 'error');
      await fetchWuServiceStatus();
    }
  } catch (err) {
    showToast('שגיאה בשינוי מצב שירות: ' + (err.message || err), 'error');
    await fetchWuServiceStatus();
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('is-busy');
    }
  }
}

// =============================================================================
async function fetchBattery(force = false) {

  const btn = document.getElementById('btnRefreshBattery');
  if (force && btn) {
    btn.disabled = true;
    btn.classList.add('is-busy');
  }

  try {
    const url = force ? '/api/battery?force=true' : '/api/battery';
    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();
    rawBattery = data;
    renderBattery(data);
  } catch (err) {
    console.error("Failed to fetch battery:", err);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('is-busy');
    }
  }
}

async function fetchProcesses() {
  try {
    const query = new URLSearchParams({
      grouped: isGroupedView,
      category: currentCategory,
      search: searchQuery
    });
    const res = await fetch(`/api/processes?${query.toString()}`);
    if (!res.ok) return;
    const data = await res.json();
    rawProcesses = data.processes;
    renderProcessTable();
  } catch (err) {
    console.error("Failed to fetch processes:", err);
  }
}

async function optimizeMemory() {
  const btn = document.getElementById('btnOptimize');
  const txt = document.getElementById('txtBtnOptimize');
  const originalText = txt ? txt.textContent : '';
  
  if (btn) {
    btn.disabled = true;
    btn.classList.add('is-busy');
  }
  if (txt) {
    txt.textContent = t('optimizing');
  }

  try {
    const res = await fetch('/api/optimize', { method: 'POST' });
    const data = await res.json();
    
    if (data.success) {
      const freed = data.freed_formatted;
      const msg = data.freed_bytes > 0
        ? `${t('toastFreedSuccess')} ${freed} (${data.before_used_percent}% → ${data.after_used_percent}%)`
        : t('toastFreedNothing');
      showToast(t('toastFreedTitle'), msg);
    }
    await fetchStats();
    await fetchDiagnostics();
    await fetchProcesses();
  } catch (err) {
    showToast("Error", err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('is-busy');
    }
    if (txt) {
      txt.textContent = originalText;
    }
  }
}

let confirmCallback = null;

function openConfirmModal(title, desc, confirmBtnText, onConfirm) {
  document.getElementById('confirmModalTitle').textContent = title;
  document.getElementById('confirmModalDesc').textContent = desc;
  const btn = document.getElementById('btnConfirmActionExec');
  btn.textContent = confirmBtnText || t('btnKill');
  confirmCallback = onConfirm;
  btn.onclick = () => {
    closeConfirmModal();
    if (confirmCallback) confirmCallback();
  };
  document.getElementById('confirmActionModal').classList.remove('hidden');
}

function closeConfirmModal() {
  document.getElementById('confirmActionModal').classList.add('hidden');
  confirmCallback = null;
}

async function killProcess(pid, name) {
  const desc = currentLang === 'he'
    ? `האם לסיים את התהליך ${name} (PID: ${pid})?`
    : `Terminate process ${name} (PID: ${pid})?`;

  openConfirmModal(t('confirmKillTitle'), desc, t('btnKill'), async () => {
    rawProcesses = rawProcesses.filter(p => p.pid !== pid);
    renderProcessTable();

    try {
      const res = await fetch('/api/kill', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid: pid })
      });
      const data = await res.json();
      showToast(data.success ? (currentLang === 'he' ? "התהליך הסתיים" : "Terminated") : "Notice", data.message);
      await fetchProcesses();
      await fetchStats();
      await fetchDiagnostics();
    } catch (err) {
      showToast("Error", err.message);
      fetchProcesses();
    }
  });
}

async function killGroup(groupName) {
  const desc = currentLang === 'he'
    ? `האם לסיים את כל תהליכי ${groupName}?`
    : `Terminate all instances of ${groupName}?`;

  openConfirmModal(t('confirmKillGroupTitle'), desc, t('btnKill'), async () => {
    rawProcesses = rawProcesses.filter(p => p.name.toLowerCase() !== groupName.toLowerCase());
    renderProcessTable();

    try {
      const res = await fetch('/api/kill', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group_name: groupName })
      });
      const data = await res.json();
      showToast(data.success ? (currentLang === 'he' ? "סיום קבוצה הושלם" : "Group Terminated") : "Notice", data.message);
      await fetchProcesses();
      await fetchStats();
      await fetchDiagnostics();
    } catch (err) {
      showToast("Error", err.message);
      fetchProcesses();
    }
  });
}

async function trimSingleProcess(pid) {
  try {
    const res = await fetch('/api/trim_process', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pid })
    });
    const data = await res.json();
    showToast("Working Set", data.message);
    fetchProcesses();
  } catch (err) {
    showToast("Error", err.message);
  }
}

function trimSingleProcessFromModal() {
  if (currentModalPid > 0) {
    trimSingleProcess(currentModalPid);
    closeProcModal();
  }
}

async function runDeepDiagnosis() {
  await fetchDiagnostics();
  showToast(t('toastScanDone'), t('toastScanDoneMsg'));
}

// -------------------------------------------------------------
// UI Rendering
// -------------------------------------------------------------

function updateMemoryUI(stats) {
  if (!stats) return;

  const pct = stats.used_percent ?? stats.percent ?? 0;

  const set = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };

  set('statRamPercent', `${pct}%`);
  set('valUsedRam', stats.used_formatted || stats.formatted?.used || '--');
  set('valAvailableRam', stats.available_formatted || stats.formatted?.available || '--');
  set('valTotalRam', stats.total_formatted || stats.formatted?.total || '--');
  set('valCachedRam', stats.cached_formatted || stats.formatted?.cached || '--');

  // Load tone drives the meter, the verdict label and the topbar chip so the
  // same signal reads identically in all three places.
  let tone = 'ok';
  let loadLabel = t('loadNormal');
  if (pct > 85) {
    tone = 'danger';
    loadLabel = t('loadHigh');
  } else if (pct > 65) {
    tone = 'warn';
    loadLabel = t('loadModerate');
  }

  const bar = document.getElementById('ramProgressBar');
  if (bar) {
    bar.style.width = `${pct}%`;
    bar.className = `meter-fill ${tone}`;
  }

  const loadStatus = document.getElementById('valMemoryLoadStatus');
  if (loadStatus) {
    loadStatus.textContent = loadLabel;
    loadStatus.className = tone === 'ok' ? 'tone-ok' : (tone === 'warn' ? 'tone-warn' : 'tone-danger');
    loadStatus.style.fontWeight = '650';
  }

  const chip = document.getElementById('liveChip');
  if (chip) chip.className = `live-chip${tone === 'ok' ? '' : ' ' + tone}`;
  set('liveChipVal', `${pct}%`);

  // Kernel pools & pagefile
  set('valNonPagedPool', stats.kernel_nonpaged_formatted || stats.formatted?.kernel_nonpaged || '--');
  set('valPagedPool', stats.kernel_paged_formatted || stats.formatted?.kernel_paged || '--');
  const swapUsed = stats.swap_used_formatted || stats.formatted?.swap_used || '0 B';
  const swapTotal = stats.swap_total_formatted || stats.formatted?.swap_total || '0 B';
  set('valSwapUsed', `${swapUsed} / ${swapTotal}`);
  set('valSwapPercent', `${stats.swap_percent ?? 0}%`);

  // A Non-Paged Pool above ~1.2 GB almost always means a leaking driver.
  const isNppLeak = (stats.kernel_nonpaged_bytes || 0) > (1.2 * 1024 * 1024 * 1024);
  const nppStatus = document.getElementById('badgeNppStatus');
  const leakStatus = document.getElementById('valDriverLeakStatus');

  if (nppStatus) {
    nppStatus.textContent = isNppLeak ? t('nppHigh') : t('nppOk');
    nppStatus.className = `badge ${isNppLeak ? 'badge-danger' : 'badge-ok'}`;
  }
  if (leakStatus) {
    leakStatus.textContent = isNppLeak ? t('driverLeakWarn') : t('driverLeakOk');
    leakStatus.className = isNppLeak ? 'tone-danger' : 'tone-ok';
    leakStatus.style.fontWeight = '650';
  }
}

function renderBattery(data) {
  if (!data) return;

  const activeBody = document.getElementById('batteryActiveBody');
  const desktopBody = document.getElementById('batteryDesktopBody');
  const scoreCircle = document.getElementById('batteryScoreCircle');
  const scoreVal = document.getElementById('batteryScoreVal');
  const badge = document.getElementById('batteryStatusBadge');
  const summary = document.getElementById('batterySummaryText');

  // Desktop PC / No Battery
  if (!data.has_battery) {
    if (activeBody) activeBody.classList.add('hidden');
    if (desktopBody) desktopBody.classList.remove('hidden');
    if (scoreCircle) scoreCircle.className = 'score neutral';
    if (scoreVal) {
      scoreVal.textContent = 'AC';
      scoreVal.className = 'score-val muted';
    }
    if (badge) {
      badge.textContent = t('desktopNoBatteryTitle');
      badge.className = 'badge badge-neutral';
    }
    if (summary) {
      summary.textContent = t('desktopNoBatteryDesc');
    }
    return;
  }

  // Laptop Battery Present
  if (activeBody) activeBody.classList.remove('hidden');
  if (desktopBody) desktopBody.classList.add('hidden');

  const healthPct = data.health_percent;
  const wearPct = data.wear_percent ?? (healthPct != null ? Math.max(0, 100 - healthPct) : 0);
  const tone = data.health_tone || (healthPct != null ? (healthPct >= 80 ? 'ok' : (healthPct >= 60 ? 'warn' : 'danger')) : 'ok');

  // Health Score circle
  if (scoreCircle) scoreCircle.className = `score ${tone}`;
  if (scoreVal) {
    scoreVal.textContent = healthPct != null ? `${Math.round(healthPct)}%` : '--%';
    scoreVal.className = `score-val tone-${tone}`;
  }

  // Status Badge
  if (badge) {
    const statusText = currentLang === 'he' ? (data.status_he || t('batteryGood')) : (data.status_en || 'Good condition');
    badge.textContent = statusText;
    badge.className = `badge badge-${tone}`;
  }

  // Summary Text
  if (summary) {
    const mfg = data.manufacturer && data.manufacturer !== 'Unknown' ? data.manufacturer : '';
    const chem = data.chemistry && data.chemistry !== '--' ? data.chemistry : '';
    const cycles = data.cycle_count != null ? `${data.cycle_count} ${t('batteryCyclesUnit')}` : '';
    
    let parts = [];
    if (mfg || chem) parts.push(`${mfg} ${chem}`.trim());
    if (cycles) parts.push(cycles);
    if (wearPct != null) {
      parts.push(currentLang === 'he' ? `שחיקה: ${wearPct}%` : `Wear: ${wearPct}%`);
    }

    if (parts.length > 0) {
      summary.textContent = parts.join(' · ');
    } else {
      summary.textContent = t('batteryScanning');
    }
  }

  // Live Charge percentage
  const chargePct = data.current_charge_percent ?? 0;
  const statPct = document.getElementById('statBatteryPercent');
  if (statPct) statPct.textContent = `${chargePct}%`;

  // Power state text
  let powerLabel = '';
  if (data.is_charging) {
    powerLabel = t('batteryStatusCharging');
  } else if (data.power_plugged) {
    powerLabel = t('batteryStatusPlugged');
  } else {
    powerLabel = t('batteryStatusDischarging');
  }

  const valStatus = document.getElementById('valBatteryPowerStatus');
  if (valStatus) {
    valStatus.textContent = powerLabel;
    valStatus.className = data.is_charging ? 'tone-accent' : (data.power_plugged ? 'tone-ok' : (chargePct <= 20 ? 'tone-danger' : ''));
  }

  // Progress Bar
  const bar = document.getElementById('batteryProgressBar');
  if (bar) {
    bar.style.width = `${Math.min(100, Math.max(0, chargePct))}%`;
    let barTone = 'ok';
    if (chargePct <= 15) barTone = 'danger';
    else if (chargePct <= 30) barTone = 'warn';
    else if (data.is_charging) barTone = 'accent';
    bar.className = `meter-fill ${barTone}`;
  }

  // Grid Stats
  const fullCap = document.getElementById('valBatteryFullCapacity');
  if (fullCap) fullCap.textContent = data.full_charge_capacity_formatted || (data.full_charge_capacity_mwh ? ltrIsolate(`${data.full_charge_capacity_mwh} mWh`, true) : '--');

  const designCap = document.getElementById('valBatteryDesignCapacity');
  if (designCap) designCap.textContent = data.design_capacity_formatted || (data.design_capacity_mwh ? ltrIsolate(`${data.design_capacity_mwh} mWh`, true) : '--');

  const wearEl = document.getElementById('valBatteryWear');
  if (wearEl) {
    wearEl.textContent = wearPct != null ? `${wearPct}%` : '--%';
    wearEl.className = `stat-value sm ltr ${wearPct > 35 ? 'tone-danger' : (wearPct > 20 ? 'tone-warn' : 'tone-ok')}`;
  }

  const cyclesEl = document.getElementById('valBatteryCycles');
  if (cyclesEl) {
    cyclesEl.textContent = data.cycle_count != null ? data.cycle_count : '--';
  }

  const timeEl = document.getElementById('valBatteryTimeRemaining');
  if (timeEl) {
    const timeText = currentLang === 'he'
      ? (data.time_remaining_formatted_he || '--')
      : (data.time_remaining_formatted_en || '--');
    timeEl.textContent = timeText;
  }
}

function renderDiagnostics() {
  if (!rawDiagnostics) return;

  const diag = rawDiagnostics;
  const score = diag.health_score;
  const tone = score >= 80 ? 'ok' : (score >= 60 ? 'warn' : 'danger');

  const scoreCircle = document.getElementById('healthScoreCircle');
  const scoreVal = document.getElementById('healthScoreVal');
  if (scoreCircle) scoreCircle.className = `score ${tone}`;
  if (scoreVal) {
    scoreVal.textContent = score;
    scoreVal.className = `score-val tone-${tone === 'ok' ? 'ok' : tone}`;
  }

  const badge = document.getElementById('healthStatusBadge');
  if (badge) {
    badge.textContent = currentLang === 'he' ? diag.status_he : diag.status_en;
    badge.className = `badge badge-${tone}`;
  }

  const findings = diag.findings || [];

  const summary = document.getElementById('healthSummaryText');
  if (summary) {
    summary.textContent = findings.length > 0
      ? (currentLang === 'he' ? findings[0].desc_he : findings[0].desc_en)
      : t('diagScanning');
  }

  // --- Nav badge: how many findings are worth acting on ---
  const actionable = findings.filter(f => f.severity === 'high' || f.severity === 'medium');
  const navTag = document.getElementById('navTagFindings');
  if (navTag) {
    navTag.textContent = actionable.length;
    navTag.className = 'nav-tag mono' +
      (findings.some(f => f.severity === 'high') ? ' alert' : (actionable.length ? ' warn' : ''));
    navTag.classList.toggle('hidden', actionable.length === 0);
  }

  // --- Overview: the three findings that matter most ---
  const brief = document.getElementById('overviewFindings');
  if (brief) {
    brief.innerHTML = '';
    const rank = { high: 0, medium: 1, low: 2 };
    const shortlist = [...findings]
      .sort((a, b) => (rank[a.severity] ?? 3) - (rank[b.severity] ?? 3))
      .slice(0, 3);

    if (shortlist.length === 0) {
      brief.innerHTML = `<div class="empty" style="padding: 26px 10px;">
        <span class="tone-ok" style="font-size: 18px;">&#10003;</span>
        <span class="empty-desc">${esc(t('attentionNone'))}</span>
      </div>`;
    } else {
      shortlist.forEach(f => {
        const el = document.createElement('div');
        el.className = `finding sev-${f.severity}`;
        el.innerHTML = `
          <div class="spread">
            <span class="finding-title">${esc(currentLang === 'he' ? f.title_he : f.title_en)}</span>
            <span class="badge badge-${f.severity === 'high' ? 'danger' : (f.severity === 'medium' ? 'warn' : 'accent')}">${esc(f.severity)}</span>
          </div>
        `;
        brief.appendChild(el);
      });
    }
  }

  // --- Memory-analysis screen: every finding, in full ---
  const container = document.getElementById('findingsContainer');
  if (container) {
    container.innerHTML = '';

    if (findings.length === 0) {
      container.innerHTML = `<div class="empty span-2">
        <span class="tone-ok" style="font-size: 22px;">&#10003;</span>
        <span class="empty-title">${esc(t('attentionNone'))}</span>
      </div>`;
    }

    findings.forEach(f => {
      const action = currentLang === 'he' ? f.action_he : f.action_en;
      const canTrim = f.type === 'TOP_HOGS' || f.type === 'STANDBY_CACHE';

      const card = document.createElement('div');
      card.className = `finding sev-${f.severity}`;
      card.innerHTML = `
        <div class="spread">
          <span class="finding-title">${esc(currentLang === 'he' ? f.title_he : f.title_en)}</span>
          <span class="badge badge-${f.severity === 'high' ? 'danger' : (f.severity === 'medium' ? 'warn' : 'accent')}">${esc(f.severity)}</span>
        </div>
        <p class="finding-desc">${esc(currentLang === 'he' ? f.desc_he : f.desc_en)}</p>
        ${action ? `
          <div class="finding-action">
            <span>${esc(action)}</span>
            ${canTrim ? `<button class="btn btn-xs" onclick="optimizeMemory()">${esc(t('btnOptimize'))}</button>` : ''}
          </div>
        ` : ''}
      `;
      container.appendChild(card);
    });
  }

  // --- Top consumers ---
  const topHogsContainer = document.getElementById('topHogsContainer');
  if (topHogsContainer && diag.top_consumers) {
    topHogsContainer.innerHTML = '';

    diag.top_consumers.slice(0, 5).forEach((topItem, index) => {
      const card = document.createElement('button');
      card.type = 'button';
      card.className = 'hog';
      // Row keys are index-based, so resolve the group by its raw process name.
      card.onclick = () => openProcModalByName(topItem.raw_name);

      card.innerHTML = `
        <div class="spread">
          <span class="hog-rank">#${index + 1}</span>
          <span class="cat ${categoryClass(topItem.category)}">${esc(topItem.category)}</span>
        </div>

        <div>
          <div class="hog-name truncate" title="${esc(topItem.name)}">${esc(topItem.name)}</div>
          <span class="hog-exe truncate">${esc(topItem.raw_name)}</span>
        </div>

        <div>
          <div class="spread ltr">
            <span class="hog-size">${esc(topItem.rss_formatted)}</span>
            <span class="hog-pct">${esc(topItem.percent)}%</span>
          </div>
          <div class="meter thin" style="margin-top: 5px;">
            <div class="meter-fill" style="width: ${Math.min(100, topItem.percent * 2.5)}%"></div>
          </div>
        </div>

        <div class="hog-foot">
          <span class="mono">${topItem.process_count} ${esc(t('procsShort'))}</span>
          <span class="tone-accent" style="font-weight: 600;">${esc(t('details'))}</span>
        </div>
      `;
      topHogsContainer.appendChild(card);
    });
  }
}

function renderProcessTable() {
  const tbody = document.getElementById('processTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';
  procStore.clear();

  let procs = [...rawProcesses];

  // Sort indicators in the table header
  ['rss_bytes', 'memory_percent', 'cpu_percent'].forEach(col => {
    const el = document.getElementById(`sortIcon_${col}`);
    if (!el) return;
    el.textContent = sortColumn === col ? (sortDirection === 'desc' ? '▼' : '▲') : '';
  });

  procs.sort((a, b) => {
    let vA, vB;
    if (isGroupedView) {
      vA = sortColumn === 'cpu_percent' ? (a.total_cpu_percent || 0) : (sortColumn === 'memory_percent' ? (a.total_memory_percent || 0) : (a.total_rss_bytes || 0));
      vB = sortColumn === 'cpu_percent' ? (b.total_cpu_percent || 0) : (sortColumn === 'memory_percent' ? (b.total_memory_percent || 0) : (b.total_rss_bytes || 0));
    } else {
      vA = a[sortColumn] || 0;
      vB = b[sortColumn] || 0;
    }
    return sortDirection === 'desc' ? (vB > vA ? 1 : -1) : (vA > vB ? 1 : -1);
  });

  const badge = document.getElementById('procCountBadge');
  if (badge) badge.textContent = procs.length;
  const navTag = document.getElementById('navTagProcCount');
  if (navTag) navTag.textContent = procs.length;

  if (procs.length === 0) {
    tbody.innerHTML = `
      <tr><td colspan="6">
        <div class="empty">
          <svg fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          <span class="empty-title">${esc(t('noProcs'))}</span>
          <span class="empty-desc">${esc(t('noProcsDesc'))}</span>
        </div>
      </td></tr>`;
    return;
  }

  // Relative bar scale: the heaviest row is 100%.
  const maxRss = procs.reduce((max, p) => Math.max(max, isGroupedView ? (p.total_rss_bytes || 0) : (p.rss_bytes || 0)), 1);

  procs.forEach((item, index) => {
    const rank = index + 1;
    const rankBadge = `<span class="rank${rank <= 3 ? ' top' : ''}">${rank}</span>`;

    if (isGroupedView) {
      const lowerName = (item.name || '').toLowerCase();
      const isExpanded = expandedGroups.has(lowerName) || expandedGroups.has(item.name);
      const hasServices = item.all_services && item.all_services.length > 0;

      // Opaque, alphanumeric key: never interpolate an OS-supplied name into
      // an inline event handler.
      const groupKey = `g${index}`;
      procStore.set(groupKey, item);

      const memPct = Math.min(100, Math.max(4, Math.round(((item.total_rss_bytes || 0) / maxRss) * 100)));
      const cpu = item.total_cpu_percent || 0;

      const row = document.createElement('tr');
      row.className = 'trow group';
      row.innerHTML = `
        <td>
          <div class="row" style="gap: 8px;">
            ${rankBadge}
            <button type="button" class="expander${isExpanded ? ' open' : ''}" onclick="toggleExpandGroupByKey('${groupKey}', event)">&#9654;</button>
            <div class="grow">
              <div class="row-wrap" style="gap: 7px;">
                <span class="proc-name">${esc(item.friendly_name || item.name)}</span>
                ${item.process_count > 1 ? `<span class="badge badge-mono">${item.process_count} ${esc(t('procsShort'))}</span>` : ''}
                ${hasServices ? `<span class="badge badge-info">${item.all_services.length} ${esc(t('svcsShort'))}</span>` : ''}
              </div>
              <span class="proc-exe truncate">${esc(item.name)}</span>
            </div>
          </div>
        </td>
        <td class="num"><span class="cat ${categoryClass(item.category)}">${esc(item.category)}</span></td>
        <td class="num">
          <div class="mem-cell">
            <span class="mem-val">${esc(item.total_rss_formatted)}</span>
            <div class="meter thin"><div class="meter-fill" style="width: ${memPct}%"></div></div>
          </div>
        </td>
        <td class="num muted">${item.total_memory_percent}%</td>
        <td class="num${cpu > 10 ? ' tone-danger' : ' muted'}">${cpu}%</td>
        <td class="act">
          <div class="row-actions" onclick="event.stopPropagation()">
            <button class="btn btn-xs" onclick="trimGroupByKey('${groupKey}')">Trim</button>
            <button class="btn btn-xs" onclick="openProcModalByKey('${groupKey}')">${esc(t('details'))}</button>
            <button class="btn btn-xs btn-danger" onclick="killGroupByKey('${groupKey}')">${esc(t('btnKill'))}</button>
          </div>
        </td>
      `;

      row.onclick = (e) => {
        if (e.target.closest('button')) return;
        toggleExpandGroup(item.name, e);
      };
      tbody.appendChild(row);

      if (isExpanded && item.children) {
        item.children.forEach((child, cIdx) => {
          const childKey = `g${index}c${cIdx}`;
          procStore.set(childKey, child);
          const childHasServices = child.services && child.services.length > 0;

          const cRow = document.createElement('tr');
          cRow.className = 'trow child';
          cRow.innerHTML = `
            <td>
              <div class="child-indent">
                <div class="row-wrap" style="gap: 7px;">
                  <span class="mono" style="font-weight: 700; font-size: 11.5px;">PID ${Number(child.pid) || 0}</span>
                  ${childHasServices ? `<span class="badge badge-info">${esc(child.services.join(', '))}</span>` : ''}
                </div>
                <span class="proc-exe truncate" title="${esc(child.cmdline || child.name)}">${esc(child.cmdline || child.name)}</span>
              </div>
            </td>
            <td class="num faint" style="font-size: 10.5px;">${child.threads} threads</td>
            <td class="num"><span class="mem-val">${esc(child.rss_formatted)}</span></td>
            <td class="num muted">${child.memory_percent}%</td>
            <td class="num muted">${child.cpu_percent}%</td>
            <td class="act">
              <div class="row-actions" onclick="event.stopPropagation()">
                <button class="btn btn-xs" onclick="openProcModalByKey('${childKey}')">${esc(t('details'))}</button>
                <button class="btn btn-xs" onclick="trimSingleProcess(${Number(child.pid) || 0})">Trim</button>
                <button class="btn btn-xs btn-danger" onclick="killProcessByKey('${childKey}')">&#10005;</button>
              </div>
            </td>
          `;
          tbody.appendChild(cRow);
        });
      }

    } else {
      const flatKey = `f${index}`;
      procStore.set(flatKey, item);
      const hasServices = item.services && item.services.length > 0;
      const memPct = Math.min(100, Math.max(4, Math.round(((item.rss_bytes || 0) / maxRss) * 100)));
      const cpu = item.cpu_percent || 0;

      const row = document.createElement('tr');
      row.className = 'trow';
      row.innerHTML = `
        <td>
          <div class="row" style="gap: 8px;">
            ${rankBadge}
            <div class="grow">
              <div class="row-wrap" style="gap: 7px;">
                <span class="proc-name">${esc(item.friendly_name || item.name)}</span>
                <span class="badge badge-mono badge-accent">PID ${Number(item.pid) || 0}</span>
                ${hasServices ? `<span class="badge badge-info">${esc(item.services.join(', '))}</span>` : ''}
              </div>
              <span class="proc-exe truncate" title="${esc(item.cmdline || item.name)}">${esc(item.cmdline || item.name)}</span>
            </div>
          </div>
        </td>
        <td class="num"><span class="cat ${categoryClass(item.category)}">${esc(item.category)}</span></td>
        <td class="num">
          <div class="mem-cell">
            <span class="mem-val">${esc(item.rss_formatted)}</span>
            <div class="meter thin"><div class="meter-fill" style="width: ${memPct}%"></div></div>
          </div>
        </td>
        <td class="num muted">${item.memory_percent}%</td>
        <td class="num${cpu > 10 ? ' tone-danger' : ' muted'}">${cpu}%</td>
        <td class="act">
          <div class="row-actions" onclick="event.stopPropagation()">
            <button class="btn btn-xs" onclick="trimSingleProcess(${Number(item.pid) || 0})">Trim</button>
            <button class="btn btn-xs" onclick="openProcModalByKey('${flatKey}')">${esc(t('details'))}</button>
            <button class="btn btn-xs btn-danger" onclick="killProcessByKey('${flatKey}')">${esc(t('btnKill'))}</button>
          </div>
        </td>
      `;
      tbody.appendChild(row);
    }
  });
}

async function trimGroup(groupName) {
  try {
    const res = await fetch('/api/trim_group', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: groupName })
    });
    const data = await res.json();
    showToast(data.success ? (currentLang === 'he' ? "שחרור זיכרון הושלם" : "RAM Trimmed") : "Notice", data.message);
    await fetchProcesses();
    await fetchStats();
  } catch (err) {
    showToast("Error", err.message);
  }
}

// -------------------------------------------------------------
// Key-based action dispatch
// -------------------------------------------------------------
// Inline handlers only ever receive an opaque row key. The real process name
// is looked up from procStore, so a hostile executable name can never break
// out of the handler's string literal.
function trimGroupByKey(key) {
  const item = procStore.get(key);
  if (item) trimGroup(item.name);
}

function killGroupByKey(key) {
  const item = procStore.get(key);
  if (item) killGroup(item.name);
}

function killProcessByKey(key) {
  const item = procStore.get(key);
  if (item) killProcess(item.pid, item.name);
}

function toggleExpandGroupByKey(key, event) {
  const item = procStore.get(key);
  if (item) toggleExpandGroup(item.name, event);
}

/** Maps a backend category name to its CSS colour class. */
function categoryClass(cat) {
  switch (cat) {
    case 'Browsers': return 'cat-browsers';
    case 'Development': return 'cat-development';
    case 'Communication': return 'cat-communication';
    case 'System': return 'cat-system';
    case 'Background & Services': return 'cat-background';
    case 'Apps': return 'cat-apps';
    default: return 'cat-default';
  }
}

// Kept as an alias so older call sites keep working.
function getCategoryColor(cat) {
  return categoryClass(cat);
}

function toggleExpandGroup(groupName, event) {
  if (event && event.stopPropagation) {
    event.stopPropagation();
  }
  const key = (groupName || '').toLowerCase();
  if (expandedGroups.has(key) || expandedGroups.has(groupName)) {
    expandedGroups.delete(key);
    expandedGroups.delete(groupName);
  } else {
    expandedGroups.add(key);
  }
  renderProcessTable();
}

function setGroupedView(isGrouped) {
  isGroupedView = !!isGrouped;
  const btnG = document.getElementById('btnViewAppGrouped');
  const btnF = document.getElementById('btnViewFlatPids');
  if (btnG) btnG.classList.toggle('active', isGroupedView);
  if (btnF) btnF.classList.toggle('active', !isGroupedView);
  fetchProcesses();
}

function setCategoryFilter(cat) {
  currentCategory = cat;
  document.querySelectorAll('#categoryFilterContainer .pill').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-category') === cat);
  });
  fetchProcesses();
}

function clearSearch() {
  const input = document.getElementById('procSearchInput');
  if (input) input.value = '';
  searchQuery = '';
  const clearBtn = document.getElementById('btnClearSearch');
  if (clearBtn) clearBtn.classList.add('hidden');
  fetchProcesses();
}

function filterProcesses() {
  const input = document.getElementById('procSearchInput');
  searchQuery = input ? input.value.trim() : '';
  const clearBtn = document.getElementById('btnClearSearch');
  if (clearBtn) {
    if (searchQuery.length > 0) {
      clearBtn.classList.remove('hidden');
    } else {
      clearBtn.classList.add('hidden');
    }
  }
  fetchProcesses();
}

function sortBy(column) {
  if (sortColumn === column) {
    sortDirection = sortDirection === 'desc' ? 'asc' : 'desc';
  } else {
    sortColumn = column;
    sortDirection = 'desc';
  }
  renderProcessTable();
}

// -------------------------------------------------------------
// Chart.js Visualizations
// -------------------------------------------------------------

// Chart.js draws to a canvas and cannot read CSS custom properties, so the
// palette is mirrored here per theme and re-applied whenever the theme changes.
const CHART_PALETTE = {
  dark: {
    accent: '#5d8bff',
    accentFill: 'rgba(93, 139, 255, 0.14)',
    muted: '#6b7489',
    grid: 'rgba(255, 255, 255, 0.05)',
    tick: '#6b7489',
    text: '#eef1f8',
    tooltipBg: '#171b28',
    tooltipLine: 'rgba(255, 255, 255, 0.16)',
    donutBorder: '#11141f'
  },
  light: {
    accent: '#4f6ef7',
    accentFill: 'rgba(79, 110, 247, 0.12)',
    muted: '#79839a',
    grid: 'rgba(16, 24, 40, 0.07)',
    tick: '#79839a',
    text: '#0f1420',
    tooltipBg: '#ffffff',
    tooltipLine: 'rgba(16, 24, 40, 0.18)',
    donutBorder: '#ffffff'
  }
};

function chartInk() {
  return CHART_PALETTE[currentTheme] || CHART_PALETTE.dark;
}

/** Re-tints both charts in place after a theme switch. */
function repaintCharts() {
  const ink = chartInk();

  // Every access is optional-chained: a theme switch is cosmetic and must
  // never be able to throw, whatever state the charts happen to be in.
  if (timelineChart) {
    const ds = timelineChart.data?.datasets || [];
    if (ds[0]) {
      ds[0].borderColor = ink.accent;
      ds[0].backgroundColor = ink.accentFill;
    }
    if (ds[1]) ds[1].borderColor = ink.muted;

    const scales = timelineChart.options?.scales;
    if (scales) {
      ['x', 'y'].forEach(axis => {
        if (scales[axis]?.grid) scales[axis].grid.color = ink.grid;
        if (scales[axis]?.ticks) scales[axis].ticks.color = ink.tick;
      });
    }

    const tip = timelineChart.options?.plugins?.tooltip;
    if (tip) {
      tip.backgroundColor = ink.tooltipBg;
      tip.titleColor = ink.accent;
      tip.bodyColor = ink.text;
      tip.borderColor = ink.tooltipLine;
    }

    timelineChart.update('none');
  }

  if (categoryChart) {
    const ds = categoryChart.data?.datasets?.[0];
    if (ds) ds.borderColor = ink.donutBorder;

    const tip = categoryChart.options?.plugins?.tooltip;
    if (tip) {
      tip.backgroundColor = ink.tooltipBg;
      tip.bodyColor = ink.text;
      tip.borderColor = ink.tooltipLine;
    }
    categoryChart.update();
  }
}

function initCharts() {
  // Chart.js throws "Canvas is already in use" if a second chart is attached
  // to the same canvas, so building twice is never correct.
  if (timelineChart || categoryChart) return;

  const CHART_INK = chartInk();
  const timelineCanvas = document.getElementById('timelineChart');
  if (timelineCanvas) {
    timelineChart = new Chart(timelineCanvas.getContext('2d'), {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'In-Use (GB)',
            borderColor: CHART_INK.accent,
            backgroundColor: CHART_INK.accentFill,
            borderWidth: 1.75,
            fill: true,
            tension: 0.25,
            pointRadius: 0,
            data: []
          },
          {
            label: 'Standby Cache (GB)',
            borderColor: CHART_INK.muted,
            backgroundColor: 'transparent',
            borderWidth: 1,
            borderDash: [3, 3],
            tension: 0.25,
            pointRadius: 0,
            data: []
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        interaction: { mode: 'index', intersect: false },
        scales: {
          x: {
            grid: { color: CHART_INK.grid, drawTicks: false },
            border: { display: false },
            ticks: { color: CHART_INK.tick, font: { size: 10, family: 'Consolas' }, maxTicksLimit: 8, padding: 6 }
          },
          y: {
            grid: { color: CHART_INK.grid, drawTicks: false },
            border: { display: false },
            ticks: { color: CHART_INK.tick, font: { size: 10, family: 'Consolas' }, padding: 8 }
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: CHART_INK.tooltipBg,
            titleColor: CHART_INK.accent,
            bodyColor: CHART_INK.text,
            borderColor: CHART_INK.tooltipLine,
            borderWidth: 1,
            padding: 10,
            displayColors: false
          }
        }
      }
    });
  }

  const categoryCanvas = document.getElementById('categoryChart');
  if (categoryCanvas) {
    categoryChart = new Chart(categoryCanvas.getContext('2d'), {
      type: 'doughnut',
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: ['#5d8bff', '#8b7bff', '#a06bff', '#38c8c0', '#f5b544', '#34d399', '#ff6b7d'],
          borderWidth: 2,
          borderColor: CHART_INK.donutBorder
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: CHART_INK.tooltipBg,
            borderColor: CHART_INK.tooltipLine,
            borderWidth: 1,
            padding: 10,
            callbacks: { label: (ctx) => ` ${ctx.label}: ${ctx.raw}%` }
          }
        }
      }
    });
  }
}

function updateTimelineChart(history) {
  if (!timelineChart || !history) return;
  timelineChart.data.labels = history.map(h => h.time);
  timelineChart.data.datasets[0].data = history.map(h => h.used_gb);
  timelineChart.data.datasets[1].data = history.map(h => h.cached_gb);
  timelineChart.update('none');
}

function updateCategoryChart(categories) {
  if (!categoryChart || !categories) return;

  const validCats = categories.filter(c => c.bytes > 0);
  categoryChart.data.labels = validCats.map(c => currentLang === 'he' ? c.label_he : c.name);
  categoryChart.data.datasets[0].data = validCats.map(c => c.percent);
  categoryChart.data.datasets[0].backgroundColor = validCats.map(c => c.color);
  categoryChart.update();

  const leg = document.getElementById('categoryLegend');
  if (!leg) return;

  leg.innerHTML = '';
  validCats.forEach(c => {
    const item = document.createElement('div');
    item.className = 'legend-row';
    item.innerHTML = `
      <span class="legend-key">
        <span class="legend-dot" style="background: ${esc(c.color)}"></span>
        <span class="truncate">${esc(currentLang === 'he' ? c.label_he : c.name)}</span>
      </span>
      <span class="legend-val">${esc(c.formatted)}</span>
    `;
    leg.appendChild(item);
  });
}

// -------------------------------------------------------------
// Modals & Process Details
// -------------------------------------------------------------

let toastTimer = null;
const toastQueue = [];
let toastShowing = false;

/**
 * Third argument is the tone ('warn' | 'danger' | 'ok' | 'accent'). Call sites
 * have been passing it for a long time; it is finally rendered.
 *
 * Toasts queue instead of overwriting each other, so a burst of warnings (a
 * failed restore point followed by a missing-elevation notice) is actually
 * readable rather than a single flash of the last one.
 */
function showToast(title, message, tone) {
  toastQueue.push({ title, message, tone });
  if (!toastShowing) drainToastQueue();
}

function drainToastQueue() {
  const toast = document.getElementById('toast');
  if (!toast) { toastQueue.length = 0; return; }

  const next = toastQueue.shift();
  if (!next) {
    toastShowing = false;
    return;
  }

  toastShowing = true;
  document.getElementById('toastTitle').textContent = next.title;
  document.getElementById('toastMessage').textContent = next.message;

  toast.classList.remove('toast-warn', 'toast-danger', 'toast-ok');
  if (next.tone === 'warn' || next.tone === 'danger' || next.tone === 'ok') {
    toast.classList.add('toast-' + next.tone);
  }

  toast.classList.add('show');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(drainToastQueue, 260);
  }, toastQueue.length ? 2600 : 3800);
}

const procDetailsCache = new Map();

function openProcModalByKey(key) {
  const proc = procStore.get(key);
  if (!proc) return;
  openProcModal(proc);
}

function openProcModalByName(rawName) {
  if (!rawName) return;
  const wanted = String(rawName).toLowerCase();
  for (const proc of procStore.values()) {
    if ((proc.name || '').toLowerCase() === wanted) {
      openProcModal(proc);
      return;
    }
  }
  // Not currently rendered (filtered out / flat view): fall back to a lookup.
  const match = rawProcesses.find(p => (p.name || '').toLowerCase() === wanted);
  if (match) openProcModal(match);
}

async function openProcModal(proc) {
  currentModalProc = proc;
  const isGroup = !!proc.total_rss_bytes;
  currentModalPid = isGroup ? (proc.main_pid || 0) : (proc.pid || 0);

  // Initial fast display from available list data
  document.getElementById('modalProcName').textContent = proc.friendly_name || proc.name;
  document.getElementById('modalRawName').textContent = proc.name;
  const catBadge = document.getElementById('modalCategoryBadge');
  catBadge.textContent = proc.category || '';
  catBadge.className = `badge`;
  document.getElementById('modalProcPid').textContent = isGroup
    ? `${t('groupOf')} · ${proc.process_count} ${t('procsShort')}`
    : `PID: ${proc.pid}`;

  document.getElementById('modalExplanationDesc').textContent = t('loadingDeep');
  document.getElementById('modalWhyInMemory').textContent = t('checkingDetails');

  document.getElementById('modalProcRss').textContent = isGroup ? proc.total_rss_formatted : proc.rss_formatted;
  document.getElementById('modalProcVms').textContent = isGroup ? proc.total_vms_formatted : proc.vms_formatted;
  document.getElementById('modalProcPercent').textContent = `${isGroup ? proc.total_memory_percent : proc.memory_percent}%`;
  document.getElementById('modalProcCpu').textContent = `${isGroup ? proc.total_cpu_percent : proc.cpu_percent}%`;

  document.getElementById('modalProcPath').textContent = t('loading');
  document.getElementById('modalProcCmd').textContent = proc.name;

  const btnKill = document.getElementById('modalBtnKill');
  btnKill.onclick = () => {
    if (isGroup) {
      killGroup(proc.name);
    } else {
      killProcess(proc.pid, proc.name);
    }
    closeProcModal();
  };

  const modal = document.getElementById('procModal');
  modal.classList.remove('hidden');

  // Fetch full details and explanation on-demand (Lazy Loading)
  const cacheKey = `${currentModalPid}_${proc.name}`;
  let details = procDetailsCache.get(cacheKey);

  if (!details) {
    try {
      const res = await fetch(`/api/process_details?pid=${currentModalPid}&name=${encodeURIComponent(proc.name)}`);
      if (res.ok) {
        details = await res.json();
        procDetailsCache.set(cacheKey, details);
      }
    } catch (e) {
      console.warn('Failed to fetch detailed explanation:', e);
    }
  }

  // Update modal with rich details once available
  if (details && currentModalProc === proc) {
    const exp = details.explanation || {};

    document.getElementById('modalProcName').textContent = currentLang === 'he' ? (exp.title_he || details.friendly_name) : (exp.title_en || details.name);
    document.getElementById('modalCategoryBadge').textContent = exp.category || details.category || '';
    document.getElementById('modalExplanationDesc').textContent = currentLang === 'he' ? (exp.description_he || 'אין מידע נוסף') : (exp.description_en || 'No additional info');
    document.getElementById('modalWhyInMemory').textContent = currentLang === 'he' ? (exp.why_in_memory_he || 'פועל ברקע.') : (exp.why_in_memory_he || 'Running in background.');

    const safetyCard = document.getElementById('modalSafetyCard');
    const safetyBadge = document.getElementById('modalSafetyBadge');
    const safetyDesc = document.getElementById('modalSafetyDesc');

    const isSafe = exp.is_safe_to_kill !== false;

    safetyCard.className = 'panel';
    safetyBadge.className = `badge ${isSafe ? 'badge-ok' : 'badge-danger'}`;
    safetyBadge.textContent = isSafe ? t('safeToKill') : t('protectedProc');
    safetyDesc.textContent = currentLang === 'he'
      ? (exp.kill_impact_he || (isSafe ? t('safeToKillDesc') : t('protectedProcDesc')))
      : (exp.kill_impact_en || (isSafe ? t('safeToKillDesc') : t('protectedProcDesc')));

    const svcsContainer = document.getElementById('modalServicesContainer');
    const svcsList = document.getElementById('modalServicesList');
    const services = (exp.services_list && exp.services_list.length > 0)
      ? exp.services_list
      : (details.services ? details.services.map(s => ({ service_name: s, title_he: `שירות Windows (${s})`, desc_he: "שירות רקע של מערכת ההפעלה." })) : []);

    if (services && services.length > 0) {
      svcsContainer.classList.remove('hidden');
      svcsList.innerHTML = '';
      services.forEach(s => {
        const item = document.createElement('div');
        item.className = "list-row";
        item.innerHTML = `
          <div class="grow" style="min-width: 0;">
            <span class="list-title">${esc(s.title_he || s.service_name)}</span>
            <span class="opt-desc">${esc(s.desc_he || '')}</span>
          </div>
        `;
        svcsList.appendChild(item);
      });
    } else {
      svcsContainer.classList.add('hidden');
    }

    document.getElementById('modalProcPath').textContent = details.exe_path || (isGroup ? proc.main_exe : proc.exe_path) || 'N/A';
    document.getElementById('modalProcCmd').textContent = details.cmdline || (isGroup ? proc.main_exe : proc.cmdline) || proc.name;
  }
}

function closeProcModal() {
  const modal = document.getElementById('procModal');
  modal.classList.add('hidden');
}

function exportSnapshotReport() {
  if (!rawStats) return;

  const reportData = {
    generated_at: new Date().toISOString(),
    stats: rawStats,
    diagnostics: rawDiagnostics,
    top_processes: rawProcesses.slice(0, 30)
  };

  const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `Polaris_Report_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast(t('settingExport'), currentLang === 'he'
    ? 'הדוח נשמר בתיקיית ההורדות.'
    : 'The report was saved to your Downloads folder.');
}

// -------------------------------------------------------------
// System Maintenance & Repair Engine
// -------------------------------------------------------------

async function refreshRepairAudit() {
  const auditSizeElem = document.getElementById('auditRecoverableSize');
  const startupCountElem = document.getElementById('auditStartupCount');
  const highImpactElem = document.getElementById('auditHighImpactCount');
  const badgeStartupElem = document.getElementById('badgeStartupCount');
  const navTag = document.getElementById('navTagStartup');

  if (auditSizeElem) auditSizeElem.textContent = t('auditScanning');

  try {
    const [auditRes, startupRes] = await Promise.all([
      fetch('/api/revitalize/audit'),
      fetch('/api/startup/apps')
    ]);

    if (auditRes.ok) {
      const audit = await auditRes.json();
      if (auditSizeElem) {
        auditSizeElem.textContent = (audit.recoverable_temp_approx ? '~' : '') +
          (audit.recoverable_temp_formatted || '0 MB');
      }
      if (startupCountElem) startupCountElem.textContent = audit.startup_apps_count || '0';

      // The component-store cleanup is the slowest thing in the app, so it is
      // off by default and only nudged when the audit says it would pay off.
      const dismHint = document.getElementById('dismSuggestHint');
      if (dismHint) {
        const reason = (currentLang === 'he'
          ? audit.suggest_dism_reason_he
          : (audit.suggest_dism_reason_en || audit.suggest_dism_reason_he)) || '';
        dismHint.textContent = reason;
        dismHint.classList.toggle('hidden', !reason);
        dismHint.style.color = audit.suggest_dism_cleanup ? 'var(--warn)' : 'var(--text-faint)';
      }
      if (highImpactElem) highImpactElem.textContent = `${audit.high_impact_startup_count || 0} ${t('auditHighImpact')}`;

      if (navTag) {
        const high = audit.high_impact_startup_count || 0;
        navTag.textContent = high;
        navTag.className = 'nav-tag mono' + (high > 0 ? ' warn' : '');
        navTag.classList.toggle('hidden', high === 0);
      }
    } else if (auditSizeElem) {
      auditSizeElem.textContent = '--';
    }

    if (startupRes.ok) {
      const data = await startupRes.json();
      const apps = data.apps || [];
      if (badgeStartupElem) badgeStartupElem.textContent = apps.length;
      renderStartupApps(apps);
    }
  } catch (err) {
    console.error('Failed to load repair audit:', err);
    // Otherwise the tile is stuck reading "Scanning..." forever.
    if (auditSizeElem) auditSizeElem.textContent = '--';
  }
}

function renderStartupApps(apps) {
  const list = document.getElementById('startupAppsList');
  if (!list) return;
  list.innerHTML = '';

  if (!apps || apps.length === 0) {
    list.innerHTML = `<div class="empty span-2">
      <span class="empty-title">${esc(t('noStartup'))}</span>
    </div>`;
    return;
  }

  apps.forEach(app => {
    let impactClass = 'badge';
    if (app.impact === 'High') impactClass = 'badge badge-danger';
    else if (app.impact === 'Medium') impactClass = 'badge badge-warn';
    else if (app.impact === 'Low') impactClass = 'badge badge-ok';

    const item = document.createElement('div');
    item.className = 'list-row';
    item.innerHTML = `
      <div class="grow" style="min-width: 0;">
        <span class="list-title truncate">${esc(app.name)}</span>
        <span class="list-sub truncate" title="${esc(app.command)}">${esc(app.command)}</span>
      </div>
      <span class="${impactClass}">${esc(app.impact)} ${esc(t('impactSuffix'))}</span>
    `;
    list.appendChild(item);
  });
}

// Log rows are reconciled by uid rather than re-rendered wholesale: a DISM run
// produces a self-updating progress row, and rebuilding 1000 lines of innerHTML
// three times a second made the whole pane stutter.
const revitalizeLogNodes = new Map();
let revitalizeLogRev = 0;
let revitalizeTimerId = null;

const STEP_ICONS = {
  pending: '○',
  running: '●',
  done: '✓',
  failed: '!',
  skipped: '–'
};

function logToneClass(l) {
  if (l.level === 'SUCCESS' || l.level === 'DONE') return 'term-line term-ok';
  if (l.level === 'STEP') return 'term-line term-step';
  if (l.level === 'START' || l.level === 'SAFETY') return 'term-line term-ok';
  if (l.level === 'ERROR') return 'term-line term-err';
  if (l.level === 'WARN') return 'term-line term-warn';
  if (l.text.includes('[DISM]')) return 'term-line term-dism';
  if (l.text.includes('[SFC]')) return 'term-line term-sfc';
  if (l.text.includes('[WU]')) return 'term-line term-sfc';
  if (l.text.includes('[NET]') || l.text.includes('[DNS]')) return 'term-line term-net';
  if (l.text.startsWith('[PLAN]') || l.text.startsWith('[?]') || l.text.startsWith('[$]')) return 'term-line term-plan';
  return 'term-line term-info';
}

/**
 * Draws incremental log rows into a terminal box.
 *
 * `nodeMap` keeps one DOM node per row uid, so a self-updating row (a progress
 * counter) is edited in place instead of appended again, and the whole list is
 * never rebuilt. Shared by the maintenance centre and the uninstall wizard.
 */
function appendTerminalLogs(box, logs, nodeMap) {
  if (!box || !logs || !logs.length) return;

  // Within ~24px of the bottom counts as "following along"; don't yank the
  // view back down if the user scrolled up to read something.
  const wasAtBottom = (box.scrollHeight - box.scrollTop - box.clientHeight) < 24;

  logs.forEach(l => {
    let node = nodeMap.get(l.uid);
    if (!node) {
      node = document.createElement('div');
      nodeMap.set(l.uid, node);
      box.appendChild(node);
    }
    node.className = logToneClass(l);
    node.innerHTML = `<span class="term-time">[${escapeHtml(l.time)}]</span>${escapeHtml(l.text)}`;
  });

  if (wasAtBottom) box.scrollTop = box.scrollHeight;
}

function appendRevitalizeLogs(box, logs) {
  appendTerminalLogs(box, logs, revitalizeLogNodes);
}

function renderRevitalizeSteps(steps) {
  renderStepList(document.getElementById('revitalizeStepList'), steps);
}

function renderStepList(list, steps) {
  if (!list || !steps) return;

  const he = currentLang === 'he';
  const visible = steps.filter(s => s.status !== 'skipped');
  const skipped = steps.filter(s => s.status === 'skipped');

  const row = (s, index) => {
    const title = he ? s.title_he : (s.title_en || s.title_he);
    const explain = he ? s.explain_he : (s.explain_en || s.explain_he);
    const detail = he ? s.detail_he : (s.detail_en || s.detail_he);
    const time = s.elapsed ? `${Number(s.elapsed).toFixed(1)}s` :
      (s.status === 'pending' ? `~${s.est_seconds}s` : '');

    return `
      <li class="step-row is-${esc(s.status)}">
        <span class="step-icon">${STEP_ICONS[s.status] || '○'}</span>
        <span class="step-body">
          <span class="step-title">${index ? index + '. ' : ''}${esc(title)}</span>
          <span class="step-explain">${esc(explain)}</span>
          ${detail ? `<span class="step-detail">${esc(detail)}</span>` : ''}
        </span>
        <span class="step-time">${esc(time)}</span>
      </li>`;
  };

  list.innerHTML =
    visible.map((s, i) => row(s, i + 1)).join('') +
    skipped.map(s => row(s, 0)).join('');
}

function fmtClock(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  const m = Math.floor(s / 60);
  if (m >= 60) {
    const h = Math.floor(m / 60);
    return `${h}:${String(m % 60).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
  }
  return `${String(m).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
}

async function runSafeRevitalization() {
  const btn = document.getElementById('btnRunRevitalize');
  const txt = document.getElementById('txtBtnRunRevitalize');
  const originalText = txt.textContent;

  const options = {
    flush_ram: document.getElementById('chkFlushRam')?.checked ?? true,
    clean_temp: document.getElementById('chkCleanTemp')?.checked ?? true,
    retrim_ssd: document.getElementById('chkRetrimSsd')?.checked ?? true,
    flush_dns: document.getElementById('chkFlushDns')?.checked ?? true,
    dism_restore: document.getElementById('chkDismRestore')?.checked ?? false,
    // Every opt-in repair defaults to false: a missing checkbox must never
    // silently enable the slowest, least reversible step in the app.
    dism_cleanup: document.getElementById('chkDismCleanup')?.checked ?? false,
    sfc_scan: document.getElementById('chkSfc')?.checked ?? false,
    reset_wu: document.getElementById('chkWuReset')?.checked ?? false,
    reset_network: document.getElementById('chkNetReset')?.checked ?? false,
    reset_spooler: document.getElementById('chkSpoolerReset')?.checked ?? false
  };

  btn.disabled = true;
  btn.classList.add('is-busy');
  txt.textContent = t('runningMaintenance');

  const resultsContainer = document.getElementById('revitalizeResultsContainer');
  const terminalBox = document.getElementById('revitalizeTerminalLogs');
  const tasksList = document.getElementById('revitalizeTasksList');
  const progressBar = document.getElementById('revitalizeProgressBar');
  const percentBadge = document.getElementById('revitalizePercentBadge');
  const stepText = document.getElementById('txtRevitalizeCurrentStep');

  if (resultsContainer) {
    resultsContainer.classList.remove('hidden');
    resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  const elapsedElem = document.getElementById('revitalizeElapsed');
  const etaElem = document.getElementById('revitalizeEta');
  const stepCountElem = document.getElementById('revitalizeStepCount');
  const stepList = document.getElementById('revitalizeStepList');

  if (tasksList) tasksList.innerHTML = '';
  if (stepList) stepList.innerHTML = '';
  revitalizeLogNodes.clear();
  revitalizeLogRev = 0;
  if (terminalBox) terminalBox.innerHTML = `<div class="term-line term-info">[System] ${currentLang === 'he' ? 'מתחיל פעולות תחזוקה ותיקון...' : 'Starting system repair routine...'}</div>`;
  if (progressBar) progressBar.style.width = '0%';
  if (percentBadge) percentBadge.textContent = '0%';
  if (etaElem) etaElem.textContent = '';
  if (stepCountElem) stepCountElem.textContent = '';

  const finish = () => {
    if (revitalizePollTimer) { clearInterval(revitalizePollTimer); revitalizePollTimer = null; }
    if (revitalizeTimerId) { clearInterval(revitalizeTimerId); revitalizeTimerId = null; }
    btn.disabled = false;
    btn.classList.remove('is-busy');
    txt.textContent = originalText;
  };

  try {
    const startRes = await fetch('/api/revitalize/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ options })
    });

    if (!startRes.ok) throw new Error("Failed to start maintenance");

    // The backend answers 200 with {success:false} when a run is already in
    // flight; without this check the UI would attach itself to that other run.
    const startBody = await startRes.json().catch(() => ({ success: true }));
    if (startBody.success === false) {
      throw new Error(startBody.message || 'A maintenance run is already in progress.');
    }

    if (revitalizePollTimer) clearInterval(revitalizePollTimer);
    if (revitalizeTimerId) clearInterval(revitalizeTimerId);

    // The clock ticks locally every second so it stays smooth between polls -
    // the backend's elapsed value only corrects it.
    let elapsedSeconds = 0;
    if (elapsedElem) elapsedElem.textContent = fmtClock(0);
    revitalizeTimerId = setInterval(() => {
      elapsedSeconds += 1;
      if (elapsedElem) elapsedElem.textContent = fmtClock(elapsedSeconds);
    }, 1000);

    revitalizePollTimer = setInterval(async () => {
      try {
        const progRes = await fetch(`/api/revitalize/progress?since=${revitalizeLogRev}`);
        if (!progRes.ok) return;
        const prog = await progRes.json();

        if (typeof prog.log_rev === 'number') revitalizeLogRev = prog.log_rev;

        if (progressBar) progressBar.style.width = `${prog.percent}%`;
        if (percentBadge) percentBadge.textContent = `${prog.percent}%`;
        const stepLabel = currentLang === 'he'
          ? prog.current_step
          : (prog.current_step_en || prog.current_step);
        if (stepLabel && stepText) stepText.textContent = stepLabel;

        if (typeof prog.elapsed_seconds === 'number') {
          elapsedSeconds = Math.round(prog.elapsed_seconds);
          if (elapsedElem) elapsedElem.textContent = fmtClock(elapsedSeconds);
        }

        if (etaElem) {
          etaElem.textContent = prog.running && prog.eta_seconds > 0
            ? (currentLang === 'he' ? `נותרו כ-${fmtClock(prog.eta_seconds)}` : `~${fmtClock(prog.eta_seconds)} left`)
            : '';
        }
        if (stepCountElem && prog.total_steps) {
          stepCountElem.textContent = currentLang === 'he'
            ? `שלב ${Math.min(prog.done_steps + 1, prog.total_steps)} מתוך ${prog.total_steps}`
            : `Step ${Math.min(prog.done_steps + 1, prog.total_steps)} of ${prog.total_steps}`;
        }

        renderRevitalizeSteps(prog.steps);
        appendRevitalizeLogs(terminalBox, prog.logs);

        if (!prog.running && prog.results) {
          finish();

          const data = prog.results;
          const freedBadge = document.getElementById('revitalizeTotalFreedBadge');
          if (freedBadge) freedBadge.textContent = `${t('totalFreed')} ${data.total_freed_formatted}`;
          if (stepCountElem) {
            stepCountElem.textContent = currentLang === 'he'
              ? `${data.tasks.length} פעולות הושלמו`
              : `${data.tasks.length} tasks completed`;
          }

          if (tasksList && data.tasks) {
            tasksList.innerHTML = '';
            data.tasks.forEach(task => {
              const item = document.createElement('div');
              item.className = 'task-done' + (task.status === 'notice' ? ' is-notice' : '');
              const mark = task.status === 'success' ? '✓' : '!';
              const secs = task.elapsed ? ` · ${Number(task.elapsed).toFixed(1)}s` : '';
              item.innerHTML = `
                <span class="task-check">${mark}</span>
                <div>
                  <span class="task-title">${esc(currentLang === 'he' ? task.title_he : (task.title_en || task.title_he))}</span>
                  <span class="task-detail">${esc(currentLang === 'he' ? task.detail_he : (task.detail_en || task.detail_he))}${esc(secs)}</span>
                </div>
              `;
              tasksList.appendChild(item);
            });

            // Anything deliberately not run is shown too, so the report never
            // looks like it silently dropped a task.
            (data.skipped || []).forEach(task => {
              const item = document.createElement('div');
              item.className = 'task-done is-skipped';
              item.innerHTML = `
                <span class="task-check">–</span>
                <div>
                  <span class="task-title">${esc(currentLang === 'he' ? task.title_he : (task.title_en || task.title_he))}</span>
                  <span class="task-detail">${currentLang === 'he' ? 'לא נבחר להרצה.' : 'Not selected.'}</span>
                </div>
              `;
              tasksList.appendChild(item);
            });
          }

          const took = fmtClock(data.elapsed_seconds || 0);
          showToast(
            t('toastMaintDone'),
            currentLang === 'he'
              ? `הסתיים ב-${took}. פונו ${data.total_freed_formatted}.`
              : `Finished in ${took}. Reclaimed ${data.total_freed_formatted}.`
          );

          await fetchStats();
          await fetchDiagnostics();
          await fetchProcesses();
          await refreshRepairAudit();
        }

      } catch (pollErr) {
        console.error("Poll error:", pollErr);
      }
    }, 400);

  } catch (err) {
    finish();
    showToast("Error", err.message);
    if (terminalBox) {
      // appendChild, not innerHTML +=, which would re-parse the container and
      // orphan every node held in revitalizeLogNodes.
      const line = document.createElement('div');
      line.className = 'term-line term-err';
      line.textContent = `[Error] ${err.message}`;
      terminalBox.appendChild(line);
      terminalBox.scrollTop = terminalBox.scrollHeight;
    }
  }
}

// -------------------------------------------------------------
// BSOD & Crash History Inspector
// -------------------------------------------------------------

async function fetchCrashHistory() {
  const list = document.getElementById('crashHistoryList');
  if (!list) return;

  try {
    const res = await fetch('/api/crashes');
    if (!res.ok) return;
    const data = await res.json();

    currentCrashes = data.crashes || [];
    crashStore.clear();
    // Index-based keys: crash ids are derived from event-log text and must not
    // be interpolated into inline handlers.
    currentCrashes.forEach((c, i) => crashStore.set(`c${i}`, c));

    const set = (id, value) => {
      const el = document.getElementById(id);
      if (el) el.textContent = value;
    };
    set('valTotalCrashes', data.total_crashes ?? 0);
    set('valBsodCount', data.bsod_count ?? 0);
    set('valPowerLossCount', data.power_loss_count ?? 0);

    const bsod = data.bsod_count || 0;
    const power = data.power_loss_count || 0;

    const healthBadge = document.getElementById('badgeCrashHealth');
    if (healthBadge) {
      if (bsod > 0) {
        healthBadge.className = 'badge badge-danger';
        healthBadge.textContent = t('healthBsod');
      } else if (power > 2) {
        healthBadge.className = 'badge badge-warn';
        healthBadge.textContent = t('healthPower');
      } else {
        healthBadge.className = 'badge badge-ok';
        healthBadge.textContent = t('healthStable');
      }
    }

    const navTag = document.getElementById('navTagCrashes');
    if (navTag) {
      const total = data.total_crashes || 0;
      navTag.textContent = total;
      navTag.className = 'nav-tag mono' + (bsod > 0 ? ' alert' : (power > 2 ? ' warn' : ''));
      navTag.classList.toggle('hidden', total === 0);
    }

    renderCrashHistory(currentCrashes);

  } catch (err) {
    console.error('Failed to fetch crash history:', err);
  }
}

let currentModalCrash = null;
let currentModalModules = [];

function renderCrashHistory(crashes) {
  const list = document.getElementById('crashHistoryList');
  if (!list) return;
  list.innerHTML = '';

  if (!crashes || crashes.length === 0) {
    list.innerHTML = `
      <div class="empty">
        <span class="tone-ok" style="font-size: 22px;">&#10003;</span>
        <span class="empty-title">${esc(t('noCrashes'))}</span>
        <span class="empty-desc">${esc(t('noCrashesDesc'))}</span>
      </div>`;
    return;
  }

  crashes.forEach((c, crashIndex) => {
    const crashKey = `c${crashIndex}`;

    let kind = 'other';
    let typeBadge = 'badge badge-accent';
    if (c.type === 'BSOD') { kind = 'bsod'; typeBadge = 'badge badge-danger'; }
    else if (c.type === 'Kernel-Power') { kind = 'power'; typeBadge = 'badge badge-warn'; }

    const confBadge = c.confidence_label ? `<span class="badge badge-mono badge-xs" style="background: rgba(239,68,68,0.15); color: var(--danger); border: 1px solid rgba(239,68,68,0.3);">${esc(c.confidence_label)}</span>` : '';
    const driverName = c.responsible_driver || 'ntoskrnl.exe';
    const is3rdParty = driverName !== 'ntoskrnl.exe' && driverName !== 'Kernel Minidump';

    const card = document.createElement('div');
    card.className = `crash-card ${kind}`;
    card.innerHTML = `
      <div class="spread">
        <div class="row-wrap" style="gap: 8px; align-items: center;">
          <span class="${typeBadge} badge-mono">${esc(c.type)}</span>
          <span class="list-title" style="font-weight: 600;">${esc(currentLang === 'he' ? c.title_he : (c.title_en || c.title_he))}</span>
          ${confBadge}
        </div>
        <div class="row" style="gap: 8px; align-items: center;">
          <span class="mono faint" style="font-size: 11px;">${esc(c.timestamp)}</span>
          <button class="btn btn-xs btn-accent" onclick="openCrashDetailModal('${crashKey}')">${esc(t('crashDetailsBtn'))}</button>
        </div>
      </div>

      <div class="crash-meta">
        <div class="row-wrap" style="gap: 12px; font-size: 11px; align-items: center;">
          <span class="muted">${esc(t('crashCodeShort'))} <code class="tone-accent" style="font-weight:700;">${esc(c.bugcheck_code || 'N/A')}</code></span>
          <span class="muted">${esc(t('crashDriverShort'))} <code style="color: ${is3rdParty ? 'var(--danger)' : 'var(--info)'}; font-weight:700; background: rgba(255,255,255,0.06); padding: 1px 6px; border-radius: 4px;">${esc(driverName)}</code></span>
          ${c.driver_info?.vendor ? `<span class="badge badge-mono badge-xs">${esc(c.driver_info.vendor)}</span>` : ''}
          ${c.driver_info?.category ? `<span class="faint" style="font-size: 10.5px;">(${esc(c.driver_info.category)})</span>` : ''}
        </div>
        <p class="crash-cause">${esc(currentLang === 'he' ? c.cause_he : (c.cause_en || c.cause_he))}</p>
      </div>
    `;
    list.appendChild(card);
  });
}

function openCrashDetailModal(crashId) {
  const c = crashStore.get(crashId);
  if (!c) return;
  currentModalCrash = c;
  currentModalModules = c.modules || [];

  const modal = document.getElementById('crashDetailModal');
  if (!modal) return;

  document.getElementById('crashModalTitle').textContent = currentLang === 'he' ? c.title_he : (c.title_en || c.title_he);
  document.getElementById('crashModalTimestamp').textContent = c.timestamp;
  document.getElementById('crashModalCause').textContent = currentLang === 'he' ? c.cause_he : (c.cause_en || c.cause_he);
  document.getElementById('crashModalSolution').textContent = currentLang === 'he' ? c.solution_he : (c.solution_en || c.solution_he);
  document.getElementById('crashModalBugcheck').textContent = `${c.bugcheck_name} (${c.bugcheck_code})`;
  
  const paramsEl = document.getElementById('crashModalParams');
  if (paramsEl) {
    if (c.bugcheck_parameters && c.bugcheck_parameters.length > 0) {
      paramsEl.textContent = c.bugcheck_parameters.join(' · ');
    } else {
      paramsEl.textContent = c.event_id ? `Event ID ${c.event_id}` : 'N/A';
    }
  }

  // 1. Populate Culprit Hero
  const driverName = c.responsible_driver || 'ntoskrnl.exe';
  const heroDriverName = document.getElementById('crashHeroDriverName');
  if (heroDriverName) heroDriverName.textContent = driverName;

  const heroDesc = document.getElementById('crashHeroDriverDesc');
  if (heroDesc) {
    heroDesc.textContent = c.driver_info?.desc_he || c.driver_info?.desc_en || (currentLang === 'he' ? c.cause_he : c.cause_en);
  }

  const heroCat = document.getElementById('crashHeroCategory');
  if (heroCat) heroCat.textContent = c.driver_info?.category || 'מערכת / ליבה';

  const heroVendor = document.getElementById('crashHeroVendor');
  if (heroVendor) heroVendor.textContent = c.driver_info?.vendor ? `יצרן: ${c.driver_info.vendor}` : 'יצרן: Microsoft / Third-Party';

  const heroMethod = document.getElementById('crashHeroResolutionMethod');
  if (heroMethod) heroMethod.textContent = c.resolution_method ? `שיטת פענוח: ${c.resolution_method}` : '';

  const confBadge = document.getElementById('crashModalConfidenceBadge');
  if (confBadge) {
    if (c.confidence_label) {
      confBadge.textContent = c.confidence_label;
      confBadge.style.display = 'inline-block';
    } else {
      confBadge.style.display = 'none';
    }
  }

  // 2. Hardware / Driver Info
  const info = c.driver_info;
  const meaning = document.getElementById('crashDriverMeaning');
  const version = document.getElementById('crashDriverVersion');
  if (meaning) {
    if (info && (info.matched || info.desc_he)) {
      meaning.textContent = `${info.desc_he || loc(info, 'description')} (${info.vendor || 'Unknown'})`;
      meaning.className = 'panel-text';
    } else {
      meaning.textContent = t('crashDriverUnknown');
      meaning.className = 'panel-text muted';
    }
  }
  if (version) {
    const installed = info && info.installed;
    version.textContent = installed
      ? `${t('crashDriverInstalled')}: ${installed.name} · v${installed.version} · ${installed.date}`
      : (info?.version ? `גרסת דרייבר שקרס: ${info.version}` : '');
  }

  // 3. Online Intelligence
  renderModalOnlineIntel(c.online_intelligence, driverName);

  // 4. Modules Explorer
  const modPanel = document.getElementById('crashModulesPanel');
  const modCount = document.getElementById('crashModulesCount');
  if (modPanel && modCount) {
    if (currentModalModules.length > 0) {
      modPanel.style.display = 'block';
      modCount.textContent = currentModalModules.length;
      renderCrashModulesTable(currentModalModules);
    } else {
      modPanel.style.display = 'none';
    }
  }

  // Raw Record
  document.getElementById('crashModalRaw').textContent = c.raw_message || c.filename || (c.file_path ? `קובץ: ${c.file_path}` : 'N/A');

  const sevBadge = document.getElementById('crashModalSeverityBadge');
  if (sevBadge) {
    sevBadge.textContent = c.severity || 'Critical';
    if (c.severity === 'Critical') sevBadge.className = 'badge badge-danger';
    else if (c.severity === 'High') sevBadge.className = 'badge badge-warn';
    else sevBadge.className = 'badge badge-accent';
  }

  modal.classList.remove('hidden');
}

function renderModalOnlineIntel(intel, driverName) {
  const summaryEl = document.getElementById('crashOnlineSummary');
  const linksRow = document.getElementById('crashOnlineLinksRow');
  if (!summaryEl || !linksRow) return;

  linksRow.innerHTML = '';

  if (intel) {
    summaryEl.textContent = currentLang === 'he' ? intel.online_summary_he : intel.online_summary_en;

    if (intel.google_search_url) {
      linksRow.innerHTML += `<a href="${esc(intel.google_search_url)}" target="_blank" class="btn-link-online">🌐 חיפוש פתרונות בגוגל</a>`;
    }
    if (intel.ms_docs_url) {
      linksRow.innerHTML += `<a href="${esc(intel.ms_docs_url)}" target="_blank" class="btn-link-online">📖 תיעוד רשמי ב-Microsoft Learn</a>`;
    }
    if (intel.vendor_download_url) {
      linksRow.innerHTML += `<a href="${esc(intel.vendor_download_url)}" target="_blank" class="btn-link-online tone-accent">📥 אתר הורדת דרייבר יצרן</a>`;
    }
    if (intel.ms_community_url) {
      linksRow.innerHTML += `<a href="${esc(intel.ms_community_url)}" target="_blank" class="btn-link-online">💬 קהילת התמיכה של מיקרוסופט</a>`;
    }
  } else {
    summaryEl.textContent = `לחץ על הכפתור לבדיקת מידע מאומת מהרשת עבור הדרייבר ${driverName}.`;
    linksRow.innerHTML = `<button class="btn btn-xs btn-accent" onclick="triggerModalOnlineLookup()">🔍 בצע בדיקה מקוונת עכשיו</button>`;
  }
}

async function triggerModalOnlineLookup() {
  if (!currentModalCrash) return;
  const btn = document.getElementById('btnRefreshOnlineLookup');
  const summaryEl = document.getElementById('crashOnlineSummary');
  if (btn) btn.textContent = 'בודק ברשת...';
  if (summaryEl) summaryEl.textContent = 'מתחבר למאגרי מידע ומבצע תחקור רשת...';

  try {
    const driverName = currentModalCrash.responsible_driver || 'ntoskrnl.exe';
    const code = currentModalCrash.bugcheck_code_raw || parseInt(currentModalCrash.bugcheck_code || '0', 16) || 0;

    const res = await fetch('/api/crashes/online_lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ driver_name: driverName, bugcheck_code: code })
    });
    const intel = await res.json();
    currentModalCrash.online_intelligence = intel;
    renderModalOnlineIntel(intel, driverName);
    showToast(currentLang === 'he' ? "בדיקה ברשת הושלמה" : "Online Check Complete", currentLang === 'he' ? `נמצאו נתוני רשת מאומתים עבור ${driverName}` : `Found online data for ${driverName}`);
  } catch (err) {
    if (summaryEl) summaryEl.textContent = `שגיאה בחיבור לרשת: ${err.message}`;
  } finally {
    if (btn) btn.textContent = '🔍 רענן בדיקה ברשת';
  }
}

function renderCrashModulesTable(modules) {
  const tbody = document.getElementById('crashModulesTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  modules.slice(0, 100).forEach(m => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="font-weight: 600; font-family: var(--font-mono);">${esc(m.name)}</td>
      <td class="mono faint" style="font-size: 10px;">${esc(m.base_address_hex || '0x0')} - ${esc(m.end_address_hex || '0x0')}</td>
      <td class="mono faint" style="font-size: 10.5px;">${esc(m.version || '--')}</td>
      <td class="faint" style="font-size: 10.5px;">${esc(m.timestamp || '--')}</td>
    `;
    tbody.appendChild(tr);
  });
}

function toggleCrashModulesExplorer() {
  const content = document.getElementById('crashModulesContent');
  const icon = document.getElementById('crashModulesToggleIcon');
  if (!content) return;
  const isHidden = content.style.display === 'none';
  content.style.display = isHidden ? 'block' : 'none';
  if (icon) icon.textContent = isHidden ? '▲ הסתר' : '▼ הצג';
}

function filterCrashModules(query) {
  const q = query.toLowerCase().trim();
  const filtered = currentModalModules.filter(m => m.name.toLowerCase().includes(q) || (m.path && m.path.toLowerCase().includes(q)));
  renderCrashModulesTable(filtered);
}

// Custom Minidump drag & drop / manual analysis
function handleDumpDragOver(e) {
  e.preventDefault();
  const dropzone = document.getElementById('minidumpDropzone');
  if (dropzone) dropzone.classList.add('dragover');
}

function handleDumpDragLeave(e) {
  e.preventDefault();
  const dropzone = document.getElementById('minidumpDropzone');
  if (dropzone) dropzone.classList.remove('dragover');
}

function handleDumpDrop(e) {
  e.preventDefault();
  const dropzone = document.getElementById('minidumpDropzone');
  if (dropzone) dropzone.classList.remove('dragover');

  if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
    const file = e.dataTransfer.files[0];
    if (file.name.toLowerCase().endsWith('.dmp')) {
      analyzeCustomDumpFile(file.path || file.name);
    } else {
      showToast("פורמט לא נתמך", "אנא בחר קובץ עם סיומת .dmp בלבד");
    }
  }
}

function handleCustomDumpSelected(e) {
  if (e.target.files && e.target.files.length > 0) {
    const file = e.target.files[0];
    // In pywebview or browser, get file path or name
    analyzeCustomDumpFile(file.path || file.name);
  }
}

async function analyzeCustomDumpFile(filePath) {
  const resultArea = document.getElementById('customDumpResultArea');
  if (resultArea) {
    resultArea.style.display = 'block';
    resultArea.innerHTML = `
      <div class="loading" style="padding: 20px; text-align: center;">
        <span class="tone-accent" style="font-weight: 600;">מפענח מבנה בינארי של Minidump, סורק מודולים ומצליב נתוני רשת...</span>
      </div>`;
  }

  try {
    const res = await fetch('/api/crashes/analyze_dump', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ file_path: filePath })
    });
    const data = await res.json();

    if (!data.success) {
      if (resultArea) {
        resultArea.innerHTML = `
          <div class="panel" style="border-color: var(--danger);">
            <div class="tone-danger" style="font-weight: 600;">שגיאה בפענוח קובץ ה-Minidump:</div>
            <p class="panel-text" style="margin-top: 4px;">${esc(data.error || 'קובץ הדאמפ אינו קריא או פגום')}</p>
          </div>`;
      }
      return;
    }

    const culprit = data.culprit_analysis || {};
    const driverName = culprit.responsible_driver || 'ntoskrnl.exe';
    const conf = culprit.confidence_label || '95% ודאות';
    const driverInfo = culprit.driver_info || {};
    const bugcheck = culprit.bugcheck_info || {};

    if (resultArea) {
      resultArea.innerHTML = `
        <div class="culprit-hero high-conf">
          <div class="culprit-title">
            <span class="row" style="gap: 6px;">
              <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width: 20px; height: 20px;">
                <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
              <span>תוצאת פענוח מעמיק: הדרייבר האשם שגרם לקריסה</span>
            </span>
            <span class="badge badge-danger mono">${esc(conf)}</span>
          </div>
          <div class="row-wrap" style="align-items: center; gap: 10px; margin-top: 10px;">
            <span class="culprit-driver-name" style="font-size: 16px;">${esc(driverName)}</span>
            <span class="badge badge-accent">${esc(driverInfo.category || 'חומרה')}</span>
            <span class="muted font-mono" style="font-size: 11.5px;">${esc(driverInfo.vendor || '')}</span>
          </div>
          <p style="margin-top: 8px; font-size: 12px; line-height: 1.6;">${esc(culprit.cause_he || bugcheck.cause_he)}</p>
          
          <div class="grid grid-3" style="margin-top: 12px; gap: 8px; font-size: 11px;">
            <div class="card" style="padding: 8px 10px; margin: 0; background: rgba(0,0,0,0.2);">
              <span class="faint">קוד שגיאה:</span>
              <div class="mono font-bold tone-accent">${esc(data.bugcheck_code)} (${esc(bugcheck.name || 'BSOD')})</div>
            </div>
            <div class="card" style="padding: 8px 10px; margin: 0; background: rgba(0,0,0,0.2);">
              <span class="faint">ארכיטקטורה:</span>
              <div class="mono">${esc(data.architecture || 'x64')}</div>
            </div>
            <div class="card" style="padding: 8px 10px; margin: 0; background: rgba(0,0,0,0.2);">
              <span class="faint">מודולים שנסרקו:</span>
              <div class="mono font-bold">${esc(data.total_modules_loaded || 0)} דרייברים</div>
            </div>
          </div>

          <div style="margin-top: 12px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,0.1);">
            <div class="tone-ok font-bold" style="font-size: 12px;">המלצה לפתרון:</div>
            <p style="font-size: 11.5px; white-space: pre-line; margin-top: 4px;">${esc(culprit.solution_he || bugcheck.solution_he)}</p>
          </div>

          ${culprit.online_intelligence ? `
            <div class="online-links-row" style="margin-top: 10px;">
              <a href="${esc(culprit.online_intelligence.google_search_url)}" target="_blank" class="btn-link-online">🌐 חיפוש פתרונות בגוגל</a>
              <a href="${esc(culprit.online_intelligence.ms_docs_url)}" target="_blank" class="btn-link-online">📖 תיעוד Microsoft Learn</a>
              <a href="${esc(culprit.online_intelligence.vendor_download_url)}" target="_blank" class="btn-link-online tone-accent">📥 אתר הורדת דרייבר יצרן</a>
            </div>
          ` : ''}
        </div>
      `;
    }
  } catch (err) {
    if (resultArea) {
      resultArea.innerHTML = `<div class="panel tone-danger">שגיאה בתקשורת עם השרת: ${esc(err.message)}</div>`;
    }
  }
}

function closeCrashModal() {
  const modal = document.getElementById('crashDetailModal');
  if (modal) {
    modal.classList.add('hidden');
  }
}

async function scheduleMemoryDiagnostic() {
  try {
    const res = await fetch('/api/memory_diagnostic', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(currentLang === 'he' ? "בדיקת זיכרון הופעלה" : "Diagnostic Launched", currentLang === 'he' ? "חלון בדיקת הזיכרון של Windows נפתח. פעל לפי ההנחיות במסך." : data.message);
    } else {
      showToast("Error", data.message);
    }
  } catch (err) {
    showToast("Error", err.message);
  }
}

async function openCopilotKeyboardSettings() {
  try {
    showToast(
      currentLang === 'he' ? "פותח הגדרות Windows..." : "Opening Windows Settings...",
      currentLang === 'he' ? "מעביר להגדרות המקלדת של Windows 11..." : "Navigating to Windows 11 Keyboard Settings..."
    );
    const res = await fetch('/api/open_keyboard_settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();
    if (data.success) {
      showToast(
        currentLang === 'he' ? "הגדרות מקלדת נפתחו" : "Keyboard Settings Opened",
        currentLang === 'he' 
          ? "בחר בסעיף ״התאמה אישית של מקש Copilot״ באפשרות Right Ctrl. ההגדרה נשמרת לצמיתות."
          : "Under 'Customize Copilot key on keyboard', select Right Ctrl. The setting is saved permanently."
      );
    } else {
      showToast(
        currentLang === 'he' ? "שים לב" : "Notice",
        data.message || (currentLang === 'he' ? "לא ניתן לפתוח את ההגדרות אוטומטית." : "Could not open settings automatically.")
      );
    }
  } catch (err) {
    console.error("Failed to open keyboard settings:", err);
    showToast(
      currentLang === 'he' ? "שגיאה" : "Error",
      currentLang === 'he' ? "שגיאה בפתיחת הגדרות מקלדת." : "Error opening keyboard settings."
    );
  }
}


// -------------------------------------------------------------
// Drive health (S.M.A.R.T.)
// -------------------------------------------------------------
// These three reports are slow (each shells out to PowerShell) and describe
// hardware that does not change while the app is open, so each is fetched once
// on first visit and only re-queried when the user asks.
let diskReport = null;
let deviceReport = null;
let eventReport = null;

const TONE_BADGE = { ok: 'badge-ok', warn: 'badge-warn', danger: 'badge-danger', neutral: '' };
const SEV_BADGE = { high: 'badge-danger', medium: 'badge-warn', low: '' };

/** Localised field off a `_he` / `_en` pair. */
function loc(obj, field) {
  if (!obj) return '';
  return (currentLang === 'he' ? obj[field + '_he'] : obj[field + '_en']) || obj[field + '_he'] || '';
}

function findingCard(finding) {
  const action = loc(finding, 'action');
  return `
    <div class="finding sev-${esc(finding.severity)}">
      <div class="spread">
        <span class="finding-title">${esc(loc(finding, 'title'))}</span>
        <span class="badge ${SEV_BADGE[finding.severity] || ''}">${esc(finding.severity)}</span>
      </div>
      <p class="finding-desc">${esc(loc(finding, 'desc'))}</p>
      ${action ? `<div class="finding-action"><span>${esc(action)}</span></div>` : ''}
    </div>`;
}

async function fetchDiskHealth(force) {
  if (diskReport && !force) {
    renderDiskHealth();
    return;
  }

  const list = document.getElementById('diskList');
  if (list && force) list.innerHTML = `<div class="loading">${esc(t('scanning'))}</div>`;

  try {
    const res = await fetch('/api/disks');
    if (!res.ok) return;
    diskReport = await res.json();
    renderDiskHealth();
  } catch (err) {
    console.error('Failed to fetch disk health:', err);
  }
}

function renderDiskHealth() {
  const report = diskReport;
  const list = document.getElementById('diskList');
  if (!report || !list) return;

  // --- Verdict header ---
  const badge = document.getElementById('diskOverallBadge');
  if (badge) {
    badge.textContent = loc(report, 'overall');
    badge.className = `badge ${TONE_BADGE[report.overall] || ''}`;
  }
  const scoreBox = document.getElementById('diskScoreBox');
  const scoreIcon = document.getElementById('diskScoreIcon');
  if (scoreBox) scoreBox.className = `score ${report.overall === 'neutral' ? '' : report.overall}`;
  if (scoreIcon) {
    scoreIcon.textContent = report.overall === 'ok' ? '✓' : (report.overall === 'danger' ? '!' : '~');
    scoreIcon.className = `score-val tone-${report.overall === 'neutral' ? 'accent' : report.overall}`;
  }

  const navTag = document.getElementById('navTagDisks');
  if (navTag) {
    const serious = (report.findings || []).filter(f => f.severity !== 'low').length;
    navTag.textContent = serious;
    navTag.className = 'nav-tag mono' + (report.overall === 'danger' ? ' alert' : (serious ? ' warn' : ''));
    navTag.classList.toggle('hidden', serious === 0);
  }

  // --- Findings ---
  const findingsWrap = document.getElementById('diskFindingsWrap');
  const findings = document.getElementById('diskFindings');
  if (findings && findingsWrap) {
    const items = report.findings || [];
    findings.innerHTML = items.map(findingCard).join('');
    findingsWrap.classList.toggle('hidden', items.length === 0);
  }

  // S.M.A.R.T. counters need elevation; say so rather than silently omitting them.
  const limited = document.getElementById('diskLimitedBanner');
  if (limited) limited.classList.toggle('hidden', !(report.supported && report.limited_data));

  // --- Drive cards ---
  if (!report.disks || report.disks.length === 0) {
    list.innerHTML = `<div class="card"><div class="empty">
      <span class="empty-title">${esc(t('disksNone'))}</span>
      <span class="empty-desc">${esc(t('disksNoneDesc'))}</span>
    </div></div>`;
    return;
  }

  list.innerHTML = report.disks.map(disk => {
    const specs = [];
    if (disk.media_type && disk.media_type !== 'Unknown') specs.push(esc(disk.media_type));
    if (disk.bus_type) specs.push(esc(disk.bus_type));
    if (disk.serial) specs.push(esc(disk.serial));
    if (disk.firmware) specs.push(`${esc(t('driveFirmware'))}: ${esc(disk.firmware)}`);

    const stats = [];
    if (disk.life_remaining_percent !== null && disk.life_remaining_percent !== undefined) {
      const tone = disk.life_remaining_percent <= 20 ? 'tone-danger'
                 : (disk.life_remaining_percent <= 50 ? 'tone-warn' : 'tone-ok');
      stats.push(`<div class="stat">
        <span class="stat-label">${esc(t('driveLife'))}</span>
        <span class="stat-value sm ${tone}">${disk.life_remaining_percent}%</span>
        <span class="stat-note">${esc(t('driveWear'))} ${disk.wear_percent !== null && disk.wear_percent !== undefined ? disk.wear_percent : (100 - disk.life_remaining_percent)}%</span>
      </div>`);
    }
    if (disk.temperature_c !== null && disk.temperature_c !== undefined) {
      const tone = disk.temperature_c >= 70 ? 'tone-danger' : (disk.temperature_c >= 60 ? 'tone-warn' : 'tone-ok');
      stats.push(`<div class="stat">
        <span class="stat-label">${esc(t('driveTemp'))}</span>
        <span class="stat-value sm ${tone}">${disk.temperature_c}°C</span>
        <span class="stat-note">${disk.temperature_c >= 70 ? esc(t('smartBad')) : (disk.temperature_c >= 60 ? esc(t('smartCaution')) : esc(t('smartGood')))}</span>
      </div>`);
    }
    if (disk.host_writes_formatted) {
      stats.push(`<div class="stat">
        <span class="stat-label">${esc(t('driveWrites'))}</span>
        <span class="stat-value sm mono tone-accent">${esc(disk.host_writes_formatted)}</span>
        <span class="stat-note ltr">${disk.host_reads_formatted ? `${esc(t('driveReads'))}: ${esc(disk.host_reads_formatted)}` : ''}</span>
      </div>`);
    }
    if (disk.power_on_hours) {
      stats.push(`<div class="stat">
        <span class="stat-label">${esc(t('driveHours'))}</span>
        <span class="stat-value sm mono">${disk.power_on_hours.toLocaleString('en-US')}</span>
        <span class="stat-note">${esc(t('driveAbout'))} ${disk.power_on_years || Math.round(disk.power_on_hours / 876) / 10} ${esc(t('driveYears'))}${disk.power_cycles ? ` · ${disk.power_cycles.toLocaleString('en-US')} ${esc(t('drivePowerCycles'))}` : ''}</span>
      </div>`);
    }

    const errorTotal = (disk.read_errors || 0) + (disk.write_errors || 0) + (disk.media_errors || 0);
    if (disk.media_errors !== null && disk.media_errors !== undefined) {
      stats.push(`<div class="stat">
        <span class="stat-label">${esc(t('driveMediaErrors'))}</span>
        <span class="stat-value sm ${disk.media_errors > 0 ? 'tone-danger' : 'tone-ok'}">${disk.media_errors}</span>
        <span class="stat-note">${disk.unsafe_shutdowns !== null && disk.unsafe_shutdowns !== undefined ? `${disk.unsafe_shutdowns} ${esc(t('driveUnsafeShutdowns'))}` : esc(t('smartGood'))}</span>
      </div>`);
    } else if (disk.read_errors !== null && disk.read_errors !== undefined) {
      stats.push(`<div class="stat">
        <span class="stat-label">${esc(t('driveErrors'))}</span>
        <span class="stat-value sm ${errorTotal > 0 ? 'tone-danger' : 'tone-ok'}">${errorTotal}</span>
        <span class="stat-note">${esc(t('driveErrorsNote'))}</span>
      </div>`);
    }

    const volumes = (disk.volumes || []).map(vol => {
      const usedPct = vol.used_percent || 0;
      const tone = vol.free_percent <= 8 ? 'danger' : (vol.free_percent <= 15 ? 'warn' : '');
      return `
        <div class="vol-row">
          <span class="vol-letter">${esc(vol.letter)}</span>
          <div>
            <span class="vol-name">${esc(vol.label || t('driveNoLabel'))} ${vol.filesystem ? `<span class="faint mono">${esc(vol.filesystem)}</span>` : ''}</span>
            <div class="meter"><div class="meter-fill ${tone}" style="width: ${usedPct}%"></div></div>
          </div>
          <span class="vol-nums ltr">
            <span class="vol-free">${esc(vol.free_formatted)}</span>
            ${esc(t('driveFreeOf'))} ${esc(vol.total_formatted)}
          </span>
        </div>`;
    }).join('');

    // S.M.A.R.T. Detailed Attributes Table (CrystalDiskInfo style)
    let smartHtml = '';
    if (disk.attributes && disk.attributes.length > 0) {
      const attrRows = disk.attributes.map(attr => {
        const attrName = (currentLang === 'he' ? attr.name_he : attr.name_en) || attr.name_en || attr.name_he || '';
        const attrDesc = (currentLang === 'he' ? attr.desc_he : attr.desc_en) || attr.desc_en || attr.desc_he || '';
        const statusClass = attr.status === 'Bad' ? 'smart-status-bad' : (attr.status === 'Caution' ? 'smart-status-caution' : 'smart-status-good');
        const statusLabel = attr.status === 'Bad' ? t('smartBad') : (attr.status === 'Caution' ? t('smartCaution') : t('smartGood'));

        return `<tr>
          <td><span class="smart-id-pill">${esc(attr.id_hex || String(attr.id))}</span></td>
          <td>
            <div class="smart-attr-title">${esc(attrName)}</div>
            ${attrDesc ? `<div class="smart-attr-desc">${esc(attrDesc)}</div>` : ''}
          </td>
          <td class="mono ltr">${attr.current !== null && attr.current !== undefined ? esc(attr.current) : '--'}</td>
          <td class="mono ltr">${attr.worst !== null && attr.worst !== undefined ? esc(attr.worst) : '--'}</td>
          <td class="mono ltr">${attr.threshold !== null && attr.threshold !== undefined ? esc(attr.threshold) : '--'}</td>
          <td class="mono ltr" style="font-weight: 600;">${esc(attr.raw_formatted || String(attr.raw_value || '0'))}</td>
          <td><span class="smart-status-badge ${statusClass}">${esc(statusLabel)}</span></td>
        </tr>`;
      }).join('');

      smartHtml = `
        <div class="smart-tools">
          <button type="button" class="btn btn-ghost btn-sm" onclick="toggleSmartTable('${esc(disk.device_id)}')">
            <span id="smartToggleIcon_${esc(disk.device_id)}">▸</span>
            <span id="smartToggleText_${esc(disk.device_id)}">${esc(t('btnShowSmart'))} (${disk.attributes.length})</span>
          </button>
        </div>
        <div id="smartTable_${esc(disk.device_id)}" class="smart-table-wrap hidden">
          <table class="smart-table">
            <thead>
              <tr>
                <th style="width: 50px;">${esc(t('thSmartId'))}</th>
                <th>${esc(t('thSmartAttr'))}</th>
                <th style="width: 75px;">${esc(t('thSmartCurrent'))}</th>
                <th style="width: 75px;">${esc(t('thSmartWorst'))}</th>
                <th style="width: 75px;">${esc(t('thSmartThresh'))}</th>
                <th style="width: 150px;">${esc(t('thSmartRaw'))}</th>
                <th style="width: 80px;">${esc(t('thSmartStatus'))}</th>
              </tr>
            </thead>
            <tbody>
              ${attrRows}
            </tbody>
          </table>
        </div>`;
    }

    return `
      <div class="card">
        <div class="card-head">
          <div>
            <div class="drive-head">
              <div>
                <span class="drive-title">${esc(disk.name)}</span>
                <span class="drive-sub">${specs.join(' · ') || '&nbsp;'}</span>
              </div>
            </div>
          </div>
          <div class="card-tools">
            <span class="badge badge-mono">${esc(disk.size_formatted)}</span>
            <span class="badge ${TONE_BADGE[disk.tone] || (disk.health_status === 'Good' || disk.health_status === 'Healthy' ? 'badge-ok' : (disk.health_status === 'Caution' ? 'badge-warn' : (disk.health_status === 'Bad' ? 'badge-danger' : '')))}">${esc(driveHealthLabel(disk))}</span>
          </div>
        </div>
        <div class="card-body">
          ${stats.length ? `<div class="grid grid-4" style="margin-bottom: 14px;">${stats.join('')}</div>` : ''}
          ${volumes || `<span class="muted" style="font-size: 11.5px;">${esc(t('driveNoVolumes'))}</span>`}
          ${smartHtml}
        </div>
      </div>`;
  }).join('');
}

function toggleSmartTable(deviceId) {
  const table = document.getElementById(`smartTable_${deviceId}`);
  const icon = document.getElementById(`smartToggleIcon_${deviceId}`);
  const text = document.getElementById(`smartToggleText_${deviceId}`);
  if (!table) return;

  const isHidden = table.classList.contains('hidden');
  if (isHidden) {
    table.classList.remove('hidden');
    if (icon) icon.textContent = '▾';
    if (text) text.textContent = t('btnHideSmart');
  } else {
    table.classList.add('hidden');
    if (icon) icon.textContent = '▸';
    if (text) text.textContent = t('btnShowSmart');
  }
}

function driveHealthLabel(disk) {
  if (currentLang === 'he' && disk.status_he) return disk.status_he;
  if (currentLang !== 'he' && disk.status_en) return disk.status_en;
  if (disk.health_status === 'Healthy' || disk.health_status === 'Good') return t('driveHealthy');
  if (!disk.health_status || disk.health_status === 'Unknown') return t('driveUnknown');
  return disk.health_status;
}


// -------------------------------------------------------------
// Devices & drivers
// -------------------------------------------------------------

async function fetchDevices(force) {
  if (deviceReport && !force) {
    renderDevices();
    return;
  }

  const list = document.getElementById('problemDeviceList');
  if (list && force) list.innerHTML = `<div class="loading">${esc(t('scanning'))}</div>`;

  try {
    const res = await fetch('/api/devices');
    if (!res.ok) return;
    deviceReport = await res.json();
    renderDevices();
  } catch (err) {
    console.error('Failed to fetch devices:', err);
  }
}

function renderDevices() {
  const report = deviceReport;
  if (!report) return;

  const problems = report.problem_devices || [];
  const stale = report.stale_drivers || [];

  const problemBadge = document.getElementById('deviceProblemBadge');
  if (problemBadge) {
    problemBadge.textContent = problems.length;
    problemBadge.className = `badge ${problems.length ? 'badge-danger' : 'badge-ok'}`;
  }

  const staleBadge = document.getElementById('staleDriverBadge');
  if (staleBadge) staleBadge.textContent = stale.length;

  const countBadge = document.getElementById('driverCountBadge');
  if (countBadge) countBadge.textContent = `${report.driver_count || 0} ${t('driversInstalled')}`;

  const navTag = document.getElementById('navTagDevices');
  if (navTag) {
    navTag.textContent = problems.length || stale.length;
    navTag.className = 'nav-tag mono' + (problems.length ? ' alert' : (stale.length ? ' warn' : ''));
    navTag.classList.toggle('hidden', problems.length === 0 && stale.length === 0);
  }

  // --- Problem devices ---
  const list = document.getElementById('problemDeviceList');
  if (list) {
    if (problems.length === 0) {
      list.innerHTML = `<div class="empty">
        <span class="tone-ok" style="font-size: 22px;">&#10003;</span>
        <span class="empty-title">${esc(t('devicesAllOk'))}</span>
        <span class="empty-desc">${esc(t('devicesAllOkDesc'))}</span>
      </div>`;
    } else {
      list.innerHTML = problems.map(device => `
        <div class="evt-card sev-${esc(device.severity)}">
          <div class="spread">
            <div class="row-wrap" style="gap: 8px;">
              <span class="list-title">${esc(device.name)}</span>
              ${device.device_class ? `<span class="badge">${esc(device.device_class)}</span>` : ''}
            </div>
            <span class="badge ${SEV_BADGE[device.severity] || ''} badge-mono">
              ${device.problem_code !== null && device.problem_code !== undefined
                ? `${esc(t('deviceProblemCode'))} ${device.problem_code}` : esc(device.status)}
            </span>
          </div>
          <p class="finding-desc">${esc(loc(device, 'desc'))}</p>
          <div class="finding-action">
            <span>${esc(loc(device, 'action'))}</span>
            ${device.manufacturer ? `<span class="faint mono">${esc(device.manufacturer)}</span>` : ''}
          </div>
          ${device.instance_id ? `
            <details class="raw">
              <summary>${esc(t('deviceInstanceId'))}</summary>
              <code class="code-block">${esc(device.instance_id)}</code>
            </details>` : ''}
        </div>`).join('');
    }
  }

  // --- Stale drivers ---
  const staleList = document.getElementById('staleDriverList');
  if (staleList) {
    if (stale.length === 0) {
      staleList.innerHTML = `<div class="empty">
        <span class="empty-title">${esc(t('driversAllCurrent'))}</span>
        <span class="empty-desc">${esc(t('driversAllCurrentDesc'))}</span>
      </div>`;
    } else {
      staleList.innerHTML = stale.map(driver => `
        <div class="list-row">
          <div class="grow" style="min-width: 0;">
            <span class="list-title truncate">${esc(driver.name)}</span>
            <span class="list-sub truncate">${esc(driver.provider || driver.manufacturer)} · v${esc(driver.version)}</span>
          </div>
          <div class="row" style="gap: 8px;">
            <span class="badge">${esc(driver.device_class)}</span>
            <span class="badge badge-warn badge-mono">${esc(driver.date)}</span>
            <span class="faint mono nowrap" style="font-size: 11px;">${driver.age_years} ${esc(t('driveYears'))}</span>
          </div>
        </div>`).join('');
    }
  }
}

// -------------------------------------------------------------
// OEM / Manufacturer Updates
// -------------------------------------------------------------

let oemInfo = null;
let oemPollTimer = null;
let oemTimerInterval = null;
let oemStartTime = null;
let oemLastLogRev = 0;

async function fetchOemInfo(overrideMfr) {
  try {
    const url = overrideMfr ? `/api/oem/info?vendor=${encodeURIComponent(overrideMfr)}` : '/api/oem/info';
    const res = await fetch(url);
    if (!res.ok) return;
    oemInfo = await res.json();
    renderOemInfo();

    if (oemInfo.is_running && !oemPollTimer) {
      resumeOemPolling();
    }
  } catch (err) {
    console.error('Failed to fetch OEM info:', err);
  }
}

function renderOemInfo() {
  if (!oemInfo) return;

  const mfr = oemInfo.selected_manufacturer || oemInfo.manufacturer || 'Universal';
  const rawMfr = oemInfo.raw_manufacturer || mfr;
  const model = oemInfo.model || 'Standard PC';
  const tool = oemInfo.tool || {};

  // Badge on Hardware subtabs header
  const badgeMfr = document.getElementById('badgeOemMfr');
  if (badgeMfr) {
    badgeMfr.textContent = mfr;
    badgeMfr.className = 'badge badge-sm badge-mono';
  }

  // Card 1: Hardware & System
  const oemMfrBadge = document.getElementById('oemMfrBadge');
  if (oemMfrBadge) {
    oemMfrBadge.textContent = mfr;
    oemMfrBadge.className = 'badge ' + (mfr === 'Dell' ? 'badge-primary' : (mfr === 'Lenovo' ? 'badge-accent' : (mfr === 'HP' ? 'badge-ok' : 'badge-mono')));
  }

  const elBrand = document.getElementById('oemDetectedBrand');
  if (elBrand) elBrand.textContent = rawMfr;

  const elModel = document.getElementById('oemDetectedModel');
  if (elModel) elModel.textContent = model + (oemInfo.serial && oemInfo.serial !== 'N/A' ? ` [S/N: ${oemInfo.serial}]` : '');

  const selMfr = document.getElementById('selOemManufacturer');
  if (selMfr && !selMfr.dataset.userModified) {
    selMfr.value = mfr;
  }

  // Card 2: Tool Status
  const toolBadge = document.getElementById('oemToolStatusBadge');
  if (toolBadge) {
    if (tool.installed) {
      toolBadge.textContent = t('oemStatusInstalled');
      toolBadge.className = 'badge badge-ok badge-mono';
    } else {
      toolBadge.textContent = t('oemStatusMissing');
      toolBadge.className = 'badge badge-warn badge-mono';
    }
  }

  const toolName = document.getElementById('oemToolName');
  if (toolName) toolName.textContent = tool.tool_name || '--';

  const toolDesc = document.getElementById('oemToolDetailText');
  if (toolDesc) {
    toolDesc.textContent = currentLang === 'en' ? (tool.details_en || '') : (tool.details_he || '');
  }

  const dotnetRow = document.getElementById('oemDotnetRow');
  if (dotnetRow) {
    if (mfr === 'Dell') {
      const dot8 = tool.dotnet_8_installed;
      const dot10 = tool.dotnet_10_installed;
      dotnetRow.innerHTML = `
        <span class="stat-label" style="font-size: 11px;">${currentLang === 'en' ? 'Prerequisites:' : 'דרישות קדם:'}</span>
        <span class="badge badge-sm badge-mono ${dot8 ? 'badge-ok' : 'badge-warn'}">.NET 8 ${dot8 ? '✓' : (currentLang === 'en' ? 'Auto-install' : 'יותקן')}</span>
        <span class="badge badge-sm badge-mono ${dot10 ? 'badge-ok' : 'badge-warn'}">.NET 10 ${dot10 ? '✓' : (currentLang === 'en' ? 'Auto-install' : 'יותקן')}</span>
      `;
      dotnetRow.classList.remove('hidden');
    } else {
      dotnetRow.classList.add('hidden');
    }
  }

  const toolPathRow = document.getElementById('oemToolPathRow');
  const toolPath = document.getElementById('oemToolPath');
  if (toolPathRow && toolPath) {
    if (tool.path) {
      toolPath.textContent = tool.path;
      toolPath.title = tool.path;
      toolPathRow.classList.remove('hidden');
    } else {
      toolPathRow.classList.add('hidden');
    }
  }

  // Pending reboot check on initial render
  if (oemInfo.pending_reboot) {
    const banner = document.getElementById('oemResultBanner');
    const desc = document.getElementById('oemResultDesc');
    const title = document.getElementById('oemResultTitle');
    if (banner && desc && title && !oemInfo.is_running) {
      banner.className = 'banner banner-warn';
      title.textContent = t('oemRebootRequired');
      desc.textContent = t('oemRebootRequired');
      banner.classList.remove('hidden');
    }
  }
}

async function onOemManufacturerChanged() {
  const sel = document.getElementById('selOemManufacturer');
  if (!sel) return;
  sel.dataset.userModified = '1';
  const val = sel.value;
  await fetchOemInfo(val);
}

async function startOemUpdates() {
  const sel = document.getElementById('selOemManufacturer');
  const mfr = sel ? sel.value : 'Auto';
  const twoPasses = document.getElementById('chkOemTwoPasses') ? document.getElementById('chkOemTwoPasses').checked : true;
  const winOptional = document.getElementById('chkOemWinOptional') ? document.getElementById('chkOemWinOptional').checked : true;

  const btnRun = document.getElementById('btnRunOemUpdates');
  const btnCancel = document.getElementById('btnCancelOemUpdates');
  const txtBtnRun = document.getElementById('txtBtnRunOemUpdates');
  const resultBanner = document.getElementById('oemResultBanner');

  if (resultBanner) resultBanner.classList.add('hidden');
  if (btnRun) btnRun.disabled = true;
  if (txtBtnRun) txtBtnRun.textContent = t('btnRunningOemUpdates');
  if (btnCancel) btnCancel.classList.remove('hidden');

  oemLastLogRev = 0;
  clearOemTerminal();
  startOemTimer();

  try {
    const res = await fetch('/api/oem/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        manufacturer: mfr,
        options: {
          two_passes: twoPasses,
          include_windows_optional: winOptional
        }
      })
    });
    let data = {};
    try {
      data = await res.json();
    } catch (e) {
      data = { success: false, error: `שגיאת שרת (${res.status} ${res.statusText || ''})`.trim() };
    }
    if (!res.ok || !data.success) {
      const errMsg = data.error || data.message || `שגיאת שרת (${res.status} ${res.statusText || ''})`.trim() || 'נכשל';
      appendOemLogLine(`[!] שגיאה בהפעלת עדכונים: ${errMsg}`, 'ERROR');
      finishOemUpdates(false, errMsg);
      return;
    }

    resumeOemPolling();
  } catch (err) {
    console.error('Failed to start OEM updates:', err);
    appendOemLogLine(`[!] שגיאת תקשורת: ${err.message}`, 'ERROR');
    finishOemUpdates(false, err.message);
  }
}

function startOemTimer() {
  stopOemTimer();
  oemStartTime = Date.now();
  const timerEl = document.getElementById('oemTimerText');
  oemTimerInterval = setInterval(() => {
    if (!timerEl || !oemStartTime) return;
    const diffSec = Math.floor((Date.now() - oemStartTime) / 1000);
    const m = String(Math.floor(diffSec / 60)).padStart(2, '0');
    const s = String(diffSec % 60).padStart(2, '0');
    timerEl.textContent = `${m}:${s}`;
  }, 1000);
}

function stopOemTimer() {
  if (oemTimerInterval) {
    clearInterval(oemTimerInterval);
    oemTimerInterval = null;
  }
}

function resumeOemPolling() {
  if (oemPollTimer) clearInterval(oemPollTimer);

  const btnRun = document.getElementById('btnRunOemUpdates');
  const btnCancel = document.getElementById('btnCancelOemUpdates');
  const txtBtnRun = document.getElementById('txtBtnRunOemUpdates');

  if (btnRun) btnRun.disabled = true;
  if (txtBtnRun) txtBtnRun.textContent = t('btnRunningOemUpdates');
  if (btnCancel) btnCancel.classList.remove('hidden');

  if (!oemStartTime) startOemTimer();

  const poll = async () => {
    try {
      const res = await fetch(`/api/oem/progress?since=${oemLastLogRev}`);
      if (!res.ok) return;
      const data = await res.json();

      // Update progress bar & text
      const p = data.progress || 0;
      const bar = document.getElementById('oemProgressBar');
      if (bar) bar.style.width = `${p}%`;

      const badge = document.getElementById('oemProgressBadge');
      if (badge) badge.textContent = `${p}%`;

      const stepText = document.getElementById('oemCurrentStepText');
      if (stepText) {
        stepText.textContent = currentLang === 'en' ? (data.step_en || data.step) : (data.step || '');
      }

      // Append new logs
      if (data.new_logs && data.new_logs.length > 0) {
        appendOemLogs(data.new_logs);
      }
      oemLastLogRev = data.log_rev || oemLastLogRev;

      // Completed / Cancelled / Errored
      if (!data.is_running) {
        clearInterval(oemPollTimer);
        oemPollTimer = null;
        stopOemTimer();
        finishOemUpdates(data.status !== 'error', data.final_results || data.step);
      }
    } catch (err) {
      console.error('OEM poll error:', err);
    }
  };

  oemPollTimer = setInterval(poll, 1200);
  poll();
}

function finishOemUpdates(success, results) {
  const btnRun = document.getElementById('btnRunOemUpdates');
  const btnCancel = document.getElementById('btnCancelOemUpdates');
  const txtBtnRun = document.getElementById('txtBtnRunOemUpdates');
  const banner = document.getElementById('oemResultBanner');
  const title = document.getElementById('oemResultTitle');
  const desc = document.getElementById('oemResultDesc');

  if (btnRun) btnRun.disabled = false;
  if (txtBtnRun) txtBtnRun.textContent = t('btnStartOemUpdates');
  if (btnCancel) btnCancel.classList.add('hidden');

  stopOemTimer();

  if (banner && title && desc) {
    banner.classList.remove('hidden');
    if (success) {
      banner.className = 'banner banner-ok';
      title.textContent = t('oemCompleted');
      if (typeof results === 'object' && results !== null) {
        const reboot = results.reboot_pending ? ` (${t('oemRebootRequired')})` : '';
        desc.textContent = `הסתיים בהצלחה. דרייברים שעודכנו: ${results.installed_count || 0}. שגיאות: ${results.error_count || 0}.${reboot}`;
      } else {
        desc.textContent = String(results || '');
      }
    } else {
      banner.className = 'banner banner-danger';
      title.textContent = t('oemError');
      desc.textContent = typeof results === 'string' ? results : t('oemError');
    }
  }

  // Refresh general device status in case drivers were installed
  setTimeout(() => fetchDevices(true), 3000);
}

async function cancelOemUpdates() {
  const btnCancel = document.getElementById('btnCancelOemUpdates');
  if (btnCancel) btnCancel.disabled = true;

  try {
    const res = await fetch('/api/oem/cancel', { method: 'POST' });
    const data = await res.json();
    appendOemLogLine('[!] בקשת עצירה נשלחה לשרת...', 'WARN');
  } catch (err) {
    console.error('Failed to cancel OEM updates:', err);
  } finally {
    if (btnCancel) btnCancel.disabled = false;
  }
}

function appendOemLogs(logs) {
  const term = document.getElementById('oemTerminal');
  if (!term) return;

  const fragment = document.createDocumentFragment();
  for (const item of logs) {
    const line = document.createElement('div');
    const lvl = (item.level || 'INFO').toLowerCase();
    line.className = `term-line term-${lvl}`;
    line.textContent = `[${item.time || ''}] ${item.text || ''}`;
    fragment.appendChild(line);
  }
  term.appendChild(fragment);
  term.scrollTop = term.scrollHeight;
}

function appendOemLogLine(text, level = 'INFO') {
  const term = document.getElementById('oemTerminal');
  if (!term) return;
  const line = document.createElement('div');
  const now = new Date().toTimeString().split(' ')[0];
  line.className = `term-line term-${level.toLowerCase()}`;
  line.textContent = `[${now}] ${text}`;
  term.appendChild(line);
  term.scrollTop = term.scrollHeight;
}

function clearOemTerminal() {
  const term = document.getElementById('oemTerminal');
  if (term) term.innerHTML = '';
  const bar = document.getElementById('oemProgressBar');
  if (bar) bar.style.width = '0%';
  const badge = document.getElementById('oemProgressBadge');
  if (badge) badge.textContent = '0%';
  const stepText = document.getElementById('oemCurrentStepText');
  if (stepText) stepText.textContent = t('oemReady');
  const timerText = document.getElementById('oemTimerText');
  if (timerText) timerText.textContent = '00:00';
  const banner = document.getElementById('oemResultBanner');
  if (banner) banner.classList.add('hidden');
}

// -------------------------------------------------------------
// System error log
// -------------------------------------------------------------

async function fetchEventLog(force) {
  if (eventReport && !force) {
    renderEventLog();
    return;
  }

  const list = document.getElementById('eventGroupList');
  if (list && force) list.innerHTML = `<div class="loading">${esc(t('scanning'))}</div>`;

  const daysSelect = document.getElementById('eventDays');
  const days = daysSelect ? daysSelect.value : 7;

  try {
    const res = await fetch(`/api/events?days=${encodeURIComponent(days)}`);
    if (!res.ok) return;
    eventReport = await res.json();
    renderEventLog();
  } catch (err) {
    console.error('Failed to fetch event log:', err);
  }
}

function renderEventLog() {
  const report = eventReport;
  if (!report) return;

  const set = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };
  set('valEventTotal', report.total_events ?? 0);
  set('valEventActionable', report.actionable_count ?? 0);
  set('valEventNoise', report.noise_count ?? 0);

  const badge = document.getElementById('eventOverallBadge');
  if (badge) {
    badge.textContent = loc(report, 'overall');
    badge.className = `badge ${TONE_BADGE[report.overall] || ''}`;
  }

  const navTag = document.getElementById('navTagEvents');
  if (navTag) {
    const count = report.actionable_count || 0;
    navTag.textContent = count;
    navTag.className = 'nav-tag mono' + (report.overall === 'danger' ? ' alert' : (count ? ' warn' : ''));
    navTag.classList.toggle('hidden', count === 0);
  }

  renderEventGroups();
}

function renderEventGroups() {
  const list = document.getElementById('eventGroupList');
  if (!list || !eventReport) return;

  const showNoise = !!(document.getElementById('chkShowNoise') || {}).checked;
  const groups = (eventReport.groups || []).filter(g => showNoise || !g.noise);

  if (groups.length === 0) {
    const cleanLog = (eventReport.total_events || 0) === 0;
    list.innerHTML = `<div class="empty">
      <span class="tone-ok" style="font-size: 22px;">&#10003;</span>
      <span class="empty-title">${esc(cleanLog ? t('eventsClean') : t('eventsOnlyNoise'))}</span>
      <span class="empty-desc">${esc(cleanLog ? t('eventsCleanDesc') : t('eventsOnlyNoiseDesc'))}</span>
    </div>`;
    return;
  }

  list.innerHTML = groups.map(group => `
    <div class="evt-card sev-${esc(group.severity)}${group.noise ? ' is-noise' : ''}">
      <div class="spread">
        <div class="row-wrap" style="gap: 8px;">
          <span class="list-title">${esc(loc(group, 'title'))}</span>
          <span class="badge">${esc(currentLang === 'he' ? group.category_he : group.category_en)}</span>
          ${group.known ? '' : `<span class="badge badge-mono">${esc(t('eventsUnknown'))}</span>`}
        </div>
        <span class="evt-count">${group.count}× ${esc(t('eventsTimes'))}</span>
      </div>

      <p class="finding-desc">${esc(loc(group, 'desc'))}</p>

      <div class="finding-action">
        <span>${esc(loc(group, 'action'))}</span>
        <span class="faint mono nowrap" style="font-size: 10.5px;">
          ${esc(group.provider)} · ID ${group.event_id}
        </span>
      </div>

      <div class="row-wrap faint mono" style="gap: 10px; font-size: 10.5px; margin-top: 7px;">
        <span>${esc(t('eventsLast'))} ${esc(group.last_seen || '--')}</span>
        <span>${esc(t('eventsFirst'))} ${esc(group.first_seen || '--')}</span>
        <span>${esc(group.log)}</span>
      </div>

      ${group.sample_message ? `
        <details class="raw">
          <summary>${esc(t('eventsRaw'))}</summary>
          <code class="code-block">${esc(group.sample_message)}</code>
        </details>` : ''}
    </div>`).join('');
}

// -------------------------------------------------------------
// Copilot Key 1-Click Auto-Remapper
// -------------------------------------------------------------
let copilotRemapStatus = null;

async function fetchCopilotRemapStatus() {
  try {
    const res = await fetch('/api/copilot_remap/status');
    if (!res.ok) return;
    copilotRemapStatus = await res.json();
    renderCopilotStatus();
  } catch (err) {
    console.error("Failed to fetch copilot remap status:", err);
  }
}

function renderCopilotStatus() {
  const badge = document.getElementById('badgeCopilotStatus');
  const dot = document.getElementById('dotCopilotStatus');
  const txt = document.getElementById('txtCopilotStatus');
  const btnEnable = document.getElementById('btnEnableCopilot');
  const btnDisable = document.getElementById('btnDisableCopilot');

  if (!badge || !txt) return;
  const isActive = !!(copilotRemapStatus && copilotRemapStatus.is_active);

  badge.className = `badge ${isActive ? 'badge-ok' : ''}`;
  if (dot) dot.style.background = isActive ? 'var(--ok)' : 'var(--text-faint)';
  txt.textContent = isActive ? t('copilotStatusActive') : t('copilotStatusInactive');

  if (btnEnable) btnEnable.classList.toggle('is-busy', isActive);
  if (btnDisable) btnDisable.classList.toggle('is-busy', !isActive);
}

async function enableCopilotRemap() {
  const btn = document.getElementById('btnEnableCopilot');
  if (btn) btn.disabled = true;
  showToast(
    currentLang === 'he' ? "מפעיל מיפוי אוטומטי..." : "Enabling Auto-Remap...",
    currentLang === 'he' ? "מקמפל ומגדיר את שירות ה-Hook ב-Startup..." : "Setting up hook service in Startup..."
  );

  try {
    const res = await fetch('/api/copilot_remap/enable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();

    if (data.success) {
      copilotRemapStatus = data.status || { is_active: true };
      renderCopilotStatus();
      showToast(
        currentLang === 'he' ? "מיפוי Copilot פעיל" : "Copilot Remapper Active",
        currentLang === 'he'
          ? "מקש Copilot ממופה כעת ל-Right Ctrl ופועל ברקע. (Created by YAKIR LAVIE)"
          : "Copilot key is now mapped to Right Control and running in the background. (Created by YAKIR LAVIE)"
      );
    } else {
      showToast("Error", data.message || "Failed to enable");
    }
  } catch (err) {
    showToast("Error", err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function disableCopilotRemap() {
  const btn = document.getElementById('btnDisableCopilot');
  if (btn) btn.disabled = true;
  showToast(
    currentLang === 'he' ? "מבטל מיפוי..." : "Disabling remap...",
    currentLang === 'he' ? "מסיר את השירות מהפעלה אוטומטית..." : "Removing service from Startup..."
  );

  try {
    const res = await fetch('/api/copilot_remap/disable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();

    if (data.success) {
      copilotRemapStatus = data.status || { is_active: false };
      renderCopilotStatus();
      showToast(
        currentLang === 'he' ? "מיפוי בוטל" : "Remapping Disabled",
        currentLang === 'he' ? "מקש Copilot חזר לתפקוד ברירת המחדל." : "Copilot key restored to default."
      );
    } else {
      showToast("Error", data.message || "Failed to disable");
    }
  } catch (err) {
    showToast("Error", err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

// -------------------------------------------------------------
// Microsoft OneDrive Reset & Management
// -------------------------------------------------------------
let oneDriveStatus = null;

async function fetchOneDriveStatus() {
  try {
    const res = await fetch('/api/onedrive/status');
    if (!res.ok) return;
    oneDriveStatus = await res.json();
    renderOneDriveStatus();
  } catch (err) {
    console.error("Failed to fetch OneDrive status:", err);
  }
}

function renderOneDriveStatus() {
  const badge = document.getElementById('badgeOneDriveStatus');
  const dot = document.getElementById('dotOneDriveStatus');
  const txt = document.getElementById('txtOneDriveStatus');

  if (!badge || !txt) return;

  if (!oneDriveStatus) {
    txt.textContent = currentLang === 'he' ? "בודק סטטוס..." : "Checking status...";
    if (dot) dot.style.background = 'var(--text-faint)';
    return;
  }

  const isRunning = !!oneDriveStatus.is_running;
  const accountsExist = !!oneDriveStatus.accounts_key_exists;

  if (isRunning) {
    badge.className = 'badge badge-accent';
    if (dot) dot.style.background = 'var(--accent)';
    txt.textContent = t('onedriveStatusRunning');
  } else {
    badge.className = 'badge';
    if (dot) dot.style.background = 'var(--text-faint)';
    txt.textContent = accountsExist
      ? (currentLang === 'he' ? "סגור (יש חשבונות)" : "Stopped (configured)")
      : t('onedriveStatusStopped');
  }
}

function confirmResetOneDrive() {
  showConfirmDialog({
    title: t('confirmOneDriveTitle'),
    desc: t('confirmOneDriveDesc'),
    confirmText: t('btnConfirmReset'),
    confirmClass: 'btn-solid-danger',
    onConfirm: () => executeResetOneDrive()
  });
}

async function executeResetOneDrive() {
  const btn = document.getElementById('btnResetOneDrive');
  if (btn) {
    btn.disabled = true;
    btn.classList.add('is-busy');
  }

  showToast(
    currentLang === 'he' ? "מאפס את OneDrive..." : "Resetting OneDrive...",
    currentLang === 'he' ? "סוגר תהליכים, מוחק חשבונות ברגיסטרי ומנקה מטמון..." : "Terminating process, deleting registry accounts & clearing cache..."
  );

  try {
    const res = await fetch('/api/onedrive/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clean_cache: true, relaunch: false })
    });
    const data = await res.json();

    if (data.success) {
      showToast(
        currentLang === 'he' ? "איפוס OneDrive הושלם" : "OneDrive Reset Completed",
        data.message || (currentLang === 'he' ? "OneDrive נסגר וכל הגדרות החשבונות הוסרו בהצלחה." : "OneDrive closed and account settings cleared successfully.")
      );
      await fetchOneDriveStatus();
    } else {
      showToast(
        currentLang === 'he' ? "שגיאה באיפוס OneDrive" : "Error resetting OneDrive",
        data.message || (currentLang === 'he' ? "נכשלה פעולת המחיקה." : "Failed to reset OneDrive."),
        "danger"
      );
    }
  } catch (err) {
    showToast("Error", err.message, "danger");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('is-busy');
    }
  }
}

async function launchOneDriveApp() {
  const btn = document.getElementById('btnLaunchOneDrive');
  if (btn) btn.disabled = true;

  showToast(
    currentLang === 'he' ? "מפעיל את OneDrive..." : "Starting OneDrive...",
    currentLang === 'he' ? "פותח את יישום OneDrive במערכת..." : "Launching OneDrive application..."
  );

  try {
    const res = await fetch('/api/onedrive/launch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();
    if (data.success) {
      showToast(
        currentLang === 'he' ? "OneDrive הופעל" : "OneDrive Launched",
        data.message || (currentLang === 'he' ? "יישום OneDrive הופעל בהצלחה." : "OneDrive launched successfully.")
      );
      setTimeout(() => fetchOneDriveStatus(), 1500);
    } else {
      showToast(
        currentLang === 'he' ? "שים לב" : "Notice",
        data.message || (currentLang === 'he' ? "לא ניתן להפעיל את OneDrive אוטומטית." : "Could not launch OneDrive."),
        "warn"
      );
    }
  } catch (err) {
    showToast("Error", err.message, "danger");
  } finally {
    if (btn) btn.disabled = false;
  }
}

// -------------------------------------------------------------
// Confirmation Dialog Helper
// -------------------------------------------------------------
function showConfirmDialog(opts) {
  const modal = document.getElementById('confirmActionModal');
  if (!modal) {
    if (window.confirm(opts.desc || opts.title || "Confirm?")) {
      if (typeof opts.onConfirm === 'function') opts.onConfirm();
    }
    return;
  }

  const titleEl = document.getElementById('confirmModalTitle');
  const descEl = document.getElementById('confirmModalDesc');
  const execBtn = document.getElementById('btnConfirmActionExec');

  if (titleEl) titleEl.textContent = opts.title || (currentLang === 'he' ? "אישור פעולה" : "Confirm Action");
  if (descEl) descEl.textContent = opts.desc || (currentLang === 'he' ? "האם אתה בטוח שברצונך להמשיך?" : "Are you sure you want to proceed?");

  if (execBtn) {
    execBtn.textContent = opts.confirmText || (currentLang === 'he' ? "אישור" : "Confirm");
    execBtn.className = `btn btn-sm ${opts.confirmClass || 'btn-danger'}`;
    execBtn.onclick = () => {
      closeConfirmModal();
      if (typeof opts.onConfirm === 'function') opts.onConfirm();
    };
  }

  modal.classList.remove('hidden');
}

function closeConfirmModal() {
  const modal = document.getElementById('confirmActionModal');
  if (modal) modal.classList.add('hidden');
}

// -------------------------------------------------------------
// Center Screen Alert / Result Modal (with Restart Notice)
// -------------------------------------------------------------
function showCenterAlertModal(opts) {
  const modal = document.getElementById('centerAlertModal');
  if (!modal) {
    alert((opts.title ? opts.title + '\n\n' : '') + (opts.message || ''));
    return;
  }
  const titleEl = document.getElementById('centerAlertTitle');
  const msgEl = document.getElementById('centerAlertMessage');
  const restartBox = document.getElementById('centerAlertRestartBox');
  const restartTitle = document.getElementById('centerAlertRestartTitle');
  const restartDesc = document.getElementById('centerAlertRestartDesc');
  const okBtn = document.getElementById('btnCenterAlertOk');

  if (titleEl) titleEl.textContent = opts.title || (currentLang === 'he' ? "איפוס הושלם בהצלחה" : "Reset Completed Successfully");
  if (msgEl) msgEl.textContent = opts.message || '';

  if (opts.restartRecommended) {
    if (restartBox) restartBox.style.display = 'flex';
    if (restartTitle && opts.restartTitle) restartTitle.textContent = opts.restartTitle;
    if (restartDesc && opts.restartDesc) restartDesc.textContent = opts.restartDesc;
  } else {
    if (restartBox) restartBox.style.display = 'none';
  }

  if (okBtn) {
    okBtn.textContent = opts.okText || (currentLang === 'he' ? "אישור" : "OK");
    okBtn.onclick = () => {
      closeCenterAlertModal();
      if (typeof opts.onOk === 'function') opts.onOk();
    };
  }

  modal.classList.remove('hidden');
}

function closeCenterAlertModal() {
  const modal = document.getElementById('centerAlertModal');
  if (modal) modal.classList.add('hidden');
}

// -------------------------------------------------------------
// Icon & Thumbnail Cache Rebuild (Enterprise IT)
// -------------------------------------------------------------
let iconCacheStatus = null;

async function fetchIconCacheStatus() {
  try {
    const res = await fetch('/api/icon_cache/status');
    if (!res.ok) return;
    iconCacheStatus = await res.json();
    renderIconCacheStatus();
  } catch (err) {
    console.error("Failed to fetch icon cache status:", err);
  }
}

function renderIconCacheStatus() {
  const badge = document.getElementById('badgeIconCacheStatus');
  const dot = document.getElementById('dotIconCacheStatus');
  const txt = document.getElementById('txtIconCacheStatus');

  if (!badge || !txt) return;

  if (!iconCacheStatus || !iconCacheStatus.success) {
    txt.textContent = currentLang === 'he' ? "בודק מטמון..." : "Checking cache...";
    if (dot) dot.style.background = 'var(--text-faint)';
    return;
  }

  const count = iconCacheStatus.file_count || 0;
  const size = iconCacheStatus.formatted_size || "0 B";

  if (count > 0) {
    badge.className = 'badge badge-accent';
    if (dot) dot.style.background = 'var(--accent)';
    txt.textContent = currentLang === 'he'
      ? `${count} קבצים (${size})`
      : `${count} files (${size})`;
  } else {
    badge.className = 'badge badge-ok';
    if (dot) dot.style.background = 'var(--ok)';
    txt.textContent = currentLang === 'he' ? "נקי ומעודכן" : "Clean & up to date";
  }
}

function confirmRebuildIconCache() {
  showConfirmDialog({
    title: t('confirmIconCacheTitle'),
    desc: t('confirmIconCacheDesc'),
    confirmText: t('btnConfirmRebuildIcon'),
    confirmClass: 'btn-solid-primary',
    onConfirm: () => executeRebuildIconCache()
  });
}

async function executeRebuildIconCache() {
  const btn = document.getElementById('btnRebuildIconCache');
  if (btn) {
    btn.disabled = true;
    btn.classList.add('is-busy');
  }

  showToast(
    currentLang === 'he' ? "בונה מחדש מטמון אייקונים..." : "Rebuilding Icon Cache...",
    currentLang === 'he'
      ? "סוגר את סייר הקבצים, מוחק קובצי db ישנים ומרענן את ה-Shell..."
      : "Restarting File Explorer, deleting old db caches and refreshing Shell..."
  );

  try {
    const res = await fetch('/api/icon_cache/rebuild', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();

    if (data.success) {
      showToast(
        currentLang === 'he' ? "מטמון האייקונים נבנה מחדש" : "Icon Cache Rebuilt",
        data.message || (currentLang === 'he' ? "האייקונים והתצוגות המקדימות רועננו בהצלחה." : "Icons and previews refreshed successfully.")
      );
      await fetchIconCacheStatus();
    } else {
      showToast(
        currentLang === 'he' ? "שגיאה בבנייה מחדש" : "Error Rebuilding Cache",
        data.message || (currentLang === 'he' ? "פעולת האיפוס נכשלה." : "Failed to rebuild icon cache."),
        "danger"
      );
    }
  } catch (err) {
    showToast("Error", err.message, "danger");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('is-busy');
    }
  }
}

// -------------------------------------------------------------
// Enterprise IT Toolkit Suite (Active Directory, GPO, M365, SMB, etc.)
// -------------------------------------------------------------
const ENTERPRISE_TOOL_META = {
  kerberos_purge: {
    confirmTitleKey: 'confirmKerberosTitle',
    confirmDescKey: 'confirmKerberosDesc',
    btnConfirmKey: 'toolKerberosBtn',
    btnConfirmClass: 'btn-solid-primary',
    toastProgressHe: 'מאפס כרטיסי Kerberos ו-NetBIOS...',
    toastProgressEn: 'Purging Kerberos and NetBIOS tickets...'
  },
  gpo_reset: {
    confirmTitleKey: 'confirmGpoTitle',
    confirmDescKey: 'confirmGpoDesc',
    btnConfirmKey: 'toolGpoBtn',
    btnConfirmClass: 'btn-solid-primary',
    toastProgressHe: 'מסנכרן Group Policy מול שרת הדומיין...',
    toastProgressEn: 'Synchronizing Group Policy with Domain Controller...'
  },
  credentials_purge: {
    confirmTitleKey: 'confirmCredsTitle',
    confirmDescKey: 'confirmCredsDesc',
    btnConfirmKey: 'toolCredsBtn',
    btnConfirmClass: 'btn-solid-danger',
    toastProgressHe: 'מנקה אישורים וסיסמאות ישנות מ-Credential Manager...',
    toastProgressEn: 'Purging stale credentials from Credential Manager...'
  },
  entra_wam_reset: {
    confirmTitleKey: 'confirmEntraTitle',
    confirmDescKey: 'confirmEntraDesc',
    btnConfirmKey: 'toolEntraBtn',
    btnConfirmClass: 'btn-solid-primary',
    toastProgressHe: 'מאפס מנגנון אימות Entra ID WAM Broker...',
    toastProgressEn: 'Resetting Entra ID WAM Broker token cache...'
  },
  teams_reset: {
    confirmTitleKey: 'confirmTeamsTitle',
    confirmDescKey: 'confirmTeamsDesc',
    btnConfirmKey: 'toolTeamsBtn',
    btnConfirmClass: 'btn-solid-primary',
    toastProgressHe: 'מאפס את Microsoft Teams, מנקה מטמון ואסימוני אימות WAM...',
    toastProgressEn: 'Resetting Microsoft Teams, clearing caches & WAM auth tokens...'
  },
  outlook_reset: {
    confirmTitleKey: 'confirmOutlookTitle',
    confirmDescKey: 'confirmOutlookDesc',
    btnConfirmKey: 'toolOutlookBtn',
    btnConfirmClass: 'btn-solid-primary',
    toastProgressHe: 'מאפס את Microsoft Outlook, מנקה RoamCache, SRS ואסימוני אימות WAM...',
    toastProgressEn: 'Resetting Microsoft Outlook, clearing RoamCache, SRS & WAM auth tokens...'
  },
  outlook_srs_reset: {
    confirmTitleKey: 'confirmOutlookTitle',
    confirmDescKey: 'confirmOutlookDesc',
    btnConfirmKey: 'toolOutlookBtn',
    btnConfirmClass: 'btn-solid-primary',
    toastProgressHe: 'מאפס הגדרות שלח/קבל ומטמון Outlook...',
    toastProgressEn: 'Purging Outlook .SRS file and Autodiscover cache...'
  },
  network_drives_reset: {
    confirmTitleKey: 'confirmDrivesTitle',
    confirmDescKey: 'confirmDrivesDesc',
    btnConfirmKey: 'toolDrivesBtn',
    btnConfirmClass: 'btn-solid-primary',
    toastProgressHe: 'מנתק כונני רשת תקועים ומאתחל שירות SMB...',
    toastProgressEn: 'Disconnecting stuck mapped drives & restarting SMB...'
  },
  proxy_reset: {
    confirmTitleKey: 'confirmProxyTitle',
    confirmDescKey: 'confirmProxyDesc',
    btnConfirmKey: 'toolProxyBtn',
    btnConfirmClass: 'btn-solid-primary',
    toastProgressHe: 'מאפס הגדרות Proxy ו-WinHTTP לחיבור ישיר...',
    toastProgressEn: 'Resetting proxy and WinHTTP configurations...'
  },
  intune_sync: {
    confirmTitleKey: 'confirmIntuneTitle',
    confirmDescKey: 'confirmIntuneDesc',
    btnConfirmKey: 'toolIntuneBtn',
    btnConfirmClass: 'btn-solid-primary',
    toastProgressHe: 'מסנכרן סוכן Microsoft Intune (IME)...',
    toastProgressEn: 'Triggering Microsoft Intune agent synchronization...'
  },
  print_spooler_purge: {
    confirmTitleKey: 'confirmSpoolerTitle',
    confirmDescKey: 'confirmSpoolerDesc',
    btnConfirmKey: 'toolSpoolerBtn',
    btnConfirmClass: 'btn-solid-primary',
    toastProgressHe: 'עוצר Spooler, מנקה תור הדפסה ומפעיל מחדש...',
    toastProgressEn: 'Stopping Spooler, purging spool files and restarting...'
  },
  cert_crl_purge: {
    confirmTitleKey: 'confirmCertTitle',
    confirmDescKey: 'confirmCertDesc',
    btnConfirmKey: 'toolCertBtn',
    btnConfirmClass: 'btn-solid-primary',
    toastProgressHe: 'מנקה מטמון רשימות ביטול תעודות (CRL / OCSP)...',
    toastProgressEn: 'Flushing Certificate Revocation List (CRL) cache...'
  }
};

let enterpriseToolsList = [];

async function fetchEnterpriseTools() {
  try {
    const res = await fetch('/api/enterprise_tools/list');
    if (!res.ok) return;
    const data = await res.json();
    if (data && Array.isArray(data.tools)) {
      enterpriseToolsList = data.tools;
    }
  } catch (err) {
    console.error("Failed to fetch enterprise tools list:", err);
  }
}

function confirmRunEnterpriseTool(toolId) {
  const meta = ENTERPRISE_TOOL_META[toolId] || {};
  showConfirmDialog({
    title: meta.confirmTitleKey ? t(meta.confirmTitleKey) : (currentLang === 'he' ? "אישור ביצוע כלי IT" : "Confirm Tool Execution"),
    desc: meta.confirmDescKey ? t(meta.confirmDescKey) : (currentLang === 'he' ? "האם להמשיך בהפעלת הכלי?" : "Do you want to proceed?"),
    confirmText: meta.btnConfirmKey ? t(meta.btnConfirmKey) : (currentLang === 'he' ? "הפעל כלי" : "Execute Tool"),
    confirmClass: meta.btnConfirmClass || 'btn-solid-primary',
    onConfirm: () => executeEnterpriseTool(toolId)
  });
}

async function executeEnterpriseTool(toolId) {
  const meta = ENTERPRISE_TOOL_META[toolId] || {};
  const btn = document.getElementById(`btnRunTool_${toolId}`);
  if (btn) {
    btn.disabled = true;
    btn.classList.add('is-busy');
  }

  showToast(
    currentLang === 'he' ? "מבצע פעולת IT..." : "Executing IT utility...",
    currentLang === 'he'
      ? (meta.toastProgressHe || "מעבד את הפקודה ומחיל שינויים במערכת...")
      : (meta.toastProgressEn || "Processing command and applying system changes...")
  );

  try {
    const res = await fetch('/api/enterprise_tools/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool_id: toolId })
    });
    const data = await res.json();

    if (data.success) {
      showToast(
        currentLang === 'he' ? "פעולת ה-IT הושלמה" : "Enterprise Tool Completed",
        data.message || (currentLang === 'he' ? "הפעולה בוצעה בהצלחה." : "Action executed successfully.")
      );

      // Pop up notification in the center of the screen (with restart advice)
      if (data.restart_recommended || toolId === 'teams_reset' || toolId === 'outlook_reset' || toolId === 'entra_wam_reset') {
        showCenterAlertModal({
          title: currentLang === 'he' ? "איפוס הושלם בהצלחה" : "Reset Completed Successfully",
          message: data.message,
          restartRecommended: Boolean(data.restart_recommended || toolId === 'teams_reset' || toolId === 'outlook_reset'),
          restartTitle: currentLang === 'he'
            ? "שים לב — מומלץ לבצע הפעלה מחדש (Restart):"
            : "Notice — System Restart Recommended:",
          restartDesc: data.restart_reason || (currentLang === 'he'
            ? "כדי ש-Windows ייצור מפתחות אימות והצפנה נקיים (DPAPI Keyset) עבור חשבון מיקרוסופט ויפתור את שגיאה 894893981, מומלץ להפעיל מחדש את המחשב כעת לפני פתיחת האפליקציה."
            : "To allow Windows to generate fresh DPAPI cryptographic keysets for Microsoft accounts and resolve error 894893981, it is strongly recommended to restart your computer before launching the application.")
        });
      }
    } else {
      showToast(
        currentLang === 'he' ? "שגיאה בביצוע הפעולה" : "Execution Error",
        data.message || (currentLang === 'he' ? "הפעולה נכשלה." : "Tool execution failed."),
        "danger"
      );
    }
  } catch (err) {
    showToast("Error", err.message, "danger");
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('is-busy');
    }
  }
}

// Kept for backwards compatibility - delegates to esc() so there is a single
// escaping implementation (esc() also handles numbers and non-string values).
function escapeHtml(text) {
  return esc(text);
}

// =========================================================================
// UNINSTALLER SUITE (Revo-Grade Software Management & Leftovers Engine)
// =========================================================================

let allInstalledApps = [];
let uninstallerFilter = 'all';
let uninstallerSearchQuery = '';
let appsSortCol = 'name';
let appsSortAsc = true;
let isBatchMode = false;
let batchSelectedAppIds = new Set();

let activeUninstallApp = null;
let wizardPollingTimer = null;
let currentWizardLeftovers = null;
let currentLeftoversTab = 'registry';
let selectedLeftoverItems = new Set();
let selectedWizardScanMode = 'moderate';
let selectedForcedScanMode = 'moderate';
let currentHunterResolved = null;

// Set when the user closes the wizard while a request is still in flight, so
// the response that arrives afterwards does not force the modal back open.
let wizardClosedByUser = false;

// Live terminal state for the uninstall wizard.
const uninstallLogNodes = new Map();
let uninstallLogRev = 0;
let uninstallClockTimer = null;
let uninstallElapsedSeconds = 0;

/** Resets the wizard's live output and starts its local clock. */
function startWizardLiveOutput(firstLine) {
  const box = document.getElementById('wizardTerminalLogs');
  uninstallLogNodes.clear();
  uninstallLogRev = 0;
  uninstallElapsedSeconds = 0;

  if (box) box.innerHTML = `<div class="term-line term-info">[System] ${esc(firstLine)}</div>`;
  document.getElementById('wizardLiveOutputBox')?.classList.remove('hidden');
  const stepList = document.getElementById('wizardStepList');
  if (stepList) stepList.innerHTML = '';

  const elapsedEl = document.getElementById('wizardElapsed');
  if (elapsedEl) elapsedEl.textContent = fmtClock(0);
  const etaEl = document.getElementById('wizardEta');
  if (etaEl) etaEl.textContent = '';
  const countEl = document.getElementById('wizardStepCount');
  if (countEl) countEl.textContent = '';

  // The clock ticks locally every second so it stays smooth between polls;
  // the backend's elapsed value only corrects it.
  if (uninstallClockTimer) clearInterval(uninstallClockTimer);
  uninstallClockTimer = setInterval(() => {
    uninstallElapsedSeconds += 1;
    const el = document.getElementById('wizardElapsed');
    if (el) el.textContent = fmtClock(uninstallElapsedSeconds);
  }, 1000);
}

function stopWizardClock() {
  if (uninstallClockTimer) {
    clearInterval(uninstallClockTimer);
    uninstallClockTimer = null;
  }
  const etaEl = document.getElementById('wizardEta');
  if (etaEl) etaEl.textContent = '';
}

/** Pulls whatever is new in the engine's log into the wizard terminal. */
async function pumpUninstallLog() {
  try {
    const res = await fetch(`/api/uninstaller/status?since=${uninstallLogRev}`);
    if (!res.ok) return null;
    const status = await res.json();
    applyUninstallLiveOutput(status);
    return status;
  } catch (err) {
    return null;
  }
}

function applyUninstallLiveOutput(status) {
  if (!status) return;
  if (typeof status.log_rev === 'number') uninstallLogRev = status.log_rev;

  const he = currentLang === 'he';

  appendTerminalLogs(document.getElementById('wizardTerminalLogs'), status.logs, uninstallLogNodes);
  renderStepList(document.getElementById('wizardStepList'), status.steps);

  if (typeof status.elapsed_seconds === 'number' && status.elapsed_seconds > 0) {
    uninstallElapsedSeconds = Math.round(status.elapsed_seconds);
    const el = document.getElementById('wizardElapsed');
    if (el) el.textContent = fmtClock(uninstallElapsedSeconds);
  }

  const etaEl = document.getElementById('wizardEta');
  if (etaEl) {
    etaEl.textContent = status.eta_seconds > 0
      ? (he ? `נותרו כ-${fmtClock(status.eta_seconds)}` : `~${fmtClock(status.eta_seconds)} left`)
      : '';
  }

  const countEl = document.getElementById('wizardStepCount');
  if (countEl && status.total_steps) {
    const n = Math.min(status.done_steps + 1, status.total_steps);
    countEl.textContent = he
      ? `שלב ${n} מתוך ${status.total_steps}`
      : `Step ${n} of ${status.total_steps}`;
  }

  // A forced scan has no session, so it has no `progress_pct`; `plan_percent`
  // is published unconditionally so its bar moves too.
  if (!status.active && typeof status.plan_percent === 'number' && status.steps?.length) {
    const bar = document.getElementById('wizardProgressBar');
    const pctText = document.getElementById('wizardProgressPercent');
    if (bar) bar.style.width = `${status.plan_percent}%`;
    if (pctText) pctText.textContent = `${status.plan_percent}%`;
  }
}

/** Copies the whole visible log, so a failure can be pasted into a report. */
async function copyUninstallLog() {
  const box = document.getElementById('wizardTerminalLogs');
  if (!box) return;
  const text = Array.from(box.children).map(n => n.textContent).join('\n');
  try {
    await navigator.clipboard.writeText(text);
    showToast("הלוג הועתק", `${box.children.length} שורות הועתקו ללוח.`, "ok");
  } catch (err) {
    // Clipboard access can be refused; selecting the text is the fallback.
    const range = document.createRange();
    range.selectNodeContents(box);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    showToast("העתקה נחסמה", "הלוג נבחר — לחץ Ctrl+C להעתקה.", "warn");
  }
}

/** Fetch installed applications from the backend uninstaller engine (instant 0 ms display). */
async function fetchInstalledApps(force = false) {
  const tbody = document.getElementById('installedAppsTbody');

  // 1. Instant Cache: If memory is empty, load from localStorage immediately (0 ms)
  if (!allInstalledApps.length) {
    try {
      const cached = localStorage.getItem('mempulse_apps_cache');
      if (cached) {
        allInstalledApps = JSON.parse(cached);
        updateUninstallerMetrics();
        renderInstalledAppsTable();
        const navTag = document.getElementById('navTagUninstaller');
        if (navTag && allInstalledApps.length) {
          navTag.textContent = allInstalledApps.length;
          navTag.classList.remove('hidden');
        }
      }
    } catch (e) {
      console.warn("Error reading apps cache:", e);
    }
  }

  // Only show loading spinner if we have completely empty state (no memory & no cache)
  if (!allInstalledApps.length && tbody) {
    tbody.innerHTML = `<tr><td colspan="7" class="loading" style="text-align: center; padding: 40px;">${t('loadingApps')}</td></tr>`;
  }

  try {
    const res = await fetch(`/api/uninstaller/apps?force=${force ? 1 : 0}`);
    const data = await res.json();
    const freshApps = data.apps || [];
    allInstalledApps = freshApps;

    // Cache in localStorage for instant 0 ms loading on next visit/reload
    try {
      localStorage.setItem('mempulse_apps_cache', JSON.stringify(freshApps));
    } catch (e) {}

    updateUninstallerMetrics();
    renderInstalledAppsTable();

    const navTag = document.getElementById('navTagUninstaller');
    if (navTag) {
      navTag.textContent = allInstalledApps.length;
      navTag.classList.remove('hidden');
    }
  } catch (err) {
    if (!allInstalledApps.length && tbody) {
      tbody.innerHTML = `<tr><td colspan="7" class="panel-text tone-danger" style="text-align: center; padding: 30px;">שגיאה בטעינת רשימת התוכנות: ${esc(err.message)}</td></tr>`;
    }
  }
}

/** Update top stats / metrics bar. */
function updateUninstallerMetrics() {
  const totalAppsEl = document.getElementById('valTotalApps');
  const totalSpaceEl = document.getElementById('valTotalAppSpace');
  const win32AppsEl = document.getElementById('valWin32Apps');
  const uwpAppsEl = document.getElementById('valUwpApps');

  if (totalAppsEl) totalAppsEl.textContent = allInstalledApps.length;

  let totalBytes = 0;
  let win32Count = 0;
  let uwpCount = 0;

  for (const app of allInstalledApps) {
    if (app.size_bytes) totalBytes += app.size_bytes;
    if (app.type === 'uwp') uwpCount++;
    else win32Count++;
  }

  if (win32AppsEl) win32AppsEl.textContent = win32Count;
  if (uwpAppsEl) uwpAppsEl.textContent = uwpCount;

  if (totalSpaceEl) {
    if (totalBytes > 1024 * 1024 * 1024) {
      totalSpaceEl.textContent = ltrIsolate((totalBytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB', true);
    } else {
      totalSpaceEl.textContent = ltrIsolate(Math.round(totalBytes / (1024 * 1024)) + ' MB', true);
    }
  }
}

/** Render applications table with filtering and sorting. */
function renderInstalledAppsTable() {
  const tbody = document.getElementById('installedAppsTbody');
  if (!tbody) return;

  let list = allInstalledApps.slice();

  // Search filter
  if (uninstallerSearchQuery) {
    const q = uninstallerSearchQuery.toLowerCase();
    list = list.filter(a => {
      const name = (a.name || '').toLowerCase();
      const pub = (a.publisher || '').toLowerCase();
      const loc = (a.install_location || '').toLowerCase();
      return name.includes(q) || pub.includes(q) || loc.includes(q);
    });
  }

  // Category filter
  if (uninstallerFilter === 'win32') {
    list = list.filter(a => a.type !== 'uwp');
  } else if (uninstallerFilter === 'uwp') {
    list = list.filter(a => a.type === 'uwp');
  } else if (uninstallerFilter === 'heavy') {
    list = list.filter(a => (a.size_bytes || 0) >= 500 * 1024 * 1024);
  }

  // Sort
  list.sort((a, b) => {
    let valA = a[appsSortCol];
    let valB = b[appsSortCol];

    if (appsSortCol === 'name') {
      valA = (a.name || '').toLowerCase();
      valB = (b.name || '').toLowerCase();
    } else if (appsSortCol === 'publisher') {
      valA = (a.publisher || '').toLowerCase();
      valB = (b.publisher || '').toLowerCase();
    } else if (appsSortCol === 'size') {
      valA = a.size_bytes || 0;
      valB = b.size_bytes || 0;
    } else if (appsSortCol === 'date') {
      valA = a.install_date || '';
      valB = b.install_date || '';
    }

    if (valA < valB) return appsSortAsc ? -1 : 1;
    if (valA > valB) return appsSortAsc ? 1 : -1;
    return 0;
  });

  const countBadge = document.getElementById('badgeAppsFilteredCount');
  if (countBadge) countBadge.textContent = list.length;

  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty" style="text-align: center; padding: 40px; color: var(--text-dim);">לא נמצאו תוכנות התואמות לחיפוש או לסינון הנוכחי.</td></tr>`;
    return;
  }

  const rows = list.map(app => {
    const isUwp = app.type === 'uwp';
    const isChecked = batchSelectedAppIds.has(app.id);

    let sizeText = '--';
    if (app.size_bytes) {
      if (app.size_bytes >= 1024 * 1024 * 1024) {
        sizeText = ltrIsolate((app.size_bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB', true);
      } else {
        sizeText = ltrIsolate(Math.round(app.size_bytes / (1024 * 1024)) + ' MB', true);
      }
    }

    const typeBadge = isUwp
      ? `<span class="badge badge-uwp">Store</span>`
      : `<span class="badge badge-win32">Win32</span>`;

    // The backend has no icon extractor (DisplayIcon is a "file.exe,0" resource
    // reference, not image data), so this is the real icon, not a fallback.
    const iconHtml = `<div class="app-icon-placeholder">${isUwp ? '⚡' : '📦'}</div>`;

    return `
      <tr class="trow">
        <td class="batch-col ${isBatchMode ? '' : 'hidden'}" style="text-align: center;">
          <input type="checkbox" ${isChecked ? 'checked' : ''} onchange="toggleBatchApp('${esc(app.id)}', this.checked)">
        </td>
        <td class="col-app-name">
          <div class="app-name-cell">
            ${iconHtml}
            <div class="app-info-wrap">
              <div class="row app-title-row" style="gap: 5px; align-items: center;">
                <span class="app-title-text" title="${esc(app.name)}" style="font-weight: 650;">${esc(app.name)}</span>
                ${typeBadge}
              </div>
              ${app.install_location ? `<div class="app-meta-sub" title="${esc(app.install_location)}">${esc(app.install_location)}</div>` : ''}
            </div>
          </div>
        </td>
        <td class="faint cell-truncate col-app-pub" title="${esc(app.publisher || '')}">${esc(app.publisher || '--')}</td>
        <td class="mono faint cell-truncate col-app-ver" title="${esc(app.version || '')}">${esc(app.version || '--')}</td>
        <td class="mono faint cell-truncate col-app-date" title="${esc(app.install_date || '')}">${esc(app.install_date || '--')}</td>
        <td class="num cell-truncate col-app-size" style="font-weight: 600;">${sizeText}</td>
        <td class="act col-app-act">
          <div class="row row-actions" style="gap: 4px; justify-content: flex-end; flex-wrap: nowrap;">
            <button class="btn btn-xs btn-solid-danger" onclick="openUninstallWizard('${esc(app.id)}')" title="הסרה מלאה עם סריקת שאריות">
              <svg fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24" style="width: 11px; height: 11px;">
                <path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
              </svg>
              <span>${t('btnUninstall') || 'הסר'}</span>
            </button>
            <button class="btn btn-xs btn-outline-warn btn-forced-uninstall" onclick="openForcedUninstallForApp('${esc(app.id)}')" title="הסרה כפויה">
              <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width: 11px; height: 11px;">
                <path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/>
              </svg>
              <span>${t('btnForcedUninstall') || 'הסרה כפויה'}</span>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  tbody.innerHTML = rows;
}

/** Search input handler */
function onUninstallerSearch(val) {
  uninstallerSearchQuery = (val || '').trim();
  const clearBtn = document.getElementById('btnClearUninstallerSearch');
  if (clearBtn) {
    clearBtn.classList.toggle('hidden', !uninstallerSearchQuery);
  }
  renderInstalledAppsTable();
}

/** Clear search input */
function clearUninstallerSearch() {
  const input = document.getElementById('uninstallerSearchInput');
  if (input) input.value = '';
  onUninstallerSearch('');
}

/** Filter category handler */
function setUninstallerFilter(filter) {
  uninstallerFilter = filter;
  ['All', 'Win32', 'Uwp', 'Heavy'].forEach(f => {
    const btn = document.getElementById(`uninstallerFilter${f}`);
    if (btn) btn.classList.toggle('active', filter === f.toLowerCase());
  });
  renderInstalledAppsTable();
}

/** Sort handler */
function sortApps(col) {
  if (appsSortCol === col) {
    appsSortAsc = !appsSortAsc;
  } else {
    appsSortCol = col;
    appsSortAsc = true;
  }
  renderInstalledAppsTable();
}

/** Toggle batch selection mode */
function toggleBatchMode() {
  isBatchMode = !isBatchMode;
  const bar = document.getElementById('batchActionBar');
  const btn = document.getElementById('btnToggleBatchMode');

  if (bar) bar.classList.toggle('hidden', !isBatchMode);
  if (btn) btn.classList.toggle('btn-primary', !isBatchMode);

  document.querySelectorAll('.batch-col').forEach(el => {
    el.classList.toggle('hidden', !isBatchMode);
  });

  updateBatchCountText();
}

/** Toggle individual batch app checkbox */
function toggleBatchApp(appId, checked) {
  if (checked) batchSelectedAppIds.add(appId);
  else batchSelectedAppIds.delete(appId);
  updateBatchCountText();
}

/** Select all / clear selection in batch */
function selectAllBatchApps(selectAll) {
  if (selectAll) {
    allInstalledApps.forEach(a => batchSelectedAppIds.add(a.id));
  } else {
    batchSelectedAppIds.clear();
  }
  renderInstalledAppsTable();
  updateBatchCountText();
}

/** Toggle header checkbox for batch */
function toggleSelectAllBatch(checked) {
  selectAllBatchApps(checked);
}

/** Update batch selection counter */
function updateBatchCountText() {
  const textEl = document.getElementById('batchSelectedCountText');
  if (textEl) {
    textEl.textContent = `${batchSelectedAppIds.size} תוכנות נבחרו להסרה`;
  }
}

/** Execute batch uninstallation */
async function executeBatchUninstall() {
  if (batchSelectedAppIds.size === 0) {
    showToast("הסרה מרוכזת", "בחר לפחות תוכנה אחת להסרה.");
    return;
  }

  const skipRp = !!document.getElementById('chkBatchSkipRp')?.checked;
  const count = batchSelectedAppIds.size;
  const confirmMsg = `האם אתה בטוח שברצונך להסיר ברצף ${count} תוכנות?${skipRp ? ' (ללא נקודת שחזור)' : ''}`;

  if (!confirm(confirmMsg)) return;

  showToast(
    "הסרה מרוכזת בפעולה",
    `מפעיל הסרה ברצף עבור ${count} תוכנות...`,
    "accent"
  );

  try {
    const res = await fetch('/api/uninstaller/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        app_ids: Array.from(batchSelectedAppIds),
        mode: "moderate",
        skip_restore_point: skipRp
      })
    });
    const data = await res.json();

    if (data.success) {
      let msg = `הוסרו בהצלחה ${data.succeeded} מתוך ${data.total} תוכנות.`;
      if (data.needs_review) {
        msg += ` ${data.needs_review} שאריות רגישות (שירותים, דרייברים ורכיבי COM) לא נוקו אוטומטית וממתינות לבדיקה שלך.`;
      }
      if ((data.warnings || []).length) {
        msg += ' ' + data.warnings.join(' ');
      }
      showToast("הסרה מרוכזת הושלמה", msg, data.needs_review ? "warn" : undefined);
      batchSelectedAppIds.clear();
      toggleBatchMode();
      fetchInstalledApps(true);
    } else {
      showToast("שגיאה בהסרה מרוכזת", data.error || "נכשלה הפעולה");
    }
  } catch (err) {
    showToast("שגיאה", err.message);
  }
}

// -------------------------------------------------------------------------
// Uninstall Wizard Execution Flow (Pre-Safety, Monitored Exec, Leftovers)
// -------------------------------------------------------------------------

/** Open uninstallation wizard for an app */
function openUninstallWizard(appId) {
  const app = allInstalledApps.find(a => a.id === appId);
  if (!app) return;

  wizardClosedByUser = false;
  activeUninstallApp = app;

  const titleEl = document.getElementById('wizardAppTitle');
  const subEl = document.getElementById('wizardAppSub');
  const iconContainer = document.getElementById('wizardAppIconContainer');

  if (titleEl) titleEl.textContent = app.name;
  if (subEl) subEl.textContent = (app.publisher ? app.publisher + ' · ' : '') + (app.version || '');
  if (iconContainer) {
    iconContainer.innerHTML = app.type === 'uwp' ? '⚡' : '📦';
  }

  // Reset steps
  document.getElementById('wizardStep1Content')?.classList.remove('hidden');
  document.getElementById('wizardStep2Content')?.classList.add('hidden');
  document.getElementById('wizardStep3Content')?.classList.add('hidden');
  document.getElementById('wizardStep4Content')?.classList.add('hidden');

  // Reset foot buttons
  document.getElementById('btnWizardCancel')?.classList.remove('hidden');
  document.getElementById('btnWizardPreviewScan')?.classList.remove('hidden');
  document.getElementById('btnWizardStartNoRp')?.classList.remove('hidden');
  document.getElementById('btnWizardStartNormal')?.classList.remove('hidden');
  document.getElementById('btnWizardDeleteSelected')?.classList.add('hidden');
  document.getElementById('btnWizardFinish')?.classList.add('hidden');

  // The wizard is a single set of DOM nodes reused for every run, so anything
  // the previous run disabled, rewrote or recoloured has to be undone here.
  // Without this the delete button stayed dead after the first cleanup and the
  // Skip button kept the error-path handler for the rest of the page session.
  const btnDelete = document.getElementById('btnWizardDeleteSelected');
  if (btnDelete) btnDelete.disabled = false;

  const btnSkip = document.getElementById('btnWizardSkipCurrent');
  if (btnSkip) btnSkip.disabled = true;

  const bar = document.getElementById('wizardProgressBar');
  if (bar) {
    bar.style.backgroundColor = '';
    bar.style.width = '0%';
  }

  const doneDesc = document.getElementById('wizardDoneDesc');
  if (doneDesc) doneDesc.textContent = 'כל השאריות הנבחרות הוסרו מהמערכת.';

  document.getElementById('wizardRebootNotice')?.classList.add('hidden');
  document.getElementById('wizardLiveOutputBox')?.classList.add('hidden');
  stopWizardClock();
  currentWizardLeftovers = null;
  selectedLeftoverItems.clear();

  const chkRp = document.getElementById('chkWizardRestorePoint');
  if (chkRp) chkRp.checked = true;
  const chkReg = document.getElementById('chkWizardRegistryBackup');
  if (chkReg) chkReg.checked = true;

  selectWizardScanMode('moderate');

  document.getElementById('modalUninstallWizard')?.classList.remove('hidden');
}

/** Close wizard modal and clean up timers */
function closeUninstallWizard() {
  wizardClosedByUser = true;
  if (wizardPollingTimer) {
    clearInterval(wizardPollingTimer);
    wizardPollingTimer = null;
  }
  stopWizardClock();
  document.getElementById('modalUninstallWizard')?.classList.add('hidden');
  activeUninstallApp = null;
  currentWizardLeftovers = null;
}

/** Toggle restore point checkbox in wizard */
function wizardToggleSkipRpOnly() {
  const chk = document.getElementById('chkWizardRestorePoint');
  if (chk) {
    chk.checked = !chk.checked;
    showToast(
      "הגדרות שחזור",
      chk.checked ? "יצירת נקודת שחזור הופעלה" : "דולג על יצירת נקודת שחזור מערכת"
    );
  }
}

/** Select heuristic scan mode in wizard */
function selectWizardScanMode(mode) {
  selectedWizardScanMode = mode;
  ['safe', 'moderate', 'advanced'].forEach(m => {
    const card = document.getElementById(`modeCard${m.charAt(0).toUpperCase() + m.slice(1)}`);
    if (card) card.classList.toggle('active', m === mode);
  });
}

/** Submit start of uninstallation */
async function submitStartUninstall(skipRestorePoint = false) {
  if (!activeUninstallApp) return;

  const chkRp = document.getElementById('chkWizardRestorePoint');
  const chkReg = document.getElementById('chkWizardRegistryBackup');

  const skipRp = skipRestorePoint || !(chkRp && chkRp.checked);
  const skipReg = !(chkReg && chkReg.checked);

  // Transition to step 2
  document.getElementById('wizardStep1Content')?.classList.add('hidden');
  document.getElementById('wizardStep2Content')?.classList.remove('hidden');

  document.getElementById('btnWizardPreviewScan')?.classList.add('hidden');
  document.getElementById('btnWizardStartNoRp')?.classList.add('hidden');
  document.getElementById('btnWizardStartNormal')?.classList.add('hidden');

  const stageText = document.getElementById('wizardCurrentStageText');
  const pctText = document.getElementById('wizardProgressPercent');
  const bar = document.getElementById('wizardProgressBar');
  const details = document.getElementById('wizardStatusDetails');
  const btnSkip = document.getElementById('btnWizardSkipCurrent');

  if (stageText) stageText.textContent = "מאתחל תהליך הסרה...";
  if (pctText) pctText.textContent = "0%";
  if (bar) bar.style.width = "0%";
  if (details) details.textContent = "מתכונן להסרה...";
  if (btnSkip) btnSkip.disabled = true;

  startWizardLiveOutput(`מתחיל הסרה של ${activeUninstallApp.name}…`);

  try {
    const res = await fetch('/api/uninstaller/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        app_id: activeUninstallApp.id,
        skip_restore_point: skipRp,
        skip_registry_backup: skipReg,
        scan_mode: selectedWizardScanMode
      })
    });
    const data = await res.json();

    if (!data.success) {
      if (details) details.textContent = `שגיאה: ${data.error || 'נכשל'}`;
      showToast("שגיאה", data.error || "נכשל אתחול ההסרה", "danger");
      abortWizardStart();
      return;
    }

    // A run is now in flight on the engine. Cancel would only hide the modal
    // and orphan it — the way out of a stuck step is Skip.
    document.getElementById('btnWizardCancel')?.classList.add('hidden');

    // Start status polling
    if (wizardPollingTimer) clearInterval(wizardPollingTimer);
    wizardPollingTimer = setInterval(pollUninstallStatus, 700);

  } catch (err) {
    if (details) details.textContent = `שגיאת רשת: ${err.message}`;
    showToast("שגיאת רשת", err.message, "danger");
    abortWizardStart();
  }
}

/**
 * Scans an installed program for what it has scattered around the system,
 * without uninstalling it and without pre-selecting anything for deletion.
 * The engine leaves the program's own folder and Add/Remove entry out of the
 * results entirely - they are the program, not residue.
 */
async function submitPreviewScan() {
  if (!activeUninstallApp) return;

  // A poll loop left over from an earlier run would keep rewriting the stage
  // text and could force step 3 while this scan is still in flight.
  if (wizardPollingTimer) {
    clearInterval(wizardPollingTimer);
    wizardPollingTimer = null;
  }

  document.getElementById('wizardStep1Content')?.classList.add('hidden');
  document.getElementById('wizardStep2Content')?.classList.remove('hidden');
  document.getElementById('wizardStep3Content')?.classList.add('hidden');
  document.getElementById('wizardStep4Content')?.classList.add('hidden');
  document.getElementById('btnWizardPreviewScan')?.classList.add('hidden');
  document.getElementById('btnWizardStartNoRp')?.classList.add('hidden');
  document.getElementById('btnWizardStartNormal')?.classList.add('hidden');
  document.getElementById('btnWizardDeleteSelected')?.classList.add('hidden');
  document.getElementById('btnWizardFinish')?.classList.add('hidden');

  const stageText = document.getElementById('wizardCurrentStageText');
  if (stageText) stageText.textContent = 'סריקה בלבד — לא מוסר דבר';
  const details = document.getElementById('wizardStatusDetails');
  if (details) details.textContent = 'מאתר מה התוכנה השאירה ברישום ובדיסק.';
  const skipBtn = document.getElementById('btnWizardSkipCurrent');
  if (skipBtn) skipBtn.disabled = true;

  startWizardLiveOutput(`סורק את ${activeUninstallApp.name} בלי להסיר…`);
  const logPump = setInterval(pumpUninstallLog, 600);

  try {
    const res = await fetch('/api/uninstaller/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ app_id: activeUninstallApp.id, mode: selectedWizardScanMode })
    });
    const data = await res.json();
    clearInterval(logPump);
    await pumpUninstallLog();
    stopWizardClock();

    if (wizardClosedByUser) return;

    if (!data.success) {
      // Stay on step 2: the terminal above holds the reason the scan failed.
      if (details) details.textContent = data.error || 'הסריקה נכשלה';
      document.getElementById('btnWizardPreviewScan')?.classList.remove('hidden');
      document.getElementById('btnWizardStartNoRp')?.classList.remove('hidden');
      document.getElementById('btnWizardStartNormal')?.classList.remove('hidden');
      showToast("שגיאה", data.error || "הסריקה נכשלה", "danger");
      return;
    }

    currentWizardLeftovers = data.leftovers || { registry: [], files: [] };
    document.getElementById('wizardStep2Content')?.classList.add('hidden');
    document.getElementById('wizardStep3Content')?.classList.remove('hidden');
    const btnDel = document.getElementById('btnWizardDeleteSelected');
    if (btnDel) {
      btnDel.classList.remove('hidden');
      btnDel.disabled = false;
    }
    renderLeftoversView();
    showToast(
      "סריקה בלבד",
      "התוכנה לא הוסרה. שום פריט לא נבחר מראש — סמן בעצמך מה למחוק.",
      "warn"
    );
  } catch (err) {
    showToast("שגיאה", err.message, "danger");
    abortWizardStart();
  } finally {
    clearInterval(logPump);
    stopWizardClock();
  }
}

/**
 * The run never started, so put step 1 back instead of leaving the user on a
 * progress screen with a clock ticking against nothing.
 */
function abortWizardStart() {
  stopWizardClock();
  document.getElementById('wizardLiveOutputBox')?.classList.add('hidden');
  document.getElementById('wizardStep2Content')?.classList.add('hidden');
  document.getElementById('wizardStep1Content')?.classList.remove('hidden');
  document.getElementById('btnWizardPreviewScan')?.classList.remove('hidden');
  document.getElementById('btnWizardStartNoRp')?.classList.remove('hidden');
  document.getElementById('btnWizardStartNormal')?.classList.remove('hidden');
}

/** Skip current step in active uninstallation (e.g. restore point or uninstaller) */
async function skipCurrentUninstallStep() {
  const btn = document.getElementById('btnWizardSkipCurrent');
  if (btn) btn.disabled = true;

  showToast("דילוג על שלב", "מדלג על השלב הנוכחי לפי בקשתך...", "warn");

  try {
    await fetch('/api/uninstaller/skip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    console.error("Skip error:", err);
  }
}

/** Poll active uninstallation session status */
async function pollUninstallStatus() {
  try {
    const res = await fetch(`/api/uninstaller/status?since=${uninstallLogRev}`);
    if (!res.ok) throw new Error(`הסטטוס חזר עם קוד ${res.status}`);
    const status = await res.json();

    // Log rows and step states arrive on the same poll as the stage, so the
    // terminal keeps moving even while one long step is running.
    applyUninstallLiveOutput(status);

    if (!status.active) {
      // The engine has no session at all. Something ended the run behind our
      // back; say so instead of freezing on step 2 with no explanation.
      if (wizardPollingTimer) {
        clearInterval(wizardPollingTimer);
        wizardPollingTimer = null;
      }
      stopWizardClock();
      document.getElementById('btnWizardCancel')?.classList.remove('hidden');
      const lost = document.getElementById('wizardStatusDetails');
      if (lost) lost.textContent = 'הקשר לתהליך ההסרה אבד. בדוק את הלוג למעלה.';
      showToast("ההסרה הופסקה", "הקשר לתהליך ההסרה אבד. הפרטים בלוג.", "warn");
      return;
    }

    const stageText = document.getElementById('wizardCurrentStageText');
    const pctText = document.getElementById('wizardProgressPercent');
    const bar = document.getElementById('wizardProgressBar');
    const details = document.getElementById('wizardStatusDetails');
    const btnSkip = document.getElementById('btnWizardSkipCurrent');

    const pct = status.progress_pct || 0;
    if (pctText) pctText.textContent = pct + '%';
    if (bar) bar.style.width = pct + '%';
    if (details) details.textContent = status.status_message || '';
    if (btnSkip) btnSkip.disabled = !status.can_skip;

    if (stageText) {
      if (status.stage === 'restore_point') stageText.textContent = "יצירת נקודת שחזור מערכת (VSS)";
      else if (status.stage === 'registry_backup') stageText.textContent = "גיבוי ענפי ה-Registry";
      else if (status.stage === 'native_uninstall') stageText.textContent = "הפעלת מסיר התוכנה המקורי (Uninstaller)";
      else if (status.stage === 'scanning') stageText.textContent = `סריקת שאריות מבוססת דפוסים (${status.scan_mode || 'Moderate'})`;
      else if (status.stage === 'ready_for_review') stageText.textContent = "סריקת השאריות הושלמה";
      else stageText.textContent = status.status_message || "מעבד...";
    }

    // Ready for leftover review
    if (status.stage === 'ready_for_review') {
      if (wizardPollingTimer) {
        clearInterval(wizardPollingTimer);
        wizardPollingTimer = null;
      }
      stopWizardClock();
      document.getElementById('btnWizardCancel')?.classList.remove('hidden');

      currentWizardLeftovers = status.leftovers || { registry: [], files: [] };

      document.getElementById('wizardStep2Content')?.classList.add('hidden');
      document.getElementById('wizardStep3Content')?.classList.remove('hidden');
      document.getElementById('btnWizardDeleteSelected')?.classList.remove('hidden');

      // A restore point that silently failed to be created is exactly the kind
      // of thing the user needs to hear about before deleting anything.
      (status.warnings || []).forEach(w => showToast("שים לב", w, "warn"));

      renderLeftoversView();
    } else if (status.stage === 'error') {
      if (wizardPollingTimer) {
        clearInterval(wizardPollingTimer);
        wizardPollingTimer = null;
      }
      stopWizardClock();
      document.getElementById('btnWizardCancel')?.classList.remove('hidden');
      if (stageText) stageText.textContent = "שגיאה במהלך ההסרה";
      if (details) details.textContent = status.error || status.status_message || "אירעה שגיאה";
      if (bar) bar.style.backgroundColor = "var(--danger)";

      // Move on to the leftovers list rather than repurposing the Skip button
      // (rewriting that shared button's markup and handler left it broken for
      // every later run on the same page) - but only when there is actually a
      // scan result. Otherwise step 3 would claim "המערכת נקייה" directly
      // under the error, which is the opposite of what happened.
      if (btnSkip) btnSkip.disabled = true;
      if (status.leftovers) {
        currentWizardLeftovers = status.leftovers;
        document.getElementById('wizardStep2Content')?.classList.add('hidden');
        document.getElementById('wizardStep3Content')?.classList.remove('hidden');
        const btnDel = document.getElementById('btnWizardDeleteSelected');
        if (btnDel) {
          btnDel.classList.remove('hidden');
          btnDel.disabled = false;
        }
        renderLeftoversView();
      }

      showToast("שגיאה במהלך ההסרה", status.error || "אירעה שגיאה", "danger");
    }

  } catch (err) {
    // One dropped poll is noise; the next tick recovers. Only surface it if
    // the wizard would otherwise sit silent.
    console.error("Poll error:", err);
    const details = document.getElementById('wizardStatusDetails');
    if (details) details.textContent = `אין תשובה מהשרת (${err.message}) — ממשיך לנסות…`;
  }
}

// -------------------------------------------------------------------------
// Leftovers View & The Bold Rule Execution
// -------------------------------------------------------------------------

/** Initialize and render leftovers view */
function renderLeftoversView() {
  if (!currentWizardLeftovers) return;

  const regItems = currentWizardLeftovers.registry || [];
  const fileItems = currentWizardLeftovers.files || [];
  const taskItems = currentWizardLeftovers.scheduled_tasks || [];

  const regBadge = document.getElementById('badgeCountRegLeftovers');
  const filesBadge = document.getElementById('badgeCountFilesLeftovers');
  const tasksBadge = document.getElementById('badgeCountTasksLeftovers');
  if (regBadge) regBadge.textContent = regItems.length;
  if (filesBadge) filesBadge.textContent = fileItems.length;
  if (tasksBadge) tasksBadge.textContent = taskItems.length;

  const summary = document.getElementById('wizardLeftoversCountSummary');
  if (summary) {
    const taskNote = taskItems.length ? ` ו-${taskItems.length} משימות מתוזמנות` : '';
    summary.textContent = currentWizardLeftovers.still_installed
      ? `סריקה בלבד: ${regItems.length} מפתחות רישום, ${fileItems.length} קבצים ותיקיות${taskNote}. התוכנה לא הוסרה, ולכן שום פריט לא נבחר מראש.`
      : `נמצאו ${regItems.length} מפתחות רישום, ${fileItems.length} קבצים ותיקיות${taskNote} שנותרו במערכת.`;
  }

  // Pre-select ALL bold items by default (Revo's core safety rule).
  // Keyed on the engine's item id, not on the path: two autostart values under
  // the same Run key share a path and used to collapse into one checkbox.
  selectedLeftoverItems.clear();
  regItems.concat(fileItems, taskItems).forEach(item => {
    if (item.is_bold && item.id) selectedLeftoverItems.add(item.id);
  });

  const sharedDlls = currentWizardLeftovers.shared_dlls_protected || [];
  const sharedDllsNote = document.getElementById('sharedDllsNote');
  if (sharedDllsNote) {
    sharedDllsNote.classList.toggle('hidden', sharedDlls.length === 0);
    if (sharedDlls.length) {
      sharedDllsNote.textContent =
        `ℹ ${sharedDlls.length} ספריות DLL משותפות עדיין רשומות לתוכנות אחרות — התיקיות שמכילות אותן לא נבחרו למחיקה.`;
    }
  }

  // Half the leftovers live under HKLM and simply cannot be removed without
  // elevation. Say so before the user clicks, not after.
  if (currentWizardLeftovers.requires_admin) {
    showToast(
      "דרושות הרשאות מנהל",
      "חלק מהשאריות נמצאות ב-HKLM. ללא הרצה כמנהל הן לא יימחקו.",
      "warn"
    );
  }

  switchLeftoversTab('registry');
}

/** Switch between Registry and Files tabs */
function switchLeftoversTab(tab) {
  currentLeftoversTab = tab;
  document.getElementById('tabLeftoversRegistry')?.classList.toggle('active', tab === 'registry');
  document.getElementById('tabLeftoversFiles')?.classList.toggle('active', tab === 'files');
  document.getElementById('tabLeftoversTasks')?.classList.toggle('active', tab === 'scheduled_tasks');
  renderActiveLeftoversTab();
}

/** Render items for the active leftover tab */
function renderActiveLeftoversTab() {
  const container = document.getElementById('leftoversTreeContainer');
  if (!container || !currentWizardLeftovers) return;

  const items = currentWizardLeftovers[currentLeftoversTab] || [];

  if (!items.length) {
    container.innerHTML = `<div class="empty" style="padding: 24px; text-align: center; color: var(--text-dim);">לא נמצאו שאריות בקטגוריה זו. המערכת נקייה.</div>`;
    return;
  }

  const html = items.map(item => {
    const isChecked = selectedLeftoverItems.has(item.id);
    const isBold = !!item.is_bold;
    const isHighRisk = item.risk === 'high';

    let sizeStr = item.size_formatted || '';
    if (!sizeStr && item.size_bytes) {
      sizeStr = formatBytesJS(item.size_bytes);
    }

    const boldIndicator = isBold
      ? `<span class="leftover-bold-indicator" title="סומן כבטוח למחיקה">● מומלץ למחיקה (Bold)</span>`
      : `<span class="faint" style="font-size: 10px;">פריט מערכת / הקשר</span>`;

    const riskIndicator = isHighRisk
      ? `<span class="badge badge-warn" title="נוגע במצב משותף של המערכת — בדוק לפני מחיקה">דורש בדיקה</span>`
      : '';

    const label = item.name && item.type === 'value'
      ? `${item.path}\\${item.name}`
      : item.path;

    return `
      <div class="leftover-item ${isBold ? 'leftover-bold' : 'leftover-regular'}">
        <input type="checkbox" class="leftover-checkbox" ${isChecked ? 'checked' : ''} onchange="toggleLeftoverItem('${esc(item.id)}', this.checked)">
        <div class="leftover-content">
          <span class="leftover-path" title="${esc(item.reason || label)}">${esc(label)}</span>
          <div class="leftover-meta">
            <span class="leftover-tag">${esc(item.type || '')}</span>
            ${sizeStr ? `<span>${esc(sizeStr)}</span>` : ''}
            ${riskIndicator}
            ${boldIndicator}
          </div>
        </div>
      </div>
    `;
  }).join('');

  container.innerHTML = html;
}

/** Toggle individual leftover item selection (by engine item id) */
function toggleLeftoverItem(itemId, checked) {
  if (checked) selectedLeftoverItems.add(itemId);
  else selectedLeftoverItems.delete(itemId);
}

/** All leftovers across every tab */
function allLeftoverItems() {
  if (!currentWizardLeftovers) return [];
  return (currentWizardLeftovers.registry || [])
    .concat(currentWizardLeftovers.files || [])
    .concat(currentWizardLeftovers.scheduled_tasks || []);
}

/** Select bold items only (Revo safety rule) */
function selectOnlyBoldLeftovers() {
  if (!currentWizardLeftovers) return;
  selectedLeftoverItems.clear();
  allLeftoverItems().forEach(item => {
    if (item.is_bold && item.id) selectedLeftoverItems.add(item.id);
  });

  renderActiveLeftoversTab();
  showToast("בחירה בטוחה", "נבחרו כל הפריטים הבטוחים והמודגשים (Bold).");
}

/** Select all or clear all leftovers */
function selectAllLeftovers(selectAll) {
  if (!currentWizardLeftovers) return;
  selectedLeftoverItems.clear();

  if (selectAll) {
    allLeftoverItems().forEach(item => {
      if (item.id) selectedLeftoverItems.add(item.id);
    });
    showToast("בחירת שאריות", "כל השאריות נבחרו למחיקה.");
  } else {
    showToast("ניקוי בחירה", "נוקתה הבחירה.");
  }

  renderActiveLeftoversTab();
}

/** Execute deletion of selected leftovers */
async function executeDeleteLeftovers() {
  if (!currentWizardLeftovers || selectedLeftoverItems.size === 0) {
    showToast("מחיקת שאריות", "לא נבחרו פריטים למחיקה.");
    return;
  }

  // Only ids travel to the server; it resolves them against its own scan
  // results, so the client can never name a path to delete.
  const idsToDelete = allLeftoverItems()
    .filter(i => selectedLeftoverItems.has(i.id))
    .map(i => i.id);

  if (!idsToDelete.length) {
    showToast("מחיקת שאריות", "לא נבחרו פריטים למחיקה.");
    return;
  }

  const btn = document.getElementById('btnWizardDeleteSelected');
  if (btn) btn.disabled = true;

  // The delete is one blocking POST, so without this the terminal would freeze
  // for the whole cleanup. Poll the engine's log alongside it.
  document.getElementById('wizardLiveOutputBox')?.classList.remove('hidden');
  const logPump = setInterval(pumpUninstallLog, 600);

  try {
    const res = await fetch('/api/uninstaller/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ selected_ids: idsToDelete })
    });
    const data = await res.json();
    clearInterval(logPump);
    await pumpUninstallLog();  // drain the last lines

    // data.success now reflects whether EVERY selected item was removed
    // (see delete_leftovers) - a run that partially failed still ran and
    // still freed whatever it could, so it's shown on the done screen with
    // the failures listed, same as before. Only a request the server never
    // even ran (no scan match, nothing selected) has no summary at all and
    // falls to the error toast below.
    const ran = data.summary || data.deleted_registry !== undefined || data.deleted_files !== undefined;

    if (ran) {
      // Transition to step 4 (Done)
      document.getElementById('wizardStep3Content')?.classList.add('hidden');
      document.getElementById('wizardStep4Content')?.classList.remove('hidden');

      document.getElementById('btnWizardDeleteSelected')?.classList.add('hidden');
      document.getElementById('btnWizardCancel')?.classList.add('hidden');
      document.getElementById('btnWizardFinish')?.classList.remove('hidden');

      const valReg = document.getElementById('valWizardDeletedReg');
      const valFiles = document.getElementById('valWizardDeletedFiles');
      const valTasks = document.getElementById('valWizardDeletedTasks');
      if (valReg) valReg.textContent = data.deleted_registry || 0;
      if (valFiles) valFiles.textContent = data.deleted_files || 0;
      if (valTasks) valTasks.textContent = data.deleted_tasks || 0;

      const rebootNotice = document.getElementById('wizardRebootNotice');
      if (rebootNotice) {
        rebootNotice.classList.toggle('hidden', !data.reboot_required);
      }

      // Honest reporting: anything that could not be removed is named, not
      // quietly folded into the success count.
      const failed = data.failed || [];
      const doneDesc = document.getElementById('wizardDoneDesc');
      if (doneDesc) {
        if (failed.length) {
          const sample = failed.slice(0, 3)
            .map(f => `${f.name || f.path} — ${f.reason}`)
            .join(' · ');
          doneDesc.textContent =
            `${failed.length} פריטים לא הוסרו: ${sample}${failed.length > 3 ? ' ועוד…' : ''}`;
        } else {
          doneDesc.textContent =
            `כל השאריות הנבחרות הוסרו מהמערכת. שוחרר ${data.freed_formatted || '0 B'}.`;
        }
      }

      showToast(
        "ניקוי שאריות הושלם",
        `נמחקו ${data.deleted_registry || 0} פריטי רישום, ${data.deleted_files || 0} קבצים` +
        (data.deleted_tasks ? ` ו-${data.deleted_tasks} משימות מתוזמנות` : '') +
        (failed.length ? ` · ${failed.length} נכשלו` : ''),
        failed.length ? "warn" : undefined
      );
      fetchInstalledApps(true);
    } else {
      showToast("שגיאה במחיקה", data.error || "נכשלה מחיקת השאריות");
      if (btn) btn.disabled = false;
    }
  } catch (err) {
    showToast("שגיאה", err.message);
    if (btn) btn.disabled = false;
  } finally {
    clearInterval(logPump);
  }
}

// -------------------------------------------------------------------------
// Forced Uninstall Modal Flow
// -------------------------------------------------------------------------

/**
 * Opens the forced-uninstall modal for a row in the table.
 *
 * Takes the app id rather than interpolating the name and path into the inline
 * onclick: an install path like C:\Users\... produced an invalid JS escape and
 * broke the button outright, and a crafted DisplayName could execute, because
 * the HTML parser decodes &#39; back to a quote before the handler is compiled.
 * Same reasoning as the atomic-key fix applied to the process table in v2.6.
 */
function openForcedUninstallForApp(appId) {
  const app = allInstalledApps.find(a => a.id === appId);
  if (!app) return;
  openForcedUninstallModal(app.name, app.install_location || '');
}

/** Open forced uninstall modal */
function openForcedUninstallModal(defaultTarget = '', defaultPath = '') {
  const input = document.getElementById('forcedTargetInput');
  if (input) input.value = defaultPath || defaultTarget || '';
  setForcedMode('moderate');
  document.getElementById('modalForcedUninstall')?.classList.remove('hidden');
}

/** Close forced modal */
function closeForcedModal() {
  document.getElementById('modalForcedUninstall')?.classList.add('hidden');
}

/** Set scanning mode for forced uninstallation */
function setForcedMode(mode) {
  selectedForcedScanMode = mode;
  ['safe', 'moderate', 'advanced'].forEach(m => {
    const card = document.getElementById(`forcedMode${m.charAt(0).toUpperCase() + m.slice(1)}`);
    if (card) card.classList.toggle('active', m === mode);
  });
}

/** Execute forced uninstall scan */
async function executeForcedScan() {
  const input = document.getElementById('forcedTargetInput');
  const target = (input ? input.value : '').trim();

  if (!target) {
    showToast("הסרה כפויה", "הזן שם תוכנה או נתיב לקובץ / תיקייה.");
    return;
  }

  const btn = document.getElementById('btnRunForced');
  if (btn) btn.disabled = true;

  showToast("הסרה כפויה", `מבצע סריקה עמוקה עבור: ${target}...`);

  // A deep forced scan can take a while and is also a single blocking POST, so
  // open the wizard's terminal first and stream the engine's log into it.
  closeForcedModal();
  wizardClosedByUser = false;
  startWizardLiveOutput(`סורק שאריות עבור ${target}…`);
  document.getElementById('wizardStep1Content')?.classList.add('hidden');
  document.getElementById('wizardStep2Content')?.classList.remove('hidden');
  document.getElementById('wizardStep3Content')?.classList.add('hidden');
  document.getElementById('wizardStep4Content')?.classList.add('hidden');
  document.getElementById('btnWizardPreviewScan')?.classList.add('hidden');
  document.getElementById('btnWizardStartNoRp')?.classList.add('hidden');
  document.getElementById('btnWizardStartNormal')?.classList.add('hidden');
  document.getElementById('btnWizardDeleteSelected')?.classList.add('hidden');
  document.getElementById('btnWizardFinish')?.classList.add('hidden');
  document.getElementById('btnWizardCancel')?.classList.remove('hidden');
  const forcedTitle = document.getElementById('wizardAppTitle');
  if (forcedTitle) forcedTitle.textContent = `הסרה כפויה: ${target}`;
  const forcedSub = document.getElementById('wizardAppSub');
  if (forcedSub) forcedSub.textContent = `סריקה מבוססת דפוסים (${selectedForcedScanMode})`;
  const forcedStage = document.getElementById('wizardCurrentStageText');
  if (forcedStage) forcedStage.textContent = 'סורק שאריות במערכת…';
  const forcedDetails = document.getElementById('wizardStatusDetails');
  if (forcedDetails) forcedDetails.textContent = 'מאתר מפתחות רישום, תיקיות וקיצורי דרך שנשארו.';
  // Without this the bar keeps the previous run's width and, after a failed
  // run, its red colour.
  const forcedBar = document.getElementById('wizardProgressBar');
  if (forcedBar) {
    forcedBar.style.width = '0%';
    forcedBar.style.backgroundColor = '';
  }
  const forcedPct = document.getElementById('wizardProgressPercent');
  if (forcedPct) forcedPct.textContent = '0%';
  document.getElementById('modalUninstallWizard')?.classList.remove('hidden');

  const logPump = setInterval(pumpUninstallLog, 600);

  try {
    const res = await fetch('/api/uninstaller/forced', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: target,
        mode: selectedForcedScanMode
      })
    });
    const data = await res.json();
    clearInterval(logPump);
    await pumpUninstallLog();
    stopWizardClock();

    // The user closed the wizard while this was in flight; do not drag it back.
    if (wizardClosedByUser) return;

    if (data.success) {

      // Directly open wizard Step 3 with leftovers
      activeUninstallApp = data.app_metadata || { name: target };
      currentWizardLeftovers = data.leftovers || { registry: [], files: [] };

      const titleEl = document.getElementById('wizardAppTitle');
      const subEl = document.getElementById('wizardAppSub');
      if (titleEl) titleEl.textContent = `הסרה כפויה: ${target}`;
      if (subEl) subEl.textContent = `סריקה מבוססת דפוסים (${selectedForcedScanMode})`;

      document.getElementById('wizardStep1Content')?.classList.add('hidden');
      document.getElementById('wizardStep2Content')?.classList.add('hidden');
      document.getElementById('wizardStep3Content')?.classList.remove('hidden');
      document.getElementById('wizardStep4Content')?.classList.add('hidden');

      document.getElementById('btnWizardCancel')?.classList.remove('hidden');
      document.getElementById('btnWizardStartNoRp')?.classList.add('hidden');
      document.getElementById('btnWizardStartNormal')?.classList.add('hidden');
      document.getElementById('btnWizardFinish')?.classList.add('hidden');

      // This is the second entry point into step 3, so it has to clear the same
      // leftover state openUninstallWizard does - otherwise a forced scan that
      // follows a completed cleanup arrives with a disabled delete button.
      const btnDel = document.getElementById('btnWizardDeleteSelected');
      if (btnDel) {
        btnDel.classList.remove('hidden');
        btnDel.disabled = false;
      }
      const bar = document.getElementById('wizardProgressBar');
      if (bar) bar.style.backgroundColor = '';
      document.getElementById('wizardRebootNotice')?.classList.add('hidden');
      const doneDesc = document.getElementById('wizardDoneDesc');
      if (doneDesc) doneDesc.textContent = 'כל השאריות הנבחרות הוסרו מהמערכת.';

      renderLeftoversView();
      document.getElementById('modalUninstallWizard')?.classList.remove('hidden');
    } else {
      // Leave the terminal on screen: it holds the reason the scan failed.
      const details = document.getElementById('wizardStatusDetails');
      if (details) details.textContent = data.error || "נכשלה הסריקה הכפויה";
      showToast("שגיאה", data.error || "נכשלה הסריקה הכפויה", "danger");
    }
  } catch (err) {
    showToast("שגיאה", err.message, "danger");
  } finally {
    clearInterval(logPump);
    stopWizardClock();
    if (btn) btn.disabled = false;
  }
}

// -------------------------------------------------------------------------
// Hunter Mode Modal Flow
// -------------------------------------------------------------------------

/** Open hunter mode modal */
function openHunterModal() {
  currentHunterResolved = null;
  const input = document.getElementById('hunterTargetInput');
  if (input) input.value = '';
  document.getElementById('hunterTargetCard')?.classList.add('hidden');
  document.getElementById('modalHunterMode')?.classList.remove('hidden');
}

/** Close hunter mode modal */
function closeHunterModal() {
  document.getElementById('modalHunterMode')?.classList.add('hidden');
}

/** Resolve hunter target */
async function resolveHunterTargetAction() {
  const input = document.getElementById('hunterTargetInput');
  const target = (input ? input.value : '').trim();

  if (!target) {
    showToast("מיקוד ידני", "הזן שם תהליך, נתיב או PID.");
    return;
  }

  try {
    const res = await fetch('/api/uninstaller/hunter_resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: target })
    });
    const data = await res.json();

    if (data.success) {
      currentHunterResolved = data;

      document.getElementById('hunterTargetName').textContent = data.process_name || data.query || target;
      document.getElementById('hunterTargetPath').textContent = data.exe_path || 'נתיב לא זמין';
      document.getElementById('hunterTargetPid').textContent = `PID: ${data.pid || '--'}`;
      document.getElementById('hunterTargetMemory').textContent = data.memory_mb ? ltrIsolate(`${data.memory_mb} MB`, true) : '--';
      document.getElementById('hunterTargetPublisher').textContent = (data.matched_app && data.matched_app.publisher) ? data.matched_app.publisher : 'ללא חתימה';

      document.getElementById('hunterTargetCard')?.classList.remove('hidden');
      showToast("מטרה זוהתה", `${data.process_name || target} מוכן לפעולה.`);
    } else {
      showToast("מיקוד ידני", data.error || "לא נמצאה התאמה לתהליך או לתוכנה");
    }
  } catch (err) {
    showToast("שגיאה", err.message);
  }
}

/** Execute hunter action on target */
async function executeHunterActionBtn(action) {
  if (!currentHunterResolved) {
    const input = document.getElementById('hunterTargetInput');
    const target = (input ? input.value : '').trim();
    if (!target) {
      showToast("מיקוד ידני", "זהה מטרה תחילה.");
      return;
    }
    await resolveHunterTargetAction();
    if (!currentHunterResolved) return;
  }

  if (action === 'forced_uninstall') {
    closeHunterModal();
    openForcedUninstallModal(
      currentHunterResolved.matched_app ? currentHunterResolved.matched_app.name : currentHunterResolved.process_name,
      currentHunterResolved.exe_path
    );
    return;
  }

  try {
    const res = await fetch('/api/uninstaller/hunter_action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: action,
        target_path: currentHunterResolved.exe_path,
        pid: currentHunterResolved.pid
      })
    });
    const data = await res.json();

    if (data.success) {
      showToast("מיקוד ידני", data.message || "הפעולה בוצעה בהצלחה.");
      closeHunterModal();
      fetchProcesses();
      fetchInstalledApps(true);
    } else {
      showToast("מיקוד ידני", data.error || "הפעולה נכשלה");
    }
  } catch (err) {
    showToast("שגיאה", err.message);
  }
}

// -------------------------------------------------------------------------
// Backup Center Modal Flow
// -------------------------------------------------------------------------

/** Open backup center modal and fetch history */
function openBackupCenterModal() {
  document.getElementById('modalBackupCenter')?.classList.remove('hidden');
  fetchBackupHistory();
}

/** Close backup center modal */
function closeBackupCenterModal() {
  document.getElementById('modalBackupCenter')?.classList.add('hidden');
}

/** Open Terms of Use & EULA modal */
function openTermsModal() {
  document.getElementById('modalTerms')?.classList.remove('hidden');
}

/** Close Terms of Use & EULA modal */
function closeTermsModal() {
  document.getElementById('modalTerms')?.classList.add('hidden');
}

// Attach to window so buttons work inline
window.openTermsModal = openTermsModal;
window.closeTermsModal = closeTermsModal;

/** Fetch backups list from backend */
async function fetchBackupHistory() {
  const tbody = document.getElementById('backupHistoryTbody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/uninstaller/backups');
    const data = await res.json();
    const backups = data.backups || [];

    if (!backups.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty" style="text-align: center; padding: 30px; color: var(--text-dim);">אין גיבויים קודמים במערכת. גיבויים נוצרים אוטומטית לפני כל הסרה.</td></tr>`;
      return;
    }

    const rows = backups.map(b => {
      const regCount = (b.registry_backups || []).length;
      const offlineBadge = b.has_restore_script
        ? `<span class="badge badge-ok">Restore.bat זמין</span>`
        : `<span class="faint mono">--</span>`;

      return `
        <tr class="trow">
          <td class="mono" style="font-size: 11.5px;">${esc(b.date_str || b.session_id)}</td>
          <td style="font-weight: 650;">${esc(b.app_name || '--')}</td>
          <td><span class="mono">${regCount} קבצי .reg</span></td>
          <td>${offlineBadge}</td>
          <td class="act">
            <button class="btn btn-sm btn-primary" onclick="restoreBackupSession('${esc(b.session_id)}')">
              שחזר עכשיו
            </button>
          </td>
        </tr>
      `;
    }).join('');

    tbody.innerHTML = rows;

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="panel-text tone-danger" style="text-align: center; padding: 20px;">שגיאה: ${esc(err.message)}</td></tr>`;
  }
}

/** Restore a backup session */
async function restoreBackupSession(sessionId) {
  if (!confirm(`האם אתה בטוח שברצונך לשחזר את גיבוי ה-Registry של הפעלה זו?`)) return;

  showToast("שחזור גיבוי", "מייבא מפתחות רישום מקוריים ל-Windows...", "accent");

  try {
    const res = await fetch('/api/uninstaller/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId })
    });
    const data = await res.json();

    if (data.success) {
      showToast("השחזור הושלם בהצלחה", data.message || "מפתחות הרישום שוחזרו בהצלחה.");
      fetchBackupHistory();
      fetchInstalledApps(true);
    } else {
      showToast("שגיאה בשחזור", data.error || "נכשל שחזור הגיבוי", "danger");
    }
  } catch (err) {
    showToast("שגיאה", err.message);
  }
}

// =========================================================================
// STORAGE ANALYZER & WINDIRSTAT ENGINE
// =========================================================================

let storageDrives = [];
let selectedStorageDrive = "";
let storageScanPollTimer = null;
let currentStorageScanStatus = "idle";
let storageTreeData = null;
let storageTreemapData = null;
let storageSunburstData = null;
let currentSunburstNode = null;
let sunburstVisibleSlices = [];
let sunburstBreadcrumbs = [];
let collectorItems = new Map();
let storageExtensions = [];
let storageTopFiles = [];
let activeStorageTab = "sunburst";
let currentTreemapRootId = null;
let treemapBreadcrumbs = [];
let activeExtFilter = null;
let treemapStyle = "cushion";
let selectedNodeId = null;
let contextTargetNode = null;
let treemapVisibleRects = [];

async function initStorageScreen() {
  await fetchStorageDrives();
  initStorageCanvas();
  initSunburstCanvas();
  checkStorageProgressStatus();
}

async function fetchStorageDrives() {
  try {
    const res = await fetch('/api/storage/drives');
    const data = await res.json();
    storageDrives = data.drives || [];

    renderStorageDiskCards(storageDrives);

    const select = document.getElementById('storageDriveSelect');
    if (select) {
      if (storageDrives.length === 0) {
        select.innerHTML = '<option value="">לא נמצאו כוננים</option>';
      } else {
        select.innerHTML = storageDrives.map(d => {
          const freeStr = formatBytesJS(d.free_bytes);
          const totalStr = formatBytesJS(d.total_bytes);
          return `<option value="${esc(d.path)}">${esc(d.letter)} [${esc(d.label)}] (${freeStr} פנוי מתוך ${totalStr})</option>`;
        }).join('');
      }
    }

    if (!selectedStorageDrive && storageDrives.length > 0) {
      selectedStorageDrive = storageDrives[0].path;
    }
  } catch (err) {
    console.error("fetchStorageDrives error:", err);
  }
}

function refreshStorageDrives() {
  fetchStorageDrives();
}

function renderStorageDiskCards(drives) {
  const container = document.getElementById('storageDiskCardsGrid');
  if (!container) return;

  if (!drives || drives.length === 0) {
    container.innerHTML = `<div class="text-muted text-center" style="padding: 20px;">לא נמצאו כוננים</div>`;
    return;
  }

  container.innerHTML = drives.map((d, index) => {
    const isRemovable = d.is_removable;
    const pct = d.percent_used || 0;
    const meterClass = pct >= 90 ? 'danger' : (pct >= 75 ? 'warn' : '');
    const freeStr = formatBytesJS(d.free_bytes);
    const totalStr = formatBytesJS(d.total_bytes);

    return `
      <div class="disk-card" onclick="selectAndScanDriveByIndex(${index})">
        <div class="disk-card-head">
          <div class="disk-card-icon">
            ${isRemovable ? `
              <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width: 22px; height: 22px;">
                <path stroke-linecap="round" stroke-linejoin="round" d="M8 9l4-4 4 4m0 6l-4 4-4-4"/>
                <circle cx="12" cy="12" r="2"/>
              </svg>
            ` : `
              <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width: 22px; height: 22px;">
                <path stroke-linecap="round" stroke-linejoin="round" d="M4 7a8 4 0 1016 0A8 4 0 004 7zm0 0v10a8 4 0 0016 0V7M4 12a8 4 0 0016 0"/>
              </svg>
            `}
          </div>
          <div class="grow">
            <div class="disk-card-title row" style="gap: 6px; align-items: center;">
              <span>${esc(d.letter)} [${esc(d.label)}]</span>
              ${isRemovable ? '<span class="badge" style="font-size: 10px;">USB</span>' : ''}
            </div>
            <div class="disk-card-sub">${esc(d.fs_type || 'NTFS')} &middot; ${d.type || 'Fixed'}</div>
          </div>
        </div>

        <div class="disk-card-meter">
          <div class="disk-card-meter-fill ${meterClass}" style="width: ${pct}%;"></div>
        </div>

        <div class="disk-card-foot">
          <span>${freeStr} פנוי מתוך ${totalStr}</span>
          <strong>${pct}%</strong>
        </div>
      </div>
    `;
  }).join('');
}

function selectAndScanDriveByIndex(index) {
  if (!storageDrives || !storageDrives[index]) return;
  const drive = storageDrives[index];
  selectAndScanDrive(drive.path);
}

function selectAndScanDrive(drivePath) {
  const selView = document.getElementById('storageDiskSelectionView');
  const detView = document.getElementById('storageDetailView');
  if (selView) selView.classList.add('hidden');
  if (detView) detView.classList.remove('hidden');

  const lbl = document.getElementById('storageCurrentTargetLabel');
  if (lbl) lbl.textContent = drivePath;
  selectedStorageDrive = drivePath;

  // Clear previous scan data so stale views are not shown
  storageSunburstData = null;
  currentSunburstNode = null;
  storageTreeData = null;
  sunburstBreadcrumbs = [];
  renderSunburstBreadcrumbs();
  renderStorageSunburst();
  renderStorageFileList();

  showStorageScanningOverlay(drivePath);
  startStorageScan([drivePath]);
}

function returnToDiskSelection() {
  const selView = document.getElementById('storageDiskSelectionView');
  const detView = document.getElementById('storageDetailView');
  if (selView) selView.classList.remove('hidden');
  if (detView) detView.classList.add('hidden');
  hideStorageScanningOverlay();
  fetchStorageDrives();
}

function startStorageCustomScan() {
  const input = document.getElementById('storageCustomFolderInput');
  const path = input ? input.value.trim() : '';
  if (!path) {
    showToast("בחירת תיקייה", "הזן נתיב תיקייה לסריקה", "warn");
    return;
  }
  selectAndScanDrive(path);
}

function onStorageDriveChanged() {
  const select = document.getElementById('storageDriveSelect');
  if (select) {
    selectedStorageDrive = select.value;
  }
}

// -------------------------------------------------------------
// Scan Controls & Polling
// -------------------------------------------------------------
function showStorageScanningOverlay(targetPath) {
  const overlay = document.getElementById('storageScanningOverlay');
  if (!overlay) return;
  overlay.classList.remove('hidden');

  const title = document.getElementById('scanOverlayTitle');
  if (title) title.textContent = `סורק את ${targetPath || 'הכונן'}...`;

  const bar = document.getElementById('scanOverlayBar');
  if (bar) bar.style.width = '0%';

  const stats = document.getElementById('scanOverlayStats');
  if (stats) stats.textContent = 'מתחיל סריקה...';

  const pathEl = document.getElementById('scanOverlayPath');
  if (pathEl) pathEl.textContent = targetPath || '';
}

function hideStorageScanningOverlay() {
  const overlay = document.getElementById('storageScanningOverlay');
  if (overlay) overlay.classList.add('hidden');
}

async function startStorageScan(customTargets) {
  let targets = [];
  if (Array.isArray(customTargets) && customTargets.length > 0) {
    targets = customTargets;
  } else if (typeof customTargets === 'string' && customTargets.trim()) {
    targets = [customTargets.trim()];
  } else if (selectedStorageDrive) {
    targets = [selectedStorageDrive];
  } else {
    const select = document.getElementById('storageDriveSelect');
    if (select && select.value) targets = [select.value];
  }

  if (!targets || targets.length === 0) {
    showToast("בחירת כונן", "בחר כונן לסריקה", "danger");
    return;
  }

  const targetPath = targets[0];
  showStorageScanningOverlay(targetPath);

  try {
    const res = await fetch('/api/storage/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targets: targets })
    });
    const data = await res.json();

    if (data.success) {
      showToast("הסריקה החלה", `סורק את ${targetPath}...`, "accent");
      setStorageScanUiState("scanning");
      startStoragePolling();
    } else {
      hideStorageScanningOverlay();
      showToast("שגיאה בהפעלת סריקה", data.message || "נכשלה הפעלת הסריקה", "danger");
    }
  } catch (err) {
    hideStorageScanningOverlay();
    showToast("שגיאת תקשורת", err.message, "danger");
  }
}

async function toggleStoragePause() {
  const isPaused = currentStorageScanStatus === 'paused';
  const endpoint = isPaused ? '/api/storage/resume' : '/api/storage/pause';

  // Optimistically toggle UI state for instant responsiveness
  setStorageScanUiState(isPaused ? "scanning" : "paused");

  try {
    const res = await fetch(endpoint, { method: 'POST' });
    const data = await res.json();
    if (!data.success) {
      // Revert if request unsuccessful
      setStorageScanUiState(isPaused ? "paused" : "scanning");
    }
  } catch (err) {
    console.error("pause/resume error:", err);
    setStorageScanUiState(isPaused ? "paused" : "scanning");
  }
}

async function cancelStorageScan() {
  stopStoragePolling();
  setStorageScanUiState("cancelled");
  hideStorageScanningOverlay();
  showToast("סריקה בוטלה", "הסריקה הופסקה על ידי המשתמש", "warn");

  try {
    await fetch('/api/storage/cancel', { method: 'POST' });
  } catch (err) {
    console.error("cancel error:", err);
  }
}

function startStoragePolling() {
  if (storageScanPollTimer) clearInterval(storageScanPollTimer);
  storageScanPollTimer = setInterval(pollStorageProgress, 350);
}

function stopStoragePolling() {
  if (storageScanPollTimer) {
    clearInterval(storageScanPollTimer);
    storageScanPollTimer = null;
  }
}

async function checkStorageProgressStatus() {
  try {
    const res = await fetch('/api/storage/progress');
    const data = await res.json();
    updateStorageProgressUi(data);
    if (data.status === 'scanning' || data.status === 'paused') {
      setStorageScanUiState(data.status);
      if (data.targets && data.targets[0]) {
        showStorageScanningOverlay(data.targets[0]);
      }
      startStoragePolling();
    } else if (data.status === 'completed' && !storageTreeData) {
      hideStorageScanningOverlay();
      loadStorageResults();
    }
  } catch (err) {
    console.error("checkStorageProgressStatus error:", err);
  }
}

async function pollStorageProgress() {
  try {
    const res = await fetch('/api/storage/progress');
    const data = await res.json();
    updateStorageProgressUi(data);

    if (data.status === 'completed') {
      stopStoragePolling();
      setStorageScanUiState("completed");
      hideStorageScanningOverlay();
      showToast("הסריקה הושלמה", `נסרקו ${(data.files_scanned || 0).toLocaleString()} קבצים ב-${data.total_bytes_formatted}`, "accent");
      if (data.access_denied_count > 0) {
        showToast("הרשאות חסרות",
                   `${data.access_denied_count.toLocaleString()} תיקיות/פריטים לא נקראו עקב חוסר הרשאה — הרץ כמנהל לתמונה מלאה.`,
                   "warn");
      }
      await loadStorageResults();
    } else if (data.status === 'error') {
      stopStoragePolling();
      setStorageScanUiState("error");
      hideStorageScanningOverlay();
      showToast("שגיאה בסריקה", data.error_message || "אירעה שגיאה", "danger");
    } else if (data.status === 'cancelled') {
      stopStoragePolling();
      setStorageScanUiState("cancelled");
      hideStorageScanningOverlay();
    } else if (data.status === 'paused') {
      if (currentStorageScanStatus !== 'paused') {
        setStorageScanUiState("paused");
      }
    } else if (data.status === 'scanning') {
      if (currentStorageScanStatus !== 'scanning') {
        setStorageScanUiState("scanning");
      }
    }
  } catch (err) {
    console.error("pollStorageProgress error:", err);
  }
}

function setStorageScanUiState(status) {
  currentStorageScanStatus = status;
  const badge = document.getElementById('storageStatusBadge');
  const btnScan = document.getElementById('btnStorageScan');
  const btnPause = document.getElementById('btnStoragePause');
  const btnCancel = document.getElementById('btnStorageCancel');
  const txtPause = document.getElementById('txtBtnStoragePause');
  const pacmanLane = document.getElementById('pacmanLane');

  // Overlay controls
  const btnOverlayPause = document.getElementById('btnOverlayPause');
  const txtOverlayPause = document.getElementById('txtOverlayPause');

  if (status === 'scanning') {
    if (badge) { badge.textContent = t('storageScanning'); badge.className = 'badge badge-accent'; }
    if (btnScan) btnScan.classList.add('hidden');
    if (btnPause) btnPause.classList.remove('hidden');
    if (btnCancel) btnCancel.classList.remove('hidden');
    if (txtPause) txtPause.textContent = '⏸️ השהה';
    if (txtOverlayPause) txtOverlayPause.textContent = '⏸️ השהה סריקה';
    if (pacmanLane) pacmanLane.classList.remove('hidden');
  } else if (status === 'paused') {
    if (badge) { badge.textContent = t('storagePaused'); badge.className = 'badge badge-warn'; }
    if (btnScan) btnScan.classList.add('hidden');
    if (btnPause) btnPause.classList.remove('hidden');
    if (btnCancel) btnCancel.classList.remove('hidden');
    if (txtPause) txtPause.textContent = '▶ המשך';
    if (txtOverlayPause) txtOverlayPause.textContent = '▶ המשך סריקה';
    if (pacmanLane) pacmanLane.classList.remove('hidden');
  } else if (status === 'completed') {
    if (badge) { badge.textContent = t('storageCompleted'); badge.className = 'badge badge-good'; }
    if (btnScan) btnScan.classList.remove('hidden');
    if (btnPause) btnPause.classList.add('hidden');
    if (btnCancel) btnCancel.classList.add('hidden');
    if (pacmanLane) pacmanLane.classList.add('hidden');
  } else {
    // idle / cancelled / error
    if (badge) { badge.textContent = t('storageIdle'); badge.className = 'badge'; }
    if (btnScan) btnScan.classList.remove('hidden');
    if (btnPause) btnPause.classList.add('hidden');
    if (btnCancel) btnCancel.classList.add('hidden');
    if (pacmanLane) pacmanLane.classList.add('hidden');
  }
}

function updateStorageProgressUi(data) {
  const elFiles = document.getElementById('storagePillFiles');
  const elFolders = document.getElementById('storagePillFolders');
  const elSize = document.getElementById('storagePillSize');
  const elRate = document.getElementById('storagePillRate');
  const elTime = document.getElementById('storagePillTime');
  const elPath = document.getElementById('pacmanCurrentPath');

  // While a scan is running, files_scanned/folders_scanned only get their
  // real values once at the very end (from the finished, pruned tree) - the
  // native pdu engine reports a single running total in the meantime
  // (items_seen), so that is what's live during scanning. Once completed,
  // items_seen holds the same total the tree reports, so this never has to
  // jump between two different sources.
  if (elFiles) {
    const liveTotal = data.status === 'scanning' ? (data.items_seen || 0) : (data.files_scanned || 0);
    elFiles.textContent = liveTotal.toLocaleString();
  }
  if (elFolders) elFolders.textContent = (data.folders_scanned || 0).toLocaleString();
  if (elSize) elSize.textContent = data.total_bytes_formatted || "0 B";
  if (elRate) elRate.textContent = `${(data.scan_rate || 0).toLocaleString()} קבצים/שנ'`;
  if (elTime) {
    const sec = Math.floor(data.elapsed_seconds || 0);
    const m = String(Math.floor(sec / 60)).padStart(2, '0');
    const s = String(sec % 60).padStart(2, '0');
    elTime.textContent = `${m}:${s}`;
  }
  if (elPath && data.current_path) {
    elPath.textContent = data.current_path;
    elPath.title = data.current_path;
  }

  // Update SquirrelDisk scanning overlay if active
  const overlayBar = document.getElementById('scanOverlayBar');
  const overlayStats = document.getElementById('scanOverlayStats');
  const overlayPath = document.getElementById('scanOverlayPath');
  const overlayTitle = document.getElementById('scanOverlayTitle');

  if (overlayPath && data.current_path) {
    overlayPath.textContent = data.current_path;
    overlayPath.title = data.current_path;
  }

  // Volume Bar Breakdown & Progress % Calculation (SquirrelDisk Parity)
  const vol = data.volume_info;
  if (vol && vol.total_bytes > 0) {
    const scanned = vol.scanned_bytes || data.total_bytes_scanned || 0;
    const free = vol.free_bytes || 0;
    const unknown = vol.unknown_bytes || 0;
    const total = vol.total_bytes;
    const used = vol.used_bytes || Math.max(1, total - free);

    // SquirrelDisk parity: Scan progress % is calculated relative to USED drive space!
    const pctScannedOfUsed = Math.min(100, (scanned / used) * 100);
    const pctDriveScanned = Math.min(100, (scanned / total) * 100);
    const pctDriveUnknown = Math.min(100, (unknown / total) * 100);
    const pctDriveFree = Math.max(0, 100 - pctDriveScanned - pctDriveUnknown);

    if (overlayBar) overlayBar.style.width = `${pctScannedOfUsed.toFixed(1)}%`;
    if (overlayTitle && data.targets && data.targets[0]) {
      overlayTitle.textContent = `סורק את ${data.targets[0]} (${pctScannedOfUsed.toFixed(1)}%)...`;
    }

    if (overlayStats) {
      const fCount = (data.status === 'scanning' ? (data.items_seen || 0) : (data.files_scanned || 0)).toLocaleString();
      const dCount = (data.folders_scanned || 0).toLocaleString();
      const bytesStr = data.total_bytes_formatted || "0 B";
      const usedStr = vol.used_formatted || formatBytesJS(used);
      const rateStr = `${(data.scan_rate || 0).toLocaleString()} קבצים/שנ'`;
      overlayStats.textContent = `${fCount} קבצים · ${dCount} תיקיות · נסרקו ${bytesStr} מתוך ${usedStr} · ${rateStr}`;
    }

    const segScanned = document.getElementById('segScanned');
    const segUnknown = document.getElementById('segUnknown');
    const segFree = document.getElementById('segFree');

    if (segScanned) segScanned.style.width = `${pctDriveScanned.toFixed(1)}%`;
    if (segUnknown) segUnknown.style.width = `${pctDriveUnknown.toFixed(1)}%`;
    if (segFree) segFree.style.width = `${pctDriveFree.toFixed(1)}%`;

    const legScanned = document.getElementById('storageLegScanned');
    const legFree = document.getElementById('storageLegFree');
    const legUnknown = document.getElementById('storageLegUnknown');
    const legTotal = document.getElementById('storageLegTotal');

    if (legScanned) legScanned.textContent = `${vol.scanned_formatted || formatBytesJS(scanned)} (${pctScannedOfUsed.toFixed(1)}% מהנפח התפוס)`;
    if (legFree) legFree.textContent = `${vol.free_formatted || formatBytesJS(free)} (${(free / total * 100).toFixed(1)}%)`;
    if (legUnknown) legUnknown.textContent = `${vol.unknown_formatted || formatBytesJS(unknown)} (${(unknown / total * 100).toFixed(1)}%)`;
    if (legTotal) legTotal.textContent = vol.total_formatted || formatBytesJS(total);
  }
}

// -------------------------------------------------------------
// Loading & Rendering Scan Results
// -------------------------------------------------------------
async function loadStorageResults() {
  try {
    const [treeRes, treemapRes, extsRes, topRes, sunburstRes] = await Promise.all([
      fetch('/api/storage/tree?depth=2'),
      fetch('/api/storage/treemap?depth=6'),
      fetch('/api/storage/extensions'),
      fetch('/api/storage/top_files?limit=100'),
      fetch('/api/storage/sunburst?depth=4')
    ]);

    const treeData = await treeRes.json();
    const treemapData = await treemapRes.json();
    const extsData = await extsRes.json();
    const topData = await topRes.json();
    const sunburstData = await sunburstRes.json();

    storageTreeData = treeData.tree;
    storageTreemapData = treemapData.treemap;
    storageExtensions = extsData.extensions || [];
    storageTopFiles = topData.files || [];
    storageSunburstData = sunburstData.sunburst;
    currentSunburstNode = storageSunburstData;

    currentTreemapRootId = null;
    treemapBreadcrumbs = storageTreemapData ? [{ id: storageTreemapData.id, name: storageTreemapData.name }] : [];
    sunburstBreadcrumbs = storageSunburstData ? [{ id: storageSunburstData.id, name: storageSunburstData.name, node: storageSunburstData }] : [];

    renderSunburstBreadcrumbs();
    renderStorageSunburst();
    renderStorageFileList();

    renderStorageTree();
    renderStorageExtensions();
    renderStorageBreadcrumbs();
    renderStorageTreemap();
    renderStorageTopFiles();
  } catch (err) {
    console.error("loadStorageResults error:", err);
  }
}

// -------------------------------------------------------------
// SquirrelDisk Sunburst Canvas Engine & Deletion Collector
// -------------------------------------------------------------
let sunburstCanvas = null;
let sunburstCtx = null;
let hoveredSunburstSlice = null;

function initSunburstCanvas() {
  sunburstCanvas = document.getElementById('storageSunburstCanvas');
  if (!sunburstCanvas) return;
  sunburstCtx = sunburstCanvas.getContext('2d');

  resizeSunburstCanvas();
  window.addEventListener('resize', debounceSunburstResize);

  sunburstCanvas.onmousemove = handleSunburstMouseMove;
  sunburstCanvas.onmouseleave = handleSunburstMouseLeave;
  sunburstCanvas.onclick = handleSunburstClick;
  sunburstCanvas.oncontextmenu = handleSunburstContextMenu;
}

function debounceSunburstResize() {
  if (currentScreen === 'storage' && activeStorageTab === 'sunburst') {
    resizeSunburstCanvas();
    renderStorageSunburst();
  }
}

function resizeSunburstCanvas() {
  if (!sunburstCanvas) return;
  const wrap = document.getElementById('sunburstCanvasWrap');
  if (!wrap) return;
  const rect = wrap.getBoundingClientRect();
  const side = Math.max(340, Math.min(Math.floor(rect.width - 24), Math.floor(rect.height - 24), 540));
  if (sunburstCanvas.width !== side || sunburstCanvas.height !== side) {
    sunburstCanvas.width = side;
    sunburstCanvas.height = side;
  }
}

function redrawSunburstChart() {
  resizeSunburstCanvas();
  renderStorageSunburst();
}

function lightenColor(color, percent) {
  if (!color) return '#3498db';
  if (color.startsWith('hsl')) {
    return color.replace(/(\d+)%\)/, (m, l) => `${Math.min(100, parseInt(l, 10) + percent)}%)`);
  }
  if (typeof hexToRgb === 'function') {
    const { r, g, b } = hexToRgb(color);
    const factor = percent / 100;
    const newR = Math.min(255, Math.floor(r + (255 - r) * factor));
    const newG = Math.min(255, Math.floor(g + (255 - g) * factor));
    const newB = Math.min(255, Math.floor(b + (255 - b) * factor));
    return `rgb(${newR}, ${newG}, ${newB})`;
  }
  return color;
}

function renderStorageSunburst() {
  if (!sunburstCanvas) initSunburstCanvas();
  if (!sunburstCanvas || !sunburstCtx) return;

  const w = sunburstCanvas.width;
  const h = sunburstCanvas.height;
  const cx = w / 2;
  const cy = h / 2;
  const maxRadius = Math.min(w, h) / 2 - 12;
  const innerRadius = Math.max(54, Math.floor(maxRadius * 0.28));

  sunburstCtx.clearRect(0, 0, w, h);
  sunburstVisibleSlices = [];

  const centerName = document.getElementById('sunburstCenterName');
  const centerSize = document.getElementById('sunburstCenterSize');
  const centerHint = document.getElementById('sunburstCenterHint');

  if (!currentSunburstNode) {
    if (centerName) centerName.textContent = t('storageNoScanYet');
    if (centerSize) centerSize.textContent = "0 B";
    if (centerHint) centerHint.textContent = "";
    return;
  }

  // Restore center label to current node
  if (centerName) centerName.textContent = currentSunburstNode.name || (selectedStorageDrive || "Root");
  if (centerSize) centerSize.textContent = currentSunburstNode.size_formatted || formatBytesJS(currentSunburstNode.size);
  if (centerHint) {
    centerHint.textContent = sunburstBreadcrumbs.length > 1 ? "⬆ לחץ לחזרה רמה למעלה" : "בחר תיקייה לצלילה";
  }

  // Center Circle
  sunburstCtx.beginPath();
  sunburstCtx.arc(cx, cy, innerRadius - 2, 0, Math.PI * 2);
  sunburstCtx.fillStyle = 'rgba(255, 255, 255, 0.04)';
  sunburstCtx.fill();
  sunburstCtx.lineWidth = 1.5;
  sunburstCtx.strokeStyle = 'rgba(255, 255, 255, 0.12)';
  sunburstCtx.stroke();

  // Layout Rings
  const maxDepth = 4;
  const ringStep = (maxRadius - innerRadius) / maxDepth;

  function walk(node, depth, a0, a1) {
    if (!node.children || node.children.length === 0 || depth > maxDepth) return;

    const angleSpan = a1 - a0;
    if (angleSpan <= 0.002) return;

    const children = node.children;
    const levelTotal = children.reduce((sum, c) => sum + (c.value || c.size || 0), 0);
    if (levelTotal <= 0) return;

    let currentA = a0;
    const r0 = innerRadius + (depth - 1) * ringStep;
    const r1 = r0 + ringStep;

    for (const child of children) {
      const childVal = child.value || child.size || 0;
      if (childVal <= 0) continue;

      const childSpan = (childVal / levelTotal) * angleSpan;
      const childA0 = currentA;
      const childA1 = currentA + childSpan;
      currentA = childA1;

      if (childSpan < 0.003) continue;

      const pad = Math.min(childSpan / 2, 0.007);
      const drawA0 = childA0 + pad;
      const drawA1 = childA1 - pad;

      const isHovered = hoveredSunburstSlice && hoveredSunburstSlice.node && hoveredSunburstSlice.node.id === child.id;
      const fill = isHovered ? lightenColor(child.color, 20) : child.color;

      sunburstCtx.beginPath();
      sunburstCtx.arc(cx, cy, r0 + 1.5, drawA0, drawA1, false);
      sunburstCtx.arc(cx, cy, r1 - 1.5, drawA1, drawA0, true);
      sunburstCtx.closePath();
      sunburstCtx.fillStyle = fill;
      sunburstCtx.fill();

      sunburstCtx.strokeStyle = isHovered ? 'rgba(255,255,255,0.85)' : 'rgba(0,0,0,0.3)';
      sunburstCtx.lineWidth = isHovered ? 2 : 1;
      sunburstCtx.stroke();

      sunburstVisibleSlices.push({
        node: child,
        depth: depth,
        r0: r0,
        r1: r1,
        drawA0: drawA0,
        drawA1: drawA1,
        rawA0: childA0,
        rawA1: childA1,
        color: child.color
      });

      if (child.is_dir && child.children && child.children.length > 0) {
        walk(child, depth + 1, childA0, childA1);
      }
    }
  }

  walk(currentSunburstNode, 1, -Math.PI / 2, 1.5 * Math.PI);
}

function findSunburstSliceAt(px, py) {
  if (!sunburstCanvas) return null;
  const w = sunburstCanvas.width;
  const h = sunburstCanvas.height;
  const cx = w / 2;
  const cy = h / 2;
  const maxRadius = Math.min(w, h) / 2 - 12;
  const innerRadius = Math.max(54, Math.floor(maxRadius * 0.28));

  const dx = px - cx;
  const dy = py - cy;
  const dist = Math.sqrt(dx * dx + dy * dy);

  if (dist <= innerRadius) {
    return { isCenter: true };
  }
  if (dist > maxRadius) {
    return null;
  }

  let angle = Math.atan2(dy, dx);
  // Normalize angle to [-PI/2, 1.5*PI)
  if (angle < -Math.PI / 2) {
    angle += Math.PI * 2;
  }

  // Search slices (outer rings first)
  for (let i = sunburstVisibleSlices.length - 1; i >= 0; i--) {
    const s = sunburstVisibleSlices[i];
    if (dist >= s.r0 && dist <= s.r1) {
      if (angle >= s.rawA0 && angle <= s.rawA1) {
        return s;
      }
    }
  }

  return null;
}

function getSunburstCanvasCoords(e) {
  if (!sunburstCanvas) return { px: 0, py: 0 };
  const rect = sunburstCanvas.getBoundingClientRect();
  const scaleX = rect.width ? (sunburstCanvas.width / rect.width) : 1;
  const scaleY = rect.height ? (sunburstCanvas.height / rect.height) : 1;
  return {
    px: (e.clientX - rect.left) * scaleX,
    py: (e.clientY - rect.top) * scaleY
  };
}

function handleSunburstMouseMove(e) {
  if (!sunburstCanvas) return;
  const { px, py } = getSunburstCanvasCoords(e);

  const hit = findSunburstSliceAt(px, py);
  const centerName = document.getElementById('sunburstCenterName');
  const centerSize = document.getElementById('sunburstCenterSize');
  const centerHint = document.getElementById('sunburstCenterHint');

  if (hit && hit.isCenter) {
    sunburstCanvas.style.cursor = sunburstBreadcrumbs.length > 1 ? 'pointer' : 'default';
    if (hoveredSunburstSlice !== null) {
      hoveredSunburstSlice = null;
      renderStorageSunburst();
    }
    if (centerName) centerName.textContent = currentSunburstNode.name || (selectedStorageDrive || "Root");
    if (centerSize) centerSize.textContent = currentSunburstNode.size_formatted || formatBytesJS(currentSunburstNode.size);
    if (centerHint) centerHint.textContent = sunburstBreadcrumbs.length > 1 ? "⬆ לחץ לחזרה רמה למעלה" : "";
    return;
  }

  if (hit && hit.node) {
    sunburstCanvas.style.cursor = hit.node.is_dir ? 'pointer' : 'default';
    const changed = !hoveredSunburstSlice || hoveredSunburstSlice.node.id !== hit.node.id;
    hoveredSunburstSlice = hit;

    if (centerName) centerName.textContent = hit.node.name;
    if (centerSize) centerSize.textContent = hit.node.size_formatted || formatBytesJS(hit.node.size);
    if (centerHint) {
      const rootSize = currentSunburstNode.size || 1;
      const pct = ((hit.node.size / rootSize) * 100).toFixed(1);
      const oneDriveTag = isOneDriveStoragePath(hit.node.path) ? " • ☁️ OneDrive" : "";
      centerHint.textContent = `${pct}% ${hit.node.is_dir ? "• לחץ לצלילה" : "• קובץ"}${oneDriveTag}`;
    }

    if (changed) {
      renderStorageSunburst();
    }
    return;
  }

  sunburstCanvas.style.cursor = 'default';
  if (hoveredSunburstSlice !== null) {
    hoveredSunburstSlice = null;
    renderStorageSunburst();
  }
}

function handleSunburstMouseLeave() {
  if (!sunburstCanvas) return;
  sunburstCanvas.style.cursor = 'default';
  if (hoveredSunburstSlice !== null) {
    hoveredSunburstSlice = null;
    renderStorageSunburst();
  }
}

function handleSunburstClick(e) {
  if (!sunburstCanvas) return;
  const { px, py } = getSunburstCanvasCoords(e);

  const hit = findSunburstSliceAt(px, py);
  if (!hit) return;

  if (hit.isCenter) {
    zoomSunburstUp();
    return;
  }

  if (hit.node) {
    if (hit.node.is_dir && hit.node.children && hit.node.children.length > 0) {
      zoomSunburstToNode(hit.node);
    } else if (!hit.node.is_aggregated && hit.node.path) {
      toggleCollectorItem(hit.node.id, hit.node.path, hit.node.name, hit.node.size);
    }
  }
}

function handleSunburstContextMenu(e) {
  if (!sunburstCanvas) return;
  e.preventDefault();
  const { px, py } = getSunburstCanvasCoords(e);

  const hit = findSunburstSliceAt(px, py);
  // Same synthetic-rollup guard as the treemap context menu - "<N Smaller
  // Items>" slices (id -1, is_aggregated) must never open a delete menu.
  if (hit && hit.node && hit.node.id !== -1 && !hit.node.is_aggregated && hit.node.path) {
    openStorageContextMenu(e, hit.node.id, hit.node.path);
  }
}

// -------------------------------------------------------------
// Sunburst Navigation & Breadcrumbs
// -------------------------------------------------------------
function zoomSunburstToNode(node) {
  if (!node || !node.is_dir) return;
  sunburstBreadcrumbs.push({ id: node.id, name: node.name, node: node });
  currentSunburstNode = node;
  hoveredSunburstSlice = null;
  renderSunburstBreadcrumbs();
  renderStorageSunburst();
  renderStorageFileList();
}

function zoomSunburstToNodeById(id) {
  const node = findSunburstNodeById(id);
  if (node && node.is_dir) {
    zoomSunburstToNode(node);
  }
}

function zoomSunburstUp() {
  if (sunburstBreadcrumbs.length > 1) {
    sunburstBreadcrumbs.pop();
    currentSunburstNode = sunburstBreadcrumbs[sunburstBreadcrumbs.length - 1].node;
    hoveredSunburstSlice = null;
    renderSunburstBreadcrumbs();
    renderStorageSunburst();
    renderStorageFileList();
  }
}

function zoomSunburstRoot() {
  currentSunburstNode = storageSunburstData;
  sunburstBreadcrumbs = storageSunburstData ? [{ id: storageSunburstData.id, name: storageSunburstData.name, node: storageSunburstData }] : [];
  hoveredSunburstSlice = null;
  renderSunburstBreadcrumbs();
  renderStorageSunburst();
  renderStorageFileList();
}

function zoomSunburstToIndex(index) {
  if (index < 0 || index >= sunburstBreadcrumbs.length) return;
  sunburstBreadcrumbs = sunburstBreadcrumbs.slice(0, index + 1);
  currentSunburstNode = sunburstBreadcrumbs[index].node;
  hoveredSunburstSlice = null;
  renderSunburstBreadcrumbs();
  renderStorageSunburst();
  renderStorageFileList();
}

function renderSunburstBreadcrumbs() {
  const container = document.getElementById('sunburstBreadcrumbs');
  if (!container) return;

  if (!sunburstBreadcrumbs || sunburstBreadcrumbs.length === 0) {
    container.innerHTML = `<span class="breadcrumb-item active" onclick="zoomSunburstRoot()">ROOT</span>`;
    return;
  }

  container.innerHTML = sunburstBreadcrumbs.map((b, i) => {
    const isLast = i === sunburstBreadcrumbs.length - 1;
    const label = esc(b.name || (selectedStorageDrive || 'ROOT'));
    return `
      <span class="breadcrumb-item ${isLast ? 'active' : ''}" onclick="zoomSunburstToIndex(${i})">${label}</span>
      ${!isLast ? '<span class="faint">/</span>' : ''}
    `;
  }).join('');
}

// -------------------------------------------------------------
// Synchronized Directory File List
// -------------------------------------------------------------
function renderStorageFileList() {
  const container = document.getElementById('storageFilelineWrap');
  const titleEl = document.getElementById('sunburstCurrentDirTitle');
  const sizeEl = document.getElementById('sunburstCurrentDirSize');
  if (!container) return;

  if (!currentSunburstNode) {
    container.innerHTML = `<div class="text-muted text-center" style="padding: 20px;">${t('storageNoScanYet')}</div>`;
    if (titleEl) titleEl.textContent = selectedStorageDrive || "כונן";
    if (sizeEl) sizeEl.textContent = "0 B";
    return;
  }

  if (titleEl) titleEl.textContent = currentSunburstNode.name || (selectedStorageDrive || "Root");
  if (sizeEl) sizeEl.textContent = currentSunburstNode.size_formatted || formatBytesJS(currentSunburstNode.size);

  const filter = (document.getElementById('storageFileListFilter')?.value || '').toLowerCase().trim();
  const children = currentSunburstNode.children || [];

  const sorted = [...children].sort((a, b) => (b.size || 0) - (a.size || 0));
  const filtered = filter ? sorted.filter(c => (c.name || '').toLowerCase().includes(filter)) : sorted;

  if (filtered.length === 0) {
    container.innerHTML = `<div class="text-muted text-center" style="padding: 20px;">${filter ? "לא נמצאו פריטים תואמים" : "התיקייה ריקה"}</div>`;
    return;
  }

  container.innerHTML = filtered.map(child => {
    const isDir = child.is_dir;
    const isAggregated = child.is_aggregated;
    const icon = isDir ? '📁' : getFileIcon(child.name, child.extension);
    const inCollector = child.path && collectorItems.has(child.path);
    const sizeFormatted = child.size_formatted || formatBytesJS(child.size);
    const pathEsc = esc(child.path || '');
    const nameEsc = esc(child.name || '');
    const isOneDrive = isOneDriveStoragePath(child.path);
    const oneDriveBadgeHtml = isOneDrive
      ? `<span class="badge badge-onedrive" style="font-size: 10px; margin-inline-start: 6px; padding: 1px 6px; vertical-align: middle;" title="${esc(t('storageOneDriveTooltip') || 'קובץ מסונכרן בענן של OneDrive')}">☁️ ${esc(t('storageOneDriveBadge') || 'OneDrive')}</span>`
      : '';

    return `
      <div class="storage-fileline ${inCollector ? 'is-in-collector' : ''}"
           data-node-id="${child.id}"
           data-path="${pathEsc}"
           data-name="${nameEsc}"
           data-size="${child.size || 0}"
           draggable="${!isAggregated && child.path ? 'true' : 'false'}"
           ondragstart="onFileLineDragStart(event, this)"
           onclick="${isDir ? `zoomSunburstToNodeById(${child.id})` : ''}"
           oncontextmenu="openStorageContextMenuFromEl(event, this)">
        <span class="storage-fileline-icon">${icon}</span>
        <span class="storage-fileline-name" title="${pathEsc}">${nameEsc}${oneDriveBadgeHtml}</span>
        <span class="storage-fileline-size mono">${sizeFormatted}</span>
        ${!isAggregated && child.path ? `
          <button class="storage-fileline-btn" onclick="event.stopPropagation(); toggleCollectorFromEl(this.parentElement)" title="${inCollector ? 'הסר מסל האיסוף' : 'הוסף לסל מחיקה'}">
            ${inCollector ? '✓' : '➕'}
          </button>
        ` : ''}
      </div>
    `;
  }).join('');
}

function findSunburstNodeById(id, root = storageSunburstData) {
  if (!root) return null;
  if (root.id === id) return root;
  if (root.children) {
    for (const c of root.children) {
      if (c.id === id) return c;
      const found = findSunburstNodeById(id, c);
      if (found) return found;
    }
  }
  return null;
}

function filterStorageFileList() {
  renderStorageFileList();
}

function getFileIcon(filename, ext) {
  const e = (ext || (filename ? filename.split('.').pop() : '') || '').toLowerCase().replace(/^\./, '');
  const videoExts = ['mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv', 'webm', 'm4v'];
  const audioExts = ['mp3', 'wav', 'flac', 'aac', 'ogg', 'wma', 'm4a'];
  const imgExts = ['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'bmp', 'ico', 'tiff'];
  const archExts = ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'iso'];
  const codeExts = ['js', 'ts', 'py', 'html', 'css', 'json', 'c', 'cpp', 'cs', 'rs', 'go', 'java', 'xml'];
  const execExts = ['exe', 'msi', 'bat', 'cmd', 'ps1', 'dll', 'sys'];

  if (videoExts.includes(e)) return '🎬';
  if (audioExts.includes(e)) return '🎵';
  if (imgExts.includes(e)) return '🖼️';
  if (archExts.includes(e)) return '📦';
  if (codeExts.includes(e)) return '💻';
  if (execExts.includes(e)) return '⚙️';
  return '📄';
}

// -------------------------------------------------------------
// Deletion Collector (Drag & Drop + Safe Batch Recycle)
// -------------------------------------------------------------
function onFileLineDragStart(e, el) {
  const id = Number(el.getAttribute('data-node-id'));
  const path = el.getAttribute('data-path') || '';
  const name = el.getAttribute('data-name') || '';
  const size = Number(el.getAttribute('data-size')) || 0;
  e.dataTransfer.setData('application/json', JSON.stringify({ id, path, name, size }));
  e.dataTransfer.effectAllowed = 'copy';
}

function toggleCollectorFromEl(el) {
  if (!el) return;
  const id = Number(el.getAttribute('data-node-id'));
  const path = el.getAttribute('data-path') || '';
  const name = el.getAttribute('data-name') || '';
  const size = Number(el.getAttribute('data-size')) || 0;
  toggleCollectorItem(id, path, name, size);
}

function openStorageContextMenuFromEl(e, el) {
  if (!el) return;
  const nodeId = Number(el.getAttribute('data-node-id')) || 0;
  const path = el.getAttribute('data-path') || '';
  openStorageContextMenu(e, nodeId, path);
}

function onCollectorDragOver(e) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'copy';
  const box = document.getElementById('collectorDropzone');
  if (box) box.classList.add('drag-over');
}

function onCollectorDragLeave(e) {
  const box = document.getElementById('collectorDropzone');
  if (box) box.classList.remove('drag-over');
}

function onCollectorDrop(e) {
  e.preventDefault();
  const box = document.getElementById('collectorDropzone');
  if (box) box.classList.remove('drag-over');

  try {
    const raw = e.dataTransfer.getData('application/json');
    if (!raw) return;
    const item = JSON.parse(raw);
    if (item && item.path) {
      toggleCollectorItem(item.id, item.path, item.name, item.size, true);
    }
  } catch (err) {
    console.error("onCollectorDrop parse error:", err);
  }
}

function toggleCollectorItem(id, path, name, size, forceAdd = false) {
  if (!path) return;
  if (collectorItems.has(path)) {
    if (!forceAdd) {
      collectorItems.delete(path);
    }
  } else {
    // id is the scan-produced node id - the delete call resolves against it
    // server-side rather than trusting this path string directly, so a
    // missing/invalid id here means the item simply can't be deleted later
    // (surfaced as an error from the server, not a silent path substitution).
    collectorItems.set(path, {
      id: Number.isFinite(id) ? id : null,
      path,
      name: name || path.split('\\').pop() || path,
      size: Number(size) || 0,
    });
  }
  updateCollectorUi();
}

function removeCollectorItem(path) {
  if (collectorItems.has(path)) {
    collectorItems.delete(path);
    updateCollectorUi();
  }
}

function removeCollectorItemByIndex(idx) {
  const keys = Array.from(collectorItems.keys());
  if (keys[idx] !== undefined) {
    collectorItems.delete(keys[idx]);
    updateCollectorUi();
  }
}

function clearCollectorSelection() {
  collectorItems.clear();
  updateCollectorUi();
}

function updateCollectorUi() {
  const emptyMsg = document.getElementById('collectorEmptyMsg');
  const itemsList = document.getElementById('collectorItemsList');
  const totalSizeEl = document.getElementById('collectorTotalSize');
  const countEl = document.getElementById('collectorItemsCount');
  const btnDelete = document.getElementById('btnExecuteCollectorDelete');

  const count = collectorItems.size;
  let totalBytes = 0;
  collectorItems.forEach(item => { totalBytes += item.size; });

  if (totalSizeEl) totalSizeEl.textContent = formatBytesJS(totalBytes);
  if (countEl) countEl.textContent = `(${count} פריטים)`;

  if (count === 0) {
    if (emptyMsg) emptyMsg.classList.remove('hidden');
    if (itemsList) { itemsList.classList.add('hidden'); itemsList.innerHTML = ''; }
    if (btnDelete) btnDelete.disabled = true;
  } else {
    if (emptyMsg) emptyMsg.classList.add('hidden');
    if (itemsList) {
      itemsList.classList.remove('hidden');
      const itemsArr = Array.from(collectorItems.values());
      itemsList.innerHTML = itemsArr.map((item, idx) => `
        <div class="collector-chip" title="${esc(item.path)}">
          <span class="collector-chip-name">${esc(item.name)} (${formatBytesJS(item.size)})</span>
          <span class="collector-chip-del" onclick="removeCollectorItemByIndex(${idx})" title="הסר מהסל">✕</span>
        </div>
      `).join('');
    }
    if (btnDelete) btnDelete.disabled = false;
  }

  // Refresh highlight in the file list
  renderStorageFileList();
}

async function executeCollectorDelete() {
  const count = collectorItems.size;
  if (count === 0) return;

  let totalBytes = 0;
  const ids = [];
  collectorItems.forEach(item => {
    totalBytes += item.size;
    if (item.id !== null && item.id !== undefined) ids.push(item.id);
  });

  const confirmMsg = `האם אתה בטוח שברצונך להעביר ${count} פריטים (${formatBytesJS(totalBytes)}) לסל המחזור של Windows?`;
  if (!confirm(confirmMsg)) return;

  try {
    showToast("מחיקה בתהליך", "מעביר פריטים שנאספו לסל המחזור...", "accent");
    // ids are resolved against the live scan index on the server - the
    // client's paths are never used directly for the delete itself.
    const res = await fetch('/api/storage/collector/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids })
    });
    const data = await res.json();
    // `success` now means "every item was deleted" - a partial run (some
    // deleted, some rejected/protected) still ran and freed real space, so it
    // is reported here too instead of being treated as an outright failure.
    const ran = data.deleted_count !== undefined;

    if (ran) {
      if (data.deleted_count > 0) {
        showToast("מחיקה הושלמה", `הועברו ${data.deleted_count} פריטים לסל המחזור (${data.freed_formatted})`, "accent");
      }
      if (data.errors && data.errors.length > 0) {
        showToast(data.deleted_count > 0 ? "אזהרה" : "שגיאה במחיקה",
                  `${data.errors.length} פריטים לא נמחקו (מוגנים או לא נמצאו)`,
                  data.deleted_count > 0 ? "warn" : "danger");
      }
      collectorItems.clear();
      updateCollectorUi();
      await loadStorageResults();
    } else {
      showToast("שגיאה במחיקה", data.error || "נכשלה מחיקת הפריטים", "danger");
    }
  } catch (err) {
    showToast("שגיאת תקשורת", err.message, "danger");
  }
}

// -------------------------------------------------------------
// Directory Tree View
// -------------------------------------------------------------
function renderStorageTree() {
  const tbody = document.getElementById('storageTreeBody');
  if (!tbody) return;

  if (!storageTreeData) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-muted text-center" style="padding: 24px;">${t('storageNoScanYet')}</td></tr>`;
    return;
  }

  const rows = [];
  function renderNode(node, depth = 0) {
    const isSelected = node.id === selectedNodeId;
    const hasChildren = node.is_dir && node.children && node.children.length > 0;
    const isExpanded = node._expanded !== false; // default expanded
    const indentPx = depth * 16;
    const icon = node.is_dir ? (isExpanded ? '📂' : '📁') : '📄';
    const propPct = node.percentage_of_parent || node.percentage_of_total || 0;
    const isOneDrive = isOneDriveStoragePath(node.path);
    const oneDriveBadgeHtml = isOneDrive
      ? `<span class="badge badge-onedrive" style="font-size: 10px; margin-inline-start: 6px; padding: 1px 6px; vertical-align: middle;" title="${esc(t('storageOneDriveTooltip') || 'קובץ מסונכרן בענן של OneDrive')}">☁️ ${esc(t('storageOneDriveBadge') || 'OneDrive')}</span>`
      : '';

    rows.push(`
      <tr class="storage-tree-row ${isSelected ? 'selected' : ''}" data-node-id="${node.id}" onclick="selectStorageTreeNode(${node.id})" oncontextmenu="openStorageContextMenu(event, ${node.id})">
        <td style="padding-inline-start: ${indentPx + 8}px;">
          ${node.is_dir ? `<span class="tree-expander" onclick="event.stopPropagation(); toggleStorageTreeExpand(${node.id})">${isExpanded ? '▼' : '▶'}</span>` : '<span class="tree-expander"></span>'}
          <span class="tree-icon">${icon}</span>
          <span class="tree-name" title="${esc(node.path)}">${esc(node.name)}</span>${oneDriveBadgeHtml}
        </td>
        <td>
          <div class="prop-bar-wrap" title="${propPct}%">
            <div class="prop-bar-fill" style="width: ${Math.min(100, Math.max(2, propPct))}%;"></div>
          </div>
        </td>
        <td class="mono">${esc(node.size_formatted)}</td>
        <td class="mono text-muted">${node.is_dir ? (node.file_count || 0).toLocaleString() : '-'}</td>
        <td class="mono text-muted">${node.is_dir ? (node.dir_count || 0).toLocaleString() : '-'}</td>
        <td style="text-align: center;">
          <button class="btn btn-sm btn-icon" onclick="event.stopPropagation(); openStorageContextMenu(event, ${node.id})" title="פעולות">⋮</button>
        </td>
      </tr>
    `);

    if (node.is_dir && isExpanded && node.children) {
      for (const child of node.children) {
        renderNode(child, depth + 1);
      }
    }
  }

  renderNode(storageTreeData, 0);
  tbody.innerHTML = rows.join('');
}

function toggleStorageTreeExpand(nodeId) {
  function findAndToggle(node) {
    if (node.id === nodeId) {
      node._expanded = !(node._expanded !== false);
      return true;
    }
    if (node.children) {
      for (const c of node.children) {
        if (findAndToggle(c)) return true;
      }
    }
    return false;
  }

  if (storageTreeData) {
    findAndToggle(storageTreeData);
    renderStorageTree();
  }
}

function selectStorageTreeNode(nodeId) {
  selectedNodeId = nodeId;
  renderStorageTree();
  highlightTreemapBlock(nodeId);
}

function filterStorageTree() {
  const query = (document.getElementById('storageTreeFilter')?.value || '').toLowerCase().trim();
  const rows = document.querySelectorAll('#storageTreeBody tr');
  rows.forEach(tr => {
    const nameEl = tr.querySelector('.tree-name');
    if (!nameEl) return;
    const name = nameEl.textContent.toLowerCase();
    tr.style.display = !query || name.includes(query) ? '' : 'none';
  });
}

// -------------------------------------------------------------
// Extension Breakdown Legend
// -------------------------------------------------------------
function renderStorageExtensions() {
  const tbody = document.getElementById('storageExtBody');
  const countBadge = document.getElementById('storageExtCountBadge');
  if (!tbody) return;

  if (countBadge) countBadge.textContent = `${storageExtensions.length} סוגים`;

  if (!storageExtensions || storageExtensions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-muted text-center" style="padding: 24px;">${t('storageNoExts')}</td></tr>`;
    return;
  }

  tbody.innerHTML = storageExtensions.map(ext => {
    const isActive = activeExtFilter === ext.extension;
    return `
      <tr class="storage-ext-row ${isActive ? 'active-ext' : ''}" onclick="toggleExtensionFilter('${esc(ext.extension)}')" title="לחץ לסינון מפת Treemap">
        <td><span class="ext-swatch" style="background: ${esc(ext.color)};"></span></td>
        <td><strong>${esc(ext.extension)}</strong></td>
        <td class="mono">${esc(ext.size_formatted)}</td>
        <td class="mono">${ext.percentage}%</td>
        <td class="mono text-muted">${(ext.count || 0).toLocaleString()}</td>
      </tr>
    `;
  }).join('');
}

function toggleExtensionFilter(ext) {
  if (activeExtFilter === ext) {
    activeExtFilter = null;
  } else {
    activeExtFilter = ext;
  }
  renderStorageExtensions();
  renderStorageTreemap();
}

// -------------------------------------------------------------
// Cushion Treemap Canvas Engine (WinDirStat Native Mathematics)
// -------------------------------------------------------------
let storageCanvas = null;
let storageCtx = null;

function initStorageCanvas() {
  storageCanvas = document.getElementById('storageTreemapCanvas');
  if (!storageCanvas) return;
  storageCtx = storageCanvas.getContext('2d');

  // Resize canvas to container
  resizeStorageCanvas();
  window.addEventListener('resize', debounceStorageResize);

  // Mouse interactions
  storageCanvas.onmousemove = handleTreemapMouseMove;
  storageCanvas.onmouseleave = handleTreemapMouseLeave;
  storageCanvas.onclick = handleTreemapClick;
  storageCanvas.ondblclick = handleTreemapDblClick;
  storageCanvas.oncontextmenu = handleTreemapContextMenu;
}

function debounceStorageResize() {
  if (currentScreen === 'storage' && activeStorageTab === 'treemap') {
    resizeStorageCanvas();
    renderStorageTreemap();
  }
}

function resizeStorageCanvas() {
  if (!storageCanvas) return;
  const container = document.getElementById('storageCanvasContainer');
  if (!container) return;
  const rect = container.getBoundingClientRect();
  const width = Math.max(400, Math.floor(rect.width));
  const height = 460;
  if (storageCanvas.width !== width || storageCanvas.height !== height) {
    storageCanvas.width = width;
    storageCanvas.height = height;
  }
}

function changeTreemapStyle() {
  const sel = document.getElementById('storageTreemapStyle');
  if (sel) {
    treemapStyle = sel.value;
    renderStorageTreemap();
  }
}

function redrawStorageTreemap() {
  resizeStorageCanvas();
  renderStorageTreemap();
}

// Squarified Treemap Algorithm
function computeSquarifiedTreemap(node, x, y, width, height) {
  const resultRects = [];
  if (!node || width <= 0 || height <= 0) return resultRects;

  function squarify(children, currentX, currentY, curW, curH, parentSurface, depth) {
    if (!children || children.length === 0 || curW <= 1 || curH <= 1) return;

    const totalWeight = children.reduce((sum, c) => sum + (c.size || 0), 0);
    if (totalWeight <= 0) return;

    let remaining = [...children];
    let posX = currentX;
    let posY = currentY;
    let availW = curW;
    let availH = curH;

    while (remaining.length > 0) {
      const isHorizontal = availW >= availH;
      const length = isHorizontal ? availH : availW;

      let row = [remaining[0]];
      let rowWeight = remaining[0].size;
      let i = 1;

      while (i < remaining.length) {
        const next = remaining[i];
        const nextWeight = rowWeight + next.size;
        const currentWorst = worstAspect(row, rowWeight, length, availW, availH, isHorizontal);
        const nextWorst = worstAspect([...row, next], nextWeight, length, availW, availH, isHorizontal);

        if (nextWorst <= currentWorst) {
          row.push(next);
          rowWeight = nextWeight;
          i++;
        } else {
          break;
        }
      }

      remaining = remaining.slice(row.length);

      // Layout current row
      const rowThickness = Math.max(1, isHorizontal ? availW * (rowWeight / (totalWeight * (availW / curW))) : availH * (rowWeight / (totalWeight * (availH / curH))));
      const actualThickness = Math.min(isHorizontal ? availW : availH, rowThickness);

      let itemPos = isHorizontal ? posY : posX;
      for (const item of row) {
        const itemFraction = item.size / rowWeight;
        const itemLength = (isHorizontal ? availH : availW) * itemFraction;

        const rx = isHorizontal ? posX : itemPos;
        const ry = isHorizontal ? itemPos : posY;
        const rw = isHorizontal ? actualThickness : itemLength;
        const rh = isHorizontal ? itemLength : actualThickness;

        const intRx = Math.floor(rx);
        const intRy = Math.floor(ry);
        const intRw = Math.max(1, Math.floor(rw));
        const intRh = Math.max(1, Math.floor(rh));

        // Cushion parabolic ridge update
        const childSurface = [...parentSurface];
        addCushionRidge(childSurface, intRx, intRy, intRw, intRh, 0.18 * Math.pow(0.85, depth));

        if (item.is_dir && item.children && item.children.length > 0 && depth < 12 && intRw > 6 && intRh > 6) {
          const pad = intRw > 12 && intRh > 12 ? 2 : 0;
          squarify(item.children, intRx + pad, intRy + pad, intRw - pad * 2, intRh - pad * 2, childSurface, depth + 1);
        } else {
          resultRects.push({
            id: item.id,
            name: item.name,
            path: item.path,
            size: item.size,
            size_formatted: item.size_formatted,
            is_dir: item.is_dir,
            extension: item.extension || '',
            color: item.color || (item.is_dir ? '#334155' : '#3498db'),
            rect: { x: intRx, y: intRy, w: intRw, h: intRh },
            surface: childSurface,
            depth: depth
          });
        }

        itemPos += itemLength;
      }

      if (isHorizontal) {
        posX += actualThickness;
        availW -= actualThickness;
      } else {
        posY += actualThickness;
        availH -= actualThickness;
      }
    }
  }

  function worstAspect(row, totalR, length, w, h, isHoriz) {
    if (totalR <= 0 || length <= 0) return 999999;
    let minSize = row[0].size;
    let maxSize = row[0].size;
    for (const r of row) {
      if (r.size < minSize) minSize = r.size;
      if (r.size > maxSize) maxSize = r.size;
    }
    const side = (totalR / (w * h)) * length * length;
    const aspect1 = (length * length * maxSize) / (totalR * totalR);
    const aspect2 = (totalR * totalR) / (length * length * minSize);
    return Math.max(aspect1, aspect2);
  }

  function addCushionRidge(surface, rx, ry, rw, rh, hVal) {
    if (rw <= 0 || rh <= 0) return;
    const h4 = 4.0 * hVal;
    const wf = h4 / rw;
    const hf = h4 / rh;
    surface[2] += wf * (rx + rx + rw);
    surface[0] -= wf;
    surface[3] += hf * (ry + ry + rh);
    surface[1] -= hf;
  }

  const initialSurface = [0, 0, 0, 0];
  const children = node.children || [node];
  squarify(children, x, y, width, height, initialSurface, 1);
  return resultRects;
}

// Cushion Treemap Renderer
function renderStorageTreemap() {
  if (!storageCanvas || !storageCtx) return;
  const w = storageCanvas.width;
  const h = storageCanvas.height;

  storageCtx.clearRect(0, 0, w, h);

  if (!storageTreemapData) {
    storageCtx.fillStyle = '#222';
    storageCtx.fillRect(0, 0, w, h);
    storageCtx.fillStyle = '#888';
    storageCtx.font = '14px sans-serif';
    storageCtx.textAlign = 'center';
    storageCtx.fillText(t('storageNoScanYet'), w / 2, h / 2);
    return;
  }

  // Find active subtree based on currentTreemapRootId
  let rootSubtree = storageTreemapData;
  if (currentTreemapRootId) {
    rootSubtree = findSubtreeInNode(storageTreemapData, currentTreemapRootId) || storageTreemapData;
  }

  treemapVisibleRects = computeSquarifiedTreemap(rootSubtree, 0, 0, w, h);

  // Render Rectangles
  if (treemapStyle === 'cushion') {
    renderCushionMode(w, h);
  } else if (treemapStyle === 'pastel') {
    renderFlatMode(w, h, true);
  } else {
    renderFlatMode(w, h, false);
  }
}

function hexToRgb(color) {
  if (!color) return { r: 52, g: 152, b: 219 };
  if (typeof color !== 'string') return { r: 52, g: 152, b: 219 };

  if (color.startsWith('#')) {
    let c = color.replace('#', '');
    if (c.length === 3) c = c.split('').map(x => x + x).join('');
    const num = parseInt(c, 16);
    if (!isNaN(num)) {
      return { r: (num >> 16) & 255, g: (num >> 8) & 255, b: num & 255 };
    }
  } else if (color.startsWith('rgb')) {
    const m = color.match(/\d+/g);
    if (m && m.length >= 3) {
      return { r: Number(m[0]), g: Number(m[1]), b: Number(m[2]) };
    }
  } else if (color.startsWith('hsl')) {
    const m = color.match(/[\d.]+/g);
    if (m && m.length >= 3) {
      const h = Number(m[0]) / 360;
      const s = Number(m[1]) / 100;
      const l = Number(m[2]) / 100;
      let r, g, b;
      if (s === 0) {
        r = g = b = l;
      } else {
        const hue2rgb = (p, q, t) => {
          if (t < 0) t += 1;
          if (t > 1) t -= 1;
          if (t < 1/6) return p + (q - p) * 6 * t;
          if (t < 1/2) return q;
          if (t < 2/3) return p + (q - p) * (2/3 - t) * 6;
          return p;
        };
        const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
        const p = 2 * l - q;
        r = hue2rgb(p, q, h + 1/3);
        g = hue2rgb(p, q, h);
        b = hue2rgb(p, q, h - 1/3);
      }
      return { r: Math.round(r * 255), g: Math.round(g * 255), b: Math.round(b * 255) };
    }
  }
  return { r: 52, g: 152, b: 219 };
}

function renderCushionMode(w, h) {
  const imgData = storageCtx.createImageData(w, h);
  const data = imgData.data;

  // Fill dark background
  for (let i = 0; i < data.length; i += 4) {
    data[i] = 18; data[i + 1] = 20; data[i + 2] = 26; data[i + 3] = 255;
  }

  const lx = -0.577;
  const ly = -0.577;
  const lz = 0.577;
  const ambient = 0.45;
  const diffuse = 0.70;

  const blocksToRender = treemapVisibleRects.length > 1500
    ? treemapVisibleRects.slice(0, 1500)
    : treemapVisibleRects;

  for (const block of blocksToRender) {
    const { x, y, w: bw, h: bh } = block.rect;
    if (bw <= 2 || bh <= 2) continue;

    const isDimmed = activeExtFilter && block.extension !== activeExtFilter;
    const isSelected = block.id === selectedNodeId;

    let baseRgb = hexToRgb(block.color);
    if (isDimmed) {
      baseRgb = { r: Math.floor(baseRgb.r * 0.25), g: Math.floor(baseRgb.g * 0.25), b: Math.floor(baseRgb.b * 0.25) };
    }

    const s = block.surface;
    const s0 = s[0];
    const s1 = s[1];
    const s2 = s[2];
    const s3 = s[3];

    for (let py = y; py < y + bh && py < h; py++) {
      if (py < 0) continue;
      const ny = -(2 * s1 * (py + 0.5) + s3);
      const nyLyLz = ny * ly + lz;
      const ny2_1 = ny * ny + 1.0;
      let rowIdx = (py * w + x) * 4;

      for (let px = x; px < x + bw && px < w; px++) {
        if (px < 0) { rowIdx += 4; continue; }

        // Grid border (1px)
        if (px === x || py === y || px === x + bw - 1 || py === y + bh - 1) {
          data[rowIdx] = isSelected ? 255 : 24;
          data[rowIdx + 1] = isSelected ? 255 : 28;
          data[rowIdx + 2] = isSelected ? 255 : 36;
          data[rowIdx + 3] = 255;
          rowIdx += 4;
          continue;
        }

        const nx = -(2 * s0 * (px + 0.5) + s2);
        let cosa = (nx * lx + nyLyLz) / Math.sqrt(nx * nx + ny2_1);
        if (cosa > 1.0) cosa = 1.0;

        let intensity = ambient + diffuse * Math.max(0, cosa);
        if (isSelected) intensity = Math.min(1.5, intensity * 1.35);

        data[rowIdx] = Math.min(255, Math.floor(baseRgb.r * intensity));
        data[rowIdx + 1] = Math.min(255, Math.floor(baseRgb.g * intensity));
        data[rowIdx + 2] = Math.min(255, Math.floor(baseRgb.b * intensity));
        data[rowIdx + 3] = 255;

        rowIdx += 4;
      }
    }
  }

  storageCtx.putImageData(imgData, 0, 0);
  drawTreemapLabels();
}

function renderFlatMode(w, h, isPastel) {
  for (const block of treemapVisibleRects) {
    const { x, y, w: bw, h: bh } = block.rect;
    if (bw <= 0 || bh <= 0) continue;

    const isDimmed = activeExtFilter && block.extension !== activeExtFilter;
    const isSelected = block.id === selectedNodeId;

    let col = block.color;
    if (isPastel) {
      col = lightenColor(col, 30);
    }
    storageCtx.fillStyle = isDimmed ? 'rgba(40,44,52,0.4)' : col;
    storageCtx.fillRect(x, y, bw, bh);

    // Border
    storageCtx.strokeStyle = isSelected ? '#ffffff' : 'rgba(0,0,0,0.35)';
    storageCtx.lineWidth = isSelected ? 2 : 1;
    storageCtx.strokeRect(x, y, bw, bh);
  }

  drawTreemapLabels();
}

function drawTreemapLabels() {
  if (!storageCtx || !treemapVisibleRects) return;
  storageCtx.save();
  for (const block of treemapVisibleRects) {
    const { x, y, w: bw, h: bh } = block.rect;
    if (bw < 34 || bh < 16) continue;

    const isSelected = block.id === selectedNodeId;
    storageCtx.textAlign = 'center';
    storageCtx.textBaseline = 'middle';
    storageCtx.shadowColor = 'rgba(0, 0, 0, 0.9)';
    storageCtx.shadowBlur = 4;
    storageCtx.shadowOffsetX = 1;
    storageCtx.shadowOffsetY = 1;

    const label = block.name || block.extension || '';
    if (!label) continue;

    storageCtx.fillStyle = isSelected ? '#38bdf8' : '#ffffff';
    storageCtx.font = 'bold 11px sans-serif';

    const maxTextWidth = bw - 8;
    let displayText = label;
    if (storageCtx.measureText(displayText).width > maxTextWidth) {
      while (displayText.length > 2 && storageCtx.measureText(displayText + '…').width > maxTextWidth) {
        displayText = displayText.slice(0, -1);
      }
      displayText += '…';
    }

    if (bh >= 34 && block.size_formatted) {
      storageCtx.fillText(displayText, x + bw / 2, y + bh / 2 - 7);
      storageCtx.fillStyle = 'rgba(255, 255, 255, 0.85)';
      storageCtx.font = '10px monospace';
      storageCtx.fillText(block.size_formatted, x + bw / 2, y + bh / 2 + 8);
    } else {
      storageCtx.fillText(displayText, x + bw / 2, y + bh / 2);
    }
  }
  storageCtx.restore();
}


// Treemap Mouse Event Handlers
function findTreemapBlockAt(mouseX, mouseY) {
  for (let i = treemapVisibleRects.length - 1; i >= 0; i--) {
    const b = treemapVisibleRects[i];
    const { x, y, w, h } = b.rect;
    if (mouseX >= x && mouseX <= x + w && mouseY >= y && mouseY <= y + h) {
      return b;
    }
  }
  return null;
}

function handleTreemapMouseMove(e) {
  const rect = storageCanvas.getBoundingClientRect();
  const mouseX = e.clientX - rect.left;
  const mouseY = e.clientY - rect.top;

  const hovered = findTreemapBlockAt(mouseX, mouseY);
  const tooltip = document.getElementById('storageTreemapTooltip');

  if (hovered && tooltip) {
    tooltip.classList.remove('hidden');
    document.getElementById('ttName').textContent = hovered.name;
    document.getElementById('ttSize').textContent = hovered.size_formatted;
    document.getElementById('ttPath').textContent = hovered.path;

    const oneDriveBadge = document.getElementById('ttOneDriveBadge');
    if (oneDriveBadge) {
      if (isOneDriveStoragePath(hovered.path)) {
        oneDriveBadge.classList.remove('hidden');
        oneDriveBadge.textContent = `☁️ ${t('storageOneDriveBadge') || 'OneDrive'}`;
        oneDriveBadge.title = t('storageOneDriveTooltip') || 'קובץ מסונכרן בענן של OneDrive';
      } else {
        oneDriveBadge.classList.add('hidden');
      }
    }

    let tipX = mouseX + 15;
    let tipY = mouseY + 15;
    if (tipX + 260 > rect.width) tipX = mouseX - 260;
    if (tipY + 90 > rect.height) tipY = mouseY - 90;

    tooltip.style.left = `${Math.max(10, tipX)}px`;
    tooltip.style.top = `${Math.max(10, tipY)}px`;
  } else if (tooltip) {
    tooltip.classList.add('hidden');
  }
}

function handleTreemapMouseLeave() {
  const tooltip = document.getElementById('storageTreemapTooltip');
  if (tooltip) tooltip.classList.add('hidden');
}

function handleTreemapClick(e) {
  const rect = storageCanvas.getBoundingClientRect();
  const mouseX = e.clientX - rect.left;
  const mouseY = e.clientY - rect.top;

  const clicked = findTreemapBlockAt(mouseX, mouseY);
  if (clicked) {
    selectedNodeId = clicked.id;
    renderStorageTree();
    renderStorageTreemap();
  }
}

async function handleTreemapDblClick(e) {
  const rect = storageCanvas.getBoundingClientRect();
  const mouseX = e.clientX - rect.left;
  const mouseY = e.clientY - rect.top;

  const clicked = findTreemapBlockAt(mouseX, mouseY);
  if (!clicked) return;

  if (clicked.is_dir) {
    await zoomStorageTreemapToNode(clicked.id, clicked.name);
  } else if (clicked.path) {
    performStorageFileAction('reveal', clicked.path);
  }
}

function handleTreemapContextMenu(e) {
  e.preventDefault();
  const rect = storageCanvas.getBoundingClientRect();
  const mouseX = e.clientX - rect.left;
  const mouseY = e.clientY - rect.top;

  const clicked = findTreemapBlockAt(mouseX, mouseY);
  // A "<N smaller files>" rollup block is a synthetic summary, not a real
  // file or folder - it carries id -1 and no real path. Never let it reach
  // the context menu, since a delete there could otherwise target whatever
  // path a stale/legacy payload happened to leave on the node.
  if (clicked && clicked.id !== -1 && !clicked.is_aggregated && clicked.path) {
    openStorageContextMenu(e, clicked.id, clicked.path);
  }
}

function highlightTreemapBlock(nodeId) {
  selectedNodeId = nodeId;
  renderStorageTreemap();
}

// Breadcrumbs Navigation
function renderStorageBreadcrumbs() {
  const wrap = document.getElementById('storageBreadcrumbs');
  if (!wrap) return;

  if (treemapBreadcrumbs.length === 0) {
    wrap.innerHTML = '<span class="breadcrumb-item active" onclick="zoomStorageTreemapRoot()">ROOT</span>';
    return;
  }

  wrap.innerHTML = treemapBreadcrumbs.map((b, idx) => {
    const isLast = idx === treemapBreadcrumbs.length - 1;
    return `
      <span class="breadcrumb-item ${isLast ? 'active' : ''}" onclick="zoomStorageTreemapTo(${idx})">${esc(b.name)}</span>
      ${!isLast ? '<span class="text-muted">/</span>' : ''}
    `;
  }).join('');
}

async function zoomStorageTreemapTo(index) {
  treemapBreadcrumbs = treemapBreadcrumbs.slice(0, index + 1);
  const target = treemapBreadcrumbs[treemapBreadcrumbs.length - 1];
  currentTreemapRootId = target ? target.id : null;
  renderStorageBreadcrumbs();
  renderStorageTreemap();
}

function zoomStorageTreemapRoot() {
  currentTreemapRootId = null;
  treemapBreadcrumbs = storageTreemapData ? [{ id: storageTreemapData.id, name: storageTreemapData.name }] : [];
  renderStorageBreadcrumbs();
  renderStorageTreemap();
}

async function zoomStorageTreemapUp() {
  if (treemapBreadcrumbs.length > 1) {
    treemapBreadcrumbs.pop();
    const target = treemapBreadcrumbs[treemapBreadcrumbs.length - 1];
    currentTreemapRootId = target ? target.id : null;
    renderStorageBreadcrumbs();
    renderStorageTreemap();
  } else {
    zoomStorageTreemapRoot();
  }
}

async function zoomStorageTreemapToNode(nodeId, nodeName) {
  currentTreemapRootId = nodeId;
  treemapBreadcrumbs.push({ id: nodeId, name: nodeName });
  renderStorageBreadcrumbs();

  let subtree = findSubtreeInNode(storageTreemapData, nodeId);
  if (!subtree || !subtree.children || subtree.children.length === 0) {
    try {
      const res = await fetch(`/api/storage/treemap?node_id=${nodeId}&depth=10`);
      const data = await res.json();
      if (data.treemap && data.treemap.children) {
        if (subtree) {
          subtree.children = data.treemap.children;
        } else if (storageTreemapData) {
          subtree = data.treemap;
        }
      }
    } catch (err) {
      console.warn("Could not fetch subtree for treemap:", err);
    }
  }

  renderStorageTreemap();
}

function findSubtreeInNode(node, targetId) {
  if (!node) return null;
  if (node.id === targetId) return node;
  if (node.children) {
    for (const c of node.children) {
      const found = findSubtreeInNode(c, targetId);
      if (found) return found;
    }
  }
  return null;
}

async function reloadStorageTreemapData() {
  showToast("מרענן מפת שטחים", "טוען מבנה קבצים מלא...", "info");
  try {
    const res = await fetch('/api/storage/treemap?depth=10');
    const data = await res.json();
    if (data.treemap) {
      storageTreemapData = data.treemap;
      currentTreemapRootId = null;
      treemapBreadcrumbs = [{ id: storageTreemapData.id, name: storageTreemapData.name }];
      renderStorageBreadcrumbs();
      redrawStorageTreemap();
      showToast("הושלם", "מפת השטחים נטענה בהצלחה.");
    } else {
      redrawStorageTreemap();
    }
  } catch (err) {
    redrawStorageTreemap();
    showToast("שגיאה", "שגיאה בטעינת נתוני מפת הכריות: " + err.message, "danger");
  }
}

// -------------------------------------------------------------
// Top Largest Files
// -------------------------------------------------------------
function renderStorageTopFiles() {
  const tbody = document.getElementById('storageTopBody');
  const countBadge = document.getElementById('storageTopCountBadge');
  if (!tbody) return;

  if (countBadge) countBadge.textContent = `${storageTopFiles.length}`;

  if (!storageTopFiles || storageTopFiles.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-muted text-center" style="padding: 24px;">${t('storageNoScanYet')}</td></tr>`;
    return;
  }

  tbody.innerHTML = storageTopFiles.map((f, i) => {
    const isSystem = Boolean(f.is_system) || isProtectedStoragePath(f.path, f);
    const isProtected = f.is_safe_to_delete === false || isSystem;
    const badgeHtml = isSystem
      ? `<span class="badge badge-accent" style="font-size: 10px; margin-inline-start: 6px; padding: 1px 6px; vertical-align: middle; background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3);" title="${esc(f.protection_reason || 'קובץ מערכת של Windows')}">🛡️ ${t('storageSystemBadge') || 'מערכת'}</span>`
      : '';
    const isOneDrive = isOneDriveStoragePath(f.path);
    const oneDriveBadgeHtml = isOneDrive
      ? `<span class="badge badge-onedrive" style="font-size: 10px; margin-inline-start: 6px; padding: 1px 6px; vertical-align: middle;" title="${esc(t('storageOneDriveTooltip') || 'קובץ מסונכרן בענן של OneDrive')}">☁️ ${esc(t('storageOneDriveBadge') || 'OneDrive')}</span>`
      : '';

    const actionDeleteHtml = isProtected
      ? `<button class="btn btn-sm btn-icon btn-disabled" disabled title="${esc(f.protection_reason || t('storageSystemProtectedTooltip') || 'קובץ מערכת מוגן - לא ניתן למחיקה')}" style="opacity: 0.35; cursor: not-allowed; filter: grayscale(1);">🔒</button>`
      : `<button class="btn btn-sm btn-icon" data-path="${esc(f.path)}" onclick="performStorageActionFromEl(this, 'recycle')" title="העבר לסל המחזור">🗑️</button>`;

    return `
      <tr class="storage-top-row" data-path="${esc(f.path)}" data-node-id="${f.id}" data-is-system="${isSystem ? 'true' : 'false'}" data-is-protected="${isProtected ? 'true' : 'false'}" oncontextmenu="openStorageContextMenuFromEl(event, this)">
        <td class="text-muted">${i + 1}</td>
        <td><strong>${esc(f.name)}</strong>${badgeHtml}${oneDriveBadgeHtml}</td>
        <td class="mono font-bold">${esc(f.size_formatted)}</td>
        <td class="mono">${f.percentage}%</td>
        <td class="mono text-muted text-xs" style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${esc(f.path)}">${esc(f.path)}</td>
        <td>
          <button class="btn btn-sm btn-icon" data-path="${esc(f.path)}" onclick="performStorageActionFromEl(this, 'reveal')" title="הצג בסייר הקבצים">📁</button>
          ${actionDeleteHtml}
        </td>
      </tr>
    `;
  }).join('');

  filterStorageTopFiles();
}

function filterStorageTopFiles() {
  const query = stripBidi(document.getElementById('storageTopFilter')?.value || '').toLowerCase().trim();
  const hideSystem = document.getElementById('storageHideSystemTopFiles')?.checked ?? true;
  const rows = document.querySelectorAll('#storageTopBody tr.storage-top-row');
  let visibleCount = 0;
  rows.forEach(tr => {
    const isSystem = tr.getAttribute('data-is-system') === 'true';
    if (hideSystem && isSystem) {
      tr.style.display = 'none';
      return;
    }
    const text = stripBidi(tr.textContent).toLowerCase();
    const matches = !query || text.includes(query);
    tr.style.display = matches ? '' : 'none';
    if (matches) visibleCount++;
  });
  const countBadge = document.getElementById('storageTopCountBadge');
  if (countBadge && storageTopFiles && storageTopFiles.length > 0) {
    countBadge.textContent = `${visibleCount}`;
  }
}

// -------------------------------------------------------------
// Duplicate Files Finder
// -------------------------------------------------------------
async function runStorageDuplicateScan() {
  const minSizeEl = document.getElementById('storageDupeMinSize');
  const minSize = minSizeEl ? minSizeEl.value : 10;
  const container = document.getElementById('storageDupesContainer');
  if (!container) return;

  container.innerHTML = `<div class="loading text-center" style="padding: 28px;">סורק כפילויות ומחשב Hash...</div>`;

  try {
    const res = await fetch(`/api/storage/duplicates?min_size_mb=${minSize}`);
    const data = await res.json();
    const dupes = data.duplicates || [];

    const wasteBadge = document.getElementById('storageDupesWasteBadge');
    if (dupes.length > 0) {
      const totalWasted = dupes.reduce((sum, d) => sum + d.wasted_bytes, 0);
      if (wasteBadge) {
        wasteBadge.textContent = `${formatBytesJS(totalWasted)} שטח מבוזבז`;
        wasteBadge.classList.remove('hidden');
      }

      container.innerHTML = `
        <div class="stack" style="gap: 12px;">
          ${dupes.map((group, idx) => `
            <div class="card" style="background: var(--panel-2); border: 1px solid var(--line); padding: 12px;">
              <div class="row" style="justify-content: space-between; margin-bottom: 8px;">
                <div class="row" style="gap: 8px;">
                  <span class="badge badge-accent">קבוצה #${idx + 1}</span>
                  <strong>${group.files.length} קבצים זהים (${group.size_formatted} כל אחד)</strong>
                </div>
                <span class="badge badge-warn">מבוזבז: ${group.wasted_formatted}</span>
              </div>
              <div class="table-wrap">
                <table class="data-table">
                  <tbody>
                    ${group.files.map(f => {
                      const isProt = f.is_safe_to_delete === false || f.is_system || isProtectedStoragePath(f.path, f);
                      const isOneDrive = isOneDriveStoragePath(f.path);
                      const oneDriveBadgeHtml = isOneDrive
                        ? `<span class="badge badge-onedrive" style="font-size: 10px; margin-inline-start: 6px; padding: 1px 6px; vertical-align: middle;" title="${esc(t('storageOneDriveTooltip') || 'קובץ מסונכרן בענן של OneDrive')}">☁️ ${esc(t('storageOneDriveBadge') || 'OneDrive')}</span>`
                        : '';
                      const deleteBtn = isProt
                        ? `<button class="btn btn-sm btn-icon btn-disabled" disabled title="קובץ מערכת מוגן - לא ניתן למחיקה" style="opacity: 0.35; cursor: not-allowed; filter: grayscale(1);">🔒</button>`
                        : `<button class="btn btn-sm btn-icon" data-path="${esc(f.path)}" onclick="performStorageActionFromEl(this, 'recycle')" title="העבר לסל המחזור">🗑️</button>`;
                      return `
                        <tr data-node-id="${f.id}">
                          <td class="mono font-bold" style="width: 25%;">${esc(f.name)}${oneDriveBadgeHtml}</td>
                          <td class="mono text-muted text-xs">${esc(f.path)}</td>
                          <td style="width: 110px; text-align: end;">
                            <button class="btn btn-sm btn-icon" data-path="${esc(f.path)}" onclick="performStorageActionFromEl(this, 'reveal')" title="הצג בסייר">📁</button>
                            ${deleteBtn}
                          </td>
                        </tr>
                      `;
                    }).join('')}
                  </tbody>
                </table>
              </div>
            </div>
          `).join('')}
        </div>
      `;
    } else {
      if (wasteBadge) wasteBadge.classList.add('hidden');
      container.innerHTML = `<div class="text-muted text-center" style="padding: 28px;">לא נמצאו קבצים כפולים מעל ${ltrIsolate(minSize + ' MB', true)}.</div>`;
    }
  } catch (err) {
    container.innerHTML = `<div class="text-danger text-center" style="padding: 28px;">שגיאה בסריקת כפילויות: ${esc(err.message)}</div>`;
  }
}

// -------------------------------------------------------------
// Storage Sub-tab Switching
// -------------------------------------------------------------
function switchStorageTab(tabName) {
  activeStorageTab = tabName;
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.id === `tabBtnStorage${capitalize(tabName)}`);
  });
  document.querySelectorAll('.storage-tab-content').forEach(el => {
    el.classList.toggle('hidden', el.id !== `storageTabContent${capitalize(tabName)}`);
  });

  if (tabName === 'treemap') {
    setTimeout(redrawStorageTreemap, 50);
  } else if (tabName === 'sunburst') {
    setTimeout(redrawSunburstChart, 50);
  }
}

function capitalize(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// -------------------------------------------------------------
// Storage Context Menu & File Actions
// -------------------------------------------------------------
function isProtectedStoragePath(path, node = null) {
  if (node) {
    if (node.is_safe_to_delete === false || node.is_system === true) return true;
  }
  if (!path || typeof path !== 'string') return false;
  const p = path.toLowerCase().replace(/\//g, '\\');
  // Bare drive root: C:\, D:\, etc.
  if (/^[a-z]:\\?$/.test(p)) return true;
  // Critical Windows system files on any drive
  const rootSysFiles = [
    'pagefile.sys', 'swapfile.sys', 'hiberfil.sys', 'dumpstack.log',
    'dumpstack.log.tmp', 'memory.dmp', 'bootmgr', 'bootnxt', 'bootstat.dat',
    'ntldr', 'ntdetect.com', 'boot.ini', 'winre.wim'
  ];
  const parts = p.split('\\').filter(Boolean);
  if (parts.length > 0) {
    const filename = parts[parts.length - 1];
    if (rootSysFiles.includes(filename)) return true;
  }
  // Reserved system directory names anywhere in path
  const protectedSegments = [
    'windows', 'system32', 'syswow64', 'winsxs', 'boot', 'recovery',
    'system volume information', '$recycle.bin', '$winreagent',
    '$windows.~bt', '$windows.~ws', '$sysreset'
  ];
  if (parts.some(seg => protectedSegments.includes(seg))) return true;
  return false;
}

function isOneDriveStoragePath(path) {
  if (!path || typeof path !== 'string') return false;
  const p = path.toLowerCase().replace(/\//g, '\\');
  // Exclude OneDrive application binaries/install directories
  if (p.includes('\\appdata\\local\\microsoft\\onedrive') || p.includes('\\program files\\microsoft onedrive') || p.includes('\\program files (x86)\\microsoft onedrive')) {
    return false;
  }
  // Matches sync folder: e.g. \Users\<User>\OneDrive, \OneDrive\, \OneDrive - Organization\
  return /(?:^|[\\/])onedrive(?: - [^\\/]+)?(?:[\\/]|$)/i.test(p);
}

function openStorageContextMenu(e, nodeId, path = "") {
  e.preventDefault();
  // Backstop: id -1 is reserved for synthetic "<N smaller files>" rollup
  // nodes across every caller (treemap, sunburst, tree, top-files table).
  // They must never be actionable, whatever path a caller passed in.
  if (nodeId === -1) return;
  contextTargetNode = { id: nodeId, path: path };

  if (!contextTargetNode.path && storageTreeData) {
    function findNode(node) {
      if (node.id === nodeId) return node;
      if (node.children) {
        for (const c of node.children) {
          const res = findNode(c);
          if (res) return res;
        }
      }
      return null;
    }
    const found = findNode(storageTreeData);
    if (found) {
      contextTargetNode.path = found.path;
      contextTargetNode.is_safe_to_delete = found.is_safe_to_delete;
      contextTargetNode.is_system = found.is_system;
    }
  }

  const isProtected = isProtectedStoragePath(contextTargetNode.path, contextTargetNode);
  const recycleItem = document.getElementById('storageCtxRecycleItem');
  const deleteItem = document.getElementById('storageCtxDeleteItem');
  const protectedItem = document.getElementById('storageCtxProtectedItem');

  if (isProtected) {
    if (recycleItem) recycleItem.classList.add('hidden');
    if (deleteItem) deleteItem.classList.add('hidden');
    if (protectedItem) protectedItem.classList.remove('hidden');
  } else {
    if (recycleItem) recycleItem.classList.remove('hidden');
    if (deleteItem) deleteItem.classList.remove('hidden');
    if (protectedItem) protectedItem.classList.add('hidden');
  }

  const menu = document.getElementById('storageCtxMenu');
  if (!menu) return;

  menu.classList.remove('hidden');
  const x = Math.min(window.innerWidth - 220, e.clientX);
  const y = Math.min(window.innerHeight - 260, e.clientY);
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;

  setTimeout(() => {
    window.addEventListener('click', closeStorageContextMenu, { once: true });
  }, 10);
}

function closeStorageContextMenu() {
  const menu = document.getElementById('storageCtxMenu');
  if (menu) menu.classList.add('hidden');
}

async function onStorageCtxAction(action) {
  closeStorageContextMenu();
  if (!contextTargetNode || !contextTargetNode.path) return;
  const targetPath = contextTargetNode.path;
  const nodeId = contextTargetNode.id;

  if (action === 'copy') {
    navigator.clipboard.writeText(targetPath);
    showToast("העתקה ללוח", "הנתיב הועתק בהצלחה.");
    return;
  }

  await performStorageFileAction(action, targetPath, nodeId);
}

function performStorageActionFromEl(el, action) {
  if (!el) return;
  // Path and node-id are looked up independently: some rows put data-path
  // directly on the button (redundant with the row) but only the row
  // carries data-node-id, so closest() from the button itself would find
  // data-path immediately and never walk up far enough to see the id.
  const pathHost = el.closest('[data-path]');
  const path = pathHost ? (pathHost.getAttribute('data-path') || '') : '';
  const idHost = el.closest('[data-node-id]');
  const nodeIdAttr = idHost ? idHost.getAttribute('data-node-id') : null;
  const nodeId = (nodeIdAttr !== null && nodeIdAttr !== '') ? Number(nodeIdAttr) : undefined;
  if (path) {
    performStorageFileAction(action, path, nodeId);
  }
}

async function performStorageFileAction(action, targetPath, nodeId) {
  let endpointAction = action;
  if (action === 'reveal') endpointAction = 'reveal_in_explorer';
  if (action === 'open') endpointAction = 'open_item';
  if (action === 'cmd') endpointAction = 'open_in_cmd';
  if (action === 'powershell') endpointAction = 'open_in_powershell';
  if (action === 'recycle') endpointAction = 'recycle';
  if (action === 'delete') endpointAction = 'delete_permanent';

  if (endpointAction === 'recycle' || endpointAction === 'delete_permanent') {
    if (isProtectedStoragePath(targetPath)) {
      showToast("פעולה נחסמה", "קובץ מערכת מוגן: לא ניתן למחוק קבצי מערכת של Windows", "warn");
      return;
    }
    if (endpointAction === 'delete_permanent') {
      if (!confirm(`האם אתה בטוח לחלוטין שברצונך למחוק לצמיתות את:\n${targetPath}`)) return;
    } else if (endpointAction === 'recycle') {
      if (!confirm(`להעביר לסל המחזור את:\n${targetPath}?`)) return;
    }
  }

  try {
    // recycle/delete_permanent are resolved server-side against the node id
    // from our own scan, never trusted from the raw path alone - target_path
    // is still sent for the other (non-destructive) actions and as a
    // human-readable fallback message if the id can't be resolved.
    const body = { action: endpointAction, target_path: targetPath };
    if (nodeId !== undefined && nodeId !== null && !Number.isNaN(nodeId)) {
      body.node_id = nodeId;
    }
    const res = await fetch('/api/storage/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (data.success) {
      showToast("פעולה בוצעה", data.message || "הפעולה הושלמה בהצלחה");
      if (endpointAction === 'recycle' || endpointAction === 'delete_permanent') {
        loadStorageResults();
      }
    } else {
      showToast("שגיאה", data.message || "נכשלה הפעולה", "danger");
    }
  } catch (err) {
    showToast("שגיאת תקשורת", err.message, "danger");
  }
}

async function executeStorageQuickClean(action) {
  if (action === 'empty_bin') {
    if (!confirm("האם לרוקן לצמיתות את סל המחזור של Windows?")) return;
    const drive = selectedStorageDrive || 'C:\\';
    showToast("סל המחזור", "מרוקן את סל המחזור...", "accent");
    try {
      const res = await fetch('/api/storage/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'empty_recycle_bin', target_path: drive })
      });
      const data = await res.json();
      if (data.success) {
        showToast("סל המחזור", data.message || "סל המחזור רוקן בהצלחה.");
      } else {
        showToast("שגיאה", data.message || "ריקון סל המחזור נכשל", "danger");
      }
    } catch (err) {
      showToast("שגיאה", err.message, "danger");
    }
  } else if (action === 'launch_cleanmgr') {
    const drive = selectedStorageDrive || 'C:\\';
    try {
      await fetch('/api/storage/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'launch_cleanmgr', target_path: drive })
      });
      showToast("Cleanmgr", "כלי הניקוי של Windows הופעל");
    } catch (err) {
      showToast("שגיאה", err.message, "danger");
    }
  } else if (action === 'query_vss') {
    try {
      const res = await fetch('/api/storage/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'get_vss_storage', target_path: 'C:\\' })
      });
      const data = await res.json();
      alert(data.message || "לא נמצא מידע על צלליות VSS");
    } catch (err) {
      showToast("שגיאה", err.message, "danger");
    }
  } else if (action === 'reveal_drive') {
    const drive = selectedStorageDrive || 'C:\\';
    performStorageFileAction('reveal', drive);
  }
}

function exportStorageReport(format) {
  window.open(`/api/storage/export?format=${format}`, '_blank');
}

function formatBytesJS(bytes) {
  return ltrIsolate(formatBytesRawJS(bytes), true);
}

// Plain "8.20 GB" - for exports, sorting keys and anything that is not displayed
// inside the RTL document.
function formatBytesRawJS(bytes) {
  if (bytes === null || bytes === undefined || isNaN(bytes)) return '0 B';
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.max(0, Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024))));
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

// -------------------------------------------------------------
// Remote Control & Auto-Updater Engine
// -------------------------------------------------------------
window._isAppKilled = false;
window._isMandatoryUpdate = false;
window._latestRemoteUpdate = null;
let updateDownloadPollTimer = null;

async function checkRemoteControlStatus(force = false) {
  try {
    const res = await fetch(`/api/remote_control/status?force=${force ? 'true' : 'false'}`);
    const data = await res.json();
    handleRemoteControlData(data);
    return data;
  } catch (err) {
    console.warn("Remote control check error:", err);
    return null;
  }
}

function handleRemoteControlData(data) {
  if (!data) return;

  // 1. Kill Switch Evaluation
  if (data.is_killed) {
    window._isAppKilled = true;
    triggerKillSwitch(data.kill_info || {});
    return;
  } else {
    window._isAppKilled = false;
    const killModal = document.getElementById('killSwitchModal');
    if (killModal) killModal.classList.add('hidden');
  }

  // 2. Update Evaluation
  const updateInfo = data.update_info || {};
  window._currentAppVersion = data.current_version || '3.1.0';
  window._latestRemoteUpdate = updateInfo;
  window._isMandatoryUpdate = !!updateInfo.mandatory;

  const btnIndicator = document.getElementById('btnUpdateIndicator');
  const indicatorText = document.getElementById('updateIndicatorText');
  const alertBox = document.getElementById('settingsUpdateAlertBox');
  const statusBadge = document.getElementById('settingsUpdateStatusBadge');
  const lastChecked = document.getElementById('settingsLastCheckedTime');
  const verDisplay = document.getElementById('settingsCurrentVersionDisplay');
  const inputUrl = document.getElementById('inputControlUrl');

  if (verDisplay && data.current_version) {
    verDisplay.textContent = data.current_version;
  }
  if (lastChecked && data.last_checked_iso) {
    lastChecked.textContent = data.last_checked_iso;
  }
  if (inputUrl && data.control_url && !inputUrl.value) {
    inputUrl.value = data.control_url;
  }

  if (data.has_update) {
    if (btnIndicator) {
      btnIndicator.classList.remove('hidden');
      if (indicatorText) indicatorText.textContent = `עדכון חדש: v${updateInfo.latest_version}`;
    }
    if (alertBox) {
      alertBox.classList.remove('hidden');
      const desc = document.getElementById('settingsUpdateAlertDesc');
      if (desc) desc.textContent = `גרסה ${updateInfo.latest_version} זמינה להורדה ישירה מ-GitHub Releases.`;
    }
    if (statusBadge) {
      statusBadge.innerHTML = `<span class="badge badge-warn" style="font-weight: 600;">זמין עדכון ${updateInfo.latest_version}</span>`;
    }

    // Auto-open update modal if mandatory
    if (window._isMandatoryUpdate) {
      openUpdateModal();
    }
  } else {
    if (btnIndicator) btnIndicator.classList.add('hidden');
    if (alertBox) alertBox.classList.add('hidden');
    if (statusBadge) {
      statusBadge.innerHTML = `<span class="badge badge-success">מעודכן לגרסה האחרונה</span>`;
    }
  }

  // 3. Optional Broadcast Announcement
  if (data.broadcast_message && data.broadcast_message.active && data.broadcast_message.message_he) {
    const bId = `polaris_bcast_${data.broadcast_message.id}`;
    if (!localStorage.getItem(bId)) {
      showToast(data.broadcast_message.title_he || "הודעת מערכת", data.broadcast_message.message_he, data.broadcast_message.level || "info");
      localStorage.setItem(bId, '1');
    }
  }
}

function triggerKillSwitch(killInfo) {
  const modal = document.getElementById('killSwitchModal');
  const title = document.getElementById('killSwitchTitle');
  const msg = document.getElementById('killSwitchMessage');

  if (title && killInfo.title_he) title.textContent = killInfo.title_he;
  if (msg && killInfo.message_he) msg.textContent = killInfo.message_he;

  if (modal) modal.classList.remove('hidden');
}

async function exitPolaris() {
  try {
    const btn = document.querySelector('#killSwitchModal button');
    if (btn) {
      btn.disabled = true;
      btn.style.opacity = '0.7';
      btn.innerHTML = '<span>סוגר את התוכנה...</span>';
    }
  } catch (e) {}

  try {
    fetch('/api/exit', { method: 'POST' }).catch(() => {});
    fetch('/api/exit').catch(() => {});
  } catch (e) {}

  try {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/exit', true);
    xhr.send();
  } catch (e) {}

  setTimeout(() => {
    try { window.close(); } catch (e) {}
  }, 200);
}

function openUpdateModal() {
  const modal = document.getElementById('updateModal');
  if (!modal) return;

  const currentVerEl = document.getElementById('updateCurrentVer');
  const newVerEl = document.getElementById('updateNewVer');
  const notesEl = document.getElementById('updateReleaseNotes');
  const closeBtn = document.getElementById('btnCloseUpdateModal');
  const laterBtn = document.getElementById('btnUpdateLater');

  const update = window._latestRemoteUpdate || {};
  if (currentVerEl) currentVerEl.textContent = window._currentAppVersion || '3.1.0';
  if (newVerEl) newVerEl.textContent = update.latest_version || '3.2.0';
  if (notesEl) notesEl.textContent = update.release_notes_he || 'עדכון גרסה שוטף מ-GitHub Releases.';

  if (window._isMandatoryUpdate) {
    if (closeBtn) closeBtn.style.display = 'none';
    if (laterBtn) laterBtn.style.display = 'none';
  } else {
    if (closeBtn) closeBtn.style.display = '';
    if (laterBtn) laterBtn.style.display = '';
  }

  modal.classList.remove('hidden');
  modal.style.display = 'flex';
}

function closeUpdateModal() {
  if (window._isMandatoryUpdate) return;
  const modal = document.getElementById('updateModal');
  if (modal) {
    modal.classList.add('hidden');
    modal.style.display = 'none';
  }
}

async function startUpdateDownload() {
  const startBtn = document.getElementById('btnStartDownloadUpdate');
  const progressSec = document.getElementById('updateProgressSection');
  const statusText = document.getElementById('updateProgressStatusText');
  const percentEl = document.getElementById('updateProgressPercent');
  const barEl = document.getElementById('updateProgressBar');
  const sizeInfo = document.getElementById('updateSizeInfo');
  const applyBtn = document.getElementById('btnApplyUpdateNow');

  if (startBtn) {
    startBtn.disabled = true;
    startBtn.innerHTML = `<span>מתחיל הורדה...</span>`;
  }
  if (progressSec) progressSec.classList.remove('hidden');

  try {
    const res = await fetch('/api/remote_control/start_download', { method: 'POST' });
    const data = await res.json();
    if (!data.success) {
      showToast("שגיאה בהורדה", data.message, "danger");
      if (startBtn) {
        startBtn.disabled = false;
        startBtn.innerHTML = `<span>הורד והתקן עדכון עכשיו</span>`;
      }
      return;
    }

    if (updateDownloadPollTimer) clearInterval(updateDownloadPollTimer);
    updateDownloadPollTimer = setInterval(async () => {
      try {
        const pRes = await fetch('/api/remote_control/update_progress');
        const p = await pRes.json();

        if (percentEl) percentEl.textContent = `${p.percent}%`;
        if (barEl) barEl.style.width = `${p.percent}%`;

        if (p.total_bytes > 0 && sizeInfo) {
          const mbDown = (p.downloaded_bytes / (1024 * 1024)).toFixed(1);
          const mbTotal = (p.total_bytes / (1024 * 1024)).toFixed(1);
          sizeInfo.textContent = `${mbDown} MB מתוך ${mbTotal} MB`;
        }

        if (p.status === 'downloading') {
          if (statusText) statusText.textContent = `מוריד עדכון מ-GitHub Releases... (${p.percent}%)`;
        } else if (p.status === 'verifying') {
          if (statusText) statusText.textContent = "מאמת שלמות קובץ וחתימת אבטחה...";
        } else if (p.status === 'ready') {
          clearInterval(updateDownloadPollTimer);
          updateDownloadPollTimer = null;
          if (statusText) statusText.textContent = "הקובץ מוכן להתקנה! לחץ להפעלה מחדש.";
          if (startBtn) startBtn.classList.add('hidden');
          if (applyBtn) applyBtn.classList.remove('hidden');
          showToast("העדכון מוכן", "קובץ העדכון הורד בהצלחה. לחץ להפעלה מחדש.", "success");
        } else if (p.status === 'error') {
          clearInterval(updateDownloadPollTimer);
          updateDownloadPollTimer = null;
          if (statusText) statusText.textContent = `שגיאה: ${p.error}`;
          if (startBtn) {
            startBtn.disabled = false;
            startBtn.innerHTML = `<span>נסה שוב</span>`;
          }
          showToast("שגיאה בהורדת עדכון", p.error, "danger");
        }
      } catch (pollErr) {
        console.warn("Poll error:", pollErr);
      }
    }, 450);

  } catch (err) {
    showToast("שגיאה", err.message, "danger");
    if (startBtn) {
      startBtn.disabled = false;
      startBtn.innerHTML = `<span>הורד והתקן עדכון עכשיו</span>`;
    }
  }
}

async function applyUpdateRestart() {
  const applyBtn = document.getElementById('btnApplyUpdateNow');
  if (applyBtn) {
    applyBtn.disabled = true;
    applyBtn.innerHTML = `<span>מפעיל מחדש...</span>`;
  }
  showToast("מעדכן", "מפעיל את התוכנה מחדש עם הגרסה העדכנית...", "info");

  try {
    const res = await fetch('/api/remote_control/apply_update', { method: 'POST' });
    const data = await res.json();
    if (!data.success) {
      showToast("שגיאה בהחלת עדכון", data.message, "danger");
      if (applyBtn) applyBtn.disabled = false;
    }
  } catch (err) {
    // In frozen mode the server drops and terminates as the batch restarts it
  }
}

async function checkRemoteUpdates(manual = true) {
  const btn = document.getElementById('btnCheckUpdatesNow');
  if (btn && manual) {
    btn.disabled = true;
    btn.classList.add('is-busy');
  }

  const data = await checkRemoteControlStatus(true);

  if (btn && manual) {
    btn.disabled = false;
    btn.classList.remove('is-busy');
  }

  if (manual) {
    if (!data || data.offline) {
      showToast("בדיקת עדכונים", "לא ניתן היה ליצור קשר עם שרת הבקרה (בדוק חיבור אינטרנט או כתובת).", "warn");
    } else if (data.is_killed) {
      showToast("אבטחה", "התוכנה הושבתה על ידי המפתח.", "danger");
    } else if (data.has_update) {
      showToast("עדכון זמין!", `נמצא עדכון גרסה חדש: ${data.update_info.latest_version}`, "success");
      openUpdateModal();
    } else {
      showToast("התוכנה מעודכנת", `הגרסה שברשותך (${data.current_version}) היא הגרסה העדכנית ביותר.`, "success");
    }
  }
}

async function saveControlUrl() {
  const input = document.getElementById('inputControlUrl');
  if (!input) return;
  const newUrl = input.value.trim();

  try {
    const res = await fetch('/api/remote_control/set_url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: newUrl })
    });
    const data = await res.json();
    if (data.success) {
      showToast("כתובת נשמרה", "כתובת הבקרה מרחוק עודכנה ונשמרה בהצלחה.", "success");
      handleRemoteControlData(data.status);
    } else {
      showToast("שגיאה", "שמירת הכתובת נכשלה.", "danger");
    }
  } catch (err) {
    showToast("שגיאה", err.message, "danger");
  }
}

function resetDefaultControlUrl() {
  const input = document.getElementById('inputControlUrl');
  if (input) {
    input.value = "https://gist.githubusercontent.com/Hero-Ghost/22bc7b324e2a5118384d3413490ef636/raw/app_control.json";
    saveControlUrl();
  }
}
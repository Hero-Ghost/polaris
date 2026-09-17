"""
Polaris - Revo-Grade Advanced Uninstaller Engine
Deep filesystem, registry, service, task, and driver residual cleaner
with full registry export rollback and VSS restore-point safety.

Safety model
------------
Nothing is ever deleted because a caller asked for a path. Two gates stand in
front of every destructive operation:

  1. **Provenance** - only items this engine itself produced during a scan can
     be deleted. The HTTP layer sends opaque item ids; the engine resolves them
     against its own scan index and uses *its* copy of the record. A crafted
     request naming ``C:\\Windows`` cannot reach the filesystem code at all.
  2. **Static validation** - even an engine-produced item is re-validated
     against the protected-path tables right before deletion, so a scanner bug
     cannot turn into data loss.

Everything reports what actually happened. A registry key that could not be
deleted for lack of Administrator rights is counted as a failure, not as a
success, and a locked folder is reported as pending-reboot rather than "clean".
"""

import os
import re
import json
import time
import shutil
import ctypes
import threading
import subprocess
import hashlib
from datetime import datetime

from backend.win_utils import (
    IS_WINDOWS, run_hidden, popen_hidden, run_powershell_json,
    is_admin, format_bytes, reveal_in_explorer
)

# winreg exists only on Windows. Importing it unconditionally used to take the
# whole server down on any other platform (fixed in v2.6, regressed here, fixed
# again): every call site already guards on `winreg is None`.
try:
    import winreg
except ImportError:  # pragma: no cover - Windows-only module
    winreg = None

try:
    import psutil
except ImportError:  # pragma: no cover - optional at import time
    psutil = None

# Constants for Windows API
MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Base storage for uninstaller backups
BACKUP_BASE_DIR = os.path.join(
    os.environ.get('LOCALAPPDATA', os.path.expanduser('~')),
    'Polaris', 'UninstallerBackups'
)

# A leftover shallower than this many path components below the drive letter is
# refused. C:\Program Files\Acme passes (2); C:\Acme does not. The cost is that
# a portable app installed directly on the drive root has to be removed by hand;
# the benefit is that no scanner bug can ever hand rmtree a top-level folder.
MIN_DELETE_DEPTH = 2

# HIVE + at least two components, so HKLM\SOFTWARE\Acme passes but
# HKLM\SOFTWARE does not.
MIN_REG_DEPTH = 3

# Recursion guard for registry tree deletion.
MAX_REG_DEPTH = 32

# Ceiling on how long we wait for a native uninstaller the user launched.
NATIVE_UNINSTALL_MAX_WAIT = 3600

# The published plan for an uninstall run. Weights are relative durations and
# are recalibrated against the real pace to produce the ETA, exactly as the
# maintenance centre does - so a step that turns out slow pushes the estimate
# instead of freezing the bar.
UNINSTALL_STEPS = [
    {
        "id": "restore_point",
        "title_he": "נקודת שחזור מערכת",
        "title_en": "System restore point",
        "explain_he": "מצלם את מצב המערכת כדי שתהיה דרך חזרה אם ההסרה תשתבש.",
        "explain_en": "Snapshots the system so the uninstall can be rolled back.",
        "weight": 22, "est_seconds": 35,
    },
    {
        "id": "registry_backup",
        "title_he": "גיבוי ענפי רישום",
        "title_en": "Registry backup",
        "explain_he": "מייצא את מפתחות הרישום של התוכנה לקובץ .reg לפני שנוגעים בהם.",
        "explain_en": "Exports the app's registry keys to a .reg file before touching them.",
        "weight": 4, "est_seconds": 3,
    },
    {
        "id": "native_uninstall",
        "title_he": "מסיר התוכנה המקורי",
        "title_en": "Native uninstaller",
        "explain_he": "מריץ את ההסרה של היצרן עצמו — הדרך הנקייה ביותר להסיר תוכנה.",
        "explain_en": "Runs the vendor's own uninstaller, the cleanest way to remove software.",
        "weight": 40, "est_seconds": 50,
    },
    {
        "id": "scan_registry",
        "title_he": "סריקת שאריות ברישום",
        "title_en": "Registry leftover scan",
        "explain_he": "מחפש מפתחות, ערכי הפעלה אוטומטית ורישומי COM שנשארו מאחור.",
        "explain_en": "Looks for keys, autostart values and COM registrations left behind.",
        "weight": 17, "est_seconds": 10,
    },
    {
        "id": "scan_files",
        "title_he": "סריקת שאריות בדיסק",
        "title_en": "Filesystem leftover scan",
        "explain_he": "מחפש תיקיות הגדרות, נתונים וקיצורי דרך שנשארו על הדיסק.",
        "explain_en": "Looks for leftover settings folders, data and shortcuts.",
        "weight": 17, "est_seconds": 10,
    },
]
STEP_BY_ID = {s["id"]: s for s in UNINSTALL_STEPS}

MAX_LOG_LINES = 1200

# System stop words to prevent broad matching of core OS components
SYSTEM_STOP_WORDS = {
    "setup", "the", "version", "win32", "x64", "x86", "edition", "release",
    "microsoft", "windows", "system", "system32", "program", "programs",
    "desktop", "update", "updater", "updates", "service", "services", "server",
    "runtime", "common", "files", "shared", "package", "packages", "installer",
    "installation", "tool", "tools", "app", "apps", "application", "applications",
    "data", "corporation", "inc", "ltd", "llc", "technologies", "technology",
    "software", "support", "framework", "redistributable", "component",
    "components", "client", "driver", "drivers", "security", "securityfix",
    "hotfix", "patch", "preview", "build", "platform", "standard", "professional",
    "enterprise", "ultimate", "home", "basic", "core"
}

# Critical registry keys that must NEVER be flagged as removable leftovers
PROTECTED_REG_SUBKEYS = {
    "microsoft", "windows", "windows nt", "windows mail", "windows media",
    "windows defender", "windows security", "classes", "policies",
    "registeredapplications", "system", "currentcontrolset", "services",
    "hardware", "sam", "security", "software", "wow6432node"
}

# Critical system directories that must NEVER be flagged as removable leftovers
PROTECTED_FOLDER_NAMES = {
    "windows", "system32", "syswow64", "program files", "program files (x86)",
    "common files", "microsoft", "microsoft shared", "users", "appdata",
    "local", "locallow", "roaming", "localappdata", "programdata",
    "start menu", "programs", "desktop", "documents", "downloads",
    "system tools", "accessories", "administrative tools", "startup"
}

# Registry branches that may be *read from* and have single values removed, but
# may never be deleted as a whole.
PROTECTED_REG_PATHS = {
    "hklm", "hkcu", "hkcr", "hku",
    "hklm\\software",
    "hklm\\software\\wow6432node",
    "hklm\\software\\microsoft",
    "hklm\\software\\wow6432node\\microsoft",
    "hklm\\software\\classes",
    "hklm\\software\\classes\\clsid",
    "hklm\\software\\classes\\installer",
    "hklm\\software\\classes\\installer\\products",
    "hklm\\software\\classes\\wow6432node",
    "hklm\\software\\classes\\wow6432node\\clsid",
    "hklm\\software\\microsoft\\windows",
    "hklm\\software\\microsoft\\windows\\currentversion",
    "hklm\\software\\microsoft\\windows\\currentversion\\run",
    "hklm\\software\\microsoft\\windows\\currentversion\\runonce",
    "hklm\\software\\microsoft\\windows\\currentversion\\uninstall",
    "hklm\\software\\microsoft\\windows\\currentversion\\app paths",
    "hklm\\software\\microsoft\\windows\\currentversion\\shareddlls",
    "hklm\\software\\microsoft\\windows\\currentversion\\installer",
    "hklm\\software\\wow6432node\\microsoft\\windows",
    "hklm\\software\\wow6432node\\microsoft\\windows\\currentversion",
    "hklm\\software\\wow6432node\\microsoft\\windows\\currentversion\\run",
    "hklm\\software\\wow6432node\\microsoft\\windows\\currentversion\\uninstall",
    "hklm\\system",
    "hklm\\system\\currentcontrolset",
    "hklm\\system\\currentcontrolset\\services",
    "hklm\\system\\currentcontrolset\\control",
    "hklm\\sam", "hklm\\security", "hklm\\hardware",
    "hkcu\\software",
    "hkcu\\software\\microsoft",
    "hkcu\\software\\classes",
    "hkcu\\software\\microsoft\\windows",
    "hkcu\\software\\microsoft\\windows\\currentversion",
    "hkcu\\software\\microsoft\\windows\\currentversion\\run",
    "hkcu\\software\\microsoft\\windows\\currentversion\\runonce",
    "hkcu\\software\\microsoft\\windows\\currentversion\\uninstall",
    "hkcu\\software\\microsoft\\windows\\currentversion\\app paths",
    "hkcu\\software\\classes\\local settings",
}

# Services and drivers Windows cannot survive without. Deliberately
# over-inclusive: a missed leftover service is an annoyance, a deleted one is a
# machine that does not boot.
CRITICAL_SERVICE_NAMES = {
    "rpcss", "dcomlaunch", "lsm", "power", "plugplay", "winmgmt", "eventlog",
    "schedule", "w32time", "wuauserv", "bits", "cryptsvc", "dnscache",
    "lanmanserver", "lanmanworkstation", "netlogon", "nsi", "profsvc", "samss",
    "termservice", "trustedinstaller", "windefend", "wdnissvc", "wscsvc",
    "msiserver", "dhcp", "audiosrv", "audioendpointbuilder", "eventsystem",
    "gpsvc", "pcasvc", "seclogon", "shellhwdetection", "sysmain", "themes",
    "usosvc", "wlansvc", "wpdbusenum", "bfe", "mpssvc", "nlasvc", "ikeext",
    "policyagent", "netman", "wcmsvc", "dot3svc", "eaphost", "rasman",
    "sstpsvc", "appinfo", "usermanager", "staterepository",
    "disk", "volmgr", "volmgrx", "volsnap", "ntfs", "partmgr", "storahci",
    "stornvme", "storufs", "pci", "acpi", "ksecdd", "ksecpkg", "cng", "fltmgr",
    "mup", "tcpip", "tcpip6", "netbt", "afd", "http", "wanarp", "atapi",
    "usbhub", "usbxhci", "usbstor", "hidusb", "hidclass", "kbdclass",
    "mouclass", "kbdhid", "mouhid", "npfs", "msfs", "srv", "srv2", "srvnet",
    "rdbss", "wof", "wcifs", "bindflt", "cldflt", "fvevol", "rdyboost",
    "iorate", "wdfilter", "luafv", "filecrypt", "applockerfltr", "bam", "dam",
    "pdc", "vdrvroot", "spaceport", "storqosflt", "fileinfo", "clfs",
    "condrv", "null", "beep", "cdrom", "cdfs", "exfat", "fastfat", "refs",
}


def _norm_win_path(path):
    """
    Normalizes a Windows path for comparison purposes only, without touching the
    filesystem and without depending on the host OS. Deliberately not
    os.path.normcase/abspath: those are no-ops (or worse, cwd-relative) on
    Linux, where this module's tests run.
    """
    if not path or not isinstance(path, str):
        return ""
    p = path.strip().strip('"').replace('/', '\\')
    is_unc = p.startswith('\\\\')
    p = re.sub(r'\\{2,}', '\\\\', p)
    if is_unc:
        p = '\\' + p
    return p.rstrip('\\').lower()


def _norm_reg_path(path):
    """Normalizes a registry path and canonicalizes long hive names to short."""
    if not path or not isinstance(path, str):
        return ""
    p = path.strip().strip('"').replace('/', '\\')
    p = re.sub(r'\\{2,}', '\\\\', p).strip('\\').lower()
    aliases = (
        ("hkey_local_machine", "hklm"),
        ("hkey_current_user", "hkcu"),
        ("hkey_classes_root", "hkcr"),
        ("hkey_users", "hku"),
    )
    for long_name, short in aliases:
        if p == long_name or p.startswith(long_name + "\\"):
            p = short + p[len(long_name):]
            break
    return p


def _build_protected_abs_paths():
    """The concrete directories on *this* machine that must never be deleted."""
    roots = set()

    def add(p):
        n = _norm_win_path(p)
        if n:
            roots.add(n)

    win = os.environ.get('SystemRoot', r'C:\Windows')
    pf = os.environ.get('ProgramFiles', r'C:\Program Files')
    pf86 = os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')
    pdata = os.environ.get('ProgramData', r'C:\ProgramData')
    appdata = os.environ.get('APPDATA', '')
    localapp = os.environ.get('LOCALAPPDATA', '')
    profile = os.environ.get('USERPROFILE', '')

    for p in (win, pf, pf86, pdata, appdata, localapp, profile,
              os.environ.get('PUBLIC', r'C:\Users\Public')):
        add(p)

    add(os.path.join(win, 'System32'))
    add(os.path.join(win, 'SysWOW64'))
    add(os.path.join(pf, 'Common Files'))
    add(os.path.join(pf86, 'Common Files'))
    add(os.path.join(pf, 'WindowsApps'))
    add(os.path.join(pf86, 'WindowsApps'))
    add(os.path.join(pdata, 'Microsoft'))
    add(os.path.join(pdata, r'Microsoft\Windows\Start Menu\Programs'))

    if localapp:
        add(os.path.join(localapp, 'Temp'))
        add(os.path.join(localapp, 'Microsoft'))
        add(os.path.join(localapp, 'Packages'))
    if appdata:
        add(os.path.join(appdata, 'Microsoft'))
        add(os.path.join(appdata, r'Microsoft\Windows\Start Menu\Programs'))
    if profile:
        add(os.path.dirname(profile))  # C:\Users
        for sub in ('Desktop', 'Documents', 'Downloads', 'Pictures', 'Music',
                    'Videos', 'Favorites', 'Links', 'Contacts', 'Searches',
                    'Saved Games', 'OneDrive', 'AppData'):
            add(os.path.join(profile, sub))
    else:
        add(r'C:\Users')

    return roots


PROTECTED_ABS_PATHS = _build_protected_abs_paths()


def is_path_safe_to_delete(path, protected=None):
    """
    Gatekeeper for every filesystem deletion.

    Returns (ok: bool, reason: str|None). Pure string logic, so it is unit
    testable on any platform.
    """
    protected = PROTECTED_ABS_PATHS if protected is None else protected

    if not path or not isinstance(path, str):
        return False, "נתיב ריק"
    if any(ch in path for ch in '*?'):
        return False, "נתיב מכיל תווים כלליים (wildcard)"
    if '%' in path:
        return False, "נתיב מכיל משתנה סביבה שלא הורחב"

    norm = _norm_win_path(path)
    if not norm:
        return False, "נתיב ריק"
    if norm.startswith('\\\\'):
        return False, "נתיב רשת (UNC) אינו נתמך למחיקה"
    if not re.match(r'^[a-z]:\\', norm):
        return False, "נדרש נתיב מוחלט עם אות כונן"

    parts = [p for p in norm.split('\\')[1:] if p]
    if len(parts) < MIN_DELETE_DEPTH:
        return False, "נתיב רדוד מדי (שורש כונן או תיקייה ראשית)"
    if norm in protected:
        return False, "תיקיית מערכת מוגנת"
    for prot in protected:
        if prot.startswith(norm + '\\'):
            return False, "הנתיב מכיל בתוכו תיקיית מערכת מוגנת"
    if parts[-1] in PROTECTED_FOLDER_NAMES:
        return False, "שם תיקייה שמור למערכת"
    if any(p.lower() == 'windowsapps' for p in parts):
        return False, "חבילת מערכת/חנות (WindowsApps) — לא ניתנת למחיקה ישירה מהדיסק; יש להסירה באמצעות Remove-AppxPackage"

    return True, None


def is_reg_path_safe_to_delete(path):
    """Gatekeeper for registry *key tree* deletion. Returns (ok, reason)."""
    if not path or not isinstance(path, str):
        return False, "נתיב רישום ריק"

    norm = _norm_reg_path(path)
    if not norm:
        return False, "נתיב רישום ריק"

    hive = norm.split('\\', 1)[0]
    if hive not in ("hklm", "hkcu", "hkcr"):
        return False, "כוורת רישום לא נתמכת"

    parts = [p for p in norm.split('\\') if p]
    if len(parts) < MIN_REG_DEPTH:
        return False, "ענף רישום רדוד מדי"
    if norm in PROTECTED_REG_PATHS:
        return False, "ענף רישום קריטי של מערכת ההפעלה"
    for prot in PROTECTED_REG_PATHS:
        if prot.startswith(norm + '\\'):
            return False, "הענף מכיל בתוכו ענף רישום קריטי"

    services_root = "hklm\\system\\currentcontrolset\\services\\"
    if norm.startswith(services_root):
        svc = norm[len(services_root):].split('\\', 1)[0]
        if svc in CRITICAL_SERVICE_NAMES:
            return False, "שירות או דרייבר חיוני של Windows"

    return True, None


def to_uninstall_command(cmd_string):
    """
    Turns an UninstallString into a command that actually *uninstalls*.

    Many MSI products register ``MsiExec.exe /I{GUID}``. Running that verbatim
    repairs the product instead of removing it, which is why batch uninstall
    used to report success while changing nothing. Only the install switch is
    rewritten - the rest of the command, including its casing and any quoted
    path containing "/i", is left untouched.
    """
    if not cmd_string or not isinstance(cmd_string, str):
        return ""
    if 'msiexec' not in cmd_string.lower():
        return cmd_string
    if re.search(r'[/-]\s*[xX](?=[\s{"]|$)', cmd_string):
        return cmd_string  # already an uninstall
    return re.sub(r'[/-]\s*[iI](?=[\s{"])', '/x', cmd_string, count=1)


def to_silent_command(cmd_string):
    """Appends the silent/no-restart switches for the known installer families."""
    if not cmd_string or not isinstance(cmd_string, str):
        return ""
    low = cmd_string.lower()
    if 'msiexec' in low:
        if '/qn' not in low and '/quiet' not in low and '/passive' not in low:
            cmd_string += ' /qn'
        if '/norestart' not in low:
            cmd_string += ' /norestart'
    elif re.search(r'unins\d*\.exe', low):  # Inno Setup: unins000, unins001, ...
        if '/verysilent' not in low and '/silent' not in low:
            cmd_string += ' /VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
    elif 'uninstall.exe' in low or 'uninst.exe' in low:  # NSIS
        if ' /s' not in low:
            cmd_string += ' /S'
    return cmd_string


def make_item_id(item):
    """
    Stable identity for a leftover.

    Includes the *name*, not just the path: two autostart values living under
    the same Run key share a path, and keying the UI selection on the path alone
    used to collapse them into a single checkbox that deleted both.
    """
    raw = "{}|{}|{}".format(
        (item.get('type') or ''),
        _norm_win_path(item.get('path') or '') or (item.get('path') or '').lower(),
        (item.get('name') or '').lower(),
    )
    return hashlib.sha1(raw.encode('utf-8', 'replace')).hexdigest()[:16]


class UninstallerEngine:
    """
    Core engine providing full Revo Uninstaller feature parity:
    - 64-bit & 32-bit Win32 + Modern UWP/MSIX package enumeration
    - Multi-tier safety (System Restore Point, Registry Hive Backup, Session Logging)
    - Active Skip control for restore points & native uninstallers
    - Process tree monitoring for native uninstallers
    - Heuristic Leftover Scanning (Safe, Moderate, Advanced modes)
    - Shared DLLs Reference Counting protection
    - Bold-marking selective tree deletion
    - Forced Uninstall for damaged / unlisted applications
    - Quick / Batch Uninstall with automatic silent switches
    - Hunter Mode target resolution and execution control
    - Backup Center with full & surgical rollback
    """

    def __init__(self):
        # Reentrant: the logging and step helpers take this lock and are called
        # from inside code that already holds it.
        self._lock = threading.RLock()
        self.active_session = None
        self._skip_requested = threading.Event()
        self._busy = False
        self.cached_apps = []
        self.last_apps_fetch = 0
        # Items this engine produced in recent scans, keyed by id. Only these
        # can ever be deleted.
        self._scan_index = {}

        # ---- live log & step plan (mirrors the maintenance centre) ----------
        self.live_logs = []
        self._log_uid = 0   # stable identity of a row, never reused
        self._log_rev = 0   # bumped on create AND on in-place update
        self._last_log_at = 0.0
        self._steps = []
        self._step_fraction = {}
        self._started_at = None
        self._stop_heartbeat = threading.Event()
        self._heartbeat_thread = None
        # Which run the published plan belongs to, so a forced scan's steps are
        # never mistaken for the wizard session's.
        self._steps_owner = None

        # Background pre-warm on engine startup so apps are ready immediately
        threading.Thread(target=self._prewarm_cache, daemon=True).start()

    def _prewarm_cache(self):
        try:
            time.sleep(3.0)
            self.get_installed_apps(force_refresh=True)
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # 0. Live log & step plan
    # -------------------------------------------------------------------------
    def log(self, message, level="INFO", replace_key=None):
        """
        Appends a line to the live terminal.

        `replace_key` makes a line self-updating, so a counter ("נסרקו 1,400
        מפתחות") redraws one row instead of flooding the terminal. Rows carry a
        stable `uid` plus a `rev` that also bumps on an in-place edit, so a
        polling client can ask for "everything newer than rev N" and still be
        handed edits to a row it already drew.
        """
        ts = time.strftime("%H:%M:%S")
        with self._lock:
            self._log_rev += 1
            if replace_key and self.live_logs:
                for entry in reversed(self.live_logs[-12:]):
                    if entry.get("key") != replace_key:
                        continue
                    entry["time"] = ts
                    entry["text"] = message
                    entry["level"] = level
                    entry["rev"] = self._log_rev
                    self._last_log_at = time.time()
                    return
            self._log_uid += 1
            self.live_logs.append({
                "uid": self._log_uid,
                "rev": self._log_rev,
                "time": ts,
                "level": level,
                "text": message,
                "key": replace_key,
            })
            if len(self.live_logs) > MAX_LOG_LINES:
                self.live_logs.pop(0)
            self._last_log_at = time.time()

    def _reset_run_state(self, owner=None):
        # Stop and *join* any heartbeat still running before clearing the event,
        # otherwise a thread caught mid-iteration never sees the stop and keeps
        # writing into the new run's log alongside its replacement.
        self._stop_heartbeat.set()
        old = self._heartbeat_thread
        if old is not None and old.is_alive():
            old.join(timeout=4.0)
        with self._lock:
            self.live_logs = []
            self._log_uid = 0
            self._log_rev = 0
            self._steps = []
            self._step_fraction = {}
            self._started_at = time.time()
            self._steps_owner = owner
            self._heartbeat_thread = None
            # Otherwise the first heartbeat of a new run measures its silence
            # against the last line of the previous one.
            self._last_log_at = time.time()
        self._stop_heartbeat.clear()

    def _start_heartbeat(self):
        t = threading.Thread(target=self._heartbeat_loop, daemon=True)
        with self._lock:
            self._heartbeat_thread = t
        t.start()
        return t

    def _plan_steps(self, skip_restore_point, skip_registry_backup, is_uwp,
                    force_skip_native=False, native_skip_reason=""):
        """Publishes the plan before anything runs, including what is skipped."""
        plan = []
        for meta in UNINSTALL_STEPS:
            status = "pending"
            detail_he = ""
            if meta["id"] == "restore_point" and skip_restore_point:
                status, detail_he = "skipped", "לא נבחר על ידך"
            elif meta["id"] == "registry_backup" and (skip_registry_backup or is_uwp):
                status, detail_he = "skipped", ("לא נבחר על ידך" if skip_registry_backup
                                                else "אפליקציית Store — אין מפתח רישום קלאסי")
            elif meta["id"] == "native_uninstall" and force_skip_native:
                status, detail_he = "skipped", native_skip_reason or "אין מסיר מקורי להריץ"
            plan.append({
                "id": meta["id"],
                "title_he": meta["title_he"],
                "title_en": meta["title_en"],
                "explain_he": meta["explain_he"],
                "explain_en": meta["explain_en"],
                "est_seconds": meta["est_seconds"],
                "status": status,
                "detail_he": detail_he,
                "started_at": None,
            })
        with self._lock:
            self._steps = plan

        self.log("[PLAN] תוכנית הריצה:", "STEP")
        for s in plan:
            mark = "–" if s["status"] == "skipped" else "•"
            suffix = f" (דולג — {s['detail_he']})" if s["status"] == "skipped" else f" (~{s['est_seconds']} שניות)"
            self.log(f"[PLAN]   {mark} {s['title_he']}{suffix}", "PLAN")

    def _find_step(self, step_id):
        for s in self._steps:
            if s["id"] == step_id:
                return s
        return None

    def _begin_step(self, step_id):
        with self._lock:
            s = self._find_step(step_id)
            if not s or s["status"] == "skipped":
                return False
            s["status"] = "running"
            s["started_at"] = time.time()
            self._step_fraction[step_id] = 0.05
        self.log(f"▶ {s['title_he']} — {s['explain_he']}", "STEP")
        return True

    def _end_step(self, step_id, status="done", detail_he=""):
        with self._lock:
            s = self._find_step(step_id)
            if not s or s["status"] == "skipped":
                return
            elapsed = time.time() - (s["started_at"] or time.time())
            s["status"] = status
            s["elapsed"] = round(elapsed, 1)
            if detail_he:
                s["detail_he"] = detail_he
            self._step_fraction[step_id] = 1.0
        icon = "✓" if status == "done" else "!"
        level = "SUCCESS" if status == "done" else "WARN"
        self.log(f"{icon} {s['title_he']} — {detail_he or 'הושלם'} ({elapsed:.1f} שניות)", level)

    def _set_fraction(self, step_id, fraction):
        with self._lock:
            self._step_fraction[step_id] = max(0.0, min(1.0, fraction))

    def _heartbeat_loop(self):
        """Keeps the terminal visibly alive while a long step stays silent."""
        while not self._stop_heartbeat.wait(3.0):
            with self._lock:
                quiet_for = time.time() - (self._last_log_at or time.time())
                running = [s for s in self._steps if s["status"] == "running"]
            if quiet_for >= 3.0 and running:
                names = " · ".join(s["title_he"] for s in running)
                self.log(f"… עדיין עובד על: {names} ({int(quiet_for)} שניות ללא פלט)",
                         "INFO", replace_key="heartbeat")

    def _compute_percent_locked(self):
        planned = [s for s in self._steps if s["status"] != "skipped"]
        if not planned:
            return 0
        total_w = sum(STEP_BY_ID[s["id"]]["weight"] for s in planned) or 1
        done_w = 0.0
        for s in planned:
            w = STEP_BY_ID[s["id"]]["weight"]
            if s["status"] in ("done", "failed"):
                done_w += w
            elif s["status"] == "running":
                done_w += w * max(0.0, min(1.0, self._step_fraction.get(s["id"], 0.05)))
        return int(max(0, min(100, round(100.0 * done_w / total_w))))

    def _eta_locked(self, elapsed):
        """Remaining seconds, from declared weights recalibrated by real pace."""
        planned = [s for s in self._steps if s["status"] != "skipped"]
        if not planned:
            return 0
        spent_w = 0.0
        left_w = 0.0
        for s in planned:
            w = STEP_BY_ID[s["id"]]["weight"]
            if s["status"] in ("done", "failed"):
                spent_w += w
            elif s["status"] == "running":
                f = max(0.0, min(1.0, self._step_fraction.get(s["id"], 0.05)))
                spent_w += w * f
                left_w += w * (1 - f)
            else:
                left_w += w
        if spent_w <= 0:
            return int(left_w)
        return int(max(0, left_w * (elapsed / spent_w)))

    @staticmethod
    def _ensure_backup_dirs():
        """Creates the backup tree on first use rather than at import time."""
        try:
            os.makedirs(os.path.join(BACKUP_BASE_DIR, 'Sessions'), exist_ok=True)
            os.makedirs(os.path.join(BACKUP_BASE_DIR, 'RegBackup'), exist_ok=True)
            return True
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # 1. Application Enumeration (Win32 + Modern UWP Store Apps)
    # -------------------------------------------------------------------------
    def get_installed_apps(self, force_refresh=False, include_uwp=True):
        """
        Enumerates all installed software on the machine:
        - 64-bit Native Win32 applications
        - 32-bit WoW64 Win32 applications
        - Current User installations (HKCU)
        - Windows Store (UWP/AppX/MSIX) packages
        """
        now = time.time()
        with self._lock:
            if not force_refresh and self.cached_apps and (now - self.last_apps_fetch < 300):
                return list(self.cached_apps)

        apps = []
        seen_keys = set()

        def _scan_win32():
            if IS_WINDOWS and winreg:
                # 1. System-wide 64-bit
                self._scan_registry_uninstall(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    winreg.KEY_WOW64_64KEY if hasattr(winreg, 'KEY_WOW64_64KEY') else 0,
                    apps, seen_keys, is_64bit=True
                )

                # 2. System-wide 32-bit on 64-bit OS (WoW6432Node)
                if hasattr(winreg, 'KEY_WOW64_32KEY'):
                    self._scan_registry_uninstall(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                        winreg.KEY_WOW64_32KEY,
                        apps, seen_keys, is_64bit=False
                    )

                # 3. Current user installs (HKCU)
                self._scan_registry_uninstall(
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    0,
                    apps, seen_keys, is_user=True
                )

        uwp_apps = []

        def _scan_uwp():
            nonlocal uwp_apps
            if include_uwp and IS_WINDOWS:
                try:
                    uwp_apps = self._get_uwp_apps()
                except Exception:
                    pass

        # Parallelize Win32 registry and UWP queries
        # Daemons: the UWP query can outlive its 6 s join by the PowerShell
        # timeout, and a non-daemon thread would hold up process exit.
        t_win32 = threading.Thread(target=_scan_win32, daemon=True)
        t_uwp = threading.Thread(target=_scan_uwp, daemon=True)
        t_win32.start()
        t_uwp.start()
        t_win32.join()
        # Cap the UWP query so it never blocks the Win32 list, but do not treat
        # a timeout as "there are no Store apps": caching that empty answer for
        # five minutes is how Store apps used to disappear from the screen.
        t_uwp.join(timeout=6.0)
        uwp_complete = not t_uwp.is_alive()

        apps.extend(uwp_apps)
        apps.sort(key=lambda x: (x.get('name') or '').lower())

        if include_uwp:
            with self._lock:
                self.cached_apps = apps
                # A partial answer gets a short retry window instead of the full
                # TTL: pinning the timestamp to 0 would disable the cache
                # outright and re-run the whole sweep on every single request.
                self.last_apps_fetch = now if uwp_complete else (now - 270)
        # A uwp=0 request must not poison the shared cache with a Win32-only
        # list that the next default request would be served.

        return list(apps)

    def _scan_registry_uninstall(self, root_hive, subkey_path, access_mask, apps_list,
                                 seen_keys, is_64bit=True, is_user=False):
        if not winreg:
            return
        try:
            h_key = winreg.OpenKey(root_hive, subkey_path, 0, winreg.KEY_READ | access_mask)
        except Exception:
            return

        try:
            num_subkeys, _, _ = winreg.QueryInfoKey(h_key)
            for i in range(num_subkeys):
                try:
                    sub_name = winreg.EnumKey(h_key, i)
                    hive_name = 'HKLM' if root_hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU'
                    unique_id = f"{hive_name}_{'x64' if is_64bit else 'x86'}_{sub_name}"
                    if unique_id in seen_keys:
                        continue

                    sub_h = winreg.OpenKey(h_key, sub_name, 0, winreg.KEY_READ | access_mask)
                    app_data = self._read_uninstall_key_values(
                        sub_h, sub_name, root_hive, subkey_path, access_mask, is_64bit, is_user
                    )
                    winreg.CloseKey(sub_h)

                    if app_data:
                        seen_keys.add(unique_id)
                        # Avoid duplicates with identical DisplayName & Version
                        name = app_data.get('name')
                        if name and not any(a.get('name') == name and a.get('version') == app_data.get('version')
                                            for a in apps_list):
                            apps_list.append(app_data)
                except Exception:
                    continue
        finally:
            winreg.CloseKey(h_key)

    def _read_uninstall_key_values(self, sub_h, sub_name, root_hive, subkey_path,
                                   access_mask, is_64bit, is_user):
        def _get_val(name, default=""):
            try:
                v, _ = winreg.QueryValueEx(sub_h, name)
                return str(v).strip() if v is not None else default
            except Exception:
                return default

        name = _get_val("DisplayName")
        if not name:
            return None

        # Ignore system updates, hotfixes, security patches unless user explicitly requests
        system_comp = _get_val("SystemComponent")
        parent_key = _get_val("ParentKeyName")
        release_type = _get_val("ReleaseType")
        if system_comp == "1" or parent_key or release_type in ("Security Update", "Update", "Hotfix"):
            return None

        uninstall_str = _get_val("UninstallString")
        quiet_uninstall_str = _get_val("QuietUninstallString")
        if not uninstall_str and not quiet_uninstall_str:
            return None

        install_loc = _get_val("InstallLocation")
        display_icon = _get_val("DisplayIcon")
        publisher = _get_val("Publisher")
        version = _get_val("DisplayVersion")
        install_date = _get_val("InstallDate")

        # Estimate size directly from registry (instant 0 ms)
        size_bytes = 0
        try:
            est_size_kb, _ = winreg.QueryValueEx(sub_h, "EstimatedSize")
            if est_size_kb:
                size_bytes = int(est_size_kb) * 1024
        except Exception:
            pass

        # Parse install date
        formatted_date = ""
        if install_date and len(install_date) == 8 and install_date.isdigit():
            formatted_date = f"{install_date[0:4]}-{install_date[4:6]}-{install_date[6:8]}"
        elif install_date:
            formatted_date = install_date

        app_id = f"win32_{hashlib.md5(f'{sub_name}_{name}'.encode()).hexdigest()[:12]}"
        hive_name = 'HKLM' if root_hive == winreg.HKEY_LOCAL_MACHINE else 'HKCU'

        # The 32-bit view of HKLM lives under WOW6432Node; spell that out so the
        # exported .reg file and any later deletion address the same key the
        # scan actually read.
        effective_path = subkey_path
        if (hive_name == 'HKLM' and not is_64bit
                and 'wow6432node' not in subkey_path.lower()
                and subkey_path.lower().startswith('software\\')):
            effective_path = 'SOFTWARE\\WOW6432Node\\' + subkey_path[len('SOFTWARE\\'):]

        return {
            "id": app_id,
            "type": "win32",
            "name": name,
            "publisher": publisher or "Unknown Publisher",
            "version": version or "-",
            "install_date": formatted_date or "-",
            "install_location": install_loc,
            "size_bytes": size_bytes,
            "size_formatted": format_bytes(size_bytes) if size_bytes > 0 else "-",
            "uninstall_string": uninstall_str,
            "quiet_uninstall_string": quiet_uninstall_str,
            "display_icon": display_icon,
            "registry_key": f"{hive_name}\\{effective_path}\\{sub_name}",
            "is_64bit": is_64bit,
            "is_user": is_user,
            "raw_key_name": sub_name
        }

    def _get_uwp_apps(self):
        """Fetches modern Windows Store Apps (UWP / MSIX) using PowerShell."""
        # -AllUsers needs elevation; without it PowerShell errors out and we get
        # an empty list. Query the current user instead when not elevated.
        scope = "-AllUsers " if is_admin() else ""
        ps_cmd = (
            f"Get-AppxPackage {scope}| Where-Object {{ -not $_.IsFramework -and $_.NonRemovable -ne $true }} | "
            "Select-Object Name, PackageFullName, PackageFamilyName, PublisherId, Version, InstallLocation | "
            "ConvertTo-Json -Compress"
        )
        data = run_powershell_json(ps_cmd, timeout=15)
        uwp_list = []

        for item in data:
            full_name = item.get("PackageFullName", "")
            raw_name = item.get("Name", "")
            if not raw_name or not full_name:
                continue

            # Skip common background system runtime packages
            if raw_name.startswith("Microsoft.VCLibs") or raw_name.startswith("Microsoft.UI.Xaml") \
                    or raw_name.startswith("Microsoft.NET.Native"):
                continue

            # Friendly name formatting
            clean_name = raw_name.replace("Microsoft.", "").replace(".", " ")
            install_loc = item.get("InstallLocation", "")

            app_id = f"uwp_{hashlib.md5(full_name.encode()).hexdigest()[:12]}"
            remove_cmd = f"Remove-AppxPackage -Package {full_name}" + (" -AllUsers" if is_admin() else "")
            uwp_list.append({
                "id": app_id,
                "type": "uwp",
                "name": clean_name,
                "raw_name": raw_name,
                "package_full_name": full_name,
                "package_family_name": item.get("PackageFamilyName", ""),
                "publisher": "Microsoft Store / Developer",
                "version": item.get("Version", "-"),
                "install_date": "-",
                "install_location": install_loc,
                "size_bytes": 0,
                "size_formatted": "-",
                "uninstall_string": remove_cmd,
                "quiet_uninstall_string": remove_cmd,
                "display_icon": "",
                "registry_key": "",
                "is_64bit": True,
                "is_user": False
            })

        return uwp_list

    def _quick_dir_size(self, path, max_files=4000):
        """
        Returns (total_bytes, truncated). `truncated` is True when the walk hit
        its file cap, so callers can say "לפחות X" instead of quoting a number
        that silently under-reports a large tree.
        """
        total = 0
        count = 0
        for root, _, files in os.walk(path):
            for f in files:
                count += 1
                if count > max_files:
                    return total, True
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except Exception:
                    pass
        return total, False

    # -------------------------------------------------------------------------
    # 2. Safety & Backup Operations (Restore Points, Reg Hives, Rollback)
    # -------------------------------------------------------------------------
    def create_system_restore_point(self, app_name):
        """
        Creates a Windows VSS System Restore Point before uninstallation.

        Reports the truth: System Protection is off by default on many installs
        and Windows throttles checkpoints to one per 24h, so a silent "success"
        here would leave the user believing in a safety net that isn't there.
        """
        if not IS_WINDOWS:
            return {"success": False, "error": "Windows only"}
        if not is_admin():
            return {"success": False, "error": "יצירת נקודת שחזור דורשת הרשאות מנהל"}

        safe_name = re.sub(r"['\"`$]", "", str(app_name))[:80]
        try:
            ps_script = (
                "try {"
                f" Checkpoint-Computer -Description 'Polaris Uninstaller: {safe_name}'"
                " -RestorePointType 'APPLICATION_UNINSTALL' -ErrorAction Stop;"
                " @{success=$true} | ConvertTo-Json"
                "} catch {"
                " @{success=$false; error=$_.Exception.Message} | ConvertTo-Json"
                "}"
            )
            res = run_powershell_json(ps_script, timeout=90)
            if not res:
                return {"success": False, "error": "PowerShell לא החזיר תשובה (ייתכן שהפעולה חרגה מזמן ההמתנה)"}
            first = res[0]
            if first.get("success"):
                return {"success": True, "message": "נקודת שחזור מערכת נוצרה בהצלחה"}
            return {"success": False, "error": first.get("error") or "יצירת נקודת השחזור נכשלה"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def backup_registry_key_tree(self, key_path, backup_session_dir):
        """Exports a target registry key to a .reg file for instant surgical recovery."""
        if not IS_WINDOWS or not key_path:
            return None
        try:
            os.makedirs(backup_session_dir, exist_ok=True)
        except Exception:
            return None
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', key_path)[:60]
        out_path = os.path.join(backup_session_dir, f"reg_{safe_name}.reg")
        if os.path.exists(out_path):
            return out_path
        try:
            res = run_hidden(["reg.exe", "export", key_path, out_path, "/y"], capture_output=True)
        except Exception:
            return None
        if res.returncode == 0 and os.path.exists(out_path):
            return out_path
        return None

    def create_emergency_recovery_script(self, session_id, app_name, backup_session_dir, deleted_keys=None):
        """
        Creates Restore.dat (which can be renamed to Restore.bat in WinRE)
        to restore all deleted registry branches offline if Windows fails to boot.
        """
        dat_path = os.path.join(backup_session_dir, "Restore.dat")
        bat_lines = [
            "@echo off",
            "echo ==================================================",
            "echo   Polaris Emergency Registry Restore Utility",
            f"echo   Restoring session: {session_id} ({app_name})",
            "echo ==================================================",
            "echo.",
        ]

        for key in (deleted_keys or []):
            bat_lines.append(f"echo   - {key}")
        if deleted_keys:
            bat_lines.append("echo.")

        imported = 0
        try:
            for f in sorted(os.listdir(backup_session_dir)):
                if f.startswith("reg_") and f.endswith(".reg"):
                    bat_lines.append(f'reg.exe import "%~dp0{f}"')
                    imported += 1
        except Exception:
            pass

        bat_lines.extend([
            "echo.",
            f"echo Restored {imported} registry export(s).",
            "echo NOTE: deleted FILES are not covered by this script - use the",
            "echo       System Restore Point created before the uninstall.",
            "pause",
        ])

        try:
            with open(dat_path, "w", encoding="utf-8") as f:
                f.write("\r\n".join(bat_lines))
        except Exception:
            return None
        return dat_path

    # -------------------------------------------------------------------------
    # 3. Uninstallation Lifecycle Execution
    # -------------------------------------------------------------------------
    def start_uninstall_session(self, app_id, skip_restore_point=False,
                                skip_registry_backup=False, scan_mode="moderate"):
        """
        Initiates an uninstallation lifecycle:
        1. Pre-analysis & session initialization
        2. System Restore Point (unless skipped)
        3. Registry Backup (unless skipped)
        4. Running native uninstaller with process tree tracking
        """
        if scan_mode not in ("safe", "moderate", "advanced"):
            scan_mode = "moderate"

        app = next((a for a in self.get_installed_apps() if a.get('id') == app_id), None)
        if not app:
            return {"success": False, "error": "Application not found"}

        # Claim the engine atomically: two fast clicks used to overwrite
        # active_session and leave the first run reporting into a dead object.
        with self._lock:
            if self._busy:
                return {"success": False, "error": "פעולת הסרה אחרת כבר פועלת. המתן לסיומה."}
            self._busy = True

        session_id = f"uninstall_{int(time.time())}_{app_id}"
        session_dir = os.path.join(BACKUP_BASE_DIR, 'Sessions', session_id)
        self._ensure_backup_dirs()
        try:
            os.makedirs(session_dir, exist_ok=True)
        except Exception:
            pass

        self._skip_requested.clear()
        self._reset_run_state(owner=session_id)

        elevated = is_admin()
        self.log(f"[START] הסרה של: {app.get('name')} {app.get('version', '')}".strip(), "START")
        self.log(f"[$] יצרן: {app.get('publisher') or '—'} · סוג: "
                 f"{'אפליקציית Store' if app.get('type') == 'uwp' else 'Win32'}", "INFO")
        if app.get("install_location"):
            self.log(f"[$] תיקיית התקנה: {app['install_location']}", "INFO")
        self.log(f"[$] הרשאות: {'מנהל' if elevated else 'משתמש רגיל'}"
                 + ("" if elevated else " — שאריות ב-HKLM ובתיקיות מערכת לא יימחקו"),
                 "INFO" if elevated else "WARN")
        self.log(f"[$] מצב סריקה: {scan_mode}", "INFO")
        self.log(f"[SAFETY] גיבויים ייכתבו אל: {session_dir}", "SAFETY")

        self._plan_steps(skip_restore_point, skip_registry_backup, app.get("type") == "uwp")

        session = {
            "session_id": session_id,
            "session_dir": session_dir,
            "app": app,
            "scan_mode": scan_mode,
            "skip_restore_point": skip_restore_point,
            "skip_registry_backup": skip_registry_backup,
            "stage": "starting",
            "progress_pct": 5,
            "status_message": "מאתחל תהליך הסרה...",
            "error": None,
            "warnings": [],
            "leftovers": None,
            "deleted_summary": None,
            "can_skip": False,
            "is_admin": is_admin(),
        }

        with self._lock:
            self.active_session = session

        thread = threading.Thread(target=self._run_session_worker, args=(session,), daemon=True)
        try:
            thread.start()
        except Exception as e:
            # Without this the engine would stay marked busy forever and refuse
            # every later uninstall.
            with self._lock:
                self._busy = False
                self.active_session = None
            return {"success": False, "error": f"לא ניתן להפעיל את תהליך ההסרה: {e}"}

        return {"success": True, "session_id": session_id, "app": app}

    def skip_current_step(self):
        """Allows user to skip restore point creation or native uninstaller if stuck."""
        self._skip_requested.set()
        with self._lock:
            if self.active_session:
                self.active_session["status_message"] = "מדלג על השלב הנוכחי לפי בקשת המשתמש..."
        return {"success": True, "message": "Skip requested"}

    def get_session_status(self, since_log_id=0):
        """
        Status plus everything the live terminal needs.

        `since_log_id` is a log *revision*, not an index: the client sends back
        the `log_rev` it last saw and gets only what changed, including in-place
        edits to rows it already drew.
        """
        with self._lock:
            try:
                since = int(since_log_id or 0)
            except (TypeError, ValueError):
                since = 0

            logs = [dict(l) for l in self.live_logs if l.get("rev", 0) > since]
            elapsed = (time.time() - self._started_at) if self._started_at else 0

            steps_out = []
            for s in self._steps:
                item = dict(s)
                if s["status"] == "running" and s.get("started_at"):
                    item["elapsed"] = round(time.time() - s["started_at"], 1)
                item["fraction"] = round(self._step_fraction.get(s["id"], 0.0), 3)
                item.pop("started_at", None)
                steps_out.append(item)

            done_steps = len([s for s in self._steps
                              if s["status"] in ("done", "failed")])
            total_steps = len([s for s in self._steps if s["status"] != "skipped"])

            # A forced scan publishes a plan without claiming _busy, so gate the
            # ETA on there being a running step rather than on the flag alone.
            running_now = any(s["status"] == "running" for s in self._steps)

            live = {
                "logs": logs,
                "log_rev": self._log_rev,
                "steps": steps_out,
                "done_steps": done_steps,
                "total_steps": total_steps,
                "elapsed_seconds": round(elapsed, 1),
                "eta_seconds": self._eta_locked(elapsed) if (self._busy or running_now) else 0,
                # Always published, so a forced scan (which has no session) can
                # still drive the wizard's progress bar.
                "plan_percent": self._compute_percent_locked() if self._steps else 0,
            }

            if not self.active_session:
                return {"active": False, **live}

            out = {"active": True, **self.active_session, **live}
            # Only let the plan drive the bar while the plan actually belongs to
            # this session; otherwise a later forced scan's steps would rewrite
            # a finished session's percentage.
            if self._steps and self._steps_owner == self.active_session.get("session_id"):
                out["progress_pct"] = self._compute_percent_locked()
            return out

    def _set_stage(self, session, stage=None, pct=None, message=None, can_skip=None):
        with self._lock:
            if stage is not None:
                session["stage"] = stage
            if pct is not None:
                session["progress_pct"] = pct
            if message is not None:
                session["status_message"] = message
            if can_skip is not None:
                session["can_skip"] = can_skip

    def _run_session_worker(self, session):
        app = session["app"]
        session_dir = session["session_dir"]

        try:
            # Inside the try: a failure to spawn the heartbeat would otherwise
            # skip the finally and leave the engine marked busy forever.
            self._start_heartbeat()

            # 1. System Restore Point
            if self._begin_step("restore_point"):
                self._set_stage(session, "restore_point", None,
                                "יוצר נקודת שחזור מערכת (System Restore Point)...", True)
                self.log("[$] Checkpoint-Computer -RestorePointType 'APPLICATION_UNINSTALL'", "PLAN")
                self.log("[?] הפעולה בטוחה: היא רק מוסיפה נקודת חזרה, לא משנה קבצים.", "INFO")

                rp_result = {}

                def _make_rp():
                    rp_result.update(self.create_system_restore_point(app["name"]))

                rp_thread = threading.Thread(target=_make_rp, daemon=True)
                rp_thread.start()
                start_t = time.time()
                timed_out = False
                skipped = False
                while rp_thread.is_alive():
                    if self._skip_requested.is_set():
                        skipped = True
                        break
                    waited = time.time() - start_t
                    if waited > 90:
                        timed_out = True
                        break
                    self._set_fraction("restore_point", min(0.95, waited / 35.0))
                    time.sleep(0.5)

                if skipped:
                    msg = "דולג לבקשתך — אין נקודת חזרה לפני ההסרה"
                    session["warnings"].append("נקודת השחזור דולגה לבקשת המשתמש — אין נקודת חזרה לפני ההסרה.")
                    self._end_step("restore_point", "failed", msg)
                elif timed_out:
                    session["warnings"].append("יצירת נקודת השחזור חרגה מ-90 שניות וננטשה.")
                    self._end_step("restore_point", "failed", "חרגה מ-90 שניות וננטשה")
                elif rp_result and not rp_result.get("success"):
                    err = rp_result.get('error', 'סיבה לא ידועה')
                    session["warnings"].append(f"נקודת שחזור לא נוצרה: {err}")
                    self._end_step("restore_point", "failed", f"לא נוצרה — {err}")
                else:
                    self._end_step("restore_point", "done", "נקודת שחזור נוצרה")
            else:
                self.log("– נקודת שחזור מערכת: דולג.", "WARN")

            self._skip_requested.clear()

            # 2. Registry Backup
            if self._begin_step("registry_backup"):
                self._set_stage(session, "registry_backup", None,
                                "מגבה מפתחות רישום (Registry Backup)...", False)
                reg_key = app.get("registry_key")
                if not reg_key:
                    self._end_step("registry_backup", "done", "אין מפתח רישום לגבות")
                else:
                    self.log(f'[$] reg.exe export "{reg_key}" …\\reg_*.reg /y', "PLAN")
                    self.log("[?] ייצוא בלבד — קריאה מהרישום וכתיבה לקובץ, בלי לשנות דבר.", "INFO")
                    out = self.backup_registry_key_tree(reg_key, session_dir)
                    if out:
                        self._end_step("registry_backup", "done", os.path.basename(out))
                    else:
                        session["warnings"].append(
                            "גיבוי מפתח הרישום של התוכנה נכשל (ייתכן שדרושות הרשאות מנהל)."
                        )
                        self._end_step("registry_backup", "failed", "הייצוא נכשל")

            # 3. Native Uninstaller Execution
            self._begin_step("native_uninstall")
            self._set_stage(session, "native_uninstall", None,
                            "מפעיל את מסיר התוכנה המקורי... אנא השלם את ההסרה בחלון שנפתח.", True)

            native_ok = False
            if app.get("type") == "uwp":
                pkg = app.get('package_full_name', '')
                scope = " -AllUsers" if is_admin() else ""
                self.log(f"[$] Remove-AppxPackage -Package '{pkg}'{scope}", "PLAN")
                res = run_hidden(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     f"Remove-AppxPackage -Package '{pkg}'{scope}"],
                    capture_output=True, text=True, timeout=180
                )
                if res.returncode == 0:
                    native_ok = True
                    self._end_step("native_uninstall", "done", "החבילה הוסרה")
                else:
                    err = (getattr(res, 'stderr', '') or '').strip().splitlines()
                    self.log(f"[ERROR] {err[0] if err else f'קוד יציאה {res.returncode}'}", "ERROR")
                    self._end_step("native_uninstall", "failed", f"קוד יציאה {res.returncode}")
            else:
                uninstall_cmd = app.get("uninstall_string") or app.get("quiet_uninstall_string")
                if uninstall_cmd:
                    native_ok, note = self._execute_native_uninstaller_monitored(uninstall_cmd, session)
                    self._end_step("native_uninstall", "done" if native_ok else "failed", note)
                else:
                    self.log("[WARN] לא נמצאה פקודת הסרה ברישום — ממשיך ישר לסריקת שאריות.", "WARN")
                    self._end_step("native_uninstall", "failed", "לא נמצאה פקודת הסרה")

            self._skip_requested.clear()
            self._set_stage(session, can_skip=False)

            # 4. Scanning for Leftovers
            self._set_stage(session, "scanning", None,
                            f"מבצע סריקת שאריות היוריסטית ({session['scan_mode'].capitalize()} Mode)...", True)

            def scan_progress(step_msg, pct):
                self._set_stage(session, message=step_msg)

            if not native_ok:
                self.log("[SAFETY] ההסרה המקורית לא הושלמה, ולכן התוכנה עדיין מותקנת: "
                         "תיקיית ההתקנה ורשומת ההסרה שלה לא ייחשבו שאריות ולא ייבחרו למחיקה.",
                         "SAFETY")

            # still_installed mirrors reality: a skipped, failed or missing
            # uninstaller means the program is still there, and its own folder
            # and Add/Remove entry are the program, not residue.
            leftovers = self.scan_leftovers(
                app, mode=session["scan_mode"], progress_cb=scan_progress,
                still_installed=not native_ok
            )

            with self._lock:
                session["leftovers"] = leftovers

            n_reg = len(leftovers.get('registry', []))
            n_files = len(leftovers.get('files', []))
            total_bytes = sum(i.get('size_bytes', 0) for i in leftovers.get('files', []))
            self.log(f"[SUMMARY] נמצאו {n_reg} שאריות רישום ו-{n_files} קבצים ותיקיות "
                     f"({format_bytes(total_bytes)}).", "SUCCESS")
            if leftovers.get("requires_admin"):
                self.log("[WARN] חלק מהשאריות ב-HKLM — ללא הרצה כמנהל הן לא יימחקו.", "WARN")

            self._set_stage(
                session, "ready_for_review", 100,
                f"הסריקה הושלמה. נמצאו {n_reg} שאריות רישום ו-{n_files} קבצים ותיקיות.",
                False
            )

        except Exception as e:
            self.log(f"[ERROR] {e}", "ERROR")
            with self._lock:
                for s in self._steps:
                    if s["status"] == "running":
                        s["status"] = "failed"
                        s["detail_he"] = str(e)
                session["stage"] = "error"
                session["error"] = str(e)
                session["status_message"] = f"שגיאה במהלך ההסרה: {e}"
                session["can_skip"] = False
        finally:
            self._stop_heartbeat.set()
            # A skip left pending here used to abort every *later* scan the
            # moment it started, silently returning zero leftovers.
            self._skip_requested.clear()
            with self._lock:
                self._busy = False

    def _execute_native_uninstaller_monitored(self, cmd_string, session):
        """
        Runs the native uninstaller and monitors its process tree until it ends.

        Returns (ok, note). An uninstaller that could not even be launched used
        to be reported to the step list as a green ✓.
        """
        outcome = [True, "המסיר המקורי הסתיים"]
        try:
            original = cmd_string
            cmd_string = to_uninstall_command(cmd_string)
            if cmd_string != original:
                self.log("[?] פקודת ההסרה הרשומה הייתה /I (התקנה/תיקון) — הומרה ל-/X (הסרה).", "WARN")
            self.log(f"[$] {cmd_string}", "PLAN")
            self.log("[?] זו פקודת ההסרה שהיצרן עצמו רשם ב-Windows. "
                     "אם נפתח חלון — השלם אותו, ואם נתקע לחץ 'דלג'.", "INFO")

            proc = subprocess.Popen(cmd_string, shell=True)
            parent_pid = proc.pid
            children = []
            started = time.time()
            self.log(f"[$] המסיר פועל (PID {parent_pid})…", "INFO")

            # Hard ceiling so a wizard the user closed mid-run cannot leave the
            # engine marked busy forever.
            deadline = time.time() + NATIVE_UNINSTALL_MAX_WAIT
            while proc.poll() is None:
                waited = time.time() - started
                self._set_fraction("native_uninstall", min(0.95, waited / 50.0))
                self.log(f"[$] ממתין למסיר המקורי — {int(waited)} שניות"
                         + (f" · {len(children)} תהליכי משנה" if children else ""),
                         "INFO", replace_key="native_wait")
                # The children have to be collected while the parent is still
                # alive. Asking for them afterwards (as this used to) always
                # returns an empty list, so the "process tree monitoring" never
                # actually waited on anything.
                if psutil is not None:
                    try:
                        children = psutil.Process(parent_pid).children(recursive=True) or children
                    except Exception:
                        pass
                if self._skip_requested.is_set():
                    self.log("[WARN] דילוג לבקשתך — ההמתנה למסיר המקורי הופסקה.", "WARN")
                    self._set_stage(session, message="דולג על ההמתנה למסיר המקורי.")
                    outcome[:] = [False, "דולג לבקשתך לפני שהסתיים"]
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    break
                if time.time() > deadline:
                    self.log("[WARN] המסיר המקורי לא הסתיים תוך שעה — מפסיק להמתין.", "WARN")
                    session["warnings"].append(
                        "המסיר המקורי לא הסתיים תוך שעה — Polaris הפסיק להמתין לו."
                    )
                    outcome[:] = [False, "לא הסתיים תוך שעה"]
                    break
                time.sleep(0.8)

            rc = proc.poll()
            if rc not in (None, 0, 3010) and outcome[0]:
                self.log(f"[WARN] המסיר המקורי סיים עם קוד {rc}.", "WARN")
                outcome[:] = [False, f"קוד יציאה {rc}"]
            elif rc == 3010 and outcome[0]:
                outcome[:] = [True, "הוסר — נדרשת הפעלה מחדש"]

            if children:
                self.log(f"[$] ממתין ל-{len(children)} תהליכי משנה שהמסיר השאיר…", "INFO")
                child_deadline = time.time() + 3.0
                for child in children:
                    if self._skip_requested.is_set():
                        break
                    rem = child_deadline - time.time()
                    if rem <= 0:
                        break
                    try:
                        child.wait(timeout=max(0.2, rem))
                    except Exception:
                        pass

        except Exception as e:
            self.log(f"[ERROR] המסיר המקורי לא רץ: {e}. ממשיך לסריקת שאריות.", "ERROR")
            self._set_stage(session, message=f"שים לב: המסיר המקורי הודיע: {e}. ממשיך לסריקת שאריות...")
            outcome[:] = [False, str(e)]

        return outcome[0], outcome[1]

    # -------------------------------------------------------------------------
    # 4. Post-Uninstall Residual Scanning Engine
    # -------------------------------------------------------------------------
    def scan_leftovers(self, app_metadata, mode="moderate", progress_cb=None, still_installed=False):
        """
        Heuristic residual scanning across Registry and Filesystem.

        `still_installed` is for a preview scan of software that has NOT been
        uninstalled. The app's own Add/Remove entry and its install folder are
        then left out entirely - they are not leftovers, they are the program -
        and nothing is marked bold, so the review screen pre-selects nothing.

        - Safe:     install folder, the app's own Uninstall key, shortcuts
        - Moderate: + AppData / ProgramData / Common Files, Run keys, App Paths
        - Advanced: + COM/CLSID, squished MSI GUIDs, services, drivers, MuiCache

        Every item carries `risk`: "low" items are the ordinary residue of an
        application, "high" items touch shared machine state (services,
        drivers, COM registration) and are never cleaned without a human
        looking at them.
        """
        if mode not in ("safe", "moderate", "advanced"):
            mode = "moderate"

        app_metadata = app_metadata or {}
        app_name = app_metadata.get("name", "") or ""
        publisher = app_metadata.get("publisher", "") or ""
        install_loc = app_metadata.get("install_location", "") or ""
        raw_key = app_metadata.get("raw_key_name", "") or ""

        # Tokens are still needed for matching; the live program's own entry and
        # folder are simply never produced as findings.
        own_key = "" if still_installed else (app_metadata.get("registry_key") or "")
        own_folder = "" if still_installed else install_loc
        if still_installed:
            self.log("[?] סריקת תצוגה מקדימה — התוכנה עדיין מותקנת, ולכן תיקיית ההתקנה "
                     "ורשומת ההסרה שלה אינן נחשבות שאריות ואינן מוצעות למחיקה.", "SAFETY")

        name_tokens = [
            t for t in re.split(r'[\s_\-\.]+', app_name)
            if len(t) > 2 and t.lower() not in SYSTEM_STOP_WORDS
        ]
        pub_tokens = [
            t for t in re.split(r'[\s_\-\.]+', publisher)
            if len(t) > 2 and t.lower() not in SYSTEM_STOP_WORDS
        ]

        shared_dlls = self._get_shared_dlls_table()
        shared_protected = []

        registry_leftovers = []
        file_leftovers = []

        self.log(f"[SCAN] מילות חיפוש מהשם: {', '.join(name_tokens) or '(אין)'}"
                 + (f" · מהיצרן: {', '.join(pub_tokens)}" if pub_tokens else ""), "INFO")
        if shared_dlls:
            self.log(f"[SCAN] נטענה טבלת SharedDlls — {len(shared_dlls)} ספריות משותפות מוגנות.", "INFO")

        # `sub` reports progress inside a step so the bar keeps moving even
        # while one long sweep is running.
        def sub(step_id, fraction, message, count=None):
            self._set_fraction(step_id, fraction)
            if progress_cb:
                progress_cb(message, 0)
            self.log(f"[SCAN] {message}" + (f" — {count} ממצאים עד כה" if count is not None else ""),
                     "INFO", replace_key=f"scan_{step_id}")

        if IS_WINDOWS and winreg:
            self._begin_step("scan_registry")

            # 0. The app's own Uninstall entry - without this a forced uninstall
            #    leaves the program listed in Windows' own "Apps & features".
            sub("scan_registry", 0.1, "בודק את רשומת ההתקנה של התוכנה")
            if own_key:
                self._scan_own_uninstall_key(app_metadata, registry_leftovers)

            if mode in ("moderate", "advanced"):
                if not self._skip_requested.is_set():
                    sub("scan_registry", 0.25, "סורק ענפי יצרן ומוצר תחת SOFTWARE", len(registry_leftovers))
                    self._scan_software_keys(name_tokens, pub_tokens, registry_leftovers)
                if not self._skip_requested.is_set():
                    sub("scan_registry", 0.45, "סורק ערכי הפעלה אוטומטית (Run / RunOnce)", len(registry_leftovers))
                    self._scan_run_keys(name_tokens, install_loc, registry_leftovers)
                if not self._skip_requested.is_set():
                    sub("scan_registry", 0.55, "סורק קיצורי הרצה (App Paths)", len(registry_leftovers))
                    self._scan_app_paths(name_tokens, registry_leftovers)

            if mode == "advanced" and not self._skip_requested.is_set():
                sub("scan_registry", 0.65, "סורק רכיבי COM / CLSID", len(registry_leftovers))
                self._scan_com_clsid(install_loc, registry_leftovers)
                if "{" in raw_key and "}" in raw_key:
                    squished = self._squish_guid(raw_key)
                    if squished:
                        sub("scan_registry", 0.78, "סורק רישומי Windows Installer", len(registry_leftovers))
                        self._scan_msi_squished(squished, registry_leftovers)
                if not self._skip_requested.is_set():
                    sub("scan_registry", 0.85, "סורק שירותים ודרייברים", len(registry_leftovers))
                    self._scan_services_and_drivers(name_tokens, install_loc, registry_leftovers)
                if not self._skip_requested.is_set():
                    sub("scan_registry", 0.95, "סורק מטמון ממשק (MuiCache)", len(registry_leftovers))
                    self._scan_muicache(name_tokens, install_loc, registry_leftovers)

            self._end_step("scan_registry", "done", f"{len(registry_leftovers)} ממצאים")

        # File System Scan
        if not self._skip_requested.is_set():
            self._begin_step("scan_files")
            sub("scan_files", 0.2, "סורק תיקיות התקנה, AppData ו-ProgramData")
            self._scan_filesystem_leftovers(
                name_tokens, pub_tokens, install_loc, shared_dlls, mode,
                file_leftovers, shared_protected, own_folder=own_folder
            )
            self._end_step("scan_files", "done", f"{len(file_leftovers)} ממצאים")

        if self._skip_requested.is_set():
            self.log("[WARN] הסריקה נקטעה לבקשתך — ייתכן שלא כל השאריות נמצאו.", "WARN")
            # A step the skip jumped over would otherwise stay "pending"
            # forever, freezing the bar below 100% under a "scan complete"
            # message and leaving a ○ next to a finished run.
            with self._lock:
                for s in self._steps:
                    if s["status"] in ("pending", "running"):
                        s["status"] = "skipped"
                        s["detail_he"] = "דולג לבקשתך"

        # Drop anything that would fail validation later, so the user is never
        # offered a checkbox that cannot be honoured.
        raw_counts = (len(registry_leftovers), len(file_leftovers))
        registry_leftovers = self._filter_unsafe(registry_leftovers, registry=True)
        file_leftovers = self._filter_unsafe(file_leftovers, registry=False)
        dropped = (raw_counts[0] - len(registry_leftovers)) + (raw_counts[1] - len(file_leftovers))
        if dropped:
            self.log(f"[SAFETY] {dropped} ממצאים נדחו על ידי שומרי הבטיחות ולא יוצעו למחיקה.", "SAFETY")

        for item in registry_leftovers + file_leftovers:
            item["id"] = make_item_id(item)
            item.setdefault("risk", "low")
            if still_installed:
                # Nothing from a preview scan is pre-selected: the program is
                # running, and these entries may well be in use.
                item["is_bold"] = False

        self._log_findings("רישום", registry_leftovers)
        self._log_findings("דיסק", file_leftovers)

        self._remember_scan(registry_leftovers + file_leftovers)

        return {
            "mode": mode,
            "registry": registry_leftovers,
            "files": file_leftovers,
            "total_registry_count": len(registry_leftovers),
            "total_files_count": len(file_leftovers),
            "shared_dlls_protected": shared_protected,
            "still_installed": still_installed,
            "is_admin": is_admin(),
            "requires_admin": any(i.get("hive") == "HKLM" for i in registry_leftovers) and not is_admin(),
        }

    def _log_findings(self, label, items, cap=25):
        """Prints what was found, so the list on screen is not a black box."""
        if not items:
            self.log(f"[SCAN] לא נמצאו שאריות ב{label}.", "INFO")
            return
        for it in items[:cap]:
            mark = "!" if it.get("risk") == "high" else "+"
            size = f" · {it['size_formatted']}" if it.get("size_formatted") else ""
            name = f"\\{it['name']}" if it.get("type") == "value" and it.get("name") else ""
            self.log(f"[{mark}] {it.get('path', '')}{name}{size} — {it.get('reason', '')}",
                     "WARN" if it.get("risk") == "high" else "INFO")
        if len(items) > cap:
            self.log(f"[SCAN] …ועוד {len(items) - cap} ממצאים ב{label} (מוצגים ברשימה).", "INFO")

    @staticmethod
    def _filter_unsafe(items, registry):
        kept = []
        for it in items:
            if registry and it.get("type") == "value":
                kept.append(it)  # values are validated against their own whitelist
                continue
            if registry:
                ok, _ = is_reg_path_safe_to_delete(it.get("path", ""))
            else:
                ok, _ = is_path_safe_to_delete(it.get("path", ""))
            if ok:
                kept.append(it)
        return kept

    def _remember_scan(self, items):
        with self._lock:
            if len(self._scan_index) > 8000:
                self._scan_index = {}
            for it in items:
                self._scan_index[it["id"]] = it

    def _get_shared_dlls_table(self):
        shared = {}
        if not (IS_WINDOWS and winreg):
            return shared

        masks = (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY) if hasattr(winreg, 'KEY_WOW64_64KEY') else (0,)
        for access in masks:
            try:
                k = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls",
                    0, winreg.KEY_READ | access
                )
            except Exception:
                continue
            try:
                _, num_vals, _ = winreg.QueryInfoKey(k)
                for i in range(num_vals):
                    try:
                        v_name, v_data, _ = winreg.EnumValue(k, i)
                        count = int(v_data) if str(v_data).isdigit() else 1
                        key = _norm_win_path(v_name)
                        shared[key] = max(shared.get(key, 0), count)
                    except Exception:
                        pass
            finally:
                winreg.CloseKey(k)
        return shared

    @staticmethod
    def find_shared_dlls_in_folder(folder, shared_dlls, max_files=600):
        """
        Returns the DLLs under `folder` that Windows' SharedDlls refcount says
        are still used by at least one other product.

        This is the protection the docstring has always promised and the code
        never actually performed: the table was built, passed down and then
        ignored.
        """
        hits = []
        if not shared_dlls or not folder:
            return hits
        seen = 0
        try:
            for root, _, files in os.walk(folder):
                for f in files:
                    seen += 1
                    if seen > max_files:
                        return hits
                    if not f.lower().endswith(('.dll', '.ocx', '.ax')):
                        continue
                    full = _norm_win_path(os.path.join(root, f))
                    if shared_dlls.get(full, 0) > 1:
                        hits.append({"path": os.path.join(root, f), "refcount": shared_dlls[full]})
        except Exception:
            pass
        return hits

    def _squish_guid(self, raw_guid):
        clean = re.sub(r'[^0-9A-Fa-f]', '', raw_guid)
        if len(clean) != 32:
            return None
        p1 = clean[0:8][::-1]
        p2 = clean[8:12][::-1]
        p3 = clean[12:16][::-1]
        p4 = clean[16:18][::-1] + clean[18:20][::-1]
        p5 = "".join([clean[i:i + 2][::-1] for i in range(20, 32, 2)])
        return (p1 + p2 + p3 + p4 + p5).upper()

    def _scan_own_uninstall_key(self, app_metadata, leftovers):
        key_path = app_metadata.get("registry_key") or ""
        if not key_path or not winreg:
            return
        hive_str = key_path.split('\\', 1)[0].upper()
        hive = winreg.HKEY_LOCAL_MACHINE if hive_str == 'HKLM' else winreg.HKEY_CURRENT_USER
        sub = key_path.split('\\', 1)[1] if '\\' in key_path else ''
        if not sub:
            return
        try:
            k = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ)
            winreg.CloseKey(k)
        except Exception:
            return  # native uninstaller already removed it

        leftovers.append({
            "type": "key",
            "path": key_path,
            "name": os.path.basename(sub),
            "hive": hive_str,
            "is_bold": True,
            "risk": "low",
            "reason": "רשומת ההתקנה של התוכנה ברשימת 'הוספה או הסרה'"
        })

    def _scan_software_keys(self, name_tokens, pub_tokens, leftovers):
        if not name_tokens:
            return

        for hive, hive_name in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            for root_path in (r"SOFTWARE", r"SOFTWARE\WOW6432Node"):
                try:
                    h_root = winreg.OpenKey(hive, root_path, 0, winreg.KEY_READ)
                except Exception:
                    continue

                try:
                    num_subkeys, _, _ = winreg.QueryInfoKey(h_root)
                    for i in range(num_subkeys):
                        if self._skip_requested.is_set():
                            break
                        try:
                            vendor_key_name = winreg.EnumKey(h_root, i)
                            vendor_lower = vendor_key_name.lower().strip()

                            # Critical OS vendor protection: never flag an entire
                            # Microsoft/Windows/Classes branch.
                            if vendor_lower in PROTECTED_REG_SUBKEYS:
                                if pub_tokens and any(pt.lower() == vendor_lower for pt in pub_tokens):
                                    self._scan_vendor_products(
                                        h_root, vendor_key_name, hive_name, root_path,
                                        name_tokens, leftovers
                                    )
                                continue

                            if any(tok.lower() in vendor_lower for tok in name_tokens):
                                leftovers.append({
                                    "type": "key",
                                    "path": f"{hive_name}\\{root_path}\\{vendor_key_name}",
                                    "name": vendor_key_name,
                                    "hive": hive_name,
                                    "is_bold": True,
                                    "risk": "low",
                                    "reason": "מפתח רישום תואם שם תוכנה"
                                })
                                continue

                            if pub_tokens and any(pt.lower() in vendor_lower for pt in pub_tokens):
                                self._scan_vendor_products(
                                    h_root, vendor_key_name, hive_name, root_path,
                                    name_tokens, leftovers
                                )
                        except Exception:
                            continue
                finally:
                    winreg.CloseKey(h_root)

    def _scan_vendor_products(self, h_root, vendor_key_name, hive_name, root_path, name_tokens, leftovers):
        try:
            v_key = winreg.OpenKey(h_root, vendor_key_name, 0, winreg.KEY_READ)
        except Exception:
            return
        try:
            v_subs, _, _ = winreg.QueryInfoKey(v_key)
            for j in range(v_subs):
                try:
                    prod_name = winreg.EnumKey(v_key, j)
                except Exception:
                    break
                if prod_name.lower().strip() in PROTECTED_REG_SUBKEYS:
                    continue
                if any(tok.lower() in prod_name.lower() for tok in name_tokens):
                    leftovers.append({
                        "type": "key",
                        "path": f"{hive_name}\\{root_path}\\{vendor_key_name}\\{prod_name}",
                        "name": prod_name,
                        "parent": f"{hive_name}\\{root_path}\\{vendor_key_name}",
                        "hive": hive_name,
                        "is_bold": True,
                        "risk": "low",
                        "reason": "מפתח מוצר תחת יצרן"
                    })
        finally:
            winreg.CloseKey(v_key)

    def _scan_run_keys(self, name_tokens, install_loc, leftovers):
        run_paths = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        ]
        clean_loc = self._usable_install_loc(install_loc)

        for hive, path, hive_name in run_paths:
            if self._skip_requested.is_set():
                break
            try:
                k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            except Exception:
                continue
            try:
                _, num_vals, _ = winreg.QueryInfoKey(k)
                for i in range(num_vals):
                    try:
                        v_name, v_data, _ = winreg.EnumValue(k, i)
                    except Exception:
                        break
                    v_str = str(v_data).lower()
                    match = bool(name_tokens and any(t.lower() in v_name.lower() for t in name_tokens))
                    if not match and clean_loc and clean_loc in v_str:
                        match = True

                    if match:
                        leftovers.append({
                            "type": "value",
                            "path": f"{hive_name}\\{path}",
                            "name": v_name,
                            "value": str(v_data),
                            "hive": hive_name,
                            "is_bold": True,
                            "risk": "low",
                            "reason": "ערך הפעלה אוטומטית (Run)"
                        })
            finally:
                winreg.CloseKey(k)

    def _scan_app_paths(self, name_tokens, leftovers):
        if not name_tokens:
            return

        path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
        for hive, hive_name in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
            if self._skip_requested.is_set():
                break
            try:
                k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            except Exception:
                continue
            try:
                num_subs, _, _ = winreg.QueryInfoKey(k)
                for i in range(num_subs):
                    try:
                        sub = winreg.EnumKey(k, i)
                    except Exception:
                        break
                    if sub.lower().strip() in PROTECTED_REG_SUBKEYS:
                        continue
                    if any(t.lower() in sub.lower() for t in name_tokens):
                        leftovers.append({
                            "type": "key",
                            "path": f"{hive_name}\\{path}\\{sub}",
                            "name": sub,
                            "hive": hive_name,
                            "is_bold": True,
                            "risk": "low",
                            "reason": "קיצור הרצה (App Path)"
                        })
            finally:
                winreg.CloseKey(k)

    @staticmethod
    def _usable_install_loc(install_loc):
        """
        The install location, normalized, or "" when it is too generic to match
        against (a bare drive root or Program Files matches half the machine).
        """
        if not install_loc:
            return ""
        norm = _norm_win_path(install_loc)
        ok, _ = is_path_safe_to_delete(install_loc)
        if not ok or len(norm) < 6:
            return ""
        return norm

    def _scan_com_clsid(self, install_loc, leftovers):
        clean_loc = self._usable_install_loc(install_loc)
        if not clean_loc or not os.path.exists(install_loc):
            return

        # Both registry views: a 32-bit product registers its COM servers under
        # WOW6432Node, which the previous 0.4s / HKLM-only sweep never reached.
        roots = [
            ("HKLM", r"SOFTWARE\Classes\CLSID"),
            ("HKLM", r"SOFTWARE\Classes\WOW6432Node\CLSID"),
        ]
        budget = time.time() + 2.5

        for hive_name, base_path in roots:
            if time.time() > budget or self._skip_requested.is_set():
                break
            try:
                h_clsid = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path, 0, winreg.KEY_READ)
            except Exception:
                continue
            try:
                num_subs, _, _ = winreg.QueryInfoKey(h_clsid)
                for i in range(num_subs):
                    if i % 200 == 0 and (time.time() > budget or self._skip_requested.is_set()):
                        break
                    try:
                        clsid_name = winreg.EnumKey(h_clsid, i)
                    except Exception:
                        break
                    try:
                        sub_k = winreg.OpenKey(h_clsid, clsid_name, 0, winreg.KEY_READ)
                    except Exception:
                        continue
                    try:
                        for server_type in ("InprocServer32", "LocalServer32"):
                            try:
                                s_key = winreg.OpenKey(sub_k, server_type, 0, winreg.KEY_READ)
                            except Exception:
                                continue
                            try:
                                val, _ = winreg.QueryValueEx(s_key, "")
                            except Exception:
                                continue
                            finally:
                                # A key without a default value used to leak its
                                # handle on every CLSID in the sweep.
                                winreg.CloseKey(s_key)
                            if val and clean_loc in _norm_win_path(str(val)):
                                leftovers.append({
                                    "type": "key",
                                    "path": f"{hive_name}\\{base_path}\\{clsid_name}",
                                    "name": clsid_name,
                                    "hive": hive_name,
                                    "is_bold": True,
                                    "risk": "high",
                                    "reason": f"שרת COM יתום ({server_type})"
                                })
                                break
                    finally:
                        winreg.CloseKey(sub_k)
            finally:
                winreg.CloseKey(h_clsid)

    def _scan_msi_squished(self, squished_guid, leftovers):
        msi_paths = [
            rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\{squished_guid}",
            rf"SOFTWARE\Classes\Installer\Products\{squished_guid}"
        ]
        for p in msi_paths:
            try:
                k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, p, 0, winreg.KEY_READ)
                winreg.CloseKey(k)
            except Exception:
                continue
            leftovers.append({
                "type": "key",
                "path": f"HKLM\\{p}",
                "name": squished_guid,
                "hive": "HKLM",
                "is_bold": True,
                "risk": "high",
                "reason": "מפתח רישום Windows Installer (MSI)"
            })

    def _scan_services_and_drivers(self, name_tokens, install_loc, leftovers):
        clean_loc = self._usable_install_loc(install_loc)
        if not name_tokens and not clean_loc:
            return

        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services", 0, winreg.KEY_READ)
        except Exception:
            return
        try:
            num_subs, _, _ = winreg.QueryInfoKey(k)
            for i in range(num_subs):
                if self._skip_requested.is_set():
                    break
                try:
                    s_name = winreg.EnumKey(k, i)
                except Exception:
                    break
                s_lower = s_name.lower().strip()
                if s_lower in PROTECTED_REG_SUBKEYS or s_lower in CRITICAL_SERVICE_NAMES:
                    continue

                try:
                    s_k = winreg.OpenKey(k, s_name, 0, winreg.KEY_READ)
                except Exception:
                    continue
                img_path = ""
                try:
                    img_val, _ = winreg.QueryValueEx(s_k, "ImagePath")
                    img_path = _norm_win_path(str(img_val))
                except Exception:
                    pass
                finally:
                    winreg.CloseKey(s_k)

                match = False
                if clean_loc and clean_loc in img_path:
                    match = True
                elif name_tokens and any(
                    t.lower() == s_lower or (len(t) >= 4 and t.lower() in s_lower) for t in name_tokens
                ):
                    if "system32" not in img_path and "\\windows\\" not in img_path:
                        match = True

                if match:
                    leftovers.append({
                        "type": "key",
                        "path": f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{s_name}",
                        "name": s_name,
                        "hive": "HKLM",
                        "is_bold": True,
                        "risk": "high",
                        "reason": "שירות מערכת או דרייבר שהושאר ברקע"
                    })
        finally:
            winreg.CloseKey(k)

    def _scan_muicache(self, name_tokens, install_loc, leftovers):
        clean_loc = self._usable_install_loc(install_loc)
        p = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, p, 0, winreg.KEY_READ)
        except Exception:
            return
        try:
            _, num_vals, _ = winreg.QueryInfoKey(k)
            for i in range(num_vals):
                if self._skip_requested.is_set():
                    break
                try:
                    v_name, _, _ = winreg.EnumValue(k, i)
                except Exception:
                    break
                v_lower = v_name.lower()
                match = bool(clean_loc and clean_loc in _norm_win_path(v_name))
                if not match and name_tokens and any(t.lower() in v_lower for t in name_tokens):
                    match = True

                if match:
                    leftovers.append({
                        "type": "value",
                        "path": f"HKCU\\{p}",
                        "name": v_name,
                        "hive": "HKCU",
                        "is_bold": True,
                        "risk": "low",
                        "reason": "היסטוריית הפעלה ומטמון ממשק (MuiCache)"
                    })
        finally:
            winreg.CloseKey(k)

    def _folder_leftover(self, path, display_name, reason, shared_dlls, shared_protected):
        """Builds a folder leftover, downgrading it when it still holds shared DLLs."""
        ok, why = is_path_safe_to_delete(path)
        if not ok:
            return None

        size, truncated = self._quick_dir_size(path)
        hits = self.find_shared_dlls_in_folder(path, shared_dlls)
        item = {
            "type": "folder",
            "path": path,
            "name": display_name,
            "size_bytes": size,
            "size_formatted": ("לפחות " if truncated else "") + format_bytes(size),
            "size_truncated": truncated,
            "is_bold": True,
            "risk": "low",
            "reason": reason,
        }
        if hits:
            shared_protected.extend(h["path"] for h in hits)
            item["is_bold"] = False
            item["risk"] = "high"
            item["shared_dlls"] = hits[:10]
            item["reason"] = f"{reason} — מכילה {len(hits)} ספריות משותפות שתוכנות אחרות עדיין רשומות עליהן"
        return item

    def _scan_filesystem_leftovers(self, name_tokens, pub_tokens, install_loc,
                                   shared_dlls, mode, leftovers, shared_protected,
                                   own_folder=None):
        # own_folder is "" for a preview scan of software that is still
        # installed: the install directory is then the program, not residue.
        if own_folder is None:
            own_folder = install_loc
        # The generic AppData/ProgramData sweep below matches on name alone, so
        # without this a per-user install (%LOCALAPPDATA%\Acme) would come back
        # as a "settings folder" despite being excluded above - and in an
        # ordinary scan it would appear twice.
        excluded_dir = "" if own_folder else _norm_win_path(install_loc)

        if own_folder and os.path.exists(own_folder):
            item = self._folder_leftover(
                own_folder, os.path.basename(os.path.normpath(own_folder)),
                "תיקיית ההתקנה הראשית של התוכנה", shared_dlls, shared_protected
            )
            if item:
                leftovers.append(item)

        # Shortcuts belong to Safe mode as well - they are the most visible
        # residue and the least risky thing on the list.
        shortcut_dirs = [
            os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
            os.path.join(os.environ.get("PUBLIC", "C:\\Users\\Public"), "Desktop"),
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs"),
            os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), r"Microsoft\Windows\Start Menu\Programs")
        ]
        for sc_dir in shortcut_dirs:
            if self._skip_requested.is_set():
                break
            if not sc_dir or not os.path.exists(sc_dir):
                continue
            for root, _, files in os.walk(sc_dir):
                if self._skip_requested.is_set():
                    break
                for f in files:
                    if not f.lower().endswith(".lnk"):
                        continue
                    if not (name_tokens and any(tok.lower() in f.lower() for tok in name_tokens)):
                        continue
                    full_p = os.path.join(root, f)
                    ok, _ = is_path_safe_to_delete(full_p)
                    if not ok:
                        continue
                    try:
                        sz = os.path.getsize(full_p)
                    except OSError:
                        sz = 0
                    leftovers.append({
                        "type": "file",
                        "path": full_p,
                        "name": f,
                        "size_bytes": sz,
                        "size_formatted": format_bytes(sz),
                        "is_bold": True,
                        "risk": "low",
                        "reason": "קיצור דרך (Shortcut)"
                    })

        if mode == "safe":
            return

        search_roots = [
            os.environ.get("APPDATA"),
            os.environ.get("LOCALAPPDATA"),
            os.environ.get("ProgramData"),
            os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "Common Files"),
            os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Common Files")
        ]

        for s_root in search_roots:
            if self._skip_requested.is_set():
                break
            if not s_root or not os.path.exists(s_root):
                continue
            try:
                entries = list(os.scandir(s_root))
            except Exception:
                continue

            for entry in entries:
                if self._skip_requested.is_set():
                    break
                try:
                    if not entry.is_dir():
                        continue
                except OSError:
                    continue
                e_name = entry.name.lower()
                if e_name in PROTECTED_FOLDER_NAMES:
                    continue
                entry_norm = _norm_win_path(entry.path)
                if entry_norm and (entry_norm == excluded_dir
                                   or (own_folder and entry_norm == _norm_win_path(own_folder))):
                    continue

                if name_tokens and any(tok.lower() in e_name for tok in name_tokens):
                    item = self._folder_leftover(
                        entry.path, entry.name,
                        f"תיקיית הגדרות ונתונים ({os.path.basename(s_root)})",
                        shared_dlls, shared_protected
                    )
                    if item:
                        leftovers.append(item)
                elif pub_tokens and any(pt.lower() in e_name for pt in pub_tokens):
                    try:
                        sub_entries = list(os.scandir(entry.path))
                    except Exception:
                        continue
                    for sub_entry in sub_entries:
                        try:
                            if not sub_entry.is_dir():
                                continue
                        except OSError:
                            continue
                        if sub_entry.name.lower() in PROTECTED_FOLDER_NAMES:
                            continue
                        if not (name_tokens and any(tok.lower() in sub_entry.name.lower() for tok in name_tokens)):
                            continue
                        item = self._folder_leftover(
                            sub_entry.path, f"{entry.name}\\{sub_entry.name}",
                            f"תיקיית מוצר תחת יצרן ({os.path.basename(s_root)})",
                            shared_dlls, shared_protected
                        )
                        if item:
                            leftovers.append(item)

    # -------------------------------------------------------------------------
    # 5. Safe Leftovers Deletion & Rollback Logging
    # -------------------------------------------------------------------------
    def resolve_selection(self, selected_ids=None, selected_items=None):
        """
        Maps whatever the HTTP layer received onto records this engine produced.

        Anything that did not come out of a scan in this process is rejected -
        the client never gets to name a path.
        """
        ids = []
        if selected_ids:
            ids = [str(i) for i in selected_ids if i]
        elif selected_items:
            for it in selected_items:
                if isinstance(it, dict):
                    ids.append(str(it.get("id") or make_item_id(it)))

        resolved, rejected = [], []
        with self._lock:
            for i in ids:
                item = self._scan_index.get(i)
                if item:
                    resolved.append(item)
                else:
                    rejected.append({"id": i, "reason": "הפריט אינו מוכר למנוע (לא הופק בסריקה הנוכחית)"})
        return resolved, rejected

    def delete_leftovers(self, selected_ids=None, selected_items=None, update_session=True,
                         app_name=None):
        if not selected_ids and not selected_items:
            return {"success": False, "error": "No items selected"}

        items, rejected = self.resolve_selection(selected_ids, selected_items)
        if not items and rejected:
            return {
                "success": False,
                "error": "אף אחד מהפריטים שנבחרו לא זוהה כתוצאה של סריקה. רענן את הסריקה ונסה שוב.",
                "rejected": rejected,
            }

        session_id = f"del_{int(time.time())}"
        session_dir = os.path.join(BACKUP_BASE_DIR, 'Sessions', session_id)
        self._ensure_backup_dirs()
        try:
            os.makedirs(session_dir, exist_ok=True)
        except Exception:
            pass

        elevated = is_admin()
        self.log(f"[START] מנקה {len(items)} שאריות שנבחרו"
                 + (f" · {len(rejected)} פריטים לא זוהו ונדחו" if rejected else ""), "START")
        self.log(f"[SAFETY] גיבוי הרישום נכתב אל: {session_dir}", "SAFETY")

        log_record = {
            "session_id": session_id,
            "timestamp": datetime.now().isoformat(),
            "app_name": (app_name
                         or (self.active_session or {}).get("app", {}).get("name")
                         or "ניקוי שאריות"),
            "deleted_registry": [],
            "deleted_files": [],
            "pending_reboot_files": [],
            "failed": [],
        }

        deleted_reg_count = 0
        deleted_files_count = 0
        deleted_bytes = 0
        failed = []
        backed_up_keys = []

        reg_items = [i for i in items if i.get('type') in ('key', 'value')]
        file_items = [i for i in items if i.get('type') in ('file', 'folder')]

        # ---- Registry -------------------------------------------------------
        for item in reg_items:
            path = item.get('path', '')
            item_type = item.get('type')
            name = item.get('name', '')
            hive_str = path.split('\\', 1)[0].upper() if '\\' in path else ''

            if hive_str == 'HKLM' and not elevated:
                failed.append({"path": path, "name": name, "reason": "דרושות הרשאות מנהל"})
                self.log(f"[!] דילוג על {path} — דרושות הרשאות מנהל.", "WARN")
                continue

            if item_type == 'value':
                ok, why = self._is_value_deletion_allowed(path, name)
                if not ok:
                    failed.append({"path": path, "name": name, "reason": why})
                    continue
                # Export the parent key first, so Restore.dat can bring the
                # value back - the JSON audit log alone was never restorable.
                if self.backup_registry_key_tree(path, session_dir):
                    backed_up_keys.append(path)
                done, err = self._delete_reg_value(path, name)
                if done:
                    deleted_reg_count += 1
                    log_record["deleted_registry"].append({"type": "value", "path": path, "name": name})
                    self.log(f"[✓] נמחק ערך: {path}\\{name}", "SUCCESS")
                else:
                    failed.append({"path": path, "name": name, "reason": err or "מחיקה נכשלה"})
                    self.log(f"[!] נכשל: {path}\\{name} — {err or 'מחיקה נכשלה'}", "ERROR")

            else:
                ok, why = is_reg_path_safe_to_delete(path)
                if not ok:
                    failed.append({"path": path, "name": name, "reason": why})
                    self.log(f"[!] נדחה: {path} — {why}", "WARN")
                    continue
                if self.backup_registry_key_tree(path, session_dir):
                    backed_up_keys.append(path)
                done, err = self._delete_reg_key_recursive(path)
                if done:
                    deleted_reg_count += 1
                    log_record["deleted_registry"].append({"type": "key", "path": path})
                    self.log(f"[✓] נמחק מפתח: {path}", "SUCCESS")
                else:
                    failed.append({"path": path, "name": name, "reason": err or "מחיקה נכשלה"})
                    self.log(f"[!] נכשל: {path} — {err or 'מחיקה נכשלה'}", "ERROR")

        # ---- Filesystem -----------------------------------------------------
        for item in file_items:
            p = item.get('path', '')
            ok, why = is_path_safe_to_delete(p)
            if not ok:
                failed.append({"path": p, "name": item.get('name', ''), "reason": why})
                continue
            if not os.path.exists(p):
                continue

            try:
                if os.path.isfile(p):
                    try:
                        sz = os.path.getsize(p)
                    except OSError:
                        sz = 0
                    try:
                        os.remove(p)
                    except Exception:
                        try:
                            import stat
                            os.chmod(p, stat.S_IWRITE)
                            os.remove(p)
                        except Exception:
                            pass
                    if not os.path.exists(p):
                        deleted_files_count += 1
                        deleted_bytes += sz
                        log_record["deleted_files"].append(p)
                        self.log(f"[✓] נמחק קובץ: {p} ({format_bytes(sz)})", "SUCCESS")
                    elif self._schedule_reboot_deletion(p):
                        log_record["pending_reboot_files"].append(p)
                        self.log(f"[i] {p} נעול — תוזמנה מחיקה באתחול הבא.", "WARN")
                    else:
                        failed.append({"path": p, "name": item.get('name', ''),
                                       "reason": "הקובץ נעול ולא ניתן לתזמן מחיקה באתחול"})
                        self.log(f"[!] {p} נעול ולא ניתן לתזמן מחיקה באתחול.", "ERROR")

                elif os.path.isdir(p):
                    sz, _ = self._quick_dir_size(p)
                    self.log(f"[$] מוחק תיקייה: {p} ({format_bytes(sz)})", "PLAN")
                    self._force_remove_tree(p)
                    if not os.path.exists(p):
                        deleted_files_count += 1
                        deleted_bytes += sz
                        log_record["deleted_files"].append(p)
                        self.log(f"[✓] נמחקה תיקייה: {p} ({format_bytes(sz)})", "SUCCESS")
                    else:
                        remaining = self._count_remaining(p)
                        if self._schedule_reboot_folder_deletion(p):
                            log_record["pending_reboot_files"].append(p)
                            failed.append({"path": p, "name": item.get('name', ''),
                                           "reason": f"{remaining} קבצים נעולים בידי תוכנה פעילה — תוזמנה מחיקה באתחול"})
                            self.log(f"[i] {p}: {remaining} קבצים נעולים — תוזמנה מחיקה באתחול.", "WARN")
                        else:
                            failed.append({"path": p, "name": item.get('name', ''),
                                           "reason": f"{remaining} קבצים נעולים בידי תוכנה פעילה"})
                            self.log(f"[!] {p}: {remaining} קבצים נעולים בידי תוכנה פעילה.", "ERROR")
            except Exception as e:
                failed.append({"path": p, "name": item.get('name', ''), "reason": str(e)})
                self.log(f"[!] {p} — {e}", "ERROR")

        log_record["failed"] = failed

        try:
            with open(os.path.join(session_dir, "session_log.json"), "w", encoding="utf-8") as f:
                json.dump(log_record, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

        self.create_emergency_recovery_script(
            session_id, log_record["app_name"], session_dir, deleted_keys=backed_up_keys
        )
        self.log(f"[SUMMARY] נוקו {deleted_reg_count} פריטי רישום ו-{deleted_files_count} "
                 f"קבצים ותיקיות · שוחרר {format_bytes(deleted_bytes)}"
                 + (f" · {len(failed)} לא נמחקו" if failed else ""),
                 "WARN" if failed else "SUCCESS")
        if log_record["pending_reboot_files"]:
            self.log(f"[i] {len(log_record['pending_reboot_files'])} פריטים ימחקו באתחול הבא.", "WARN")
        self.log(f"[SAFETY] ניתן לשחזר את הרישום ממרכז הגיבויים (מזהה: {session_id}).", "SAFETY")

        summary = {
            "session_id": session_id,
            "deleted_registry": deleted_reg_count,
            "deleted_files": deleted_files_count,
            "freed_bytes": deleted_bytes,
            "freed_formatted": format_bytes(deleted_bytes),
            "pending_reboot_count": len(log_record["pending_reboot_files"]),
            "reboot_required": bool(log_record["pending_reboot_files"]),
            "failed": failed,
            "failed_count": len(failed),
            "rejected": rejected,
            "is_admin": elevated,
        }

        with self._lock:
            if update_session and self.active_session:
                self.active_session["stage"] = "completed"
                self.active_session["deleted_summary"] = summary
                self.active_session["status_message"] = (
                    f"נוקו {deleted_reg_count} פריטי רישום ו-{deleted_files_count} קבצים ותיקיות"
                    + (f" · {len(failed)} פריטים לא נמחקו" if failed else "")
                )

        return {"success": True, "summary": summary, **summary}

    @staticmethod
    def _count_remaining(path, cap=50000):
        n = 0
        try:
            for _, _, files in os.walk(path):
                n += len(files)
                if n > cap:
                    break
        except Exception:
            pass
        return n

    @staticmethod
    def _is_value_deletion_allowed(key_path, value_name):
        """
        Single values may only be removed from the autostart / shell-cache keys
        the scanner reads. Everything else needs the key-level gate.
        """
        if not value_name:
            return False, "מחיקת ערך ברירת המחדל של מפתח אינה נתמכת"
        norm = _norm_reg_path(key_path)
        allowed_suffixes = (
            r"\microsoft\windows\currentversion\run",
            r"\microsoft\windows\currentversion\runonce",
            r"\microsoft\windows\shell\muicache",
        )
        if any(norm.endswith(s) for s in allowed_suffixes):
            return True, None
        return False, "מחיקת ערכים מותרת רק במפתחות ההפעלה האוטומטית ובמטמון הממשק"

    @staticmethod
    def _hive_from_string(hive_str):
        if not winreg:
            return None
        return {
            'HKLM': winreg.HKEY_LOCAL_MACHINE,
            'HKCU': winreg.HKEY_CURRENT_USER,
            'HKCR': winreg.HKEY_CLASSES_ROOT,
        }.get((hive_str or '').upper())

    def _delete_reg_value(self, full_key_path, value_name):
        if not winreg:
            return False, "winreg לא זמין"
        try:
            hive_str, sub_p = full_key_path.split('\\', 1)
        except ValueError:
            return False, "נתיב רישום לא תקין"
        hive = self._hive_from_string(hive_str)
        if hive is None:
            return False, "כוורת רישום לא נתמכת"
        try:
            k = winreg.OpenKey(hive, sub_p, 0, winreg.KEY_SET_VALUE)
        except FileNotFoundError:
            return True, None
        except Exception as e:
            return False, str(e)
        try:
            winreg.DeleteValue(k, value_name)
            return True, None
        except FileNotFoundError:
            return True, None
        except Exception as e:
            return False, str(e)
        finally:
            winreg.CloseKey(k)

    def _delete_reg_key_recursive(self, full_key_path):
        """
        Deletes a key and everything under it. Returns (ok, error).

        The previous implementation looped on ``EnumKey(k, 0)`` and swallowed
        the DeleteKey error, so a child that could not be removed made it
        enumerate the same name forever and hang the request thread. Children
        are now enumerated up front and every failure propagates.
        """
        if not winreg:
            return False, "winreg לא זמין"
        try:
            hive_str, sub_p = full_key_path.split('\\', 1)
        except ValueError:
            return False, "נתיב רישום לא תקין"
        hive = self._hive_from_string(hive_str)
        if hive is None:
            return False, "כוורת רישום לא נתמכת"

        def _walk(sub, depth):
            if depth > MAX_REG_DEPTH:
                return False, "עץ הרישום עמוק מהמותר"
            try:
                k = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ)
            except FileNotFoundError:
                return True, None
            except Exception as e:
                return False, str(e)

            children = []
            try:
                n_sub, _, _ = winreg.QueryInfoKey(k)
                for i in range(n_sub):
                    try:
                        children.append(winreg.EnumKey(k, i))
                    except OSError:
                        break
            except Exception:
                pass
            finally:
                winreg.CloseKey(k)

            for child in children:
                ok, err = _walk(sub + "\\" + child, depth + 1)
                if not ok:
                    return False, err

            try:
                winreg.DeleteKey(hive, sub)
                return True, None
            except FileNotFoundError:
                return True, None
            except (PermissionError, OSError) as primary_err:
                deleted = False
                if hasattr(winreg, 'DeleteKeyEx'):
                    for flags in (getattr(winreg, 'KEY_WOW64_64KEY', 0x0100), getattr(winreg, 'KEY_WOW64_32KEY', 0x0200)):
                        try:
                            winreg.DeleteKeyEx(hive, sub, flags, 0)
                            deleted = True
                            break
                        except FileNotFoundError:
                            deleted = True
                            break
                        except Exception:
                            pass
                if deleted:
                    return True, None
                if isinstance(primary_err, PermissionError) or getattr(primary_err, 'winerror', 0) == 5:
                    return False, "אין הרשאה למחוק את המפתח"
                return False, str(primary_err)
            except Exception as e:
                return False, str(e)

        return _walk(sub_p, 0)

    @staticmethod
    def _force_remove_tree(dir_path):
        import stat
        def _remove_readonly(func, path, _):
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except Exception:
                pass
        try:
            shutil.rmtree(dir_path, onerror=_remove_readonly)
        except Exception:
            pass

    def _schedule_reboot_deletion(self, path):
        if not IS_WINDOWS:
            return False
        try:
            return ctypes.windll.kernel32.MoveFileExW(path, None, MOVEFILE_DELAY_UNTIL_REBOOT) != 0
        except Exception:
            return False

    def _schedule_reboot_folder_deletion(self, folder_path):
        if not IS_WINDOWS:
            return False
        scheduled_any = False
        try:
            import stat
            for root, dirs, files in os.walk(folder_path, topdown=False):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        os.chmod(fp, stat.S_IWRITE)
                    except Exception:
                        pass
                    if self._schedule_reboot_deletion(fp):
                        scheduled_any = True
                for d in dirs:
                    dp = os.path.join(root, d)
                    try:
                        os.chmod(dp, stat.S_IWRITE)
                    except Exception:
                        pass
                    if self._schedule_reboot_deletion(dp):
                        scheduled_any = True
            try:
                os.chmod(folder_path, stat.S_IWRITE)
            except Exception:
                pass
            if self._schedule_reboot_deletion(folder_path):
                scheduled_any = True
        except Exception:
            pass
        return scheduled_any

    # -------------------------------------------------------------------------
    # 6. Forced Uninstall & Quick / Batch Uninstall
    # -------------------------------------------------------------------------
    def run_forced_uninstall(self, name_or_path, mode="moderate"):
        name = ""
        install_loc = ""
        name_or_path = (name_or_path or "").strip().strip('"')
        if not name_or_path:
            return {"success": False, "error": "לא הוזן שם תוכנה או נתיב"}

        # The forced flow resets the shared log, plan and skip flag, so it has to
        # claim the engine exactly like a wizard run does - otherwise it would
        # wipe a live session's terminal out from under it.
        with self._lock:
            if self._busy:
                return {"success": False, "error": "פעולת הסרה אחרת כבר פועלת. המתן לסיומה."}
            self._busy = True

        try:
            return self._run_forced_uninstall(name_or_path, mode)
        finally:
            self._stop_heartbeat.set()
            self._skip_requested.clear()
            with self._lock:
                self._busy = False

    def _resolve_uwp_target(self, name_or_path):
        """
        Determines if name_or_path refers to a Windows Store / UWP / MSIX package.
        Returns a dict with package metadata (package_full_name, name, install_location, etc.),
        or None if not a UWP package.
        """
        target = (name_or_path or "").strip().strip('"')
        if not target:
            return None

        norm_target = _norm_win_path(target)

        # 1. Path inside WindowsApps folder
        package_full_name_candidate = None
        if "\\windowsapps\\" in norm_target:
            after_wa = norm_target.split("\\windowsapps\\", 1)[1]
            seg = after_wa.split("\\")[0]
            if seg:
                package_full_name_candidate = seg

        # 2. Check installed UWP apps from system
        uwp_apps = []
        try:
            uwp_apps = self._get_uwp_apps() or []
        except Exception:
            uwp_apps = []

        target_lower = target.lower()

        # If candidate extracted from WindowsApps path, check matches first
        if package_full_name_candidate:
            cand_lower = package_full_name_candidate.lower()
            for app in uwp_apps:
                if app.get("package_full_name", "").lower() == cand_lower:
                    return app

            # Construct fallback metadata from the folder name
            raw_n = package_full_name_candidate.split("_")[0] if "_" in package_full_name_candidate else package_full_name_candidate
            clean_n = raw_n.replace("microsoft.", "").replace(".", " ").title() if "microsoft." in raw_n.lower() else raw_n
            seg_parts = package_full_name_candidate.split("_")
            fam_name = f"{seg_parts[0]}_{seg_parts[-1]}" if len(seg_parts) >= 2 else ""
            return {
                "id": f"uwp_{hashlib.md5(package_full_name_candidate.encode()).hexdigest()[:12]}",
                "type": "uwp",
                "name": clean_n,
                "raw_name": raw_n,
                "package_full_name": package_full_name_candidate,
                "package_family_name": fam_name,
                "publisher": "Microsoft Store / Developer",
                "version": seg_parts[1] if len(seg_parts) > 1 else "-",
                "install_location": target if os.path.isdir(target) else os.path.dirname(target),
            }

        # Check installed apps by package_full_name, raw_name, name, or install_location
        for app in uwp_apps:
            pkg_full = app.get("package_full_name", "").lower()
            raw_n = app.get("raw_name", "").lower()
            n = app.get("name", "").lower()
            inst_loc = _norm_win_path(app.get("install_location", ""))

            if target_lower in (pkg_full, raw_n, n):
                return app
            if inst_loc and inst_loc == norm_target:
                return app

        # 3. Check if target string itself looks like a PackageFullName
        # Pattern: <Name>_<Version>_<Arch>_<ResourceId>_<PublisherId>
        if re.match(r'^[a-zA-Z0-9\.\-]+_\d+\.\d+.*_[a-zA-Z0-9]+$', target):
            parts = target.split("_")
            raw_n = parts[0]
            clean_n = raw_n.replace("Microsoft.", "").replace(".", " ")
            fam_name = f"{parts[0]}_{parts[-1]}" if len(parts) >= 2 else ""
            return {
                "id": f"uwp_{hashlib.md5(target.encode()).hexdigest()[:12]}",
                "type": "uwp",
                "name": clean_n,
                "raw_name": raw_n,
                "package_full_name": target,
                "package_family_name": fam_name,
                "publisher": "Microsoft Store / Developer",
                "version": parts[1] if len(parts) > 1 else "-",
                "install_location": "",
            }

        return None

    def _run_forced_uwp_uninstall(self, uwp_app, original_target, mode):
        name = uwp_app.get("name", "")
        pkg = uwp_app.get("package_full_name", "")
        install_loc = uwp_app.get("install_location", "")

        app_metadata = {
            "id": uwp_app.get("id", ""),
            "type": "uwp",
            "name": name,
            "raw_name": uwp_app.get("raw_name", name),
            "package_full_name": pkg,
            "package_family_name": uwp_app.get("package_family_name", ""),
            "publisher": uwp_app.get("publisher", "Microsoft Store / Developer"),
            "install_location": install_loc,
            "raw_key_name": "",
            "registry_key": "",
        }

        self.log(f"[START] הסרה כפויה: {name} (אפליקציית Windows Store)", "START")
        self.log(f"[$] מזהה חבילה: {pkg}", "INFO")
        if install_loc:
            self.log(f"[$] תיקיית התקנה: {install_loc}", "INFO")
        self.log(f"[$] מצב סריקה: {mode}", "INFO")
        self.log("[?] אפליקציות Windows Store מוסרות דרך תשתית AppX של Windows.", "INFO")

        # Plan steps: UWP skips restore point and registry backup, but executes native removal
        self._plan_steps(
            skip_restore_point=True,
            skip_registry_backup=True,
            is_uwp=True,
            force_skip_native=False,
        )

        self._start_heartbeat()
        native_ok = False
        try:
            self._begin_step("native_uninstall")
            scope = " -AllUsers" if is_admin() else ""
            self.log(f"[$] Remove-AppxPackage -Package '{pkg}'{scope}", "PLAN")
            res = run_hidden(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f"Remove-AppxPackage -Package '{pkg}'{scope}"],
                capture_output=True, text=True, timeout=180
            )
            if getattr(res, "returncode", 1) == 0:
                native_ok = True
                self.log("[✓] חבילת ה-UWP הוסרה בהצלחה ממערכת ההפעלה.", "SUCCESS")
                self._end_step("native_uninstall", "done", "החבילה הוסרה")
            else:
                err = (getattr(res, 'stderr', '') or '').strip().splitlines()
                err_msg = err[0] if err else f"קוד יציאה {getattr(res, 'returncode', 'שגיאה')}"
                self.log(f"[ERROR] שגיאה בהסרת חבילת UWP: {err_msg}", "ERROR")
                self._end_step("native_uninstall", "failed", err_msg)

            leftovers = self.scan_leftovers(
                app_metadata, mode=mode, still_installed=not native_ok
            )
        finally:
            self._stop_heartbeat.set()

        n_reg = len(leftovers.get('registry', []))
        n_files = len(leftovers.get('files', []))
        self.log(f"[SUMMARY] נמצאו {n_reg} שאריות רישום ו-{n_files} קבצים ותיקיות.", "SUCCESS")

        return {
            "success": True,
            "target": original_target,
            "app_metadata": app_metadata,
            "resolved_name": name,
            "resolved_location": install_loc,
            "leftovers": leftovers,
            "is_uwp": True,
            "native_uninstall_ok": native_ok
        }

    def _run_forced_uninstall(self, name_or_path, mode):
        name = ""
        install_loc = ""
        forced_id = f"forced_{int(time.time())}"

        self._skip_requested.clear()
        # The previous wizard session is over; leaving it attached would keep
        # `active` true and stop this run's plan from driving the bar.
        with self._lock:
            self.active_session = None
        self._reset_run_state(owner=forced_id)

        # Detect if target is a Windows Store / UWP / MSIX package
        uwp_app = self._resolve_uwp_target(name_or_path)
        if uwp_app:
            return self._run_forced_uwp_uninstall(uwp_app, name_or_path, mode)

        if os.path.exists(name_or_path):
            if os.path.isdir(name_or_path):
                install_loc = os.path.abspath(name_or_path)
                name = os.path.basename(install_loc)
            else:
                install_loc = os.path.dirname(os.path.abspath(name_or_path))
                name = os.path.splitext(os.path.basename(name_or_path))[0]
        else:
            name = name_or_path

        app_metadata = {
            "name": name,
            "publisher": "",
            "install_location": install_loc,
            "raw_key_name": "",
            "registry_key": "",
        }

        # The forced flow has no uninstaller to run, so it publishes a two-step
        # plan and streams into the same terminal as a normal run.
        self.log(f"[START] הסרה כפויה: {name_or_path}", "START")
        self.log(f"[$] יעד: {name}" + (f" · תיקייה: {install_loc}" if install_loc else " · ללא תיקייה מזוהה"), "INFO")
        self.log(f"[$] מצב סריקה: {mode}", "INFO")
        self.log("[?] לא מורצת שום פקודת הסרה — רק סריקה של מה שנשאר במערכת.", "INFO")
        # force_skip_native so the printed plan does not advertise a step that
        # is then immediately marked as skipped one line later.
        self._plan_steps(
            skip_restore_point=True, skip_registry_backup=True, is_uwp=False,
            force_skip_native=True,
            native_skip_reason="הסרה כפויה — אין מסיר מקורי להריץ",
        )

        self._start_heartbeat()
        try:
            leftovers = self.scan_leftovers(app_metadata, mode=mode)
        finally:
            self._stop_heartbeat.set()

        n_reg = len(leftovers.get('registry', []))
        n_files = len(leftovers.get('files', []))
        self.log(f"[SUMMARY] נמצאו {n_reg} שאריות רישום ו-{n_files} קבצים ותיקיות.", "SUCCESS")

        return {
            "success": True,
            "target": name_or_path,
            "app_metadata": app_metadata,
            "resolved_name": name,
            "resolved_location": install_loc,
            "leftovers": leftovers
        }

    def run_standalone_scan(self, app_id, mode="moderate"):
        """
        Scans one installed app for leftovers without uninstalling anything.

        Claims the engine like any other run: the log and the step plan are a
        single shared resource, and a scan that started underneath a live
        session used to rewrite that session's steps.
        """
        with self._lock:
            if self._busy:
                return {"success": False, "error": "פעולת הסרה אחרת כבר פועלת. המתן לסיומה."}
            self._busy = True

        try:
            app = next((a for a in self.get_installed_apps() if a.get('id') == app_id), None)
            if not app:
                return {"success": False, "error": "Application not found"}

            scan_id = f"scan_{int(time.time())}"
            self._skip_requested.clear()
            with self._lock:
                self.active_session = None
            self._reset_run_state(owner=scan_id)
            self.log(f"[START] סריקת שאריות בלבד: {app.get('name')}", "START")
            self._plan_steps(
                skip_restore_point=True, skip_registry_backup=True, is_uwp=False,
                force_skip_native=True, native_skip_reason="סריקה בלבד — לא מורצת הסרה",
            )
            self._start_heartbeat()
            try:
                # still_installed: nothing was uninstalled, so the program's own
                # folder and Add/Remove entry are not leftovers and must not be
                # offered - let alone pre-selected - for deletion.
                leftovers = self.scan_leftovers(app, mode=mode, still_installed=True)
            finally:
                self._stop_heartbeat.set()

            return {"success": True, "app_metadata": app, "leftovers": leftovers}
        finally:
            self._skip_requested.clear()
            with self._lock:
                self._busy = False

    def run_batch_uninstall(self, app_ids, mode="moderate", skip_restore_point=False):
        all_apps = {a["id"]: a for a in self.get_installed_apps()}
        targets = [all_apps[aid] for aid in app_ids if aid in all_apps]
        if not targets:
            return {"success": False, "error": "No valid applications selected"}

        with self._lock:
            if self._busy:
                return {"success": False, "error": "פעולת הסרה אחרת כבר פועלת. המתן לסיומה."}
            self._busy = True

        try:
            self._skip_requested.clear()
            # Batch scans call scan_leftovers directly; without its own run
            # state they would mutate the previous session's published plan.
            with self._lock:
                self.active_session = None
            self._reset_run_state(owner=f"batch_{int(time.time())}")
            self.log(f"[START] הסרה מרוכזת של {len(targets)} תוכנות", "START")
            warnings = []

            if not skip_restore_point:
                rp = self.create_system_restore_point(f"Batch Uninstall ({len(targets)} apps)")
                if not rp.get("success"):
                    warnings.append(f"נקודת שחזור לא נוצרה: {rp.get('error')}")

            results = []
            succeeded = 0
            needs_review = []

            for app in targets:
                removed = False
                note = ""

                if app.get("type") == "uwp":
                    scope = " -AllUsers" if is_admin() else ""
                    try:
                        res = run_hidden(
                            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                             f"Remove-AppxPackage -Package '{app.get('package_full_name')}'{scope}"],
                            capture_output=True, timeout=180
                        )
                        removed = (res.returncode == 0)
                    except Exception as e:
                        note = str(e)
                else:
                    cmd = app.get("quiet_uninstall_string") or app.get("uninstall_string") or ""
                    cmd = to_silent_command(to_uninstall_command(cmd))
                    if cmd:
                        try:
                            p = popen_hidden(cmd, shell=True)
                            rc = p.wait(timeout=300)
                            # 3010 is "succeeded, reboot required" - counting it
                            # as a failure misreported every such uninstall.
                            removed = rc in (0, 3010)
                            if rc == 3010:
                                note = "הוסר — נדרשת הפעלה מחדש"
                            elif rc != 0:
                                note = f"קוד יציאה {rc}"
                        except subprocess.TimeoutExpired:
                            note = "המסיר לא הסתיים תוך 5 דקות"
                            try:
                                p.kill()
                            except Exception:
                                pass
                        except Exception as e:
                            note = str(e)
                    else:
                        note = "לא נמצאה פקודת הסרה"

                if removed:
                    succeeded += 1

                # If the uninstall did not actually succeed, the program is
                # still installed - its own folder and Add/Remove entry are not
                # residue, and the unattended clean below must not touch them.
                leftovers = self.scan_leftovers(app, mode=mode, still_installed=not removed)
                all_items = leftovers.get("registry", []) + leftovers.get("files", [])

                # Only ordinary application residue is cleaned unattended.
                # Services, drivers, COM registration and MSI bookkeeping are
                # handed back for a human to look at.
                auto = [i for i in all_items if i.get("is_bold") and i.get("risk") == "low"]
                review = [i for i in all_items if i.get("risk") == "high" or not i.get("is_bold")]
                needs_review.extend(review)

                cleaned = 0
                del_failed = 0
                if auto:
                    res = self.delete_leftovers(
                        selected_ids=[i["id"] for i in auto],
                        update_session=False,
                        app_name=app.get("name"),
                    )
                    cleaned = res.get("deleted_registry", 0) + res.get("deleted_files", 0)
                    del_failed = res.get("failed_count", 0)

                results.append({
                    "name": app.get("name"),
                    "removed": removed,
                    "note": note,
                    "leftovers_cleaned": cleaned,
                    "leftovers_failed": del_failed,
                    "needs_review": len(review),
                })

            return {
                "success": True,
                "total": len(targets),
                "succeeded": succeeded,
                "failed": len(targets) - succeeded,
                "needs_review": len(needs_review),
                "needs_review_items": needs_review[:200],
                "warnings": warnings,
                "results": results,
            }
        finally:
            self._skip_requested.clear()
            with self._lock:
                self._busy = False

    # -------------------------------------------------------------------------
    # 7. Hunter Mode Target Resolution & Actions
    # -------------------------------------------------------------------------
    def resolve_hunter_target(self, process_name_or_pid_or_path):
        if psutil is None:
            return {"success": False, "error": "המודול psutil אינו זמין — כוונת ציד מושבתת"}

        target = (process_name_or_pid_or_path or "").strip().strip('"')
        if not target:
            return {"success": False, "error": "לא הוזנה מטרה"}

        info = {
            "pid": None,
            "process_name": None,
            "exe_path": None,
            "cmdline": None,
            "memory_mb": None,
            "autostart_entries": [],
            "matched_app": None,
        }

        try:
            if target.isdigit():
                p = psutil.Process(int(target))
                info.update(self._describe_process(p))
            elif os.path.exists(target):
                path = os.path.abspath(target)
                info["exe_path"] = path
                info["process_name"] = os.path.basename(path)
                for p in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        if p.info.get('exe') and os.path.normcase(p.info['exe']) == os.path.normcase(path):
                            info.update(self._describe_process(p))
                            break
                    except Exception:
                        continue
            else:
                low = target.lower()
                for p in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        if p.info.get('name') and low in p.info['name'].lower():
                            info.update(self._describe_process(p))
                            break
                    except Exception:
                        continue
        except psutil.NoSuchProcess:
            return {"success": False, "error": "התהליך אינו קיים יותר"}
        except psutil.AccessDenied:
            return {"success": False, "error": "אין הרשאה לקרוא את פרטי התהליך (נסה להריץ כמנהל)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

        if not info["exe_path"] and not info["pid"]:
            return {"success": False, "error": "לא נמצא תהליך או קובץ תואם"}

        exe = info.get("exe_path")
        if exe:
            exe_norm = _norm_win_path(exe)
            for a in self.get_installed_apps():
                loc = self._usable_install_loc(a.get("install_location"))
                if loc and exe_norm.startswith(loc + '\\'):
                    info["matched_app"] = a
                    break
            info["autostart_entries"] = self._find_autostart_for(exe)

        # `query` echoes what the user typed. It used to be spread as `target`,
        # which collided with the dict below it and rendered as [object Object]
        # whenever the process name could not be read.
        return {"success": True, "query": target, "target": info, **info}

    @staticmethod
    def _describe_process(p):
        out = {"pid": p.pid}
        try:
            out["process_name"] = p.name()
        except Exception:
            pass
        try:
            out["exe_path"] = p.exe()
        except Exception:
            pass
        try:
            out["cmdline"] = " ".join(p.cmdline())
        except Exception:
            pass
        try:
            out["memory_mb"] = round(p.memory_info().rss / (1024 * 1024), 1)
        except Exception:
            pass
        return out

    @staticmethod
    def _find_autostart_for(exe_path):
        found = []
        if not (IS_WINDOWS and winreg and exe_path):
            return found
        needle = _norm_win_path(exe_path)
        base = os.path.basename(exe_path).lower()
        for hive, hive_name in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            for path in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                         r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"):
                try:
                    k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                except Exception:
                    continue
                try:
                    _, n_vals, _ = winreg.QueryInfoKey(k)
                    for i in range(n_vals):
                        try:
                            v_name, v_data, _ = winreg.EnumValue(k, i)
                        except Exception:
                            break
                        data_norm = _norm_win_path(str(v_data))
                        if needle in data_norm or base in data_norm:
                            found.append({"hive": hive_name, "path": path, "name": v_name, "value": str(v_data)})
                finally:
                    winreg.CloseKey(k)
        return found

    def execute_hunter_action(self, action, target_path, pid=None):
        result = {"success": True, "action": action, "message": ""}
        messages = []

        if action in ('kill', 'kill_and_delete'):
            if psutil is None:
                return {"success": False, "error": "המודול psutil אינו זמין"}
            if not pid:
                return {"success": False, "error": "לא התקבל מזהה תהליך (PID)"}
            try:
                p = psutil.Process(int(pid))
                p.kill()
                try:
                    p.wait(timeout=5)
                except Exception:
                    pass
                messages.append(f"התהליך {pid} נסגר.")
            except psutil.NoSuchProcess:
                messages.append("התהליך כבר לא רץ.")
            except psutil.AccessDenied:
                return {"success": False, "error": "אין הרשאה לסגור את התהליך (נסה להריץ כמנהל)"}
            except Exception as e:
                return {"success": False, "error": str(e)}

        if action == 'kill_and_delete':
            ok, why = is_path_safe_to_delete(target_path or "")
            if not ok:
                return {"success": False, "error": f"מחיקת הקובץ נדחתה: {why}"}
            if os.path.exists(target_path):
                try:
                    os.remove(target_path)
                except Exception:
                    pass
                if not os.path.exists(target_path):
                    messages.append("הקובץ נמחק.")
                elif self._schedule_reboot_deletion(target_path):
                    messages.append("הקובץ נעול — תוזמנה מחיקה באתחול הבא.")
                else:
                    return {"success": False, "error": "הקובץ נעול ולא ניתן היה למחוק אותו."}
            else:
                messages.append("הקובץ כבר לא קיים.")

        if action == 'disable_autostart':
            if not target_path:
                return {"success": False, "error": "לא התקבל נתיב מטרה"}
            if not winreg:
                return {"success": False, "error": "רישום Windows אינו זמין"}
            removed = 0
            needle = _norm_win_path(target_path)
            base = os.path.basename(target_path).lower()
            for hive, hive_name in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
                if hive_name == "HKLM" and not is_admin():
                    continue
                for path in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"):
                    try:
                        k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE)
                    except Exception:
                        continue
                    try:
                        _, n_vals, _ = winreg.QueryInfoKey(k)
                        to_del = []
                        for i in range(n_vals):
                            try:
                                v_name, v_data, _ = winreg.EnumValue(k, i)
                            except Exception:
                                break
                            data_norm = _norm_win_path(str(v_data))
                            if needle in data_norm or base in data_norm:
                                to_del.append(v_name)
                        for n in to_del:
                            try:
                                winreg.DeleteValue(k, n)
                                removed += 1
                            except Exception:
                                pass
                    finally:
                        winreg.CloseKey(k)
            if removed:
                messages.append(f"הוסרו {removed} ערכי הפעלה אוטומטית.")
            else:
                messages.append("לא נמצאו ערכי הפעלה אוטומטית עבור קובץ זה.")

        if action == 'open_folder':
            if not target_path or not os.path.exists(target_path):
                return {"success": False, "error": "הנתיב אינו קיים"}
            ok, msg = reveal_in_explorer(target_path)
            if not ok:
                return {"success": False, "error": msg}
            messages.append(msg + ".")

        if not messages:
            return {"success": False, "error": f"פעולה לא מוכרת: {action}"}

        result["message"] = " ".join(messages)
        return result

    # -------------------------------------------------------------------------
    # 8. Backup Center Management (History & Restoration)
    # -------------------------------------------------------------------------
    def get_backup_history(self):
        sessions_dir = os.path.join(BACKUP_BASE_DIR, 'Sessions')
        sessions = []
        if not os.path.exists(sessions_dir):
            return sessions

        for s_name in sorted(os.listdir(sessions_dir), reverse=True):
            s_path = os.path.join(sessions_dir, s_name)
            if not os.path.isdir(s_path):
                continue

            try:
                files = os.listdir(s_path)
            except Exception:
                continue

            reg_files = [f for f in files if f.startswith("reg_") and f.endswith(".reg")]
            has_script = "Restore.dat" in files

            data = {}
            log_file = os.path.join(s_path, "session_log.json")
            if os.path.exists(log_file):
                try:
                    with open(log_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    data = {}

            if not reg_files and not data:
                continue

            ts = data.get("timestamp")
            date_str = ts
            if ts:
                try:
                    date_str = datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M")
                except Exception:
                    pass
            else:
                try:
                    date_str = datetime.fromtimestamp(os.path.getmtime(s_path)).strftime("%Y-%m-%d %H:%M")
                except Exception:
                    date_str = s_name

            sessions.append({
                "session_id": s_name,
                "timestamp": ts,
                "date_str": date_str,
                "app_name": data.get("app_name") or "—",
                "registry_backups": reg_files,
                "has_restore_script": has_script,
                "deleted_reg_count": len(data.get("deleted_registry", [])),
                "deleted_files_count": len(data.get("deleted_files", [])),
                "failed_count": len(data.get("failed", [])),
                "path": s_path
            })
        return sessions

    def restore_backup(self, session_id):
        if not session_id or not re.match(r'^[A-Za-z0-9_.-]+$', str(session_id)):
            return {"success": False, "error": "מזהה גיבוי לא תקין"}

        session_dir = os.path.join(BACKUP_BASE_DIR, 'Sessions', session_id)
        if not os.path.isdir(session_dir):
            return {"success": False, "error": "תיקיית הגיבוי לא נמצאה"}

        restored = 0
        failures = []
        for f in sorted(os.listdir(session_dir)):
            if not (f.startswith("reg_") and f.endswith(".reg")):
                continue
            reg_file = os.path.join(session_dir, f)
            try:
                res = run_hidden(["reg.exe", "import", reg_file], capture_output=True, text=True)
            except Exception as e:
                failures.append(f"{f}: {e}")
                continue
            if res.returncode == 0:
                restored += 1
            else:
                failures.append(f"{f}: {(res.stderr or '').strip() or f'קוד {res.returncode}'}")

        if restored == 0 and failures:
            return {
                "success": False,
                "error": "שחזור הרישום נכשל" + ("" if is_admin() else " — ייתכן שדרושות הרשאות מנהל"),
                "failures": failures,
            }

        msg = f"שוחזרו {restored} ייצואי רישום."
        if failures:
            msg += f" {len(failures)} נכשלו."
        msg += " שים לב: קבצים שנמחקו אינם מכוסים בגיבוי זה."

        return {"success": True, "message": msg, "restored_reg_files": restored, "failures": failures}

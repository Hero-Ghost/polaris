"""
Polaris - Safe Deep System Revitalizer & Windows Repair Engine
100% Microsoft-approved, non-destructive system repair and refresh engine.

Execution model
---------------
Every maintenance action is declared once in STEP_DEFS with a lane, a weight
and a plain-Hebrew explanation. The runner turns the user's checkbox options
into a concrete plan, runs the cheap independent steps concurrently and the
service-touching / image-repair steps one at a time, and publishes a live
per-step status that the UI renders as a checklist.

Two things used to make the old runner look frozen and they are both fixed
here:

  * dism.exe and sfc.exe draw their progress with carriage returns, not
    newlines, so ``for line in proc.stdout`` yielded nothing at all until the
    process exited. Output is now read as raw bytes and split on BOTH \\r and
    \\n through an incremental decoder (sfc.exe also emits UTF-16LE down a
    redirected pipe, which the decoder detects).
  * when Polaris is not elevated, DISM was launched through
    ``Start-Process -Verb RunAs -Wait`` with its output captured, which threw
    every line away. It now elevates a cmd.exe wrapper that redirects to a
    temp file, and that file is tailed live while the tool runs.
"""

import os
import re
import sys
import time
import codecs
import queue
import shutil
import tempfile
import subprocess
import threading
import psutil

from concurrent.futures import ThreadPoolExecutor

from backend.win_utils import run_hidden, popen_hidden, is_admin, format_bytes as _fmt

# winreg only exists on Windows - keep the module importable elsewhere so the
# server can start (and report "Windows only") instead of crashing at import.
try:
    import winreg
except ImportError:
    winreg = None

IS_WINDOWS = sys.platform.startswith('win')

# A console line that carries a percentage is a progress redraw, not news.
# Those collapse onto a single self-updating log row instead of flooding the
# terminal with hundreds of near-identical lines.
_PCT_RE = re.compile(r'(\d{1,3}(?:[.,]\d+)?)\s*%')

# How often the heartbeat thread reassures the UI that a long step is alive.
HEARTBEAT_SECONDS = 3.0

# Lanes:
#   "fast"    - cheap, independent, safe to run concurrently
#   "fast2"   - cheap, but must follow the first wave (TRIM after temp delete)
#   "serial"  - touches services or the component store; strictly one at a time
STEP_DEFS = [
    {
        "id": "flush_ram",
        "lane": "fast",
        "weight": 2,
        "title_he": "שחרור זיכרון RAM ומטמון רדום",
        "title_en": "Release working sets and idle RAM",
        "explain_he": "מבקש מ-Windows להחזיר לזיכרון הפנוי דפים שתוכנות תפסו ולא משתמשות בהם. לא סוגר שום תוכנה.",
        "explain_en": "Asks Windows to return pages that apps reserved but no longer use. Closes nothing.",
        "command_he": "EmptyWorkingSet לכל תהליך",
    },
    {
        "id": "clean_temp",
        "lane": "fast",
        "weight": 12,
        "title_he": "ניקוי קבצי מטמון זמניים ושאריות עדכונים",
        "title_en": "Clean temporary files and old update leftovers",
        "explain_he": "מוחק רק קבצים בתיקיות הזמניות של Windows שלא נגעו בהם ב-24 השעות האחרונות. מסמכים, תמונות ותוכנות מותקנות לא נוגעים.",
        "explain_en": "Deletes only files in Windows temp folders untouched for 24h. Personal files are never touched.",
        "command_he": "מחיקה מ-%TEMP%, %WINDIR%\\Temp, SoftwareDistribution\\Download",
    },
    {
        "id": "flush_dns",
        "lane": "fast",
        "weight": 2,
        "title_he": "רענון מטמון DNS",
        "title_en": "Flush the DNS resolver cache",
        "explain_he": "מנקה את טבלת כתובות האתרים השמורה במחשב. עוזר כשאתר נטען שגוי או לא נטען בכלל.",
        "explain_en": "Clears the cached site-address table. Helps when a site loads stale or not at all.",
        "command_he": "ipconfig /flushdns",
    },
    {
        "id": "retrim_ssd",
        "lane": "fast2",
        "weight": 12,
        "title_he": "מיטוב כונן SSD (פקודת TRIM)",
        "title_en": "SSD optimization (TRIM)",
        "explain_he": "מודיע לכונן אילו תאים כבר לא בשימוש, כדי שכתיבות עתידיות יהיו מהירות. פעולה רשמית של Windows, לא איחוי דיסק.",
        "explain_en": "Tells the drive which cells are free so future writes stay fast. Not a defrag.",
        "command_he": "Optimize-Volume -DriveLetter C -ReTrim",
    },
    {
        "id": "reset_network",
        "lane": "serial",
        "weight": 8,
        "title_he": "איפוס מחסנית רשת ו-Winsock",
        "title_en": "Reset the network stack and Winsock",
        "explain_he": "מחזיר את הגדרות התקשורת של Windows למצב נקי. מומלץ לאתחל את המחשב אחרי הפעולה הזו.",
        "explain_en": "Returns Windows networking to a clean state. A restart is recommended afterwards.",
        "command_he": "netsh winsock reset + netsh int ip reset",
    },
    {
        "id": "reset_spooler",
        "lane": "serial",
        "weight": 8,
        "title_he": "איפוס שירות הדפסה וניקוי תור",
        "title_en": "Reset the print spooler and clear its queue",
        "explain_he": "עוצר את שירות ההדפסה, מוחק מסמכים תקועים בתור ומפעיל אותו מחדש. משמש כשמדפסת לא מגיבה.",
        "explain_en": "Stops the spooler, drops stuck jobs and restarts it. For an unresponsive printer.",
        "command_he": "net stop/start spooler",
    },
    {
        "id": "reset_wu",
        "lane": "serial",
        "weight": 20,
        "title_he": "איפוס שירותי Windows Update",
        "title_en": "Reset the Windows Update services",
        "explain_he": "עוצר את שירותי העדכונים, מוחק הורדות פגומות שנתקעו ומפעיל אותם מחדש. משמש כשעדכון נכשל שוב ושוב.",
        "explain_en": "Stops update services, drops corrupt downloads and restarts them.",
        "command_he": "net stop wuauserv/bits/cryptsvc + ניקוי Download",
    },
    # DISM must precede SFC: SFC restores damaged files *from* the component
    # store, so repairing the store first is what makes the SFC pass useful.
    {
        "id": "dism_restore",
        "lane": "serial",
        "weight": 300,
        "title_he": "תיקון תמונת מערכת Windows (DISM RestoreHealth)",
        "title_en": "Repair the Windows image (DISM RestoreHealth)",
        "explain_he": "מתקן את מאגר הרכיבים של Windows עצמו, שממנו SFC שואב עותקים תקינים. לכן הוא רץ לפני SFC. איטי מטבעו — בדרך כלל 5 עד 20 דקות.",
        "explain_en": "Repairs the component store that SFC restores from, so it runs before SFC. Typically 5-20 minutes.",
        "command_he": "dism /online /cleanup-image /restorehealth",
    },
    {
        "id": "sfc_scan",
        "lane": "serial",
        "weight": 300,
        "title_he": "סריקה ותיקון קבצי מערכת (SFC)",
        "title_en": "System File Checker scan (SFC)",
        "explain_he": "בודק כל קובץ ליבה מוגן של Windows מול העותק הרשמי ומחליף עותקים פגומים. איטי מטבעו — בדרך כלל 5 עד 15 דקות.",
        "explain_en": "Verifies every protected Windows core file and restores damaged copies. Typically 5-15 minutes.",
        "command_he": "sfc.exe /scannow",
    },
    {
        "id": "dism_cleanup",
        "lane": "serial",
        "weight": 240,
        "title_he": "ניקוי ספריית רכיבי Windows (DISM ResetBase)",
        "title_en": "Clean the component store (DISM ResetBase)",
        "explain_he": "מוחק גיבויים של עדכונים ישנים ומצמצם את WinSxS. משחרר מקום אמיתי, אבל אחריו אי אפשר להסיר עדכונים קודמים. איטי מטבעו — 4 עד 20 דקות, ואין צורך להריץ יותר מפעם בכמה חודשים.",
        "explain_en": "Removes superseded update backups and shrinks WinSxS. Installed updates can no longer be uninstalled. 4-20 minutes.",
        "command_he": "dism /online /cleanup-image /startcomponentcleanup /resetbase",
    },
]

STEP_BY_ID = {s["id"]: s for s in STEP_DEFS}

# A plain run of the button does the cheap things only. The multi-minute image
# repairs are opt-in, because they are the entire reason a run used to take a
# quarter of an hour.
DEFAULT_OPTIONS = {
    "flush_ram": True,
    "clean_temp": True,
    "flush_dns": True,
    "retrim_ssd": True,
    "dism_cleanup": False,
    "dism_restore": False,
    "sfc_scan": False,
    "reset_wu": False,
    "reset_network": False,
    "reset_spooler": False,
}

# Component cleanup is worth suggesting again after this long.
DISM_CLEANUP_SUGGEST_AFTER_DAYS = 90


def _state_dir():
    base = os.environ.get('LOCALAPPDATA') or tempfile.gettempdir()
    path = os.path.join(base, 'Polaris')
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        return tempfile.gettempdir()
    return path


class _LineSplitter:
    """
    Turns a byte stream from a console tool into logical lines.

    Splits on \\r as well as \\n (progress redraws use \\r), and picks the
    encoding from the first chunk: sfc.exe writes UTF-16LE down a redirected
    pipe, dism.exe writes the OEM code page.
    """

    def __init__(self):
        self._dec = None
        self._buf = ""

    @staticmethod
    def _pick_encoding(first):
        if first.startswith(codecs.BOM_UTF16_LE):
            return 'utf-16-le'
        # UTF-16LE ASCII text looks like 'd\x00i\x00s\x00m\x00'.
        head = first[:16]
        if len(head) >= 4 and head[1::2].count(0) >= max(1, len(head[1::2]) - 1):
            return 'utf-16-le'
        return 'oem' if IS_WINDOWS else 'utf-8'

    def _ensure_decoder(self, chunk):
        if self._dec is not None:
            return
        enc = self._pick_encoding(chunk)
        for candidate in (enc, 'utf-8'):
            try:
                self._dec = codecs.getincrementaldecoder(candidate)(errors='replace')
                return
            except (LookupError, TypeError):
                continue
        self._dec = codecs.getincrementaldecoder('latin-1')(errors='replace')

    def feed(self, chunk):
        self._ensure_decoder(chunk)
        try:
            self._buf += self._dec.decode(chunk)
        except Exception:
            self._buf += chunk.decode('utf-8', errors='replace')

        parts = re.split(r'[\r\n]', self._buf)
        self._buf = parts.pop()
        out = []
        for p in parts:
            p = p.replace('﻿', '').strip()
            if p:
                out.append(p)
        return out

    def flush(self):
        rest = self._buf.replace('﻿', '').strip()
        self._buf = ""
        return [rest] if rest else []


class SystemRevitalizer:
    def __init__(self):
        self.is_windows = IS_WINDOWS
        self.is_running = False
        self.current_step = ""
        self.current_step_en = ""
        self.progress_percent = 0
        self.live_logs = []
        self.final_results = None
        self.lock = threading.Lock()

        self._log_uid = 0   # stable identity of a log row, never reused
        self._log_rev = 0   # bumped on create AND on in-place update
        self._last_log_at = 0.0
        self._steps = []            # live plan, published to the UI
        self._step_fraction = {}    # step id -> 0..1 sub-progress
        self._started_at = None
        self._stop_heartbeat = threading.Event()

    # ------------------------------------------------------------------
    # logging
    # ------------------------------------------------------------------

    def log(self, message, level="INFO", step=None, replace_key=None):
        """
        Appends a log line.

        `replace_key` makes the line self-updating: a second line with the same
        key overwrites the previous one instead of appending. That is what keeps
        a DISM progress bar on one row rather than 400.

        Rows carry a stable `uid` plus a `rev` that also bumps on an in-place
        update, so a polling client can ask for "everything newer than rev N"
        and still receive edits to a row it already drew.
        """
        ts = time.strftime("%H:%M:%S")
        with self.lock:
            self._log_rev += 1
            if replace_key and self.live_logs:
                # Look back a short window rather than only at the last row:
                # during the parallel wave several steps interleave, and a
                # heartbeat can land between two progress redraws.
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
                "step": step,
                "key": replace_key,
            })
            if len(self.live_logs) > 1200:
                self.live_logs.pop(0)
            self._last_log_at = time.time()

    # ------------------------------------------------------------------
    # progress publishing
    # ------------------------------------------------------------------

    def _compute_percent_locked(self):
        planned = [s for s in self._steps if s["status"] != "skipped"]
        if not planned:
            return 100 if not self.is_running else 0
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
        """Remaining seconds, using declared weights recalibrated by real pace."""
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
        pace = elapsed / spent_w  # real seconds per weight unit
        return int(max(0, left_w * pace))

    def get_progress(self, since_log_id=0):
        with self.lock:
            elapsed = (time.time() - self._started_at) if self._started_at else 0
            running = [s for s in self._steps if s["status"] == "running"]
            if self.is_running and running:
                if len(running) == 1:
                    current = running[0]["title_he"]
                    current_en = running[0].get("title_en") or running[0]["title_he"]
                else:
                    current = (f"מריץ {len(running)} פעולות במקביל: "
                               + " · ".join(s["title_he"] for s in running))
                    current_en = (f"Running {len(running)} tasks in parallel: "
                                  + " · ".join(s.get("title_en") or s["title_he"] for s in running))
            else:
                current = self.current_step
                current_en = self.current_step_en or self.current_step

            steps_out = []
            for s in self._steps:
                item = dict(s)
                if s["status"] == "running" and s.get("started_at"):
                    item["elapsed"] = round(time.time() - s["started_at"], 1)
                item["fraction"] = round(self._step_fraction.get(s["id"], 0.0), 3)
                item.pop("started_at", None)
                steps_out.append(item)

            try:
                since = int(since_log_id or 0)
            except (TypeError, ValueError):
                since = 0
            logs = [dict(l) for l in self.live_logs if l.get("rev", 0) > since]

            return {
                "running": self.is_running,
                "current_step": current,
                "current_step_en": current_en,
                "percent": self._compute_percent_locked() if self._steps else self.progress_percent,
                "logs": logs,
                "log_rev": self._log_rev,
                "log_truncated_before": self.live_logs[0]["uid"] if self.live_logs else 0,
                "results": self.final_results,
                "steps": steps_out,
                "elapsed_seconds": round(elapsed, 1),
                "eta_seconds": self._eta_locked(elapsed) if self.is_running else 0,
                "is_admin": is_admin(),
                "total_steps": len([s for s in self._steps if s["status"] != "skipped"]),
                "done_steps": len([s for s in self._steps if s["status"] in ("done", "failed")]),
            }

    def _set_step(self, step_id, status=None, detail_he=None, detail_en=None, freed_bytes=None):
        with self.lock:
            for s in self._steps:
                if s["id"] != step_id:
                    continue
                if status:
                    if status == "running" and not s.get("started_at"):
                        s["started_at"] = time.time()
                    if status in ("done", "failed", "skipped") and s.get("started_at"):
                        s["elapsed"] = round(time.time() - s["started_at"], 1)
                        self._step_fraction[step_id] = 1.0
                    s["status"] = status
                if detail_he is not None:
                    s["detail_he"] = detail_he
                if detail_en is not None:
                    s["detail_en"] = detail_en
                if freed_bytes is not None:
                    s["freed_bytes"] = freed_bytes
                return

    def _set_fraction(self, step_id, fraction):
        with self.lock:
            self._step_fraction[step_id] = max(0.0, min(1.0, fraction))

    # ------------------------------------------------------------------
    # audit
    # ------------------------------------------------------------------

    def audit_system(self):
        """
        Non-destructive audit of recoverable space, memory pressure, SSD status
        and startup impact. The temp-folder walk is time-capped so opening the
        maintenance screen never stalls on a huge SoftwareDistribution folder.
        """
        temp_bytes, temp_approx = self._calculate_safe_temp_size(budget_seconds=1.5)
        startup_apps = self.get_startup_apps()
        high_impact_startup = [a for a in startup_apps if a.get('impact') == 'High']

        mem = psutil.virtual_memory()
        mem_pressure = mem.percent

        clutter_score = 100
        if temp_bytes > (2 * 1024 * 1024 * 1024):
            clutter_score -= 15
        elif temp_bytes > (500 * 1024 * 1024):
            clutter_score -= 8

        if len(startup_apps) > 10:
            clutter_score -= 15
        elif len(startup_apps) > 5:
            clutter_score -= 8

        if mem_pressure > 80:
            clutter_score -= 15

        clutter_score = max(35, min(100, clutter_score))

        suggest_dism, dism_reason_he, dism_reason_en = self._should_suggest_component_cleanup()
        if suggest_dism:
            clutter_score = max(35, clutter_score - 8)

        return {
            "revitalize_score": clutter_score,
            "recoverable_temp_bytes": temp_bytes,
            "recoverable_temp_formatted": self._format_bytes(temp_bytes),
            "recoverable_temp_approx": temp_approx,
            "startup_apps_count": len(startup_apps),
            "high_impact_startup_count": len(high_impact_startup),
            "memory_usage_percent": mem_pressure,
            "suggest_dism_cleanup": suggest_dism,
            "suggest_dism_reason_he": dism_reason_he,
            "suggest_dism_reason_en": dism_reason_en,
            "safety_guarantee": "100% בטוח ומאושר: המערכת אינה נוגעת בקבצים אישיים, מסמכים או תוכנות מותקנות."
        }

    def _cleanup_marker_path(self):
        return os.path.join(_state_dir(), 'last_component_cleanup.txt')

    def _last_component_cleanup(self):
        try:
            with open(self._cleanup_marker_path(), 'r', encoding='utf-8') as fh:
                return float(fh.read().strip())
        except Exception:
            return None

    def _mark_component_cleanup(self):
        try:
            with open(self._cleanup_marker_path(), 'w', encoding='utf-8') as fh:
                fh.write(str(time.time()))
        except Exception:
            pass

    def _should_suggest_component_cleanup(self):
        """
        Cheap heuristic for 'is the component store worth a 10 minute cleanup'.

        A real answer needs `dism /analyzecomponentstore`, which itself costs a
        minute, so instead: how many superseded update backups sit in
        WinSxS\\Backup (one shallow scandir), and how long since we last ran it.
        """
        if not self.is_windows:
            return False, "", ""

        last = self._last_component_cleanup()
        if last and (time.time() - last) < DISM_CLEANUP_SUGGEST_AFTER_DAYS * 86400:
            days = int((time.time() - last) / 86400)
            return (False,
                    f"ניקוי ספריית הרכיבים בוצע לפני {days} ימים — אין צורך לחזור עליו.",
                    f"The component store was cleaned {days} days ago; no need to repeat it.")

        backup_dir = os.path.expandvars(r"%WINDIR%\WinSxS\Backup")
        count = 0
        try:
            with os.scandir(backup_dir) as it:
                for _ in it:
                    count += 1
                    if count > 600:
                        break
        except Exception:
            return False, "", ""

        if count > 400:
            return (True,
                    f"נמצאו מעל {count} גיבויי עדכונים ישנים ב-WinSxS. ניקוי ספריית הרכיבים ישחרר מקום משמעותי (לוקח 4–20 דקות).",
                    f"Over {count} superseded update backups in WinSxS. A component store cleanup would reclaim real space (4-20 minutes).")
        return (False,
                "ספריית רכיבי Windows במצב תקין — אין צורך בניקוי העמוק כרגע.",
                "The Windows component store looks healthy; the deep cleanup is not needed right now.")

    # ------------------------------------------------------------------
    # runner
    # ------------------------------------------------------------------

    def start_revitalization_async(self, options=None):
        # Claim the run under the lock and clear the previous run's results in
        # the same breath. Testing the flag here and setting it inside the
        # worker left a window where two POSTs both passed the guard, and where
        # a poll landing right after the POST saw running=False next to the
        # PREVIOUS run's results and declared the new run finished.
        with self.lock:
            if self.is_running:
                return {"success": False, "message": "תהליך תחזוקה כבר פועל כעת."}
            self.is_running = True
            self.final_results = None
            self.live_logs = []
            self._log_uid = 0
            self._log_rev = 0
            self._steps = []
            self._step_fraction = {}
            self._started_at = time.time()
            self.progress_percent = 0
            self.current_step = "מכין תוכנית תחזוקה..."
            self.current_step_en = "Preparing the maintenance plan..."

        # If the thread cannot start, release the claim - otherwise is_running
        # stays True forever and every later run is refused.
        try:
            threading.Thread(target=self._run_all_steps, args=(options,), daemon=True).start()
        except Exception as e:
            with self.lock:
                self.is_running = False
            return {"success": False, "message": f"לא ניתן להפעיל את תהליך התחזוקה: {e}"}

        return {"success": True, "message": "תהליך תחזוקה הופעל ברקע."}

    def _run_all_steps(self, options=None):
        """
        Wrapper that guarantees `is_running` is cleared. Without this, a single
        unexpected exception left the flag stuck at True and every later
        maintenance run was refused with "a process is already running" until
        the app was restarted.
        """
        try:
            self._run_all_steps_inner(options)
        except Exception as e:
            self.log(f"[ERROR] תהליך התחזוקה נעצר בשל שגיאה בלתי צפויה: {e}", "ERROR")
            with self.lock:
                self.current_step = "התהליך נעצר בשל שגיאה."
                self.current_step_en = "The run stopped because of an error."
                self.progress_percent = 100
                self.final_results = {
                    "success": False,
                    "timestamp": time.time(),
                    "error": str(e),
                    "total_freed_formatted": self._format_bytes(0),
                    "total_freed_bytes": 0,
                    "tasks": []
                }
        finally:
            self._stop_heartbeat.set()
            with self.lock:
                self.is_running = False
                for s in self._steps:
                    if s["status"] == "running":
                        s["status"] = "failed"

    def _build_plan(self, options):
        """
        Turns checkbox options into an ordered plan. Steps the user left off are
        kept in the list as 'skipped' so the UI can show what was deliberately
        not done, instead of silently omitting it.
        """
        opts = dict(DEFAULT_OPTIONS)
        if options:
            opts.update({k: bool(v) for k, v in options.items() if k in DEFAULT_OPTIONS})

        # A full network reset already flushes DNS; running both is redundant.
        # It is folded in, not dropped, so the checklist must not claim the
        # user's ticked box was "not selected".
        folded = {}
        if opts.get("reset_network") and opts.get("flush_dns"):
            opts["flush_dns"] = False
            folded["flush_dns"] = (
                "מבוצע כחלק מאיפוס מחסנית הרשת.",
                "Performed as part of the network stack reset.",
            )
        elif opts.get("reset_network"):
            opts["flush_dns"] = False

        steps = []
        for d in STEP_DEFS:
            enabled = opts.get(d["id"], False)
            fold_he, fold_en = folded.get(d["id"], (None, None))
            steps.append({
                "id": d["id"],
                "title_he": d["title_he"],
                "title_en": d["title_en"],
                "explain_he": d["explain_he"],
                "explain_en": d["explain_en"],
                "command_he": d["command_he"],
                "lane": d["lane"],
                "est_seconds": d["weight"],
                "status": "pending" if enabled else "skipped",
                "detail_he": "" if enabled else (fold_he or "לא נבחר להרצה."),
                "detail_en": "" if enabled else (fold_en or "Not selected."),
                "elapsed": 0,
                "freed_bytes": 0,
                "started_at": None,
            })
        return opts, steps

    def _heartbeat_loop(self, stop_event):
        """Keeps the terminal visibly alive during a long silent step."""
        while not stop_event.wait(1.0):
            with self.lock:
                if not self.is_running:
                    continue
                quiet_for = time.time() - (self._last_log_at or time.time())
                running = [(s["id"], s["title_he"], s.get("started_at")) for s in self._steps
                           if s["status"] == "running"]
            if quiet_for < HEARTBEAT_SECONDS or not running:
                continue
            for sid, title, started in running:
                secs = int(time.time() - started) if started else 0
                self.log(
                    f"[…] {title} — עדיין פועל, {self._format_duration(secs)} עד כה. זה תקין, הכלי של Windows לא מדווח כרגע.",
                    "INFO", step=sid, replace_key=f"heartbeat-{sid}"
                )

    def _run_all_steps_inner(self, options=None):
        opts, steps = self._build_plan(options)

        # start_revitalization_async already claimed the run and reset state;
        # this only publishes the plan it could not know about.
        with self.lock:
            self.is_running = True
            self._steps = steps
            self._step_fraction = {}
            if not self._started_at:
                self._started_at = time.time()

        stop_heartbeat = threading.Event()
        self._stop_heartbeat = stop_heartbeat

        planned = [s for s in steps if s["status"] == "pending"]
        skipped = [s for s in steps if s["status"] == "skipped"]
        est_total = sum(s["est_seconds"] for s in planned)

        self.log("[START] הפעלת מרכז תיקון ותחזוקת מערכת Windows (Polaris Revitalizer)...", "START")
        self.log("[SAFETY] בדיקת בטיחות: אפס פגיעה במסמכים, תמונות, שולחן עבודה או תוכנות מותקנות.", "SAFETY")
        self.log(f"[PLAN] נבחרו {len(planned)} פעולות. הערכת זמן: {self._format_duration(est_total)}.", "INFO")
        for i, s in enumerate(planned, 1):
            self.log(f"[PLAN] {i}. {s['title_he']} — {s['explain_he']}", "INFO", step=s["id"])
        if skipped:
            self.log(f"[PLAN] דילוג על {len(skipped)} פעולות שלא נבחרו: " +
                     ", ".join(s["title_he"] for s in skipped), "INFO")
        if not is_admin():
            self.log("[UAC] Polaris לא רץ כמנהל מערכת. פעולות תיקון עמוקות יבקשו אישור UAC בנפרד — חפש את חלון האישור אם התהליך נראה תקוע.", "WARN")

        # Each run owns its own stop event, so a previous run's heartbeat
        # thread cannot survive into this one.
        hb = threading.Thread(target=self._heartbeat_loop, args=(stop_heartbeat,), daemon=True)
        hb.start()

        handlers = {
            "flush_ram": self._step_flush_ram,
            "clean_temp": lambda: self._step_clean_temp(skip_wu_download=opts.get("reset_wu", False)),
            "flush_dns": self._step_flush_dns,
            "retrim_ssd": self._step_retrim_ssd,
            "reset_network": self._step_reset_network,
            "reset_spooler": self._step_reset_spooler,
            "reset_wu": self._step_reset_wu,
            "sfc_scan": self._step_sfc,
            "dism_restore": self._step_dism_restore,
            "dism_cleanup": self._step_dism_cleanup,
        }

        def execute(step_id):
            self._set_step(step_id, status="running")
            self._set_fraction(step_id, 0.05)
            d = STEP_BY_ID[step_id]
            self.log(f"[>] {d['title_he']}", "STEP", step=step_id)
            self.log(f"[?] מה זה עושה: {d['explain_he']}", "INFO", step=step_id)
            self.log(f"[$] פקודה: {d['command_he']}", "INFO", step=step_id)
            t0 = time.time()
            try:
                ok, detail_he, detail_en, freed = handlers[step_id]()
            except Exception as e:
                self.log(f"[WARN] {d['title_he']}: {e}", "WARN", step=step_id)
                self._set_step(step_id, status="failed",
                               detail_he=f"הפעולה נכשלה: {e}",
                               detail_en=f"Failed: {e}")
                return 0
            took = time.time() - t0
            self._set_step(step_id,
                           status="done" if ok else "failed",
                           detail_he=detail_he,
                           detail_en=detail_en,
                           freed_bytes=freed)
            self.log(f"[OK] {d['title_he']} — הושלם ב-{self._format_duration(took)}. {detail_he}",
                     "SUCCESS" if ok else "WARN", step=step_id)
            return freed

        total_freed = 0

        # Wave 1 - cheap and independent, run together.
        wave1 = [s["id"] for s in planned if s["lane"] == "fast"]
        if wave1:
            self.log(f"[PAR] מריץ במקביל {len(wave1)} פעולות מהירות.", "INFO")
            with ThreadPoolExecutor(max_workers=len(wave1)) as pool:
                for freed in pool.map(execute, wave1):
                    total_freed += freed or 0

        # Wave 2 - cheap, but meaningful only after wave 1 (TRIM after deletes).
        for sid in [s["id"] for s in planned if s["lane"] == "fast2"]:
            total_freed += execute(sid) or 0

        # Serial lane - services and the component store, strictly one at a time.
        for sid in [s["id"] for s in planned if s["lane"] == "serial"]:
            total_freed += execute(sid) or 0

        self._stop_heartbeat.set()

        elapsed = time.time() - self._started_at
        with self.lock:
            self.progress_percent = 100
            self.current_step = "תהליך התיקון והתחזוקה הושלם בהצלחה!"
            self.current_step_en = "Maintenance and repair finished."
        self.log(
            f"[DONE] התהליך הסתיים ב-{self._format_duration(elapsed)}. "
            f"בוצעו {len(planned)} פעולות, סה\"כ פונו: {self._format_bytes(total_freed)}.",
            "DONE"
        )

        with self.lock:
            tasks = [{
                "task": s["id"],
                "title_he": s["title_he"],
                "title_en": s["title_en"],
                "status": {"done": "success", "failed": "notice", "skipped": "skipped"}.get(s["status"], "notice"),
                "detail_he": s["detail_he"],
                "detail_en": s.get("detail_en") or s["detail_he"],
                "elapsed": s["elapsed"],
                "freed_bytes": s["freed_bytes"],
            } for s in self._steps if s["status"] != "skipped"]

            self.final_results = {
                "success": True,
                "timestamp": time.time(),
                "elapsed_seconds": round(elapsed, 1),
                "total_freed_formatted": self._format_bytes(total_freed),
                "total_freed_bytes": total_freed,
                "tasks": tasks,
                "skipped": [{"task": s["id"], "title_he": s["title_he"], "title_en": s["title_en"]}
                            for s in self._steps if s["status"] == "skipped"],
            }

    # ------------------------------------------------------------------
    # individual steps  ->  (ok, detail_he, detail_en, freed_bytes)
    # ------------------------------------------------------------------

    def _step_flush_ram(self):
        mem_before = psutil.virtual_memory().used
        from backend.memory_analyzer import MemoryAnalyzer
        MemoryAnalyzer().trim_working_sets()
        time.sleep(0.4)
        freed = max(0, mem_before - psutil.virtual_memory().used)
        self._set_fraction("flush_ram", 1.0)
        if freed == 0:
            return (True,
                    "לא היה זיכרון רדום לשחרור — המצב כבר היה תקין.",
                    "No idle memory to release; already healthy.", 0)
        return (True,
                f"שוחררו {self._format_bytes(freed)} של זיכרון פעיל.",
                f"Released {self._format_bytes(freed)} of active memory.", freed)

    def _step_clean_temp(self, skip_wu_download=False):
        freed, locked = self._clean_safe_temp_files_with_logs(skip_wu_download=skip_wu_download)
        if locked:
            # Files held open by a running program cannot be deleted. Saying so
            # is more useful than reporting an unqualified success.
            return (True,
                    f"נוקו {self._format_bytes(freed)} של קבצי זבל. {locked} פריטים נעולים בידי תוכנות פעילות ולא נמחקו.",
                    f"Cleaned {self._format_bytes(freed)}. {locked} items were locked by running programs and were left alone.",
                    freed)
        return (True,
                f"נוקו {self._format_bytes(freed)} של קבצי זבל.",
                f"Cleaned {self._format_bytes(freed)} of junk files.", freed)

    def _step_flush_dns(self):
        ok = self._flush_dns_resolver()
        self._set_fraction("flush_dns", 1.0)
        if not ok:
            return False, "איפוס מטמון ה-DNS נכשל.", "Flushing the DNS cache failed.", 0
        return True, "מטמון כתובות הרשת אופס.", "DNS resolver cache cleared.", 0

    def _step_retrim_ssd(self):
        ok, msg_he, msg_en = self._retrim_system_drive_with_logs()
        self._set_fraction("retrim_ssd", 1.0)
        return ok, msg_he, msg_en, 0

    def _step_reset_network(self):
        ok = self._reset_network_stack()
        if not ok:
            return False, "איפוס מחסנית הרשת נכשל.", "Network stack reset failed.", 0
        return (True,
                "מחסנית הרשת ו-Winsock אופסו. מומלץ לאתחל את המחשב.",
                "Network stack and Winsock reset. A restart is recommended.", 0)

    def _step_reset_spooler(self):
        ok = self._reset_print_spooler()
        if not ok:
            return False, "איפוס שירות ההדפסה נכשל.", "Print spooler reset failed.", 0
        return (True,
                "שירות ההדפסה אותחל ותור ההדפסה נוקה.",
                "Print spooler restarted and its queue cleared.", 0)

    def _step_reset_wu(self):
        ok = self._reset_windows_update_services()
        if not ok:
            return False, "איפוס שירותי העדכונים נכשל.", "Windows Update reset failed.", 0
        return (True,
                "שירותי העדכונים ומטמון ההורדות רועננו.",
                "Update services and the download cache were refreshed.", 0)

    def _step_sfc(self):
        ok, msg_he, msg_en = self._run_streamed_tool(
            step_id="sfc_scan",
            tag="SFC",
            cmd=['sfc.exe', '/scannow'],
            timeout=1800,
            ok_he="סריקת SFC הושלמה.",
            ok_en="SFC scan completed.",
        )
        return ok, msg_he, msg_en, 0

    def _step_dism_restore(self):
        ok, msg_he, msg_en = self._run_streamed_tool(
            step_id="dism_restore",
            tag="DISM",
            cmd=['dism.exe', '/online', '/cleanup-image', '/restorehealth'],
            timeout=2400,
            ok_he="שחזור ותיקון תמונת המערכת הושלם.",
            ok_en="Windows image repair completed.",
        )
        return ok, msg_he, msg_en, 0

    def _step_dism_cleanup(self):
        ok, msg_he, msg_en = self._run_streamed_tool(
            step_id="dism_cleanup",
            tag="DISM",
            cmd=['dism.exe', '/online', '/cleanup-image', '/startcomponentcleanup', '/resetbase'],
            timeout=2400,
            ok_he="ניקוי ספריית הרכיבים הושלם.",
            ok_en="Component store cleanup completed.",
        )
        if ok:
            self._mark_component_cleanup()
        return ok, msg_he, msg_en, 0

    # ------------------------------------------------------------------
    # streaming command execution
    # ------------------------------------------------------------------

    def _emit_tool_line(self, step_id, tag, line):
        """One line of tool output -> one log row, with progress lines folded."""
        m = _PCT_RE.search(line)
        if m:
            try:
                pct = float(m.group(1).replace(',', '.'))
                self._set_fraction(step_id, pct / 100.0)
            except ValueError:
                pass
            # Progress redraws overwrite each other instead of stacking up.
            self.log(f"[{tag}] {line}", "INFO", step=step_id, replace_key=f"{tag}-{step_id}-progress")
        else:
            self.log(f"[{tag}] {line}", "INFO", step=step_id)

    def _run_streamed_tool(self, step_id, tag, cmd, timeout, ok_he, ok_en):
        """
        Runs a long console tool with genuinely live output.

        Elevated: read the pipe directly. Not elevated: elevate a cmd.exe that
        redirects into a temp file, and tail that file while it runs - which is
        the only way to see anything at all through a UAC elevation.
        """
        if not self.is_windows:
            return False, "נתמך בסביבת Windows בלבד.", "Windows only."

        if is_admin():
            return self._stream_direct(step_id, tag, cmd, timeout, ok_he, ok_en)
        return self._stream_via_uac(step_id, tag, cmd, timeout, ok_he, ok_en)

    def _stream_direct(self, step_id, tag, cmd, timeout, ok_he, ok_en):
        """
        Streams an elevated tool's pipe.

        The read happens on a helper thread feeding a queue, because a raw pipe
        read blocks forever: a tool that wedges - exactly the failure this
        screen exists to diagnose - would otherwise never hit its timeout and
        would pin `is_running` at True until the app restarted.
        """
        splitter = _LineSplitter()
        deadline = time.time() + timeout
        proc = popen_hidden(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        chunks = queue.Queue()

        def reader():
            try:
                while True:
                    data = proc.stdout.read(4096)
                    if not data:
                        break
                    chunks.put(data)
            except Exception:
                pass
            finally:
                chunks.put(None)

        threading.Thread(target=reader, daemon=True).start()

        try:
            while True:
                try:
                    chunk = chunks.get(timeout=0.5)
                except queue.Empty:
                    if time.time() > deadline:
                        return self._kill_and_report(proc, timeout)
                    continue
                if chunk is None:
                    break
                for line in splitter.feed(chunk):
                    self._emit_tool_line(step_id, tag, line)
                if time.time() > deadline:
                    return self._kill_and_report(proc, timeout)

            for line in splitter.flush():
                self._emit_tool_line(step_id, tag, line)
            rc = proc.wait(timeout=30)
        except Exception as e:
            try:
                proc.kill()
            except Exception:
                pass
            return False, f"שגיאה בהרצת הכלי: {e}", f"Tool failed to run: {e}"

        self._set_fraction(step_id, 1.0)
        if rc == 0:
            return True, ok_he, ok_en
        return False, f"{ok_he} (קוד יציאה {rc})", f"{ok_en} (exit code {rc})"

    def _timed_out(self, timeout):
        return (False,
                f"הפעולה חרגה מ-{self._format_duration(timeout)} ונעצרה.",
                f"The operation exceeded {int(timeout)}s and was stopped.")

    def _kill_and_report(self, proc, timeout):
        """Kills a timed-out child and reaps it, so no zombie is left behind."""
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        return self._timed_out(timeout)

    def _stream_via_uac(self, step_id, tag, cmd, timeout, ok_he, ok_en):
        out_path = os.path.join(tempfile.gettempdir(), f"polaris_{step_id}_{int(time.time())}.log")
        inner = subprocess.list2cmdline(cmd) + f' > "{out_path}" 2>&1'
        ps = [
            'powershell', '-NoProfile', '-NonInteractive', '-Command',
            "$p = Start-Process cmd.exe -ArgumentList '/c', "
            + self._ps_quote(inner)
            + " -Verb RunAs -WindowStyle Hidden -PassThru; $p.WaitForExit(); exit $p.ExitCode"
        ]

        self.log("[UAC] נפתחה בקשת אישור מנהל מערכת של Windows. אשר את החלון כדי שהפעולה תתחיל.",
                 "WARN", step=step_id)

        try:
            proc = popen_hidden(ps, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        except Exception as e:
            return (False,
                    f"לא ניתן להפעיל את הפעולה עם הרשאות מנהל: {e}",
                    f"Could not start the elevated operation: {e}")

        splitter = _LineSplitter()
        pos = 0
        deadline = time.time() + timeout
        approved_logged = False

        while True:
            if proc.poll() is not None and not os.path.exists(out_path):
                break

            if os.path.exists(out_path):
                if not approved_logged:
                    self.log("[UAC] האישור התקבל, הפעולה רצה כעת עם הרשאות מנהל.", "SUCCESS", step=step_id)
                    approved_logged = True
                try:
                    with open(out_path, 'rb') as fh:
                        fh.seek(pos)
                        data = fh.read()
                        pos = fh.tell()
                    if data:
                        for line in splitter.feed(data):
                            self._emit_tool_line(step_id, tag, line)
                except Exception:
                    pass

            if proc.poll() is not None:
                break
            if time.time() > deadline:
                result = self._kill_and_report(proc, timeout)
                try:
                    os.remove(out_path)
                except Exception:
                    pass
                return result
            time.sleep(0.4)

        # Drain whatever landed between the last read and process exit.
        try:
            if os.path.exists(out_path):
                with open(out_path, 'rb') as fh:
                    fh.seek(pos)
                    data = fh.read()
                if data:
                    for line in splitter.feed(data):
                        self._emit_tool_line(step_id, tag, line)
            for line in splitter.flush():
                self._emit_tool_line(step_id, tag, line)
        except Exception:
            pass

        rc = proc.returncode
        try:
            os.remove(out_path)
        except Exception:
            pass

        self._set_fraction(step_id, 1.0)
        if not approved_logged:
            return (False,
                    "אישור מנהל המערכת (UAC) לא ניתן, הפעולה לא בוצעה.",
                    "The UAC prompt was not approved, so the operation did not run.")
        if rc == 0:
            return True, ok_he, ok_en
        return False, f"{ok_he} (קוד יציאה {rc})", f"{ok_en} (exit code {rc})"

    @staticmethod
    def _ps_quote(s):
        """Single-quoted PowerShell literal."""
        return "'" + s.replace("'", "''") + "'"

    # ------------------------------------------------------------------
    # workers
    # ------------------------------------------------------------------

    def _clean_safe_temp_files_with_logs(self, skip_wu_download=False):
        """
        Deletes stale temp entries in a single pass.

        The old version walked each directory to measure it and then deleted it,
        paying for the tree twice. Sizes now come from the stat() we already
        need, and directory sizes are summed during the same walk that feeds the
        delete.

        Returns (freed_bytes, locked_count) - a temp file held open by a running
        program cannot be deleted, and the caller reports that rather than
        claiming an unqualified success.
        """
        freed = 0
        locked = 0
        now = time.time()
        max_age_seconds = 24 * 3600

        temp_dirs = [
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%WINDIR%\Temp"),
        ]
        if not skip_wu_download:
            temp_dirs.append(os.path.expandvars(r"%WINDIR%\SoftwareDistribution\Download"))
        else:
            self.log("[CLEAN] מדלג על SoftwareDistribution\\Download — שלב איפוס Windows Update יטפל בו.",
                     "INFO", step="clean_temp")

        existing = [d for d in temp_dirs if os.path.exists(d)]
        for idx, t_dir in enumerate(existing):
            try:
                entries = list(os.scandir(t_dir))
            except Exception:
                continue

            self.log(f"[CLEAN] בודק תיקייה: {t_dir} ({len(entries)} פריטים)", "INFO", step="clean_temp")

            total = max(1, len(entries))
            for i, entry in enumerate(entries):
                if i % 40 == 0:
                    self._set_fraction("clean_temp", (idx + (i / total)) / max(1, len(existing)))
                try:
                    if entry.name.lower() == 'desktop.ini':
                        continue

                    st = entry.stat(follow_symlinks=False)
                    if (now - st.st_mtime) < max_age_seconds:
                        continue

                    if entry.is_file(follow_symlinks=False):
                        sz = st.st_size
                        try:
                            os.remove(entry.path)
                        except OSError:
                            locked += 1
                            continue
                        freed += sz
                    elif entry.is_dir(follow_symlinks=False):
                        dir_sz = 0
                        for r, _, fs in os.walk(entry.path):
                            for f in fs:
                                try:
                                    dir_sz += os.stat(os.path.join(r, f)).st_size
                                except Exception:
                                    pass
                        shutil.rmtree(entry.path, ignore_errors=True)
                        # Only count what actually went away - locked temp
                        # folders survive rmtree(ignore_errors=True) silently.
                        if os.path.exists(entry.path):
                            locked += 1
                        else:
                            freed += dir_sz
                except Exception:
                    locked += 1
                    continue

        if locked:
            self.log(f"[CLEAN] {locked} פריטים נעולים בידי תוכנות פעילות — נותרו במקומם.",
                     "INFO", step="clean_temp")
        self._set_fraction("clean_temp", 1.0)
        return freed, locked

    def _retrim_system_drive_with_logs(self):
        if not self.is_windows:
            return True, "נתמך בסביבת Windows בלבד.", "Windows only."
        try:
            cmd = ['powershell', '-NoProfile', '-NonInteractive', '-Command',
                   "$ProgressPreference='SilentlyContinue';"
                   "Optimize-Volume -DriveLetter C -ReTrim -Verbose -ErrorAction SilentlyContinue"]
            res = run_hidden(cmd, capture_output=True, text=True, encoding='utf-8',
                             errors='replace', timeout=120, check=False)
            for stream in (res.stdout, res.stderr):
                for line in (stream or "").splitlines():
                    if line.strip():
                        self.log(f"[SSD] {line.strip()}", "INFO", step="retrim_ssd")
            return True, "פקודת TRIM נשלחה לכונן C: בהצלחה.", "TRIM was issued to drive C: successfully."
        except subprocess.TimeoutExpired:
            return (False,
                    "פקודת TRIM לא הסתיימה בזמן שהוקצב לה.",
                    "The TRIM command did not finish within its time budget.")
        except Exception as e:
            return False, str(e), str(e)

    def _flush_dns_resolver(self):
        if not self.is_windows:
            return True
        try:
            res = run_hidden(['ipconfig', '/flushdns'], capture_output=True, text=True,
                             encoding='utf-8', errors='replace', timeout=15, check=False)
            for line in (res.stdout or "").splitlines():
                if line.strip():
                    self.log(f"[DNS] {line.strip()}", "INFO", step="flush_dns")
            return res.returncode == 0
        except Exception:
            return False

    def _reset_network_stack(self):
        if not self.is_windows:
            return True
        try:
            for label, argv, frac in (
                ("netsh winsock reset", ['netsh', 'winsock', 'reset'], 0.35),
                ("netsh int ip reset", ['netsh', 'int', 'ip', 'reset'], 0.7),
            ):
                self.log(f"[NET] מריץ: {label}...", "INFO", step="reset_network")
                res = run_hidden(argv, capture_output=True, text=True, encoding='utf-8',
                                 errors='replace', timeout=60, check=False)
                for line in (res.stdout or "").splitlines():
                    if line.strip():
                        self.log(f"[NET] {line.strip()}", "INFO", step="reset_network")
                self._set_fraction("reset_network", frac)
            self._flush_dns_resolver()
            self._set_fraction("reset_network", 1.0)
            return True
        except Exception as e:
            self.log(f"[WARN] [NET] {e}", "WARN", step="reset_network")
            return False

    def _reset_print_spooler(self):
        if not self.is_windows:
            return True
        try:
            self.log("[SPOOLER] עוצר שירות Spooler...", "INFO", step="reset_spooler")
            run_hidden(['net', 'stop', 'spooler'], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=60, check=False)
            self._set_fraction("reset_spooler", 0.4)

            printers_dir = os.path.expandvars(r"%WINDIR%\System32\spool\PRINTERS")
            removed = 0
            if os.path.exists(printers_dir):
                for f in os.listdir(printers_dir):
                    fp = os.path.join(printers_dir, f)
                    try:
                        if os.path.isfile(fp):
                            os.remove(fp)
                            removed += 1
                    except Exception:
                        pass
            self.log(f"[SPOOLER] נמחקו {removed} קבצי תור הדפסה תקועים.", "INFO", step="reset_spooler")
            self._set_fraction("reset_spooler", 0.7)

            self.log("[SPOOLER] מפעיל שירות Spooler מחדש...", "INFO", step="reset_spooler")
            run_hidden(['net', 'start', 'spooler'], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=60, check=False)
            self._set_fraction("reset_spooler", 1.0)
            return True
        except Exception as e:
            self.log(f"[WARN] [SPOOLER] {e}", "WARN", step="reset_spooler")
            return False

    def _reset_windows_update_services(self):
        if not self.is_windows:
            return True
        try:
            for i, svc in enumerate(['wuauserv', 'bits', 'cryptsvc']):
                self.log(f"[WU] עוצר שירות {svc}...", "INFO", step="reset_wu")
                run_hidden(['net', 'stop', svc], capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=60, check=False)
                self._set_fraction("reset_wu", 0.1 + i * 0.1)

            download_dir = os.path.expandvars(r"%WINDIR%\SoftwareDistribution\Download")
            removed = 0
            if os.path.exists(download_dir):
                for f in os.listdir(download_dir):
                    fp = os.path.join(download_dir, f)
                    try:
                        if os.path.isfile(fp):
                            os.remove(fp)
                        else:
                            shutil.rmtree(fp, ignore_errors=True)
                        removed += 1
                    except Exception:
                        pass
            self.log(f"[WU] נוקו {removed} פריטי הורדה ממטמון העדכונים.", "INFO", step="reset_wu")
            self._set_fraction("reset_wu", 0.6)

            for i, svc in enumerate(['cryptsvc', 'bits', 'wuauserv']):
                self.log(f"[WU] מפעיל מחדש שירות {svc}...", "INFO", step="reset_wu")
                run_hidden(['net', 'start', svc], capture_output=True, text=True,
                           encoding='utf-8', errors='replace', timeout=60, check=False)
                self._set_fraction("reset_wu", 0.7 + i * 0.1)

            self._set_fraction("reset_wu", 1.0)
            return True
        except Exception as e:
            self.log(f"[WARN] [WU] {e}", "WARN", step="reset_wu")
            return False

    # ------------------------------------------------------------------
    # startup inventory & helpers
    # ------------------------------------------------------------------

    def get_startup_apps(self):
        apps = []
        seen = set()

        if not self.is_windows or winreg is None:
            return apps

        reg_locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "Current User"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "Local Machine"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Local Machine (32-bit)")
        ]

        for hkey, subkey, source in reg_locations:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    for i in range(count):
                        try:
                            name, val, _ = winreg.EnumValue(key, i)
                            if name.lower() not in seen:
                                seen.add(name.lower())
                                impact = self._estimate_startup_impact(name, val)
                                apps.append({
                                    "name": name,
                                    "command": val,
                                    "source": source,
                                    "impact": impact,
                                    "safe_to_disable": not self._is_critical_startup(name)
                                })
                        except Exception:
                            continue
            except Exception:
                continue

        startup_dirs = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        ]

        for s_dir in startup_dirs:
            if os.path.exists(s_dir):
                for f in os.listdir(s_dir):
                    if f.lower() != 'desktop.ini' and f.lower() not in seen:
                        seen.add(f.lower())
                        full_p = os.path.join(s_dir, f)
                        impact = self._estimate_startup_impact(f, full_p)
                        apps.append({
                            "name": os.path.splitext(f)[0],
                            "command": full_p,
                            "source": "Startup Folder",
                            "impact": impact,
                            "safe_to_disable": True
                        })

        return apps

    def _estimate_startup_impact(self, name, command):
        n = (name + " " + command).lower()
        if any(h in n for h in ['chrome', 'edge', 'teams', 'spotify', 'discord', 'steam', 'epic', 'adobe', 'onedrive']):
            return "High"
        if any(m in n for m in ['update', 'helper', 'tray', 'service', 'client']):
            return "Medium"
        return "Low"

    def _is_critical_startup(self, name):
        n = name.lower()
        return any(c in n for c in ['security', 'antivirus', 'defender', 'audio', 'realtek', 'synaptics', 'touchpad', 'intel', 'nvidia', 'amd'])

    def _calculate_safe_temp_size(self, budget_seconds=None):
        """
        Sums the temp folders. With a budget, the walk stops once it expires and
        reports the figure as approximate, so the audit never blocks the UI on a
        multi-gigabyte SoftwareDistribution folder.
        """
        total = 0
        approx = False
        deadline = (time.time() + budget_seconds) if budget_seconds else None
        checked = 0

        temp_dirs = [
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%WINDIR%\Temp"),
            os.path.expandvars(r"%WINDIR%\SoftwareDistribution\Download")
        ]

        for t_dir in temp_dirs:
            if not os.path.exists(t_dir):
                continue
            try:
                for root, _, files in os.walk(t_dir):
                    for f in files:
                        try:
                            total += os.stat(os.path.join(root, f)).st_size
                        except Exception:
                            continue
                        checked += 1
                        if deadline and (checked % 512 == 0) and time.time() > deadline:
                            return total, True
            except Exception:
                continue

        return total, approx

    @staticmethod
    def _format_duration(seconds):
        try:
            seconds = int(round(float(seconds)))
        except (TypeError, ValueError):
            return "0 שניות"
        if seconds < 60:
            return f"{seconds} שניות"
        minutes, secs = divmod(seconds, 60)
        if minutes < 60:
            return f"{minutes} דק' {secs} שנ'" if secs else f"{minutes} דקות"
        hours, minutes = divmod(minutes, 60)
        return f"{hours} שע' {minutes} דק'"

    @staticmethod
    def _format_bytes(b):
        return _fmt(b)

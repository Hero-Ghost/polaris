"""
Polaris - Remote Control & Auto-Update Engine
Provides remote kill-switch capabilities and seamless GitHub-based auto-updates.
Free, serverless, and resilient: utilizes GitHub Raw / Gist for status control
and GitHub Releases for binary distribution.
"""

import os
import sys
import json
import time
import hashlib
import urllib.request
import urllib.error
import subprocess
import threading
from typing import Dict, Any, Optional, Tuple

APP_VERSION = "3.7.0"
CURRENT_VERSION_TUPLE = (3, 7, 0)

DEFAULT_CONTROL_URL = (
    "https://gist.githubusercontent.com/Hero-Ghost/22bc7b324e2a5118384d3413490ef636/raw/app_control.json"
)

def _get_appdata_dir() -> str:
    """Returns persistent Polaris directory in LOCALAPPDATA."""
    base = os.environ.get('LOCALAPPDATA', '')
    if not base:
        base = os.path.expanduser('~')
    polaris_dir = os.path.join(base, 'Polaris')
    try:
        os.makedirs(polaris_dir, exist_ok=True)
    except Exception:
        pass
    return polaris_dir

def _get_config_file_path() -> str:
    return os.path.join(_get_appdata_dir(), 'remote_config.json')

def _get_cache_file_path() -> str:
    return os.path.join(_get_appdata_dir(), 'control_cache.json')


def parse_version(ver_str: str) -> Tuple[int, ...]:
    """
    Parses a version string like '3.1', '3.1.0', 'v3.2.1' into a comparable tuple of integers.
    """
    if not ver_str:
        return (0, 0, 0)
    cleaned = str(ver_str).strip().lstrip('vV')
    parts = []
    for token in cleaned.split('.'):
        digits = ''
        for ch in token:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


class RemoteControlManager:
    def __init__(self, current_version: str = APP_VERSION):
        self.current_version = current_version
        self.current_version_tuple = parse_version(current_version)
        self.config_path = _get_config_file_path()
        self.cache_path = _get_cache_file_path()

        self._lock = threading.Lock()
        self._last_check_time = 0.0
        self._cache_ttl = 300.0  # 5 minutes cache TTL

        # Cached in-memory status
        self._cached_status: Dict[str, Any] = {
            "is_killed": False,
            "kill_info": {
                "title_he": "התוכנה הושבתה על ידי המפתח",
                "message_he": "",
                "allow_exit_only": True
            },
            "has_update": False,
            "update_info": {
                "latest_version": self.current_version,
                "release_title_he": "",
                "release_notes_he": "",
                "download_url": "",
                "mandatory": False,
                "sha256": ""
            },
            "broadcast_message": None,
            "last_checked_iso": "",
            "offline": False
        }

        # Update download state
        self._download_state = {
            "in_progress": False,
            "downloaded_bytes": 0,
            "total_bytes": 0,
            "percent": 0.0,
            "status": "idle",  # idle, downloading, verifying, ready, error
            "target_file": "",
            "error": ""
        }

        # Load persisted local config (custom URL if set)
        self.control_url = self._load_persisted_url()

        # Load cached state if available
        self._load_cache()

    def _load_persisted_url(self) -> str:
        env_url = os.environ.get('POLARIS_CONTROL_URL', '').strip()
        if env_url:
            return env_url
        if os.path.isfile(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    url = data.get('control_url', '').strip()
                    if url:
                        return url
            except Exception:
                pass
        return DEFAULT_CONTROL_URL

    def set_control_url(self, new_url: str) -> bool:
        """Sets and persists a custom GitHub Raw / Gist URL for remote control."""
        clean_url = (new_url or '').strip()
        if not clean_url or clean_url == DEFAULT_CONTROL_URL:
            self.control_url = DEFAULT_CONTROL_URL
            try:
                if os.path.isfile(self.config_path):
                    os.remove(self.config_path)
                if os.path.isfile(self.cache_path):
                    os.remove(self.cache_path)
            except Exception:
                pass
            self._last_check_time = 0.0
            return True

        self.control_url = clean_url
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump({"control_url": clean_url, "updated_at": time.time()}, f, ensure_ascii=False, indent=2)
            # Invalidate cache to force check with new URL
            self._last_check_time = 0.0
            return True
        except Exception:
            return False

    def _load_cache(self):
        if os.path.isfile(self.cache_path):
            try:
                with open(self.cache_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        # Restore cached evaluation
                        self._cached_status.update(data.get('status', {}))
                        self._last_check_time = data.get('timestamp', 0.0)
            except Exception:
                pass

    def _save_cache(self, status: Dict[str, Any]):
        try:
            with open(self.cache_path, 'w', encoding='utf-8') as f:
                json.dump({
                    "timestamp": time.time(),
                    "status": status
                }, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def is_app_killed(self) -> bool:
        """Fast check for server request guarding."""
        with self._lock:
            return bool(self._cached_status.get("is_killed", False))

    def get_status(self) -> Dict[str, Any]:
        """Returns the current state, cached or freshly evaluated."""
        with self._lock:
            result = dict(self._cached_status)
            result["control_url"] = self.control_url
            result["current_version"] = self.current_version
            result["download_state"] = dict(self._download_state)
            return result

    def check_remote_control(self, force: bool = False) -> Dict[str, Any]:
        """
        Polls the remote GitHub Raw/Gist control file.
        Resilient: if connection fails, falls back gracefully without breaking offline usage.
        """
        now = time.time()
        if not force and (now - self._last_check_time) < self._cache_ttl:
            return self.get_status()

        req_url = self.control_url
        # Append cache-busting timestamp parameter to avoid CDN stale caching
        separator = '&' if '?' in req_url else '?'
        cache_busted_url = f"{req_url}{separator}_t={int(now)}"

        headers = {
            'User-Agent': f'Polaris/{self.current_version} (Windows NT; x64)',
            'Accept': 'application/json',
            'Cache-Control': 'no-cache'
        }

        try:
            req = urllib.request.Request(cache_busted_url, headers=headers)
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                raw_bytes = resp.read()
                data = json.loads(raw_bytes.decode('utf-8', errors='replace'))

            evaluated = self._evaluate_control_data(data)
            with self._lock:
                self._cached_status = evaluated
                self._last_check_time = now
                self._save_cache(evaluated)
            return self.get_status()

        except Exception as exc:
            # Network error, timeout, or invalid JSON
            with self._lock:
                # Mark as offline, but keep previously cached kill status if was previously locked
                self._cached_status["offline"] = True
                self._cached_status["last_error"] = str(exc)
            return self.get_status()

    def _evaluate_control_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates raw remote control JSON payload against current app version."""
        kill_cfg = data.get('kill_switch', {})
        update_cfg = data.get('update', {})
        broadcast_cfg = data.get('broadcast_message', {})

        # 1. Kill Switch evaluation
        kill_enabled = bool(kill_cfg.get('enabled', False))
        blocked_versions = [str(v).strip() for v in kill_cfg.get('blocked_versions', [])]
        min_version_allowed = str(kill_cfg.get('min_version_allowed', '')).strip()

        is_killed = False
        kill_reason = ""

        if kill_enabled:
            is_killed = True
            kill_reason = "enabled_globally"
        elif self.current_version in blocked_versions:
            is_killed = True
            kill_reason = "version_blocked"
        elif min_version_allowed:
            min_ver_tuple = parse_version(min_version_allowed)
            if self.current_version_tuple < min_ver_tuple:
                is_killed = True
                kill_reason = "version_below_minimum"

        kill_info = {
            "title_he": kill_cfg.get('title_he') or "התוכנה הושבתה על ידי המפתח",
            "message_he": kill_cfg.get('message_he') or "הגישה לתוכנה הושבתה מרחוק על ידי המפתח.",
            "allow_exit_only": bool(kill_cfg.get('allow_exit_only', True)),
            "reason": kill_reason
        }

        # 2. Update evaluation
        latest_version = str(update_cfg.get('latest_version', '')).strip()
        latest_ver_tuple = parse_version(latest_version) if latest_version else (0, 0, 0)
        has_update = latest_ver_tuple > self.current_version_tuple

        is_mandatory = bool(update_cfg.get('mandatory', False))
        if min_version_allowed and (self.current_version_tuple < parse_version(min_version_allowed)):
            is_mandatory = True

        update_info = {
            "latest_version": latest_version or self.current_version,
            "release_title_he": update_cfg.get('release_title_he') or f"גרסה {latest_version} זמינה להורדה",
            "release_notes_he": update_cfg.get('release_notes_he') or "עדכון גרסה שוטף, שיפורי ביצועים ותיקוני תאימות.",
            "download_url": update_cfg.get('download_url', '').strip(),
            "mandatory": is_mandatory,
            "sha256": update_cfg.get('sha256', '').strip()
        }

        # 3. Broadcast banner / notification (optional announcement)
        broadcast_info = None
        if broadcast_cfg.get('active'):
            broadcast_info = {
                "id": broadcast_cfg.get('id', '1'),
                "level": broadcast_cfg.get('level', 'info'),  # info, warn, success
                "title_he": broadcast_cfg.get('title_he', 'הודעת מערכת'),
                "message_he": broadcast_cfg.get('message_he', '')
            }

        return {
            "is_killed": is_killed,
            "kill_info": kill_info,
            "has_update": has_update,
            "update_info": update_info,
            "broadcast_message": broadcast_info,
            "last_checked_iso": time.strftime("%Y-%m-%d %H:%M:%S"),
            "offline": False
        }

    def start_download_update(self, custom_url: Optional[str] = None) -> Dict[str, Any]:
        """Starts asynchronous download of the update executable with strict validation."""
        with self._lock:
            if self._download_state["in_progress"]:
                return {"success": False, "message": "הורדת העדכון כבר מתבצעת כעת."}

            url = custom_url or self._cached_status.get('update_info', {}).get('download_url')
            if not url:
                return {"success": False, "message": "לא הוגדר קישור להורדת קובץ העדכון (download_url)."}

            # Validate HTTPS scheme
            try:
                parsed = urllib.parse.urlparse(url)
            except Exception:
                return {"success": False, "message": "כתובת הקישור להורדה אינה תקינה."}

            if parsed.scheme.lower() != 'https':
                return {"success": False, "message": "הורדת עדכון מותרת אך ורק דרך חיבור מאובטח (HTTPS)."}

            # Restrict update sources to official GitHub domains
            hostname = (parsed.hostname or '').lower()
            trusted_domains = (
                'github.com',
                'raw.githubusercontent.com',
                'gist.githubusercontent.com',
                'objects.githubusercontent.com',
                'github-releases.githubusercontent.com'
            )
            if not any(hostname == td or hostname.endswith('.' + td) for td in trusted_domains):
                return {"success": False, "message": f"הורדת עדכון נדחתה: הדומיין {hostname} אינו ברשימת המקורות המורשים של Polaris."}

            # Enforce mandatory SHA256 checksum for executable files
            expected_sha256 = self._cached_status.get('update_info', {}).get('sha256', '').lower().strip()
            if not expected_sha256 or len(expected_sha256) != 64 or not all(c in '0123456789abcdef' for c in expected_sha256):
                return {"success": False, "message": "לא הוגדרה חתימת אבטחה (SHA256) רשמית לקובץ העדכון. ההורדה נחסמה כדי להגן על המערכת."}

            self._download_state.update({
                "in_progress": True,
                "downloaded_bytes": 0,
                "total_bytes": 0,
                "percent": 0.0,
                "status": "downloading",
                "error": "",
                "target_file": ""
            })

        worker = threading.Thread(target=self._download_worker, args=(url, expected_sha256), daemon=True)
        worker.start()
        return {"success": True, "message": "הורדת העדכון החלה ברקע."}

    def _download_worker(self, url: str, expected_sha256: str):
        temp_dir = os.environ.get('TEMP', os.environ.get('TMP', ''))
        target_file = os.path.join(temp_dir, f"Polaris_Update_{int(time.time())}.exe")

        headers = {
            'User-Agent': f'Polaris-Updater/{self.current_version} (Windows NT; x64)',
            'Accept': '*/*'
        }

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                content_len = resp.headers.get('Content-Length')
                total_bytes = int(content_len) if content_len and content_len.isdigit() else 0

                downloaded = 0
                chunk_size = 65536  # 64 KB chunks

                with open(target_file, 'wb') as out_f:
                    while True:
                        chunk = resp.read(chunk_size)
                        if not chunk:
                            break
                        out_f.write(chunk)
                        downloaded += len(chunk)
                        percent = round((downloaded / total_bytes * 100.0), 1) if total_bytes > 0 else 0.0

                        with self._lock:
                            self._download_state["downloaded_bytes"] = downloaded
                            self._download_state["total_bytes"] = total_bytes
                            self._download_state["percent"] = percent

            # Mandatory SHA256 integrity check
            with self._lock:
                self._download_state["status"] = "verifying"

            hasher = hashlib.sha256()
            with open(target_file, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    hasher.update(chunk)
            computed_hash = hasher.hexdigest().lower()
            if computed_hash != expected_sha256:
                raise ValueError("חתימת האבטחה (SHA256) של הקובץ אינה תואמת לחתימה הרשמית. הקובץ נמחק כדי להגן על המערכת.")

            with self._lock:
                self._download_state["in_progress"] = False
                self._download_state["status"] = "ready"
                self._download_state["percent"] = 100.0
                self._download_state["target_file"] = target_file

        except Exception as exc:
            if os.path.isfile(target_file):
                try:
                    os.remove(target_file)
                except Exception:
                    pass
            err_str = str(exc)
            if "404" in err_str:
                err_msg = "קובץ העדכון לא נמצא ב-GitHub (שגיאה 404). יש לוודא שהעלית את קובץ ה-Polaris.exe ל-Releases ב-GitHub תחת הקישור שהוגדר ב-Gist."
            elif "timed out" in err_str.lower():
                err_msg = "תם הזמן המוקצב להורדה (Timeout). יש לבדוק את חיבור האינטרנט ולנסות שוב."
            else:
                err_msg = err_str

            with self._lock:
                self._download_state["in_progress"] = False
                self._download_state["status"] = "error"
                self._download_state["error"] = err_msg

    def apply_update(self) -> Dict[str, Any]:
        """
        Executes the self-replacement updater script in Windows:
        Kills current instance, replaces the executable, relaunches Polaris, and exits.
        """
        with self._lock:
            target_file = self._download_state.get("target_file")
            status = self._download_state.get("status")

        if not target_file or not os.path.isfile(target_file) or status != "ready":
            return {"success": False, "message": "קובץ העדכון אינו מוכן להתקנה. יש להוריד אותו מחדש."}

        # Check if running as compiled executable
        if getattr(sys, 'frozen', False):
            current_exe = sys.executable
            current_pid = os.getpid()
            temp_dir = os.environ.get('TEMP', os.environ.get('TMP', ''))
            bat_path = os.path.join(temp_dir, f"polaris_apply_{int(time.time())}.bat")

            # Self-replacing Windows batch updater
            bat_content = f"""@echo off
chcp 65001 > nul
title Polaris Auto-Updater
timeout /t 1 /nobreak > nul

:wait_process
taskkill /f /pid {current_pid} > nul 2>&1
timeout /t 1 /nobreak > nul

:replace_file
del /f /q "{current_exe}" > nul 2>&1
if exist "{current_exe}" (
    timeout /t 1 /nobreak > nul
    goto replace_file
)

move /y "{target_file}" "{current_exe}" > nul
if errorlevel 1 (
    echo [ERROR] Failed to replace executable.
    pause
    exit /b 1
)

:: Clear PyInstaller onefile bootloader variables so the new executable starts as a clean root process
set _MEIPASS2=
set _PYI_APPLICATION_HOME_DIR=
set _PYI_PARENT_PROCESS_LEVEL=
set _PYI_SPLASH_IPC=

timeout /t 1 /nobreak > nul
start "" "{current_exe}"
del /f /q "%~f0" > nul 2>&1
exit
"""
            try:
                with open(bat_path, 'w', encoding='utf-8') as f:
                    f.write(bat_content)

                # Strip internal PyInstaller environment variables before launching updater
                clean_env = os.environ.copy()
                for k in list(clean_env.keys()):
                    if k.startswith(('_MEI', '_PYI', 'PYI')):
                        clean_env.pop(k, None)

                # Launch detached batch updater with clean environment
                DETACHED_PROCESS = 0x00000008
                CREATE_NEW_PROCESS_GROUP = 0x00000200
                subprocess.Popen(
                    ['cmd.exe', '/c', bat_path],
                    env=clean_env,
                    creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                    close_fds=True
                )

                # Terminate current app cleanly
                def _do_exit():
                    time.sleep(0.5)
                    os._exit(0)

                threading.Thread(target=_do_exit, daemon=True).start()
                return {
                    "success": True,
                    "message": "העדכון מוכן. התוכנה מפעילה את עצמה מחדש כעת עם הגרסה העדכנית."
                }
            except Exception as exc:
                return {"success": False, "message": f"שגיאה בהפעלת מנגנון העדכון: {str(exc)}"}
        else:
            # Running in Python dev environment
            return {
                "success": True,
                "message": f"הקובץ העדכני הורד בהצלחה אל: {target_file}. בסביבת פיתוח יש להפעיל את הקובץ ידנית."
            }

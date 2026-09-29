"""
Polaris - Windows Update Hide/Unhide Manager.

Provides a modern, in-process replacement for the deprecated Microsoft
'wushowhide.diagcab' troubleshooter. Uses the official Windows Update Agent
(WUA) COM API (Microsoft.Update.Session) — the same engine wushowhide relied
on internally — without any external dependency or MSDT.

Key capabilities:
  - List pending (not-yet-installed) updates: both visible and hidden.
  - Hide a specific update so Windows Update ignores it permanently.
  - Unhide (show) a previously hidden update to restore normal behaviour.
  - Graceful no-op on non-Windows environments (CI / dev on macOS/Linux).

Admin note:
  Querying the update list works without elevation.
  Setting IsHidden requires Administrator privileges (WUA error 0x80240044
  is raised when running without them).  Polaris enforces elevation at startup
  via main.py / win_utils.elevate_me(), so this is always satisfied at runtime.
"""

import threading
import traceback
from typing import Any, Dict, List, Optional

from backend.win_utils import IS_WINDOWS, is_admin, run_hidden

# ---------------------------------------------------------------------------
# Thread-local COM initialisation
# COM objects are apartment-threaded (STA); each thread that calls into
# win32com must call CoInitialize/CoUninitialize.  We use a threading.local()
# to track whether the current thread has already been initialised.
# ---------------------------------------------------------------------------
_com_local = threading.local()

def _ensure_com():
    """Initialise COM on the calling thread if not already done."""
    if not IS_WINDOWS:
        return
    if getattr(_com_local, "initialized", False):
        return
    try:
        import pythoncom
        pythoncom.CoInitialize()
        _com_local.initialized = True
    except Exception:
        pass  # pythoncom not available — win32com will still work in many cases


def _cleanup_com():
    """Uninitialise COM on the calling thread (call at thread exit)."""
    if not IS_WINDOWS:
        return
    if not getattr(_com_local, "initialized", False):
        return
    try:
        import pythoncom
        pythoncom.CoUninitialize()
        _com_local.initialized = False
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_update_dict(update) -> Dict[str, Any]:
    """Convert a COM IUpdate object to a plain serialisable dict."""
    try:
        kb_ids: List[str] = []
        for k in range(update.KBArticleIDs.Count):
            kb_ids.append("KB" + update.KBArticleIDs.Item(k))

        categories: List[str] = []
        for c in range(update.Categories.Count):
            categories.append(update.Categories.Item(c).Name)

        size_bytes = 0
        try:
            size_bytes = int(update.MaxDownloadSize)
        except Exception:
            pass
        size_mb = round(size_bytes / (1024 * 1024), 2) if size_bytes else 0

        description = ""
        try:
            description = update.Description or ""
        except Exception:
            pass

        return {
            "id": update.Identity.UpdateID,
            "title": update.Title or "",
            "description": description,
            "kb_numbers": kb_ids,
            "categories": categories,
            "is_hidden": bool(update.IsHidden),
            "is_mandatory": bool(getattr(update, "IsMandatory", False)),
            "size_mb": size_mb,
        }
    except Exception as exc:
        return {
            "id": "unknown",
            "title": str(getattr(update, "Title", "?")),
            "description": "",
            "kb_numbers": [],
            "categories": [],
            "is_hidden": False,
            "is_mandatory": False,
            "size_mb": 0,
            "_error": str(exc),
        }


# ---------------------------------------------------------------------------
# WUA error code translation
# ---------------------------------------------------------------------------
_WUA_ERRORS: Dict[int, str] = {
    0x80240044: "נדרשות הרשאות מנהל (Administrator) לשינוי זה. אנא הפעל את Polaris כמנהל.",
    0x80240032: "שגיאת חיפוש: לא ניתן לסיים את החיפוש. נסה שוב.",
    0x8024001E: "שירות Windows Update אינו זמין כרגע. נסה שוב בעוד רגע.",
    0x80240008: "העדכון אינו נמצא בקטלוג המקומי.",
}

def _translate_com_error(exc) -> str:
    """Return a human-readable Hebrew message for a COM error."""
    def _to_u32(v):
        """Normalise a potentially signed 32-bit integer to its unsigned form."""
        return v & 0xFFFFFFFF if isinstance(v, int) else 0

    try:
        # pywintypes.com_error: args = (hresult, description, excepinfo, argerr)
        # excepinfo is a tuple; excepinfo[5] = scode (inner HRESULT)
        if len(exc.args) >= 3 and isinstance(exc.args[2], tuple) and len(exc.args[2]) > 5:
            inner = _to_u32(exc.args[2][5])
            if inner in _WUA_ERRORS:
                return _WUA_ERRORS[inner]
        outer = _to_u32(exc.args[0]) if exc.args else 0
        if outer in _WUA_ERRORS:
            return _WUA_ERRORS[outer]
        return f"שגיאת Windows Update ({exc})"
    except Exception:
        return f"שגיאת Windows Update ({exc})"



# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class WindowsUpdateManager:
    """
    Thread-safe manager for listing, hiding, and un-hiding Windows updates
    via the official WUA COM API (Microsoft.Update.Session).
    """

    def __init__(self):
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal COM session factory
    # ------------------------------------------------------------------

    def _create_searcher(self, online: bool = False):
        """Return a configured IUpdateSearcher COM object."""
        import win32com.client  # type: ignore
        _ensure_com()
        session = win32com.client.Dispatch("Microsoft.Update.Session")
        searcher = session.CreateUpdateSearcher()
        searcher.Online = online
        return searcher

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_updates(self, online: bool = False) -> Dict[str, Any]:
        """
        Return two lists:
          'available' – pending updates that are NOT hidden (candidate for hiding).
          'hidden'    – pending updates that ARE already hidden.

        online=False (default) uses the local WU cache — fast, no network call.
        online=True  performs a full network scan against Microsoft's servers —
                     may take 10–60 s but finds the most up-to-date list.
        """
        if not IS_WINDOWS:
            return {"available": [], "hidden": [], "admin": False, "error": None}

        with self._lock:
            try:
                searcher = self._create_searcher(online=online)

                # All not-installed updates (hidden + visible)
                result = searcher.Search("IsInstalled=0")

                available: List[Dict] = []
                hidden: List[Dict] = []

                for i in range(result.Updates.Count):
                    u = result.Updates.Item(i)
                    d = _make_update_dict(u)
                    if d["is_hidden"]:
                        hidden.append(d)
                    else:
                        available.append(d)

                return {
                    "available": available,
                    "hidden": hidden,
                    "admin": is_admin(),
                    "error": None,
                }
            except Exception as exc:
                return {
                    "available": [],
                    "hidden": [],
                    "admin": is_admin(),
                    "error": _translate_com_error(exc),
                }

    def get_hidden_updates(self) -> Dict[str, Any]:
        """
        Faster shortcut that fetches *only* hidden updates from the local cache.
        """
        if not IS_WINDOWS:
            return {"hidden": [], "admin": False, "error": None}

        with self._lock:
            try:
                searcher = self._create_searcher(online=False)
                result = searcher.Search("IsHidden=1")

                hidden: List[Dict] = []
                for i in range(result.Updates.Count):
                    u = result.Updates.Item(i)
                    hidden.append(_make_update_dict(u))

                return {"hidden": hidden, "admin": is_admin(), "error": None}
            except Exception as exc:
                return {
                    "hidden": [],
                    "admin": is_admin(),
                    "error": _translate_com_error(exc),
                }

    def set_update_hidden(
        self, update_id: str, hide: bool = True
    ) -> Dict[str, Any]:
        """
        Set IsHidden on the update identified by *update_id*.

        Parameters
        ----------
        update_id : str  – The GUID from update.Identity.UpdateID.
        hide      : bool – True = hide; False = unhide.

        Returns a dict with keys: 'success', 'message'.
        Requires Administrator privileges (Polaris ensures this at startup).
        """
        if not IS_WINDOWS:
            action = "הוסתר" if hide else "שוחזר"
            return {
                "success": True,
                "message": f"סביבת בדיקה: העדכון {update_id} סומן כ-{action} (מדומה).",
            }

        with self._lock:
            try:
                searcher = self._create_searcher(online=False)
                # Search all non-installed updates (includes hidden+visible)
                result = searcher.Search("IsInstalled=0")

                target_id = update_id.strip().lower()
                for i in range(result.Updates.Count):
                    u = result.Updates.Item(i)
                    if u.Identity.UpdateID.lower() == target_id:
                        u.IsHidden = hide
                        action_he = "הוסתר" if hide else "שוחזר"
                        return {
                            "success": True,
                            "message": f"✓ העדכון '{u.Title}' {action_he} בהצלחה.",
                        }

                return {
                    "success": False,
                    "message": f"לא נמצא עדכון עם המזהה: {update_id}",
                }
            except Exception as exc:
                return {
                    "success": False,
                    "message": _translate_com_error(exc),
                }

    def set_update_hidden_by_kb(
        self, kb: str, hide: bool = True
    ) -> Dict[str, Any]:
        """
        Same as set_update_hidden but matches by KB article number.
        kb should be provided with or without the 'KB' prefix.
        """
        if not IS_WINDOWS:
            action = "הוסתר" if hide else "שוחזר"
            return {
                "success": True,
                "message": f"סביבת בדיקה: KB{kb} {action} (מדומה).",
            }

        kb_clean = kb.upper().lstrip("KB")
        with self._lock:
            try:
                searcher = self._create_searcher(online=False)
                result = searcher.Search("IsInstalled=0")

                matched = 0
                for i in range(result.Updates.Count):
                    u = result.Updates.Item(i)
                    for k in range(u.KBArticleIDs.Count):
                        if u.KBArticleIDs.Item(k) == kb_clean:
                            u.IsHidden = hide
                            matched += 1
                            break

                if matched:
                    action_he = "הוסתר" if hide else "שוחזר"
                    return {
                        "success": True,
                        "message": f"✓ {matched} עדכוני KB{kb_clean} {action_he} בהצלחה.",
                    }
                return {
                    "success": False,
                    "message": f"לא נמצאו עדכונים עבור KB{kb_clean}.",
                }
            except Exception as exc:
                return {
                    "success": False,
                    "message": _translate_com_error(exc),
                }

    # -----------------------------------------------------------------------
    # Windows Update Service Control (wuauserv)
    # -----------------------------------------------------------------------

    def get_service_status(self) -> Dict[str, Any]:
        """
        Queries the current execution status and startup type of the Windows Update service (wuauserv).
        """
        if not IS_WINDOWS:
            return {
                "service_name": "wuauserv",
                "display_name": "Windows Update",
                "status": "stopped",
                "start_type": "manual",
                "is_disabled": False,
                "is_running": False,
                "status_he": "מצב הדמיה (סביבת פיתוח)"
            }

        try:
            import psutil
            svc = psutil.win_service_get('wuauserv')
            status = svc.status()
            start_type = svc.start_type()
            is_disabled = (start_type == 'disabled')
            is_running = (status == 'running')

            if is_disabled:
                status_he = "מושבת (Disabled)"
            elif is_running:
                status_he = "פעיל (Running)"
            else:
                status_he = "מופסק (זמין ידנית)"

            return {
                "service_name": "wuauserv",
                "display_name": svc.display_name(),
                "status": status,
                "start_type": start_type,
                "is_disabled": is_disabled,
                "is_running": is_running,
                "status_he": status_he
            }
        except Exception as exc:
            # Fallback parsing via sc.exe
            try:
                res_qc = run_hidden(['sc.exe', 'qc', 'wuauserv'], capture_output=True, text=True, timeout=5)
                res_q = run_hidden(['sc.exe', 'query', 'wuauserv'], capture_output=True, text=True, timeout=5)
                qc_out = (res_qc.stdout or '').lower()
                q_out = (res_q.stdout or '').lower()
                is_disabled = 'disabled' in qc_out
                is_running = 'running' in q_out
                start_type = 'disabled' if is_disabled else ('auto' if 'auto_start' in qc_out else 'manual')
                status = 'running' if is_running else 'stopped'
                return {
                    "service_name": "wuauserv",
                    "display_name": "Windows Update",
                    "status": status,
                    "start_type": start_type,
                    "is_disabled": is_disabled,
                    "is_running": is_running,
                    "status_he": "מושבת (Disabled)" if is_disabled else ("פעיל (Running)" if is_running else "מופסק")
                }
            except Exception:
                return {
                    "service_name": "wuauserv",
                    "display_name": "Windows Update",
                    "status": "unknown",
                    "start_type": "unknown",
                    "is_disabled": False,
                    "is_running": False,
                    "status_he": f"לא ידוע ({exc})"
                }

    def toggle_service(self, action: Optional[str] = None) -> Dict[str, Any]:
        """
        Disables or enables the Windows Update service (wuauserv).
        If action is 'disable': stops service and sets startup type to 'disabled'.
        If action is 'enable': sets startup type to 'demand' (manual) and starts service.
        If action is None: toggles current state.
        """
        if not IS_WINDOWS:
            mock_disabled = (action == 'disable')
            return {
                "success": True,
                "is_disabled": mock_disabled,
                "message": f"סביבת בדיקה: שירות Windows Update {'הושבת' if mock_disabled else 'הופעל'} בהצלחה (מדומה).",
                "status_info": {
                    "service_name": "wuauserv",
                    "display_name": "Windows Update",
                    "status": "stopped" if mock_disabled else "running",
                    "start_type": "disabled" if mock_disabled else "manual",
                    "is_disabled": mock_disabled,
                    "is_running": not mock_disabled,
                    "status_he": "מושבת (Disabled)" if mock_disabled else "פעיל (Running)"
                }
            }

        current = self.get_service_status()
        if action:
            target_disable = (action.strip().lower() == 'disable')
        else:
            target_disable = not current["is_disabled"]

        try:
            if target_disable:
                # 1. Stop service
                run_hidden(['sc.exe', 'stop', 'wuauserv'], capture_output=True, text=True, timeout=20)
                # 2. Config disabled
                res = run_hidden(['sc.exe', 'config', 'wuauserv', 'start=', 'disabled'], capture_output=True, text=True, timeout=20)
                if res.returncode != 0 and 'Access is denied' in (res.stdout or ''):
                    return {
                        "success": False,
                        "is_disabled": current["is_disabled"],
                        "message": "נדרשות הרשאות מנהל (Administrator) כדי להשבית את שירות העדכונים."
                    }
                new_status = self.get_service_status()
                return {
                    "success": True,
                    "is_disabled": True,
                    "status_info": new_status,
                    "message": "✓ שירות עדכוני Windows (wuauserv) נעצר והושבת בהצלחה. Windows לא יוריד או יתקין עדכונים ברקע."
                }
            else:
                # 1. Config demand (Manual)
                res = run_hidden(['sc.exe', 'config', 'wuauserv', 'start=', 'demand'], capture_output=True, text=True, timeout=20)
                if res.returncode != 0 and 'Access is denied' in (res.stdout or ''):
                    return {
                        "success": False,
                        "is_disabled": current["is_disabled"],
                        "message": "נדרשות הרשאות מנהל (Administrator) כדי להפעיל את שירות העדכונים."
                    }
                # 2. Start service
                run_hidden(['sc.exe', 'start', 'wuauserv'], capture_output=True, text=True, timeout=20)
                new_status = self.get_service_status()
                return {
                    "success": True,
                    "is_disabled": False,
                    "status_info": new_status,
                    "message": "✓ שירות עדכוני Windows (wuauserv) הופעל וחזר לפעילות תקינה."
                }
        except Exception as exc:
            return {
                "success": False,
                "is_disabled": current["is_disabled"],
                "message": f"שגיאה בשינוי מצב שירות העדכונים: {str(exc)}"
            }

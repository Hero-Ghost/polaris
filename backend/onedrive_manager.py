"""
Polaris - Microsoft OneDrive Management & Reset Engine
Handles closing OneDrive processes, deleting account configurations from the Windows Registry,
and resetting local caches to resolve sync stalls and enable fresh logins.
"""

import os
import sys
import time
import shutil
import subprocess
from typing import Dict, Any, Optional

from backend.win_utils import IS_WINDOWS, run_hidden, popen_visible

try:
    import winreg
except ImportError:
    winreg = None

REG_ONEDRIVE_KEY = r"Software\Microsoft\OneDrive"
REG_ACCOUNTS_KEY = r"Software\Microsoft\OneDrive\Accounts"


def get_onedrive_exe_path() -> Optional[str]:
    """Finds the path to the OneDrive executable on Windows."""
    if not IS_WINDOWS:
        return None

    candidates = [
        os.path.join(os.environ.get('LOCALAPPDATA', ''), r'Microsoft\OneDrive\OneDrive.exe'),
        os.path.join(os.environ.get('ProgramFiles', ''), r'Microsoft OneDrive\OneDrive.exe'),
        os.path.join(os.environ.get('ProgramFiles(x86)', ''), r'Microsoft OneDrive\OneDrive.exe'),
        os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), r'SysWOW64\OneDriveSetup.exe'),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def is_onedrive_running() -> bool:
    """Checks if OneDrive.exe is currently running."""
    if not IS_WINDOWS:
        return False

    try:
        import psutil
        for proc in psutil.process_iter(['name']):
            try:
                name = proc.info.get('name') or ''
                if name.lower() == 'onedrive.exe':
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        # Fallback to tasklist if psutil fails
        try:
            res = run_hidden(['tasklist.exe', '/FI', 'IMAGENAME eq OneDrive.exe', '/NH'],
                             capture_output=True, text=True)
            if 'OneDrive.exe' in (res.stdout or ''):
                return True
        except Exception:
            pass

    return False


def close_onedrive() -> Dict[str, Any]:
    """
    Terminates all running OneDrive.exe instances cleanly and forcefully.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    was_running = is_onedrive_running()
    if not was_running:
        return {"success": True, "message": "OneDrive אינו פועל כעת", "killed": False}

    try:
        # Kill forcefully and silently without popping up console windows
        res = run_hidden(['taskkill.exe', '/F', '/T', '/IM', 'OneDrive.exe'],
                         capture_output=True, text=True)
        time.sleep(0.5)
        still_running = is_onedrive_running()
        if still_running:
            # Second attempt with psutil if taskkill didn't catch everything
            try:
                import psutil
                for proc in psutil.process_iter(['name', 'pid']):
                    try:
                        if (proc.info.get('name') or '').lower() == 'onedrive.exe':
                            proc.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                time.sleep(0.3)
            except Exception:
                pass

        return {
            "success": True,
            "message": "תהליכי OneDrive נסגרו בהצלחה.",
            "killed": True
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"שגיאה בסגירת OneDrive: {str(e)}",
            "killed": False
        }


def accounts_registry_exists() -> bool:
    """Checks whether HKCU\\Software\\Microsoft\\OneDrive\\Accounts exists."""
    if not IS_WINDOWS or winreg is None:
        return False

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_ACCOUNTS_KEY, 0, winreg.KEY_READ):
            return True
    except OSError:
        return False


def delete_onedrive_accounts_registry() -> Dict[str, Any]:
    """
    Deletes the HKEY_CURRENT_USER\\Software\\Microsoft\\OneDrive\\Accounts registry key
    and all its subkeys (each subkey represents a configured user account).
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    existed_before = accounts_registry_exists()

    try:
        # reg.exe delete handles recursive deletion of keys with subkeys cleanly
        cmd = ['reg.exe', 'delete', r'HKCU\Software\Microsoft\OneDrive\Accounts', '/f']
        res = run_hidden(cmd, capture_output=True, text=True)

        if res.returncode == 0:
            return {
                "success": True,
                "message": "מפתח הרגיסטרי Accounts נמחק בהצלחה.",
                "deleted": True,
                "existed_before": existed_before
            }
        else:
            # Check if it failed because it simply didn't exist
            if not accounts_registry_exists():
                return {
                    "success": True,
                    "message": "מפתח הרגיסטרי Accounts לא היה קיים (כבר נקי).",
                    "deleted": False,
                    "existed_before": False
                }
            return {
                "success": False,
                "message": f"שגיאה במחיקת הרגיסטרי: {res.stderr.strip() or res.stdout.strip()}",
                "deleted": False,
                "existed_before": existed_before
            }
    except Exception as e:
        return {
            "success": False,
            "message": f"שגיאה בפקודת מחיקת הרגיסטרי: {str(e)}",
            "deleted": False,
            "existed_before": existed_before
        }


def clear_onedrive_local_cache() -> Dict[str, Any]:
    """
    Cleans local OneDrive configuration and telemetry caches:
    - %LOCALAPPDATA%\\Microsoft\\OneDrive\\settings
    - %LOCALAPPDATA%\\Microsoft\\OneDrive\\setup\\logs
    Note: Personal user files inside the synced OneDrive folder are NEVER touched.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד", "cleared_dirs": []}

    local_app_data = os.environ.get('LOCALAPPDATA', '')
    if not local_app_data:
        return {"success": False, "message": "משתנה LOCALAPPDATA אינו מוגדר", "cleared_dirs": []}

    targets = [
        os.path.join(local_app_data, r'Microsoft\OneDrive\settings'),
        os.path.join(local_app_data, r'Microsoft\OneDrive\setup\logs'),
    ]

    cleared = []
    errors = []

    for target in targets:
        if os.path.exists(target):
            try:
                # Delete files inside or the whole directory
                for item in os.listdir(target):
                    item_path = os.path.join(target, item)
                    try:
                        if os.path.isdir(item_path):
                            shutil.rmtree(item_path, ignore_errors=True)
                        else:
                            os.remove(item_path)
                    except Exception:
                        pass
                cleared.append(target)
            except Exception as e:
                errors.append(f"{os.path.basename(target)}: {str(e)}")

    return {
        "success": len(errors) == 0,
        "cleared_dirs": cleared,
        "errors": errors,
        "message": f"נוקו {len(cleared)} תיקיות מטמון והגדרות מקומיות." if cleared else "לא נמצאו תיקיות מטמון לניקוי."
    }


def launch_onedrive() -> Dict[str, Any]:
    """Relaunches OneDrive.exe in the user session."""
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    exe_path = get_onedrive_exe_path()
    if not exe_path or not os.path.exists(exe_path):
        return {"success": False, "message": "קובץ OneDrive.exe לא אותר במערכת."}

    try:
        popen_visible([exe_path, '/background'])
        return {"success": True, "message": "OneDrive הופעל מחדש בהצלחה.", "path": exe_path}
    except Exception as e:
        return {"success": False, "message": f"שגיאה בהפעלת OneDrive: {str(e)}"}


def get_onedrive_status() -> Dict[str, Any]:
    """Returns the current state of OneDrive (running state, registry, exe path)."""
    running = is_onedrive_running()
    reg_exists = accounts_registry_exists()
    exe_path = get_onedrive_exe_path()

    return {
        "success": True,
        "is_running": running,
        "accounts_key_exists": reg_exists,
        "installed": exe_path is not None,
        "exe_path": exe_path
    }


def reset_onedrive(relaunch: bool = False, clean_cache: bool = True) -> Dict[str, Any]:
    """
    Full OneDrive Reset Flow:
    1. Force kill OneDrive.exe
    2. Delete HKCU\\Software\\Microsoft\\OneDrive\\Accounts
    3. Clear local settings and logs cache (if clean_cache=True)
    4. Optionally relaunch OneDrive.exe (if relaunch=True)
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "איפוס OneDrive נתמך בסביבת Windows בלבד."}

    # Step 1: Close OneDrive
    kill_res = close_onedrive()

    # Wait brief moment for locks to release
    time.sleep(0.6)

    # Step 2: Delete registry accounts key
    reg_res = delete_onedrive_accounts_registry()

    # Step 3: Clean local cache/settings if requested
    cache_res = {}
    if clean_cache:
        cache_res = clear_onedrive_local_cache()

    # Step 4: Optionally relaunch
    relaunch_res = {}
    if relaunch:
        time.sleep(0.5)
        relaunch_res = launch_onedrive()

    overall_success = reg_res.get("success", False)

    summary_parts = []
    if kill_res.get("killed"):
        summary_parts.append("OneDrive נסגר")
    if reg_res.get("deleted"):
        summary_parts.append("חשבונות הרגיסטרי נמחקו")
    elif not reg_res.get("existed_before"):
        summary_parts.append("מפתח החשבונות ברגיסטרי כבר היה נקי")
    if cache_res.get("cleared_dirs"):
        summary_parts.append("מטמון ההגדרות נוקה")
    if relaunch and relaunch_res.get("success"):
        summary_parts.append("OneDrive הופעל מחדש")

    msg = " · ".join(summary_parts) if summary_parts else "איפוס OneDrive הושלם בהצלחה."

    return {
        "success": overall_success,
        "message": msg,
        "details": {
            "kill": kill_res,
            "registry": reg_res,
            "cache": cache_res,
            "relaunch": relaunch_res if relaunch else None
        }
    }

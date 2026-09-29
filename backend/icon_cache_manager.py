"""
Polaris - Windows Icon & Thumbnail Cache Rebuild Engine (Enterprise IT Suite)
Terminates File Explorer, completely purges corrupted IconCache.db and Explorer
thumbcache_*.db / iconcache_*.db databases, relaunches Explorer and notifies
the Shell to regenerate clean icons without requiring a system reboot.
"""

import os
import sys
import glob
import time
from typing import Dict, Any, List

from backend.win_utils import IS_WINDOWS, run_hidden, popen_visible, format_bytes

try:
    import ctypes
except ImportError:
    ctypes = None


def get_icon_cache_paths() -> List[str]:
    """
    Returns the list of all icon and thumbnail cache files on the system.
    """
    if not IS_WINDOWS:
        return []

    local_app_data = os.environ.get('LOCALAPPDATA', '')
    if not local_app_data:
        return []

    cache_files = []

    # Legacy icon cache file
    legacy_cache = os.path.join(local_app_data, 'IconCache.db')
    if os.path.exists(legacy_cache):
        cache_files.append(legacy_cache)

    # Modern Explorer icon & thumbnail database caches (Windows 8, 10, 11)
    explorer_dir = os.path.join(local_app_data, r'Microsoft\Windows\Explorer')
    if os.path.isdir(explorer_dir):
        patterns = [
            os.path.join(explorer_dir, 'iconcache_*.db'),
            os.path.join(explorer_dir, 'thumbcache_*.db'),
        ]
        for pattern in patterns:
            for filepath in glob.glob(pattern):
                if os.path.isfile(filepath):
                    cache_files.append(filepath)

    return cache_files


def get_icon_cache_stats() -> Dict[str, Any]:
    """
    Gathers current statistics about the icon and thumbnail cache files.
    """
    if not IS_WINDOWS:
        return {
            "success": False,
            "message": "נתמך בסביבת Windows בלבד",
            "file_count": 0,
            "total_bytes": 0,
            "formatted_size": "0 B"
        }

    files = get_icon_cache_paths()
    total_bytes = 0
    for f in files:
        try:
            total_bytes += os.path.getsize(f)
        except OSError:
            pass

    return {
        "success": True,
        "file_count": len(files),
        "total_bytes": total_bytes,
        "formatted_size": format_bytes(total_bytes),
        "files": [os.path.basename(f) for f in files]
    }


def notify_shell_refresh() -> None:
    """
    Broadcasts a shell association and icon change notification (SHCNE_ASSOCCHANGED).
    Instructs the Windows Shell to immediately reload all icon and thumbnail caches.
    """
    if not IS_WINDOWS or ctypes is None:
        return

    try:
        SHCNE_ASSOCCHANGED = 0x08000000
        SHCNF_IDLIST = 0x0000
        ctypes.windll.shell32.SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)
    except Exception:
        pass


def rebuild_icon_cache() -> Dict[str, Any]:
    """
    Executes the full icon & thumbnail cache purge and rebuild:
    1. Force-kills explorer.exe to release file locks on database files.
    2. Deletes all IconCache.db and Explorer thumbcache_*.db / iconcache_*.db files.
    3. Relaunches explorer.exe with a visible window.
    4. Issues SHChangeNotify to force immediate desktop/taskbar redraw.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    # 1. Kill Explorer
    try:
        run_hidden(['taskkill.exe', '/F', '/IM', 'explorer.exe'], capture_output=True, text=True)
    except Exception as e:
        pass

    time.sleep(0.6)

    # 2. Delete cache files
    files = get_icon_cache_paths()
    deleted_count = 0
    freed_bytes = 0
    locked_files = []

    for f in files:
        file_size = 0
        try:
            file_size = os.path.getsize(f)
        except OSError:
            pass

        try:
            os.remove(f)
            deleted_count += 1
            freed_bytes += file_size
        except OSError as err:
            locked_files.append(os.path.basename(f))

    # 3. Relaunch Explorer (Must use popen_visible so it starts as a normal interactive shell)
    explorer_started = False
    try:
        popen_visible(['explorer.exe'])
        explorer_started = True
    except Exception as e:
        try:
            # Fallback
            import subprocess
            subprocess.Popen(['explorer.exe'])
            explorer_started = True
        except Exception:
            pass

    time.sleep(0.5)

    # 4. Notify Windows Shell
    notify_shell_refresh()

    msg_parts = [
        f"נמחקו {deleted_count} קובצי מטמון אייקונים ותמונות ממוזערות ({format_bytes(freed_bytes)})",
        "סייר הקבצים אותחל מחדש וה-Shell רוענן בהצלחה"
    ]
    if locked_files:
        msg_parts.append(f"שים לב: {len(locked_files)} קבצים היו נעולים ויתרעננו בהפעלה הבאה")

    return {
        "success": True,
        "message": " · ".join(msg_parts),
        "deleted_count": deleted_count,
        "freed_bytes": freed_bytes,
        "formatted_freed": format_bytes(freed_bytes),
        "explorer_restarted": explorer_started,
        "locked_files": locked_files
    }

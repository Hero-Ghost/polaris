"""
Polaris - Storage Analyzer & WinDirStat Engine
Provides full WinDirStat feature parity:
  - Multi-threaded disk scanning with Win32 / os.scandir optimizations
  - Hierarchical folder size & allocated physical size calculation
  - WinDirStat's signature <Unknown> and <Free Space> calculation
  - Extension breakdown with color palette assignment
  - Treemap layout data preparation with tiny-node rollup
  - Largest files tracking (heap-based)
  - Duplicate files detection (sparse hashing + full SHA256)
  - Safe Windows file operations (Recycle Bin via SHFileOperationW, Reveal in Explorer,
    Terminal shortcuts, cleanmgr, vssadmin)
  - Live progress streaming with Pacman animation frames
"""

import os
import sys
import time
import ctypes
import hashlib
import heapq
import threading
import subprocess
import psutil
import json
import re
import shutil
from collections import defaultdict
import queue
import itertools
from ctypes import wintypes

from backend.win_utils import (
    IS_WINDOWS, run_hidden, popen_visible,
    format_bytes, strip_bidi, reveal_in_explorer, is_admin
)

# Win32 Constants for SHFileOperationW (Recycle Bin)
FO_DELETE = 0x0003
FOF_ALLOWUNDO = 0x0040
FOF_NOCONFIRMATION = 0x0010
FOF_SILENT = 0x0004
FOF_NOERRORUI = 0x0400

# File attribute flags
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
FILE_ATTRIBUTE_COMPRESSED = 0x0800
FILE_ATTRIBUTE_SPARSE_FILE = 0x0200

# Standard WinDirStat Cushion Palette colors (Hex)
WDS_PALETTE = [
    "#268bd2",  # Blue
    "#dc322f",  # Red
    "#859900",  # Green
    "#b58900",  # Yellow
    "#cb4b16",  # Orange
    "#6c71c4",  # Violet
    "#d33682",  # Magenta
    "#2aa198",  # Cyan
    "#3498db",  # Sky Blue
    "#e74c3c",  # Coral Red
    "#2ecc71",  # Emerald
    "#f39c12",  # Amber
    "#9b59b6",  # Amethyst
    "#1abc9c",  # Turquoise
    "#e67e22",  # Carrot
    "#95a5a6",  # Gray
    "#e84393",  # Pink
    "#00b894",  # Mint
    "#0984e3",  # Deep Blue
    "#fdcb6e",  # Sunflower
]

def _norm_win_path(path):
    """
    Normalizes a Windows path for comparison purposes only, without touching
    the filesystem and without depending on the host OS's own path module.

    Deliberately NOT os.path.normpath: on POSIX (where this module's tests
    run) normpath treats backslashes as ordinary characters and never
    collapses "C:\\\\" down to "C:\\", which silently defeats every
    drive-root / protected-path check below. This mirrors the same helper
    already used by uninstaller_engine.py for the identical reason.
    """
    if not path or not isinstance(path, str):
        return ""
    p = path.strip().strip('"').replace('/', '\\')
    is_unc = p.startswith('\\\\')
    p = re.sub(r'\\{2,}', '\\\\', p)
    if is_unc:
        p = '\\' + p
    return p.rstrip('\\').lower()


PROTECTED_SEGMENT_NAMES = {
    'windows', 'system32', 'syswow64', 'winsxs', 'boot', 'recovery',
    'system volume information', '$recycle.bin', '$winreagent',
    '$windows.~bt', '$windows.~ws', '$sysreset', 'programdata'
}

ROOT_SYSTEM_FILES = {
    'pagefile.sys', 'swapfile.sys', 'hiberfil.sys', 'dumpstack.log',
    'dumpstack.log.tmp', 'memory.dmp', 'bootmgr', 'bootnxt', 'bootstat.dat',
    'ntldr', 'ntdetect.com', 'boot.ini'
}


def _build_system_protected_paths():
    """Concrete system directories where neither the directory nor ANY file inside it may be deleted."""
    roots = set()

    def add(p):
        n = _norm_win_path(p)
        if n:
            roots.add(n)

    win = os.environ.get('SystemRoot', r'C:\Windows')
    pf = os.environ.get('ProgramFiles', r'C:\Program Files')
    pf86 = os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')
    pdata = os.environ.get('ProgramData', r'C:\ProgramData')
    system_drive = os.environ.get('SystemDrive', 'C:')

    for p in (win, pf, pf86, pdata,
              os.environ.get('PUBLIC', r'C:\Users\Public'),
              f"{system_drive}\\pagefile.sys",
              f"{system_drive}\\hiberfil.sys",
              f"{system_drive}\\swapfile.sys",
              f"{system_drive}\\Boot",
              f"{system_drive}\\Recovery",
              f"{system_drive}\\System Volume Information",
              f"{system_drive}\\$WinREAgent",
              f"{system_drive}\\$Recycle.Bin",
              f"{system_drive}\\$Windows.~BT",
              f"{system_drive}\\$Windows.~WS",
              f"{system_drive}\\$SysReset"):
        add(p)

    add(os.path.join(win, 'System32'))
    add(os.path.join(win, 'SysWOW64'))

    return roots


def _build_protected_paths():
    """The concrete directories on *this* machine that must never be deleted as a whole."""
    roots = set(_build_system_protected_paths())

    def add(p):
        n = _norm_win_path(p)
        if n:
            roots.add(n)

    profile = os.environ.get('USERPROFILE', '')
    system_drive = os.environ.get('SystemDrive', 'C:')
    if profile:
        trimmed = profile.rstrip('\\/')
        parent = trimmed.rsplit('\\', 1)[0] if '\\' in trimmed else trimmed.rsplit('/', 1)[0]
        add(parent)   # e.g. C:\Users
        add(profile)  # e.g. C:\Users\pc
    else:
        add(f"{system_drive}\\Users")

    return roots


SYSTEM_PROTECTED_PATHS = _build_system_protected_paths()
PROTECTED_PATHS = _build_protected_paths()


def _is_path_safe_and_system(path):
    """
    Evaluates whether a path is safe to delete and whether it belongs to Windows system.
    Returns: (is_safe_to_delete: bool, is_system: bool, reason: str)
    """
    if not path or not isinstance(path, str) or not path.strip():
        return False, False, "Path is empty"
    if any(ch in path for ch in '*?'):
        return False, False, "Path contains wildcard characters"
    if '%' in path:
        return False, False, "Path contains an unexpanded environment variable"

    norm = _norm_win_path(path)
    if not norm:
        return False, False, "Path is empty"

    if norm.startswith('\\\\'):
        return False, False, f"Path '{path}' is a network (UNC) location and is not supported for deletion."

    # A bare drive root ("c:" or "c:\\", with nothing after it)
    if re.match(r'^[a-z]:\\?$', norm):
        return False, True, f"Path '{path}' is a protected drive root and cannot be deleted as a whole."

    # Check filename for root-level or critical Windows system files on ANY drive
    parts = [p for p in norm.split('\\') if p]
    if parts:
        filename = parts[-1]
        if filename in ROOT_SYSTEM_FILES:
            return False, True, f"Path '{path}' is a protected Windows system file ({filename})."

    # Check reserved system segment names anywhere in the path
    for seg in parts:
        if seg in PROTECTED_SEGMENT_NAMES:
            return False, True, f"Path '{path}' contains a protected Windows system folder ('{seg}')."

    # Check directories where neither the folder nor ANYTHING inside it may be deleted
    for prot in SYSTEM_PROTECTED_PATHS:
        if norm == prot or norm.startswith(prot + "\\"):
            return False, True, f"Path '{path}' is inside protected system folder '{prot}'."
        # Ancestor check: e.g. someone trying to delete an ancestor of a protected folder
        if prot.startswith(norm + "\\"):
            return False, True, f"Path '{path}' contains the protected system folder '{prot}' and cannot be deleted as a whole."

    # Users root directory (e.g. C:\Users) and user profile roots
    system_drive = os.environ.get('SystemDrive', 'C:')
    users_dir = _norm_win_path(f"{system_drive}\\Users")
    profile = _norm_win_path(os.environ.get('USERPROFILE', ''))
    if profile:
        trimmed = profile.rstrip('\\')
        users_dir = trimmed.rsplit('\\', 1)[0] if '\\' in trimmed else users_dir

    if norm == users_dir:
        return False, False, f"Path '{path}' is the protected users root directory."

    if profile and norm == profile:
        return False, False, f"Path '{path}' is the protected user profile root."

    if users_dir and (norm.startswith(users_dir + "\\")):
        if profile and norm.startswith(profile + "\\"):
            pass  # Files inside current user's profile are permitted
        else:
            return False, False, f"Path '{path}' is inside a protected user profile folder under '{users_dir}'."

    # Reparse points (junctions, symlinks, mount points) can redirect a delete.
    try:
        if os.path.islink(path):
            return False, False, f"Path '{path}' is a symbolic link / junction and will not be followed for deletion."
        if IS_WINDOWS:
            attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
            if attrs != -1 and (attrs & FILE_ATTRIBUTE_REPARSE_POINT):
                return False, False, f"Path '{path}' is a reparse point (junction/symlink) and will not be followed for deletion."
    except Exception:
        pass

    return True, False, ""


def _is_safe_to_delete(path):
    """
    Safety guard: prevents deletion of critical Windows system directories,
    drive roots, UNC roots, reparse points/symlinks, or anything that turns
    out to be an ancestor of one of those (e.g. a client sending "C:\\").
    """
    is_safe, is_sys, reason = _is_path_safe_and_system(path)
    return is_safe, reason


class SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", wintypes.UINT),
        ("pFrom", wintypes.LPCWSTR),
        ("pTo", wintypes.LPCWSTR),
        ("fFlags", wintypes.WORD),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", wintypes.LPVOID),
        ("lpszProgressTitle", wintypes.LPCWSTR),
    ]


class SHQUERYRBINFO(ctypes.Structure):
    """
    Used to detect whether SHFileOperationW's FOF_ALLOWUNDO actually recycled
    an item or silently fell back to a permanent delete (which Windows does
    without any error when the item exceeds the bin's quota, lives on a
    volume with no Recycle Bin - removable/network media - or has recycling
    disabled by policy). cbSize must be set before every call.
    """
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("i64Size", ctypes.c_int64),
        ("i64NumItems", ctypes.c_int64),
    ]


def _win_shell_file_op(file_op):
    """Thin wrapper around SHFileOperationW so tests can substitute a fake
    implementation without needing ctypes.windll, which does not exist at
    all on a non-Windows Python (used to develop/test this module)."""
    return ctypes.windll.shell32.SHFileOperationW(ctypes.byref(file_op))


def _win_query_recycle_bin(drive_root, info):
    """Thin wrapper around SHQueryRecycleBinW - see _win_shell_file_op."""
    return ctypes.windll.shell32.SHQueryRecycleBinW(drive_root, ctypes.byref(info))


# Win32 constants for SHEmptyRecycleBinW
SHERB_NOCONFIRMATION = 0x00000001
SHERB_NOPROGRESSUI = 0x00000002
SHERB_NOSOUND = 0x00000004


def _win_empty_recycle_bin(drive_root, flags):
    """Thin wrapper around SHEmptyRecycleBinW - see _win_shell_file_op."""
    return ctypes.windll.shell32.SHEmptyRecycleBinW(None, drive_root, flags)


class StorageNode:
    """Represents a file or folder in the WinDirStat storage tree."""
    __slots__ = (
        'id', 'name', 'path', 'is_dir', 'size', 'physical_size',
        'file_count', 'dir_count', 'mtime', 'extension', 'children',
        'parent_id', 'attributes'
    )

    def __init__(self, node_id, name, path, is_dir, size=0, physical_size=0, mtime=0, extension=""):
        self.id = node_id
        self.name = name
        self.path = path
        self.is_dir = is_dir
        self.size = size
        self.physical_size = physical_size
        self.file_count = 0 if is_dir else 1
        self.dir_count = 0
        self.mtime = mtime
        self.extension = extension
        self.children = [] if is_dir else None
        self.parent_id = None
        self.attributes = ""

    def to_dict(self, include_children=False, depth=1):
        is_safe, is_sys, prot_reason = _is_path_safe_and_system(self.path) if self.path else (False, False, "Non-actionable node")
        d = {
            "id": self.id,
            "name": self.name,
            "path": self.path,
            "is_dir": self.is_dir,
            "size": self.size,
            "size_formatted": format_bytes(self.size),
            "physical_size": self.physical_size,
            "physical_size_formatted": format_bytes(self.physical_size),
            "file_count": self.file_count,
            "dir_count": self.dir_count,
            "mtime": self.mtime,
            "extension": self.extension,
            "attributes": self.attributes,
            "is_system": is_sys,
            "is_safe_to_delete": is_safe,
            "protection_reason": prot_reason,
        }
        if include_children and self.is_dir and depth > 0:
            d["children"] = [
                c.to_dict(include_children=True, depth=depth - 1)
                for c in sorted(self.children, key=lambda x: x.size, reverse=True)
            ]
        elif self.is_dir:
            d["child_count"] = len(self.children)
        return d


def _find_pdu_binary():
    """
    Locates the standalone native Rust pdu scanning engine binary:
    1. PyInstaller frozen environment (sys._MEIPASS/bin/pdu.exe or sys._MEIPASS/pdu.exe)
    2. Project bin folder (bin/pdu.exe or backend/bin/pdu.exe)
    3. SquirrelDisk vendor bin or system PATH
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        for sub in ("bin", ""):
            cand = os.path.join(sys._MEIPASS, sub, "pdu.exe")
            if os.path.isfile(cand):
                return cand

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base_dir, "bin", "pdu.exe"),
        os.path.join(base_dir, "backend", "bin", "pdu.exe"),
        os.path.join(base_dir, "squirreldisk_src", "src-tauri", "bin", "pdu-x86_64-pc-windows-msvc.exe"),
        shutil.which("pdu"),
    ]
    for cand in candidates:
        if cand and os.path.isfile(cand):
            return cand
    return None


class StorageAnalyzer:
    """
    Core engine providing full WinDirStat & SquirrelDisk parity:
    - Standalone native Rust pdu traversal engine for ultra-fast multi-gigabyte scanning
    - Multi-threaded recursive fallback with reparse-point guards
    - Cushion treemap geometry pre-processing
    - Extension statistics & color assignments
    - Unknown / Free space calculations
    - Largest files & duplicate identification
    - Safe system cleanups & actions
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._scan_thread = None
        self._current_proc = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()

        # State
        self.status = "idle"  # idle, scanning, paused, completed, cancelled, error
        self.error_message = ""
        self.scan_id = 0
        self.start_time = 0.0
        self.elapsed_seconds = 0.0
        self.current_path = ""
        self.files_scanned = 0
        self.folders_scanned = 0
        # Live single-number progress feed from the pdu engine, which does
        # not distinguish files from folders while it is running - kept
        # separate from files_scanned/folders_scanned so the live count
        # never has to be overwritten by (and visually collapse into) the
        # much smaller final, pruned-tree count once the scan completes.
        self.items_seen = 0
        # Directories the scanner could not read at all (PermissionError) -
        # their contents are missing from every total below, not zero-sized.
        self.access_denied_count = 0
        self.total_bytes_scanned = 0
        self.scan_targets = []
        self.pacman_frame = 0

        # Data stores
        self._next_node_id = 1
        self._id_counter = itertools.count(1)
        self.root_node = None
        self._nodes_by_id = {}
        self._nodes_by_path = {}
        self.extension_stats = {}
        self.largest_files = []  # Min-heap of (size, path, name, extension, mtime)
        self.volume_info = {}

    # -------------------------------------------------------------------------
    # Drive Discovery & Volume Capacity
    # -------------------------------------------------------------------------

    def get_drives(self):
        """Returns list of all available logical drives and their capacity."""
        drives = []
        if not IS_WINDOWS:
            # Fallback for cross-platform / development testing
            usage = psutil.disk_usage('/')
            drives.append({
                "letter": "/",
                "path": "/",
                "label": "Root",
                "fs_type": "ext4",
                "total_bytes": usage.total,
                "free_bytes": usage.free,
                "used_bytes": usage.used,
                "percent_used": usage.percent,
                "is_ready": True
            })
            return drives

        # Windows logical drive detection
        try:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    letter = f"{chr(65 + i)}:\\"
                    try:
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(letter)
                        # DRIVE_FIXED = 3, DRIVE_REMOVABLE = 2, DRIVE_REMOTE = 4, DRIVE_CDROM = 5, DRIVE_RAMDISK = 6
                        type_name = "Fixed" if drive_type == 3 else ("Removable" if drive_type == 2 else ("Network" if drive_type == 4 else "Other"))
                        
                        vol_name_buf = ctypes.create_unicode_buffer(261)
                        fs_name_buf = ctypes.create_unicode_buffer(261)
                        ctypes.windll.kernel32.GetVolumeInformationW(
                            letter, vol_name_buf, 261, None, None, None, fs_name_buf, 261
                        )
                        label = vol_name_buf.value or f"Local Disk ({letter[:2]})"
                        fs_type = fs_name_buf.value or "NTFS"

                        usage = psutil.disk_usage(letter)
                        drives.append({
                            "letter": letter[:2],
                            "path": letter,
                            "label": label,
                            "type": type_name,
                            "fs_type": fs_type,
                            "total_bytes": usage.total,
                            "free_bytes": usage.free,
                            "used_bytes": usage.used,
                            "percent_used": usage.percent,
                            "is_ready": True,
                            "is_removable": (drive_type == 2)
                        })
                    except Exception:
                        drives.append({
                            "letter": letter[:2],
                            "path": letter,
                            "label": f"Drive ({letter[:2]})",
                            "type": "Unknown",
                            "fs_type": "",
                            "total_bytes": 0,
                            "free_bytes": 0,
                            "used_bytes": 0,
                            "percent_used": 0,
                            "is_ready": False,
                            "is_removable": False
                        })
        except Exception as e:
            print(f"[StorageAnalyzer] Error detecting drives: {e}")

        return drives

    # -------------------------------------------------------------------------
    # Scan Lifecycle Controls
    # -------------------------------------------------------------------------

    def start_scan(self, targets=None):
        """Starts scanning specified drive letters or directory paths."""
        with self._lock:
            if self.status == "scanning":
                return False, "Scan already in progress"

            if not targets:
                drives = self.get_drives()
                ready = [d["path"] for d in drives if d["is_ready"] and d["total_bytes"] > 0]
                targets = [ready[0]] if ready else ["C:\\"]

            self.scan_targets = targets
            self.status = "scanning"
            self.error_message = ""
            self.scan_id += 1
            self.start_time = time.time()
            self.elapsed_seconds = 0.0
            self.current_path = targets[0]
            self.files_scanned = 0
            self.folders_scanned = 0
            self.items_seen = 0
            self.access_denied_count = 0
            self.total_bytes_scanned = 0
            self.pacman_frame = 0

            self._next_node_id = 1
            self._id_counter = itertools.count(1)
            self._nodes_by_id.clear()
            self._nodes_by_path.clear()
            self.extension_stats.clear()
            self.largest_files.clear()
            self.volume_info.clear()

            self._stop_event.clear()
            self._pause_event.set()

            # Record volume info for the primary target drive
            first_target = targets[0]
            drive_root = os.path.splitdrive(os.path.abspath(first_target))[0] + "\\"
            try:
                usage = psutil.disk_usage(drive_root)
                self.volume_info = {
                    "drive": drive_root,
                    "total_bytes": usage.total,
                    "free_bytes": usage.free,
                    "used_bytes": usage.used,
                    "scanned_bytes": 0,
                    "unknown_bytes": 0,
                }
            except Exception:
                self.volume_info = {
                    "drive": drive_root,
                    "total_bytes": 0,
                    "free_bytes": 0,
                    "used_bytes": 0,
                    "scanned_bytes": 0,
                    "unknown_bytes": 0,
                }

            self._scan_thread = threading.Thread(
                target=self._scan_worker,
                args=(targets, self.scan_id),
                daemon=True,
                name=f"StorageScan-{self.scan_id}"
            )
            self._scan_thread.start()
            return True, "Scan started"

    def pause_scan(self):
        """Pauses active scan (suspends native process if active)."""
        with self._lock:
            if self.status == "scanning":
                self.status = "paused"
                self._pause_event.clear()
                if self._current_proc and self._current_proc.poll() is None:
                    try:
                        p = psutil.Process(self._current_proc.pid)
                        p.suspend()
                    except Exception:
                        pass
                return True
            return False

    def resume_scan(self):
        """Resumes paused scan (resumes native process if active)."""
        with self._lock:
            if self.status == "paused":
                self.status = "scanning"
                self._pause_event.set()
                if self._current_proc and self._current_proc.poll() is None:
                    try:
                        p = psutil.Process(self._current_proc.pid)
                        p.resume()
                    except Exception:
                        pass
                return True
            return False

    def cancel_scan(self):
        """Cancels scan (terminates native process immediately)."""
        with self._lock:
            if self.status in ("scanning", "paused"):
                self.status = "cancelled"
                self._stop_event.set()
                self._pause_event.set()
                self.elapsed_seconds = time.time() - self.start_time if self.start_time > 0 else 0.0
                if self._current_proc and self._current_proc.poll() is None:
                    try:
                        self._current_proc.terminate()
                    except Exception:
                        pass
                return True
            return False

    def get_progress(self):
        """Returns live progress report for UI updates."""
        with self._lock:
            elapsed = time.time() - self.start_time if self.start_time > 0 else 0.0
            if self.status in ("completed", "cancelled", "error"):
                elapsed = self.elapsed_seconds

            # While pdu is running, files_scanned/folders_scanned are only
            # set once at the very end (from the final tree) - items_seen is
            # what actually moves during that phase, so the rate must look
            # at whichever counter is currently the bigger, honest signal.
            items_for_rate = max(self.files_scanned + self.folders_scanned, self.items_seen)
            rate = items_for_rate / elapsed if elapsed > 0.5 else 0.0
            self.pacman_frame = (self.pacman_frame + 1) % 4 if self.status == "scanning" else 0

            # WinDirStat & SquirrelDisk parity: Volume stats calculation
            vol = dict(self.volume_info)
            if vol.get("total_bytes", 0) > 0:
                scanned = self.total_bytes_scanned
                free = vol.get("free_bytes", 0)
                used = vol.get("used_bytes", 0) or max(0, vol["total_bytes"] - free)
                unknown = max(0, vol["total_bytes"] - (scanned + free))
                vol["scanned_bytes"] = scanned
                vol["used_bytes"] = used
                vol["unknown_bytes"] = unknown
                vol["scanned_formatted"] = format_bytes(scanned)
                vol["used_formatted"] = format_bytes(used)
                vol["unknown_formatted"] = format_bytes(unknown)
                vol["free_formatted"] = format_bytes(free)
                vol["total_formatted"] = format_bytes(vol["total_bytes"])

            return {
                "status": self.status,
                "error_message": self.error_message,
                "files_scanned": self.files_scanned,
                "folders_scanned": self.folders_scanned,
                # Live, unsplit progress feed - see the field comment in
                # __init__. Present throughout scanning; once the scan
                # completes it holds the same total the final tree reports,
                # so a client can always show a number without it jumping.
                "items_seen": self.items_seen,
                "access_denied_count": self.access_denied_count,
                "total_bytes_scanned": self.total_bytes_scanned,
                "total_bytes_formatted": format_bytes(self.total_bytes_scanned),
                "current_path": self.current_path,
                "elapsed_seconds": round(elapsed, 1),
                "scan_rate": round(rate, 1),
                "pacman_frame": self.pacman_frame,
                "volume_info": vol,
                "targets": self.scan_targets
            }

    # -------------------------------------------------------------------------
    # Worker: High-Speed Scanning & Tree Construction
    # -------------------------------------------------------------------------

    def _get_physical_size(self, path, logical_size, attrs=0):
        """
        Gets true size allocated on disk.
        For normal files, uses 4KB cluster alignment without kernel roundtrip.
        Only queries GetCompressedFileSizeW for compressed or sparse files.
        """
        if not IS_WINDOWS or logical_size <= 0:
            return logical_size

        if not (attrs & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE)):
            return (logical_size + 4095) // 4096 * 4096

        try:
            high = wintypes.DWORD(0)
            low = ctypes.windll.kernel32.GetCompressedFileSizeW(path, ctypes.byref(high))
            if low != 0xFFFFFFFF or ctypes.GetLastError() == 0:
                return (high.value << 32) + low
        except Exception:
            pass
        return logical_size

    def _scan_worker(self, targets, scan_id):
        """
        SquirrelDisk native scanning engine with Python parallel fallback.
        Attempts ultra-fast native pdu binary scan first; if unavailable or fails,
        falls back seamlessly to multi-threaded Python scan.
        """
        try:
            pdu_binary = _find_pdu_binary()
            if pdu_binary and not self._stop_event.is_set():
                success = self._scan_with_pdu(targets, scan_id, pdu_binary)
                if success:
                    return

            if self._stop_event.is_set():
                with self._lock:
                    self.status = "cancelled"
                    self.elapsed_seconds = time.time() - self.start_time
                return

            # Fallback to Python parallel scanner
            self._scan_with_python(targets, scan_id)
        except Exception as e:
            with self._lock:
                self.status = "error"
                self.error_message = str(e)
            print(f"[StorageAnalyzer] Scan error: {e}")

    def _scan_with_pdu(self, targets, scan_id, pdu_binary):
        """
        Executes SquirrelDisk's standalone native Rust pdu engine to scan the target paths.
        Streams real-time progress from stderr, accumulates json output from stdout,
        and parses the resulting tree into StorageNode hierarchy.
        """
        is_drive_root = any(t.endswith(":\\") or t.endswith(":/") or t.endswith(":") for t in targets)
        ratio = "0.0005" if is_drive_root else "0"

        cmd = [
            pdu_binary,
            "--json-output",
            "--progress",
            "--silent-errors",
            "--bytes-format=plain",
            f"--min-ratio={ratio}"
        ] + [os.path.abspath(t) for t in targets]

        creationflags = 0
        if IS_WINDOWS:
            creationflags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=creationflags
            )
        except Exception as e:
            print(f"[StorageAnalyzer] Failed to spawn pdu: {e}")
            return False

        with self._lock:
            self._current_proc = proc

        stdout_chunks = []
        progress_pattern = re.compile(r'\(scanned ([0-9]+), total ([0-9]+)(?:, erred ([0-9]+))?\)')

        def read_stdout():
            while True:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    break
                stdout_chunks.append(chunk)

        def read_stderr():
            buf = ""
            while True:
                try:
                    chunk = proc.stderr.read(256)
                except Exception:
                    break
                if not chunk:
                    break
                buf += chunk
                for m in progress_pattern.finditer(buf):
                    items = int(m.group(1))
                    total_bytes = int(m.group(2))
                    # pdu does not distinguish files from folders in this
                    # line, so this used to be dumped into files_scanned -
                    # making folders_scanned look stuck at 0 for the whole
                    # scan, and then get overwritten by the much smaller,
                    # pruned-tree count once build_node() runs, which reads
                    # as the file count suddenly collapsing. items_seen is
                    # the honest live total; files_scanned/folders_scanned
                    # are left alone here and set exactly once, from the
                    # real tree, when the scan actually finishes.
                    erred = int(m.group(3)) if m.group(3) else 0
                    with self._lock:
                        self.items_seen = items
                        self.access_denied_count = erred
                        self.total_bytes_scanned = total_bytes
                        self.pacman_frame = (self.pacman_frame + 1) % 4
                        self.elapsed_seconds = time.time() - self.start_time
                if len(buf) > 1000:
                    buf = buf[-200:]

        t_out = threading.Thread(target=read_stdout, daemon=True)
        t_err = threading.Thread(target=read_stderr, daemon=True)
        t_out.start()
        t_err.start()

        # Monitor process while checking _stop_event
        while proc.poll() is None:
            if self._stop_event.is_set():
                try:
                    proc.terminate()
                except Exception:
                    pass
                break
            time.sleep(0.05)

        proc.wait()
        t_out.join(timeout=5)
        t_err.join(timeout=5)

        try:
            if proc.stdout:
                proc.stdout.close()
        except Exception:
            pass
        try:
            if proc.stderr:
                proc.stderr.close()
        except Exception:
            pass

        with self._lock:
            self._current_proc = None

        if self._stop_event.is_set():
            with self._lock:
                self.status = "cancelled"
                self.elapsed_seconds = time.time() - self.start_time
            return True

        full_stdout = "".join(stdout_chunks).strip()
        if not full_stdout or proc.returncode != 0:
            print(f"[StorageAnalyzer] pdu returned non-zero ({proc.returncode}) or empty stdout")
            return False

        try:
            pdu_json = json.loads(full_stdout)
            tree_data = pdu_json.get("tree")
            if not tree_data:
                return False
        except Exception as e:
            print(f"[StorageAnalyzer] Failed to parse pdu JSON: {e}")
            return False

        # Convert pdu tree into StorageNode hierarchy
        total_files = 0
        total_folders = 0
        ext_stats = {}
        top_heap = []
        nodes_by_id = {}
        nodes_by_path = {}

        def build_node(raw_item, parent_path, parent_id):
            nonlocal total_files, total_folders
            name = raw_item.get("name", "")
            data = raw_item.get("data", 0)
            raw_children = raw_item.get("children", [])

            if parent_path is None:
                if len(targets) == 1:
                    node_path = os.path.abspath(targets[0])
                    node_name = node_path if node_path.endswith("\\") else os.path.basename(node_path) or node_path
                else:
                    node_path = "ROOT"
                    node_name = "<All Selected Targets>"
            elif parent_path == "ROOT":
                node_path = os.path.abspath(name)
                node_name = node_path if node_path.endswith("\\") else os.path.basename(node_path) or node_path
            else:
                node_path = os.path.join(parent_path, name)
                node_name = name

            # Determined unconditionally from the real filesystem, not from
            # whether pdu happened to report children: pdu drops every child
            # under --min-ratio from the tree, so a folder whose entire
            # content fell below that threshold arrives here with data > 0
            # and an empty `children` list - the old
            # `len(raw_children) > 0 or (data == 0 and os.path.isdir(...))`
            # check then misread it as a single file (wrong extension stats,
            # wrongly eligible for the "largest files" list and its one-click
            # recycle button, since a folder can't actually be recycled that
            # way).
            is_dir = os.path.isdir(node_path)
            nid = next(self._id_counter)

            if is_dir:
                total_folders += 1
                node = StorageNode(nid, node_name, node_path, is_dir=True)
                node.parent_id = parent_id

                c_size = 0
                c_phys = 0
                c_files = 0
                c_dirs = 0

                for c in raw_children:
                    c_node = build_node(c, node_path, nid)
                    node.children.append(c_node)
                    c_size += c_node.size
                    c_phys += c_node.physical_size
                    c_files += c_node.file_count
                    if c_node.is_dir:
                        c_dirs += (c_node.dir_count + 1)

                # pdu still counts a pruned child's bytes in this folder's
                # `data`, even though it dropped the child itself from
                # `children` - without a stand-in, those bytes silently
                # vanish from the visible breakdown (the folder's own size
                # looks larger than the sum of anything you can see inside
                # it). `path=None` marks it as non-actionable, the same
                # signal the treemap/sunburst rollups already use, so the
                # frontend's existing guards refuse to offer delete/recycle
                # on it.
                pruned_bytes = max(0, data - c_size)
                if pruned_bytes > 0:
                    placeholder = StorageNode(
                        next(self._id_counter), "<תוכן שלא נסרק>", None,
                        is_dir=False, size=pruned_bytes, physical_size=pruned_bytes
                    )
                    placeholder.parent_id = nid
                    node.children.append(placeholder)
                    # Registered by id only (never by path, which is None
                    # here) so resolve_node_id() can look it up and correctly
                    # report it as non-actionable rather than "unknown id".
                    nodes_by_id[placeholder.id] = placeholder
                    c_size += pruned_bytes
                    c_phys += pruned_bytes

                node.size = max(data, c_size)
                node.physical_size = c_phys
                node.file_count = c_files
                node.dir_count = c_dirs

                nodes_by_id[nid] = node
                nodes_by_path[node_path] = node
                return node
            else:
                total_files += 1
                dot_idx = name.rfind('.')
                ext = name[dot_idx:].lower() if (dot_idx > 0 or (dot_idx == 0 and len(name) > 1)) else ""
                phys_size = (data + 4095) & ~4095 if data > 0 else 0

                mtime = 0.0
                try:
                    mtime = os.path.getmtime(node_path)
                except Exception:
                    pass

                node = StorageNode(
                    nid, node_name, node_path, is_dir=False,
                    size=data, physical_size=phys_size, mtime=mtime, extension=ext
                )
                node.parent_id = parent_id
                nodes_by_id[nid] = node
                nodes_by_path[node_path] = node

                ext_key = ext if ext else "<no extension>"
                if ext_key not in ext_stats:
                    ext_stats[ext_key] = {
                        "extension": ext_key,
                        "size": 0,
                        "physical_size": 0,
                        "count": 0,
                        "color": "#95a5a6"
                    }
                ext_stats[ext_key]["size"] += data
                ext_stats[ext_key]["physical_size"] += phys_size
                ext_stats[ext_key]["count"] += 1

                if len(top_heap) < 100:
                    heapq.heappush(top_heap, (data, nid, node_path, node_name, ext, mtime))
                elif data > top_heap[0][0]:
                    heapq.heappushpop(top_heap, (data, nid, node_path, node_name, ext, mtime))

                return node

        root = build_node(tree_data, None, None)

        with self._lock:
            self.root_node = root
            self._nodes_by_id = nodes_by_id
            self._nodes_by_path = nodes_by_path
            self.extension_stats = ext_stats
            self.largest_files = top_heap
            self.files_scanned = total_files
            self.folders_scanned = total_folders
            # Reflects the real, final split now that it exists - this is
            # the "items in map" number, distinct from the live items_seen
            # feed above (which pdu's --min-ratio pruning can make larger).
            self.items_seen = total_files + total_folders
            self.total_bytes_scanned = root.size
            self._assign_extension_colors()
            self.status = "completed"
            self.elapsed_seconds = time.time() - self.start_time

        return True

    def _scan_with_python(self, targets, scan_id):
        """Multi-threaded Python scanner fallback."""
        if len(targets) == 1:
            root_path = os.path.abspath(targets[0])
            name = root_path if root_path.endswith("\\") else os.path.basename(root_path) or root_path
            self.root_node = StorageNode(next(self._id_counter), name, root_path, is_dir=True)
            self._nodes_by_id[self.root_node.id] = self.root_node
            self._nodes_by_path[self.root_node.path] = self.root_node
            initial_dirs = [self.root_node]
        else:
            self.root_node = StorageNode(next(self._id_counter), "<All Selected Targets>", "ROOT", is_dir=True)
            self._nodes_by_id[self.root_node.id] = self.root_node
            initial_dirs = []
            for target in targets:
                t_path = os.path.abspath(target)
                t_name = t_path if t_path.endswith("\\") else os.path.basename(t_path) or t_path
                child_node = StorageNode(next(self._id_counter), t_name, t_path, is_dir=True)
                child_node.parent_id = self.root_node.id
                self.root_node.children.append(child_node)
                self._nodes_by_id[child_node.id] = child_node
                self._nodes_by_path[child_node.path] = child_node
                initial_dirs.append(child_node)

        # Parallel traversal across all subdirectories with work pool
        self._run_parallel_scan(initial_dirs, scan_id)

        if self._stop_event.is_set():
            with self._lock:
                self.status = "cancelled"
                self.elapsed_seconds = time.time() - self.start_time
            return

        # Post-order bottom-up rollup of sizes, physical sizes, and counts
        self._rollup_tree(self.root_node)

        # Assign colors to extensions once scan completes
        self._assign_extension_colors()

        with self._lock:
            if not self._stop_event.is_set():
                self.status = "completed"
            else:
                self.status = "cancelled"
            self.elapsed_seconds = time.time() - self.start_time

    def _run_parallel_scan(self, initial_dirs, scan_id):
        """
        Coordinates parallel directory scanning using a work queue and worker thread pool.
        Each worker pops a directory, scans its immediate entries via os.scandir,
        creates child directory nodes, pushes them to the queue, and aggregates
        file stats.
        """
        work_queue = queue.Queue()
        for d in initial_dirs:
            work_queue.put(d)

        num_workers = min(16, max(4, (os.cpu_count() or 4) * 2))
        active_workers = 0
        active_lock = threading.Lock()
        all_done = threading.Event()
        if not initial_dirs:
            return

        def worker_loop():
            nonlocal active_workers
            while not self._stop_event.is_set():
                # Pause handling
                if not self._pause_event.is_set():
                    self._pause_event.wait()
                    if self._stop_event.is_set():
                        break

                try:
                    dir_node = work_queue.get(timeout=0.05)
                except queue.Empty:
                    with active_lock:
                        if active_workers == 0 and work_queue.empty():
                            all_done.set()
                            return
                    continue

                with active_lock:
                    active_workers += 1

                self.current_path = dir_node.path

                # Local accumulators for this directory
                subdirs = []
                dir_files_nodes = []
                dir_size = 0
                dir_physical = 0
                local_exts = {}
                local_largest = []

                try:
                    with os.scandir(dir_node.path) as it:
                        for entry in it:
                            if self._stop_event.is_set():
                                break

                            try:
                                is_directory = entry.is_dir(follow_symlinks=False)
                                if is_directory:
                                    # Fast junction/reparse point guard to prevent infinite loops
                                    try:
                                        if entry.is_symlink():
                                            continue
                                        if IS_WINDOWS:
                                            attrs = getattr(entry.stat(follow_symlinks=False), 'st_file_attributes', 0)
                                            if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                                                continue
                                    except Exception:
                                        continue

                                    mtime = 0.0
                                    try:
                                        mtime = entry.stat(follow_symlinks=False).st_mtime
                                    except Exception:
                                        pass

                                    child_dir = StorageNode(
                                        next(self._id_counter),
                                        entry.name,
                                        entry.path,
                                        is_dir=True,
                                        mtime=mtime
                                    )
                                    child_dir.parent_id = dir_node.id
                                    subdirs.append(child_dir)

                                elif entry.is_file(follow_symlinks=False):
                                    stat_res = entry.stat(follow_symlinks=False)
                                    size = stat_res.st_size
                                    name = entry.name

                                    # Fast extension extraction
                                    dot_idx = name.rfind('.')
                                    ext = name[dot_idx:].lower() if (dot_idx > 0 or (dot_idx == 0 and len(name) > 1)) else ""

                                    # Fast cluster size calculation (4KB alignment)
                                    file_attrs = getattr(stat_res, 'st_file_attributes', 0)
                                    if IS_WINDOWS and (file_attrs & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_SPARSE_FILE)):
                                        phys_size = self._get_physical_size(entry.path, size, file_attrs)
                                    else:
                                        phys_size = (size + 4095) & ~4095 if size > 0 else 0

                                    file_node = StorageNode(
                                        next(self._id_counter),
                                        name,
                                        entry.path,
                                        is_dir=False,
                                        size=size,
                                        physical_size=phys_size,
                                        mtime=stat_res.st_mtime,
                                        extension=ext
                                    )
                                    file_node.parent_id = dir_node.id
                                    dir_files_nodes.append(file_node)

                                    dir_size += size
                                    dir_physical += phys_size

                                    # Track local extension stats
                                    ext_key = ext if ext else "<no extension>"
                                    if ext_key in local_exts:
                                        local_exts[ext_key][0] += size
                                        local_exts[ext_key][1] += phys_size
                                        local_exts[ext_key][2] += 1
                                    else:
                                        local_exts[ext_key] = [size, phys_size, 1]

                                    local_largest.append((size, file_node.id, entry.path, name, ext, stat_res.st_mtime))

                            except PermissionError:
                                with self._lock:
                                    self.access_denied_count += 1
                                continue
                            except (FileNotFoundError, OSError):
                                continue

                except PermissionError:
                    # The whole directory was unreadable - its contents are
                    # simply missing from every count below, not zero bytes.
                    # Previously swallowed silently, so a scan run without
                    # admin rights quietly under-reported and the gap showed
                    # up only as unexplained "<Unknown>" space.
                    with self._lock:
                        self.access_denied_count += 1
                except (FileNotFoundError, OSError):
                    pass

                # Attach direct children to dir_node
                dir_node.children = subdirs + dir_files_nodes
                dir_node.size = dir_size
                dir_node.physical_size = dir_physical
                dir_node.file_count = len(dir_files_nodes)

                # Enqueue subdirectories for parallel processing
                for s in subdirs:
                    work_queue.put(s)

                # Flush this directory's findings to shared state under lock
                with self._lock:
                    self.folders_scanned += 1
                    self.files_scanned += len(dir_files_nodes)
                    self.total_bytes_scanned += dir_size

                    self._nodes_by_id[dir_node.id] = dir_node
                    self._nodes_by_path[dir_node.path] = dir_node
                    for fn in dir_files_nodes:
                        self._nodes_by_id[fn.id] = fn

                    # Merge extension stats
                    for ext_key, (sz, psz, cnt) in local_exts.items():
                        if ext_key not in self.extension_stats:
                            self.extension_stats[ext_key] = {
                                "extension": ext_key,
                                "size": 0,
                                "physical_size": 0,
                                "count": 0,
                                "color": "#95a5a6"
                            }
                        self.extension_stats[ext_key]["size"] += sz
                        self.extension_stats[ext_key]["physical_size"] += psz
                        self.extension_stats[ext_key]["count"] += cnt

                    # Merge top largest files (Min-Heap of size 100)
                    for item in local_largest:
                        if len(self.largest_files) < 100:
                            heapq.heappush(self.largest_files, item)
                        elif item[0] > self.largest_files[0][0]:
                            heapq.heappushpop(self.largest_files, item)

                work_queue.task_done()
                with active_lock:
                    active_workers -= 1
                    if active_workers == 0 and work_queue.empty():
                        all_done.set()

        workers = []
        for _ in range(num_workers):
            t = threading.Thread(target=worker_loop, daemon=True)
            t.start()
            workers.append(t)

        while not all_done.is_set() and not self._stop_event.is_set():
            all_done.wait(timeout=0.05)

    def _rollup_tree(self, node):
        """
        Recursively rolls up sizes, physical sizes, file counts, and directory counts
        from leaf directories up to the root after parallel traversal completes.
        """
        if not node.is_dir:
            return node.size, node.physical_size, 1, 0

        total_size = node.size
        total_phys = node.physical_size
        total_files = node.file_count
        total_dirs = 0

        for child in (node.children or []):
            if child.is_dir:
                c_sz, c_phys, c_files, c_dirs = self._rollup_tree(child)
                total_size += c_sz
                total_phys += c_phys
                total_files += c_files
                total_dirs += (c_dirs + 1)

        node.size = total_size
        node.physical_size = total_phys
        node.file_count = total_files
        node.dir_count = total_dirs
        return total_size, total_phys, total_files, total_dirs

    def _assign_extension_colors(self):
        """Assigns vibrant, contrasting colors to extensions based on size ranking."""
        sorted_exts = sorted(self.extension_stats.values(), key=lambda x: x["size"], reverse=True)
        total_size = sum(x["size"] for x in sorted_exts) or 1

        import colorsys

        for i, ext in enumerate(sorted_exts):
            ext["percentage"] = round((ext["size"] / total_size) * 100, 2)
            ext["size_formatted"] = format_bytes(ext["size"])
            ext["physical_size_formatted"] = format_bytes(ext["physical_size"])

            if i < len(WDS_PALETTE):
                ext["color"] = WDS_PALETTE[i]
            else:
                # Golden ratio hue distribution for remaining extensions converted to hex
                hue = (i * 137.5) % 360
                r, g, b = colorsys.hls_to_rgb(hue / 360.0, 0.55, 0.70)
                ext["color"] = f"#{int(r * 255):02x}{int(g * 255):02x}{int(b * 255):02x}"

    # -------------------------------------------------------------------------
    # UI Data Feeds: Tree, Treemap, Extensions, Top Files, Duplicates
    # -------------------------------------------------------------------------

    def get_tree(self, node_id=None, max_depth=1):
        """Returns directory tree node with children sorted by size."""
        with self._lock:
            if not self.root_node:
                return None

            target_node = self._nodes_by_id.get(node_id, self.root_node) if node_id else self.root_node
            total_scan_size = self.root_node.size or 1

            def serialize(node, depth):
                d = node.to_dict(include_children=False)
                d["percentage_of_total"] = round((node.size / total_scan_size) * 100, 2)
                parent = self._nodes_by_id.get(node.parent_id)
                parent_size = parent.size if parent and parent.size > 0 else total_scan_size
                d["percentage_of_parent"] = round((node.size / parent_size) * 100, 2)

                if node.is_dir and depth > 0:
                    sorted_children = sorted(node.children, key=lambda c: c.size, reverse=True)
                    d["children"] = [serialize(c, depth - 1) for c in sorted_children]
                elif node.is_dir:
                    d["children_count"] = len(node.children)
                return d

            return serialize(target_node, max_depth)

    def get_treemap_data(self, node_id=None, max_depth=10, min_area_ratio=0.00005):
        """
        Prepares hierarchical data for the client-side Cushion Treemap.
        Rolls up microscopic files into '<Files>' containers to ensure 60fps rendering.
        """
        with self._lock:
            if not self.root_node:
                return None

            root = self._nodes_by_id.get(node_id, self.root_node) if node_id else self.root_node
            if root.size <= 0:
                return None

            def build_hierarchy(node, current_depth):
                if not node.is_dir:
                    ext_key = (node.extension if node.extension else "<no extension>").lower()
                    ext_color = self.extension_stats.get(ext_key, {}).get("color", "#3498db")
                    return {
                        "id": node.id,
                        "name": node.name,
                        "path": node.path,
                        "size": node.size,
                        "size_formatted": format_bytes(node.size),
                        "is_dir": False,
                        "extension": node.extension,
                        "color": ext_color,
                    }

                # Directory node
                children_data = []
                threshold = max(512 * 1024, int(root.size * min_area_ratio))
                small_files_size = 0
                small_files_count = 0

                for child in sorted(node.children, key=lambda c: c.size, reverse=True):
                    if child.size <= 0:
                        continue

                    if not child.is_dir:
                        if child.size < threshold and current_depth >= 2:
                            small_files_size += child.size
                            small_files_count += 1
                        else:
                            ext_key = (child.extension if child.extension else "<no extension>").lower()
                            ext_color = self.extension_stats.get(ext_key, {}).get("color", "#3498db")
                            children_data.append({
                                "id": child.id,
                                "name": child.name,
                                "path": child.path,
                                "size": child.size,
                                "size_formatted": format_bytes(child.size),
                                "is_dir": False,
                                "extension": child.extension,
                                "color": ext_color,
                            })
                    else:
                        if current_depth < max_depth:
                            subtree = build_hierarchy(child, current_depth + 1)
                            if subtree and (subtree.get("children") or not subtree.get("is_dir")):
                                children_data.append(subtree)
                        else:
                            # Leaf folder representation
                            children_data.append({
                                "id": child.id,
                                "name": child.name,
                                "path": child.path,
                                "size": child.size,
                                "size_formatted": format_bytes(child.size),
                                "is_dir": True,
                                "children": [],
                                "color": "#334155"
                            })

                if small_files_count > 0:
                    children_data.append({
                        "id": -1,
                        "name": f"<{small_files_count} smaller files>",
                        # This node is a synthetic rollup, not a real file or folder -
                        # it must never carry a real path. A real parent-folder path
                        # here would let a "delete this" click on the aggregate wipe
                        # out the whole containing directory instead of nothing.
                        "path": None,
                        "size": small_files_size,
                        "size_formatted": format_bytes(small_files_size),
                        "is_dir": False,
                        "is_aggregated": True,
                        "extension": ".misc",
                        "color": "#475569"
                    })

                return {
                    "id": node.id,
                    "name": node.name,
                    "path": node.path,
                    "size": node.size,
                    "size_formatted": format_bytes(node.size),
                    "is_dir": True,
                    "children": children_data
                }

            return build_hierarchy(root, 1)

    def get_sunburst_data(self, node_id=None, max_depth=4, min_ratio=0.004):
        """
        Prepares hierarchical data specifically for the SquirrelDisk / DaisyDisk
        interactive Sunburst (radial concentric multi-level rings) visualizer.
        Rolls up micro-items below min_ratio into a 'Smaller Items' slice.
        Assigns distinct hues to top children and computes depth shading.
        """
        with self._lock:
            if not self.root_node:
                return None

            root = self._nodes_by_id.get(node_id, self.root_node) if node_id else self.root_node
            if root.size <= 0:
                return None

            top_children = sorted([c for c in (root.children or []) if c.size > 0], key=lambda x: x.size, reverse=True)
            top_count = max(len(top_children), 1)
            child_hues = {}
            for idx, c in enumerate(top_children):
                child_hues[c.id] = int((idx * 360) / top_count)

            threshold = root.size * min_ratio

            def build_slice(node, depth, base_hue):
                lightness = max(28, 62 - (depth - 1) * 11)
                color = f"hsl({base_hue}, 75%, {lightness}%)"

                if not node.is_dir:
                    return {
                        "id": node.id,
                        "name": node.name,
                        "path": node.path,
                        "size": node.size,
                        "size_formatted": format_bytes(node.size),
                        "value": node.size,
                        "is_dir": False,
                        "extension": node.extension,
                        "depth": depth,
                        "color": color,
                        "children": []
                    }

                children_list = []
                smaller_items_size = 0
                smaller_items_count = 0

                sorted_children = sorted([c for c in (node.children or []) if c.size > 0], key=lambda x: x.size, reverse=True)

                for c in sorted_children:
                    c_hue = base_hue if depth > 1 else child_hues.get(c.id, base_hue)
                    if c.size < threshold and depth >= 2:
                        smaller_items_size += c.size
                        smaller_items_count += 1
                    else:
                        if depth < max_depth and c.is_dir:
                            subtree = build_slice(c, depth + 1, c_hue)
                            if subtree:
                                children_list.append(subtree)
                        else:
                            leaf_lightness = max(25, 60 - depth * 10)
                            children_list.append({
                                "id": c.id,
                                "name": c.name,
                                "path": c.path,
                                "size": c.size,
                                "size_formatted": format_bytes(c.size),
                                "value": c.size,
                                "is_dir": c.is_dir,
                                "extension": c.extension,
                                "depth": depth + 1,
                                "color": f"hsl({c_hue}, 70%, {leaf_lightness}%)",
                                "children": []
                            })

                if smaller_items_count > 0:
                    children_list.append({
                        "id": -1,
                        "name": f"<{smaller_items_count} Smaller Items>",
                        # Synthetic rollup slice - must never carry a real path (see
                        # the identical fix in get_treemap_data for why).
                        "path": None,
                        "size": smaller_items_size,
                        "size_formatted": format_bytes(smaller_items_size),
                        "value": smaller_items_size,
                        "is_dir": False,
                        "is_aggregated": True,
                        "depth": depth + 1,
                        "color": "rgba(160, 170, 185, 0.4)",
                        "children": []
                    })

                return {
                    "id": node.id,
                    "name": node.name,
                    "path": node.path,
                    "size": node.size,
                    "size_formatted": format_bytes(node.size),
                    "value": node.size,
                    "is_dir": True,
                    "depth": depth,
                    "color": color,
                    "children": children_list
                }

            return build_slice(root, 1, 210)

    def get_extensions_summary(self):
        """Returns sorted list of file extensions and stats."""
        with self._lock:
            sorted_exts = sorted(self.extension_stats.values(), key=lambda x: x["size"], reverse=True)
            return sorted_exts

    def get_top_files(self, limit=100):
        """Returns the top largest files found in the scan."""
        with self._lock:
            sorted_files = sorted(self.largest_files, key=lambda x: x[0], reverse=True)[:limit]
            result = []
            total_size = self.root_node.size if self.root_node and self.root_node.size > 0 else 1

            for size, node_id, path, name, ext, mtime in sorted_files:
                ext_color = self.extension_stats.get(ext, {}).get("color", "#95a5a6")
                is_safe, is_sys, prot_reason = _is_path_safe_and_system(path)
                result.append({
                    "id": node_id,
                    "name": name,
                    "path": path,
                    "size": size,
                    "size_formatted": format_bytes(size),
                    "extension": ext,
                    "percentage": round((size / total_size) * 100, 2),
                    "mtime": mtime,
                    "color": ext_color,
                    "is_system": is_sys,
                    "is_safe_to_delete": is_safe,
                    "protection_reason": prot_reason
                })
            return result

    def find_duplicates(self, min_size_mb=10, limit=50):
        """
        Fast on-demand duplicate detection:
        1. Groups candidate files by exact file size.
        2. Filters out singletons.
        3. Computes sparse hash (first 64KB + middle + end) for candidates.
        4. Computes full SHA256 for sparse matches to guarantee accuracy.
        """
        with self._lock:
            if not self.root_node:
                return []

            # Step 1: Collect files by size
            size_map = defaultdict(list)
            min_bytes = int(min_size_mb * 1024 * 1024)

            for node in self._nodes_by_id.values():
                if not node.is_dir and node.size >= min_bytes:
                    size_map[node.size].append(node)

        # Step 2: Filter size candidates with count >= 2
        candidates = {s: nodes for s, nodes in size_map.items() if len(nodes) >= 2}
        if not candidates:
            return []

        def get_sparse_hash(filepath, filesize):
            try:
                with open(filepath, "rb") as f:
                    chunk_size = 64 * 1024
                    h = hashlib.sha256()
                    h.update(f.read(chunk_size))
                    if filesize > chunk_size * 3:
                        f.seek(filesize // 2)
                        h.update(f.read(chunk_size))
                        f.seek(filesize - chunk_size)
                        h.update(f.read(chunk_size))
                    return h.hexdigest()
            except Exception:
                return None

        def get_full_hash(filepath):
            try:
                h = hashlib.sha256()
                with open(filepath, "rb") as f:
                    while chunk := f.read(256 * 1024):
                        h.update(chunk)
                return h.hexdigest()
            except Exception:
                return None

        duplicate_groups = []

        for size, nodes in list(candidates.items())[:100]:
            sparse_map = defaultdict(list)
            for node in nodes:
                sh = get_sparse_hash(node.path, size)
                if sh:
                    sparse_map[sh].append(node)

            for sh, matching_nodes in sparse_map.items():
                if len(matching_nodes) >= 2:
                    full_map = defaultdict(list)
                    for node in matching_nodes:
                        fh = get_full_hash(node.path)
                        if fh:
                            full_map[fh].append(node)

                    for fh, dupes in full_map.items():
                        if len(dupes) >= 2:
                            wasted_bytes = size * (len(dupes) - 1)
                            duplicate_groups.append({
                                "hash": fh[:12],
                                "size": size,
                                "size_formatted": format_bytes(size),
                                "wasted_bytes": wasted_bytes,
                                "wasted_formatted": format_bytes(wasted_bytes),
                                "files": [
                                    {
                                        "id": d.id,
                                        "name": d.name,
                                        "path": d.path,
                                        "mtime": d.mtime,
                                        "extension": d.extension,
                                        "is_system": _is_path_safe_and_system(d.path)[1],
                                        "is_safe_to_delete": _is_path_safe_and_system(d.path)[0],
                                        "protection_reason": _is_path_safe_and_system(d.path)[2],
                                    }
                                    for d in dupes
                                ]
                            })

        # Sort by most wasted space descending
        duplicate_groups.sort(key=lambda x: x["wasted_bytes"], reverse=True)
        return duplicate_groups[:limit]

    # -------------------------------------------------------------------------
    # WinDirStat Action Suite (Safe Deletion, Explorer, Maintenance)
    # -------------------------------------------------------------------------

    def resolve_node_id(self, node_id):
        """
        Resolves a client-supplied node id against this analyzer's own scan
        index. Returns the node's real path, or None if the id is missing,
        the synthetic aggregate sentinel (-1), or was never produced by a
        scan this process actually ran.

        This is the provenance check: a client can only ever act on a path
        that our own scanner walked and assigned an id to, never on an
        arbitrary string it happens to send in the request body.
        """
        if node_id is None:
            return None
        try:
            node_id = int(node_id)
        except (TypeError, ValueError):
            return None
        if node_id == -1:
            return None
        with self._lock:
            node = self._nodes_by_id.get(node_id)
        return node.path if node else None

    def perform_action(self, action, target_path=None, node_id=None):
        """
        Executes file system and maintenance actions with safety guards.

        For the two destructive actions (recycle / delete_permanent), the
        path actually acted on is resolved from `node_id` against this
        analyzer's own scan index - `target_path` is never trusted for those,
        even when both are supplied. Every other action is a read-only or
        already-idempotent convenience (reveal in Explorer, open a terminal,
        launch cleanmgr) and keeps accepting a raw path.
        """
        if action in ("recycle", "delete_permanent"):
            resolved_path = self.resolve_node_id(node_id)
            if resolved_path is None:
                return False, ("הפריט לא נמצא באינדקס הסריקה הנוכחי - יש לסרוק מחדש "
                                "ולנסות שוב (פעולת מחיקה מתבצעת רק על פריטים שנסרקו בפועל).")
            target_path = resolved_path

            is_safe, reason = _is_safe_to_delete(target_path)
            if not is_safe:
                return False, f"Action blocked: {reason}"

        if action == "recycle":
            return self._recycle_item(target_path)
        elif action == "delete_permanent":
            return self._delete_permanent(target_path)
        elif action == "reveal_in_explorer":
            return self._reveal_in_explorer(target_path)
        elif action == "open_item":
            return self._open_item(target_path)
        elif action == "open_in_cmd":
            return self._open_in_cmd(target_path)
        elif action == "open_in_powershell":
            return self._open_in_powershell(target_path)
        elif action == "launch_cleanmgr":
            return self._launch_cleanmgr(target_path)
        elif action == "get_vss_storage":
            return self._get_vss_storage()
        elif action == "empty_recycle_bin":
            return self._empty_recycle_bin(target_path)
        else:
            return False, f"Unknown action: {action}"

    def delete_collected_items(self, node_ids):
        """
        Safely deletes a collection of items (from the SquirrelDisk Deletion Collector).

        Takes opaque node ids produced by this analyzer's own scan, never raw
        client-supplied paths - each id is resolved against `_nodes_by_id`
        before anything is touched, exactly like `perform_action` above. A
        client that sends an id we never handed out (or one from a stale/
        different scan) gets a rejection for that item, not a deletion.
        """
        if not node_ids or not isinstance(node_ids, list):
            return {"success": False, "error": "No items provided", "deleted_count": 0, "freed_bytes": 0}

        deleted_count = 0
        freed_bytes = 0
        errors = []

        for raw_id in node_ids:
            p = self.resolve_node_id(raw_id)
            if p is None:
                errors.append({"path": None, "id": raw_id,
                                "error": "הפריט לא נמצא באינדקס הסריקה הנוכחי"})
                continue

            is_safe, reason = _is_safe_to_delete(p)
            if not is_safe:
                errors.append({"path": p, "error": reason})
                continue

            if not os.path.exists(p):
                errors.append({"path": p, "error": "Path does not exist"})
                continue

            # Calculate size before deletion
            item_size = 0
            try:
                if os.path.isdir(p):
                    for root, dirs, files in os.walk(p):
                        for f in files:
                            fp = os.path.join(root, f)
                            if not os.path.islink(fp):
                                item_size += os.path.getsize(fp)
                else:
                    item_size = os.path.getsize(p)
            except Exception:
                pass

            ok, msg = self._recycle_item(p)
            if ok:
                deleted_count += 1
                freed_bytes += item_size
                with self._lock:
                    if p in self._nodes_by_path:
                        node = self._nodes_by_path[p]
                        if node.parent_id and node.parent_id in self._nodes_by_id:
                            parent = self._nodes_by_id[node.parent_id]
                            if parent.children:
                                parent.children = [c for c in parent.children if c.id != node.id]
                                parent.size = max(0, parent.size - node.size)
            else:
                errors.append({"path": p, "error": msg})

        return {
            # Honest success: previously always True even when every item was
            # rejected or failed to delete, so a caller had no way to tell
            # "nothing was removed" apart from "everything was removed".
            "success": len(errors) == 0,
            "deleted_count": deleted_count,
            "freed_bytes": freed_bytes,
            "freed_formatted": format_bytes(freed_bytes),
            "errors": errors
        }

    @staticmethod
    def _query_recycle_bin(drive_root):
        """
        Returns the Recycle Bin's current item count for `drive_root` (e.g.
        "C:\\"), or None if the query itself fails - which on its own is a
        signal that the volume may not have a usable Recycle Bin at all
        (typical for removable/network drives).
        """
        if not IS_WINDOWS:
            return None
        info = SHQUERYRBINFO()
        info.cbSize = ctypes.sizeof(SHQUERYRBINFO)
        try:
            res = _win_query_recycle_bin(drive_root, info)
        except Exception:
            return None
        if res != 0:
            return None
        return info.i64NumItems

    def _recycle_item(self, path):
        """Sends a file or folder to the Windows Recycle Bin via SHFileOperationW."""
        if not os.path.exists(path):
            return False, "File or folder not found"

        if not IS_WINDOWS:
            # Cross-platform fallback for testing
            try:
                if os.path.isdir(path):
                    import shutil
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                return True, f"Removed '{path}'"
            except Exception as e:
                return False, str(e)

        abs_path = os.path.abspath(path)
        drive_root = os.path.splitdrive(abs_path)[0] + "\\"

        # SHFileOperationW's FOF_ALLOWUNDO does not fail when recycling isn't
        # actually possible (item too big for the bin's quota, a volume with
        # no bin, or recycling disabled by policy) - it just permanently
        # deletes the item and still reports success. Comparing the bin's
        # item count before and after is how we tell which one actually
        # happened, so the caller is never told "moved to Recycle Bin" about
        # something that was, in fact, deleted for good.
        count_before = self._query_recycle_bin(drive_root)

        try:
            # SHFileOperationW requires a double-null terminated string
            p_from = abs_path + "\0\0"
            file_op = SHFILEOPSTRUCTW()
            file_op.hwnd = None
            file_op.wFunc = FO_DELETE
            file_op.pFrom = p_from
            file_op.pTo = None
            file_op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI

            res = _win_shell_file_op(file_op)
        except Exception as e:
            return False, f"Recycle Bin error: {e}"

        if res != 0 or file_op.fAnyOperationsAborted:
            return False, f"Recycle Bin operation returned error code {res}"

        if os.path.exists(abs_path):
            return False, "Recycle Bin operation reported success but the item still exists"

        count_after = self._query_recycle_bin(drive_root)
        if count_before is not None and count_after is not None and count_after <= count_before:
            # The item is gone from its original location but the bin did not
            # grow: Windows fell back to a permanent delete. Report that
            # honestly instead of claiming it can still be restored.
            return True, (f"'{os.path.basename(path)}' נמחק לצמיתות - לא ניתן היה להעביר "
                          "אותו לסל המיחזור בכונן זה (מכסת הסל מלאה, או שהסל אינו זמין בנפח זה).")

        return True, f"Successfully moved to Recycle Bin: {os.path.basename(path)}"

    def _empty_recycle_bin(self, drive_root=None):
        """
        Permanently empties the Windows Recycle Bin via SHEmptyRecycleBinW.

        `drive_root` limits this to one volume's bin (e.g. "C:\\"); a falsy
        value empties every drive's bin, since both SHEmptyRecycleBinW and
        SHQueryRecycleBinW treat a null path as "all drives".

        This replaces the previous implementation, which shelled out to
        `powershell -Command "Clear-RecycleBin -Force -ErrorAction
        SilentlyContinue"` via the generic open-a-terminal action: that
        command was launched in a **detached** PowerShell window (the same
        action used for "open PowerShell here"), so the frontend fired the
        request, immediately showed "emptied successfully", and never
        actually waited for or checked the result - and SilentlyContinue
        meant even a failure inside that detached window produced no visible
        error. This calls the Win32 API directly and reports honestly.
        """
        if not IS_WINDOWS:
            return False, "פעולה זו נתמכת רק ב-Windows"

        root = drive_root or None
        try:
            flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
            res = _win_empty_recycle_bin(root, flags)
        except Exception as e:
            return False, f"שגיאה בריקון סל המחזור: {e}"

        count_after = self._query_recycle_bin(root)
        if res != 0:
            # A handful of Windows builds return a non-zero code when the bin
            # was already empty rather than treating that as success - so
            # only report failure if the bin turns out to still have items.
            if count_after == 0:
                return True, "סל המחזור כבר היה ריק"
            return False, f"ריקון סל המחזור נכשל (קוד שגיאה {res})"

        if count_after is not None and count_after > 0:
            return False, f"הפעולה דיווחה על הצלחה אך סל המחזור עדיין מכיל {count_after} פריטים"

        return True, "סל המחזור רוקן בהצלחה"

    def _delete_permanent(self, path):
        """Permanently deletes a file or directory tree."""
        if not os.path.exists(path):
            return False, "File or folder not found"

        try:
            if os.path.isdir(path):
                import shutil
                shutil.rmtree(path)
            else:
                os.remove(path)
            return True, f"Permanently deleted: {os.path.basename(path)}"
        except Exception as e:
            return False, f"Deletion failed: {e}"

    def _reveal_in_explorer(self, path):
        """
        Opens File Explorer with the item highlighted, or its parent folder when
        the item itself is gone. The real work lives in win_utils.reveal_in_explorer
        so that the window is actually shown (see popen_visible there).
        """
        return reveal_in_explorer(path)

    def _open_item(self, path):
        """Opens the file or directory with its default application."""
        if not path:
            return False, "לא צוין נתיב"
        path = os.path.normpath(path.strip().strip('"').strip("'"))
        if not os.path.exists(path):
            parent = os.path.dirname(path)
            if parent and os.path.exists(parent):
                try:
                    if IS_WINDOWS:
                        os.startfile(parent)
                    return True, "הקובץ לא נמצא, נפתחה התיקייה"
                except Exception as e:
                    return False, str(e)
            return False, "הנתיב אינו קיים"
        try:
            if IS_WINDOWS:
                os.startfile(path)
            return True, "נפתח בהצלחה"
        except Exception as e:
            return False, str(e)

    def _open_in_cmd(self, path):
        """Opens CMD at folder."""
        folder = path if os.path.isdir(path) else os.path.dirname(path)
        if not os.path.exists(folder):
            return False, "Folder does not exist"
        try:
            subprocess.Popen(["cmd.exe", "/K", f"cd /d \"{folder}\""], creationflags=subprocess.CREATE_NEW_CONSOLE)
            return True, "Command Prompt opened"
        except Exception as e:
            return False, str(e)

    def _open_in_powershell(self, path):
        """Opens PowerShell at folder."""
        folder = path if os.path.isdir(path) else os.path.dirname(path)
        if not os.path.exists(folder):
            return False, "Folder does not exist"
        try:
            subprocess.Popen(["powershell.exe", "-NoExit", "-Command", f"Set-Location -LiteralPath '{folder}'"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            return True, "PowerShell opened"
        except Exception as e:
            return False, str(e)

    def _launch_cleanmgr(self, drive_path):
        """Launches Windows Disk Cleanup (cleanmgr.exe)."""
        if not IS_WINDOWS:
            return False, "Windows only"
        try:
            drive_letter = os.path.splitdrive(os.path.abspath(drive_path))[0]
            # cleanmgr has a GUI - popen_hidden would start it with SW_HIDE.
            popen_visible(["cleanmgr.exe", "/d", drive_letter[:1]])
            return True, f"Launched Disk Cleanup for {drive_letter}"
        except Exception as e:
            return False, str(e)

    def _get_vss_storage(self):
        """Queries allocated VSS shadow copies space."""
        if not IS_WINDOWS:
            return False, "Windows only"
        try:
            proc = run_hidden(["vssadmin", "list", "shadowstorage"], capture_output=True, text=True, errors="replace")
            output = proc.stdout.strip()
            return True, output if output else "No shadow storage reported."
        except Exception as e:
            return False, str(e)

    # -------------------------------------------------------------------------
    # Report Exporting
    # -------------------------------------------------------------------------

    def export_report(self, export_format="json"):
        """Exports the scan tree into CSV or JSON format."""
        with self._lock:
            if not self.root_node:
                return None

            def _clean(obj):
                """Strips the BiDi display controls out of exported payloads."""
                if isinstance(obj, dict):
                    return {k: _clean(v) for k, v in obj.items()}
                if isinstance(obj, list):
                    return [_clean(v) for v in obj]
                if isinstance(obj, str):
                    return strip_bidi(obj)
                return obj

            if export_format == "json":
                import json
                data = {
                    "scan_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.start_time)),
                    "targets": self.scan_targets,
                    "total_bytes": self.root_node.size,
                    "total_files": self.files_scanned,
                    "total_folders": self.folders_scanned,
                    "extensions": self.extension_stats,
                    "tree": self.get_tree(max_depth=3)
                }
                return json.dumps(_clean(data), indent=2, ensure_ascii=False)
            elif export_format == "csv":
                lines = ["Path,Type,Size,PhysicalSize,Files,Subdirs,LastModified"]
                def walk_csv(node):
                    t = "Directory" if node.is_dir else "File"
                    m = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(node.mtime)) if node.mtime else ""
                    p = f'"{node.path}"'
                    lines.append(f"{p},{t},{node.size},{node.physical_size},{node.file_count},{node.dir_count},{m}")
                    if node.is_dir and node.children:
                        for c in sorted(node.children, key=lambda x: x.size, reverse=True):
                            walk_csv(c)
                walk_csv(self.root_node)
                return "\n".join(lines)
            return None

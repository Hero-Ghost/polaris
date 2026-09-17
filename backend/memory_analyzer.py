"""
Polaris - Memory Analyzer Engine
Provides low-level and high-level system memory statistics,
kernel memory pool analysis (Paged / Non-Paged), and safe RAM optimization.
"""

import sys
import os
import time
import ctypes
import threading
from ctypes import wintypes
import psutil

from backend.win_utils import format_bytes as _format_bytes

# Structure for Windows Performance Information
class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('cb', wintypes.DWORD),
        ('CommitTotal', ctypes.c_size_t),
        ('CommitLimit', ctypes.c_size_t),
        ('CommitPeak', ctypes.c_size_t),
        ('PhysicalTotal', ctypes.c_size_t),
        ('PhysicalAvailable', ctypes.c_size_t),
        ('SystemCache', ctypes.c_size_t),
        ('KernelTotal', ctypes.c_size_t),
        ('KernelPaged', ctypes.c_size_t),
        ('KernelNonpaged', ctypes.c_size_t),
        ('PageSize', ctypes.c_size_t),
        ('HandleCount', wintypes.DWORD),
        ('ProcessCount', wintypes.DWORD),
        ('ThreadCount', wintypes.DWORD),
    ]

# Structure for GlobalMemoryStatusEx
class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ('dwLength', wintypes.DWORD),
        ('dwMemoryLoad', wintypes.DWORD),
        ('ullTotalPhys', ctypes.c_uint64),
        ('ullAvailPhys', ctypes.c_uint64),
        ('ullTotalPageFile', ctypes.c_uint64),
        ('ullAvailPageFile', ctypes.c_uint64),
        ('ullTotalVirtual', ctypes.c_uint64),
        ('ullAvailVirtual', ctypes.c_uint64),
        ('ullAvailExtendedVirtual', ctypes.c_uint64),
    ]


class MemoryAnalyzer:
    def __init__(self):
        self.is_windows = sys.platform.startswith('win')
        self.history = []
        self.max_history = 120           # Number of samples kept
        self.history_min_interval = 1.0  # Seconds between samples
        self._last_sample_time = 0.0
        self._history_lock = threading.Lock()

    def get_windows_kernel_memory(self):
        """Extract detailed kernel memory pools (Paged / Non-Paged) and System Cache."""
        if not self.is_windows:
            return None

        try:
            perf_info = PERFORMANCE_INFORMATION()
            perf_info.cb = ctypes.sizeof(PERFORMANCE_INFORMATION)
            res = ctypes.windll.psapi.GetPerformanceInfo(
                ctypes.byref(perf_info),
                perf_info.cb
            )
            if not res:
                return None

            page_size = perf_info.PageSize

            return {
                "kernel_total_bytes": perf_info.KernelTotal * page_size,
                "kernel_paged_bytes": perf_info.KernelPaged * page_size,
                "kernel_nonpaged_bytes": perf_info.KernelNonpaged * page_size,
                "system_cache_bytes": perf_info.SystemCache * page_size,
                "commit_total_bytes": perf_info.CommitTotal * page_size,
                "commit_limit_bytes": perf_info.CommitLimit * page_size,
                "commit_peak_bytes": perf_info.CommitPeak * page_size,
                "handles_count": perf_info.HandleCount,
                "processes_count": perf_info.ProcessCount,
                "threads_count": perf_info.ThreadCount,
                "page_size": page_size
            }
        except Exception as e:
            return {"error": str(e)}

    def get_memory_stats(self):
        """Returns comprehensive real-time RAM statistics."""
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        kernel_info = self.get_windows_kernel_memory()

        # Calculation of metrics
        total = vm.total
        available = vm.available
        used = vm.used
        free = vm.free
        percent = vm.percent

        # Cached memory calculation
        cached = getattr(vm, 'cached', 0)
        if cached == 0 and kernel_info and 'system_cache_bytes' in kernel_info:
            cached = kernel_info['system_cache_bytes']

        nonpaged_bytes = 0
        paged_bytes = 0
        if kernel_info and 'kernel_nonpaged_bytes' in kernel_info:
            nonpaged_bytes = kernel_info['kernel_nonpaged_bytes']
            paged_bytes = kernel_info['kernel_paged_bytes']

        timestamp = time.time()
        stat_snapshot = {
            "timestamp": timestamp,
            "total_bytes": total,
            "available_bytes": available,
            "used_bytes": used,
            "free_bytes": free,
            "cached_bytes": cached,
            "percent": percent,
            "used_percent": percent,
            
            # Formatted flat fields for direct access
            "total_formatted": self.format_bytes(total),
            "available_formatted": self.format_bytes(available),
            "used_formatted": self.format_bytes(used),
            "free_formatted": self.format_bytes(free),
            "cached_formatted": self.format_bytes(cached),
            
            # Swap / Pagefile
            "swap_total_bytes": swap.total,
            "swap_used_bytes": swap.used,
            "swap_free_bytes": swap.free,
            "swap_percent": swap.percent,
            "swap_total_formatted": self.format_bytes(swap.total),
            "swap_used_formatted": self.format_bytes(swap.used),
            
            # Kernel Pools
            "kernel_paged_bytes": paged_bytes,
            "kernel_nonpaged_bytes": nonpaged_bytes,
            "kernel_paged_formatted": self.format_bytes(paged_bytes),
            "kernel_nonpaged_formatted": self.format_bytes(nonpaged_bytes),
            "kernel_info": kernel_info,
            
            # Formatted human readable strings dictionary (backwards compatibility)
            "formatted": {
                "total": self.format_bytes(total),
                "available": self.format_bytes(available),
                "used": self.format_bytes(used),
                "free": self.format_bytes(free),
                "cached": self.format_bytes(cached),
                "swap_total": self.format_bytes(swap.total),
                "swap_used": self.format_bytes(swap.used),
                "kernel_paged": self.format_bytes(paged_bytes),
                "kernel_nonpaged": self.format_bytes(nonpaged_bytes)
            }
        }

        # Maintain the history buffer.
        #
        # get_memory_stats() is called by /api/stats, /api/diagnose AND
        # /api/processes, so the timeline used to receive two or three samples
        # per second. The x-axis therefore lied about elapsed time and the
        # "last 60 seconds" window really covered ~20 seconds. Sampling is now
        # rate-limited to one point per second regardless of API traffic.
        with self._history_lock:
            if (timestamp - self._last_sample_time) >= self.history_min_interval:
                self._last_sample_time = timestamp
                self.history.append({
                    "time": time.strftime("%H:%M:%S", time.localtime(timestamp)),
                    "percent": percent,
                    "used_gb": round(used / (1024**3), 2),
                    "available_gb": round(available / (1024**3), 2),
                    "cached_gb": round(cached / (1024**3), 2)
                })
                if len(self.history) > self.max_history:
                    del self.history[:-self.max_history]

        return stat_snapshot

    def get_history(self):
        """Returns recorded time-series memory usage data (a safe copy)."""
        with self._history_lock:
            return list(self.history)

    def _enable_privileges(self):
        """Enable SeDebugPrivilege and quota privileges for memory trimming."""
        if not self.is_windows:
            return False
        try:
            TOKEN_ADJUST_PRIVILEGES = 0x0020
            TOKEN_QUERY = 0x0008
            SE_PRIVILEGE_ENABLED = 0x00000002

            h_process = ctypes.windll.kernel32.GetCurrentProcess()
            h_token = wintypes.HANDLE()
            if not ctypes.windll.advapi32.OpenProcessToken(h_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)):
                return False

            class LUID(ctypes.Structure):
                _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 2)]

            for priv_name in ["SeDebugPrivilege", "SeIncreaseQuotaPrivilege", "SeProfileSingleProcessPrivilege"]:
                luid = LUID()
                if ctypes.windll.advapi32.LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
                    tp = TOKEN_PRIVILEGES()
                    tp.PrivilegeCount = 1
                    tp.Privileges[0].Luid = luid
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
                    ctypes.windll.advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), 0, None, None)

            ctypes.windll.kernel32.CloseHandle(h_token)
            return True
        except Exception:
            return False

    def trim_working_sets(self):
        """
        Safely empties working sets for all accessible processes using EmptyWorkingSet
        and SetProcessWorkingSetSize Win32 APIs. Flushes inactive memory pages to standby list.
        """
        if not self.is_windows:
            return {"success": False, "message": "RAM trimming is only supported on Windows"}

        self._enable_privileges()

        initial_vm = psutil.virtual_memory()
        initial_used = initial_vm.used
        initial_available = initial_vm.available

        success_count = 0
        failed_count = 0

        # Max size_t value for SetProcessWorkingSetSize (-1)
        SIZE_T_MAX = ctypes.c_size_t(-1).value
        my_pid = os.getpid()

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                if pid <= 4 or pid == my_pid:
                    continue
                
                # Try flags in order of modern Windows compatibility
                h_proc = ctypes.windll.kernel32.OpenProcess(0x1000 | 0x0100, False, pid)
                if not h_proc:
                    h_proc = ctypes.windll.kernel32.OpenProcess(0x0400 | 0x0100, False, pid)
                if not h_proc:
                    h_proc = ctypes.windll.kernel32.OpenProcess(0x0100, False, pid)

                if h_proc:
                    ctypes.windll.kernel32.SetProcessWorkingSetSize(h_proc, SIZE_T_MAX, SIZE_T_MAX)
                    res = ctypes.windll.psapi.EmptyWorkingSet(h_proc)
                    ctypes.windll.kernel32.CloseHandle(h_proc)
                    if res:
                        success_count += 1
                    else:
                        failed_count += 1
                else:
                    failed_count += 1
            except Exception:
                failed_count += 1

        # Also trim own process
        try:
            import gc
            gc.collect()
            h_self = ctypes.windll.kernel32.GetCurrentProcess()
            ctypes.windll.kernel32.SetProcessWorkingSetSize(h_self, SIZE_T_MAX, SIZE_T_MAX)
            ctypes.windll.psapi.EmptyWorkingSet(h_self)
        except Exception:
            pass

        time.sleep(0.4)
        after_vm = psutil.virtual_memory()
        after_used = after_vm.used
        after_available = after_vm.available

        freed_bytes = max(0, initial_used - after_used)
        if freed_bytes == 0 and after_available > initial_available:
            freed_bytes = after_available - initial_available

        return {
            "success": True,
            "processes_trimmed": success_count,
            "processes_skipped": failed_count,
            "freed_bytes": freed_bytes,
            "freed_formatted": self.format_bytes(freed_bytes),
            "before_used_percent": initial_vm.percent,
            "after_used_percent": after_vm.percent
        }

    @staticmethod
    def format_bytes(b):
        """Convert bytes to human readable format (KB / MB / GB / TB)."""
        return _format_bytes(b)

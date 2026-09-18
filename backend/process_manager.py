"""
Polaris - Process Manager Engine
High-performance process tree gathering, classification, and safe termination.
"""

import sys
import os
import re
import time
import ctypes
import psutil

from backend.knowledge_base import ProcessKnowledgeBase
from backend.win_utils import run_hidden, format_bytes as _format_bytes

# Kernel-critical processes that must never be terminated.
PROTECTED_PROCESSES = {
    'system idle process', 'system', 'registry', 'memory compression',
    'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'services.exe', 'lsass.exe', 'lsaiso.exe',
}

BROWSER_NAMES = {
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe',
    'vivaldi.exe', 'arc.exe', 'waterfox.exe', 'tor.exe', 'iexplore.exe'
}

DEV_NAMES = {
    'code.exe', 'node.exe', 'python.exe', 'pythonw.exe', 'rustc.exe',
    'dotnet.exe', 'git.exe', 'java.exe', 'javaw.exe', 'docker.exe',
    'wsl.exe', 'wslhost.exe', 'devenv.exe', 'pycharm64.exe', 'idea64.exe'
}

COMMUNICATION_NAMES = {
    'discord.exe', 'slack.exe', 'teams.exe', 'telegram.exe', 'whatsapp.exe',
    'zoom.exe', 'skype.exe', 'signal.exe', 'element.exe', 'viber.exe'
}

SYSTEM_NAMES = {
    'system idle process', 'system', 'registry', 'smss.exe', 'csrss.exe',
    'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'fontdrvhost.exe',
    'winlogon.exe', 'dwm.exe', 'explorer.exe', 'sihost.exe', 'taskhostw.exe',
    'runtimebroker.exe', 'shellexperiencehost.exe', 'searchapp.exe', 'startmenuexperiencehost.exe'
}

BACKGROUND_NAMES = {
    'msmpeng.exe', 'nissrv.exe', 'securityhealthservice.exe', 'smartscreen.exe',
    'searchindexer.exe', 'searchhost.exe', 'tiworker.exe', 'trustedinstaller.exe',
    'onedrive.exe', 'dropbox.exe', 'spoolsv.exe', 'ctfmon.exe', 'compattelrunner.exe'
}

# Windows image names may legitimately contain letters, digits, spaces and a
# handful of punctuation marks. Anything else (quotes, semicolons, pipes,
# backticks, $ ...) would be handed straight to taskkill / PowerShell, so a
# process could be named `x"; Remove-Item C:\ -Recurse; #.exe` to smuggle
# commands into the shell. Such names are rejected outright.
_SAFE_IMAGE_NAME = re.compile(r'^[A-Za-z0-9 ._+\-()\[\]#&@]{1,255}$')


def _is_safe_image_name(name):
    return bool(name) and bool(_SAFE_IMAGE_NAME.match(name))


class ProcessManager:
    def __init__(self):
        self.is_windows = sys.platform.startswith('win')
        self.last_service_map_time = 0
        self.cached_service_map = {}

    def get_service_map(self):
        now = time.time()
        if now - self.last_service_map_time > 5:
            self.cached_service_map = ProcessKnowledgeBase.get_service_map()
            self.last_service_map_time = now
        return self.cached_service_map

    def get_category(self, name_lower):
        if name_lower in BROWSER_NAMES:
            return "Browsers"
        if name_lower in COMMUNICATION_NAMES:
            return "Communication"
        if name_lower in DEV_NAMES:
            return "Development"
        if name_lower in SYSTEM_NAMES:
            return "System"
        if name_lower in BACKGROUND_NAMES:
            return "Background & Services"
        return "User Apps"

    def get_friendly_name(self, name):
        friendly_map = {
            'chrome.exe': 'Google Chrome',
            'msedge.exe': 'Microsoft Edge',
            'firefox.exe': 'Mozilla Firefox',
            'brave.exe': 'Brave Browser',
            'opera.exe': 'Opera Browser',
            'code.exe': 'Visual Studio Code',
            'discord.exe': 'Discord',
            'slack.exe': 'Slack',
            'teams.exe': 'Microsoft Teams',
            'spotify.exe': 'Spotify',
            'explorer.exe': 'Windows Explorer (שולחן העבודה וסייר)',
            'svchost.exe': 'Host Process for Windows Services (svchost)',
            'msmpeng.exe': 'Windows Defender (אנטי-וירוס והגנה בזמן אמת)',
            'nissrv.exe': 'Windows Defender Network Inspection',
            'securityhealthservice.exe': 'מרכז האבטחה של Windows',
            'searchindexer.exe': 'Windows Search Indexer (אינדוקס חיפוש)',
            'dwm.exe': 'Desktop Window Manager (מנהל חלונות גרפי)',
            'system': 'Windows Kernel (ליבת המערכת וזיכרון דחוס)',
            'registry': 'Windows Registry (מאגר הגדרות ב-RAM)',
            'node.exe': 'Node.js Runtime',
            'python.exe': 'Python Process',
            'onedrive.exe': 'Microsoft OneDrive (סנכרון ענן)'
        }
        return friendly_map.get(name.lower(), name)

    def self_trim(self):
        """Forces immediate Python garbage collection and trims own process working set."""
        import gc
        gc.collect()
        if self.is_windows:
            try:
                ctypes.windll.psapi.EmptyWorkingSet(ctypes.windll.kernel32.GetCurrentProcess())
            except Exception:
                pass

    def get_all_processes(self, total_ram_bytes=None):
        """
        Lightweight, high-performance process scanner for real-time polling.
        Excludes heavy per-process IO/explanations to minimize CPU and RAM footprint.
        """
        if total_ram_bytes is None:
            total_ram_bytes = psutil.virtual_memory().total

        service_map = self.get_service_map()
        processes = []

        # Iterate only necessary lightweight attributes
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'num_threads']):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name'] or 'Unknown'
                name_lower = name.lower()

                mem_info = info['memory_info']
                rss = mem_info.rss if mem_info else 0
                vms = mem_info.vms if mem_info else 0

                percent = (rss / total_ram_bytes * 100.0) if total_ram_bytes > 0 else 0.0
                cpu = info['cpu_percent'] or 0.0

                category = self.get_category(name_lower)
                friendly_name = self.get_friendly_name(name)
                svcs = service_map.get(pid, [])

                processes.append({
                    "pid": pid,
                    "name": name,
                    "friendly_name": friendly_name,
                    "rss_bytes": rss,
                    "vms_bytes": vms,
                    "rss_formatted": self.format_bytes(rss),
                    "vms_formatted": self.format_bytes(vms),
                    "memory_percent": round(percent, 2),
                    "cpu_percent": round(cpu, 1),
                    "threads": info['num_threads'] or 1,
                    "category": category,
                    "services": svcs
                })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        return processes

    def get_grouped_processes(self, total_ram_bytes=None):
        flat_list = self.get_all_processes(total_ram_bytes)
        groups = {}

        for p in flat_list:
            key = p['name'].lower()
            if key not in groups:
                groups[key] = {
                    "name": p['name'],
                    "friendly_name": p['friendly_name'],
                    "category": p['category'],
                    "total_rss_bytes": 0,
                    "total_vms_bytes": 0,
                    "total_memory_percent": 0.0,
                    "total_cpu_percent": 0.0,
                    "total_threads": 0,
                    "process_count": 0,
                    "main_pid": p['pid'],
                    "all_services": set(),
                    "children": []
                }

            g = groups[key]
            g["total_rss_bytes"] += p['rss_bytes']
            g["total_vms_bytes"] += p['vms_bytes']
            g["total_memory_percent"] += p['memory_percent']
            g["total_cpu_percent"] += p['cpu_percent']
            g["total_threads"] += p['threads']
            g["process_count"] += 1
            g["children"].append(p)

            for s in p.get('services', []):
                g["all_services"].add(s)

        grouped_list = list(groups.values())

        for g in grouped_list:
            g["total_memory_percent"] = round(g["total_memory_percent"], 2)
            g["total_cpu_percent"] = round(g["total_cpu_percent"], 1)
            g["total_rss_formatted"] = self.format_bytes(g["total_rss_bytes"])
            g["total_vms_formatted"] = self.format_bytes(g["total_vms_bytes"])
            g["all_services"] = list(g["all_services"])
            g["children"].sort(key=lambda x: x["rss_bytes"], reverse=True)

        grouped_list.sort(key=lambda x: x["total_rss_bytes"], reverse=True)
        return grouped_list

    def get_process_details(self, pid, name=None):
        """
        On-demand detailed inspector: Fetches full command line, binary executable path,
        technical specs, and deep knowledge base analysis for a single process.
        """
        exe_path = ""
        cmdline = ""
        cpu = 0.0
        rss = 0
        vms = 0
        threads = 1
        username = ""
        create_time = 0
        proc_name = name or ""

        if pid > 0:
            try:
                p = psutil.Process(pid)
                proc_name = proc_name or p.name()
                try:
                    exe_path = p.exe()
                except Exception:
                    exe_path = ""
                try:
                    cmdline = " ".join(p.cmdline())
                except Exception:
                    cmdline = ""
                try:
                    mem = p.memory_info()
                    rss = mem.rss
                    vms = mem.vms
                except Exception:
                    pass
                try:
                    cpu = p.cpu_percent()
                except Exception:
                    pass
                try:
                    threads = p.num_threads()
                except Exception:
                    pass
                try:
                    username = p.username()
                except Exception:
                    pass
                try:
                    create_time = p.create_time()
                except Exception:
                    pass
            except Exception:
                pass

        proc_name = proc_name or (f"PID {pid}" if pid > 0 else "Unknown")
        service_map = self.get_service_map()
        svcs = service_map.get(pid, [])
        category = self.get_category(proc_name.lower())
        friendly_name = self.get_friendly_name(proc_name)
        explanation = ProcessKnowledgeBase.explain_process(proc_name, pid, exe_path, svcs)

        vm = psutil.virtual_memory()
        total_ram = vm.total
        percent = (rss / total_ram * 100.0) if total_ram > 0 else 0.0

        return {
            "pid": pid,
            "name": proc_name,
            "friendly_name": friendly_name,
            "category": category,
            "exe_path": exe_path,
            "cmdline": cmdline,
            "rss_bytes": rss,
            "vms_bytes": vms,
            "rss_formatted": self.format_bytes(rss),
            "vms_formatted": self.format_bytes(vms),
            "memory_percent": round(percent, 2),
            "cpu_percent": round(cpu, 1),
            "threads": threads,
            "username": username,
            "create_time": create_time,
            "services": svcs,
            "explanation": explanation
        }

    def kill_process(self, pid):
        """
        Forcefully terminates a single process and all its child subprocess tree.
        Uses Windows taskkill /F /T /PID and psutil force kill.
        """
        if pid <= 4:
            return {"success": False, "message": "לא ניתן לסגור תהליכי ליבה קריטיים של מערכת ההפעלה (System / Idle)."}

        if pid == os.getpid():
            return {"success": False, "message": "לא ניתן לסגור את Polaris מתוך עצמו."}

        proc_name = f"PID {pid}"
        try:
            p = psutil.Process(pid)
            proc_name = p.name()
        except Exception:
            pass

        # Refuse kernel-critical processes by name too - a PID above 4 can still
        # be csrss.exe / lsass.exe, and killing those hard-crashes Windows.
        if proc_name.lower() in PROTECTED_PROCESSES:
            return {
                "success": False,
                "message": f"סגירת {proc_name} חסומה: זהו תהליך מערכת קריטי שסגירתו תפיל את Windows."
            }

        # 1. Try Windows native forceful tree kill (taskkill /F /T /PID)
        if self.is_windows:
            try:
                res = run_hidden(
                    ['taskkill', '/F', '/T', '/PID', str(pid)],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False
                )
                if res.returncode == 0 or "SUCCESS" in res.stdout or "הצלחה" in res.stdout:
                    return {
                        "success": True,
                        "message": f"התהליך {proc_name} (PID: {pid}) וכל תהליכי הבן שלו חוסלו בהצלחה."
                    }
            except Exception:
                pass

        # 2. PowerShell Stop-Process
        if self.is_windows:
            try:
                run_hidden(
                    ['powershell', '-NoProfile', '-Command', f'Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue'],
                    capture_output=True,
                    timeout=3,
                    check=False
                )
            except Exception:
                pass

        # 3. Python psutil recursive kill
        try:
            p = psutil.Process(pid)
            for child in p.children(recursive=True):
                try:
                    child.kill()
                except Exception:
                    pass
            p.kill()
            time.sleep(0.15)
            return {
                "success": True,
                "message": f"התהליך {proc_name} (PID: {pid}) נסגר בהצלחה."
            }
        except psutil.NoSuchProcess:
            return {"success": True, "message": f"התהליך {pid} כבר אינו פועל."}
        except psutil.AccessDenied:
            return {
                "success": False,
                "message": f"גישה נדחתה: התהליך {proc_name} מוגן על ידי Windows או דורש הרשאות מנהל (Administrator)."
            }
        except Exception as e:
            return {"success": False, "message": str(e)}

    def kill_group(self, name):
        """
        Forcefully terminates all instances of an application group (e.g. all chrome.exe, all msedge.exe).
        Uses taskkill /F /IM <name> and PowerShell Stop-Process for instant complete elimination.
        """
        name_clean = os.path.basename(name).strip()

        if not _is_safe_image_name(name_clean):
            return {
                "success": False,
                "message": "שם התהליך אינו חוקי (נמצאו תווים אסורים) והפעולה בוטלה."
            }

        if name_clean.lower() in PROTECTED_PROCESSES:
            return {
                "success": False,
                "message": f"סגירת {name_clean} חסומה: זהו תהליך מערכת קריטי שסגירתו תפיל את Windows."
            }

        exe_name = name_clean if name_clean.lower().endswith('.exe') else f"{name_clean}.exe"
        base_name = name_clean[:-4] if name_clean.lower().endswith('.exe') else name_clean

        # 1. Primary method: Windows taskkill /F /T /IM <name>
        if self.is_windows:
            try:
                res = run_hidden(
                    ['taskkill', '/F', '/T', '/IM', exe_name],
                    capture_output=True,
                    text=True,
                    timeout=4,
                    check=False
                )
                if res.returncode == 0 or "SUCCESS" in res.stdout or "הצלחה" in res.stdout:
                    return {
                        "success": True,
                        "message": f"כל התהליכים של {exe_name} חוסלו ונסגרו בהצלחה.",
                        "terminated_count": 1
                    }
            except Exception:
                pass

            # Also try without extension
            try:
                run_hidden(
                    ['taskkill', '/F', '/T', '/IM', name_clean],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False
                )
            except Exception:
                pass

        # 2. PowerShell Stop-Process by name
        if self.is_windows:
            try:
                run_hidden(
                    ['powershell', '-NoProfile', '-Command', f'Get-Process -Name "{base_name}" -ErrorAction SilentlyContinue | Stop-Process -Force'],
                    capture_output=True,
                    timeout=4,
                    check=False
                )
            except Exception:
                pass

        # 3. Backup method: psutil iteration force kill.
        # Matching is EXACT. The previous `pname.startswith(base_name)` test also
        # killed unrelated executables - e.g. closing "code.exe" wiped out
        # "codemeter.exe", and closing "node.exe" hit "nodeagent.exe".
        terminated = 0
        failed = 0
        match_targets = {name_clean.lower(), exe_name.lower(), base_name.lower()}
        my_pid = os.getpid()

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pname = (proc.info['name'] or '').lower()
                if pname in match_targets and proc.info['pid'] != my_pid:
                    proc.kill()
                    terminated += 1
            except Exception:
                failed += 1

        if terminated > 0:
            return {
                "success": True,
                "message": f"נסגרו בהצלחה {terminated} תהליכים של {exe_name}.",
                "terminated_count": terminated
            }
        else:
            return {
                "success": True,
                "message": f"הפקודה לסגירת {exe_name} נשלחה לכל תהליכי המערכת."
            }

    def trim_process(self, pid):
        if not self.is_windows:
            return {"success": False, "message": "Only supported on Windows"}

        try:
            # Max size_t value for SetProcessWorkingSetSize (-1)
            SIZE_T_MAX = ctypes.c_size_t(-1).value
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
                    return {"success": True, "message": f"זיכרון העבודה של תהליך {pid} שוחרר בהצלחה."}
            return {"success": False, "message": f"לא ניתן היה לשחרר זיכרון לתהליך {pid} (דורש הרשאות)."}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def trim_group(self, name):
        if not self.is_windows:
            return {"success": False, "message": "Only supported on Windows"}
        
        name_clean = os.path.basename(name).lower().strip()
        if not _is_safe_image_name(name_clean):
            return {"success": False, "message": "שם התהליך אינו חוקי והפעולה בוטלה."}

        base_name = name_clean[:-4] if name_clean.endswith('.exe') else name_clean
        exe_name = f"{base_name}.exe"

        trimmed_count = 0
        total_freed = 0
        SIZE_T_MAX = ctypes.c_size_t(-1).value

        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                pname = (proc.info['name'] or '').lower()
                # Exact match only - see the note in kill_group().
                if pname == exe_name or pname == name_clean:
                    pid = proc.info['pid']
                    before_mem = proc.info['memory_info'].rss if proc.info.get('memory_info') else 0
                    h_proc = ctypes.windll.kernel32.OpenProcess(0x1000 | 0x0100, False, pid)
                    if not h_proc:
                        h_proc = ctypes.windll.kernel32.OpenProcess(0x0400 | 0x0100, False, pid)
                    if h_proc:
                        ctypes.windll.kernel32.SetProcessWorkingSetSize(h_proc, SIZE_T_MAX, SIZE_T_MAX)
                        res = ctypes.windll.psapi.EmptyWorkingSet(h_proc)
                        ctypes.windll.kernel32.CloseHandle(h_proc)
                        if res:
                            trimmed_count += 1
                            try:
                                after_mem = proc.memory_info().rss
                                if before_mem > after_mem:
                                    total_freed += (before_mem - after_mem)
                            except Exception:
                                pass
            except Exception:
                continue

        freed_str = self.format_bytes(total_freed) if total_freed > 0 else ""
        if trimmed_count > 0:
            msg = f"שוחרר זיכרון עבור {trimmed_count} תהליכים של {name}" + (f" (נחסכו ~{freed_str})" if freed_str else ".")
            return {"success": True, "message": msg, "trimmed_count": trimmed_count, "freed_bytes": total_freed}
        return {"success": True, "message": f"זיכרון העבודה של {name} כבר ממוטב."}

    @staticmethod
    def format_bytes(b):
        return _format_bytes(b)

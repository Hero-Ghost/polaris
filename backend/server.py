"""
Polaris - HTTP Server & REST API
Lightweight, zero-dependency, high-performance embedded server with App-Window Mode.
"""

import sys
import os
import json
import socket
import secrets
import platform
import mimetypes
import threading
import traceback
from urllib.parse import urlparse, parse_qs, unquote
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

from backend.win_utils import popen_hidden, is_admin, open_keyboard_settings

# Determine base paths (supports standard Python run and PyInstaller bundle)
if getattr(sys, 'frozen', False):
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass and os.path.exists(os.path.join(meipass, 'frontend')) and not os.environ.get('POLARIS_DEV'):
        BASE_DIR = meipass
        FRONTEND_DIR = os.path.join(meipass, 'frontend')
    else:
        exe_dir = os.path.dirname(sys.executable)
        local_frontend = os.path.join(exe_dir, 'frontend')
        if os.path.exists(local_frontend):
            FRONTEND_DIR = local_frontend
            BASE_DIR = exe_dir
        else:
            BASE_DIR = meipass or exe_dir
            FRONTEND_DIR = os.path.join(BASE_DIR, 'frontend')
else:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    FRONTEND_DIR = os.path.join(BASE_DIR, 'frontend')

from backend.memory_analyzer import MemoryAnalyzer
from backend.process_manager import ProcessManager
from backend.diagnostic_engine import DiagnosticEngine
from backend.knowledge_base import SERVICE_KNOWLEDGE
from backend.system_revitalizer import SystemRevitalizer
from backend.crash_analyzer import CrashAnalyzer
from backend.disk_health import DiskHealthAnalyzer
from backend.device_manager import DeviceManager
from backend.event_log import EventLogAnalyzer
from backend.battery_analyzer import BatteryAnalyzer
from backend.uninstaller_engine import UninstallerEngine
from backend.storage_analyzer import StorageAnalyzer
from backend.oem_update_manager import OemUpdateManager
from backend.windows_update_manager import WindowsUpdateManager
from backend.copilot_remapper import (
    get_copilot_remap_status,
    enable_copilot_remap,
    disable_copilot_remap
)
from backend.onedrive_manager import (
    get_onedrive_status,
    reset_onedrive,
    launch_onedrive
)
from backend.icon_cache_manager import (
    get_icon_cache_stats,
    rebuild_icon_cache
)
from backend.enterprise_it_manager import (
    get_enterprise_tools_list,
    execute_enterprise_tool
)
from backend.remote_control_manager import (
    RemoteControlManager,
    APP_VERSION
)

analyzer = MemoryAnalyzer()
process_mgr = ProcessManager()
diagnostics = DiagnosticEngine()
revitalizer = SystemRevitalizer()
crash_analyzer = CrashAnalyzer()
disk_health = DiskHealthAnalyzer()
device_mgr = DeviceManager()
event_log = EventLogAnalyzer()
battery_analyzer = BatteryAnalyzer()
uninstaller_engine = UninstallerEngine()
storage_analyzer = StorageAnalyzer()
oem_mgr = OemUpdateManager()
wu_mgr = WindowsUpdateManager()
remote_control = RemoteControlManager(current_version=APP_VERSION)

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------
# Polaris exposes powerful endpoints (kill a process, run DISM/SFC, reset the
# network stack). Previously the API answered every caller with
# "Access-Control-Allow-Origin: *", which meant ANY website the user happened to
# be browsing could silently POST to http://127.0.0.1:<port>/api/kill.
#
# Three independent layers now protect it:
#   1. The socket only listens on the loopback interface.
#   2. The Host header must be loopback  -> blocks DNS-rebinding attacks.
#   3. Every /api/ call must carry the per-run secret token that is injected
#      into index.html at serve time -> a cross-origin page can never read it
#      because no CORS headers are emitted at all.
SESSION_TOKEN = secrets.token_urlsafe(24)
SERVER_PORT = None

ALLOWED_HOSTNAMES = {'127.0.0.1', 'localhost', '[::1]', '::1'}

# Static assets that may be served without a token (the browser cannot attach
# custom headers to <link>/<script>/<img> requests).
STATIC_FILES = {
    '/': ('index.html', 'text/html; charset=utf-8'),
    '/index.html': ('index.html', 'text/html; charset=utf-8'),
    '/styles.css': ('styles.css', 'text/css; charset=utf-8'),
    '/app.js': ('app.js', 'application/javascript; charset=utf-8'),
    '/logo.png': ('logo.png', 'image/png'),
    '/favicon.ico': ('favicon.ico', 'image/x-icon'),
}


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class PolarisHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        pass

    # -- security helpers ---------------------------------------------------

    def _host_is_loopback(self):
        host = (self.headers.get('Host') or '').strip()
        if not host:
            return False
        hostname = host.rsplit(':', 1)[0] if ':' in host and not host.endswith(']') else host
        return hostname.lower() in ALLOWED_HOSTNAMES

    def _origin_is_local(self):
        origin = self.headers.get('Origin')
        if not origin or origin == 'null':
            # Same-origin GETs and the embedded WebView send no Origin header.
            return True
        try:
            netloc = urlparse(origin).hostname or ''
        except Exception:
            return False
        return netloc.lower() in ALLOWED_HOSTNAMES

    def _token_is_valid(self):
        supplied = self.headers.get('X-Polaris-Token') or ''
        return secrets.compare_digest(supplied, SESSION_TOKEN)

    def _reject(self, code=403, reason="Forbidden"):
        body = json.dumps({"success": False, "message": reason}).encode('utf-8')
        self._responded = True
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        # When the request body was never drained, the client must be told not
        # to pipeline the next request into a socket we are about to drop.
        if getattr(self, 'close_connection', False):
            self.send_header('Connection', 'close')
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _guard(self, path):
        """Returns True when the request may proceed."""
        # A rejected request's body is never read, so the connection has to
        # close: the unread bytes would otherwise be parsed as the next request
        # on this keep-alive socket.
        def refuse(reason):
            if self.command in ('POST', 'PUT', 'PATCH'):
                self.close_connection = True
            self._reject(403, reason)
            return False

        if not self._host_is_loopback():
            return refuse("Invalid Host header - Polaris only serves 127.0.0.1.")
        if not self._origin_is_local():
            return refuse("Cross-origin requests are not permitted.")
        if path == '/api/exit':
            return True
        if path.startswith('/api/'):
            if not self._token_is_valid():
                return refuse("Missing or invalid session token.")
            if remote_control.is_app_killed():
                # Allow status retrieval and exit endpoints even when killed, reject all other /api/ calls
                if path not in ('/api/remote_control/status', '/api/exit'):
                    return refuse("התוכנה הושבתה מרחוק על ידי המפתח.")
        return True

    def send_json_response(self, data, status_code=200):
        # Serialize BEFORE the try: a payload that cannot be encoded has to
        # reach the error handler, not vanish into `except: pass` and leave the
        # client waiting on a connection that will never answer.
        body = json.dumps(data).encode('utf-8')
        self._responded = True
        try:
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            # A half-written body must not be followed by another request on
            # the same keep-alive socket.
            self.close_connection = True

    def do_OPTIONS(self):
        # No CORS preflight is ever approved - the UI is same-origin. The body
        # is not drained, so the connection closes with the refusal.
        self.close_connection = True
        self._reject(403, "Cross-origin requests are not permitted.")

    def _answer_error(self, exc):
        """
        An unhandled error still has to come back as JSON.

        Without this the socket is simply closed, the browser reports a generic
        network failure, and the real reason never reaches the user.

        The detail goes to the console, not to the response: a static path is
        not token-gated, and exception text routinely carries absolute paths.
        """
        traceback.print_exc()
        if getattr(self, '_responded', False):
            # A response is already on the wire; a second status line would
            # desynchronise the keep-alive connection.
            self.close_connection = True
            return
        try:
            self.send_json_response(
                {"success": False, "error": "שגיאה פנימית בשרת. הפרטים נרשמו ביומן."},
                status_code=500
            )
        except Exception:
            self.close_connection = True

    def do_GET(self):
        self._responded = False
        try:
            self._dispatch_get()
        except Exception as exc:
            self._answer_error(exc)

    def do_POST(self):
        self._responded = False
        try:
            self._dispatch_post()
        except Exception as exc:
            self._answer_error(exc)

    def _dispatch_get(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if not self._guard(path):
            return

        # Static file routing
        if path in STATIC_FILES:
            filename, content_type = STATIC_FILES[path]
            self.serve_file(os.path.join(FRONTEND_DIR, filename), content_type)
            return

        if path.startswith('/vendor/'):
            self.serve_vendor_file(path)
            return

        # API Endpoints
        if path == '/api/stats':
            stats = analyzer.get_memory_stats()
            history = analyzer.get_history()
            self.send_json_response({
                "stats": stats,
                "history": history
            })
            return

        elif path == '/api/diagnose':
            stats = analyzer.get_memory_stats()
            grouped = process_mgr.get_grouped_processes(stats.get('total_bytes'))
            diag_result = diagnostics.diagnose(stats, grouped)
            self.send_json_response({
                "diagnostics": diag_result,
                "stats": stats
            })
            return

        elif path == '/api/processes':
            is_grouped = query.get('grouped', ['true'])[0].lower() == 'true'
            search_term = query.get('search', [''])[0].lower()
            category = query.get('category', ['All'])[0]
            stats = analyzer.get_memory_stats()
            total_ram = stats.get('total_bytes')

            if is_grouped:
                procs = process_mgr.get_grouped_processes(total_ram)
                if search_term:
                    procs = [p for p in procs if search_term in p['name'].lower() or search_term in p['friendly_name'].lower() or any(search_term in s.lower() for s in p.get('all_services', []))]
                if category != 'All':
                    procs = [p for p in procs if p['category'] == category]
            else:
                procs = process_mgr.get_all_processes(total_ram)
                if search_term:
                    procs = [p for p in procs if search_term in p['name'].lower() or search_term in p['friendly_name'].lower() or search_term in str(p['pid']) or any(search_term in s.lower() for s in p.get('services', []))]
                if category != 'All':
                    procs = [p for p in procs if p['category'] == category]
                procs.sort(key=lambda x: x['rss_bytes'], reverse=True)

            self.send_json_response({
                "processes": procs,
                "count": len(procs),
                "is_grouped": is_grouped
            })
            return

        elif path == '/api/explain' or path == '/api/process_details':
            name = query.get('name', [''])[0]
            pid_str = query.get('pid', ['0'])[0]
            pid = int(pid_str) if pid_str.isdigit() else 0
            details = process_mgr.get_process_details(pid, name)
            self.send_json_response(details)
            return

        elif path == '/api/services':
            stats = analyzer.get_memory_stats()
            procs = process_mgr.get_all_processes(stats.get('total_bytes'))
            
            services_data = []
            for p in procs:
                if p.get('services'):
                    for s in p['services']:
                        s_info = SERVICE_KNOWLEDGE.get(s.lower(), {
                            "title_he": f"שירות Windows ({s})",
                            "desc_he": "שירות מערכת הפועל ברקע."
                        })
                        services_data.append({
                            "service_name": s,
                            "title_he": s_info["title_he"],
                            "desc_he": s_info["desc_he"],
                            "host_pid": p['pid'],
                            "host_process": p['name'],
                            "memory_formatted": p['rss_formatted'],
                            "memory_percent": p['memory_percent']
                        })

            self.send_json_response({
                "services": services_data,
                "count": len(services_data)
            })
            return

        elif path == '/api/revitalize/audit' or path == '/api/audit':
            audit_data = revitalizer.audit_system()
            self.send_json_response(audit_data)
            return

        elif path == '/api/revitalize/progress':
            # `since` lets the UI poll fast without re-downloading the whole
            # log buffer on every tick.
            try:
                since = int(query.get('since', ['0'])[0])
            except (TypeError, ValueError):
                since = 0
            prog = revitalizer.get_progress(since_log_id=since)
            self.send_json_response(prog)
            return

        elif path == '/api/startup/apps' or path == '/api/startup_apps':
            apps = revitalizer.get_startup_apps()
            self.send_json_response({"apps": apps, "count": len(apps)})
            return

        elif path == '/api/crashes':
            crash_data = crash_analyzer.get_crash_history()

            # Translate the driver each crash blames into something a user can
            # act on ("rt640x64.sys" -> "Realtek wired network adapter").
            for crash in crash_data.get('crashes', []):
                driver_file = crash.get('responsible_driver')
                if driver_file:
                    dev_info = device_mgr.identify_driver(driver_file)
                    if not crash.get('driver_info'):
                        crash['driver_info'] = dev_info
                    elif dev_info and dev_info.get('installed'):
                        crash['driver_info']['installed'] = dev_info['installed']

            self.send_json_response(crash_data)
            return

        elif path == '/api/disks':
            self.send_json_response(disk_health.get_report())
            return

        elif path == '/api/devices':
            self.send_json_response(device_mgr.get_report())
            return

        elif path == '/api/oem/info' or path == '/api/oem_updates/info':
            mfr_override = query.get('vendor', [None])[0] or query.get('manufacturer', [None])[0]
            self.send_json_response(oem_mgr.get_oem_info(override_manufacturer=mfr_override))
            return

        elif path == '/api/oem/progress' or path == '/api/oem_updates/progress':
            try:
                since = int(query.get('since', ['0'])[0])
            except (TypeError, ValueError):
                since = 0
            self.send_json_response(oem_mgr.get_progress(since_log_id=since))
            return

        elif path == '/api/events':
            try:
                days = int(query.get('days', ['7'])[0])
            except (TypeError, ValueError):
                days = 7
            days = max(1, min(days, 30))
            self.send_json_response(event_log.get_report(days))
            return

        elif path == '/api/system_info':
            self.send_json_response(get_system_info())
            return

        elif path == '/api/copilot_remap/status':
            self.send_json_response(get_copilot_remap_status())
            return

        elif path == '/api/onedrive/status':
            self.send_json_response(get_onedrive_status())
            return

        elif path == '/api/icon_cache/status':
            self.send_json_response(get_icon_cache_stats())
            return

        elif path == '/api/enterprise_tools/list':
            self.send_json_response({"tools": get_enterprise_tools_list()})
            return

        elif path == '/api/battery':
            force = query.get('force', ['false'])[0].lower() == 'true'
            self.send_json_response(battery_analyzer.get_report(force=force))
            return

        elif path == '/api/windows_updates/list':
            # online=1 triggers a full scan against Microsoft's servers (slow)
            # online=0 (default) uses the local WU cache (fast, no network)
            online = query.get('online', ['0'])[0].strip() in ('1', 'true')
            self.send_json_response(wu_mgr.get_updates(online=online))
            return

        elif path == '/api/windows_updates/hidden':
            self.send_json_response(wu_mgr.get_hidden_updates())
            return

        elif path == '/api/windows_updates/service_status':
            self.send_json_response(wu_mgr.get_service_status())
            return


        elif path == '/api/uninstaller/apps':
            # The uninstaller screen sends force=1, not force=true, so a strict
            # == 'true' silently re-served the 5-minute cache and left removed
            # programs on the list.
            force = query.get('force', ['false'])[0].strip().lower() in ('1', 'true', 'yes')
            include_uwp = query.get('uwp', ['true'])[0].strip().lower() in ('1', 'true', 'yes')
            apps = uninstaller_engine.get_installed_apps(force_refresh=force, include_uwp=include_uwp)
            self.send_json_response({"apps": apps, "count": len(apps)})
            return

        elif path == '/api/uninstaller/status':
            # `since` is the log revision the client already drew; the engine
            # returns only newer rows and in-place edits.
            since = query.get('since', ['0'])[0]
            self.send_json_response(uninstaller_engine.get_session_status(since_log_id=since))
            return

        elif path == '/api/uninstaller/backups':
            self.send_json_response({"backups": uninstaller_engine.get_backup_history()})
            return

        elif path == '/api/storage/drives':
            self.send_json_response({"drives": storage_analyzer.get_drives()})
            return

        elif path == '/api/storage/progress':
            self.send_json_response(storage_analyzer.get_progress())
            return

        elif path == '/api/storage/tree':
            node_id_str = query.get('node_id', [None])[0]
            node_id = int(node_id_str) if node_id_str and node_id_str.isdigit() else None
            try:
                depth = int(query.get('depth', ['1'])[0])
            except (ValueError, TypeError):
                depth = 1
            tree_data = storage_analyzer.get_tree(node_id=node_id, max_depth=depth)
            self.send_json_response({"tree": tree_data})
            return

        elif path == '/api/storage/treemap':
            node_id_str = query.get('node_id', [None])[0]
            node_id = int(node_id_str) if node_id_str and node_id_str.isdigit() else None
            try:
                depth = int(query.get('depth', ['10'])[0])
            except (ValueError, TypeError):
                depth = 10
            treemap_data = storage_analyzer.get_treemap_data(node_id=node_id, max_depth=depth)
            self.send_json_response({"treemap": treemap_data})
            return

        elif path == '/api/storage/sunburst':
            node_id_str = query.get('node_id', [None])[0]
            node_id = int(node_id_str) if node_id_str and node_id_str.isdigit() else None
            try:
                depth = int(query.get('depth', ['4'])[0])
            except (ValueError, TypeError):
                depth = 4
            sunburst_data = storage_analyzer.get_sunburst_data(node_id=node_id, max_depth=depth)
            self.send_json_response({"sunburst": sunburst_data})
            return

        elif path == '/api/storage/extensions':
            exts = storage_analyzer.get_extensions_summary()
            self.send_json_response({"extensions": exts, "count": len(exts)})
            return

        elif path == '/api/storage/top_files':
            try:
                limit = int(query.get('limit', ['100'])[0])
            except (ValueError, TypeError):
                limit = 100
            files = storage_analyzer.get_top_files(limit=limit)
            self.send_json_response({"files": files, "count": len(files)})
            return

        elif path == '/api/storage/duplicates':
            try:
                min_size = float(query.get('min_size_mb', ['10'])[0])
            except (ValueError, TypeError):
                min_size = 10.0
            dupes = storage_analyzer.find_duplicates(min_size_mb=min_size)
            self.send_json_response({"duplicates": dupes, "count": len(dupes)})
            return

        elif path == '/api/storage/export':
            fmt = query.get('format', ['json'])[0]
            report = storage_analyzer.export_report(export_format=fmt)
            if fmt == 'csv':
                body = (report or "").encode('utf-8')
                self._responded = True
                self.send_response(200)
                self.send_header('Content-Type', 'text/csv; charset=utf-8')
                self.send_header('Content-Disposition', 'attachment; filename="windirstat_scan.csv"')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            else:
                self.send_json_response({"report": report})
                return

        elif path == '/api/remote_control/status':
            force = query.get('force', ['false'])[0].lower() == 'true'
            status = remote_control.check_remote_control(force=force)
            self.send_json_response(status)
            return

        elif path == '/api/remote_control/update_progress':
            status = remote_control.get_status()
            self.send_json_response(status.get('download_state', {}))
            return

        elif path == '/api/exit':
            self.send_json_response({"success": True, "message": "סוגר את Polaris..."})
            def _delayed_exit_get():
                time.sleep(0.15)
                os._exit(0)
            threading.Thread(target=_delayed_exit_get, daemon=True).start()
            return

        self._reject(404, "Not found")

    def _dispatch_post(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if not self._guard(path):
            return

        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except (TypeError, ValueError):
            # A header we cannot parse means we do not know where the body
            # ends, so this connection cannot be reused.
            content_length = 0
            self.close_connection = True

        # Refuse absurd bodies outright. The body is never read, so the
        # connection has to close - otherwise the unread bytes would be parsed
        # as the next request on this keep-alive socket.
        if content_length > 1_000_000:
            self.close_connection = True
            self._reject(413, "Request body too large")
            return

        post_data = {}
        if content_length > 0:
            try:
                body = self.rfile.read(content_length)
                post_data = json.loads(body.decode('utf-8'))
            except Exception:
                post_data = {}

        if path == '/api/optimize':
            res = analyzer.trim_working_sets()
            self.send_json_response(res)
            return

        elif path == '/api/revitalize/start' or path == '/api/revitalize/run':
            res = revitalizer.start_revitalization_async(post_data.get('options'))
            self.send_json_response(res)
            return

        elif path == '/api/oem/start' or path == '/api/oem_updates/start':
            mfr = post_data.get('manufacturer')
            opts = post_data.get('options')
            res = oem_mgr.start_oem_updates_async(mfr, opts)
            self.send_json_response(res)
            return

        elif path == '/api/oem/cancel' or path == '/api/oem_updates/cancel':
            res = oem_mgr.cancel_updates()
            self.send_json_response(res)
            return

        elif path == '/api/memory_diagnostic':
            res = crash_analyzer.trigger_memory_diagnostic()
            self.send_json_response(res)
            return

        elif path == '/api/crashes/analyze_dump' or path == '/api/crash_analyze_file':
            file_path = post_data.get('file_path')
            if not file_path:
                self.send_json_response({"success": False, "error": "Missing file_path parameter"})
                return
            res = crash_analyzer.analyze_custom_dump(file_path)
            self.send_json_response(res)
            return

        elif path == '/api/crashes/online_lookup':
            driver_name = post_data.get('driver_name', '')
            bugcheck_code = post_data.get('bugcheck_code')
            res = crash_analyzer.lookup_driver_online(driver_name, bugcheck_code)
            self.send_json_response(res)
            return

        elif path == '/api/crashes/list_dumps':
            minidump_dir = os.path.expandvars(r"%SystemRoot%\Minidump")
            found_files = []
            if os.path.exists(minidump_dir):
                import glob
                for f in glob.glob(os.path.join(minidump_dir, "*.dmp")):
                    try:
                        st = os.stat(f)
                        found_files.append({
                            "name": os.path.basename(f),
                            "path": f,
                            "size_kb": round(st.st_size / 1024, 1),
                            "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        })
                    except Exception:
                        pass
            self.send_json_response({"success": True, "files": found_files})
            return

        elif path == '/api/kill':
            pid = _coerce_pid(post_data.get('pid'))
            group_name = post_data.get('group_name')
            if pid is not None:
                res = process_mgr.kill_process(pid)
            elif group_name:
                res = process_mgr.kill_group(str(group_name))
            else:
                res = {"success": False, "message": "Missing or invalid pid / group_name parameter"}
            self.send_json_response(res)
            return

        elif path == '/api/trim_process':
            pid = _coerce_pid(post_data.get('pid'))
            if pid is not None:
                res = process_mgr.trim_process(pid)
            else:
                res = {"success": False, "message": "Missing or invalid pid"}
            self.send_json_response(res)
            return

        elif path == '/api/trim_group':
            name = post_data.get('name')
            if name:
                res = process_mgr.trim_group(str(name))
            else:
                res = {"success": False, "message": "Missing group name"}
            self.send_json_response(res)
            return

        elif path == '/api/open_keyboard_settings' or path == '/api/tools/copilot_key':
            res = open_keyboard_settings()
            self.send_json_response(res)
            return

        elif path == '/api/copilot_remap/enable':
            res = enable_copilot_remap()
            self.send_json_response(res)
            return

        elif path == '/api/copilot_remap/disable':
            res = disable_copilot_remap()
            self.send_json_response(res)
            return

        elif path == '/api/onedrive/reset':
            relaunch = bool(post_data.get('relaunch', False))
            clean_cache = bool(post_data.get('clean_cache', True))
            res = reset_onedrive(relaunch=relaunch, clean_cache=clean_cache)
            self.send_json_response(res)
            return

        elif path == '/api/onedrive/launch':
            res = launch_onedrive()
            self.send_json_response(res)
            return

        elif path == '/api/icon_cache/rebuild':
            res = rebuild_icon_cache()
            self.send_json_response(res)
            return

        elif path == '/api/enterprise_tools/run':
            tool_id = post_data.get('tool_id')
            if tool_id:
                res = execute_enterprise_tool(str(tool_id))
            else:
                res = {"success": False, "message": "Missing tool_id parameter"}
            self.send_json_response(res)
            return

        elif path == '/api/uninstaller/start':
            app_id = post_data.get('app_id')
            skip_rp = bool(post_data.get('skip_restore_point', False))
            skip_reg = bool(post_data.get('skip_registry_backup', False))
            scan_mode = post_data.get('scan_mode', 'moderate')
            res = uninstaller_engine.start_uninstall_session(
                app_id,
                skip_restore_point=skip_rp,
                skip_registry_backup=skip_reg,
                scan_mode=scan_mode
            )
            self.send_json_response(res)
            return

        elif path == '/api/uninstaller/skip':
            res = uninstaller_engine.skip_current_step()
            self.send_json_response(res)
            return

        elif path == '/api/uninstaller/scan':
            # Takes an app_id, never client-supplied metadata: the install
            # location ends up in the scan results as a deletable item, so
            # accepting it from the request would hand the client a way to name
            # a path after all. The engine claims itself for the duration.
            res = uninstaller_engine.run_standalone_scan(
                post_data.get('app_id'),
                mode=post_data.get('mode', 'moderate')
            )
            self.send_json_response(res)
            return

        elif path == '/api/uninstaller/delete':
            # Only opaque ids are honoured: the engine resolves them against its
            # own scan results, so a crafted request cannot name a path.
            selected_ids = post_data.get('selected_ids')
            selected_items = post_data.get('selected_items')
            res = uninstaller_engine.delete_leftovers(
                selected_ids=selected_ids,
                selected_items=selected_items
            )
            self.send_json_response(res)
            return

        elif path == '/api/uninstaller/forced':
            target = post_data.get('target', '')
            mode = post_data.get('mode', 'moderate')
            res = uninstaller_engine.run_forced_uninstall(target, mode=mode)
            self.send_json_response(res)
            return

        elif path == '/api/uninstaller/batch':
            app_ids = post_data.get('app_ids', [])
            mode = post_data.get('mode', 'moderate')
            skip_rp = bool(post_data.get('skip_restore_point', False))
            res = uninstaller_engine.run_batch_uninstall(app_ids, mode=mode, skip_restore_point=skip_rp)
            self.send_json_response(res)
            return

        elif path == '/api/uninstaller/hunter_resolve':
            target = post_data.get('target', '')
            res = uninstaller_engine.resolve_hunter_target(target)
            self.send_json_response(res)
            return

        elif path == '/api/uninstaller/hunter_action':
            action = post_data.get('action')
            target_path = post_data.get('target_path')
            pid = post_data.get('pid')
            res = uninstaller_engine.execute_hunter_action(action, target_path, pid=pid)
            self.send_json_response(res)
            return

        elif path == '/api/uninstaller/restore':
            session_id = post_data.get('session_id')
            res = uninstaller_engine.restore_backup(session_id)
            self.send_json_response(res)
            return

        elif path == '/api/storage/scan':
            targets = post_data.get('targets', [])
            success, message = storage_analyzer.start_scan(targets)
            self.send_json_response({"success": success, "message": message})
            return

        elif path == '/api/storage/pause':
            ok = storage_analyzer.pause_scan()
            self.send_json_response({"success": ok})
            return

        elif path == '/api/storage/resume':
            ok = storage_analyzer.resume_scan()
            self.send_json_response({"success": ok})
            return

        elif path == '/api/storage/cancel':
            ok = storage_analyzer.cancel_scan()
            self.send_json_response({"success": ok})
            return

        elif path == '/api/storage/action':
            action = post_data.get('action')
            target_path = post_data.get('target_path')
            node_id = post_data.get('node_id')
            if not action or (not target_path and node_id is None):
                self.send_json_response({"success": False, "message": "Missing action or target"})
                return
            success, message = storage_analyzer.perform_action(action, target_path, node_id=node_id)
            self.send_json_response({"success": success, "message": message})
            return

        elif path == '/api/storage/collector/delete':
            # Opaque node ids from our own scan, resolved server-side - see
            # StorageAnalyzer.delete_collected_items for why raw paths are no
            # longer accepted here.
            ids = post_data.get('ids', [])
            res = storage_analyzer.delete_collected_items(ids)
            self.send_json_response(res)
            return

        elif path == '/api/windows_updates/hide':
            # Body: {"update_id": "<guid>"} or {"kb": "KB1234567"}
            update_id = post_data.get('update_id', '').strip()
            kb = post_data.get('kb', '').strip()
            if update_id:
                res = wu_mgr.set_update_hidden(update_id, hide=True)
            elif kb:
                res = wu_mgr.set_update_hidden_by_kb(kb, hide=True)
            else:
                res = {"success": False, "message": "חסר מזהה עדכון (update_id או kb)."}
            self.send_json_response(res)
            return

        elif path == '/api/windows_updates/unhide':
            # Body: {"update_id": "<guid>"} or {"kb": "KB1234567"}
            update_id = post_data.get('update_id', '').strip()
            kb = post_data.get('kb', '').strip()
            if update_id:
                res = wu_mgr.set_update_hidden(update_id, hide=False)
            elif kb:
                res = wu_mgr.set_update_hidden_by_kb(kb, hide=False)
            else:
                res = {"success": False, "message": "חסר מזהה עדכון (update_id או kb)."}
            self.send_json_response(res)
            return

        elif path == '/api/windows_updates/service_toggle':
            action = post_data.get('action')
            res = wu_mgr.toggle_service(action=action)
            self.send_json_response(res)
            return

        elif path == '/api/remote_control/check':
            status = remote_control.check_remote_control(force=True)
            self.send_json_response(status)
            return

        elif path == '/api/remote_control/set_url':
            url = post_data.get('url', '').strip()
            ok = remote_control.set_control_url(url)
            status = remote_control.check_remote_control(force=True)
            self.send_json_response({"success": ok, "status": status})
            return

        elif path == '/api/remote_control/start_download':
            custom_url = post_data.get('download_url', '').strip() or None
            res = remote_control.start_download_update(custom_url=custom_url)
            self.send_json_response(res)
            return

        elif path == '/api/remote_control/apply_update':
            res = remote_control.apply_update()
            self.send_json_response(res)
            return

        elif path == '/api/exit':
            self.send_json_response({"success": True, "message": "סוגר את Polaris..."})
            def _delayed_exit():
                time.sleep(0.4)
                os._exit(0)
            threading.Thread(target=_delayed_exit, daemon=True).start()
            return

        self._reject(404, "Not found")


    # -- static serving -----------------------------------------------------

    def serve_vendor_file(self, path):
        """
        Serves the locally bundled Tailwind/Chart.js assets.
        The resolved path is verified to stay inside FRONTEND_DIR/vendor so a
        crafted URL such as /vendor/../../secret cannot escape the directory.
        """
        vendor_root = os.path.realpath(os.path.join(FRONTEND_DIR, 'vendor'))
        # urlparse does not decode, so an asset with a space in its name would
        # 404 on its literal %20. The commonpath guard below still applies.
        rel = unquote(path[len('/vendor/'):])
        target = os.path.realpath(os.path.join(vendor_root, rel))

        try:
            inside = os.path.commonpath([vendor_root, target]) == vendor_root
        except ValueError:
            # Different drive or a UNC path - no common prefix exists, so the
            # answer is simply "not inside", not a 500.
            inside = False
        if not inside:
            self._reject(403, "Forbidden path")
            return

        content_type = mimetypes.guess_type(target)[0] or 'application/octet-stream'
        if content_type.startswith('text/') or content_type in ('application/javascript',):
            content_type += '; charset=utf-8'
        self.serve_file(target, content_type, cacheable=True)

    def serve_file(self, filepath, content_type, cacheable=False):
        if not os.path.isfile(filepath):
            self._reject(404, "Not found")
            return

        try:
            with open(filepath, 'rb') as f:
                content = f.read()

            # Inject the per-run session token so the UI can authenticate its
            # API calls. A cross-origin page can never read this response.
            if content_type.startswith('text/html'):
                content = content.replace(
                    b'<head>',
                    b'<head>\n  <meta name="polaris-token" content="'
                    + SESSION_TOKEN.encode('ascii') + b'">',
                    1
                )
                if remote_control.is_app_killed():
                    content = content.replace(
                        b'id="killSwitchModal" class="modal-backdrop kill-switch-backdrop hidden"',
                        b'id="killSwitchModal" class="modal-backdrop kill-switch-backdrop"',
                        1
                    )

            self._responded = True
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Cache-Control', 'public, max-age=86400' if cacheable else 'no-store')
            self.end_headers()
            self.wfile.write(content)
        except Exception:
            if getattr(self, '_responded', False):
                self.close_connection = True
                return
            self._reject(500, "Internal error")


def _coerce_pid(value):
    """Safely turns arbitrary JSON input into a positive PID, or None."""
    try:
        pid = int(value)
    except (TypeError, ValueError):
        return None
    return pid if pid > 0 else None


def get_system_info():
    """Environment summary - lets the UI warn when features need elevation."""
    admin = is_admin()
    return {
        "is_admin": admin,
        "is_frozen": bool(getattr(sys, 'frozen', False)),
        "app_version": APP_VERSION,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "hostname": platform.node(),
        "port": SERVER_PORT,
        # Features that silently do nothing without elevation.
        "elevation_required_for": [] if admin else [
            "dism_cleanup", "dism_restore", "sfc_scan",
            "reset_wu", "reset_network", "reset_spooler", "retrim_ssd"
        ]
    }


def find_free_port(start_port=5789):
    """
    Finds a port we can actually bind to. Probing with connect_ex only proves
    that nobody is listening yet - it does not prove the port is bindable.
    """
    for port in range(start_port, start_port + 50):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('127.0.0.1', port))
            return port
        except OSError:
            continue

    # Fall back to an ephemeral port chosen by the OS.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def open_standalone_window(url):
    """
    Opens the URL in a dedicated standalone application window (App Mode)
    without browser toolbars, tabs, or URL address bar.
    """
    edge_paths = [
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe"),
    ]
    chrome_paths = [
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
    ]

    # Try Edge and Chrome app modes with low-memory footprint flags
    for browser_exe in edge_paths + chrome_paths:
        if os.path.exists(browser_exe):
            try:
                popen_hidden([
                    browser_exe,
                    f"--app={url}",
                    "--window-size=1360,900",
                    "--disable-features=RendererCodeIntegrity",
                    "--disable-background-networking",
                    "--disable-sync",
                    "--disable-default-apps",
                    "--no-first-run",
                    "--renderer-process-limit=2"
                ])
                return True
            except Exception:
                pass

    # Last resort: hand the URL to the default browser.
    try:
        import webbrowser
        webbrowser.open(url)
        return True
    except Exception:
        return False

def start_server(port=None, open_browser=False, block=True):
    global SERVER_PORT

    if port is None:
        port = find_free_port()

    server_address = ('127.0.0.1', port)
    httpd = ThreadedHTTPServer(server_address, PolarisHandler)
    SERVER_PORT = port
    url = f"http://127.0.0.1:{port}"
    print(f"==================================================")
    print(f"  Polaris - Windows Diagnostics & Stability Suite   ")
    print(f"  Listening on: {url}")
    print(f"  Administrator: {'yes' if is_admin() else 'no (some repair tools will prompt)'}")
    print(f"==================================================")

    # Initial non-blocking check for remote kill switch and updates
    threading.Thread(target=lambda: remote_control.check_remote_control(force=False), daemon=True).start()

    if open_browser:
        threading.Timer(0.8, lambda: open_standalone_window(url)).start()

    if block:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down Polaris server...")
            httpd.server_close()
    else:
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        return httpd, port

if __name__ == '__main__':
    start_server(open_browser=True)

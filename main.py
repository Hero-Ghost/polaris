"""
Polaris - Main Entry Point
Launches the Web GUI Server or CLI Quick Diagnostic.
"""

import sys
import os
import argparse

APP_VERSION = "3.8.0"

# When PyInstaller builds a windowed (--noconsole) executable there is no
# console attached and sys.stdout / sys.stderr are None, which makes every
# print() in the codebase raise AttributeError. Swap in a throwaway buffer.
import io
if sys.stdout is None:
    sys.stdout = io.StringIO()
if sys.stderr is None:
    sys.stderr = io.StringIO()

# Enable UTF-8 for console output on Windows
if sys.platform.startswith('win'):
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding='utf-8')
        except Exception:
            pass

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import time
from backend.win_utils import is_admin, elevate_me
from backend.server import start_server, open_standalone_window
from backend.memory_analyzer import MemoryAnalyzer
from backend.process_manager import ProcessManager
from backend.diagnostic_engine import DiagnosticEngine

def run_cli_diagnose():
    print("=" * 60)
    print("  Polaris - סריקת מערכת ואבחון שורש (System Diagnostics)")
    print("=" * 60)
    
    analyzer = MemoryAnalyzer()
    mgr = ProcessManager()
    engine = DiagnosticEngine()

    stats = analyzer.get_memory_stats()
    grouped = mgr.get_grouped_processes(stats.get('total_bytes'))
    diag = engine.diagnose(stats, grouped)

    print(f"\n[+] שימוש בזיכרון פיזי: {stats['percent']}% ({stats['formatted']['used']} מתוך {stats['formatted']['total']})")
    print(f"[+] זיכרון פנוי וזמין: {stats['formatted']['available']}")
    print(f"[+] זיכרון מטמון (Standby Cache): {stats['formatted']['cached']}")
    print(f"[+] בריכת דרייברים בלתי מוחלפת (Non-Paged Pool): {stats['formatted']['kernel_nonpaged']}")
    print(f"[+] ציון בריאות זיכרון: {diag['health_score']}/100 ({diag['status_he']})")

    print("\n--- ממצאים וסיבות עיקריות ---")
    for f in diag['findings']:
        print(f"\n* [{f['severity'].upper()}] {f['title_he']}")
        print(f"  {f['desc_he']}")
        if f.get('action_he'):
            print(f"  -> המלצה: {f['action_he']}")

    print("\n--- 5 האפליקציות הכבדות ביותר בזיכרון ---")
    for g in diag['top_consumers'][:5]:
        print(f"  - {g['name']} ({g['raw_name']}): {g['rss_formatted']} ({g['percent']}%) [{g['process_count']} תהליכים]")

    print("\n" + "=" * 60)

def launch_desktop_app(port=None):
    # 1. Start local server in background daemon thread
    httpd, actual_port = start_server(port=port, open_browser=False, block=False)
    time.sleep(0.3)
    url = f"http://127.0.0.1:{actual_port}"

    # 2. Launch Native Windows Desktop Window via pywebview (Edge WebView2)
    try:
        import webview
        webview.create_window(
            title="Polaris",
            url=url,
            width=1340,
            height=880,
            min_size=(980, 650),
            background_color="#090c15",
            text_select=False,
            zoomable=True
        )
        webview.start(debug=False)
    except Exception as e:
        print(f"Native desktop window note: {e}")
        open_standalone_window(url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

def main():
    # Enforce Administrator privileges on Windows for full hardware & repair access
    if sys.platform.startswith('win') and not is_admin():
        if elevate_me():
            sys.exit(0)

    parser = argparse.ArgumentParser(description="Polaris - Windows Diagnostics & Stability Suite")
    parser.add_argument("--port", type=int, default=None, help="Port to run the server on")
    parser.add_argument("--cli", action="store_true", help="Run in terminal CLI mode without opening GUI")
    parser.add_argument("--server-only", action="store_true",
                        help="Start the local API/UI server and print the URL, without opening a window")
    parser.add_argument("--version", action="version", version=f"Polaris {APP_VERSION}")

    args = parser.parse_args()

    if args.cli:
        run_cli_diagnose()
    elif args.server_only:
        start_server(port=args.port, open_browser=False, block=True)
    else:
        launch_desktop_app(port=args.port)

if __name__ == "__main__":
    main()

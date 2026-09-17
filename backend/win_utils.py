"""
Polaris - Shared Windows helpers.

Central place for:
  * running child processes WITHOUT flashing a black console window
    (critical once the app is packaged as a windowed .exe)
  * checking whether Polaris is running elevated (Administrator)
  * a single canonical byte formatter used across the whole backend
"""

import sys
import json
import ctypes
import subprocess

IS_WINDOWS = sys.platform.startswith('win')

# CREATE_NO_WINDOW (0x08000000) suppresses the console window that Windows
# would otherwise pop up for every taskkill / powershell / dism / netsh call.
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def _hidden_kwargs(kwargs):
    """Injects the flags that keep child processes invisible."""
    if not IS_WINDOWS:
        return kwargs

    kwargs.setdefault('creationflags', 0)
    kwargs['creationflags'] |= CREATE_NO_WINDOW

    if 'startupinfo' not in kwargs:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        kwargs['startupinfo'] = si

    return kwargs


def run_hidden(cmd, **kwargs):
    """subprocess.run() that never shows a console window."""
    return subprocess.run(cmd, **_hidden_kwargs(kwargs))


def popen_hidden(cmd, **kwargs):
    """subprocess.Popen() that never shows a console window."""
    return subprocess.Popen(cmd, **_hidden_kwargs(kwargs))


def popen_visible(cmd, **kwargs):
    """
    subprocess.Popen() for GUI programs the user is SUPPOSED to see.

    popen_hidden() forces CREATE_NO_WINDOW + STARTF_USESHOWWINDOW/SW_HIDE, and
    Windows passes that startup state on to the child. For a console tool that
    is exactly what we want, but for explorer.exe / cleanmgr.exe it means the
    process starts and immediately hides itself - the call "succeeds" while the
    user sees nothing at all. Anything with a window must go through here.
    """
    return subprocess.Popen(cmd, **kwargs)


def reveal_in_explorer(path):
    """
    Opens File Explorer with `path` selected (file) or opened (folder).

    Returns (ok, message). Uses ShellExecuteW rather than spawning explorer.exe
    through subprocess: it is what the shell itself uses, it reuses an existing
    Explorer window, and it is immune to the hidden-startup-state problem.
    """
    import os

    if not path:
        return False, "לא צוין נתיב"

    # normpath only - abspath is applied when the argument is built, so that a
    # path that cannot exist here (a Windows drive letter seen from POSIX) still
    # reports "does not exist" instead of resolving against the cwd.
    path = os.path.normpath(str(path).strip().strip('"').strip("'"))

    target, select = path, True
    ok_message = "סייר הקבצים נפתח בהצלחה"
    if not os.path.exists(path):
        parent = os.path.dirname(path)
        if not parent or not os.path.exists(parent):
            return False, "הנתיב אינו קיים"
        target, select = parent, False
        ok_message = "הקובץ לא נמצא, נפתחה תיקיית האב בסייר הקבצים"
    elif os.path.isdir(path):
        select = False

    if not IS_WINDOWS:
        # Nothing to launch off Windows, but keep the same contract.
        return True, ok_message

    target = os.path.abspath(target)
    SW_SHOWNORMAL = 1
    try:
        params = f'/select,"{target}"' if select else f'"{target}"'
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "open", "explorer.exe", params, None, SW_SHOWNORMAL
        )
        # ShellExecuteW returns a value > 32 on success.
        if int(rc) > 32:
            return True, ok_message
        last_error = rc
    except Exception as e:
        last_error = e

    # Fallback: spawn explorer.exe directly (visibly).
    try:
        args = ["explorer.exe", f"/select,{target}"] if select else ["explorer.exe", target]
        popen_visible(args)
        return True, ok_message
    except Exception as e:
        return False, f"פתיחת סייר הקבצים נכשלה ({last_error}): {e}"


def run_powershell_json(script, timeout=25):
    """
    Runs a PowerShell snippet that emits JSON and returns the decoded result.

    Always returns a list (a single object is wrapped, and any failure yields an
    empty list) so callers never need to special-case PowerShell's habit of
    collapsing one-element pipelines into a bare object.

    The console encoding is forced to UTF-8 inside the snippet, otherwise a
    Hebrew (or any non-Latin-1) Windows install mangles device and volume
    labels on the way out.
    """
    if not IS_WINDOWS:
        return []

    preamble = "$ProgressPreference='SilentlyContinue';" \
               "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"

    try:
        proc = run_hidden(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", preamble + script],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"PowerShell query timed out after {timeout}s")
        return []
    except Exception as exc:
        print(f"PowerShell query failed to start: {exc}")
        return []

    out = (proc.stdout or "").strip()
    if not out:
        return []

    try:
        data = json.loads(out)
    except (ValueError, TypeError):
        # A cmdlet that is unavailable on this Windows edition prints an error
        # to stdout instead of JSON; that is expected, not exceptional.
        return []

    if data is None:
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def is_admin():
    """True when the current process holds Administrator privileges."""
    if not IS_WINDOWS:
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def elevate_me():
    """
    Relaunches the current process with Administrator privileges (UAC prompt).
    Returns True if elevation was requested and the caller should exit.
    """
    if not IS_WINDOWS:
        return False
    if is_admin():
        return False

    try:
        if getattr(sys, 'frozen', False):
            executable = sys.executable
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
        else:
            executable = sys.executable
            params = " ".join([f'"{arg}"' for arg in sys.argv])

        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            executable,
            params,
            None,
            1  # SW_SHOWNORMAL
        )
        if ret > 32:
            return True
    except Exception as e:
        print(f"UAC elevation prompt note: {e}")
    return False


# --- BiDi helpers -----------------------------------------------------------
# The UI is a Hebrew RTL document. Inside an RTL paragraph the Unicode BiDi
# algorithm gives the digits of "8.20 GB" one level and the latin "GB" another,
# while the plain space between them falls back to the RTL paragraph direction.
# The result is that the two runs get swapped on screen and the user reads
# "GB 8.20". Wrapping the whole value in an isolate (LRI ... PDI) makes it a
# single left-to-right unit that is laid out as one atom wherever it appears -
# in a table cell, or in the middle of a Hebrew sentence - and a no-break space
# keeps the number and its unit from being split across two lines.
LRI = "⁦"   # LEFT-TO-RIGHT ISOLATE
PDI = "⁩"   # POP DIRECTIONAL ISOLATE
NBSP = " "  # NO-BREAK SPACE


def ltr_isolate(text):
    """Wraps a latin/numeric value so it renders correctly inside RTL text."""
    if text is None:
        return ""
    text = str(text)
    if not text or text.startswith(LRI):
        return text
    return f"{LRI}{text}{PDI}"


def strip_bidi(text):
    """Removes BiDi control characters - for CSV/JSON exports and comparisons."""
    if text is None:
        return ""
    return str(text).replace(LRI, "").replace(PDI, "").replace(NBSP, " ")


def format_bytes_raw(b):
    """Human readable byte formatter (KB / MB / GB / TB), plain ASCII."""
    if b is None:
        return "0 B"
    try:
        b = float(b)
    except (TypeError, ValueError):
        return "0 B"
    if b < 0:
        return "0 B"

    tb = b / (1024 ** 4)
    if tb >= 1.0:
        return f"{tb:.2f} TB"
    gb = b / (1024 ** 3)
    if gb >= 1.0:
        return f"{gb:.2f} GB"
    mb = b / (1024 ** 2)
    if mb >= 1.0:
        return f"{mb:.1f} MB"
    kb = b / 1024
    if kb >= 1.0:
        return f"{kb:.0f} KB"
    return f"{int(b)} B"


def format_bytes(b):
    """
    Human readable byte formatter for DISPLAY (KB / MB / GB / TB).

    Identical to format_bytes_raw() except the value is BiDi-isolated and uses a
    no-break space, so the unit always follows the number ("24.16 GB") in the
    Hebrew RTL UI instead of being flipped to "GB 24.16".
    Use format_bytes_raw() for exports, filenames and logs.
    """
    value = format_bytes_raw(b)
    number, _, unit = value.rpartition(" ")
    if number:
        value = f"{number}{NBSP}{unit}"
    return ltr_isolate(value)


def open_keyboard_settings():
    """
    Opens the Windows Settings keyboard page (ms-settings:keyboard)
    allowing users to remap the Copilot key to Right Ctrl natively in Windows.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    import os
    try:
        if hasattr(os, 'startfile'):
            os.startfile('ms-settings:keyboard')
        else:
            run_hidden(['cmd.exe', '/c', 'start', 'ms-settings:keyboard'])
        return {
            "success": True,
            "message": "מסך הגדרות המקלדת של Windows נפתח בהצלחה."
        }
    except Exception as e:
        return {"success": False, "message": f"שגיאה בפתיחת הגדרות: {str(e)}"}


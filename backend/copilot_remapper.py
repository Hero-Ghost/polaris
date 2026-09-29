"""
Polaris - Copilot Key Auto-Remapper Engine
Compiles and manages an ultra-lightweight (6KB, 0% CPU, no window) native Windows
Low-Level Keyboard Hook that translates the Copilot key (Win + Shift + F23) to Right Control (RCtrl).
Installs to AppData and registers in HKCU Run (Startup) so it works permanently even without Polaris.
"""

import os
import sys
import shutil
import subprocess
import threading
import psutil

from backend.win_utils import IS_WINDOWS, popen_hidden, run_hidden

try:
    import winreg
except ImportError:
    winreg = None

CS_SOURCE = r"""
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace CopilotRemap
{
    static class Program
    {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;
        private const int WM_KEYUP = 0x0101;
        private const int WM_SYSKEYDOWN = 0x0104;
        private const int WM_SYSKEYUP = 0x0105;

        private const int VK_LWIN = 0x5B;
        private const int VK_RWIN = 0x5C;
        private const int VK_LSHIFT = 0xA0;
        private const int VK_F23 = 0x86;
        private const int VK_RCONTROL = 0xA3;

        private const uint KEYEVENTF_KEYUP = 0x0002;
        private const uint KEYEVENTF_EXTENDEDKEY = 0x0001;

        private static LowLevelKeyboardProc _proc = HookCallback;
        private static IntPtr _hookID = IntPtr.Zero;
        private static bool _isCopilotHeld = false;

        private const string REG_RUN_PATH = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string REG_VAL_NAME = "CopilotToCtrl";

        [STAThread]
        static void Main(string[] args)
        {
            string currentExe = Process.GetCurrentProcess().MainModule.FileName;
            string appDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CopilotToCtrl");
            string targetServiceExe = Path.Combine(appDataDir, "CopilotService.exe");

            bool isServiceMode = false;
            if (args != null)
            {
                foreach (string arg in args)
                {
                    if (string.Equals(arg, "--service", StringComparison.OrdinalIgnoreCase))
                    {
                        isServiceMode = true;
                        break;
                    }
                    else if (string.Equals(arg, "--silent", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(arg, "-silent", StringComparison.OrdinalIgnoreCase))
                    {
                        // Silent auto-enable without UI
                        EnableRemapSilently(currentExe, appDataDir, targetServiceExe);
                        return;
                    }
                    else if (string.Equals(arg, "--uninstall", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(arg, "--disable", StringComparison.OrdinalIgnoreCase))
                    {
                        // Silent disable without UI
                        DisableRemapSilently(appDataDir);
                        return;
                    }
                }
            }

            // Background Hook Service Mode (executed by Windows Startup on boot)
            if (isServiceMode || string.Equals(currentExe, targetServiceExe, StringComparison.OrdinalIgnoreCase))
            {
                bool createdNew;
                using (Mutex mutex = new Mutex(true, "CopilotToCtrl_Service_Mutex", out createdNew))
                {
                    if (!createdNew) return;

                    _hookID = SetHook(_proc);
                    Application.Run();
                    UnhookWindowsHookEx(_hookID);
                }
                return;
            }

            // Interactive Mode: Show UI Form with 2 options (Enable & Remove)
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(currentExe, appDataDir, targetServiceExe));
        }

        public class MainForm : Form
        {
            private string _currentExe;
            private string _appDataDir;
            private string _targetServiceExe;
            private Label _lblStatus;

            public MainForm(string currentExe, string appDataDir, string targetServiceExe)
            {
                _currentExe = currentExe;
                _appDataDir = appDataDir;
                _targetServiceExe = targetServiceExe;
                InitializeComponents();
            }

            private void InitializeComponents()
            {
                this.Text = "CopilotToCtrl";
                this.Size = new Size(460, 265);
                this.StartPosition = FormStartPosition.CenterScreen;
                this.FormBorderStyle = FormBorderStyle.FixedDialog;
                this.MaximizeBox = false;
                this.MinimizeBox = false;
                this.Font = new Font("Segoe UI", 9F, FontStyle.Regular);
                this.BackColor = Color.FromArgb(248, 249, 250);

                Label lblTitle = new Label();
                lblTitle.Text = "Copilot Key Remapper";
                lblTitle.Font = new Font("Segoe UI", 12F, FontStyle.Bold);
                lblTitle.Location = new Point(24, 18);
                lblTitle.AutoSize = true;
                lblTitle.ForeColor = Color.FromArgb(33, 37, 41);

                Label lblDesc = new Label();
                lblDesc.Text = "Remaps the physical Copilot key to standard Right Control.\nChanges are permanent and automatically persist across restarts.";
                lblDesc.Location = new Point(24, 48);
                lblDesc.Size = new Size(400, 36);
                lblDesc.ForeColor = Color.FromArgb(108, 117, 125);

                _lblStatus = new Label();
                _lblStatus.Location = new Point(24, 90);
                _lblStatus.Size = new Size(400, 20);
                _lblStatus.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
                UpdateStatusLabel();

                Label lblAuthor = new Label();
                lblAuthor.Text = "Created by YAKIR LAVIE";
                lblAuthor.Font = new Font("Segoe UI", 8F, FontStyle.Regular);
                lblAuthor.ForeColor = Color.FromArgb(130, 130, 130);
                lblAuthor.Location = new Point(24, 116);
                lblAuthor.AutoSize = true;

                Button btnEnable = new Button();
                btnEnable.Text = "Enable (Right Ctrl)";
                btnEnable.Size = new Size(190, 42);
                btnEnable.Location = new Point(24, 148);
                btnEnable.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
                btnEnable.BackColor = Color.FromArgb(13, 110, 253);
                btnEnable.ForeColor = Color.White;
                btnEnable.FlatStyle = FlatStyle.Flat;
                btnEnable.FlatAppearance.BorderSize = 0;
                btnEnable.Cursor = Cursors.Hand;
                btnEnable.Click += BtnEnable_Click;

                Button btnDisable = new Button();
                btnDisable.Text = "Remove / Disable";
                btnDisable.Size = new Size(190, 42);
                btnDisable.Location = new Point(230, 148);
                btnDisable.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
                btnDisable.BackColor = Color.FromArgb(230, 235, 240);
                btnDisable.ForeColor = Color.FromArgb(70, 80, 95);
                btnDisable.FlatStyle = FlatStyle.Flat;
                btnDisable.FlatAppearance.BorderSize = 0;
                btnDisable.Cursor = Cursors.Hand;
                btnDisable.Click += BtnDisable_Click;

                this.Controls.Add(lblTitle);
                this.Controls.Add(lblDesc);
                this.Controls.Add(_lblStatus);
                this.Controls.Add(lblAuthor);
                this.Controls.Add(btnEnable);
                this.Controls.Add(btnDisable);
            }

            private void UpdateStatusLabel()
            {
                bool isRunning = IsServiceRunning();
                if (isRunning)
                {
                    _lblStatus.Text = "● Status: Active (Mapped to Right Ctrl)";
                    _lblStatus.ForeColor = Color.FromArgb(25, 135, 84);
                }
                else
                {
                    _lblStatus.Text = "○ Status: Disabled (Original Copilot key)";
                    _lblStatus.ForeColor = Color.FromArgb(108, 117, 125);
                }
            }

            private bool IsServiceRunning()
            {
                try
                {
                    foreach (Process p in Process.GetProcessesByName("CopilotService"))
                    {
                        return true;
                    }
                }
                catch { }
                return false;
            }

            private void BtnEnable_Click(object sender, EventArgs e)
            {
                try
                {
                    EnableRemapSilently(_currentExe, _appDataDir, _targetServiceExe);

                    MessageBox.Show(
                        "Done! Copilot key remapped to Right Control.\n(Active permanently across restarts. You can safely delete or move this file.)\n\nCreated by YAKIR LAVIE",
                        "CopilotToCtrl",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information
                    );

                    this.Close();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        "Error: " + ex.Message + "\n\nCreated by YAKIR LAVIE",
                        "CopilotToCtrl",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                }
            }

            private void BtnDisable_Click(object sender, EventArgs e)
            {
                try
                {
                    DisableRemapSilently(_appDataDir);

                    MessageBox.Show(
                        "Done! Copilot key remapping removed.\n\nCreated by YAKIR LAVIE",
                        "CopilotToCtrl",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information
                    );

                    this.Close();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        "Error: " + ex.Message + "\n\nCreated by YAKIR LAVIE",
                        "CopilotToCtrl",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                }
            }
        }

        public static void EnableRemapSilently(string currentExe, string appDataDir, string targetServiceExe)
        {
            StopRunningService();

            if (!Directory.Exists(appDataDir))
            {
                Directory.CreateDirectory(appDataDir);
            }

            File.Copy(currentExe, targetServiceExe, true);

            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(REG_RUN_PATH, true))
            {
                if (key != null)
                {
                    key.SetValue(REG_VAL_NAME, "\"" + targetServiceExe + "\" --service --silent");
                }
            }

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = targetServiceExe;
            psi.Arguments = "--service --silent";
            psi.UseShellExecute = true;
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            Process.Start(psi);
        }

        public static void DisableRemapSilently(string appDataDir)
        {
            StopRunningService();
            RemoveFromStartup();

            try
            {
                if (Directory.Exists(appDataDir))
                {
                    Directory.Delete(appDataDir, true);
                }
            }
            catch { }
        }

        public static void StopRunningService()
        {
            try
            {
                foreach (Process p in Process.GetProcessesByName("CopilotService"))
                {
                    try { p.Kill(); p.WaitForExit(1000); } catch { }
                }
                foreach (Process p in Process.GetProcessesByName("CopilotToCtrl"))
                {
                    if (p.Id != Process.GetCurrentProcess().Id)
                    {
                        try { p.Kill(); p.WaitForExit(1000); } catch { }
                    }
                }
            }
            catch { }
        }

        public static void RemoveFromStartup()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(REG_RUN_PATH, true))
                {
                    if (key != null)
                    {
                        try { key.DeleteValue(REG_VAL_NAME); } catch { }
                    }
                }
            }
            catch { }
        }

        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
            }
        }

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0)
            {
                int vkCode = Marshal.ReadInt32(lParam);
                int flags = Marshal.ReadInt32(lParam, 8);
                bool isInjected = (flags & 0x10) != 0;

                if (!isInjected)
                {
                    int msg = wParam.ToInt32();

                    if (vkCode == VK_F23)
                    {
                        if (msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN)
                        {
                            if (!_isCopilotHeld)
                            {
                                _isCopilotHeld = true;
                                keybd_event((byte)VK_LSHIFT, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
                                keybd_event((byte)VK_LWIN, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
                                keybd_event((byte)VK_RCONTROL, 0, KEYEVENTF_EXTENDEDKEY, UIntPtr.Zero);
                            }
                            return (IntPtr)1;
                        }
                        else if (msg == WM_KEYUP || msg == WM_SYSKEYUP)
                        {
                            _isCopilotHeld = false;
                            keybd_event((byte)VK_RCONTROL, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, UIntPtr.Zero);
                            return (IntPtr)1;
                        }
                    }
                }
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("user32.dll")]
        private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    }
}
"""

REG_RUN_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
REG_VAL_NAME = "CopilotToCtrl"

def _get_target_dir():
    appdata = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(appdata, "CopilotToCtrl")

def _get_target_service_exe():
    return os.path.join(_get_target_dir(), "CopilotService.exe")

def _get_root_exe():
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', '')
        cand = os.path.join(meipass, "CopilotToCtrl.exe")
        if os.path.exists(cand):
            return cand
        cand_exe = os.path.join(os.path.dirname(sys.executable), "CopilotToCtrl.exe")
        if os.path.exists(cand_exe):
            return cand_exe
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "CopilotToCtrl.exe")

def _find_csc():
    candidates = [
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
        r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None

def compile_helper():
    """Compiles the standalone CopilotToCtrl binary."""
    target_dir = _get_target_dir()
    os.makedirs(target_dir, exist_ok=True)
    target_service = _get_target_service_exe()
    root_exe = _get_root_exe()

    csc = _find_csc()
    if not csc:
        return False, "Could not find .NET Framework csc.exe compiler"

    cs_file = os.path.join(target_dir, "CopilotToCtrl.cs")
    try:
        with open(cs_file, "w", encoding="utf-8") as f:
            f.write(CS_SOURCE)

        cmd = [
            csc,
            "/target:winexe",
            "/r:System.Windows.Forms.dll",
            "/r:System.Drawing.dll",
            f"/out:{target_service}",
            cs_file
        ]
        res = run_hidden(cmd, capture_output=True, text=True)
        if os.path.exists(cs_file):
            try:
                os.remove(cs_file)
            except Exception:
                pass

        if res.returncode == 0 and os.path.exists(target_service):
            try:
                shutil.copy2(target_service, root_exe)
            except Exception:
                pass
            return True, target_service
        return False, f"Compilation error: {res.stderr or res.stdout}"
    except Exception as e:
        return False, f"File error: {str(e)}"

def is_service_running():
    """Checks if the background CopilotService.exe is currently active."""
    if not IS_WINDOWS:
        return False
    try:
        for p in psutil.process_iter(['name']):
            name = (p.info['name'] or '').lower()
            if name in ('copilotservice.exe', 'copilottoctrl.exe'):
                return True
    except Exception:
        pass
    return False

def is_startup_registered():
    """Checks if CopilotService is in HKCU Run registry."""
    if not IS_WINDOWS or not winreg:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_PATH, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, REG_VAL_NAME)
            return bool(val)
    except Exception:
        return False

def get_copilot_remap_status():
    """Returns current status dictionary."""
    running = is_service_running()
    startup = is_startup_registered()
    target_service = _get_target_service_exe()
    service_exists = os.path.exists(target_service)

    return {
        "is_active": running or startup,
        "is_startup": startup,
        "exe_exists": service_exists or os.path.exists(_get_root_exe()),
        "exe_path": target_service if service_exists else _get_root_exe()
    }

def enable_copilot_remap():
    """Installs the service to AppData, registers in Startup, and starts it."""
    if not IS_WINDOWS:
        return {"success": False, "message": "Supported on Windows only"}

    target_service = _get_target_service_exe()
    if not os.path.exists(target_service):
        root_exe = _get_root_exe()
        if root_exe and os.path.exists(root_exe):
            os.makedirs(_get_target_dir(), exist_ok=True)
            try:
                shutil.copy2(root_exe, target_service)
            except Exception:
                pass
        if not os.path.exists(target_service):
            ok, msg = compile_helper()
            if not ok:
                return {"success": False, "message": msg}

    # Register in Startup (HKCU Run)
    if winreg:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_PATH, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, REG_VAL_NAME, 0, winreg.REG_SZ, f'"{target_service}" --service --silent')
        except Exception as e:
            return {"success": False, "message": f"Startup registration error: {str(e)}"}

    # Start service if not running
    if not is_service_running():
        try:
            popen_hidden([target_service, "--service", "--silent"])
        except Exception as e:
            return {"success": False, "message": f"Service launch error: {str(e)}"}

    return {
        "success": True,
        "message": "Done! Copilot key remapped to Right Control. (Created by YAKIR LAVIE)",
        "status": get_copilot_remap_status()
    }

def disable_copilot_remap():
    """Kills running service and removes from Startup."""
    if not IS_WINDOWS:
        return {"success": False, "message": "Supported on Windows only"}

    # Kill background service
    try:
        run_hidden(['taskkill', '/F', '/IM', 'CopilotService.exe'], check=False)
        run_hidden(['taskkill', '/F', '/IM', 'CopilotToCtrl.exe'], check=False)
    except Exception:
        pass

    # Remove from Registry Startup
    if winreg:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_PATH, 0, winreg.KEY_SET_VALUE) as key:
                try:
                    winreg.DeleteValue(key, REG_VAL_NAME)
                except FileNotFoundError:
                    pass
        except Exception as e:
            return {"success": False, "message": f"Startup cleanup error: {str(e)}"}

    # Clean AppData directory
    try:
        target_dir = _get_target_dir()
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
    except Exception:
        pass

    return {
        "success": True,
        "message": "Done! Copilot key remapping removed. (Created by YAKIR LAVIE)",
        "status": get_copilot_remap_status()
    }

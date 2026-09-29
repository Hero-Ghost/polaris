"""
Unit tests for backend/onedrive_manager.py
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

from backend.onedrive_manager import (
    is_onedrive_running,
    close_onedrive,
    accounts_registry_exists,
    delete_onedrive_accounts_registry,
    clear_onedrive_local_cache,
    launch_onedrive,
    get_onedrive_status,
    reset_onedrive
)


class TestOneDriveManager(unittest.TestCase):

    @patch('backend.onedrive_manager.IS_WINDOWS', True)
    @patch('backend.onedrive_manager.run_hidden')
    def test_close_onedrive_when_not_running(self, mock_run):
        with patch('backend.onedrive_manager.is_onedrive_running', return_value=False):
            res = close_onedrive()
            self.assertTrue(res['success'])
            self.assertFalse(res['killed'])
            mock_run.assert_not_called()

    @patch('backend.onedrive_manager.IS_WINDOWS', True)
    @patch('backend.onedrive_manager.run_hidden')
    def test_close_onedrive_when_running(self, mock_run):
        with patch('backend.onedrive_manager.is_onedrive_running', side_effect=[True, False]):
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_run.return_value = mock_proc

            res = close_onedrive()
            self.assertTrue(res['success'])
            self.assertTrue(res['killed'])
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            self.assertIn('taskkill.exe', cmd)
            self.assertIn('OneDrive.exe', cmd)

    @patch('backend.onedrive_manager.IS_WINDOWS', True)
    @patch('backend.onedrive_manager.run_hidden')
    def test_delete_accounts_registry_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        with patch('backend.onedrive_manager.accounts_registry_exists', return_value=True):
            res = delete_onedrive_accounts_registry()
            self.assertTrue(res['success'])
            self.assertTrue(res['deleted'])
            cmd = mock_run.call_args[0][0]
            self.assertIn('reg.exe', cmd)
            self.assertIn('delete', cmd)
            self.assertIn(r'HKCU\Software\Microsoft\OneDrive\Accounts', cmd)

    @patch('backend.onedrive_manager.IS_WINDOWS', True)
    @patch('backend.onedrive_manager.run_hidden')
    def test_delete_accounts_registry_already_absent(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stderr = "The system was unable to find the specified registry key"
        mock_run.return_value = mock_proc

        with patch('backend.onedrive_manager.accounts_registry_exists', return_value=False):
            res = delete_onedrive_accounts_registry()
            self.assertTrue(res['success'])
            self.assertFalse(res['deleted'])

    @patch('backend.onedrive_manager.IS_WINDOWS', True)
    def test_clear_local_cache(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            test_settings = os.path.join(tmpdir, "Microsoft", "OneDrive", "settings")
            test_logs = os.path.join(tmpdir, "Microsoft", "OneDrive", "setup", "logs")
            os.makedirs(test_settings, exist_ok=True)
            os.makedirs(test_logs, exist_ok=True)

            with open(os.path.join(test_settings, "test.dat"), "w") as f:
                f.write("dummy")

            with patch('os.environ.get', return_value=tmpdir):
                res = clear_onedrive_local_cache()
                self.assertTrue(res['success'])
                self.assertFalse(os.path.exists(os.path.join(test_settings, "test.dat")))

    @patch('backend.onedrive_manager.IS_WINDOWS', True)
    @patch('backend.onedrive_manager.close_onedrive')
    @patch('backend.onedrive_manager.delete_onedrive_accounts_registry')
    @patch('backend.onedrive_manager.clear_onedrive_local_cache')
    def test_reset_onedrive_full_flow(self, mock_cache, mock_reg, mock_close):
        mock_close.return_value = {"success": True, "killed": True}
        mock_reg.return_value = {"success": True, "deleted": True, "existed_before": True}
        mock_cache.return_value = {"success": True, "cleared_dirs": ["dir1"]}

        res = reset_onedrive(relaunch=False, clean_cache=True)
        self.assertTrue(res['success'])
        mock_close.assert_called_once()
        mock_reg.assert_called_once()
        self.assertIn("OneDrive נסגר", res['message'])
        self.assertIn("חשבונות הרגיסטרי נמחקו", res['message'])

    @patch('backend.onedrive_manager.IS_WINDOWS', True)
    @patch('backend.onedrive_manager.is_onedrive_running', return_value=True)
    @patch('backend.onedrive_manager.accounts_registry_exists', return_value=True)
    @patch('backend.onedrive_manager.get_onedrive_exe_path', return_value=r"C:\fake\OneDrive.exe")
    def test_get_onedrive_status(self, mock_exe, mock_reg, mock_run):
        status = get_onedrive_status()
        self.assertTrue(status['success'])
        self.assertTrue(status['is_running'])
        self.assertTrue(status['accounts_key_exists'])
        self.assertTrue(status['installed'])
        self.assertEqual(status['exe_path'], r"C:\fake\OneDrive.exe")

    @patch('backend.onedrive_manager.IS_WINDOWS', True)
    @patch('backend.onedrive_manager.get_onedrive_exe_path', return_value=r"C:\fake\OneDrive.exe")
    @patch('os.path.exists', return_value=True)
    @patch('backend.onedrive_manager.popen_visible')
    def test_launch_onedrive(self, mock_popen, mock_exists, mock_exe):
        res = launch_onedrive()
        self.assertTrue(res['success'])
        mock_popen.assert_called_once_with([r"C:\fake\OneDrive.exe", '/background'])


if __name__ == '__main__':
    unittest.main()

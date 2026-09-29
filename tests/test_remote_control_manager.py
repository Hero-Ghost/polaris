"""
Unit tests for backend/remote_control_manager.py
Tests remote kill switch logic, version comparisons, update detection, and offline resilience.
"""

import os
import json
import unittest
from unittest.mock import patch, MagicMock

from backend.remote_control_manager import (
    RemoteControlManager,
    parse_version,
    APP_VERSION
)


import tempfile
import shutil

class TestRemoteControlManager(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.orig_appdata = os.environ.get('LOCALAPPDATA')
        os.environ['LOCALAPPDATA'] = self.test_dir

    def tearDown(self):
        if self.orig_appdata:
            os.environ['LOCALAPPDATA'] = self.orig_appdata
        else:
            os.environ.pop('LOCALAPPDATA', None)
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_parse_version(self):
        self.assertEqual(parse_version("3.1"), (3, 1, 0))
        self.assertEqual(parse_version("v3.1.0"), (3, 1, 0))
        self.assertEqual(parse_version("3.2.1"), (3, 2, 1))
        self.assertEqual(parse_version("10.0.19045"), (10, 0, 19045))
        self.assertTrue(parse_version("3.2.0") > parse_version("3.1.0"))
        self.assertTrue(parse_version("3.1.1") > parse_version("3.1.0"))
        self.assertFalse(parse_version("3.0.9") > parse_version("3.1.0"))

    def test_kill_switch_disabled_by_default(self):
        mgr = RemoteControlManager(current_version="3.1.0")
        mock_data = {
            "kill_switch": {"enabled": False, "blocked_versions": []},
            "update": {"latest_version": "3.1.0"}
        }
        status = mgr._evaluate_control_data(mock_data)
        self.assertFalse(status["is_killed"])
        self.assertFalse(status["has_update"])

    def test_kill_switch_enabled_globally(self):
        mgr = RemoteControlManager(current_version="3.1.0")
        mock_data = {
            "kill_switch": {
                "enabled": True,
                "title_he": "המערכת הושבתה",
                "message_he": "השבתת חירום על ידי המפתח"
            }
        }
        status = mgr._evaluate_control_data(mock_data)
        self.assertTrue(status["is_killed"])
        self.assertEqual(status["kill_info"]["reason"], "enabled_globally")
        self.assertEqual(status["kill_info"]["title_he"], "המערכת הושבתה")
        self.assertIn("השבתת חירום", status["kill_info"]["message_he"])

    def test_kill_switch_blocked_version(self):
        mgr = RemoteControlManager(current_version="3.1.0")
        mock_data = {
            "kill_switch": {
                "enabled": False,
                "blocked_versions": ["3.0.0", "3.1.0"]
            }
        }
        status = mgr._evaluate_control_data(mock_data)
        self.assertTrue(status["is_killed"])
        self.assertEqual(status["kill_info"]["reason"], "version_blocked")

    def test_kill_switch_min_version_allowed(self):
        mgr = RemoteControlManager(current_version="3.1.0")
        mock_data = {
            "kill_switch": {
                "enabled": False,
                "min_version_allowed": "3.2.0"
            }
        }
        status = mgr._evaluate_control_data(mock_data)
        self.assertTrue(status["is_killed"])
        self.assertEqual(status["kill_info"]["reason"], "version_below_minimum")

    def test_update_detection(self):
        mgr = RemoteControlManager(current_version="3.1.0")
        mock_data = {
            "kill_switch": {"enabled": False},
            "update": {
                "latest_version": "3.2.0",
                "release_title_he": "גרסה חדשה יצאה",
                "download_url": "https://github.com/Hero-Ghost/polaris/releases/download/v3.2.0/Polaris.exe",
                "mandatory": False
            }
        }
        status = mgr._evaluate_control_data(mock_data)
        self.assertFalse(status["is_killed"])
        self.assertTrue(status["has_update"])
        self.assertEqual(status["update_info"]["latest_version"], "3.2.0")
        self.assertFalse(status["update_info"]["mandatory"])

    def test_mandatory_update_detection(self):
        mgr = RemoteControlManager(current_version="3.1.0")
        mock_data = {
            "kill_switch": {"enabled": False, "min_version_allowed": "3.2.0"},
            "update": {
                "latest_version": "3.2.0",
                "mandatory": True
            }
        }
        status = mgr._evaluate_control_data(mock_data)
        self.assertTrue(status["update_info"]["mandatory"])

    @patch('urllib.request.urlopen')
    def test_check_remote_control_network_success(self, mock_urlopen):
        mgr = RemoteControlManager(current_version="3.1.0")
        payload = {
            "kill_switch": {"enabled": False},
            "update": {"latest_version": "3.3.0", "release_title_he": "עדכון 3.3.0"}
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(payload).encode('utf-8')
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res = mgr.check_remote_control(force=True)
        self.assertFalse(res["is_killed"])
        self.assertTrue(res["has_update"])
        self.assertEqual(res["update_info"]["latest_version"], "3.3.0")
        self.assertFalse(res["offline"])

    @patch('urllib.request.urlopen')
    def test_check_remote_control_network_failure_resilience(self, mock_urlopen):
        mgr = RemoteControlManager(current_version="3.1.0")
        mock_urlopen.side_effect = Exception("No route to host")

        res = mgr.check_remote_control(force=True)
        # Should NOT crash, and should not lock app unless previously killed
        self.assertFalse(res["is_killed"])
        self.assertTrue(res["offline"])

    def test_set_and_get_control_url(self):
        mgr = RemoteControlManager(current_version="3.1.0")
        test_url = "https://raw.githubusercontent.com/testuser/repo/main/control.json"
        with patch('builtins.open', unittest.mock.mock_open()):
            ok = mgr.set_control_url(test_url)
            self.assertTrue(ok)
            self.assertEqual(mgr.control_url, test_url)


if __name__ == '__main__':
    unittest.main()

"""
Tests for remote control & kill switch HTTP endpoints in backend/server.py
"""

import json
import unittest
from unittest.mock import patch, MagicMock

import backend.server as srv


class TestRemoteControlServerEndpoints(unittest.TestCase):

    def setUp(self):
        self.handler = srv.PolarisHandler.__new__(srv.PolarisHandler)
        self.handler.headers = {
            'Host': '127.0.0.1:5789',
            'Origin': 'http://127.0.0.1:5789',
            'X-Polaris-Token': srv.SESSION_TOKEN
        }
        self.handler.command = 'GET'

    def test_guard_allows_status_when_killed(self):
        with patch.object(srv.remote_control, 'is_app_killed', return_value=True):
            # Status and exit must be allowed
            self.assertTrue(self.handler._guard('/api/remote_control/status'))
            self.assertTrue(self.handler._guard('/api/exit'))

    def test_guard_blocks_other_api_when_killed(self):
        with patch.object(srv.remote_control, 'is_app_killed', return_value=True):
            with patch.object(self.handler, '_reject') as mock_reject:
                allowed = self.handler._guard('/api/processes')
                self.assertFalse(allowed)
                mock_reject.assert_called_with(403, "התוכנה הושבתה מרחוק על ידי המפתח.")

    def test_guard_allows_api_when_not_killed(self):
        with patch.object(srv.remote_control, 'is_app_killed', return_value=False):
            self.assertTrue(self.handler._guard('/api/processes'))
            self.assertTrue(self.handler._guard('/api/stats'))

    def test_get_system_info_includes_app_version(self):
        info = srv.get_system_info()
        self.assertIn("app_version", info)
        self.assertEqual(info["app_version"], srv.APP_VERSION)


if __name__ == '__main__':
    unittest.main()

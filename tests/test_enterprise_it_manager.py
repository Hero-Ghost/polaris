"""
Unit tests for backend/enterprise_it_manager.py
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

from backend.enterprise_it_manager import (
    purge_kerberos_tickets,
    reset_group_policy,
    purge_domain_credentials,
    reset_entra_id_broker,
    reset_outlook_profile_cache,
    reset_network_drives,
    reset_proxy_winhttp,
    sync_intune_agent,
    reset_print_spooler_queue,
    purge_cert_crl_cache,
    get_enterprise_tools_list,
    execute_enterprise_tool,
    ENTERPRISE_TOOLS
)


class TestEnterpriseITManager(unittest.TestCase):

    def test_registry_has_10_tools(self):
        tools = get_enterprise_tools_list()
        self.assertEqual(len(tools), 10)
        self.assertEqual(len(ENTERPRISE_TOOLS), 10)

    @patch('backend.enterprise_it_manager.IS_WINDOWS', True)
    @patch('backend.enterprise_it_manager.run_hidden')
    def test_purge_kerberos_tickets(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        res = purge_kerberos_tickets()
        self.assertTrue(res['success'])
        self.assertIn("Kerberos", res['message'])

    @patch('backend.enterprise_it_manager.IS_WINDOWS', True)
    @patch('backend.enterprise_it_manager.run_hidden')
    def test_reset_group_policy(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "User Policy update has completed successfully."
        mock_run.return_value = mock_proc

        res = reset_group_policy()
        self.assertTrue(res['success'])
        self.assertIn("Group Policy", res['message'])

    @patch('backend.enterprise_it_manager.IS_WINDOWS', True)
    @patch('backend.enterprise_it_manager.run_hidden')
    def test_purge_domain_credentials(self, mock_run):
        list_output = """
Currently stored credentials:

    Target: MicrosoftOffice16_Data:live:cid=1234
    Type: Generic
    User: user@company.com

    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic
    User: user@company.com
"""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = list_output
        mock_run.return_value = mock_proc

        res = purge_domain_credentials()
        self.assertTrue(res['success'])
        self.assertEqual(res['deleted_count'], 2)

    @patch('backend.enterprise_it_manager.IS_WINDOWS', True)
    @patch('backend.enterprise_it_manager.run_hidden')
    def test_reset_entra_id_broker(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = reset_entra_id_broker()
        self.assertTrue(res['success'])
        self.assertIn("Entra ID", res['message'])

    @patch('backend.enterprise_it_manager.IS_WINDOWS', True)
    @patch('backend.enterprise_it_manager.run_hidden')
    def test_reset_outlook_profile_cache(self, mock_run):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            outlook_dir = os.path.join(tmpdir, 'Microsoft', 'Outlook')
            os.makedirs(outlook_dir, exist_ok=True)
            srs_file = os.path.join(outlook_dir, 'profile.srs')
            with open(srs_file, 'w') as f:
                f.write('dummy')

            with patch('os.environ.get', return_value=tmpdir):
                res = reset_outlook_profile_cache()
                self.assertTrue(res['success'])
                self.assertFalse(os.path.exists(srs_file))

    @patch('backend.enterprise_it_manager.IS_WINDOWS', True)
    @patch('backend.enterprise_it_manager.run_hidden')
    def test_reset_network_drives(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = reset_network_drives()
        self.assertTrue(res['success'])
        self.assertIn("כונני הרשת", res['message'])

    @patch('backend.enterprise_it_manager.IS_WINDOWS', True)
    @patch('backend.enterprise_it_manager.run_hidden')
    def test_reset_proxy_winhttp(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = reset_proxy_winhttp()
        self.assertTrue(res['success'])
        self.assertIn("Proxy", res['message'])

    @patch('backend.enterprise_it_manager.IS_WINDOWS', True)
    @patch('backend.enterprise_it_manager.run_hidden')
    def test_sync_intune_agent(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "TaskName: \\Microsoft\\Windows\\EnterpriseMgmt\\ABC\\Schedule to run OMADMClient by client"
        mock_run.return_value = mock_proc

        res = sync_intune_agent()
        self.assertTrue(res['success'])
        self.assertIn("Intune", res['message'])

    @patch('backend.enterprise_it_manager.IS_WINDOWS', True)
    @patch('backend.enterprise_it_manager.run_hidden')
    def test_reset_print_spooler_queue(self, mock_run):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            spool_dir = os.path.join(tmpdir, 'System32', 'spool', 'PRINTERS')
            os.makedirs(spool_dir, exist_ok=True)
            job = os.path.join(spool_dir, '0001.SPL')
            with open(job, 'w') as f:
                f.write('job')

            with patch('os.environ.get', return_value=tmpdir):
                res = reset_print_spooler_queue()
                self.assertTrue(res['success'])
                self.assertFalse(os.path.exists(job))

    @patch('backend.enterprise_it_manager.IS_WINDOWS', True)
    @patch('backend.enterprise_it_manager.run_hidden')
    def test_purge_cert_crl_cache(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = purge_cert_crl_cache()
        self.assertTrue(res['success'])
        self.assertIn("CRL", res['message'])

    def test_execute_enterprise_tool_dispatch(self):
        with patch.dict(ENTERPRISE_TOOLS, {'dummy_tool': {'handler': lambda: {'success': True, 'message': 'dummy'}}}):
            res = execute_enterprise_tool('dummy_tool')
            self.assertTrue(res['success'])
            self.assertEqual(res['message'], 'dummy')

        res_unknown = execute_enterprise_tool('non_existent')
        self.assertFalse(res_unknown['success'])


if __name__ == '__main__':
    unittest.main()

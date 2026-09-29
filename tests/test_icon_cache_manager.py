"""
Unit tests for backend/icon_cache_manager.py
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

from backend.icon_cache_manager import (
    get_icon_cache_paths,
    get_icon_cache_stats,
    notify_shell_refresh,
    rebuild_icon_cache
)


class TestIconCacheManager(unittest.TestCase):

    @patch('backend.icon_cache_manager.IS_WINDOWS', True)
    def test_get_icon_cache_paths(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            legacy_file = os.path.join(tmpdir, 'IconCache.db')
            with open(legacy_file, 'w') as f:
                f.write('dummy')

            explorer_dir = os.path.join(tmpdir, 'Microsoft', 'Windows', 'Explorer')
            os.makedirs(explorer_dir, exist_ok=True)
            db1 = os.path.join(explorer_dir, 'iconcache_32.db')
            db2 = os.path.join(explorer_dir, 'thumbcache_256.db')
            with open(db1, 'w') as f:
                f.write('dummy1')
            with open(db2, 'w') as f:
                f.write('dummy2')

            with patch('os.environ.get', return_value=tmpdir):
                paths = get_icon_cache_paths()
                self.assertEqual(len(paths), 3)
                self.assertIn(legacy_file, paths)
                self.assertIn(db1, paths)
                self.assertIn(db2, paths)

    @patch('backend.icon_cache_manager.IS_WINDOWS', True)
    def test_get_icon_cache_stats(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, 'IconCache.db')
            with open(test_file, 'wb') as f:
                f.write(b'x' * 1024)

            with patch('backend.icon_cache_manager.get_icon_cache_paths', return_value=[test_file]):
                stats = get_icon_cache_stats()
                self.assertTrue(stats['success'])
                self.assertEqual(stats['file_count'], 1)
                self.assertEqual(stats['total_bytes'], 1024)
                self.assertIn('IconCache.db', stats['files'])

    @patch('backend.icon_cache_manager.IS_WINDOWS', True)
    @patch('backend.icon_cache_manager.run_hidden')
    @patch('backend.icon_cache_manager.popen_visible')
    @patch('backend.icon_cache_manager.notify_shell_refresh')
    def test_rebuild_icon_cache_flow(self, mock_notify, mock_popen, mock_run):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            file1 = os.path.join(tmpdir, 'IconCache.db')
            file2 = os.path.join(tmpdir, 'iconcache_64.db')
            with open(file1, 'w') as f:
                f.write('content')
            with open(file2, 'w') as f:
                f.write('content2')

            with patch('backend.icon_cache_manager.get_icon_cache_paths', return_value=[file1, file2]):
                res = rebuild_icon_cache()
                self.assertTrue(res['success'])
                self.assertEqual(res['deleted_count'], 2)
                self.assertFalse(os.path.exists(file1))
                self.assertFalse(os.path.exists(file2))
                mock_run.assert_called_once()
                self.assertIn('taskkill.exe', mock_run.call_args[0][0])
                mock_popen.assert_called_once_with(['explorer.exe'])
                mock_notify.assert_called_once()


if __name__ == '__main__':
    unittest.main()

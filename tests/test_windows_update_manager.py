"""
Unit tests for backend/windows_update_manager.py.

All COM interactions are mocked so the tests run identically on Windows,
macOS, and Linux (CI).  We do NOT actually hide any real system updates.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.windows_update_manager import (
    WindowsUpdateManager,
    _make_update_dict,
    _translate_com_error,
    _WUA_ERRORS,
)


# ---------------------------------------------------------------------------
# Helper: build a mock IUpdate COM object
# ---------------------------------------------------------------------------

def _mock_update(
    uid="aaaa-bbbb",
    title="Test Update 1.0",
    description="A sample update",
    kb_ids=("5000001",),
    categories=("Drivers",),
    size=52428800,   # 50 MB
    is_hidden=False,
    is_mandatory=False,
):
    u = MagicMock()
    u.Identity.UpdateID = uid
    u.Title = title
    u.Description = description
    u.IsHidden = is_hidden
    u.IsMandatory = is_mandatory
    u.MaxDownloadSize = size

    # KBArticleIDs collection
    u.KBArticleIDs.Count = len(kb_ids)
    u.KBArticleIDs.Item.side_effect = lambda i: kb_ids[i]

    # Categories collection
    cat_mocks = [MagicMock(Name=c) for c in categories]
    u.Categories.Count = len(categories)
    u.Categories.Item.side_effect = lambda i: cat_mocks[i]

    return u


def _mock_search_result(updates):
    """Wrap a list of mock IUpdate objects in a mock ISearchResult."""
    result = MagicMock()
    result.Updates.Count = len(updates)
    result.Updates.Item.side_effect = lambda i: updates[i]
    return result


# ---------------------------------------------------------------------------
# Tests for _make_update_dict
# ---------------------------------------------------------------------------

class TestMakeUpdateDict(unittest.TestCase):

    def test_basic_fields(self):
        u = _mock_update(uid="x-1", title="Drv Update", kb_ids=("12345",), categories=("Drivers",), size=10*1024*1024)
        d = _make_update_dict(u)
        self.assertEqual(d["id"], "x-1")
        self.assertEqual(d["title"], "Drv Update")
        self.assertEqual(d["kb_numbers"], ["KB12345"])
        self.assertEqual(d["categories"], ["Drivers"])
        self.assertAlmostEqual(d["size_mb"], 10.0)
        self.assertFalse(d["is_hidden"])

    def test_multiple_kbs(self):
        u = _mock_update(kb_ids=("11111", "22222"))
        d = _make_update_dict(u)
        self.assertIn("KB11111", d["kb_numbers"])
        self.assertIn("KB22222", d["kb_numbers"])

    def test_no_kbs(self):
        u = _mock_update(kb_ids=())
        d = _make_update_dict(u)
        self.assertEqual(d["kb_numbers"], [])

    def test_hidden_update(self):
        u = _mock_update(is_hidden=True)
        d = _make_update_dict(u)
        self.assertTrue(d["is_hidden"])

    def test_zero_size(self):
        u = _mock_update(size=0)
        d = _make_update_dict(u)
        self.assertEqual(d["size_mb"], 0)

    def test_com_error_in_field_returns_partial(self):
        """If one field raises, we still get a dict (no crash)."""
        u = MagicMock()
        u.Identity.UpdateID = "e-1"
        u.Title = "Partial"
        u.Description = "desc"
        u.IsHidden = False
        u.IsMandatory = False
        u.MaxDownloadSize = 0
        # KBArticleIDs.Count raises
        u.KBArticleIDs.Count = 0
        u.Categories.Count = 0
        d = _make_update_dict(u)
        self.assertEqual(d["id"], "e-1")


# ---------------------------------------------------------------------------
# Tests for _translate_com_error
# ---------------------------------------------------------------------------

class TestTranslateComError(unittest.TestCase):

    def test_known_hresult_admin(self):
        # pywintypes.com_error args: (hresult, description, excepinfo, argerr)
        # excepinfo[5] = scode (the inner HRESULT: 0x80240044 = -2145124284)
        exc = Exception(-2147352567, "Exception occurred.", (0, None, None, None, 0, -2145124284), None)
        msg = _translate_com_error(exc)
        self.assertIn("מנהל", msg)

    def test_unknown_error_returns_string(self):
        exc = MagicMock()
        exc.args = [0xDEADBEEF]
        msg = _translate_com_error(exc)
        self.assertTrue(len(msg) > 0)


# ---------------------------------------------------------------------------
# Tests for WindowsUpdateManager (mocked COM)
# ---------------------------------------------------------------------------

@patch("backend.windows_update_manager.IS_WINDOWS", True)
@patch("backend.windows_update_manager._ensure_com")
class TestWindowsUpdateManager(unittest.TestCase):

    def _setup_searcher(self, mock_updates, mock_dispatch):
        """Wire up win32com.client.Dispatch → mock_searcher → mock Search."""
        searcher = MagicMock()
        session = MagicMock()
        session.CreateUpdateSearcher.return_value = searcher
        mock_dispatch.return_value = session
        result = _mock_search_result(mock_updates)
        searcher.Search.return_value = result
        return searcher

    @patch("win32com.client.Dispatch")
    def test_get_updates_returns_available_and_hidden(self, mock_dispatch, _ensure):
        u1 = _mock_update(uid="u1", title="Driver A", is_hidden=False)
        u2 = _mock_update(uid="u2", title="Driver B", is_hidden=True)
        self._setup_searcher([u1, u2], mock_dispatch)

        mgr = WindowsUpdateManager()
        result = mgr.get_updates(online=False)

        self.assertIsNone(result["error"])
        self.assertEqual(len(result["available"]), 1)
        self.assertEqual(result["available"][0]["id"], "u1")
        self.assertEqual(len(result["hidden"]), 1)
        self.assertEqual(result["hidden"][0]["id"], "u2")

    @patch("win32com.client.Dispatch")
    def test_get_updates_empty(self, mock_dispatch, _ensure):
        self._setup_searcher([], mock_dispatch)
        mgr = WindowsUpdateManager()
        result = mgr.get_updates()
        self.assertEqual(result["available"], [])
        self.assertEqual(result["hidden"], [])
        self.assertIsNone(result["error"])

    @patch("win32com.client.Dispatch")
    def test_get_updates_com_exception_returns_error(self, mock_dispatch, _ensure):
        session = MagicMock()
        session.CreateUpdateSearcher.side_effect = Exception("COM exploded")
        mock_dispatch.return_value = session

        mgr = WindowsUpdateManager()
        result = mgr.get_updates()
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["available"], [])

    @patch("win32com.client.Dispatch")
    def test_get_hidden_updates_only_hidden(self, mock_dispatch, _ensure):
        u1 = _mock_update(uid="h1", is_hidden=True)
        self._setup_searcher([u1], mock_dispatch)
        mgr = WindowsUpdateManager()
        result = mgr.get_hidden_updates()
        self.assertEqual(len(result["hidden"]), 1)
        self.assertEqual(result["hidden"][0]["id"], "h1")

    @patch("win32com.client.Dispatch")
    def test_set_update_hidden_success(self, mock_dispatch, _ensure):
        u1 = _mock_update(uid="aaa-111", title="Target Update")
        self._setup_searcher([u1], mock_dispatch)

        mgr = WindowsUpdateManager()
        result = mgr.set_update_hidden("aaa-111", hide=True)

        self.assertTrue(result["success"])
        self.assertIn("הוסתר", result["message"])
        # The COM object's IsHidden must have been set to True
        self.assertEqual(u1.IsHidden, True)

    @patch("win32com.client.Dispatch")
    def test_set_update_hidden_unhide(self, mock_dispatch, _ensure):
        u1 = _mock_update(uid="bbb-222", is_hidden=True)
        self._setup_searcher([u1], mock_dispatch)

        mgr = WindowsUpdateManager()
        result = mgr.set_update_hidden("bbb-222", hide=False)

        self.assertTrue(result["success"])
        self.assertIn("שוחזר", result["message"])
        self.assertEqual(u1.IsHidden, False)

    @patch("win32com.client.Dispatch")
    def test_set_update_hidden_not_found(self, mock_dispatch, _ensure):
        u1 = _mock_update(uid="ccc-333")
        self._setup_searcher([u1], mock_dispatch)

        mgr = WindowsUpdateManager()
        result = mgr.set_update_hidden("does-not-exist", hide=True)

        self.assertFalse(result["success"])
        self.assertIn("לא נמצא", result["message"])

    @patch("win32com.client.Dispatch")
    def test_set_update_hidden_case_insensitive_id(self, mock_dispatch, _ensure):
        u1 = _mock_update(uid="ABC-DEF")
        self._setup_searcher([u1], mock_dispatch)

        mgr = WindowsUpdateManager()
        result = mgr.set_update_hidden("abc-def", hide=True)
        self.assertTrue(result["success"])

    @patch("win32com.client.Dispatch")
    def test_set_update_hidden_by_kb_success(self, mock_dispatch, _ensure):
        u1 = _mock_update(uid="ddd-444", kb_ids=("5001234",))
        self._setup_searcher([u1], mock_dispatch)

        mgr = WindowsUpdateManager()
        result = mgr.set_update_hidden_by_kb("5001234", hide=True)
        self.assertTrue(result["success"])
        self.assertEqual(u1.IsHidden, True)

    @patch("win32com.client.Dispatch")
    def test_set_update_hidden_by_kb_not_found(self, mock_dispatch, _ensure):
        u1 = _mock_update(uid="eee-555", kb_ids=("9999999",))
        self._setup_searcher([u1], mock_dispatch)

        mgr = WindowsUpdateManager()
        result = mgr.set_update_hidden_by_kb("0000000", hide=True)
        self.assertFalse(result["success"])


# ---------------------------------------------------------------------------
# Tests for non-Windows graceful no-op
# ---------------------------------------------------------------------------

@patch("backend.windows_update_manager.IS_WINDOWS", False)
class TestWindowsUpdateManagerNonWindows(unittest.TestCase):

    def test_get_updates_returns_empty_lists(self):
        mgr = WindowsUpdateManager()
        result = mgr.get_updates()
        self.assertEqual(result["available"], [])
        self.assertEqual(result["hidden"], [])
        self.assertIsNone(result["error"])

    def test_get_hidden_updates_returns_empty(self):
        mgr = WindowsUpdateManager()
        result = mgr.get_hidden_updates()
        self.assertEqual(result["hidden"], [])

    def test_set_update_hidden_returns_simulated_ok(self):
        mgr = WindowsUpdateManager()
        result = mgr.set_update_hidden("any-id", hide=True)
        self.assertTrue(result["success"])

    def test_set_update_hidden_by_kb_returns_simulated_ok(self):
        mgr = WindowsUpdateManager()
        result = mgr.set_update_hidden_by_kb("KB123", hide=False)
        self.assertTrue(result["success"])

    def test_get_service_status_simulated_ok(self):
        mgr = WindowsUpdateManager()
        status = mgr.get_service_status()
        self.assertIn("service_name", status)
        self.assertEqual(status["service_name"], "wuauserv")
        self.assertFalse(status["is_disabled"])

    def test_toggle_service_simulated_ok(self):
        mgr = WindowsUpdateManager()
        res_dis = mgr.toggle_service("disable")
        self.assertTrue(res_dis["success"])
        self.assertTrue(res_dis["is_disabled"])

        res_en = mgr.toggle_service("enable")
        self.assertTrue(res_en["success"])
        self.assertFalse(res_en["is_disabled"])


if __name__ == "__main__":
    unittest.main()

"""
Polaris - End-to-End Deep Verification Script.
Checks:
1. HTML elements, IDs, attributes, hierarchy, and translations.
2. JS registry, SCREENS hooks, and function definitions.
3. Backend WindowsUpdateManager methods, responses, and threading.
4. Server REST API routes, status codes, and JSON responses with session token.
"""

import sys
import os
import re
import json
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.windows_update_manager import WindowsUpdateManager
from backend.server import wu_mgr, PolarisHandler, SESSION_TOKEN


class DeepSystemVerification(unittest.TestCase):

    def test_01_html_structure_and_ids(self):
        """Verify that all required HTML IDs, classes and tags exist in index.html."""
        html_path = os.path.join(BASE_DIR, "frontend", "index.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        required_ids = [
            "btnWuScan",
            "btnWuScanOnline",
            "wuScanStatus",
            "wuAvailCount",
            "wuHiddenCount",
            "wuBadgeAvail",
            "wuBadgeHidden",
            "navTagWuHidden",
            "wuAvailList",
            "wuHiddenList",
            "screen-windows_updates"
        ]

        for elem_id in required_ids:
            self.assertTrue(
                f'id="{elem_id}"' in html or f"id='{elem_id}'" in html,
                f"Missing required element #{elem_id} in index.html"
            )

        # Check sidebar nav button
        self.assertIn('data-category="windows_updates"', html)
        self.assertIn("goToCategory('windows_updates')", html)
        self.assertIn('data-i18n="navWuHide"', html)

        # Check top-level screen section
        self.assertIn('<section class="screen" id="screen-windows_updates">', html)

    def test_02_javascript_registry_and_translations(self):
        """Verify that JS SCREENS registry and I18N dictionaries contain the new screen."""
        js_path = os.path.join(BASE_DIR, "frontend", "app.js")
        with open(js_path, "r", encoding="utf-8") as f:
            js = f.read()

        # SCREENS registration
        self.assertIn("windows_updates:", js)
        self.assertIn("fetchWindowsUpdates(false)", js)

        # Translations
        self.assertIn('navWuHide: "הסתרת עדכוני Windows"', js)
        self.assertIn('wuHideDesc:', js)
        self.assertIn('navWuHide: "Windows Update Blocker"', js)

        # Function definitions
        self.assertIn("async function fetchWindowsUpdates(", js)
        self.assertIn("function renderWindowsUpdates(", js)
        self.assertIn("async function hideWindowsUpdate(", js)
        self.assertIn("async function unhideWindowsUpdate(", js)

        # No rogue apiFetch
        self.assertNotIn("apiFetch", js, "Forbidden apiFetch reference still found in app.js!")

    def test_03_backend_manager_direct(self):
        """Verify WindowsUpdateManager returns correct data contracts."""
        mgr = WindowsUpdateManager()
        res = mgr.get_updates(online=False)
        self.assertIsInstance(res, dict)
        self.assertIn("available", res)
        self.assertIn("hidden", res)
        self.assertIn("admin", res)
        self.assertIn("error", res)
        self.assertIsInstance(res["available"], list)
        self.assertIsInstance(res["hidden"], list)

        # Verify items contract if any are available
        for item in res["available"]:
            self.assertIn("id", item)
            self.assertIn("title", item)
            self.assertIn("is_hidden", item)
            self.assertIn("categories", item)
            self.assertIn("kb_numbers", item)

        hidden_res = mgr.get_hidden_updates()
        self.assertIsInstance(hidden_res, dict)
        self.assertIn("hidden", hidden_res)

    def test_04_server_routes_integrated(self):
        """Verify that backend server.py routes handle the API paths properly."""
        import http.server
        from io import BytesIO
        from unittest.mock import MagicMock

        # Create a mock HTTP handler to test route dispatch
        handler = PolarisHandler.__new__(PolarisHandler)
        handler.command = "GET"
        handler.headers = {
            "X-Polaris-Token": SESSION_TOKEN,
            "Host": "127.0.0.1:8000"
        }
        
        sent_data = []
        def mock_send(data):
            sent_data.append(data)
        handler.send_json_response = mock_send

        # Test GET /api/windows_updates/list
        handler.path = "/api/windows_updates/list?online=0"
        handler.do_GET()
        self.assertEqual(len(sent_data), 1)
        self.assertIn("available", sent_data[0])

        # Test GET /api/windows_updates/hidden
        handler.path = "/api/windows_updates/hidden"
        handler.do_GET()
        self.assertEqual(len(sent_data), 2)
        self.assertIn("hidden", sent_data[1])

        # Test POST /api/windows_updates/hide with missing id
        sent_data.clear()
        handler.command = "POST"
        handler.path = "/api/windows_updates/hide"
        # Mock rfile
        body = json.dumps({}).encode('utf-8')
        handler.rfile = BytesIO(body)
        handler.headers["Content-Length"] = str(len(body))
        handler.headers["Content-Type"] = "application/json"
        handler.do_POST()
        self.assertEqual(len(sent_data), 1)
        self.assertFalse(sent_data[0]["success"])
        self.assertIn("חסר", sent_data[0]["message"])

    def test_05_all_16_screens_and_sidebar_buttons(self):
        """Verify that all 16 screens exist in HTML, sidebar buttons exist, and JS registers them."""
        html_path = os.path.join(BASE_DIR, "frontend", "index.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        js_path = os.path.join(BASE_DIR, "frontend", "app.js")
        with open(js_path, "r", encoding="utf-8") as f:
            js = f.read()

        expected_screens = [
            "overview",
            "processes",
            "memory",
            "disks",
            "storage",
            "maintenance",
            "uninstaller",
            "startup",
            "crashes",
            "events",
            "devices",
            "windows_updates",
            "oem_updates",
            "battery",
            "tools",
            "settings"
        ]

        for s in expected_screens:
            # Check screen section
            self.assertIn(f'id="screen-{s}"', html, f"Screen section #screen-{s} missing in index.html!")
            # Check sidebar button
            self.assertIn(f'data-screen="{s}"', html, f"Sidebar button for {s} missing in index.html!")
            # Check JS CATEGORIES
            self.assertIn(f'{s}:', js, f"Category {s} missing in app.js!")

    def test_06_javascript_syntax_validity(self):
        """Verify that frontend/app.js has zero syntax errors."""
        try:
            import tree_sitter_javascript as tsjs
            from tree_sitter import Language, Parser
            JS_LANGUAGE = Language(tsjs.language())
            parser = Parser(JS_LANGUAGE)
            js_path = os.path.join(BASE_DIR, "frontend", "app.js")
            with open(js_path, "rb") as f:
                code = f.read()
            tree = parser.parse(code)
            errors = []
            def find_errors(node):
                if node.is_error or node.is_missing:
                    errors.append((node.start_point, node.type, code[node.start_byte:min(node.start_byte+50, node.end_byte)]))
                for child in node.children:
                    find_errors(child)
            find_errors(tree.root_node)
            self.assertEqual(len(errors), 0, f"Syntax errors found in app.js: {errors[:5]}")
        except ImportError:
            pass


if __name__ == "__main__":
    unittest.main()

"""
Unit tests for the Polaris OEM update manager (Dell, Lenovo, HP, Universal).
Tests manufacturer normalization, tool cataloging, logging revisions,
and async execution safety.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.oem_update_manager import OemUpdateManager, check_pending_reboot


class TestOemUpdateManager(unittest.TestCase):
    def setUp(self):
        self.mgr = OemUpdateManager()

    def test_normalize_manufacturer_dell(self):
        test_cases = [
            ("Dell Inc.", "OptiPlex 7090"),
            ("DELL", "XPS 15 9520"),
            ("Alienware", "Aurora R13"),
            ("Dell Inc.", "Latitude 5420"),
            ("Dell", "Precision 5560"),
            ("Dell Inc.", "Inspiron 16"),
            ("DELL", "Vostro 3510"),
        ]
        for mfr, model in test_cases:
            res = self.mgr._normalize_manufacturer(mfr, model)
            self.assertEqual(res, "Dell", f"Failed for {mfr} {model}")

    def test_normalize_manufacturer_lenovo(self):
        test_cases = [
            ("LENOVO", "21AH00EGIV"),
            ("Lenovo", "ThinkPad T14 Gen 3"),
            ("Lenovo", "IdeaPad 5 Pro"),
            ("Lenovo", "Legion 5 15ACH6H"),
            ("LENOVO", "ThinkBook 14"),
        ]
        for mfr, model in test_cases:
            res = self.mgr._normalize_manufacturer(mfr, model)
            self.assertEqual(res, "Lenovo", f"Failed for {mfr} {model}")

    def test_normalize_manufacturer_hp(self):
        test_cases = [
            ("HP", "HP EliteBook 840 G8 Notebook PC"),
            ("Hewlett-Packard", "HP ProBook 450 G7"),
            ("HP", "OMEN by HP Laptop 16"),
            ("HP", "Victus by HP 16"),
            ("HP", "HP ENVY x360"),
            ("HP", "HP Pavilion Laptop"),
            ("HP", "HP Spectre x360"),
        ]
        for mfr, model in test_cases:
            res = self.mgr._normalize_manufacturer(mfr, model)
            self.assertEqual(res, "HP", f"Failed for {mfr} {model}")

    def test_normalize_manufacturer_placeholders_and_generic(self):
        placeholders = [
            ("To be filled by O.E.M.", "To be filled by O.E.M."),
            ("System manufacturer", "System Product Name"),
            ("Default string", "Default string"),
            ("Base Board", "Product Name"),
            ("Unknown", "Unknown"),
            ("", ""),
        ]
        for mfr, model in placeholders:
            res = self.mgr._normalize_manufacturer(mfr, model)
            self.assertEqual(res, "Universal", f"Failed for placeholder {mfr} {model}")

    def test_normalize_manufacturer_other(self):
        other_cases = [
            ("ASUSTeK COMPUTER INC.", "ROG Zephyrus G14"),
            ("Acer", "Predator PH315-53"),
            ("Micro-Star International Co., Ltd.", "MS-7C96"),
            ("Gigabyte Technology Co., Ltd.", "B550 AORUS ELITE"),
        ]
        for mfr, model in other_cases:
            res = self.mgr._normalize_manufacturer(mfr, model)
            self.assertEqual(res, "Other", f"Failed for {mfr} {model}")

    def test_tool_status_catalog(self):
        for brand, keyword in [
            ("Dell", "Dell Command | Update"),
            ("Lenovo", "System Update"),
            ("HP", "HP Image Assistant"),
            ("Universal", "SDIO"),
            ("Other", "SDIO"),
        ]:
            st = self.mgr.get_tool_status(brand)
            self.assertIn("tool_name", st)
            self.assertIn("can_auto_install", st)
            self.assertTrue(st["can_auto_install"])
            self.assertIn(keyword.lower(), st["tool_name"].lower())

    def test_logging_and_revisions(self):
        initial_rev = self.mgr.log_rev
        self.mgr.log("First informational line", "INFO")
        self.mgr.log("Second warning line", "WARN")

        self.assertGreater(self.mgr.log_rev, initial_rev)

        progress = self.mgr.get_progress(since_log_id=initial_rev)
        self.assertIn("new_logs", progress)
        self.assertEqual(len(progress["new_logs"]), 2)
        self.assertEqual(progress["new_logs"][0]["text"], "First informational line")
        self.assertEqual(progress["new_logs"][0]["level"], "INFO")
        self.assertEqual(progress["new_logs"][1]["text"], "Second warning line")
        self.assertEqual(progress["new_logs"][1]["level"], "WARN")

        # Querying since current rev should return 0 new logs
        progress_after = self.mgr.get_progress(since_log_id=self.mgr.log_rev)
        self.assertEqual(len(progress_after["new_logs"]), 0)

    def test_get_oem_info_structure(self):
        info = self.mgr.get_oem_info()
        required_keys = [
            "manufacturer", "selected_manufacturer", "raw_manufacturer",
            "model", "serial", "tool", "pending_reboot", "is_admin",
            "is_running", "last_results"
        ]
        for k in required_keys:
            self.assertIn(k, info, f"Missing key '{k}' in get_oem_info()")

    def test_get_oem_info_with_override(self):
        info = self.mgr.get_oem_info(override_manufacturer="Dell")
        self.assertEqual(info["selected_manufacturer"], "Dell")
        self.assertIn("Dell Command | Update", info["tool"]["tool_name"])

        info_hp = self.mgr.get_oem_info(override_manufacturer="HP")
        self.assertEqual(info_hp["selected_manufacturer"], "HP")
        self.assertIn("HP Image Assistant", info_hp["tool"]["tool_name"])

    def test_cancel_mechanics_when_idle(self):
        res = self.mgr.cancel_updates()
        self.assertTrue(res.get("success"))

    def test_check_pending_reboot_callable(self):
        # Must return boolean without throwing
        res = check_pending_reboot()
        self.assertIsInstance(res, bool)

    def test_dell_tool_status_includes_dotnet_runtimes(self):
        st = self.mgr.get_tool_status("Dell")
        self.assertIn("dotnet_8_installed", st)
        self.assertIn("dotnet_10_installed", st)
        self.assertIsInstance(st["dotnet_8_installed"], bool)
        self.assertIsInstance(st["dotnet_10_installed"], bool)
        self.assertIn(".NET", st["details_he"])
        self.assertIn(".NET", st["details_en"])

    def test_is_dotnet_desktop_installed_callable(self):
        res8 = self.mgr._is_dotnet_desktop_installed("8")
        res10 = self.mgr._is_dotnet_desktop_installed("10")
        self.assertIsInstance(res8, bool)
        self.assertIsInstance(res10, bool)

    def test_install_dotnet_methods_exist(self):
        self.assertTrue(callable(getattr(self.mgr, "install_dotnet_8", None)))
        self.assertTrue(callable(getattr(self.mgr, "install_dotnet_10", None)))


if __name__ == "__main__":
    unittest.main()

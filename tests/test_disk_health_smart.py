"""
Unit tests for Polaris S.M.A.R.T. Engine, Database, and DiskHealthAnalyzer.
"""

import unittest
from backend.smart_database import (
    SMART_ATTRIBUTES,
    NVME_LOG_FIELDS,
    detect_ssd_vendor,
    evaluate_disk_health,
)
from backend.smart_engine import smart_engine
from backend.disk_health import DiskHealthAnalyzer


class TestSmartDatabase(unittest.TestCase):
    """Tests for S.M.A.R.T. dictionary definitions and vendor mapping."""

    def test_smart_attribute_definitions(self):
        self.assertIn(0x05, SMART_ATTRIBUTES)
        reallocated = SMART_ATTRIBUTES[0x05]
        self.assertIn("סקטורים שהוקצו מחדש", reallocated["name_he"])
        self.assertEqual(reallocated["name_en"], "Reallocated Sectors Count")
        self.assertTrue(reallocated["critical"])

        self.assertIn(0xC5, SMART_ATTRIBUTES)
        pending = SMART_ATTRIBUTES[0xC5]
        self.assertIn("סקטורים פגומים בהמתנה", pending["name_he"])
        self.assertTrue(pending["critical"])

        self.assertIn(0xE7, SMART_ATTRIBUTES)
        ssd_life = SMART_ATTRIBUTES[0xE7]
        self.assertIn("אחוז חיי SSD", ssd_life["name_he"])

    def test_nvme_log_definitions(self):
        self.assertIn("critical_warning", NVME_LOG_FIELDS)
        self.assertIn("temperature", NVME_LOG_FIELDS)
        self.assertIn("available_spare", NVME_LOG_FIELDS)
        self.assertIn("percentage_used", NVME_LOG_FIELDS)

        crit = NVME_LOG_FIELDS["critical_warning"]
        self.assertTrue(crit["critical"])
        self.assertIn("התרעה קריטית", crit["name_he"])

    def test_vendor_detection(self):
        self.assertEqual(detect_ssd_vendor("WDC PC SN720 SDAPNTW-512G-1006"), "WD_SANDISK")
        self.assertEqual(detect_ssd_vendor("Samsung SSD 980 PRO 1TB"), "SAMSUNG")
        self.assertEqual(detect_ssd_vendor("Crucial CT1000P3SSD8"), "CRUCIAL_MICRON")
        self.assertEqual(detect_ssd_vendor("KINGSTON SA400S37480G"), "KINGSTON")
        self.assertEqual(detect_ssd_vendor("Generic Unknown Disk"), "GENERIC")

    def test_health_evaluation_healthy_nvme(self):
        info = {
            "is_nvme": True,
            "critical_warning": 0,
            "available_spare": 100,
            "available_spare_threshold": 10,
            "wear_percent": 5,
            "media_errors": 0,
            "temperature_c": 45,
        }
        res = evaluate_disk_health(info)
        self.assertEqual(res["status"], "Good")
        self.assertEqual(res["status_he"], "תקין")
        self.assertEqual(res["life_remaining_percent"], 95)
        self.assertEqual(res["tone"], "success")
        self.assertEqual(len(res["reasons_he"]), 0)

    def test_health_evaluation_critical_nvme(self):
        info = {
            "is_nvme": True,
            "critical_warning": 0x01,  # Available spare below threshold
            "available_spare": 5,
            "available_spare_threshold": 10,
            "wear_percent": 98,
            "media_errors": 12,
            "temperature_c": 50,
        }
        res = evaluate_disk_health(info)
        self.assertEqual(res["status"], "Bad")
        self.assertEqual(res["status_he"], "סכנה")
        self.assertEqual(res["tone"], "danger")
        self.assertGreater(len(res["reasons_he"]), 0)

    def test_health_evaluation_failing_sata(self):
        info = {
            "is_nvme": False,
            "media_type": "HDD",
            "attributes_map": {
                0x05: {"raw_value": 45},  # Reallocated sectors
                0xC5: {"raw_value": 8},   # Pending sectors
            },
            "temperature_c": 40,
        }
        res = evaluate_disk_health(info)
        self.assertEqual(res["status"], "Bad")
        self.assertEqual(res["status_he"], "סכנה")
        self.assertEqual(res["tone"], "danger")


class TestDiskHealthAnalyzer(unittest.TestCase):
    """Integration test for DiskHealthAnalyzer report generation."""

    def test_get_report_structure(self):
        analyzer = DiskHealthAnalyzer()
        rep = analyzer.get_report()

        self.assertTrue(rep["supported"])
        self.assertIn("disks", rep)
        self.assertIn("findings", rep)
        self.assertIn("overall", rep)
        self.assertIn("overall_he", rep)

        if rep["disks"]:
            disk = rep["disks"][0]
            self.assertIn("name", disk)
            self.assertIn("health_status", disk)
            self.assertIn("volumes", disk)
            self.assertIn("attributes", disk)
            if disk.get("is_nvme"):
                self.assertIsNotNone(disk.get("temperature_c"))
                self.assertIsNotNone(disk.get("wear_percent"))
                self.assertIsNotNone(disk.get("life_remaining_percent"))

    def test_analyze_disk_healthy_statuses(self):
        analyzer = DiskHealthAnalyzer()
        for healthy_status in ("Good", "Healthy", "OK", "Pass", "good", "healthy", "ok"):
            disk = {
                "name": "Test Disk",
                "health_status": healthy_status,
                "wear_percent": 10,
                "read_errors": 0,
                "write_errors": 0,
                "media_errors": 0,
                "critical_warning": 0,
                "temperature_c": 35,
                "media_type": "SSD",
                "power_on_hours": 100,
                "power_on_years": 0.1,
                "volumes": []
            }
            findings = analyzer._analyze_disk(disk)
            self.assertEqual(len(findings), 0, f"Expected 0 findings for status {healthy_status}, got: {findings}")
            disk["findings"] = findings
            tone = analyzer._disk_tone(disk)
            self.assertEqual(tone, "ok", f"Expected tone 'ok' for status {healthy_status}, got: {tone}")

    def test_analyze_disk_unhealthy_statuses(self):
        analyzer = DiskHealthAnalyzer()
        for bad_status in ("Bad", "Caution", "Pred Fail", "Unhealthy", "Degraded"):
            disk = {
                "name": "Failing Disk",
                "health_status": bad_status,
                "wear_percent": 10,
                "read_errors": 0,
                "write_errors": 0,
                "media_errors": 0,
                "critical_warning": 0,
                "temperature_c": 35,
                "media_type": "SSD",
                "power_on_hours": 100,
                "power_on_years": 0.1,
                "volumes": []
            }
            findings = analyzer._analyze_disk(disk)
            self.assertGreater(len(findings), 0, f"Expected finding for bad status {bad_status}")
            self.assertEqual(findings[0]["severity"], "high")
            disk["findings"] = findings
            tone = analyzer._disk_tone(disk)
            self.assertEqual(tone, "danger", f"Expected tone 'danger' for status {bad_status}, got: {tone}")


if __name__ == "__main__":
    unittest.main()

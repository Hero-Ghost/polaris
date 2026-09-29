"""
Unit tests for Polaris Minidump & BSOD Crash Diagnostic Engine
Tests binary dump parsing (MDMP, PAGEDU64, PAGEDUMP), culprit driver heuristics,
and online intelligence enrichment.
"""

import os
import struct
import tempfile
import unittest

from backend.minidump_parser import (
    MinidumpParser,
    STREAM_MODULE_LIST,
    STREAM_EXCEPTION,
    STREAM_SYSTEM_INFO
)
from backend.driver_database import (
    DRIVER_REGISTRY,
    BUGCHECK_DATABASE,
    CulpritResolver,
    CAT_GPU,
    CAT_NETWORK_WIFI,
    CAT_RGB_OVERCLOCK,
    CAT_ANTI_CHEAT
)
from backend.driver_online_checker import DriverOnlineChecker
from backend.crash_analyzer import CrashAnalyzer


class TestMinidumpParser(unittest.TestCase):
    """
    Tests binary parser on synthetic MDMP and PAGEDU64 dumps.
    """

    def test_parse_synthetic_mdmp(self):
        """
        Builds a valid binary MDMP minidump in memory and verifies extraction
        of streams, exception record, and module table mapping.
        """
        mod_name_str = "nvlddmkm.sys\x00".encode("utf-16-le")
        mod_name_block = struct.pack("<I", len(mod_name_str)) + mod_name_str

        fault_rip = 0xFFFFF80110002500
        ctx_data = bytearray(300)
        ctx_data[248:256] = struct.pack("<Q", fault_rip)

        sys_data = struct.pack("<HHHBBIIIII", 9, 6, 1, 8, 1, 10, 0, 19045, 2, 0)

        num_streams = 3
        rva_header = 0
        rva_dir = 32
        rva_sys = rva_dir + (num_streams * 12)
        rva_ctx = rva_sys + len(sys_data)
        rva_exc = rva_ctx + len(ctx_data)
        rva_mod_name = rva_exc + 168
        rva_mod_list = rva_mod_name + len(mod_name_block)

        exc_data = struct.pack(
            "<IIIIQQ",
            1234, 0, 0x116, 0, 0, fault_rip
        ) + struct.pack("<I", 0) + b"\x00" * 124 + struct.pack("<II", len(ctx_data), rva_ctx)

        mod_entry = struct.pack(
            "<QIIII",
            0xFFFFF80110000000, 0x2000000, 0x123456, 1700000000, rva_mod_name
        ) + struct.pack("<II", (31 << 16) | 0, (15 << 16) | 200) + b"\x00" * 76
        mod_list_data = struct.pack("<I", 1) + mod_entry

        header = struct.pack("<4sIIIIIQ", b"MDMP", 0xA1A10000, num_streams, rva_dir, 0, 1700000000, 0)
        dir_data = (
            struct.pack("<III", STREAM_SYSTEM_INFO, len(sys_data), rva_sys) +
            struct.pack("<III", STREAM_EXCEPTION, len(exc_data), rva_exc) +
            struct.pack("<III", STREAM_MODULE_LIST, len(mod_list_data), rva_mod_list)
        )

        full_dmp = header + dir_data + sys_data + ctx_data + exc_data + mod_name_block + mod_list_data

        with tempfile.NamedTemporaryFile(suffix=".dmp", delete=False) as tf:
            tf.write(full_dmp)
            tf_path = tf.name

        try:
            parser = MinidumpParser(tf_path)
            res = parser.parse()

            self.assertTrue(res["success"])
            self.assertEqual(res["format_type"], "MDMP")
            self.assertEqual(res["architecture"], "x64 (AMD64)")
            self.assertEqual(res["os_build"], 19045)
            self.assertEqual(res["bugcheck_code"], "0x00000116")
            self.assertEqual(len(res["modules"]), 1)
            self.assertEqual(res["modules"][0]["name"], "nvlddmkm.sys")
            self.assertIsNotNone(res["culprit_driver"])
            self.assertEqual(res["culprit_driver"]["name"], "nvlddmkm.sys")
            self.assertEqual(res["culprit_driver"]["matched_by"], "Context RIP")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_parse_synthetic_kernel_dump64(self):
        """
        Tests parsing 64-bit kernel dump header (_DMP_HEADER64 with signature PAGEDU64).
        """
        data = bytearray(8192)
        data[0:8] = b"PAGEDU64"
        data[8:16] = struct.pack("<II", 10, 0)
        data[0x28:0x2C] = struct.pack("<I", 0xD1)
        p1, p2, p3, p4 = 0xFFFFF80012340000, 2, 0, 0xFFFFF80056781200
        data[0x30:0x50] = struct.pack("<QQQQ", p1, p2, p3, p4)
        data[0xF8:0xFC] = struct.pack("<I", 0x8664)

        with tempfile.NamedTemporaryFile(suffix=".dmp", delete=False) as tf:
            tf.write(bytes(data))
            tf_path = tf.name

        try:
            parser = MinidumpParser(tf_path)
            res = parser.parse()

            self.assertTrue(res["success"])
            self.assertEqual(res["format_type"], "KERNEL_DUMP64")
            self.assertEqual(res["architecture"], "x64 (AMD64)")
            self.assertEqual(res["bugcheck_code"], "0x000000D1")
            self.assertEqual(res["bugcheck_parameters_raw"][3], p4)
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)


class TestCulpritResolver(unittest.TestCase):
    """
    Tests advanced heuristics to pinpoint culprit drivers and overcome ntoskrnl.exe disguise.
    """

    def test_resolve_video_tdr_gpu(self):
        """
        0x116 Video TDR failure with modules list containing NVIDIA nvlddmkm.sys.
        """
        modules = [
            {"name": "ntoskrnl.exe", "base_address": 0xFFFFF80000000000, "end_address": 0xFFFFF80001000000},
            {"name": "dxgkrnl.sys", "base_address": 0xFFFFF80002000000, "end_address": 0xFFFFF80002500000},
            {"name": "nvlddmkm.sys", "base_address": 0xFFFFF80010000000, "end_address": 0xFFFFF80012000000}
        ]

        res = CulpritResolver.resolve(
            bugcheck_code=0x116,
            params=[0, 0, 0, 0],
            exception_address=0xFFFFF80000100000,
            context_rip=0,
            modules=modules
        )

        self.assertEqual(res["driver_name"], "nvlddmkm.sys")
        self.assertGreaterEqual(res["confidence_score"], 95)
        self.assertEqual(res["driver_info"]["category"], CAT_GPU)
        self.assertIn("NVIDIA", res["driver_info"]["vendor"])

    def test_resolve_driver_irql_param4(self):
        """
        0xD1 Driver IRQL error where Param 4 holds the faulting instruction inside Realtek Wi-Fi rtwlane.sys.
        """
        fault_instruction = 0xFFFFF80030004500
        modules = [
            {"name": "ntoskrnl.exe", "base_address": 0xFFFFF80000000000, "end_address": 0xFFFFF80001000000},
            {"name": "rtwlane.sys", "base_address": 0xFFFFF80030000000, "end_address": 0xFFFFF80030500000}
        ]

        res = CulpritResolver.resolve(
            bugcheck_code=0xD1,
            params=[0xFFFFF80099990000, 2, 0, fault_instruction],
            exception_address=0,
            context_rip=0,
            modules=modules
        )

        self.assertEqual(res["driver_name"], "rtwlane.sys")
        self.assertEqual(res["confidence_score"], 95)
        self.assertEqual(res["driver_info"]["category"], CAT_NETWORK_WIFI)

    def test_resolve_asus_rgb_high_risk(self):
        """
        0x3B crash with ASUS Armoury Crate asio.sys identified via RIP register.
        """
        rip_addr = 0xFFFFF80040001200
        modules = [
            {"name": "ntoskrnl.exe", "base_address": 0xFFFFF80000000000, "end_address": 0xFFFFF80001000000},
            {"name": "asio.sys", "base_address": 0xFFFFF80040000000, "end_address": 0xFFFFF80040020000}
        ]

        res = CulpritResolver.resolve(
            bugcheck_code=0x3B,
            params=[0, 0, 0, 0],
            exception_address=0,
            context_rip=rip_addr,
            modules=modules
        )

        self.assertEqual(res["driver_name"], "asio.sys")
        self.assertEqual(res["confidence_score"], 98)
        self.assertEqual(res["driver_info"]["category"], CAT_RGB_OVERCLOCK)
        self.assertEqual(res["driver_info"]["risk_level"], "Critical")

    def test_resolve_anti_cheat(self):
        """
        Kernel crash with Riot Vanguard vgk.sys or BattlEye bedaisy.sys.
        """
        exc_addr = 0xFFFFF80060005000
        modules = [
            {"name": "ntoskrnl.exe", "base_address": 0xFFFFF80000000000, "end_address": 0xFFFFF80001000000},
            {"name": "vgk.sys", "base_address": 0xFFFFF80060000000, "end_address": 0xFFFFF80060100000}
        ]

        res = CulpritResolver.resolve(
            bugcheck_code=0x0A,
            params=[0, 0, 0, 0],
            exception_address=exc_addr,
            context_rip=0,
            modules=modules
        )

        self.assertEqual(res["driver_name"], "vgk.sys")
        self.assertEqual(res["driver_info"]["category"], CAT_ANTI_CHEAT)
        self.assertIn("Riot Games", res["driver_info"]["vendor"])


class TestDriverOnlineChecker(unittest.TestCase):
    """
    Tests online intelligence queries and link generation.
    """

    def test_enrich_driver_online(self):
        intel = DriverOnlineChecker.enrich(
            driver_name="nvlddmkm.sys",
            bugcheck_code=0x116,
            bugcheck_name="VIDEO_TDR_FAILURE",
            vendor="NVIDIA"
        )

        self.assertEqual(intel["driver_searched"], "nvlddmkm.sys")
        self.assertIn("google.com", intel["google_search_url"])
        self.assertIn("learn.microsoft.com", intel["ms_docs_url"])
        self.assertIn("nvidia.com", intel["vendor_download_url"])
        self.assertIn("DDU", intel["online_summary_he"])


class TestCrashAnalyzerIntegration(unittest.TestCase):
    """
    Tests end-to-end crash analysis with CrashAnalyzer.
    """

    def test_get_crash_history_structure(self):
        analyzer = CrashAnalyzer()
        history = analyzer.get_crash_history(limit=5)
        self.assertIn("crashes", history)
        self.assertIn("total_crashes", history)
        self.assertIn("health_status", history)

    def test_lookup_driver_online_api(self):
        analyzer = CrashAnalyzer()
        intel = analyzer.lookup_driver_online("asio.sys", 0x3B)
        self.assertEqual(intel["driver_searched"], "asio.sys")
        self.assertIn("RGB", intel["online_summary_he"])


if __name__ == "__main__":
    unittest.main()

"""
Unit tests for the Polaris Storage Analyzer (WinDirStat engine).
Verifies cushion treemap data extraction, directory tree aggregation,
extension breakdown, duplicate file detection, <Unknown> space calculation,
and deletion safety blacklists.
"""

import os
import sys
import shutil
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.storage_analyzer import (
    StorageNode,
    StorageAnalyzer,
    PROTECTED_PATHS,
    WDS_PALETTE,
)


class TestStorageNode(unittest.TestCase):

    def test_node_creation_and_attributes(self):
        node = StorageNode(1, "test_folder", "/path/to/test", is_dir=True)
        self.assertEqual(node.id, 1)
        self.assertEqual(node.name, "test_folder")
        self.assertEqual(node.path, "/path/to/test")
        self.assertTrue(node.is_dir)
        self.assertEqual(node.size, 0)
        self.assertEqual(node.file_count, 0)
        self.assertEqual(node.dir_count, 0)
        self.assertEqual(node.children, [])

    def test_file_node_creation(self):
        file_node = StorageNode(2, "image.png", "/path/to/image.png", is_dir=False, size=2048, extension=".png")
        self.assertEqual(file_node.id, 2)
        self.assertFalse(file_node.is_dir)
        self.assertEqual(file_node.size, 2048)
        self.assertEqual(file_node.file_count, 1)
        self.assertIsNone(file_node.children)

    def test_to_dict_depth_limiting(self):
        root = StorageNode(1, "root", "C:\\root", is_dir=True, size=3000)
        sub = StorageNode(2, "sub", "C:\\root\\sub", is_dir=True, size=2000)
        subsub = StorageNode(3, "subsub", "C:\\root\\sub\\subsub", is_dir=True, size=1000)
        file1 = StorageNode(4, "leaf.txt", "C:\\root\\sub\\subsub\\leaf.txt", is_dir=False, size=1000, extension=".txt")

        subsub.children.append(file1)
        sub.children.append(subsub)
        root.children.append(sub)

        d_depth_1 = root.to_dict(include_children=True, depth=1)
        self.assertEqual(len(d_depth_1["children"]), 1)
        self.assertNotIn("children", d_depth_1["children"][0])

        d_depth_3 = root.to_dict(include_children=True, depth=3)
        self.assertEqual(len(d_depth_3["children"][0]["children"]), 1)
        self.assertEqual(d_depth_3["children"][0]["children"][0]["name"], "subsub")


class TestDeletionSafetyGuard(unittest.TestCase):

    def setUp(self):
        self.analyzer = StorageAnalyzer()

    def test_system_root_is_blocked(self):
        ok, msg = self.analyzer.perform_action("recycle", r"C:\Windows")
        self.assertFalse(ok)
        self.assertIn("protected", msg.lower())

        ok, msg = self.analyzer.perform_action("delete_permanent", r"C:\Windows\System32")
        self.assertFalse(ok)
        self.assertIn("protected", msg.lower())

    def test_drive_roots_are_blocked(self):
        ok, msg = self.analyzer.perform_action("recycle", r"C:\\")
        self.assertFalse(ok)
        self.assertIn("protected", msg.lower())

        ok, msg = self.analyzer.perform_action("delete_permanent", r"D:\\")
        self.assertFalse(ok)
        self.assertIn("protected", msg.lower())

    def test_protected_windows_files_are_blocked(self):
        ok, msg = self.analyzer.perform_action("recycle", r"C:\pagefile.sys")
        self.assertFalse(ok)
        self.assertIn("protected", msg.lower())

        ok, msg = self.analyzer.perform_action("delete_permanent", r"C:\hiberfil.sys")
        self.assertFalse(ok)
        self.assertIn("protected", msg.lower())

    def test_nonexistent_path_fails_gracefully(self):
        ok, msg = self.analyzer.perform_action("recycle", r"C:\NonExistentTestFolder_XYZ123")
        self.assertFalse(ok)


class TestStorageAnalyzerFullScan(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.analyzer = StorageAnalyzer()

        # Build mock file tree
        # test_dir/
        #   sub1/
        #     doc1.txt (500 bytes)
        #     doc2.txt (500 bytes) -> duplicate of doc1
        #   sub2/
        #     nested/
        #       image.png (2000 bytes)
        #   top_large.bin (10000 bytes)
        sub1 = os.path.join(self.test_dir, "sub1")
        sub2 = os.path.join(self.test_dir, "sub2")
        nested = os.path.join(sub2, "nested")
        os.makedirs(sub1)
        os.makedirs(nested)

        dup_content = b"A" * 500
        with open(os.path.join(sub1, "doc1.txt"), "wb") as f:
            f.write(dup_content)
        with open(os.path.join(sub1, "doc2.txt"), "wb") as f:
            f.write(dup_content)

        with open(os.path.join(nested, "image.png"), "wb") as f:
            f.write(b"B" * 2000)

        with open(os.path.join(self.test_dir, "top_large.bin"), "wb") as f:
            f.write(b"C" * 10000)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_scan_aggregates_and_progress(self):
        ok, msg = self.analyzer.start_scan([self.test_dir])
        self.assertTrue(ok, msg)

        # Wait for scan completion
        max_wait = 10
        start = time.time()
        while self.analyzer.status == "scanning" and (time.time() - start < max_wait):
            time.sleep(0.05)

        self.assertEqual(self.analyzer.status, "completed")

        progress = self.analyzer.get_progress()
        self.assertEqual(progress["status"], "completed")
        self.assertEqual(progress["files_scanned"], 4)
        self.assertEqual(progress["folders_scanned"], 4)  # root_dir, sub1, sub2, nested
        self.assertEqual(progress["total_bytes_scanned"], 10000 + 2000 + 500 + 500)

        # Verify tree
        tree = self.analyzer.get_tree(max_depth=2)
        self.assertIsNotNone(tree)
        self.assertEqual(tree["file_count"], 4)
        self.assertEqual(tree["size"], 13000)

        # Verify extension breakdown
        exts = self.analyzer.get_extensions_summary()
        ext_map = {e["extension"]: e for e in exts}
        self.assertIn(".txt", ext_map)
        self.assertIn(".png", ext_map)
        self.assertIn(".bin", ext_map)
        self.assertEqual(ext_map[".txt"]["count"], 2)
        self.assertEqual(ext_map[".txt"]["size"], 1000)
        self.assertEqual(ext_map[".bin"]["size"], 10000)

        # Verify top files
        top_files = self.analyzer.get_top_files(limit=5)
        self.assertEqual(len(top_files), 4)
        self.assertEqual(top_files[0]["name"], "top_large.bin")
        self.assertEqual(top_files[0]["size"], 10000)

        # Verify duplicates detection (with min_size_mb=0 to catch our 500 byte files)
        duplicates = self.analyzer.find_duplicates(min_size_mb=0)
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0]["size"], 500)
        self.assertEqual(len(duplicates[0]["files"]), 2)
        file_names = [os.path.basename(f["path"]) for f in duplicates[0]["files"]]
        self.assertIn("doc1.txt", file_names)
        self.assertIn("doc2.txt", file_names)

        # Verify Treemap export
        treemap = self.analyzer.get_treemap_data()
        self.assertIsNotNone(treemap)
        self.assertEqual(treemap["size"], 13000)
        self.assertTrue(len(treemap["children"]) >= 1)

        # Verify Sunburst export (SquirrelDisk hierarchy)
        sunburst = self.analyzer.get_sunburst_data(max_depth=4)
        self.assertIsNotNone(sunburst)
        self.assertEqual(sunburst["size"], 13000)
        self.assertEqual(sunburst["depth"], 1)
        self.assertTrue(len(sunburst["children"]) >= 1)
        # Check depth and colors
        for child in sunburst["children"]:
            self.assertEqual(child["depth"], 2)
            self.assertIn("color", child)
            self.assertIn("value", child)

        # Verify JSON & CSV report export
        json_report = self.analyzer.export_report("json")
        self.assertIn("scan_time", json_report)
        self.assertIn("extensions", json_report)

        csv_report = self.analyzer.export_report("csv")
        self.assertIn("Path,Type,Size,PhysicalSize,Files,Subdirs,LastModified", csv_report)
        self.assertIn("top_large.bin", csv_report)

    def test_sunburst_micro_item_aggregation(self):
        ok, msg = self.analyzer.start_scan([self.test_dir])
        self.assertTrue(ok)
        while self.analyzer.status == "scanning":
            time.sleep(0.02)

        # Use high min_ratio threshold so sub1 items (< 500/13000 = ~3.8%) are aggregated
        sunburst = self.analyzer.get_sunburst_data(max_depth=4, min_ratio=0.1)
        self.assertIsNotNone(sunburst)
        # Find sub1 in sunburst children
        sub1_node = next((c for c in sunburst["children"] if c["name"] == "sub1"), None)
        if sub1_node and sub1_node["children"]:
            # Check if any aggregated node exists
            has_agg = any(c.get("is_aggregated") for c in sub1_node["children"])
            self.assertTrue(has_agg)

    def test_delete_collected_items_safety(self):
        # Create temp files to test deletion
        temp_file1 = os.path.join(self.test_dir, "del1.tmp")
        with open(temp_file1, "wb") as f:
            f.write(b"X" * 1234)

        # Test safe deletion of created file + attempt on protected path
        paths = [
            temp_file1,
            r"C:\Windows\System32",
            r"C:\pagefile.sys",
            r"C:\NonExistentTestFile_XYZ999.tmp"
        ]

        res = self.analyzer.delete_collected_items(paths)
        self.assertTrue(res["success"])
        self.assertEqual(res["deleted_count"], 1)
        self.assertEqual(res["freed_bytes"], 1234)
        self.assertFalse(os.path.exists(temp_file1))

        # Check errors list contains protected and non-existent paths
        error_paths = [e["path"] for e in res["errors"]]
        self.assertIn(r"C:\Windows\System32", error_paths)
        self.assertIn(r"C:\pagefile.sys", error_paths)
        self.assertIn(r"C:\NonExistentTestFile_XYZ999.tmp", error_paths)

    def test_pause_resume_cancel(self):
        # Start scan
        ok, msg = self.analyzer.start_scan([self.test_dir])
        self.assertTrue(ok)

        # Pause
        paused = self.analyzer.pause_scan()
        if self.analyzer.status == "scanning":
            self.assertTrue(paused)
            self.assertEqual(self.analyzer.status, "paused")

            # Resume
            resumed = self.analyzer.resume_scan()
            self.assertTrue(resumed)
            self.assertEqual(self.analyzer.status, "scanning")

        # Cancel
        cancelled = self.analyzer.cancel_scan()
        self.assertTrue(cancelled)
        self.assertEqual(self.analyzer.status, "cancelled")

    def test_unknown_space_calculation(self):
        # Fake volume info
        self.analyzer.volume_info = {
            "drive": "C:\\",
            "total_bytes": 100000,
            "free_bytes": 30000,
            "used_bytes": 70000,
        }
        self.analyzer.total_bytes_scanned = 50000

        progress = self.analyzer.get_progress()
        vol = progress["volume_info"]
        # Unknown = Total(100000) - (Scanned(50000) + Free(30000)) = 20000
        self.assertEqual(vol["unknown_bytes"], 20000)
        self.assertEqual(vol["scanned_bytes"], 50000)

    def test_reveal_in_explorer_normalization_and_fallback(self):
        # Test existing file
        top_bin = os.path.join(self.test_dir, "top_large.bin")
        ok, msg = self.analyzer.perform_action("reveal_in_explorer", top_bin)
        self.assertTrue(ok)
        self.assertIn("סייר", msg)

        # Test non-existent file in existing folder -> falls back to parent folder
        deleted_file = os.path.join(self.test_dir, "deleted_sample_file.xyz")
        ok, msg = self.analyzer.perform_action("reveal_in_explorer", deleted_file)
        self.assertTrue(ok)
        self.assertIn("תיקיית האב", msg)

        # Test completely bogus non-existent path
        bogus_path = r"Z:\Completely\Bogus\Path\NonExistent_12345.abc"
        ok, msg = self.analyzer.perform_action("reveal_in_explorer", bogus_path)
        self.assertFalse(ok)

    def test_treemap_deep_hierarchy_and_colors(self):
        ok, msg = self.analyzer.start_scan([self.test_dir])
        self.assertTrue(ok)

        max_wait = 10
        start = time.time()
        while self.analyzer.status == "scanning" and (time.time() - start < max_wait):
            time.sleep(0.05)

        treemap = self.analyzer.get_treemap_data(max_depth=8)
        self.assertIsNotNone(treemap)

        # Verify all extension colors are valid hex colors
        for ext_info in self.analyzer.extension_stats.values():
            color = ext_info.get("color", "")
            self.assertTrue(color.startswith("#"), f"Color {color} should be hex")
            self.assertEqual(len(color), 7, f"Hex color {color} should be #RRGGBB")


if __name__ == "__main__":
    unittest.main()


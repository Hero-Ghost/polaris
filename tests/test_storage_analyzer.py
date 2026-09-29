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

from backend import storage_analyzer as sa
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
        self._next_id = 90000

    def _inject_node(self, path, is_dir=False):
        """
        Registers a fake node directly in the scan index, the way a real scan
        would, so tests can exercise perform_action's full pipeline
        (provenance resolution -> safety guard) against a path of their
        choosing without needing a real filesystem scan.
        """
        self._next_id += 1
        node = StorageNode(self._next_id, os.path.basename(path) or path, path, is_dir=is_dir)
        self.analyzer._nodes_by_id[node.id] = node
        return node.id

    def test_system_root_is_blocked(self):
        nid = self._inject_node(r"C:\Windows", is_dir=True)
        ok, msg = self.analyzer.perform_action("recycle", node_id=nid)
        self.assertFalse(ok)
        self.assertIn("protected", msg.lower())

        nid2 = self._inject_node(r"C:\Windows\System32", is_dir=True)
        ok, msg = self.analyzer.perform_action("delete_permanent", node_id=nid2)
        self.assertFalse(ok)
        self.assertIn("protected", msg.lower())

    def test_drive_roots_are_blocked(self):
        nid = self._inject_node(r"C:\\", is_dir=True)
        ok, msg = self.analyzer.perform_action("recycle", node_id=nid)
        self.assertFalse(ok)
        self.assertIn("protected", msg.lower())

        nid2 = self._inject_node(r"D:\\", is_dir=True)
        ok, msg = self.analyzer.perform_action("delete_permanent", node_id=nid2)
        self.assertFalse(ok)
        self.assertIn("protected", msg.lower())

    def test_protected_windows_files_are_blocked(self):
        nid = self._inject_node(r"C:\pagefile.sys")
        ok, msg = self.analyzer.perform_action("recycle", node_id=nid)
        self.assertFalse(ok)
        self.assertIn("protected", msg.lower())

        nid2 = self._inject_node(r"C:\hiberfil.sys")
        ok, msg = self.analyzer.perform_action("delete_permanent", node_id=nid2)
        self.assertFalse(ok)
        self.assertIn("protected", msg.lower())

    def test_nonexistent_path_fails_gracefully(self):
        nid = self._inject_node(r"C:\NonExistentTestFolder_XYZ123", is_dir=True)
        ok, msg = self.analyzer.perform_action("recycle", node_id=nid)
        self.assertFalse(ok)

    def test_recycle_without_node_id_is_rejected_regardless_of_path(self):
        # The provenance check itself: a raw target_path with no node_id (or
        # an id this analyzer never handed out) must never reach deletion,
        # even for an otherwise perfectly ordinary-looking path. This is what
        # used to let a client delete anything it liked just by naming it.
        ok, msg = self.analyzer.perform_action("recycle", target_path=r"C:\Some\Real\Folder")
        self.assertFalse(ok)
        self.assertIn("סריקה", msg)

        ok, msg = self.analyzer.perform_action("delete_permanent", target_path=r"C:\Some\Real\Folder", node_id=999999)
        self.assertFalse(ok)
        self.assertIn("סריקה", msg)

    def test_resolve_node_id_rejects_aggregate_sentinel(self):
        # id -1 is reserved for synthetic "<N smaller files>" rollup nodes
        # (see get_treemap_data/get_sunburst_data) and must never resolve to
        # a real, deletable path.
        self.assertIsNone(self.analyzer.resolve_node_id(-1))
        self.assertIsNone(self.analyzer.resolve_node_id(None))
        self.assertIsNone(self.analyzer.resolve_node_id("not-a-number"))

    def test_users_root_is_blocked(self):
        # C:\Users (and %USERPROFILE%'s parent generally) used to pass the
        # guard outright - a single collector drop could recycle every user
        # profile on the machine.
        from backend.storage_analyzer import _is_safe_to_delete
        ok, reason = _is_safe_to_delete(r"C:\Users")
        self.assertFalse(ok)
        ok, reason = _is_safe_to_delete(r"C:\Users\SomeoneElse")
        self.assertFalse(ok)

    def test_program_files_is_blocked(self):
        from backend.storage_analyzer import _is_safe_to_delete
        ok, reason = _is_safe_to_delete(r"C:\Program Files")
        self.assertFalse(ok)
        ok, reason = _is_safe_to_delete(r"C:\Program Files (x86)")
        self.assertFalse(ok)

    def test_current_userprofile_is_blocked(self):
        # Simulates %USERPROFILE% actually being set, the normal case on a
        # real Windows machine (it's unset on the Linux test host).
        import os as _os
        from backend.storage_analyzer import _build_protected_paths
        old = _os.environ.get('USERPROFILE')
        _os.environ['USERPROFILE'] = r"C:\Users\TestUser"
        try:
            protected = _build_protected_paths()
            self.assertIn(r"c:\users\testuser", protected)
            self.assertIn(r"c:\users", protected)
        finally:
            if old is None:
                _os.environ.pop('USERPROFILE', None)
            else:
                _os.environ['USERPROFILE'] = old

    def test_unc_root_is_blocked(self):
        from backend.storage_analyzer import _is_safe_to_delete
        ok, reason = _is_safe_to_delete(r"\\server\share")
        self.assertFalse(ok)
        ok, reason = _is_safe_to_delete(r"\\server\share\folder")
        self.assertFalse(ok)

    def test_junction_or_symlink_is_blocked(self):
        from backend.storage_analyzer import _is_safe_to_delete
        tmp_dir = tempfile.mkdtemp()
        try:
            link_target = os.path.join(tmp_dir, "real_target")
            os.makedirs(link_target, exist_ok=True)
            link_path = os.path.join(tmp_dir, "a_link")
            try:
                os.symlink(link_target, link_path)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported in this test environment")
            ok, reason = _is_safe_to_delete(link_path)
            self.assertFalse(ok)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_reserved_segment_name_is_blocked(self):
        from backend.storage_analyzer import _is_safe_to_delete
        ok, reason = _is_safe_to_delete(r"C:\Games\WinSxS")
        self.assertFalse(ok)
        ok, reason = _is_safe_to_delete(r"D:\Backup\System Volume Information")
        self.assertFalse(ok)

    def test_ordinary_user_folder_is_still_allowed(self):
        # The guard must not become so aggressive that normal disk-cleanup
        # targets - an arbitrary top-level folder a user created - get
        # blocked too. Only actually-protected paths should be refused.
        from backend.storage_analyzer import _is_safe_to_delete
        ok, reason = _is_safe_to_delete(r"C:\MyOldGamesFolder")
        self.assertTrue(ok, reason)
        ok, reason = _is_safe_to_delete(r"C:\Users\SomeoneElse\Downloads\big_file.zip")
        self.assertFalse(ok)  # still under the protected C:\Users ancestor


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

    def test_treemap_small_files_rollup_has_no_real_path(self):
        # Regression test: the "<N smaller files>" rollup block used to carry
        # its parent folder's real path, so a delete action on that synthetic
        # block would rmtree the whole containing directory instead of doing
        # nothing. It must always report path=None and is_aggregated=True.
        ok, msg = self.analyzer.start_scan([self.test_dir])
        self.assertTrue(ok, msg)
        while self.analyzer.status == "scanning":
            time.sleep(0.02)

        treemap = self.analyzer.get_treemap_data()
        self.assertIsNotNone(treemap)

        sub1_node = next((c for c in treemap["children"] if c["name"] == "sub1"), None)
        self.assertIsNotNone(sub1_node, "expected sub1 folder in treemap output")

        rollup = next((c for c in sub1_node["children"] if c["id"] == -1), None)
        self.assertIsNotNone(rollup, "expected a small-files rollup block under sub1")
        self.assertIsNone(rollup["path"])
        self.assertTrue(rollup.get("is_aggregated"))

    def test_sunburst_small_items_rollup_has_no_real_path(self):
        # Same regression as above, for the sunburst's "<N Smaller Items>" slice.
        ok, msg = self.analyzer.start_scan([self.test_dir])
        self.assertTrue(ok, msg)
        while self.analyzer.status == "scanning":
            time.sleep(0.02)

        sunburst = self.analyzer.get_sunburst_data(max_depth=4, min_ratio=0.1)
        self.assertIsNotNone(sunburst)
        sub1_node = next((c for c in sunburst["children"] if c["name"] == "sub1"), None)
        if sub1_node and sub1_node["children"]:
            rollup = next((c for c in sub1_node["children"] if c.get("is_aggregated")), None)
            if rollup:
                self.assertIsNone(rollup["path"])

    def test_delete_collected_items_safety(self):
        # Create a temp file and actually scan its directory, so the file
        # gets a real, scan-produced node id - delete_collected_items only
        # accepts ids resolved against that index now, never raw paths.
        temp_file1 = os.path.join(self.test_dir, "del1.tmp")
        with open(temp_file1, "wb") as f:
            f.write(b"X" * 1234)

        ok, msg = self.analyzer.start_scan([self.test_dir])
        self.assertTrue(ok, msg)
        while self.analyzer.status == "scanning":
            time.sleep(0.02)

        real_node = next((n for n in self.analyzer._nodes_by_id.values()
                           if n.path == temp_file1), None)
        self.assertIsNotNone(real_node, "expected the scan to have indexed del1.tmp")

        # Simulate ids that point at paths a scan could plausibly have
        # produced but that the safety guard must still refuse - provenance
        # passing is not the same as the path being safe to delete.
        next_id = max(self.analyzer._nodes_by_id.keys()) + 1
        protected_dir_id, next_id = next_id, next_id + 1
        protected_file_id, next_id = next_id, next_id + 1
        self.analyzer._nodes_by_id[protected_dir_id] = StorageNode(
            protected_dir_id, "System32", r"C:\Windows\System32", is_dir=True)
        self.analyzer._nodes_by_id[protected_file_id] = StorageNode(
            protected_file_id, "pagefile.sys", r"C:\pagefile.sys", is_dir=False)

        ids = [real_node.id, protected_dir_id, protected_file_id, 999999999]
        res = self.analyzer.delete_collected_items(ids)
        # Honest success: three of the four ids were rejected, so this run
        # did not fully succeed even though the one legitimate item really
        # was deleted - `success` must reflect that, not just "did we run".
        self.assertFalse(res["success"])
        self.assertEqual(res["deleted_count"], 1)
        self.assertEqual(res["freed_bytes"], 1234)
        self.assertFalse(os.path.exists(temp_file1))

        # Check errors list contains the protected paths and the unresolvable id
        error_paths = [e["path"] for e in res["errors"]]
        self.assertIn(r"C:\Windows\System32", error_paths)
        self.assertIn(r"C:\pagefile.sys", error_paths)
        error_ids = [e.get("id") for e in res["errors"] if e["path"] is None]
        self.assertIn(999999999, error_ids)

    def test_delete_collected_items_success_is_true_only_when_nothing_failed(self):
        # Regression for Stage 2.4: `success` used to be hardcoded True
        # regardless of how many items were rejected or failed, so a caller
        # had no way to distinguish "everything was removed" from "nothing
        # was removed" other than inspecting `errors` by hand.
        temp_file1 = os.path.join(self.test_dir, "clean1.tmp")
        with open(temp_file1, "wb") as f:
            f.write(b"Y" * 500)

        ok, msg = self.analyzer.start_scan([self.test_dir])
        self.assertTrue(ok, msg)
        while self.analyzer.status == "scanning":
            time.sleep(0.02)

        real_node = next((n for n in self.analyzer._nodes_by_id.values()
                           if n.path == temp_file1), None)
        self.assertIsNotNone(real_node)

        # A run where every id resolves and deletes cleanly is a full success.
        res_all_ok = self.analyzer.delete_collected_items([real_node.id])
        self.assertTrue(res_all_ok["success"])
        self.assertEqual(res_all_ok["errors"], [])
        self.assertEqual(res_all_ok["deleted_count"], 1)

        # A run where even one id can't be resolved is not a full success,
        # even though it is not a total failure either (deleted_count can
        # still be > 0 for the ids that did work).
        res_partial = self.analyzer.delete_collected_items([999999999])
        self.assertFalse(res_partial["success"])
        self.assertEqual(res_partial["deleted_count"], 0)
        self.assertTrue(len(res_partial["errors"]) > 0)

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


class TestRecycleBinHonesty(unittest.TestCase):
    """
    Regression coverage: SHFileOperationW's FOF_ALLOWUNDO silently falls back
    to a PERMANENT delete (no error) when the item can't actually go to the
    Recycle Bin - too big for the volume's quota, no bin on that volume
    (removable/network media), or recycling disabled by policy. The old code
    reported "moved to Recycle Bin" regardless. _recycle_item must now check
    the bin's item count before/after and tell the truth.

    ctypes.windll does not exist at all on a non-Windows Python, so the real
    SHFileOperationW/SHQueryRecycleBinW calls are replaced with
    sa._win_shell_file_op / sa._win_query_recycle_bin - module-level
    indirection points that exist purely so this can be tested here.
    """

    def setUp(self):
        self.analyzer = StorageAnalyzer()
        self._patches = []

    def tearDown(self):
        for restore in self._patches:
            restore()

    def _patch(self, obj, name, value):
        old = obj.__dict__[name] if name in obj.__dict__ else getattr(obj, name)
        setattr(obj, name, value)
        self._patches.append(lambda: setattr(obj, name, old))

    def test_query_recycle_bin_returns_none_off_windows(self):
        self._patch(sa, "IS_WINDOWS", False)
        self.assertIsNone(self.analyzer._query_recycle_bin("C:\\"))

    def test_winreagent_and_system_files_are_protected(self):
        from backend.storage_analyzer import _is_path_safe_and_system
        safe, is_sys, reason = _is_path_safe_and_system(r"C:\$WinREAgent\Backup\winre.wim")
        self.assertFalse(safe)
        self.assertTrue(is_sys)
        self.assertIn("protected", reason.lower())

        safe, is_sys, reason = _is_path_safe_and_system(r"D:\pagefile.sys")
        self.assertFalse(safe)
        self.assertTrue(is_sys)

        safe, is_sys, reason = _is_path_safe_and_system(r"C:\System Volume Information\test.dat")
        self.assertFalse(safe)
        self.assertTrue(is_sys)

    def test_successful_recycle_reports_recycle_bin(self):
        self._patch(sa, "IS_WINDOWS", True)
        tmp_dir = tempfile.mkdtemp()
        try:
            target = os.path.join(tmp_dir, "file.txt")
            with open(target, "w") as f:
                f.write("data")

            bin_counts = iter([5, 6])  # grew by one -> really recycled

            def fake_query(drive_root, info):
                info.i64NumItems = next(bin_counts)
                return 0

            def fake_fileop(file_op):
                os.remove(target)  # simulate the OS actually removing it
                file_op.fAnyOperationsAborted = False
                return 0

            self._patch(sa, "_win_query_recycle_bin", fake_query)
            self._patch(sa, "_win_shell_file_op", fake_fileop)

            ok, msg = self.analyzer._recycle_item(target)
            self.assertTrue(ok)
            self.assertIn("Recycle Bin", msg)
            self.assertNotIn("לצמיתות", msg)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_fallback_to_permanent_delete_is_reported_honestly(self):
        self._patch(sa, "IS_WINDOWS", True)
        tmp_dir = tempfile.mkdtemp()
        try:
            target = os.path.join(tmp_dir, "big_file.bin")
            with open(target, "w") as f:
                f.write("data")

            bin_counts = iter([5, 5])  # unchanged -> permanently deleted instead

            def fake_query(drive_root, info):
                info.i64NumItems = next(bin_counts)
                return 0

            def fake_fileop(file_op):
                os.remove(target)
                file_op.fAnyOperationsAborted = False
                return 0

            self._patch(sa, "_win_query_recycle_bin", fake_query)
            self._patch(sa, "_win_shell_file_op", fake_fileop)

            ok, msg = self.analyzer._recycle_item(target)
            # The item genuinely is gone, so this is still success from the
            # caller's point of view - but the message must be honest.
            self.assertTrue(ok)
            self.assertIn("לצמיתות", msg)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_recycle_bin_query_unavailable_does_not_block_success(self):
        # A drive with no queryable bin info (e.g. network share) must not
        # prevent reporting whatever SHFileOperationW itself said.
        self._patch(sa, "IS_WINDOWS", True)
        tmp_dir = tempfile.mkdtemp()
        try:
            target = os.path.join(tmp_dir, "file.txt")
            with open(target, "w") as f:
                f.write("data")

            def fake_query(drive_root, info):
                return 1  # failure

            def fake_fileop(file_op):
                os.remove(target)
                file_op.fAnyOperationsAborted = False
                return 0

            self._patch(sa, "_win_query_recycle_bin", fake_query)
            self._patch(sa, "_win_shell_file_op", fake_fileop)

            ok, msg = self.analyzer._recycle_item(target)
            self.assertTrue(ok)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_operation_failure_is_reported_as_failure(self):
        self._patch(sa, "IS_WINDOWS", True)
        tmp_dir = tempfile.mkdtemp()
        try:
            target = os.path.join(tmp_dir, "file.txt")
            with open(target, "w") as f:
                f.write("data")

            def fake_fileop(file_op):
                file_op.fAnyOperationsAborted = True
                return 0

            self._patch(sa, "_win_query_recycle_bin", lambda d, i: 1)
            self._patch(sa, "_win_shell_file_op", fake_fileop)

            ok, msg = self.analyzer._recycle_item(target)
            self.assertFalse(ok)
            self.assertTrue(os.path.exists(target))
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


class TestEmptyRecycleBin(unittest.TestCase):
    """
    Regression coverage for Stage 2.5: the "empty Recycle Bin" quick-clean
    action used to shell out to a *detached* PowerShell window running
    `Clear-RecycleBin -Force -ErrorAction SilentlyContinue` via the generic
    open-a-terminal action, and the frontend reported success the instant the
    window was launched, without waiting for or checking any result -
    SilentlyContinue also meant a real failure produced no visible error
    even if someone had watched that window. _empty_recycle_bin now calls
    SHEmptyRecycleBinW directly and verifies the bin is actually empty
    afterward before reporting success.
    """

    def setUp(self):
        self.analyzer = StorageAnalyzer()
        self._patches = []

    def tearDown(self):
        for restore in self._patches:
            restore()

    def _patch(self, obj, name, value):
        old = obj.__dict__[name] if name in obj.__dict__ else getattr(obj, name)
        setattr(obj, name, value)
        self._patches.append(lambda: setattr(obj, name, old))

    def test_unsupported_off_windows(self):
        self._patch(sa, "IS_WINDOWS", False)
        ok, msg = self.analyzer._empty_recycle_bin("C:\\")
        self.assertFalse(ok)

    def test_success_when_bin_ends_up_empty(self):
        self._patch(sa, "IS_WINDOWS", True)
        self._patch(sa, "_win_empty_recycle_bin", lambda root, flags: 0)
        self._patch(sa, "_win_query_recycle_bin",
                    lambda root, info: (setattr(info, "i64NumItems", 0), 0)[1])

        ok, msg = self.analyzer._empty_recycle_bin("C:\\")
        self.assertTrue(ok)
        self.assertIn("רוקן", msg)

    def test_reported_success_but_items_remain_is_not_trusted(self):
        # The API said S_OK, but items are still in the bin afterward - do
        # not repeat a claim the actual state contradicts.
        self._patch(sa, "IS_WINDOWS", True)
        self._patch(sa, "_win_empty_recycle_bin", lambda root, flags: 0)
        self._patch(sa, "_win_query_recycle_bin",
                    lambda root, info: (setattr(info, "i64NumItems", 3), 0)[1])

        ok, msg = self.analyzer._empty_recycle_bin("C:\\")
        self.assertFalse(ok)

    def test_error_code_is_reported_as_failure(self):
        self._patch(sa, "IS_WINDOWS", True)
        self._patch(sa, "_win_empty_recycle_bin", lambda root, flags: 2)  # error
        self._patch(sa, "_win_query_recycle_bin",
                    lambda root, info: (setattr(info, "i64NumItems", 4), 0)[1])

        ok, msg = self.analyzer._empty_recycle_bin("C:\\")
        self.assertFalse(ok)

    def test_error_code_but_bin_already_empty_is_treated_as_success(self):
        # Some Windows builds return a non-zero code when there was nothing
        # to empty rather than treating an already-empty bin as S_OK.
        self._patch(sa, "IS_WINDOWS", True)
        self._patch(sa, "_win_empty_recycle_bin", lambda root, flags: 2)
        self._patch(sa, "_win_query_recycle_bin",
                    lambda root, info: (setattr(info, "i64NumItems", 0), 0)[1])

        ok, msg = self.analyzer._empty_recycle_bin("C:\\")
        self.assertTrue(ok)

    def test_raised_exception_is_reported_as_failure(self):
        self._patch(sa, "IS_WINDOWS", True)

        def boom(root, flags):
            raise OSError("no shell32 in this environment")
        self._patch(sa, "_win_empty_recycle_bin", boom)

        ok, msg = self.analyzer._empty_recycle_bin("C:\\")
        self.assertFalse(ok)


class TestScanProgressHonesty(unittest.TestCase):
    """
    Regression coverage for Stage 2.2/2.3:
    - A folder that could not be listed at all (PermissionError) used to be
      silently skipped, with its missing bytes swallowed into "<Unknown>"
      and no sign anywhere that anything was skipped.
    - get_progress()'s scan_rate divided by files_scanned+folders_scanned,
      which stay at 0 for the entire pdu-engine phase of a scan (real counts
      are only known once the finished tree is built) - items_seen is the
      live counter that actually moves during that phase.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.analyzer = StorageAnalyzer()

    def tearDown(self):
        # Restore permissions before cleanup, or rmtree can't remove it.
        for root, dirs, _ in os.walk(self.test_dir):
            for d in dirs:
                try:
                    os.chmod(os.path.join(root, d), 0o755)
                except OSError:
                    pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_unreadable_subfolder_is_counted_not_silently_skipped(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("running as root - permission bits are not enforced")

        readable = os.path.join(self.test_dir, "readable")
        blocked = os.path.join(self.test_dir, "blocked")
        os.makedirs(readable)
        os.makedirs(blocked)
        with open(os.path.join(readable, "a.txt"), "wb") as f:
            f.write(b"x" * 100)
        with open(os.path.join(blocked, "secret.txt"), "wb") as f:
            f.write(b"y" * 100)

        os.chmod(blocked, 0o000)
        try:
            with open(os.path.join(blocked, "secret.txt"), "rb"):
                if sys.platform == "win32":
                    self.skipTest("os.chmod(0) does not deny directory read permissions on Windows NTFS")
        except PermissionError:
            pass
            ok, msg = self.analyzer.start_scan([self.test_dir])
            self.assertTrue(ok, msg)
            while self.analyzer.status == "scanning":
                time.sleep(0.02)
            self.assertEqual(self.analyzer.status, "completed")
            self.assertGreaterEqual(self.analyzer.access_denied_count, 1)
        finally:
            os.chmod(blocked, 0o755)

    def test_access_denied_count_defaults_to_zero(self):
        self.assertEqual(self.analyzer.access_denied_count, 0)
        progress = self.analyzer.get_progress()
        self.assertEqual(progress["access_denied_count"], 0)

    def test_scan_rate_uses_items_seen_while_final_counts_are_still_zero(self):
        # Simulates the mid-pdu-scan moment: files_scanned/folders_scanned
        # have not been set yet (they are only set once, from the finished
        # tree), but items_seen is already climbing.
        self.analyzer.status = "scanning"
        self.analyzer.start_time = time.time() - 10
        self.analyzer.files_scanned = 0
        self.analyzer.folders_scanned = 0
        self.analyzer.items_seen = 500

        progress = self.analyzer.get_progress()
        self.assertEqual(progress["items_seen"], 500)
        self.assertGreater(progress["scan_rate"], 0,
                            "scan_rate must not read as zero just because "
                            "files_scanned/folders_scanned aren't populated yet")


if __name__ == "__main__":
    unittest.main()


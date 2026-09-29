"""
Unit tests for the Polaris uninstaller engine.

Everything here is platform independent on purpose: the path and registry
guards are written as pure string logic precisely so they can be exercised
without a Windows box and without touching a real filesystem or registry.

    python -m unittest discover -s tests -v
    python tests/test_uninstaller_engine.py
"""

import os
import sys
import shutil
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import uninstaller_engine as ue  # noqa: E402
from backend.uninstaller_engine import (  # noqa: E402
    UninstallerEngine,
    is_path_safe_to_delete,
    is_reg_path_safe_to_delete,
    to_uninstall_command,
    to_silent_command,
    make_item_id,
    _norm_win_path,
    _norm_reg_path,
    _token_matches_name,
)

IS_WINDOWS_HOST = sys.platform.startswith("win")


def bare_engine():
    """
    An engine without __init__'s side effects (no pre-warm thread, no registry
    access), wired with exactly the state the pure logic needs.
    """
    e = UninstallerEngine.__new__(UninstallerEngine)
    e._lock = threading.RLock()
    e._skip_requested = threading.Event()
    e._stop_heartbeat = threading.Event()
    e._heartbeat_thread = None
    e._steps_owner = None
    e._busy = False
    e.active_session = None
    e.cached_apps = []
    e.last_apps_fetch = 0
    e._scan_index = {}
    e._reset_run_state()
    return e


# A fixed stand-in for PROTECTED_ABS_PATHS so the filesystem tests behave the
# same on a Linux CI box as on the user's Windows machine.
WINDOWS_LIKE_PROTECTED = {
    r"c:\windows",
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\program files",
    r"c:\program files (x86)",
    r"c:\program files\common files",
    r"c:\program files\windowsapps",
    r"c:\program files (x86)\windowsapps",
    r"c:\programdata",
    r"c:\programdata\microsoft",
    r"c:\users",
    r"c:\users\pc",
    r"c:\users\pc\desktop",
    r"c:\users\pc\appdata",
    r"c:\users\pc\appdata\roaming",
    r"c:\users\pc\appdata\local",
}


class TestPathNormalization(unittest.TestCase):

    def test_forward_slashes_and_case_are_normalized(self):
        self.assertEqual(_norm_win_path("C:/Program Files/Acme"), r"c:\program files\acme")

    def test_trailing_separators_and_quotes_are_stripped(self):
        self.assertEqual(_norm_win_path('  "C:\\Apps\\Acme\\"  '), r"c:\apps\acme")

    def test_repeated_separators_collapse(self):
        self.assertEqual(_norm_win_path(r"C:\\Apps\\\Acme"), r"c:\apps\acme")

    def test_unc_prefix_survives_collapsing(self):
        self.assertTrue(_norm_win_path(r"\\server\share\x").startswith("\\\\"))

    def test_non_string_input_is_empty(self):
        self.assertEqual(_norm_win_path(None), "")
        self.assertEqual(_norm_win_path(42), "")

    def test_long_hive_names_are_canonicalized(self):
        self.assertEqual(
            _norm_reg_path(r"HKEY_LOCAL_MACHINE\SOFTWARE\Acme"), r"hklm\software\acme"
        )
        self.assertEqual(_norm_reg_path("HKEY_CURRENT_USER"), "hkcu")


class TestFilesystemDeletionGuard(unittest.TestCase):

    def ok(self, path):
        allowed, reason = is_path_safe_to_delete(path, WINDOWS_LIKE_PROTECTED)
        self.assertTrue(allowed, f"{path!r} should be deletable, got: {reason}")

    def blocked(self, path):
        allowed, reason = is_path_safe_to_delete(path, WINDOWS_LIKE_PROTECTED)
        self.assertFalse(allowed, f"{path!r} should have been refused")
        self.assertTrue(reason)

    def test_ordinary_leftovers_are_allowed(self):
        self.ok(r"C:\Program Files\Acme\Toolbar")
        self.ok(r"C:\Users\pc\AppData\Roaming\Acme")
        self.ok(r"C:\Users\pc\AppData\Local\Acme\cache")
        self.ok(r"D:\Games\Acme")

    def test_system_roots_are_refused(self):
        self.blocked(r"C:\Windows")
        self.blocked(r"C:\Windows\System32")
        self.blocked(r"C:\Windows\System32\\")
        self.blocked(r"C:\Program Files")
        self.blocked(r"C:\Program Files (x86)")
        self.blocked(r"C:\ProgramData")
        self.blocked(r"C:\Users")
        self.blocked(r"C:\Users\pc")
        self.blocked(r"C:\Users\pc\Desktop")
        self.blocked(r"C:\Users\pc\AppData\Roaming")

    def test_drive_root_and_shallow_paths_are_refused(self):
        self.blocked("C:\\")
        self.blocked("C:")
        self.blocked(r"C:\Acme")  # one level below the drive: too shallow

    def test_a_path_containing_a_protected_directory_is_refused(self):
        # C:\Users would swallow C:\Users\pc; the ancestor rule must catch it
        # even for a protected entry that is not itself listed.
        allowed, _ = is_path_safe_to_delete(r"C:\a\b", {r"c:\a\b\c"})
        self.assertFalse(allowed)

    def test_reserved_folder_names_are_refused_anywhere(self):
        self.blocked(r"D:\Backup\Windows")
        self.blocked(r"D:\Stuff\System32")

    def test_case_and_separator_variants_do_not_slip_through(self):
        self.blocked("c:/windows/system32")
        self.blocked(r"C:\WINDOWS\\")
        self.blocked(r"C:/Users/pc")

    def test_wildcards_env_vars_unc_and_relatives_are_refused(self):
        self.blocked(r"C:\Program Files\Acme\*")
        self.blocked(r"C:\Program Files\Acme\?.dll")
        self.blocked(r"%APPDATA%\Acme")
        self.blocked(r"\\server\share\Acme")
        self.blocked(r"..\..\Windows")
        self.blocked("Acme")
        self.blocked("")
        self.blocked(None)

    def test_windowsapps_paths_are_refused(self):
        self.blocked(r"C:\Program Files\WindowsApps")
        self.blocked(r"C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_7.326.8061.0_x64__8wekyb3d8bbwe")
        self.blocked(r"D:\WindowsApps\SomeStoreApp_1.0.0.0_x64__8wekyb3d8bbwe")
        self.blocked(r"C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_7.326.8061.0_x64__8wekyb3d8bbwe\AppxManifest.xml")


class TestRegistryDeletionGuard(unittest.TestCase):

    def ok(self, path):
        allowed, reason = is_reg_path_safe_to_delete(path)
        self.assertTrue(allowed, f"{path!r} should be deletable, got: {reason}")

    def blocked(self, path):
        allowed, reason = is_reg_path_safe_to_delete(path)
        self.assertFalse(allowed, f"{path!r} should have been refused")
        self.assertTrue(reason)

    def test_vendor_and_product_keys_are_allowed(self):
        self.ok(r"HKLM\SOFTWARE\Acme")
        self.ok(r"HKLM\SOFTWARE\WOW6432Node\Acme")
        self.ok(r"HKCU\SOFTWARE\Acme\Toolbar")
        self.ok(r"HKEY_LOCAL_MACHINE\SOFTWARE\Acme")
        self.ok(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{ACME-1234}")
        self.ok(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\acme.exe")

    def test_hive_roots_and_os_branches_are_refused(self):
        for p in (
            r"HKLM", r"HKCU",
            r"HKLM\SOFTWARE",
            r"HKLM\SOFTWARE\WOW6432Node",
            r"HKLM\SOFTWARE\Microsoft",
            r"HKLM\SOFTWARE\Classes",
            r"HKLM\SOFTWARE\Classes\CLSID",
            r"HKLM\SYSTEM",
            r"HKLM\SYSTEM\CurrentControlSet",
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            r"HKLM\SYSTEM\CurrentControlSet\Control",
            r"HKCU\SOFTWARE",
            r"HKCU\SOFTWARE\Microsoft",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        ):
            self.blocked(p)

    def test_branch_containing_a_protected_branch_is_refused(self):
        # HKLM\SOFTWARE\Microsoft\Windows is an ancestor of the Run key.
        self.blocked(r"HKLM\SOFTWARE\Microsoft\Windows")
        self.blocked(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion")

    def test_third_party_services_are_allowed_but_critical_ones_are_not(self):
        self.ok(r"HKLM\SYSTEM\CurrentControlSet\Services\AcmeUpdater")
        for svc in ("Tcpip", "RpcSs", "NTFS", "WinDefend", "TrustedInstaller", "volsnap"):
            self.blocked(rf"HKLM\SYSTEM\CurrentControlSet\Services\{svc}")

    def test_unsupported_hives_are_refused(self):
        self.blocked(r"HKU\S-1-5-18\Software\Acme")
        self.blocked(r"HKEY_USERS\S-1-5-18\Software\Acme")
        self.blocked("")
        self.blocked(None)

    def test_trailing_separator_does_not_bypass_the_guard(self):
        self.blocked("HKLM\\SOFTWARE\\")
        self.blocked("hklm/software")


class TestUninstallCommandRewriting(unittest.TestCase):

    def test_msi_install_switch_becomes_uninstall(self):
        self.assertEqual(
            to_uninstall_command("MsiExec.exe /I{90160000-000F-0000-1000-0000000FF1CE}"),
            "MsiExec.exe /x{90160000-000F-0000-1000-0000000FF1CE}",
        )
        self.assertEqual(
            to_uninstall_command("msiexec /i {ABC}"),
            "msiexec /x {ABC}",
        )

    def test_an_existing_uninstall_switch_is_left_alone(self):
        for cmd in ("MsiExec.exe /X{ABC}", "msiexec /x {ABC}", "MsiExec.exe /x{ABC} /qn"):
            self.assertEqual(to_uninstall_command(cmd), cmd)

    def test_casing_of_the_rest_of_the_command_is_preserved(self):
        # The old implementation lowercased the whole string before replacing.
        out = to_uninstall_command(r'"C:\Program Files\Acme\MsiExec.exe" /I{ABC} /QN')
        self.assertIn(r"C:\Program Files\Acme", out)
        self.assertIn("/QN", out)

    def test_non_msi_commands_are_untouched(self):
        cmd = r'"C:\Program Files\Acme\unins000.exe" /i-am-not-a-switch'
        self.assertEqual(to_uninstall_command(cmd), cmd)

    def test_only_the_first_install_switch_is_rewritten(self):
        out = to_uninstall_command("msiexec /i {A} /i {B}")
        self.assertEqual(out.count("/x"), 1)

    def test_empty_input(self):
        self.assertEqual(to_uninstall_command(""), "")
        self.assertEqual(to_uninstall_command(None), "")


class TestSilentSwitches(unittest.TestCase):

    def test_msi_gets_quiet_and_norestart(self):
        out = to_silent_command("msiexec /x{ABC}")
        self.assertIn("/qn", out)
        self.assertIn("/norestart", out)

    def test_msi_switches_are_not_duplicated(self):
        out = to_silent_command("msiexec /x{ABC} /qn /norestart")
        self.assertEqual(out.count("/qn"), 1)
        self.assertEqual(out.lower().count("/norestart"), 1)

    def test_inno_setup_uninstallers_of_any_index(self):
        for exe in ("unins000.exe", "unins001.exe", "UNINS002.EXE"):
            out = to_silent_command(rf'"C:\Program Files\Acme\{exe}"')
            self.assertIn("/VERYSILENT", out)

    def test_nsis_uninstaller(self):
        out = to_silent_command(r'"C:\Program Files\Acme\uninstall.exe"')
        self.assertIn("/S", out)


class TestItemIdentity(unittest.TestCase):

    def test_two_values_under_the_same_key_get_distinct_ids(self):
        run_key = r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        a = {"type": "value", "path": run_key, "name": "AcmeUpdater"}
        b = {"type": "value", "path": run_key, "name": "OtherVendor"}
        self.assertNotEqual(make_item_id(a), make_item_id(b))

    def test_id_is_stable_across_calls(self):
        item = {"type": "folder", "path": r"C:\Program Files\Acme", "name": "Acme"}
        self.assertEqual(make_item_id(item), make_item_id(dict(item)))

    def test_id_ignores_separator_and_case_noise(self):
        a = {"type": "folder", "path": r"C:\Program Files\Acme", "name": "Acme"}
        b = {"type": "folder", "path": "c:/program files/acme/", "name": "acme"}
        self.assertEqual(make_item_id(a), make_item_id(b))

    def test_type_is_part_of_the_identity(self):
        a = {"type": "key", "path": r"HKLM\SOFTWARE\Acme", "name": "Acme"}
        b = {"type": "value", "path": r"HKLM\SOFTWARE\Acme", "name": "Acme"}
        self.assertNotEqual(make_item_id(a), make_item_id(b))


class TestSelectionProvenance(unittest.TestCase):
    """The client may only ask for items the engine itself produced."""

    def setUp(self):
        self.engine = bare_engine()

    def test_unknown_ids_are_rejected(self):
        resolved, rejected = self.engine.resolve_selection(selected_ids=["deadbeef"])
        self.assertEqual(resolved, [])
        self.assertEqual(len(rejected), 1)

    def test_known_ids_resolve_to_the_engines_own_record(self):
        item = {"type": "folder", "path": r"C:\Program Files\Acme", "name": "Acme"}
        item["id"] = make_item_id(item)
        self.engine._scan_index[item["id"]] = item

        resolved, rejected = self.engine.resolve_selection(selected_ids=[item["id"]])
        self.assertEqual(rejected, [])
        self.assertIs(resolved[0], item)  # the engine's object, not the client's

    def test_a_forged_item_cannot_smuggle_in_a_path(self):
        forged = {"type": "folder", "path": r"C:\Windows", "name": "Windows"}
        resolved, rejected = self.engine.resolve_selection(selected_items=[forged])
        self.assertEqual(resolved, [])
        self.assertEqual(len(rejected), 1)

    def test_delete_refuses_a_selection_it_does_not_recognise(self):
        res = self.engine.delete_leftovers(selected_items=[
            {"type": "folder", "path": r"C:\Windows", "name": "Windows"}
        ])
        self.assertFalse(res["success"])
        self.assertIn("rejected", res)

    def test_delete_with_no_selection(self):
        self.assertFalse(self.engine.delete_leftovers()["success"])


class TestValueDeletionWhitelist(unittest.TestCase):

    def test_autostart_and_muicache_values_are_allowed(self):
        for key in (
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        ):
            ok, reason = UninstallerEngine._is_value_deletion_allowed(key, "Acme")
            self.assertTrue(ok, f"{key} -> {reason}")

    def test_values_elsewhere_are_refused(self):
        ok, _ = UninstallerEngine._is_value_deletion_allowed(r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip", "Start")
        self.assertFalse(ok)

    def test_the_default_value_is_never_deleted(self):
        ok, _ = UninstallerEngine._is_value_deletion_allowed(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", ""
        )
        self.assertFalse(ok)


class TestInstallLocationUsability(unittest.TestCase):

    def test_generic_locations_do_not_become_match_needles(self):
        for loc in ("", "C:\\", r"C:\Program Files", r"C:\Windows", r"C:\Windows\System32"):
            self.assertEqual(UninstallerEngine._usable_install_loc(loc), "")

    def test_a_real_install_folder_is_usable(self):
        self.assertEqual(
            UninstallerEngine._usable_install_loc(r"C:\Program Files\Acme\Toolbar"),
            r"c:\program files\acme\toolbar",
        )


class TestSquishedGuid(unittest.TestCase):

    def test_known_vector(self):
        engine = UninstallerEngine.__new__(UninstallerEngine)
        self.assertEqual(
            engine._squish_guid("{01234567-89AB-CDEF-0123-456789ABCDEF}"),
            "76543210BA98FEDC1032547698BADCFE",
        )

    def test_malformed_guid_returns_none(self):
        engine = UninstallerEngine.__new__(UninstallerEngine)
        self.assertIsNone(engine._squish_guid("not-a-guid"))
        self.assertIsNone(engine._squish_guid("{0123}"))


class TestSharedDllProtection(unittest.TestCase):
    """The refcount table used to be built, passed around and then ignored."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.dll = os.path.join(self.tmp, "acme_shared.dll")
        with open(self.dll, "wb") as f:
            f.write(b"MZ")
        with open(os.path.join(self.tmp, "readme.txt"), "w") as f:
            f.write("x")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_dll_referenced_by_others_is_reported(self):
        table = {_norm_win_path(self.dll): 3}
        hits = UninstallerEngine.find_shared_dlls_in_folder(self.tmp, table)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["refcount"], 3)

    def test_a_refcount_of_one_is_not_shared(self):
        table = {_norm_win_path(self.dll): 1}
        self.assertEqual(UninstallerEngine.find_shared_dlls_in_folder(self.tmp, table), [])

    def test_non_dll_files_are_ignored(self):
        table = {_norm_win_path(os.path.join(self.tmp, "readme.txt")): 5}
        self.assertEqual(UninstallerEngine.find_shared_dlls_in_folder(self.tmp, table), [])

    def test_empty_table_is_a_no_op(self):
        self.assertEqual(UninstallerEngine.find_shared_dlls_in_folder(self.tmp, {}), [])


# ---------------------------------------------------------------------------
# Registry tree deletion: the regression that used to hang the server thread.
# ---------------------------------------------------------------------------

class FakeWinreg:
    """Minimal in-memory stand-in for the winreg module."""

    HKEY_LOCAL_MACHINE = "HKLM"
    HKEY_CURRENT_USER = "HKCU"
    HKEY_CLASSES_ROOT = "HKCR"
    KEY_READ = 1
    KEY_WRITE = 2
    KEY_SET_VALUE = 4
    KEY_ALL_ACCESS = 8

    def __init__(self, tree, undeletable=()):
        self.tree = tree
        self.undeletable = {u.lower() for u in undeletable}
        self.delete_calls = 0
        self.enum_calls = 0

    def _resolve(self, sub):
        node = self.tree
        for part in [p for p in sub.split("\\") if p]:
            if part not in node:
                raise FileNotFoundError(sub)
            node = node[part]
        return node

    def OpenKey(self, hive, sub, reserved=0, access=0):
        self._resolve(sub)
        return ("key", sub)

    def QueryInfoKey(self, handle):
        return (len(self._resolve(handle[1])), 0, 0)

    def EnumKey(self, handle, index):
        self.enum_calls += 1
        if self.enum_calls > 5000:
            raise AssertionError("EnumKey runaway - the delete loop is not terminating")
        names = list(self._resolve(handle[1]).keys())
        if index >= len(names):
            raise OSError("no more items")
        return names[index]

    def CloseKey(self, handle):
        pass

    def DeleteKey(self, hive, sub):
        self.delete_calls += 1
        if self.delete_calls > 5000:
            raise AssertionError("DeleteKey runaway - the delete loop is not terminating")
        if sub.lower() in self.undeletable:
            raise PermissionError("Access is denied")
        parts = [p for p in sub.split("\\") if p]
        parent = self.tree
        for p in parts[:-1]:
            parent = parent[p]
        if parts[-1] not in parent:
            raise FileNotFoundError(sub)
        if parent[parts[-1]]:
            raise OSError("key still has subkeys")
        del parent[parts[-1]]


class TestRecursiveKeyDeletion(unittest.TestCase):

    def setUp(self):
        self.engine = UninstallerEngine.__new__(UninstallerEngine)
        self._real_winreg = ue.winreg

    def tearDown(self):
        ue.winreg = self._real_winreg

    def _tree(self):
        return {"SOFTWARE": {"Acme": {"Settings": {}, "Cache": {"v1": {}, "v2": {}}}}}

    def test_a_whole_tree_is_removed(self):
        tree = self._tree()
        ue.winreg = FakeWinreg(tree)
        ok, err = self.engine._delete_reg_key_recursive(r"HKLM\SOFTWARE\Acme")
        self.assertTrue(ok, err)
        self.assertNotIn("Acme", tree["SOFTWARE"])

    def test_an_undeletable_child_fails_instead_of_looping_forever(self):
        # This is the exact shape of the old hang: DeleteKey raises, the error
        # is swallowed, EnumKey(k, 0) keeps handing back the same child.
        tree = self._tree()
        fake = FakeWinreg(tree, undeletable={r"software\acme\settings"})
        ue.winreg = fake
        ok, err = self.engine._delete_reg_key_recursive(r"HKLM\SOFTWARE\Acme")
        self.assertFalse(ok)
        self.assertTrue(err)
        self.assertLess(fake.delete_calls, 100, "deletion did not terminate promptly")
        self.assertIn("Acme", tree["SOFTWARE"])  # nothing half-removed above it

    def test_a_missing_key_counts_as_already_gone(self):
        ue.winreg = FakeWinreg(self._tree())
        ok, err = self.engine._delete_reg_key_recursive(r"HKLM\SOFTWARE\DoesNotExist")
        self.assertTrue(ok, err)

    def test_a_malformed_path_is_reported_not_raised(self):
        ue.winreg = FakeWinreg(self._tree())
        ok, err = self.engine._delete_reg_key_recursive("HKLM")
        self.assertFalse(ok)
        self.assertTrue(err)

    def test_an_unsupported_hive_is_reported(self):
        ue.winreg = FakeWinreg(self._tree())
        ok, err = self.engine._delete_reg_key_recursive(r"HKU\SOFTWARE\Acme")
        self.assertFalse(ok)
        self.assertTrue(err)


class TestLiveLog(unittest.TestCase):
    """The terminal the wizard renders is fed entirely from this buffer."""

    def setUp(self):
        self.engine = bare_engine()

    def test_rows_get_increasing_uid_and_rev(self):
        self.engine.log("first")
        self.engine.log("second")
        uids = [r["uid"] for r in self.engine.live_logs]
        revs = [r["rev"] for r in self.engine.live_logs]
        self.assertEqual(uids, [1, 2])
        self.assertEqual(revs, [1, 2])

    def test_replace_key_edits_in_place_and_bumps_rev(self):
        self.engine.log("scanning 100", replace_key="scan")
        self.engine.log("scanning 200", replace_key="scan")
        self.assertEqual(len(self.engine.live_logs), 1)
        row = self.engine.live_logs[0]
        self.assertEqual(row["text"], "scanning 200")
        self.assertEqual(row["uid"], 1)      # same row for the client
        self.assertEqual(row["rev"], 2)      # but newer, so it is re-sent

    def test_since_returns_only_new_and_edited_rows(self):
        self.engine.log("a")
        self.engine.log("b", replace_key="k")
        seen = self.engine._log_rev
        self.engine.log("b2", replace_key="k")   # edits the row already drawn
        out = self.engine.get_session_status(since_log_id=seen)
        self.assertEqual([r["text"] for r in out["logs"]], ["b2"])
        self.assertEqual(out["log_rev"], 3)

    def test_since_accepts_garbage_without_raising(self):
        self.engine.log("a")
        for bad in (None, "", "abc", [], {}):
            out = self.engine.get_session_status(since_log_id=bad)
            self.assertEqual(len(out["logs"]), 1)

    def test_buffer_is_capped(self):
        for i in range(ue.MAX_LOG_LINES + 50):
            self.engine.log(f"line {i}")
        self.assertEqual(len(self.engine.live_logs), ue.MAX_LOG_LINES)
        self.assertEqual(self.engine.live_logs[-1]["text"], f"line {ue.MAX_LOG_LINES + 49}")

    def test_status_without_a_session_still_carries_the_log(self):
        self.engine.log("forced scan line")
        out = self.engine.get_session_status()
        self.assertFalse(out["active"])
        self.assertEqual(len(out["logs"]), 1)

    def test_log_is_reentrant_under_the_engine_lock(self):
        # _begin_step and friends log while already holding the lock; a plain
        # Lock would deadlock here.
        with self.engine._lock:
            self.engine.log("inside the lock")
        self.assertEqual(len(self.engine.live_logs), 1)


class TestStepPlan(unittest.TestCase):

    def setUp(self):
        self.engine = bare_engine()
        self.engine._busy = True

    def test_plan_publishes_every_step_including_skipped_ones(self):
        self.engine._plan_steps(skip_restore_point=True, skip_registry_backup=False, is_uwp=False)
        ids = [s["id"] for s in self.engine._steps]
        self.assertEqual(ids, [s["id"] for s in ue.UNINSTALL_STEPS])
        rp = next(s for s in self.engine._steps if s["id"] == "restore_point")
        self.assertEqual(rp["status"], "skipped")

    def test_uwp_skips_the_registry_backup_with_a_reason(self):
        self.engine._plan_steps(False, False, is_uwp=True)
        rb = next(s for s in self.engine._steps if s["id"] == "registry_backup")
        self.assertEqual(rb["status"], "skipped")
        self.assertTrue(rb["detail_he"])

    def test_percent_ignores_skipped_weight(self):
        self.engine._plan_steps(skip_restore_point=True, skip_registry_backup=True, is_uwp=False)
        self.assertEqual(self.engine._compute_percent_locked(), 0)
        self.engine._begin_step("native_uninstall")
        self.engine._end_step("native_uninstall")
        # native(40) of native(40)+scan_registry(17)+scan_files(17)+scan_scheduled_tasks(10) = 48%
        self.assertEqual(self.engine._compute_percent_locked(), 48)

    def test_all_steps_done_is_one_hundred(self):
        self.engine._plan_steps(False, False, False)
        for s in list(self.engine._steps):
            self.engine._begin_step(s["id"])
            self.engine._end_step(s["id"])
        self.assertEqual(self.engine._compute_percent_locked(), 100)

    def test_a_running_step_moves_the_bar_without_finishing(self):
        self.engine._plan_steps(True, True, False)
        self.engine._begin_step("native_uninstall")
        before = self.engine._compute_percent_locked()
        self.engine._set_fraction("native_uninstall", 0.5)
        self.assertGreater(self.engine._compute_percent_locked(), before)

    def test_beginning_a_skipped_or_unknown_step_is_a_no_op(self):
        self.engine._plan_steps(skip_restore_point=True, skip_registry_backup=False, is_uwp=False)
        self.assertFalse(self.engine._begin_step("restore_point"))
        self.assertFalse(self.engine._begin_step("no_such_step"))
        self.engine._end_step("no_such_step")  # must not raise

    def test_steps_work_with_no_plan_at_all(self):
        # A forced scan calls the same helpers before any plan exists.
        self.assertFalse(self.engine._begin_step("scan_files"))
        self.engine._end_step("scan_files")
        self.engine._set_fraction("scan_files", 0.5)
        self.assertEqual(self.engine._compute_percent_locked(), 0)

    def test_eta_shrinks_as_work_completes(self):
        self.engine._plan_steps(True, True, False)
        first = self.engine._eta_locked(10)
        self.engine._begin_step("native_uninstall")
        self.engine._end_step("native_uninstall")
        self.assertLess(self.engine._eta_locked(10), first)

    def test_status_exposes_the_step_list_and_counters(self):
        self.engine._plan_steps(True, False, False)
        self.engine._begin_step("registry_backup")
        self.engine._end_step("registry_backup")
        out = self.engine.get_session_status()
        self.assertEqual(len(out["steps"]), len(ue.UNINSTALL_STEPS))
        self.assertEqual(out["done_steps"], 1)
        self.assertEqual(out["total_steps"], len(ue.UNINSTALL_STEPS) - 1)
        self.assertNotIn("started_at", out["steps"][0])

    def test_every_planned_step_has_a_weight(self):
        for s in ue.UNINSTALL_STEPS:
            self.assertIn(s["id"], ue.STEP_BY_ID)
            self.assertGreater(ue.STEP_BY_ID[s["id"]]["weight"], 0)


class TestRunOwnership(unittest.TestCase):
    """
    The log, the step plan and the skip flag are one shared resource. Any entry
    point that resets them has to claim the engine first, or it wipes a live
    session's terminal out from under it.
    """

    def setUp(self):
        self.engine = bare_engine()

    def test_forced_uninstall_refuses_while_another_run_is_active(self):
        self.engine._busy = True
        res = self.engine.run_forced_uninstall(r"C:\Program Files\Acme")
        self.assertFalse(res["success"])
        self.assertIn("פועלת", res["error"])

    def test_forced_uninstall_releases_the_claim(self):
        self.engine.run_forced_uninstall("SomeAppThatDoesNotExist")
        self.assertFalse(self.engine._busy)

    def test_batch_refuses_while_another_run_is_active(self):
        self.engine._busy = True
        self.engine.cached_apps = [{"id": "x", "name": "X"}]
        self.engine.last_apps_fetch = time.time()
        res = self.engine.run_batch_uninstall(["x"])
        self.assertFalse(res["success"])

    def test_empty_target_is_rejected_before_the_claim(self):
        res = self.engine.run_forced_uninstall("   ")
        self.assertFalse(res["success"])
        self.assertFalse(self.engine._busy)

    def test_reset_stops_a_previous_heartbeat_before_clearing_the_flag(self):
        started = threading.Event()
        finished = threading.Event()

        def fake_loop():
            started.set()
            while not self.engine._stop_heartbeat.wait(0.02):
                pass
            finished.set()

        t = threading.Thread(target=fake_loop, daemon=True)
        self.engine._heartbeat_thread = t
        t.start()
        self.assertTrue(started.wait(2))

        self.engine._reset_run_state()

        self.assertTrue(finished.is_set(), "the old heartbeat was not stopped before the reset")
        self.assertFalse(self.engine._stop_heartbeat.is_set())
        self.assertIsNone(self.engine._heartbeat_thread)

    def test_standalone_scan_refuses_while_another_run_is_active(self):
        self.engine._busy = True
        res = self.engine.run_standalone_scan("whatever")
        self.assertFalse(res["success"])
        self.assertIn("פועלת", res["error"])

    def test_standalone_scan_releases_the_claim_on_an_unknown_app(self):
        res = self.engine.run_standalone_scan("no_such_app")
        self.assertFalse(res["success"])
        self.assertFalse(self.engine._busy)

    def test_a_forced_run_detaches_the_previous_session(self):
        # Otherwise `active` stays true forever and the forced run's plan is
        # never allowed to drive the progress bar.
        self.engine.active_session = {"session_id": "uninstall_1", "stage": "completed"}
        self.engine.run_forced_uninstall("SomeAppThatDoesNotExist")
        self.assertIsNone(self.engine.active_session)
        self.assertFalse(self.engine.get_session_status()["active"])

    def test_reset_refreshes_the_quiet_timer(self):
        self.engine.log("old line")
        self.engine._last_log_at = 0.0
        self.engine._reset_run_state()
        self.assertGreater(self.engine._last_log_at, 0.0)

    def test_a_finished_session_is_not_repainted_by_a_later_plan(self):
        self.engine.active_session = {"session_id": "uninstall_1", "stage": "completed",
                                      "progress_pct": 100}
        self.engine._reset_run_state(owner="forced_2")
        self.engine._plan_steps(True, True, False)
        out = self.engine.get_session_status()
        self.assertEqual(out["progress_pct"], 100)  # the session's own number

    def test_the_owning_session_does_drive_the_bar(self):
        self.engine.active_session = {"session_id": "uninstall_1", "stage": "scanning",
                                      "progress_pct": 5}
        self.engine._reset_run_state(owner="uninstall_1")
        self.engine._plan_steps(True, True, False)
        self.engine._begin_step("native_uninstall")
        self.engine._end_step("native_uninstall")
        self.assertEqual(self.engine.get_session_status()["progress_pct"], 48)


class TestPlanHonesty(unittest.TestCase):

    def setUp(self):
        self.engine = bare_engine()

    def test_force_skip_native_is_applied_before_the_plan_is_printed(self):
        self.engine._plan_steps(True, True, False, force_skip_native=True,
                                native_skip_reason="אין מסיר מקורי")
        native = next(s for s in self.engine._steps if s["id"] == "native_uninstall")
        self.assertEqual(native["status"], "skipped")

        plan_lines = [r["text"] for r in self.engine.live_logs if "מסיר התוכנה המקורי" in r["text"]]
        self.assertTrue(plan_lines)
        # The printed plan must not advertise a step that is already skipped.
        self.assertNotIn("~", plan_lines[0])
        self.assertIn("דולג", plan_lines[0])

    def test_a_skipped_scan_does_not_leave_a_step_pending(self):
        self.engine._plan_steps(True, True, False)
        self.engine._skip_requested.set()
        self.engine.scan_leftovers({"name": "Acme"}, mode="moderate")
        statuses = {s["id"]: s["status"] for s in self.engine._steps}
        self.assertNotIn("pending", statuses.values())
        self.assertNotIn("running", statuses.values())
        # The bar must land on a terminal value, never stick part-way under a
        # "scan complete" message. (On Windows the registry sweep completes
        # before the skip is noticed, so 100 is also correct.)
        self.assertIn(self.engine._compute_percent_locked(), (0, 100))

    APP = {
        "name": "Acme Toolbar",
        "publisher": "Acme",
        "install_location": r"C:\Program Files\Acme\Toolbar",
        "registry_key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Acme",
        "raw_key_name": "Acme",
    }

    def _spy_scan(self, **kwargs):
        """Runs a scan while recording what the two producers were handed."""
        seen = {"own_key_calls": 0, "own_folder": "__unset__"}
        self.engine._scan_own_uninstall_key = lambda *a, **k: seen.__setitem__(
            "own_key_calls", seen["own_key_calls"] + 1)

        real_fs = self.engine._scan_filesystem_leftovers

        def spy_fs(*args, **kw):
            seen["own_folder"] = kw.get("own_folder", "__unset__")
            return real_fs(*args, **kw)

        self.engine._scan_filesystem_leftovers = spy_fs
        res = self.engine.scan_leftovers(dict(self.APP), **kwargs)
        return res, seen

    def test_a_preview_scan_excludes_the_live_installation(self):
        # still_installed means nothing was uninstalled: the program's own
        # folder and Add/Remove entry are the program, not residue, and must
        # never reach the review screen - let alone pre-selected.
        res, seen = self._spy_scan(mode="moderate", still_installed=True)
        self.assertTrue(res["still_installed"])
        self.assertEqual(seen["own_key_calls"], 0)
        self.assertEqual(seen["own_folder"], "")
        self.assertFalse(any(i.get("is_bold") for i in res["registry"] + res["files"]))

    def test_an_ordinary_scan_includes_them(self):
        res, seen = self._spy_scan(mode="moderate")
        self.assertFalse(res["still_installed"])
        self.assertEqual(seen["own_folder"], self.APP["install_location"])
        if IS_WINDOWS_HOST:
            self.assertEqual(seen["own_key_calls"], 1)

    def test_plan_percent_is_published_without_a_session(self):
        self.engine._plan_steps(True, True, False)
        self.engine._begin_step("native_uninstall")
        self.engine._end_step("native_uninstall")
        out = self.engine.get_session_status()
        self.assertFalse(out["active"])
        self.assertEqual(out["plan_percent"], 48)

    def test_eta_is_live_for_a_run_that_never_claims_busy(self):
        self.engine._plan_steps(True, True, False)
        self.engine._begin_step("scan_registry")
        self.engine._started_at = time.time() - 5   # give the pace something to divide
        out = self.engine.get_session_status()
        self.assertFalse(self.engine._busy)
        self.assertGreater(out["eta_seconds"], 0)

    def test_eta_is_zero_when_nothing_is_running(self):
        self.engine._plan_steps(True, True, False)
        self.assertEqual(self.engine.get_session_status()["eta_seconds"], 0)


class TestNameTokenMatching(unittest.TestCase):
    """
    Regression coverage for the batch-uninstall bug where uninstalling
    "Zoom" matched (and could auto-delete) the unrelated "ZoomIt" folder,
    because leftover scanning used substring containment ("zoom" in
    "zoomit") instead of whole-word matching.
    """

    def test_substring_of_an_unrelated_name_does_not_match(self):
        self.assertFalse(_token_matches_name("Zoom", "ZoomIt"))
        self.assertFalse(_token_matches_name("Zoom", "ZoomItSettings"))
        self.assertFalse(_token_matches_name("player", "MediaPlayerSync"))

    def test_whole_word_matches_still_work(self):
        self.assertTrue(_token_matches_name("Zoom", "Zoom"))
        self.assertTrue(_token_matches_name("Zoom", "Zoom Cache"))
        self.assertTrue(_token_matches_name("Zoom", "Zoom-Backup"))
        self.assertTrue(_token_matches_name("Zoom", "zoom.old"))
        self.assertTrue(_token_matches_name("Zoom", "Zoom.lnk"))
        self.assertTrue(_token_matches_name("Zoom", "My Zoom Backup"))

    def test_empty_inputs_never_match(self):
        self.assertFalse(_token_matches_name("", "Zoom"))
        self.assertFalse(_token_matches_name("Zoom", ""))
        self.assertFalse(_token_matches_name(None, "Zoom"))


class TestBatchAutoCleanProvenance(unittest.TestCase):
    """
    Regression coverage for run_batch_uninstall's auto/review split: only
    items with a definite provenance (the app's own install folder, its own
    Uninstall key, or a matching shortcut) may be deleted unattended. A
    name-heuristic match - even one marked is_bold/risk=low - must be routed
    to needs_review instead.
    """

    def setUp(self):
        self.engine = bare_engine()
        self._old_env = {}

    def tearDown(self):
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _set_env(self, key, value):
        self._old_env[key] = os.environ.get(key)
        os.environ[key] = value

    def _bypass_drive_letter_guard(self):
        """
        is_path_safe_to_delete requires a Windows-style "C:\\..." path, which
        a real temp directory on the Linux test host can never be. These
        tests are about the name-matching/auto_safe logic in
        _scan_filesystem_leftovers, not the drive-letter path format (that is
        covered separately by TestFilesystemDeletionGuard), so the guard is
        bypassed here and restored in tearDown.
        """
        self._old_guard = ue.is_path_safe_to_delete
        ue.is_path_safe_to_delete = lambda path: (True, None)
        self.addCleanup(lambda: setattr(ue, 'is_path_safe_to_delete', self._old_guard))

    def test_name_matched_settings_folder_is_not_auto_safe(self):
        self._bypass_drive_letter_guard()
        tmp = tempfile.mkdtemp()
        try:
            appdata = os.path.join(tmp, "AppData")
            os.makedirs(os.path.join(appdata, "Zoom"))
            os.makedirs(os.path.join(appdata, "ZoomIt"))
            self._set_env("APPDATA", appdata)
            self._set_env("LOCALAPPDATA", os.path.join(tmp, "LocalAppData_nonexistent"))
            self._set_env("ProgramData", os.path.join(tmp, "ProgramData_nonexistent"))

            leftovers = []
            shared_dlls = self.engine._get_shared_dlls_table()
            self.engine._scan_filesystem_leftovers(
                ["Zoom"], [], "", shared_dlls, "moderate", leftovers, [],
                own_folder="",
            )

            names = {i["name"].lower(): i for i in leftovers if i["type"] == "folder"}
            self.assertIn("zoom", names)
            self.assertNotIn("zoomit", names,
                              "ZoomIt must not be matched by the 'Zoom' name token")
            self.assertFalse(names["zoom"].get("auto_safe"),
                              "a name-heuristic folder match must never be auto-deletable")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_own_install_folder_is_auto_safe(self):
        self._bypass_drive_letter_guard()
        tmp = tempfile.mkdtemp()
        try:
            install_dir = os.path.join(tmp, "Program Files", "Acme", "Widget")
            os.makedirs(install_dir)
            leftovers = []
            shared_dlls = {}
            self.engine._scan_filesystem_leftovers(
                ["Widget"], ["Acme"], install_dir, shared_dlls, "safe", leftovers, [],
                own_folder=install_dir,
            )
            own = next((i for i in leftovers if i["path"] == install_dir), None)
            self.assertIsNotNone(own)
            self.assertTrue(own.get("auto_safe"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestForcedUninstallTargetValidation(unittest.TestCase):
    """
    Regression coverage for forced uninstall accepting any client-supplied
    path as an install location: pasting an arbitrary folder (e.g. a source
    code directory) used to get it flagged is_bold=True/auto_safe=True,
    pre-selected for one-click deletion, without ever checking it was
    actually a program.
    """

    def setUp(self):
        self.engine = bare_engine()

    def test_folder_with_no_binaries_does_not_look_like_a_program(self):
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "notes.txt"), "w") as f:
                f.write("just some personal notes")
            os.makedirs(os.path.join(tmp, "src"))
            with open(os.path.join(tmp, "src", "main.py"), "w") as f:
                f.write("print('hello')")
            self.assertFalse(self.engine._folder_looks_like_a_program(tmp))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_folder_with_an_exe_looks_like_a_program(self):
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "app.exe"), "wb") as f:
                f.write(b"MZ")
            self.assertTrue(self.engine._folder_looks_like_a_program(tmp))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_nonexistent_or_non_directory_is_not_a_program_folder(self):
        self.assertFalse(self.engine._folder_looks_like_a_program(""))
        self.assertFalse(self.engine._folder_looks_like_a_program(r"C:\NonExistent_XYZ"))

    def test_forced_uninstall_refuses_a_folder_with_no_binaries(self):
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "diary.txt"), "w") as f:
                f.write("personal notes, not a program")
            result = self.engine.run_forced_uninstall(tmp, mode="moderate")
            self.assertFalse(result["success"])
            self.assertIn("קובצי הרצה", result["error"])
            # And the engine must not be left claimed after the refusal.
            self.assertFalse(self.engine._busy)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_match_installed_app_by_install_location(self):
        self.engine.cached_apps = [{
            "id": "win32_abc", "name": "Acme Widget", "publisher": "Acme",
            "install_location": r"C:\Program Files\Acme\Widget",
            "registry_key": r"HKLM\SOFTWARE\Acme\Widget", "raw_key_name": "Widget",
        }]
        self.engine.last_apps_fetch = time.time()
        match = self.engine._match_installed_app(r"C:\Program Files\Acme\Widget")
        self.assertIsNotNone(match)
        self.assertEqual(match["name"], "Acme Widget")

    def test_match_installed_app_by_name(self):
        self.engine.cached_apps = [{
            "id": "win32_abc", "name": "Acme Widget", "publisher": "Acme",
            "install_location": r"C:\Program Files\Acme\Widget",
            "registry_key": r"HKLM\SOFTWARE\Acme\Widget", "raw_key_name": "Widget",
        }]
        self.engine.last_apps_fetch = time.time()
        match = self.engine._match_installed_app("acme widget")
        self.assertIsNotNone(match)
        self.assertEqual(match["install_location"], r"C:\Program Files\Acme\Widget")

    def test_match_installed_app_no_match_returns_none(self):
        self.engine.cached_apps = [{
            "id": "win32_abc", "name": "Acme Widget", "publisher": "Acme",
            "install_location": r"C:\Program Files\Acme\Widget",
            "registry_key": r"HKLM\SOFTWARE\Acme\Widget", "raw_key_name": "Widget",
        }]
        self.engine.last_apps_fetch = time.time()
        self.assertIsNone(self.engine._match_installed_app(r"C:\Users\me\Projects"))

    def test_unverified_folder_is_offered_but_not_preselected(self):
        # A folder that does look like a program, but wasn't matched to a
        # real installed app, must still show up for review - just not
        # pre-ticked for one-click deletion.
        self._old_guard = ue.is_path_safe_to_delete
        ue.is_path_safe_to_delete = lambda path: (True, None)
        self.addCleanup(lambda: setattr(ue, 'is_path_safe_to_delete', self._old_guard))

        tmp = tempfile.mkdtemp()
        try:
            install_dir = os.path.join(tmp, "SomeTool")
            os.makedirs(install_dir)
            with open(os.path.join(install_dir, "tool.exe"), "wb") as f:
                f.write(b"MZ")
            leftovers = []
            self.engine._scan_filesystem_leftovers(
                ["SomeTool"], [], install_dir, {}, "safe", leftovers, [],
                own_folder=install_dir, own_folder_verified=False,
            )
            own = next((i for i in leftovers if i["path"] == install_dir), None)
            self.assertIsNotNone(own)
            self.assertFalse(own.get("is_bold"))
            self.assertFalse(own.get("auto_safe"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestModuleImportsWithoutWindows(unittest.TestCase):
    """v2.6 fixed a module-level winreg import that killed the server on
    non-Windows; this locks it down so it cannot come back a third time."""

    def test_winreg_and_psutil_are_optional(self):
        self.assertTrue(hasattr(ue, "winreg"))
        self.assertTrue(hasattr(ue, "psutil"))

    def test_psutil_is_reachable_at_module_scope(self):
        # Hunter mode referenced psutil without importing it at module level,
        # so every call raised NameError and was swallowed.
        import backend.uninstaller_engine as mod
        src = open(mod.__file__, encoding="utf-8").read()
        self.assertIn("import psutil", src)

    def test_backup_directories_are_not_created_at_import_time(self):
        self.assertTrue(hasattr(UninstallerEngine, "_ensure_backup_dirs"))


class TestUWPForcedUninstall(unittest.TestCase):

    def test_resolve_uwp_target_by_windowsapps_path(self):
        engine = bare_engine()
        engine._get_uwp_apps = lambda: [{
            "id": "uwp_123",
            "type": "uwp",
            "name": "XboxGamingOverlay",
            "raw_name": "Microsoft.XboxGamingOverlay",
            "package_full_name": "Microsoft.XboxGamingOverlay_7.326.8061.0_x64__8wekyb3d8bbwe",
            "package_family_name": "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe",
            "install_location": r"C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_7.326.8061.0_x64__8wekyb3d8bbwe",
        }]
        # By full folder path
        res = engine._resolve_uwp_target(r"C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_7.326.8061.0_x64__8wekyb3d8bbwe")
        self.assertIsNotNone(res)
        self.assertEqual(res["package_full_name"], "Microsoft.XboxGamingOverlay_7.326.8061.0_x64__8wekyb3d8bbwe")
        self.assertEqual(res["name"], "XboxGamingOverlay")

        # By inner file path
        res2 = engine._resolve_uwp_target(r"C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_7.326.8061.0_x64__8wekyb3d8bbwe\appxmanifest.xml")
        self.assertIsNotNone(res2)
        self.assertEqual(res2["package_full_name"], "Microsoft.XboxGamingOverlay_7.326.8061.0_x64__8wekyb3d8bbwe")

        # Non-UWP regular path
        self.assertIsNone(engine._resolve_uwp_target(r"C:\Program Files\Acme\app.exe"))

    def test_resolve_uwp_target_by_package_name(self):
        engine = bare_engine()
        engine._get_uwp_apps = lambda: []
        # Package full name format inferred directly
        res = engine._resolve_uwp_target("Vendor.App_1.2.3.4_x64__8wekyb3d8bbwe")
        self.assertIsNotNone(res)
        self.assertEqual(res["package_full_name"], "Vendor.App_1.2.3.4_x64__8wekyb3d8bbwe")
        self.assertEqual(res["type"], "uwp")

    def test_forced_uninstall_executes_remove_appx_package(self):
        engine = bare_engine()
        engine._get_uwp_apps = lambda: [{
            "id": "uwp_123",
            "type": "uwp",
            "name": "XboxGamingOverlay",
            "raw_name": "Microsoft.XboxGamingOverlay",
            "package_full_name": "Microsoft.XboxGamingOverlay_7.326.8061.0_x64__8wekyb3d8bbwe",
            "package_family_name": "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe",
            "install_location": r"C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_7.326.8061.0_x64__8wekyb3d8bbwe",
        }]
        engine.scan_leftovers = lambda app_meta, mode="moderate", still_installed=False: {"registry": [], "files": []}

        executed_commands = []
        class DummyCompletedProcess:
            returncode = 0
            stdout = ""
            stderr = ""

        from unittest.mock import patch
        with patch("backend.uninstaller_engine.run_hidden", side_effect=lambda cmd, **kw: (executed_commands.append(cmd), DummyCompletedProcess())[1]):
            res = engine.run_forced_uninstall(r"C:\Program Files\WindowsApps\Microsoft.XboxGamingOverlay_7.326.8061.0_x64__8wekyb3d8bbwe")

        self.assertTrue(res["success"])
        self.assertTrue(res.get("is_uwp"))
        self.assertTrue(res.get("native_uninstall_ok"))
        self.assertTrue(any("Remove-AppxPackage" in str(cmd) for cmd in executed_commands))
        native_step = next(s for s in engine._steps if s["id"] == "native_uninstall")
        self.assertEqual(native_step["status"], "done")


class TestServiceDeletionViaSCM(unittest.TestCase):
    """
    Regression coverage: a service/driver leftover used to be deleted as a
    raw registry key, which never asked Windows to stop the service first
    and had no idea whether the key belonged to a boot-critical driver.
    Deletion must now go through sc.exe, and must refuse outright when the
    Start value says the service loads at or before boot.
    """

    def setUp(self):
        self.engine = bare_engine()
        self._patches = []

    def tearDown(self):
        for restore in self._patches:
            restore()

    def _patch(self, obj, name, value):
        # obj.__dict__[name] (not getattr) so that patching a staticmethod on
        # a class captures the raw descriptor rather than the unwrapped
        # function - restoring via the unwrapped function would silently turn
        # it into a bound instance method for every test that runs after.
        old = obj.__dict__[name]
        setattr(obj, name, value)
        self._patches.append(lambda: setattr(obj, name, old))

    def _register_service_item(self, svc_name="AcmeFilter"):
        item = {
            "type": "key",
            "path": f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc_name}",
            "name": svc_name,
            "hive": "HKLM",
            "is_bold": True,
            "risk": "high",
            "reason": "שירות מערכת או דרייבר שהושאר ברקע",
        }
        item["id"] = make_item_id(item)
        self.engine._scan_index[item["id"]] = item
        return item

    def test_boot_start_service_is_refused(self):
        self._patch(ue, "is_admin", lambda: True)
        self._patch(UninstallerEngine, "_read_service_start_type", staticmethod(lambda svc: 0))
        called = []
        self._patch(UninstallerEngine, "_delete_service_via_scm",
                    staticmethod(lambda svc: (called.append(svc), (True, None))[1]))

        item = self._register_service_item()
        res = self.engine.delete_leftovers(selected_ids=[item["id"]])

        self.assertEqual(res["failed_count"], 1)
        self.assertEqual(res["deleted_registry"], 0)
        self.assertEqual(called, [], "sc.exe must never be invoked for a boot-start service")
        self.assertIn("אתחול", res["failed"][0]["reason"])

    def test_unknown_start_type_is_refused(self):
        self._patch(ue, "is_admin", lambda: True)
        self._patch(UninstallerEngine, "_read_service_start_type", staticmethod(lambda svc: None))
        called = []
        self._patch(UninstallerEngine, "_delete_service_via_scm",
                    staticmethod(lambda svc: (called.append(svc), (True, None))[1]))

        item = self._register_service_item()
        res = self.engine.delete_leftovers(selected_ids=[item["id"]])

        self.assertEqual(res["failed_count"], 1)
        self.assertEqual(called, [])

    def test_demand_start_service_goes_through_scm(self):
        self._patch(ue, "is_admin", lambda: True)
        self._patch(UninstallerEngine, "_read_service_start_type", staticmethod(lambda svc: 3))
        called = []
        self._patch(UninstallerEngine, "_delete_service_via_scm",
                    staticmethod(lambda svc: (called.append(svc), (True, None))[1]))

        item = self._register_service_item("AcmeHelper")
        res = self.engine.delete_leftovers(selected_ids=[item["id"]])

        self.assertEqual(res["deleted_registry"], 1)
        self.assertEqual(res["failed_count"], 0)
        self.assertEqual(called, ["AcmeHelper"])
        self.assertEqual(res["failed"], [])

    def test_scm_failure_is_reported_and_key_is_not_raw_deleted(self):
        self._patch(ue, "is_admin", lambda: True)
        self._patch(UninstallerEngine, "_read_service_start_type", staticmethod(lambda svc: 2))
        self._patch(UninstallerEngine, "_delete_service_via_scm",
                    staticmethod(lambda svc: (False, "access denied")))
        raw_delete_called = []
        self._patch(UninstallerEngine, "_delete_reg_key_recursive",
                    lambda self, path: (raw_delete_called.append(path), (True, None))[1])

        item = self._register_service_item("AcmeAuto")
        res = self.engine.delete_leftovers(selected_ids=[item["id"]])

        self.assertEqual(res["deleted_registry"], 0)
        self.assertEqual(res["failed_count"], 1)
        self.assertEqual(raw_delete_called, [],
                          "a failed SCM delete must never fall back to a raw key delete")

    def test_delete_service_via_scm_stops_then_deletes(self):
        self._patch(ue, "IS_WINDOWS", True)
        commands = []

        class DummyResult:
            returncode = 0
            stdout = ""
            stderr = ""

        self._patch(ue, "run_hidden", lambda cmd, **kw: (commands.append(cmd), DummyResult())[1])

        ok, err = self.engine._delete_service_via_scm("AcmeHelper")
        self.assertTrue(ok)
        self.assertEqual(len(commands), 2)
        self.assertIn("stop", commands[0])
        self.assertIn("delete", commands[1])

    def test_delete_service_via_scm_refuses_off_windows(self):
        self._patch(ue, "IS_WINDOWS", False)
        ok, err = self.engine._delete_service_via_scm("AcmeHelper")
        self.assertFalse(ok)

    def test_service_key_deletion_is_skipped_without_elevation(self):
        # HKLM items are refused before the service-specific logic even runs -
        # this just confirms that pre-existing gate still applies here too.
        self._patch(ue, "is_admin", lambda: False)
        item = self._register_service_item()
        res = self.engine.delete_leftovers(selected_ids=[item["id"]])
        self.assertEqual(res["failed_count"], 1)
        self.assertIn("מנהל", res["failed"][0]["reason"])


class TestScheduledTaskLeftovers(unittest.TestCase):
    """
    Regression coverage for Stage 3.1: scheduled tasks are flagged in the
    plan as the single most common leftover the original scanner missed
    entirely (an auto-update task nothing else ever cleans up). Covers the
    scanner's matching/exclusion rules and the schtasks-based deletion path,
    both driven through the same run_powershell_json / run_hidden
    indirection points the rest of this engine already uses so nothing here
    needs a real Windows box or a real Task Scheduler.
    """

    def setUp(self):
        self.engine = bare_engine()
        self._patches = []

    def tearDown(self):
        for restore in self._patches:
            restore()

    def _patch(self, obj, name, value):
        old = obj.__dict__[name] if name in obj.__dict__ else getattr(obj, name)
        setattr(obj, name, value)
        self._patches.append(lambda: setattr(obj, name, old))

    def test_task_matching_the_install_folder_is_a_strong_bold_match(self):
        self._patch(ue, "IS_WINDOWS", True)
        tasks = [{
            "TaskName": "UpdateChecker",
            "TaskPath": "\\Acme\\",
            "Execute": r"C:\Program Files\Acme\Toolbar\updater.exe",
            "Arguments": "",
        }]
        self._patch(ue, "run_powershell_json", lambda cmd, timeout=20: tasks)

        leftovers = []
        self.engine._scan_scheduled_tasks(["Acme", "Toolbar"], r"C:\Program Files\Acme\Toolbar", leftovers)

        self.assertEqual(len(leftovers), 1)
        item = leftovers[0]
        self.assertEqual(item["type"], "scheduled_task")
        self.assertEqual(item["path"], "\\Acme\\UpdateChecker")
        self.assertTrue(item["is_bold"])

    def test_task_matching_only_by_name_is_offered_but_not_preselected(self):
        self._patch(ue, "IS_WINDOWS", True)
        tasks = [{
            "TaskName": "AcmeToolbarUpdate",
            "TaskPath": "\\",
            "Execute": r"C:\Windows\System32\schtasks_helper.exe",
            "Arguments": "",
        }]
        self._patch(ue, "run_powershell_json", lambda cmd, timeout=20: tasks)

        leftovers = []
        self.engine._scan_scheduled_tasks(["Acme", "Toolbar"], r"C:\Program Files\Acme\Toolbar", leftovers)

        self.assertEqual(len(leftovers), 1)
        self.assertFalse(leftovers[0]["is_bold"])

    def test_microsoft_namespace_tasks_are_never_candidates(self):
        self._patch(ue, "IS_WINDOWS", True)
        tasks = [{
            "TaskName": "Acme",  # name-token match would otherwise trigger
            "TaskPath": "\\Microsoft\\Windows\\Acme\\",
            "Execute": r"C:\Program Files\Acme\Toolbar\updater.exe",  # even a path match
            "Arguments": "",
        }]
        self._patch(ue, "run_powershell_json", lambda cmd, timeout=20: tasks)

        leftovers = []
        self.engine._scan_scheduled_tasks(["Acme"], r"C:\Program Files\Acme\Toolbar", leftovers)
        self.assertEqual(leftovers, [])

    def test_unrelated_task_is_not_matched(self):
        self._patch(ue, "IS_WINDOWS", True)
        tasks = [{
            "TaskName": "DropboxUpdate",
            "TaskPath": "\\",
            "Execute": r"C:\Program Files\Dropbox\Update\DropboxUpdate.exe",
            "Arguments": "",
        }]
        self._patch(ue, "run_powershell_json", lambda cmd, timeout=20: tasks)

        leftovers = []
        self.engine._scan_scheduled_tasks(["Acme", "Toolbar"], r"C:\Program Files\Acme\Toolbar", leftovers)
        self.assertEqual(leftovers, [])

    def test_off_windows_scan_is_a_no_op(self):
        # IS_WINDOWS is already False in this sandbox - just confirms the
        # method doesn't try to call run_powershell_json (which itself
        # already returns [] off-Windows, but the point is it isn't reached).
        called = []
        self._patch(ue, "run_powershell_json", lambda cmd, timeout=20: called.append(1) or [])
        leftovers = []
        self.engine._scan_scheduled_tasks(["Acme"], r"C:\Program Files\Acme\Toolbar", leftovers)
        self.assertEqual(leftovers, [])
        self.assertEqual(called, [])

    def _register_task_item(self, path="\\Acme\\UpdateChecker", name="UpdateChecker"):
        item = {
            "type": "scheduled_task", "path": path, "name": name,
            "is_bold": True, "risk": "low",
            "reason": "משימה מתוזמנת שנשארה מאחור",
        }
        item["id"] = make_item_id(item)
        self.engine._scan_index[item["id"]] = item
        return item

    def test_successful_deletion_is_counted_and_reported(self):
        self._patch(ue, "IS_WINDOWS", True)
        self._patch(UninstallerEngine, "_export_scheduled_task_xml",
                    staticmethod(lambda path, session_dir: None))

        def fake_run(cmd, **kwargs):
            class R:
                returncode = 0
                stdout = ""
                stderr = ""
            return R()
        self._patch(ue, "run_hidden", fake_run)

        item = self._register_task_item()
        res = self.engine.delete_leftovers(selected_ids=[item["id"]])

        self.assertTrue(res["success"])
        self.assertEqual(res["deleted_tasks"], 1)
        self.assertEqual(res["failed_count"], 0)

    def test_schtasks_failure_is_reported_not_silently_dropped(self):
        self._patch(ue, "IS_WINDOWS", True)
        self._patch(UninstallerEngine, "_export_scheduled_task_xml",
                    staticmethod(lambda path, session_dir: None))

        def fake_run(cmd, **kwargs):
            class R:
                returncode = 1
                stdout = "ERROR: The system cannot find the file specified."
                stderr = ""
            return R()
        self._patch(ue, "run_hidden", fake_run)

        item = self._register_task_item()
        res = self.engine.delete_leftovers(selected_ids=[item["id"]])

        self.assertFalse(res["success"])
        self.assertEqual(res["deleted_tasks"], 0)
        self.assertEqual(res["failed_count"], 1)

    def test_a_microsoft_namespace_task_id_is_refused_even_if_forged_into_the_index(self):
        # Defense in depth: even if something bypassed the scanner's own
        # exclusion and got a \Microsoft\... task into the scan index, the
        # deletion path itself must refuse it independently.
        self._patch(ue, "IS_WINDOWS", True)
        deletion_attempted = []
        self._patch(UninstallerEngine, "_delete_scheduled_task",
                    staticmethod(lambda path: (deletion_attempted.append(path), (True, None))[1]))

        item = self._register_task_item(path="\\Microsoft\\Windows\\SomeTask", name="SomeTask")
        res = self.engine.delete_leftovers(selected_ids=[item["id"]])

        self.assertEqual(res["deleted_tasks"], 0)
        self.assertEqual(res["failed_count"], 1)
        self.assertEqual(deletion_attempted, [])


class TestDeleteLeftoversHonestReporting(unittest.TestCase):
    """
    Regression coverage: delete_leftovers used to return success=True
    unconditionally, even when every selected item failed, and a folder
    scheduled for reboot-deletion was counted in `failed` at the same time as
    `pending_reboot_files` - double-counting a non-failure as a failure.
    """

    def setUp(self):
        self.engine = bare_engine()
        self._patches = []
        self._old_guard = ue.is_path_safe_to_delete
        ue.is_path_safe_to_delete = lambda path: (True, None)

    def tearDown(self):
        ue.is_path_safe_to_delete = self._old_guard
        for restore in self._patches:
            restore()

    def _patch(self, obj, name, value):
        old = obj.__dict__[name] if name in obj.__dict__ else getattr(obj, name)
        setattr(obj, name, value)
        self._patches.append(lambda: setattr(obj, name, old))

    def _register_file_item(self, path, item_type="file"):
        item = {"type": item_type, "path": path, "name": os.path.basename(path)}
        item["id"] = make_item_id(item)
        self.engine._scan_index[item["id"]] = item
        return item

    def test_success_is_true_when_everything_is_removed(self):
        tmp = tempfile.mkdtemp()
        try:
            f = os.path.join(tmp, "leftover.txt")
            with open(f, "w") as fh:
                fh.write("x")
            item = self._register_file_item(f)
            res = self.engine.delete_leftovers(selected_ids=[item["id"]])
            self.assertTrue(res["success"])
            self.assertEqual(res["failed_count"], 0)
            self.assertEqual(res["deleted_files"], 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_success_is_false_when_something_fails(self):
        # A file item pointing at a path that does not exist counts as
        # "nothing to delete" in the current code (silently skipped, not
        # even counted) - so use a genuinely undeletable target instead: a
        # directory item whose _force_remove_tree is made a no-op and whose
        # reboot scheduling also fails, so it must land in `failed`.
        tmp = tempfile.mkdtemp()
        try:
            self._patch(UninstallerEngine, "_force_remove_tree", staticmethod(lambda p: None))
            self._patch(UninstallerEngine, "_schedule_reboot_folder_deletion", lambda self, p: False)
            item = self._register_file_item(tmp, item_type="folder")
            res = self.engine.delete_leftovers(selected_ids=[item["id"]])
            self.assertFalse(res["success"])
            self.assertEqual(res["failed_count"], 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_reboot_scheduled_folder_is_not_double_counted_as_failed(self):
        tmp = tempfile.mkdtemp()
        try:
            self._patch(UninstallerEngine, "_force_remove_tree", staticmethod(lambda p: None))
            self._patch(UninstallerEngine, "_schedule_reboot_folder_deletion", lambda self, p: True)
            item = self._register_file_item(tmp, item_type="folder")
            res = self.engine.delete_leftovers(selected_ids=[item["id"]])

            # Scheduled for reboot is not a failure: success stays True and
            # failed_count stays 0, matching the file-item branch's behavior.
            self.assertTrue(res["success"])
            self.assertEqual(res["failed_count"], 0)
            self.assertEqual(res["failed"], [])
            self.assertEqual(res["pending_reboot_count"], 1)
            self.assertIn(tmp, res["pending_reboot_files"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_reboot_scheduled_file_is_not_counted_as_failed(self):
        tmp = tempfile.mkdtemp()
        try:
            f = os.path.join(tmp, "locked.dll")
            with open(f, "w") as fh:
                fh.write("x")
            # Simulate a locked file: os.remove "succeeds" but the file is
            # still there, so the code falls through to reboot scheduling.
            self._patch(os, "remove", lambda p: None)
            self._patch(UninstallerEngine, "_schedule_reboot_deletion", lambda self, p: True)
            item = self._register_file_item(f)
            res = self.engine.delete_leftovers(selected_ids=[item["id"]])

            self.assertTrue(res["success"])
            self.assertEqual(res["failed_count"], 0)
            self.assertEqual(res["pending_reboot_count"], 1)
            self.assertIn(f, res["pending_reboot_files"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_truncated_folder_size_is_flagged_as_a_lower_bound(self):
        # _quick_dir_size caps how many files it walks, so its byte count can
        # undercount a large folder. delete_leftovers used to fold that
        # number into freed_bytes/freed_formatted with no indication it was
        # anything but exact.
        tmp = tempfile.mkdtemp()
        try:
            item = self._register_file_item(tmp, item_type="folder")
            self._patch(UninstallerEngine, "_quick_dir_size",
                        lambda self, p: (12345, True))
            self._patch(UninstallerEngine, "_force_remove_tree",
                        staticmethod(lambda p: shutil.rmtree(p, ignore_errors=True)))

            res = self.engine.delete_leftovers(selected_ids=[item["id"]])

            self.assertTrue(res["success"])
            self.assertTrue(res["freed_bytes_is_lower_bound"])
            self.assertTrue(res["freed_formatted"].startswith("לפחות "))
            self.assertEqual(res["freed_bytes"], 12345)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_untruncated_folder_size_is_not_flagged(self):
        tmp = tempfile.mkdtemp()
        try:
            f = os.path.join(tmp, "leftover.txt")
            with open(f, "w") as fh:
                fh.write("x" * 10)
            item = self._register_file_item(tmp, item_type="folder")

            res = self.engine.delete_leftovers(selected_ids=[item["id"]])

            self.assertTrue(res["success"])
            self.assertFalse(res["freed_bytes_is_lower_bound"])
            self.assertFalse(res["freed_formatted"].startswith("לפחות "))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestRegistryBackupBeforeDelete(unittest.TestCase):
    """
    Regression coverage: backup_registry_key_tree's return value used to be
    checked only to decide whether to *record* a successful backup -
    deletion proceeded either way, so a failed export silently meant the key
    was deleted with no way to bring it back. On Windows a failed export
    must now cancel the deletion; off Windows (where there is no registry to
    export - reg.exe/winreg aren't available, which is also how this whole
    suite runs) the step is an expected no-op and must not block anything.
    """

    def setUp(self):
        self.engine = bare_engine()
        self._patches = []

    def tearDown(self):
        for restore in self._patches:
            restore()

    def _patch(self, obj, name, value):
        old = obj.__dict__[name] if name in obj.__dict__ else getattr(obj, name)
        setattr(obj, name, value)
        self._patches.append(lambda: setattr(obj, name, old))

    def _register_key_item(self, path=r"HKLM\SOFTWARE\Acme\Widget"):
        item = {"type": "key", "path": path, "name": "Widget", "hive": "HKLM"}
        item["id"] = make_item_id(item)
        self.engine._scan_index[item["id"]] = item
        return item

    def test_off_windows_a_failed_export_does_not_block_deletion(self):
        self._patch(ue, "is_admin", lambda: True)
        self._patch(UninstallerEngine, "backup_registry_key_tree", lambda self, p, d: None)
        self._patch(UninstallerEngine, "_delete_reg_key_recursive",
                    lambda self, p: (True, None))
        item = self._register_key_item()
        res = self.engine.delete_leftovers(selected_ids=[item["id"]])
        self.assertTrue(res["success"])
        self.assertEqual(res["deleted_registry"], 1)

    def test_on_windows_a_failed_export_cancels_the_deletion(self):
        self._patch(ue, "is_admin", lambda: True)
        self._patch(ue, "IS_WINDOWS", True)
        self._patch(UninstallerEngine, "backup_registry_key_tree", lambda self, p, d: None)
        raw_delete_called = []
        self._patch(UninstallerEngine, "_delete_reg_key_recursive",
                    lambda self, p: (raw_delete_called.append(p), (True, None))[1])

        item = self._register_key_item()
        res = self.engine.delete_leftovers(selected_ids=[item["id"]])

        self.assertFalse(res["success"])
        self.assertEqual(res["deleted_registry"], 0)
        self.assertEqual(raw_delete_called, [],
                          "deletion must never proceed once the backup export has failed")
        self.assertIn("גיבוי", res["failed"][0]["reason"])

    def test_on_windows_a_successful_export_allows_deletion(self):
        self._patch(ue, "is_admin", lambda: True)
        self._patch(ue, "IS_WINDOWS", True)
        self._patch(UninstallerEngine, "backup_registry_key_tree",
                    lambda self, p, d: "/fake/backup.reg")
        self._patch(UninstallerEngine, "_delete_reg_key_recursive",
                    lambda self, p: (True, None))

        item = self._register_key_item()
        res = self.engine.delete_leftovers(selected_ids=[item["id"]])
        self.assertTrue(res["success"])
        self.assertEqual(res["deleted_registry"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

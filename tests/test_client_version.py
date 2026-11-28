"""Isolated app/baseline fixtures only; never inspect installed Claude or user data."""
import json
import os
from pathlib import Path
import plistlib
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import client_version
from client_version import BASELINE_NAME, ClaudeVersionObserver, MAX_BASELINE_BYTES, MAX_INFO_BYTES


class ClientVersionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rg-version-fixture-")
        self.root = Path(self.temporary.name).resolve()
        self.apps = (self.root / "system/Claude.app", self.root / "user/Claude.app")
        self.data = self.root / "private-data"

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, version="6.28899.6", *, index=0, raw=None, bundle_id="com.anthropic.claudefordesktop"):
        path = self.apps[index] / "Contents/Info.plist"
        path.parent.mkdir(parents=True, exist_ok=True)
        obj = {"CFBundleIdentifier": bundle_id, "CFBundleShortVersionString": version,
               "UnusedSecretField": "secret-fixture-device"}
        path.write_bytes(plistlib.dumps(obj) if raw is None else raw)
        return path

    def observer(self):
        return ClaudeVersionObserver(self.data, self.apps)

    def baseline(self):
        return self.data / BASELINE_NAME

    def test_constructor_and_status_do_not_read_or_write(self):
        with patch.object(client_version.os, "open", side_effect=AssertionError("unexpected IO")):
            observer = self.observer()
            view = observer.status()
        self.assertEqual(view["state"], "unverified")
        self.assertFalse(self.data.exists())

    def test_missing_apps_do_not_create_private_directory(self):
        result = self.observer().sample()
        self.assertEqual(result["state"], "missing")
        self.assertFalse(result["review_required"])
        self.assertFalse(self.data.exists())

    def test_first_valid_version_creates_private_0600_baseline_without_warning(self):
        self.write()
        result = self.observer().sample()
        self.assertEqual(result["state"], "observed")
        self.assertEqual(result["current_version"], "6.28899.6")
        self.assertFalse(result["review_required"])
        self.assertEqual(stat.S_IMODE(self.baseline().stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.data.stat().st_mode), 0o700)
        baseline = json.loads(self.baseline().read_bytes())
        self.assertEqual(baseline, {"schema": 1, "versions": ["6.28899.6"], "previous_versions": [], "pending": False})

    def test_same_version_does_not_rewrite_baseline(self):
        self.write()
        observer = self.observer()
        observer.sample()
        with patch.object(observer, "_save", side_effect=AssertionError("unchanged baseline rewritten")):
            self.assertEqual(observer.sample()["state"], "observed")

    def test_change_sets_pending_and_previous_version_across_restart(self):
        self.write("6.1.0")
        self.observer().sample()
        self.write("6.2.0")
        changed = self.observer().check()
        self.assertEqual(changed["state"], "changed")
        self.assertEqual(changed["previous_version"], "6.1.0")
        self.assertEqual(changed["current_version"], "6.2.0")
        self.assertTrue(changed["review_required"])
        restarted = self.observer().sample()
        self.assertEqual(restarted, changed)
        self.assertTrue(json.loads(self.baseline().read_bytes())["pending"])

    def test_multiple_changes_retain_pending_and_update_last_previous(self):
        for version in ("6.1.0", "6.2.0", "6.3.0"):
            self.write(version)
            result = self.observer().sample()
        self.assertEqual(result["previous_versions"], ["6.2.0"])
        self.assertEqual(result["versions"], ["6.3.0"])
        self.assertTrue(result["review_required"])

    def test_two_known_bundles_are_both_recorded_without_paths(self):
        self.write("6.2.0", index=0)
        self.write("6.1.0", index=1)
        result = self.observer().sample()
        self.assertEqual(result["versions"], ["6.1.0", "6.2.0"])
        self.write("6.3.0", index=1)
        self.assertTrue(self.observer().sample()["review_required"])

    def test_same_version_in_two_bundles_is_deduplicated(self):
        self.write(index=0)
        self.write(index=1)
        self.assertEqual(self.observer().sample()["versions"], ["6.28899.6"])

    def test_invalid_version_never_escapes_or_overwrites_baseline(self):
        self.write("6.1.0")
        self.observer().sample()
        old = self.baseline().read_bytes()
        for value in ("secret-fixture-version", "6.2-beta", "6.2\nsecret", 6.2, "6", "1." + "2" * 60):
            with self.subTest(value=value):
                self.write(value)
                result = self.observer().sample()
                self.assertEqual(result["state"], "unknown")
                self.assertNotIn("secret", json.dumps(result))
                self.assertEqual(self.baseline().read_bytes(), old)

    def test_wrong_bundle_identifier_is_unknown(self):
        self.write(bundle_id="unrelated.fixture")
        self.assertEqual(self.observer().sample()["state"], "unknown")
        self.assertFalse(self.baseline().exists())

    def test_one_malformed_bundle_prevents_overwriting_a_complete_baseline(self):
        self.write("6.1.0", index=0)
        self.write("6.1.0", index=1)
        self.observer().sample()
        before = self.baseline().read_bytes()
        self.write("6.2.0", index=0)
        self.write(raw=b"broken plist", index=1)
        self.assertEqual(self.observer().sample()["state"], "unknown")
        self.assertEqual(self.baseline().read_bytes(), before)

    def test_oversized_or_unreadable_info_is_not_read(self):
        path = self.write(raw=b"x" * (MAX_INFO_BYTES + 1))
        with patch.object(client_version, "_read", side_effect=AssertionError("untrusted bytes read")):
            self.assertEqual(self.observer().sample()["state"], "unknown")
        self.write()
        path.chmod(0)
        with patch.object(client_version, "_read", side_effect=AssertionError("unreadable file read")):
            self.assertEqual(self.observer().sample()["state"], "unknown")
        path.chmod(0o600)

    def test_info_leaf_symlink_is_rejected(self):
        path = self.write()
        target = path.with_name("fixture-info")
        path.rename(target)
        path.symlink_to(target)
        self.assertEqual(self.observer().sample()["state"], "unknown")
        self.assertFalse(self.baseline().exists())

    def test_app_parent_symlink_is_rejected(self):
        self.write()
        actual = self.apps[0].with_name("actual.app")
        self.apps[0].rename(actual)
        self.apps[0].symlink_to(actual, target_is_directory=True)
        self.assertEqual(self.observer().sample()["state"], "unknown")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_info_fifo_does_not_block(self):
        path = self.write()
        path.unlink()
        os.mkfifo(path)
        self.assertEqual(self.observer().sample()["state"], "unknown")

    def test_foreign_directory_uid_is_rejected(self):
        self.write()
        observer = self.observer()
        observer._uid = os.getuid() + 1
        self.assertEqual(observer.sample()["state"], "unknown")

    def test_private_directory_symlink_and_insecure_permissions_are_rejected(self):
        self.write()
        target = self.root / "target-data"
        target.mkdir(mode=0o700)
        self.data.symlink_to(target, target_is_directory=True)
        self.assertEqual(self.observer().sample()["state"], "unknown")
        self.assertFalse((target / BASELINE_NAME).exists())
        self.data.unlink()
        self.data.mkdir(mode=0o755)
        self.assertEqual(self.observer().sample()["state"], "unknown")
        self.assertFalse(self.baseline().exists())

    def test_baseline_symlink_never_changes_its_target(self):
        self.write()
        self.data.mkdir(mode=0o700)
        target = self.root / "private-target"
        target.write_bytes(b"secret-fixture-target")
        self.baseline().symlink_to(target)
        self.assertEqual(self.observer().sample()["state"], "unknown")
        self.assertEqual(target.read_bytes(), b"secret-fixture-target")

    def test_bad_baseline_permissions_corruption_and_oversize_are_not_overwritten(self):
        self.write()
        self.observer().sample()
        self.baseline().chmod(0o644)
        old = self.baseline().read_bytes()
        self.assertEqual(self.observer().sample()["state"], "unknown")
        self.assertEqual(self.baseline().read_bytes(), old)
        self.baseline().chmod(0o600)
        for raw in (b"{", b"x" * (MAX_BASELINE_BYTES + 1),
                    b'{"schema":1,"schema":1,"versions":[],"previous_versions":[],"pending":false}'):
            self.baseline().write_bytes(raw)
            self.assertEqual(self.observer().sample()["state"], "unknown")
            self.assertEqual(self.baseline().read_bytes(), raw)

    def test_hardlinked_baseline_is_rejected(self):
        self.write()
        self.observer().sample()
        os.link(self.baseline(), self.root / "baseline-link")
        self.assertEqual(self.observer().sample()["state"], "unknown")

    def test_info_replacement_during_read_is_unknown_and_does_not_establish_baseline(self):
        path = self.write("6.1.0")
        original = client_version._read
        once = []
        def replace(fd, maximum):
            raw = original(fd, maximum)
            if not once:
                once.append(True)
                replacement = path.with_name("replacement")
                replacement.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.anthropic.claudefordesktop",
                                                       "CFBundleShortVersionString": "6.2.0"}))
                os.replace(replacement, path)
            return raw
        with patch.object(client_version, "_read", side_effect=replace):
            self.assertEqual(self.observer().sample()["state"], "unknown")
        self.assertFalse(self.baseline().exists())

    def test_failed_private_write_is_fixed_unknown_and_temp_is_cleaned(self):
        self.write()
        with patch.object(client_version.os, "write", side_effect=OSError("secret-fixture-error")):
            result = self.observer().sample()
        self.assertEqual(result["state"], "unknown")
        self.assertNotIn("secret-fixture", json.dumps(result))
        self.assertEqual(list(self.data.iterdir()), [])

    def test_pending_survives_temporarily_missing_client(self):
        path = self.write("6.1.0")
        self.observer().sample()
        self.write("6.2.0")
        self.observer().sample()
        path.unlink()
        result = self.observer().sample()
        self.assertEqual(result["state"], "missing")
        self.assertTrue(result["review_required"])
        self.assertEqual(result["previous_versions"], ["6.1.0"])

    def test_only_fixed_version_fields_are_exported_and_status_is_a_copy(self):
        self.write()
        observer = self.observer()
        result = observer.sample()
        self.assertEqual(set(result), {"state", "current_version", "previous_version", "versions", "previous_versions", "review_required"})
        rendered = json.dumps(result)
        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn("secret-fixture", rendered)
        self.assertNotIn("secret-fixture", self.baseline().read_text())
        result["versions"].clear()
        self.assertEqual(observer.status()["versions"], ["6.28899.6"])

    def test_explicit_review_clears_pending_across_restart_and_new_change_sets_it_again(self):
        self.write("6.1.0")
        self.observer().sample()
        self.write("6.2.0")
        observer = self.observer()
        changed = observer.sample()
        reviewed = observer.mark_reviewed(changed["versions"])
        self.assertEqual(reviewed["state"], "observed")
        self.assertFalse(reviewed["review_required"])
        self.assertEqual(reviewed["current_version"], "6.2.0")
        self.assertEqual(reviewed["previous_version"], "6.1.0")
        self.assertFalse(self.observer().sample()["review_required"])
        self.write("6.3.0")
        self.assertTrue(self.observer().sample()["review_required"])

    def test_old_review_cannot_clear_a_newer_pending_baseline(self):
        self.write("6.1.0")
        self.observer().sample()
        self.write("6.2.0")
        old_page = self.observer()
        old_page.sample()
        self.write("6.3.0")
        current = self.observer()
        current.sample()
        before = self.baseline().read_bytes()
        with self.assertRaisesRegex(RuntimeError, "^client version baseline changed$"):
            old_page.mark_reviewed(["6.2.0"])
        self.assertEqual(self.baseline().read_bytes(), before)
        self.assertTrue(self.observer().sample()["review_required"])

    def test_review_only_accesses_private_baseline_and_not_client_metadata(self):
        self.write("6.1.0")
        self.observer().sample()
        self.write("6.2.0")
        observer = self.observer()
        observer.sample()
        original_open = client_version.os.open
        def private_open(name, *args, **kwargs):
            self.assertNotIn(os.fspath(name), ("Claude.app", "Contents", "Info.plist", "system", "user"))
            return original_open(name, *args, **kwargs)
        with patch.object(observer, "_info", side_effect=AssertionError("client read during review")), \
                patch.object(client_version.os, "open", side_effect=private_open):
            self.assertFalse(observer.mark_reviewed(["6.2.0"])["review_required"])

    def test_review_rejects_invalid_input_with_fixed_errors(self):
        for value in (None, "6.1.0", [], ["secret-fixture-version"], ["6.1.0", "6.1.0"], [1], ["1.0", "2.0", "3.0"]):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "^invalid expected versions$"):
                self.observer().mark_reviewed(value)
        with self.assertRaisesRegex(RuntimeError, "^client version baseline unavailable$"):
            self.observer().mark_reviewed(["6.1.0"])

    def test_review_rejects_untrusted_baseline_without_following_or_changing_it(self):
        self.write()
        observer = self.observer()
        observer.sample()
        self.baseline().unlink()
        target = self.root / "review-target"
        target.write_bytes(b"secret-fixture-target")
        self.baseline().symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "^client version baseline unavailable$"):
            observer.mark_reviewed(["6.28899.6"])
        self.assertEqual(target.read_bytes(), b"secret-fixture-target")


if __name__ == "__main__":
    unittest.main()

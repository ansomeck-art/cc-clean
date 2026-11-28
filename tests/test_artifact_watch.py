"""Private temporary fixtures only; never read user Claude data or send signals."""
import json
import os
from pathlib import Path
import select
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import artifact_watch
import telemetry_watch
from artifact_watch import ClaudeArtifactWatch, MAX_LOG_BYTES, SOURCE_IDS, SOURCE_MODES


def scope(locale="en-US", timezone="UTC"):
    return {"event": {"contexts": {"culture": {"locale": locale, "timezone": timezone}}}}


class ArtifactWatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rg-artifact-fixture-")
        self.home = Path(self.temporary.name).resolve()
        self.claude = self.home / "Library/Application Support/Claude"
        self.logs = self.home / "Library/Logs/Claude"
        self.watchers = []

    def tearDown(self):
        for watcher in self.watchers:
            watcher.stop()
        self.temporary.cleanup()

    def write(self, relative, obj=None, *, raw=None, log=False):
        path = (self.logs if log else self.claude) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw if raw is not None else json.dumps(obj).encode())
        return path

    def watcher(self, **kwargs):
        watcher = ClaudeArtifactWatch(home=self.home, interval_ms=50, **kwargs)
        self.watchers.append(watcher)
        return watcher

    def wait(self, watcher, state=None, predicate=None, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            view = watcher.sample()
            if (state is None or view["state"] == state) and (predicate is None or predicate(view)):
                return view
            time.sleep(.005)
        self.fail(f"expected {state}; sanitized result={watcher.sample()}")

    @staticmethod
    def source(view, source_id):
        return next(item for item in view["sources"] if item["id"] == source_id)

    def test_constructor_has_no_io_and_has_eight_fixed_placeholders(self):
        with patch.object(artifact_watch.os, "open", side_effect=AssertionError("IO forbidden")), \
                patch.object(threading.Thread, "start", side_effect=AssertionError("thread forbidden")):
            watcher = self.watcher()
            watcher.configure(250)
            with watcher._lock:
                view = watcher._view()
        self.assertEqual([item["id"] for item in view["sources"]], list(SOURCE_IDS))
        self.assertTrue(all(item["state"] == "checking" for item in view["sources"]))
        self.assertEqual({item["id"]: item["mode"] for item in view["sources"]}, SOURCE_MODES)

    def test_all_missing_is_unverified_and_never_calls_reader(self):
        watcher = self.watcher(reader=lambda *_: self.fail("missing sources must not be read"))
        view = self.wait(watcher, "missing")
        self.assertEqual(view["reason_codes"], [])
        self.assertEqual(view["risk_source_ids"], [])
        self.assertTrue(all(item["state"] == "missing" for item in view["sources"]))
        self.assertIn("缺失表示未验证", view["coverage"])

    def test_existing_cn_in_each_semantic_source_is_detected_at_start(self):
        fixtures = (("sentry/scope_v3.json", scope("zh-CN"), "sentry_scope", False),
                    ("config.json", {"locale": "en-CN"}, "app_config", False),
                    ("Preferences", {"intl": {"accept_languages": "en-US,zh-CN"}}, "electron_preferences", False),
                    ("main.log", {"environment": {"country": "CN"}}, "claude_logs", True))
        for relative, obj, source_id, log in fixtures:
            with self.subTest(source=source_id):
                path = self.write(relative, obj, log=log)
                watcher = self.watcher()
                view = self.wait(watcher, "risk")
                self.assertIn(source_id, view["risk_source_ids"])
                self.assertEqual(self.source(view, source_id)["state"], "risk")
                watcher.stop()
                path.unlink()

    def test_runtime_writes_and_atomic_preferences_replace_trigger_the_same_source_cache(self):
        self.write("sentry/scope_v3.json", scope())
        path = self.write("Preferences", {"intl": {"accept_languages": "en-US"}})
        watcher = self.watcher()
        self.wait(watcher, "safe")
        replacement = self.write("Preferences.new", {"spellcheck": {"dictionaries": ["zh-CN"]}})
        os.replace(replacement, path)
        view = self.wait(watcher, "risk")
        self.assertEqual(view["risk_source_ids"], ["electron_preferences"])
        self.assertGreater(self.source(view, "electron_preferences")["change_count"], 0)

    def test_metadata_only_files_can_be_large_and_never_open_or_call_reader(self):
        paths = [self.write("claude_desktop_config.json", raw=b'{"locale":"zh-CN","secret":"fixture"}'),
                 self.write("ant-did", raw=b"opaque-fixture-identifier-CN"),
                 self.write("Cookies", raw=b"X" * (2 * 1024 * 1024)),
                 self.write("Network/Cookies-wal", raw=b"X" * (2 * 1024 * 1024)),
                 self.write("sentry/queue/envelope", raw=b'{"country":"CN"}')]
        original_open = os.open
        def opening(path, *args, **kwargs):
            if os.fspath(path) in {item.name for item in paths}:
                self.fail("metadata-only leaf was opened")
            return original_open(path, *args, **kwargs)
        with patch.object(artifact_watch.os, "open", side_effect=opening):
            watcher = self.watcher(reader=lambda *_: self.fail("metadata-only content was read"))
            view = self.wait(watcher, "safe")
            for source_id in ("desktop_config", "installation_id", "cookie_store", "sentry_queue"):
                item = self.source(view, source_id)
                self.assertEqual(item["state"], "observed")
                self.assertEqual(item["files_checked"], 0)
            self.assertEqual(self.source(view, "cookie_store")["total_bytes"], 4 * 1024 * 1024)
            self.assertFalse(view["risk_source_ids"])

    def test_plain_chinese_and_chat_content_do_not_establish_cn(self):
        self.write("sentry/scope_v3.json", scope("zh-Hans", "UTC+8"))
        self.write("config.json", {"locale": "zh-Hans", "message": {"country": "CN"}})
        self.write("Preferences", {"intl": {"accept_languages": "zh-HK,zh-TW"}})
        self.write("main.log", raw='普通中文\n{"message":{"country":"CN"}}\n'.encode(), log=True)
        watcher = self.watcher()
        view = self.wait(watcher, "safe")
        self.assertEqual(view["risk_source_ids"], [])
        self.assertEqual(self.source(view, "claude_logs")["state"], "observed")

    def test_scope_missing_culture_is_observed_without_risk(self):
        self.write("sentry/scope_v3.json", {"event": {"contexts": {"app": {}}}})
        view = self.wait(self.watcher(), "observed")
        self.assertEqual(self.source(view, "sentry_scope")["reason_codes"], [])

    def test_service_diagnostics_count_once_and_never_establish_china(self):
        self.write('sentry/scope_v3.json', scope())
        path = self.write('main.log', raw=b'HTTP 403 permission_error\nHTTP 403 Forbidden\ncf-mitigated: challenge\n', log=True)
        watcher = self.watcher()
        view = self.wait(watcher, 'safe')
        expected = self.source(view, 'claude_logs')['diagnostics']
        self.assertEqual(expected['permission_denied'], 1)
        self.assertEqual(expected['http_forbidden_unknown'], 1)
        self.assertEqual(expected['edge_challenge'], 1)
        self.assertEqual(expected['region_denied'], 0)
        self.assertEqual(expected['account_banned'], 0)
        time.sleep(.12)
        self.assertEqual(self.source(watcher.sample(), 'claude_logs')['diagnostics'], expected)
        with path.open('ab') as handle:
            handle.write(b'ETIMEDOUT\n')
        view = self.wait(watcher, 'safe', lambda current: self.source(current, 'claude_logs')['diagnostics']['network_timeout'] == 1)
        self.assertEqual(self.source(view, 'claude_logs')['diagnostics']['permission_denied'], 1)
        self.assertFalse(view['risk_source_ids'])

    def test_explicit_cn_has_priority_over_another_unknown_source(self):
        self.write("sentry/scope_v3.json", {})
        self.write("config.json", {"country": "CN"})
        view = self.wait(self.watcher(), "risk")
        self.assertEqual(view["risk_source_ids"], ["app_config"])

    def test_unchanged_json_is_not_reread_and_check_heartbeat_refreshes(self):
        self.write("sentry/scope_v3.json", scope())
        self.write("config.json", {"locale": "en-US"})
        calls = []
        def reader(fd, limit):
            calls.append(limit)
            return ClaudeArtifactWatch._read(fd, limit)
        watcher = self.watcher(reader=reader)
        view = self.wait(watcher, "safe")
        count = view["files_checked"]
        time.sleep(.18)
        view = watcher.sample()
        self.assertEqual(len(calls), 2)
        self.assertEqual(view["files_checked"], count)
        self.assertLess(view["last_check_age_ms"], 150)

    def test_parse_error_is_cached_until_file_stat_changes(self):
        self.write("config.json", raw=b"{")
        calls = []
        def reader(fd, limit):
            calls.append(1)
            return ClaudeArtifactWatch._read(fd, limit)
        watcher = self.watcher(reader=reader)
        self.wait(watcher, "unknown")
        time.sleep(.13)
        self.assertEqual(len(calls), 1)
        self.write("config.json", {"locale": "en-US"})
        self.wait(watcher, "safe")
        self.assertEqual(len(calls), 2)

    def test_short_or_oversized_json_reader_cannot_report_safe(self):
        self.write("config.json", {"country": "CN", "unused": "fixture"})
        for reader in (lambda *_: b"{}", lambda *_: b" " * (1024 * 1024 + 1)):
            with self.subTest(reader=reader):
                watcher = self.watcher(reader=reader)
                view = self.wait(watcher, "unknown")
                self.assertTrue(self.source(view, "app_config")["limited"])
                watcher.stop()

    def test_oversized_json_file_fails_closed_before_reader(self):
        self.write("config.json", raw=b" " * (1024 * 1024 + 1))
        view = self.wait(self.watcher(reader=lambda *_: self.fail("oversized JSON was read")), "unknown")
        self.assertTrue(self.source(view, "app_config")["limited"])

    def test_symlink_leaf_and_parent_are_unknown_without_following(self):
        path = self.write("config.json", {})
        target = self.write("real-config", {"locale": "zh-CN"})
        path.unlink()
        path.symlink_to(target)
        watcher = self.watcher(reader=lambda *_: self.fail("symlink followed"))
        self.wait(watcher, "unknown")
        watcher.stop()
        path.unlink()
        original = self.claude.with_name("real-Claude")
        self.claude.rename(original)
        self.claude.symlink_to(original, target_is_directory=True)
        self.wait(self.watcher(reader=lambda *_: self.fail("parent symlink followed")), "unknown")

    def test_metadata_symlink_and_nonordinary_leaf_are_unknown_without_content_io(self):
        target = self.write("opaque-target", raw=b"fixture")
        path = self.claude / "Cookies"
        path.symlink_to(target)
        watcher = self.watcher(reader=lambda *_: self.fail("metadata content read"))
        self.wait(watcher, "unknown")
        watcher.stop()
        path.unlink()
        path.mkdir()
        self.wait(self.watcher(reader=lambda *_: self.fail("directory content read")), "unknown")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_fifo_semantic_file_does_not_block(self):
        self.claude.mkdir(parents=True)
        os.mkfifo(self.claude / "config.json")
        self.wait(self.watcher(reader=lambda *_: self.fail("FIFO read")), "unknown", timeout=1)

    def test_unreadable_or_foreign_owner_is_unknown(self):
        path = self.write("config.json", {})
        path.chmod(0)
        watcher = self.watcher(reader=lambda *_: self.fail("unreadable JSON read"))
        self.wait(watcher, "unknown")
        watcher.stop()
        path.chmod(0o600)
        watcher = self.watcher(reader=lambda *_: self.fail("foreign source read"))
        watcher._uid = os.getuid() + 1
        self.wait(watcher, "unknown")

    def test_queue_limit_and_entry_changes_are_metadata_only(self):
        for index in range(artifact_watch.MAX_QUEUE_ENTRIES + 1):
            self.write(f"sentry/queue/fixture-{index}", raw=b"CN")
        watcher = self.watcher(reader=lambda *_: self.fail("queue content read"))
        view = self.wait(watcher, "safe")
        item = self.source(view, "sentry_queue")
        self.assertTrue(item["limited"])
        self.assertEqual(item["file_count"], artifact_watch.MAX_QUEUE_ENTRIES)
        self.assertEqual(item["total_bytes"], artifact_watch.MAX_QUEUE_ENTRIES * 2)
        self.write("sentry/queue/fixture-0", raw=b"more fixture metadata bytes")
        self.wait(watcher, "safe", lambda value: self.source(value, "sentry_queue")["change_count"] > 0)

    def test_log_error_codes_are_only_advisory_and_counts_do_not_repeat(self):
        self.write("main.log", raw=b"region_unavailable\naccount_banned\nERR_NETWORK_CHANGED\n", log=True)
        watcher = self.watcher()
        view = self.wait(watcher, "safe")
        item = self.source(view, "claude_logs")
        self.assertEqual(item["counters"]["region"], 1)
        self.assertEqual(item["counters"]["banned"], 1)
        self.assertEqual(item["counters"]["network"], 1)
        time.sleep(.15)
        self.assertEqual(self.source(watcher.sample(), "claude_logs")["counters"], item["counters"])

    def test_large_log_tail_baseline_is_bounded_and_does_not_claim_full_history(self):
        hidden = b'{"environment":{"country":"CN"}}\n'
        path = self.write("main.log", raw=hidden + b"ordinary fixture\n" * 40000, log=True)
        calls = []
        def reader(fd, limit):
            calls.append(limit)
            return ClaudeArtifactWatch._read(fd, limit)
        watcher = self.watcher(reader=reader)
        view = self.wait(watcher, "safe")
        item = self.source(view, "claude_logs")
        self.assertTrue(item["limited"])
        self.assertEqual(item["total_bytes"], path.stat().st_size)
        self.assertEqual(calls, [MAX_LOG_BYTES])
        self.assertFalse(view["risk_source_ids"])

    def test_large_log_tail_cn_and_append_continuity_do_not_relock_old_record(self):
        path = self.write("main.log", raw=b"fixture\n" * 80000 + b'{"environment":{"country":"CN"}}\n', log=True)
        calls = []
        def reader(fd, limit):
            calls.append(limit)
            return ClaudeArtifactWatch._read(fd, limit)
        watcher = self.watcher(reader=reader)
        risk = self.wait(watcher, "risk")
        # A boundary-byte baseline may leave the final newline for the next
        # bounded window; wait until that byte has also been classified.
        risk = self.wait(watcher, "risk", lambda view: self.source(view, "claude_logs")["files_checked"] >= 2)
        watcher.acknowledge(risk["event_seq"])
        line = b"ordinary fixture append\n"
        with path.open("ab") as handle:
            handle.write(line)
        self.wait(watcher, "safe")
        self.assertEqual(calls[0], MAX_LOG_BYTES)
        self.assertTrue(all(0 <= count <= MAX_LOG_BYTES for count in calls))

    def test_same_inode_copytruncate_then_grow_checks_new_prefix_cn(self):
        path = self.write("main.log", raw=b"benign fixture x\n", log=True)
        watcher = self.watcher()
        self.wait(watcher, "safe")
        inode = path.stat().st_ino
        cn = b'{"environment":{"country":"CN"}}\n'
        with path.open("wb") as handle:
            handle.write(cn + b"benign padding\n" * 40)
        self.assertEqual(path.stat().st_ino, inode)
        view = self.wait(watcher, "risk")
        self.assertEqual(view["risk_source_ids"], ["claude_logs"])

    def test_large_same_inode_rewrite_checks_changed_old_overlap_within_tail_window(self):
        old = b"benign fixture\n" * 40000
        path = self.write("main.log", raw=old, log=True)
        watcher = self.watcher()
        self.wait(watcher, "safe")
        inode = path.stat().st_ino
        cn = b'{"environment":{"country":"CN"}}\n'
        new = old[:-60] + b"\n" + cn + b"benign fixture\n" * 20
        self.assertGreater(len(new), len(old))
        with path.open("wb") as handle:
            handle.write(new)
        self.assertEqual(path.stat().st_ino, inode)
        view = self.wait(watcher, "risk")
        self.assertEqual(view["risk_source_ids"], ["claude_logs"])

    def test_newline_completion_does_not_relatch_previously_classified_cn_tail(self):
        path = self.write("main.log", raw=b'{"environment":{"country":"CN"}}', log=True)
        watcher = self.watcher()
        first = self.wait(watcher, "risk")
        watcher.acknowledge(first["event_seq"])
        with path.open("ab") as handle:
            handle.write(b"\nordinary fixture\n")
        view = self.wait(watcher, "safe")
        self.assertEqual(view["risk_source_ids"], [])

    def test_stop_clears_private_raw_windows_but_retains_sanitized_counts(self):
        self.write("main.log", raw=b"region_unavailable\n", log=True)
        watcher = self.watcher()
        self.wait(watcher, "safe")
        self.assertTrue(watcher._runtime["claude_logs"]["logs"])
        stopped = watcher.stop()
        self.assertFalse(watcher._runtime)
        self.assertEqual(self.source(stopped, "claude_logs")["counters"]["region"], 1)

    def test_tail_window_at_exact_line_boundary_keeps_first_cn_record(self):
        cn = b'{"environment":{"country":"CN"}}\n'
        padding_size = MAX_LOG_BYTES - len(cn)
        padding = (b"x\n" * (padding_size // 2)) + (b"\n" if padding_size % 2 else b"")
        self.assertEqual(len(cn + padding), MAX_LOG_BYTES)
        self.write("main.log", raw=b"benign fixture x\n" + cn + padding, log=True)
        view = self.wait(self.watcher(), "risk")
        self.assertTrue(self.source(view, "claude_logs")["limited"])
        self.assertEqual(view["risk_source_ids"], ["claude_logs"])

    def test_small_file_continuity_reread_does_not_recount_old_append_lines(self):
        path = self.write("main.log", raw=b"region_unavailable\n", log=True)
        watcher = self.watcher()
        self.wait(watcher, "safe")
        with path.open("ab") as handle:
            handle.write(b"ERR_NETWORK_CHANGED\n")
        view = self.wait(watcher, "safe", lambda result: self.source(result, "claude_logs")["files_checked"] >= 2)
        counters = self.source(view, "claude_logs")["counters"]
        self.assertEqual(counters["region"], 1)
        self.assertEqual(counters["network"], 1)

    def test_complete_structured_last_line_without_newline_is_checked(self):
        self.write("main.log", raw=b'{"environment":{"locale":"zh-CN"}}', log=True)
        self.assertEqual(self.wait(self.watcher(), "risk")["risk_source_ids"], ["claude_logs"])

    def test_partial_json_and_split_utf8_are_completed_before_classification(self):
        line = '{"environment":{"country":"中国"}}\n'.encode()
        cut = line.index("中国".encode()) + 1
        path = self.write("main.log", raw=line[:cut], log=True)
        watcher = self.watcher()
        self.wait(watcher, "checking", lambda value: self.source(value, "claude_logs")["files_checked"] > 0)
        with path.open("ab") as handle:
            handle.write(line[cut:])
        self.wait(watcher, "risk")

    def test_log_rotation_truncation_and_parent_recreation_are_observed(self):
        path = self.write("main.log", raw=b"ordinary fixture longer baseline\n", log=True)
        watcher = self.watcher()
        self.wait(watcher, "safe")
        path.rename(path.with_name("main.log.1"))
        self.write("main.log", raw=b'{"environment":{"country":"CN"}}\n', log=True)
        risk = self.wait(watcher, "risk")
        watcher.acknowledge(risk["event_seq"])
        self.write("main.log", raw=b"ok\n", log=True)
        self.wait(watcher, "safe")
        shutil.rmtree(self.logs)
        self.wait(watcher, "missing")
        self.write("main.log", raw=b'{"environment":{"timezone":"Asia/Shanghai"}}\n', log=True)
        self.wait(watcher, "risk")

    def test_known_numeric_rotation_is_checked_but_unapproved_extensions_are_not(self):
        self.write("main.log.1", raw=b'{"environment":{"country":"CN"}}\n', log=True)
        self.write("fixture.json", raw=b"{", log=True)
        self.write("main.log.old", raw=b"{", log=True)
        view = self.wait(self.watcher(), "risk")
        self.assertEqual(self.source(view, "claude_logs")["file_count"], 1)

    def test_log_file_limit_is_explicit(self):
        for index in range(artifact_watch.MAX_LOG_FILES + 1):
            self.write(f"fixture-{index:02d}.log", raw=b"ordinary fixture\n", log=True)
        view = self.wait(self.watcher(), "safe")
        item = self.source(view, "claude_logs")
        self.assertTrue(item["limited"])
        self.assertEqual(item["file_count"], artifact_watch.MAX_LOG_FILES)

    def test_normal_append_during_read_is_not_a_cn_or_unknown_signal(self):
        path = self.write("main.log", raw=b"ordinary fixture\n", log=True)
        once = threading.Event()
        def reader(fd, limit):
            raw = ClaudeArtifactWatch._read(fd, limit)
            if not once.is_set():
                once.set()
                with path.open("ab") as handle:
                    handle.write(b"another ordinary fixture\n")
            return raw
        view = self.wait(self.watcher(reader=reader), "safe")
        self.assertEqual(self.source(view, "claude_logs")["state"], "observed")

    def test_atomic_replace_during_json_read_does_not_publish_old_safe(self):
        path = self.write("config.json", {"locale": "en-US"})
        once = threading.Event()
        def reader(fd, limit):
            raw = ClaudeArtifactWatch._read(fd, limit)
            if not once.is_set():
                once.set()
                replacement = self.write("config.new", {"country": "CN"})
                os.replace(replacement, path)
            return raw
        watcher = self.watcher(reader=reader)
        states = []
        watcher.set_callback(lambda: states.append(watcher.sample()["state"]))
        self.wait(watcher, "risk")
        self.assertNotIn("safe", states)

    def test_risk_source_ids_stay_latched_across_recovery_and_old_ack_is_ignored(self):
        self.write("config.json", {"country": "CN"})
        watcher = self.watcher()
        first = self.wait(watcher, "risk")
        self.write("config.json", {})
        self.wait(watcher, "risk", lambda view: self.source(view, "app_config")["files_checked"] >= 2)
        self.write("Preferences", {"intl": {"accept_languages": "zh-CN"}})
        second = self.wait(watcher, "risk", lambda view: "electron_preferences" in view["risk_source_ids"])
        self.write("Preferences", {})
        self.wait(watcher, "risk", lambda view: self.source(view, "electron_preferences")["files_checked"] >= 2)
        watcher.acknowledge(first["event_seq"])
        self.assertEqual(watcher.sample()["risk_source_ids"], ["app_config", "electron_preferences"])
        watcher.acknowledge(second["event_seq"])
        self.wait(watcher, "safe")

    def test_ordinary_updates_do_not_renew_an_old_unacknowledged_risk_sequence(self):
        self.write("config.json", {"country": "CN"})
        watcher = self.watcher()
        risk = self.wait(watcher, "risk")
        self.write("config.json", {})
        self.wait(watcher, "risk", lambda view: self.source(view, "app_config")["files_checked"] >= 2)
        self.write("Cookies", raw=b"ordinary metadata update")
        self.wait(watcher, "risk", lambda view: self.source(view, "cookie_store")["file_count"] == 1)
        self.assertEqual(watcher.sample()["event_seq"], risk["event_seq"])
        watcher.acknowledge(risk["event_seq"])
        self.wait(watcher, "safe")

    def test_nonblocking_cache_and_complete_cycle_age_during_slow_read(self):
        self.write("config.json", {})
        entered, release = threading.Event(), threading.Event()
        now = [100.0]
        def reader(fd, limit):
            entered.set()
            release.wait(3)
            return ClaudeArtifactWatch._read(fd, limit)
        watcher = self.watcher(reader=reader, clock=lambda: now[0])
        try:
            watcher.start()
            self.assertTrue(entered.wait(1))
            started = time.monotonic()
            self.assertEqual(watcher.sample()["state"], "checking")
            self.assertLess(time.monotonic() - started, .03)
            self.assertIsNone(watcher.sample()["last_check_age_ms"])
        finally:
            release.set()
        self.wait(watcher, "safe")
        with watcher._lock:
            now[0] += 3
            self.assertEqual(watcher._view()["last_check_age_ms"], 3000)

    def test_later_slow_log_does_not_rejuvenate_an_earlier_scope_sample(self):
        self.write("sentry/scope_v3.json", scope())
        self.write("main.log", raw=b"ordinary fixture\n", log=True)
        now = [100.0]
        captured = []
        watcher = None
        def reader(fd, limit):
            raw = ClaudeArtifactWatch._read(fd, limit)
            if limit < 1024 * 1024:
                self.write("sentry/scope_v3.json", scope("zh-CN"))
                now[0] += 1
            return raw
        watcher = self.watcher(reader=reader, clock=lambda: now[0])
        def callback():
            view = watcher.sample()
            if view["state"] == "safe":
                captured.append(view)
        watcher.set_callback(callback)
        self.wait(watcher, predicate=lambda _: bool(captured))
        first = captured[0]
        self.assertGreaterEqual(first["last_check_age_ms"], 1000)
        self.assertGreaterEqual(self.source(first, "sentry_scope")["last_check_age_ms"], 1000)
        self.assertEqual(self.source(first, "claude_logs")["last_check_age_ms"], 0)
        self.wait(watcher, "risk")

    def test_stop_invalidates_inflight_read_and_requires_explicit_restart(self):
        self.write("config.json", {"country": "CN"})
        entered, release = threading.Event(), threading.Event()
        def reader(fd, limit):
            entered.set()
            release.wait(3)
            return ClaudeArtifactWatch._read(fd, limit)
        watcher = self.watcher(reader=reader)
        watcher.start()
        self.assertTrue(entered.wait(1))
        watcher.stop()
        sequence = watcher.sample()["event_seq"]
        release.set()
        deadline = time.monotonic() + 1
        while watcher._thread is not None and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertEqual(watcher.sample()["state"], "stopped")
        self.assertEqual(watcher.sample()["event_seq"], sequence)
        self.assertTrue(all(item["state"] == "stopped" for item in watcher.sample()["sources"]))
        watcher.start()
        self.wait(watcher, "risk")

    def test_unexpected_exit_keeps_risk_and_needs_explicit_restart(self):
        self.write("config.json", {"country": "CN"})
        fail = threading.Event()
        def reader(fd, limit):
            if fail.is_set():
                fail.clear()
                raise SystemExit("private fixture failure")
            return ClaudeArtifactWatch._read(fd, limit)
        watcher = self.watcher(reader=reader)
        risk = self.wait(watcher, "risk")
        fail.set()
        self.write("config.json", {})
        deadline = time.monotonic() + 1
        while watcher._thread is not None and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertIsNone(watcher._thread)
        self.assertEqual(watcher.sample()["risk_source_ids"], ["app_config"])
        watcher.acknowledge(risk["event_seq"])
        self.assertEqual(watcher.sample()["state"], "unknown")
        self.assertIsNone(watcher._thread)
        watcher.start()
        self.wait(watcher, "safe")

    def test_concurrent_start_uses_one_worker_and_callback_failures_are_contained(self):
        self.write("config.json", {})
        watcher = self.watcher()
        fired = threading.Event()
        def callback():
            fired.set()
            raise RuntimeError("private callback fixture")
        watcher.set_callback(callback)
        barrier = threading.Barrier(5)
        workers = []
        def start():
            barrier.wait()
            watcher.start()
            workers.append(watcher._thread)
        threads = [threading.Thread(target=start) for _ in range(4)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(1)
        self.assertEqual(len(set(workers)), 1)
        self.wait(watcher, "safe")
        self.assertTrue(fired.is_set())

    def test_snapshot_schema_never_exports_paths_values_names_or_mutable_references(self):
        self.write("config.json", {"locale": "en-US", "deviceName": "secret-fixture-device"})
        self.write("private-fixture-name.log", raw=b"ordinary fixture\n", log=True)
        watcher = self.watcher()
        view = self.wait(watcher, "safe")
        self.assertEqual(set(view), {"state", "reason_codes", "field_types", "last_check_age_ms", "last_scan_ms",
                                     "backend", "coverage", "files_checked", "event_seq", "sources", "risk_source_ids"})
        serialized = json.dumps(view)
        for private in (str(self.home), "en-US", "secret-fixture-device", "private-fixture-name.log"):
            self.assertNotIn(private, serialized)
        view["sources"][0]["reason_codes"].append("fixture")
        view["sources"][0]["counters"]["region"] = 999
        self.assertNotIn("fixture", watcher.sample()["sources"][0]["reason_codes"])
        self.assertNotEqual(watcher.sample()["sources"][0]["counters"]["region"], 999)

    def test_kqueue_unavailable_falls_back_to_stat(self):
        self.write("config.json", {})
        with patch.object(telemetry_watch, "_KqueueEvents", side_effect=OSError("unavailable")):
            watcher = self.watcher()
            self.assertEqual(self.wait(watcher, "safe")["backend"], "stat")
            self.write("config.json", {"country": "CN"})
            self.wait(watcher, "risk")

    @unittest.skipUnless(sys.platform == "darwin" and hasattr(select, "kqueue"), "Darwin kqueue required")
    def test_single_real_kqueue_accelerates_non_scope_source(self):
        self.write("config.json", {})
        watcher = self.watcher()
        watcher.configure(500)
        self.assertEqual(self.wait(watcher, "safe")["backend"], "kqueue+stat")
        time.sleep(.08)
        started = time.monotonic()
        self.write("Preferences", {"intl": {"accept_languages": "zh-CN"}})
        self.wait(watcher, "risk", timeout=.4)
        self.assertLess(time.monotonic() - started, .4)


if __name__ == "__main__":
    unittest.main()

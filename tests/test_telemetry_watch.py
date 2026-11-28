"""Isolated local fixtures only: no Claude data, process signals, or network changes."""
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
import telemetry_watch
from telemetry_watch import ClaudeTelemetryWatch, MAX_SCOPE_BYTES


def scope(locale="en-US", timezone="America/New_York", **extra):
    return {"event": {"contexts": {"culture": dict(locale=locale, timezone=timezone, **extra)}}}


class MetadataPolicyTests(unittest.TestCase):
    def inspect(self, obj):
        return telemetry_watch._inspect(json.dumps(obj, ensure_ascii=False).encode())

    def test_both_sentry_culture_schemas(self):
        for obj in (scope(), {"contexts": {"culture": {"locale": "en-US", "timezone": "UTC"}}}):
            with self.subTest(obj=obj):
                self.assertEqual(self.inspect(obj), ("safe", [], ["locale", "timezone"]))

    def test_explicit_mainland_country_variants(self):
        for value in ("CN", "CHN", 156, "156", "中国", "中国大陆", "China", "中华人民共和国"):
            with self.subTest(value=value):
                result = self.inspect(scope(country=value))
                self.assertEqual(result[0], "risk")
                self.assertEqual(result[1], ["telemetry_cn_country"])
                self.assertIn("country", result[2])

    def test_explicit_cn_locale_variants(self):
        for value in ("zh-CN", "zh_CN.UTF-8", "zh-Hans-CN", "en-CN", "zh-Hans-CN-u-ca-gregory"):
            with self.subTest(value=value):
                self.assertEqual(self.inspect(scope(locale=value))[1], ["telemetry_cn_locale"])

    def test_explicit_cn_regions_use_country_category_without_guessing_city_or_province(self):
        for key in ("region", "region_code", "georegion", "clientRegion", "system_region", "os_region"):
            for value in ("CN", "CN-31", "cn-north-1", "China", "中国"):
                with self.subTest(key=key, value=value):
                    result = self.inspect(scope(**{key: value}))
                    self.assertEqual(result[0:2], ("risk", ["telemetry_cn_country"]))
                    self.assertIn("country", result[2])
            for value in ("US-CA", "HK", "MO", "TW", "31", "Shanghai", "上海"):
                with self.subTest(key=key, value=value):
                    self.assertEqual(self.inspect(scope(**{key: value}))[0], "safe")

    def test_mainland_iana_timezones_only(self):
        for value in ("Asia/Shanghai", "Asia/Chongqing", "Asia/Chungking", "Asia/Harbin", "Asia/Urumqi", "Asia/Kashgar", "PRC"):
            with self.subTest(value=value):
                self.assertEqual(self.inspect(scope(timezone=value))[1], ["telemetry_cn_timezone"])

    def test_chinese_text_language_offset_and_non_mainland_regions_are_neutral(self):
        for locale in ("zh", "zh-Hans", "zh-Hant", "zh-Hant-HK", "zh-MO", "zh-TW", "中文"):
            for timezone, country in (("UTC+8", "HK"), ("Asia/Hong_Kong", "MO"), ("Asia/Taipei", "TW"), ("Asia/Macau", "SG")):
                with self.subTest(locale=locale, timezone=timezone, country=country):
                    self.assertEqual(self.inspect(scope(locale, timezone, country=country))[0], "safe")

    def test_country_only_read_from_explicit_metadata_containers(self):
        for add in ({"metadata": {"country_code": "CN"}},
                    {"environment": {"systemCountry": "CN"}},
                    {"contexts": {"culture": {"locale": "en", "timezone": "UTC"}, "geo": {"country": "CN"}}}):
            obj = scope()
            obj["event"].update(add)
            self.assertEqual(self.inspect(obj)[1], ["telemetry_cn_country"])

    def test_never_recursively_interprets_chat_or_identifiers(self):
        obj = scope()
        obj["event"].update({"messages": [{"country": "CN", "locale": "zh-CN"}],
                             "message": "中国用户 Asia/Shanghai", "user": {"country": "CN"},
                             "extra": {"prompt": {"country": "CN"}}, "device_id": "CN"})
        obj["event"]["contexts"]["environment"] = {"request": {"country": "CN"}}
        self.assertEqual(self.inspect(obj)[0], "safe")

    def test_missing_or_not_yet_written_culture_is_observed_without_risk(self):
        fixtures = ({}, {"event": {}}, {"contexts": {}}, {"contexts": {"culture": {}}},
                    {"contexts": {"culture": {"locale": "en-US"}}},
                    {"contexts": {"culture": {"timezone": "UTC"}}})
        for obj in fixtures:
            with self.subTest(obj=obj):
                self.assertEqual(self.inspect(obj)[0:2], ("observed", []))

    def test_malformed_or_ambiguous_culture_remains_unknown(self):
        fixtures = (scope(locale=None), scope(timezone=[]), scope(country={"code": "US"}))
        for obj in fixtures:
            with self.subTest(obj=obj):
                self.assertEqual(self.inspect(obj)[0:2], ("unknown", ["telemetry_file_unknown"]))
        for raw in (b"", b"{", b"[]", b"\xff", b'{"event":{},"event":{}}', b'{"value":NaN}'):
            self.assertEqual(telemetry_watch._inspect(raw)[0], "unknown")

    def test_explicit_cn_is_risk_even_when_other_culture_fields_are_missing(self):
        self.assertEqual(self.inspect({"metadata": {"country": "CN"}})[0:2],
                         ("risk", ["telemetry_cn_country"]))

    def test_combined_fields_are_sanitized_static_categories(self):
        state, reasons, fields = self.inspect(scope("zh-CN", "Asia/Shanghai", country="CN"))
        self.assertEqual(state, "risk")
        self.assertEqual(reasons, ["telemetry_cn_country", "telemetry_cn_locale", "telemetry_cn_timezone"])
        self.assertEqual(fields, ["country", "locale", "timezone"])


class WatcherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rg-watch-fixture-")
        # macOS temporary paths may use /var; the observer intentionally rejects aliases.
        self.root = Path(self.temporary.name).resolve()
        self.path = self.root / "Claude" / "sentry" / "scope_v3.json"
        self.watchers = []

    def tearDown(self):
        for watcher in self.watchers:
            watcher.stop()
        self.temporary.cleanup()

    def write(self, obj=None, path=None, raw=None):
        path = path or self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw if raw is not None else json.dumps(obj if obj is not None else scope()).encode())

    def watcher(self, **kwargs):
        result = ClaudeTelemetryWatch(self.path, interval_ms=50, **kwargs)
        self.watchers.append(result)
        return result

    def wait(self, watcher, state, predicate=None, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            view = watcher.sample()
            if view["state"] == state and (predicate is None or predicate(view)):
                return view
            time.sleep(.005)
        self.fail(f"expected {state}; sanitized cache={watcher.sample()}")

    def test_constructor_and_configure_have_no_io_or_threads(self):
        with patch.object(telemetry_watch.os, "open", side_effect=AssertionError("filesystem IO")), \
                patch.object(threading.Thread, "start", side_effect=AssertionError("thread started")):
            watcher = self.watcher()
            watcher.configure(250)
            watcher.set_callback(lambda: None)
        self.assertIsNone(watcher._thread)
        self.assertEqual(watcher._interval_ms, 250)

    def test_lazy_start_and_explicit_stop_then_explicit_restart(self):
        self.write()
        watcher = self.watcher()
        first = self.wait(watcher, "safe")
        self.assertGreater(first["files_checked"], 0)
        watcher.stop()
        self.write(scope("zh-CN"))
        for _ in range(3):
            self.assertEqual(watcher.sample()["state"], "stopped")
            self.assertIsNone(watcher._thread)
        watcher.start()
        self.wait(watcher, "risk")

    def test_missing_scope_is_unverified_and_does_not_scan_queue_content(self):
        self.path.parent.mkdir(parents=True)
        queue = self.path.parent / "queue"
        queue.mkdir()
        (queue / "fixture-envelope").write_text('{"country":"CN"}')
        watcher = self.watcher(reader=lambda *_: self.fail("must not read missing scope or queue"))
        view = self.wait(watcher, "missing")
        self.assertEqual(view["reason_codes"], [])
        self.assertEqual(view["files_checked"], 0)
        self.assertIn("文件缺失表示未验证", view["coverage"])
        self.assertIn("不读取离线队列正文", view["coverage"])

    def test_missing_parent_recreated_and_atomic_replace_are_observed(self):
        watcher = self.watcher()
        self.wait(watcher, "missing")
        self.write()
        first = self.wait(watcher, "safe")
        replacement = self.path.with_name("scope-new")
        self.write(scope("zh-CN"), replacement)
        os.replace(replacement, self.path)
        risk = self.wait(watcher, "risk")
        self.assertGreater(risk["event_seq"], first["event_seq"])
        watcher.acknowledge(risk["event_seq"])
        shutil.rmtree(self.path.parent)
        self.wait(watcher, "missing")
        self.write()
        self.wait(watcher, "safe")

    def test_unchanged_scope_reuses_content_but_refreshes_check_age(self):
        self.write()
        calls = []
        def reader(fd, limit):
            calls.append(1)
            return ClaudeTelemetryWatch._read(fd, limit)
        watcher = self.watcher(reader=reader)
        first = self.wait(watcher, "safe")
        time.sleep(.18)
        current = watcher.sample()
        self.assertEqual(len(calls), 1)
        self.assertEqual(current["files_checked"], 1)
        self.assertEqual(current["event_seq"], first["event_seq"])
        self.assertLess(current["last_check_age_ms"], 120)

    def test_nonblocking_sample_and_pending_state_during_inflight_read(self):
        self.write()
        entered, release = threading.Event(), threading.Event()
        def reader(fd, limit):
            entered.set()
            release.wait(3)
            return ClaudeTelemetryWatch._read(fd, limit)
        watcher = self.watcher(reader=reader)
        try:
            watcher.start()
            self.assertTrue(entered.wait(1))
            started = time.monotonic()
            view = watcher.sample()
            self.assertLess(time.monotonic() - started, .03)
            self.assertEqual(view["state"], "checking")
            self.assertEqual(view["reason_codes"], ["telemetry_file_pending"])
        finally:
            release.set()
        self.wait(watcher, "safe")

    def test_stop_invalidates_inflight_read_and_sample_cannot_restart_it(self):
        self.write(scope("zh-CN"))
        entered, release = threading.Event(), threading.Event()
        def reader(fd, limit):
            entered.set()
            release.wait(3)
            return ClaudeTelemetryWatch._read(fd, limit)
        watcher = self.watcher(reader=reader)
        watcher.start()
        self.assertTrue(entered.wait(1))
        watcher.stop()
        stopped_seq = watcher.sample()["event_seq"]
        release.set()
        deadline = time.monotonic() + 1
        while watcher._thread is not None and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertEqual(watcher.sample()["state"], "stopped")
        self.assertEqual(watcher.sample()["event_seq"], stopped_seq)
        self.assertIsNone(watcher._thread)

    def test_callbacks_are_zero_argument_and_failures_do_not_stop_observation(self):
        self.write()
        fired = threading.Event()
        def callback():
            fired.set()
            raise RuntimeError("private text must not escape")
        watcher = self.watcher()
        watcher.set_callback(callback)
        self.wait(watcher, "safe")
        self.assertTrue(fired.is_set())
        self.write(scope(timezone="Asia/Shanghai"))
        self.wait(watcher, "risk")

    def test_concurrent_start_uses_one_worker(self):
        self.write()
        watcher = self.watcher()
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

    def test_symlink_leaf_and_any_parent_component_are_unknown(self):
        self.write()
        target = self.path.with_name("real-scope")
        self.path.rename(target)
        self.path.symlink_to(target)
        watcher = self.watcher(reader=lambda *_: self.fail("must not follow leaf symlink"))
        self.wait(watcher, "unknown")
        watcher.stop()
        self.path.unlink()
        target.rename(self.path)
        sentry = self.path.parent
        real = sentry.with_name("real-sentry")
        sentry.rename(real)
        sentry.symlink_to(real, target_is_directory=True)
        watcher = self.watcher(reader=lambda *_: self.fail("must not follow parent symlink"))
        self.wait(watcher, "unknown")

    def test_nonowned_unreadable_and_nonregular_scope_are_unknown_without_reading(self):
        self.write()
        watcher = self.watcher(reader=lambda *_: self.fail("untrusted file must not be read"))
        watcher._uid = os.getuid() + 1
        self.wait(watcher, "unknown")
        watcher.stop()
        self.path.chmod(0)
        watcher = self.watcher(reader=lambda *_: self.fail("unreadable file must not be read"))
        self.wait(watcher, "unknown")
        watcher.stop()
        self.path.chmod(0o600)
        self.path.unlink()
        self.path.mkdir()
        watcher = self.watcher(reader=lambda *_: self.fail("directory must not be read"))
        self.wait(watcher, "unknown")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_fifo_never_blocks_worker_or_gets_parsed(self):
        self.path.parent.mkdir(parents=True)
        os.mkfifo(self.path)
        watcher = self.watcher(reader=lambda *_: self.fail("FIFO must not be read"))
        self.wait(watcher, "unknown", timeout=1)

    def test_size_limit_and_injected_oversize_read_fail_closed(self):
        self.write(raw=b" " * (MAX_SCOPE_BYTES + 1))
        watcher = self.watcher(reader=lambda *_: self.fail("oversized file must not be read"))
        view = self.wait(watcher, "unknown")
        self.assertEqual(view["files_checked"], 0)
        watcher.stop()
        self.write()
        watcher = self.watcher(reader=lambda *_: b" " * (MAX_SCOPE_BYTES + 1))
        self.wait(watcher, "unknown")

    def test_truncated_write_is_unknown_then_recovery_is_observed(self):
        self.write(raw=b'{"event":')
        watcher = self.watcher()
        self.wait(watcher, "unknown")
        self.write()
        self.wait(watcher, "safe")

    def test_mutation_or_replacement_during_read_never_publishes_old_safe(self):
        self.write()
        replaced = threading.Event()
        def reader(fd, limit):
            data = ClaudeTelemetryWatch._read(fd, limit)
            if not replaced.is_set():
                replacement = self.path.with_name("replacement")
                self.write(scope("zh-CN"), replacement)
                os.replace(replacement, self.path)
                replaced.set()
            return data
        watcher = self.watcher(reader=reader)
        seen = []
        watcher.set_callback(lambda: seen.append(watcher.sample()["state"]))
        view = self.wait(watcher, "risk")
        self.assertTrue(replaced.is_set())
        self.assertNotIn("safe", seen)
        self.assertEqual(view["files_checked"], 1)

    def test_risk_is_latched_across_safe_rewrite_until_acknowledged(self):
        self.write(scope("zh-CN"))
        watcher = self.watcher()
        risk = self.wait(watcher, "risk")
        self.write()
        self.wait(watcher, "risk", lambda view: view["files_checked"] >= 2)
        self.assertEqual(watcher.sample()["event_seq"], risk["event_seq"])
        watcher.acknowledge(risk["event_seq"])
        self.wait(watcher, "safe")

    def test_old_ack_cannot_clear_a_newer_risk_and_view_is_a_copy(self):
        self.write(scope("zh-CN"))
        watcher = self.watcher()
        first = self.wait(watcher, "risk")
        self.write()
        self.wait(watcher, "risk", lambda view: view["files_checked"] >= 2)
        self.write(scope(timezone="Asia/Shanghai"))
        latest = self.wait(watcher, "risk", lambda view: view["event_seq"] > first["event_seq"])
        self.write()
        self.wait(watcher, "risk", lambda view: view["files_checked"] >= 4)
        watcher.acknowledge(first["event_seq"])
        view = watcher.sample()
        self.assertEqual(view["event_seq"], latest["event_seq"])
        view["reason_codes"].clear()
        self.assertEqual(watcher.sample()["reason_codes"], ["telemetry_cn_timezone"])
        watcher.acknowledge(latest["event_seq"])
        self.wait(watcher, "safe")

    def test_acknowledge_wakes_guard_for_already_cached_recovery(self):
        self.write(scope("zh-CN"))
        watcher = self.watcher()
        changed = threading.Event()
        watcher.set_callback(changed.set)
        risk = self.wait(watcher, "risk")
        self.write()
        self.wait(watcher, "risk", lambda view: view["files_checked"] >= 2)
        changed.clear()
        watcher.acknowledge(risk["event_seq"])
        self.assertTrue(changed.is_set())
        self.assertEqual(watcher.sample()["state"], "safe")

    def test_latched_risk_age_uses_latest_stat_heartbeat(self):
        self.write(scope("zh-CN"))
        clock = lambda: time.monotonic()
        watcher = self.watcher(clock=clock)
        risk = self.wait(watcher, "risk")
        self.write()
        self.wait(watcher, "risk", lambda view: view["files_checked"] >= 2)
        time.sleep(.18)
        view = watcher.sample()
        self.assertEqual(view["event_seq"], risk["event_seq"])
        self.assertLess(view["last_check_age_ms"], 120)

    def test_clock_injection_exposes_a_stalled_heartbeat_without_plaintext(self):
        self.write(scope(country="US", secret_id="secret-fixture-identity"))
        now = [100.0]
        watcher = self.watcher(clock=lambda: now[0])
        self.wait(watcher, "safe")
        with watcher._lock:
            now[0] += 3
            view = watcher._view()
        self.assertEqual(view["last_check_age_ms"], 3000)
        self.assertEqual(set(view), {"state", "reason_codes", "field_types", "last_check_age_ms",
                                     "last_scan_ms", "backend", "coverage", "files_checked", "event_seq"})
        serialized = json.dumps(view, ensure_ascii=False)
        for value in (str(self.root), "secret-fixture-identity", "en-US", "America/New_York"):
            self.assertNotIn(value, serialized)

    def test_reader_exception_is_redacted_and_unknown(self):
        self.write()
        def reader(*_):
            raise OSError("secret-fixture-identity /private/fixture/path")
        watcher = self.watcher(reader=reader)
        view = self.wait(watcher, "unknown")
        self.assertNotIn("secret-fixture", json.dumps(view))

    def test_unexpected_worker_exit_exposes_unknown_and_requires_explicit_restart(self):
        self.write()
        fail = threading.Event()
        calls = []
        def reader(fd, limit):
            calls.append(1)
            if fail.is_set():
                fail.clear()
                raise SystemExit("private failure must not escape the worker")
            return ClaudeTelemetryWatch._read(fd, limit)
        watcher = self.watcher(reader=reader)
        self.wait(watcher, "safe")
        fail.set()
        self.write(scope(locale="en-GB"))
        self.wait(watcher, "unknown")
        deadline = time.monotonic() + 1
        while watcher._thread is not None and time.monotonic() < deadline:
            time.sleep(.005)
        count = len(calls)
        for _ in range(3):
            self.assertEqual(watcher.sample()["state"], "unknown")
            self.assertIsNone(watcher._thread)
        self.assertEqual(len(calls), count)
        watcher.start()
        self.wait(watcher, "safe")

    def test_unexpected_exit_and_explicit_restart_preserve_unacknowledged_risk(self):
        self.write(scope("zh-CN"))
        fail = threading.Event()
        def reader(fd, limit):
            if fail.is_set():
                fail.clear()
                raise SystemExit("private failure must not escape the worker")
            return ClaudeTelemetryWatch._read(fd, limit)
        watcher = self.watcher(reader=reader)
        risk = self.wait(watcher, "risk")
        fail.set()
        self.write()
        deadline = time.monotonic() + 1
        while watcher._thread is not None and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertIsNone(watcher._thread)
        for _ in range(3):
            self.assertEqual(watcher.sample()["event_seq"], risk["event_seq"])
            self.assertEqual(watcher.sample()["state"], "risk")
            self.assertIsNone(watcher._thread)
        watcher.start()
        self.wait(watcher, "risk", lambda view: view["files_checked"] >= 2)
        self.assertEqual(watcher.sample()["event_seq"], risk["event_seq"])
        watcher.acknowledge(risk["event_seq"])
        self.wait(watcher, "safe")

    def test_supported_intervals_and_callback_validation(self):
        watcher = self.watcher()
        for value in (50, 100, 250, 500):
            watcher.configure(value)
        for value in (0, 10, 100.0, True, "100", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                watcher.configure(value)
        with self.assertRaises(TypeError):
            watcher.set_callback("not callable")

    @unittest.skipUnless(sys.platform == "darwin" and hasattr(select, "kqueue"), "Darwin kqueue required")
    def test_real_kqueue_observes_isolated_fixture_before_long_poll_deadline(self):
        self.write()
        watcher = self.watcher()
        watcher.configure(500)
        view = self.wait(watcher, "safe")
        self.assertEqual(view["backend"], "kqueue+stat")
        # Let the initial queued vnode notifications drain before measuring a new write.
        time.sleep(.08)
        started = time.monotonic()
        self.write(scope("zh-CN"))
        self.wait(watcher, "risk", timeout=.4)
        self.assertLess(time.monotonic() - started, .4)

    def test_unavailable_kqueue_falls_back_to_stat(self):
        self.write()
        with patch.object(telemetry_watch, "_KqueueEvents", side_effect=OSError("unavailable")):
            watcher = self.watcher()
            self.assertEqual(self.wait(watcher, "safe")["backend"], "stat")
            self.write(scope("zh-CN"))
            self.wait(watcher, "risk")

    @unittest.skipUnless(sys.platform == "darwin" and hasattr(select, "kqueue"), "Darwin kqueue required")
    def test_runtime_kqueue_registration_or_wait_failure_reverts_to_stat(self):
        for method in ("synchronize", "wait"):
            with self.subTest(method=method):
                self.write()
                with patch.object(telemetry_watch._KqueueEvents, method, side_effect=OSError("private kqueue error")):
                    watcher = self.watcher()
                    view = self.wait(watcher, "safe", lambda result: result["backend"] == "stat")
                    self.assertGreater(view["files_checked"], 0)
                    self.write(scope("zh-CN"))
                    self.wait(watcher, "risk")
                    watcher.stop()

    def test_fstat_failure_closes_opened_descriptor_and_reports_unknown(self):
        self.write()
        original_open, original_close = os.open, os.close
        opened, closed = [], []
        def track_open(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            opened.append(fd)
            return fd
        def track_close(fd):
            closed.append(fd)
            return original_close(fd)
        watcher = self.watcher()
        with patch.object(telemetry_watch.os, "open", side_effect=track_open), \
                patch.object(telemetry_watch.os, "close", side_effect=track_close), \
                patch.object(telemetry_watch.os, "fstat", side_effect=OSError("private stat error")):
            probe = watcher._open()
            self.assertEqual(probe.state, "unknown")
            probe.close()
        self.assertEqual(opened, closed)


if __name__ == "__main__":
    unittest.main()

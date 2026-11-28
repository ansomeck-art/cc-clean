"""Background/cache protocol tests with memory-only samplers, never live traffic."""
import copy
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from traffic_evidence import empty_evidence
from traffic_watch import ACTION_REASON, ClaudeTrafficWatch

PRIVATE = 'PRIVATE-IP-PATH-IDENTIFIER-ERROR'


def frame(route='tun', transport='proxy', backend='injected'):
    value = empty_evidence('observed')
    value['backend'] = backend
    value['interval_floor_ms'] = 2000 if backend == 'lsof_fallback' else 0
    group = value['groups'][0]
    group.update(process_count=1, socket_count=1, matched_count=1, observed_connection_total=1)
    group['ingress_counts']['tun'] = 1
    group['transport_counts'][transport] = 1
    group['route_counts'][route] = 1
    totals = value['history']['groups'][0]
    totals['observed_connection_total'] = 1
    if route == 'physical_bypass':
        group['physical_bypass_connection_delta'] = group['physical_bypass_connection_total'] = 1
        totals['physical_bypass_connection_total'] = 1
    if transport == 'direct':
        group['direct_connection_delta'] = group['direct_connection_total'] = 1
        totals['direct_connection_total'] = 1
        value['history']['direct_observed'] = True
    return value


class Sampler:
    def __init__(self, frames=None, *, entered=None, release=None, error=None):
        self.frames = frames or [frame()]
        self.entered, self.release, self.error = entered, release, error
        self.calls = 0
        self.closed = threading.Event()

    def sample(self):
        self.calls += 1
        if self.entered is not None:
            self.entered.set()
        if self.release is not None and not self.release.wait(3):
            raise RuntimeError('fixture was not released')
        if self.error is not None:
            raise self.error
        value = self.frames[min(self.calls - 1, len(self.frames) - 1)]
        return copy.deepcopy(value() if callable(value) else value)

    def close(self):
        self.closed.set()


class Clock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


class TrafficWatchTests(unittest.TestCase):
    def setUp(self):
        self.watchers, self.releases = [], []

    def tearDown(self):
        for event in self.releases:
            event.set()
        for watch in self.watchers:
            watch.stop()
            thread = watch._thread
            if thread is not None:
                thread.join(3)
                self.assertFalse(thread.is_alive())

    def watcher(self, sampler=None, **kwargs):
        if sampler is not None:
            kwargs['evidence_factory'] = lambda: sampler
        watch = ClaudeTrafficWatch(interval_ms=250, **kwargs)
        self.watchers.append(watch)
        return watch

    def wait(self, watch, predicate, timeout=2):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = watch.status()
            if predicate(value):
                return value
            threading.Event().wait(.003)
        self.fail('expected cache state; fixed projection=' + json.dumps(watch.status()))

    def blocked_sampler(self, value=None):
        entered, release = threading.Event(), threading.Event()
        self.releases.append(release)
        return Sampler([value or frame()], entered=entered, release=release), entered, release

    def assert_current_empty(self, value):
        for group in value['evidence']['groups']:
            self.assertEqual(group['socket_count'], 0)
            self.assertEqual(group['matched_count'], 0)
            self.assertEqual(group['route_counts']['physical_bypass'], 0)
        self.assertIs(value['all_traffic_covered'], False)

    def test_constructor_and_all_cache_operations_do_not_observe(self):
        factory = Mock(side_effect=AssertionError('no observer IO'))
        with patch.object(threading.Thread, 'start', side_effect=AssertionError('no background thread')):
            watch = self.watcher(evidence_factory=factory)
            for operation in (watch.status, watch.sample, watch.get_status, watch.reset, watch.invalidate, watch.stop):
                self.assert_current_empty(operation())
        factory.assert_not_called()

    def test_sampling_runs_on_an_independent_worker_and_public_methods_only_copy_cache(self):
        sampler = Sampler()
        watch = self.watcher(sampler)
        watch.start()
        value = self.wait(watch, lambda item: item['samples'] >= 1)
        calls = sampler.calls
        for _ in range(10):
            self.assertEqual(watch.sample()['state'], 'observed')
            self.assertEqual(watch.get_status()['event_seq'], value['event_seq'])
        self.assertEqual(sampler.calls, calls)
        value['evidence']['groups'][0]['socket_count'] = 999
        self.assertEqual(watch.status()['evidence']['groups'][0]['socket_count'], 1)

    def test_slow_io_never_holds_cache_http_or_stop_operations(self):
        sampler, entered, release = self.blocked_sampler()
        watch = self.watcher(sampler)
        watch.start()
        self.assertTrue(entered.wait(1))
        started = time.monotonic()
        for _ in range(20):
            self.assertEqual(watch.status()['state'], 'checking')
        stopped = watch.stop()
        self.assertLess(time.monotonic() - started, .2)
        self.assertEqual(stopped['state'], 'stopped')
        self.assert_current_empty(stopped)
        release.set()
        self.assertTrue(sampler.closed.wait(1))
        self.assertEqual(watch.status()['samples'], 0)

    def test_stop_then_restart_queues_one_new_io_lane_and_discards_old_generation(self):
        old, entered, release = self.blocked_sampler(frame('physical_bypass'))
        new = Sampler([frame()])
        values = iter((old, new))
        factory = Mock(side_effect=lambda: next(values))
        watch = self.watcher(evidence_factory=factory)
        watch.start()
        self.assertTrue(entered.wait(1))
        watch.stop()
        restarted = watch.start()
        self.assertEqual(restarted['state'], 'checking')
        self.assertEqual(factory.call_count, 1)
        release.set()
        current = self.wait(watch, lambda item: item['samples'] >= 1)
        self.assertEqual(factory.call_count, 2)
        self.assertTrue(old.closed.is_set())
        self.assertEqual(current['action_reason_codes'], [])
        self.assertEqual(current['history']['groups'][0]['physical_bypass_connection_total'], 0)

    def test_reset_during_io_clears_history_and_uses_fresh_sampler(self):
        old, entered, release = self.blocked_sampler(frame('physical_bypass'))
        new = Sampler()
        values = iter((old, new))
        watch = self.watcher(evidence_factory=lambda: next(values))
        watch.start()
        self.assertTrue(entered.wait(1))
        reset = watch.reset()
        self.assertEqual(reset['samples'], 0)
        self.assert_current_empty(reset)
        release.set()
        current = self.wait(watch, lambda item: item['samples'] >= 1)
        self.assertEqual(current['action_reason_codes'], [])
        self.assertEqual(current['history']['groups'][0]['physical_bypass_connection_total'], 0)
        self.assertTrue(old.closed.is_set())

    def test_stale_current_projection_is_revoked_but_history_and_unhandled_risk_remain(self):
        clock = Clock()
        watch = self.watcher(Sampler([frame('physical_bypass')]), clock=clock)
        watch.start()
        self.wait(watch, lambda item: item['samples'] >= 1)
        clock.value += 3
        value = watch.status()
        self.assertEqual(value['state'], 'unknown')
        self.assertIn('traffic_stale', value['reason_codes'])
        self.assert_current_empty(value)
        self.assertEqual(value['history']['groups'][0]['physical_bypass_connection_total'], 1)
        self.assertEqual(value['action_reason_codes'], [ACTION_REASON])

    def test_sample_age_uses_earliest_capture_start_not_slow_io_completion(self):
        clock = Clock()
        release = threading.Event()
        self.releases.append(release)
        def slow_frame():
            if sampler.calls == 1:
                clock.value += 1
            else:
                release.wait(3)
            return frame()
        sampler = Sampler([slow_frame])
        watch = self.watcher(sampler, clock=clock)
        watch.start()
        value = self.wait(watch, lambda item: item['samples'] >= 1)
        self.assertEqual(value['last_sample_ms'], 1000)
        self.assertEqual(value['last_check_age_ms'], 1000)

    def test_startup_reader_stuck_without_first_frame_eventually_becomes_unknown(self):
        clock = Clock()
        sampler, entered, release = self.blocked_sampler()
        watch = self.watcher(sampler, clock=clock)
        watch.start()
        self.assertTrue(entered.wait(1))
        clock.value += 3
        value = watch.status()
        self.assertEqual(value['state'], 'unknown')
        self.assertIsNone(value['last_check_age_ms'])
        self.assert_current_empty(value)
        release.set()

    def test_ack_only_consumes_handled_frame_and_new_fresh_bypass_rearms(self):
        watch = self.watcher(Sampler([frame('physical_bypass')]))
        watch.start()
        first = self.wait(watch, lambda item: item['samples'] >= 1)
        self.assertEqual(first['action_reason_codes'], [ACTION_REASON])
        watch.acknowledge(first['event_seq'])
        self.assertEqual(watch.status()['action_reason_codes'], [])
        self.assertEqual(watch.status()['evidence']['groups'][0]['route_counts']['physical_bypass'], 1)
        second = self.wait(watch, lambda item: item['samples'] > first['samples'])
        self.assertEqual(second['action_reason_codes'], [ACTION_REASON])
        watch.acknowledge(first['event_seq'])
        self.assertEqual(watch.status()['action_reason_codes'], [ACTION_REASON])
        watch.acknowledge(second['event_seq'])
        self.assertEqual(watch.status()['action_reason_codes'], [])

    def test_direct_rule_or_unknown_route_never_arms_physical_bypass_action(self):
        for route in ('tun', 'local', 'blocked', 'unknown'):
            with self.subTest(route=route):
                watch = self.watcher(Sampler([frame(route, 'direct')]))
                watch.start()
                value = self.wait(watch, lambda item: item['samples'] >= 1)
                self.assertEqual(value['action_reason_codes'], [])
                self.assertTrue(value['history']['direct_observed'])
                watch.stop()

    def test_invalidate_revokes_current_without_consuming_latch_or_history(self):
        sampler = Sampler([frame('physical_bypass')])
        watch = self.watcher(sampler)
        watch.start()
        value = self.wait(watch, lambda item: item['samples'] >= 1)
        invalid = watch.invalidate()
        self.assert_current_empty(invalid)
        self.assertEqual(invalid['action_reason_codes'], [ACTION_REASON])
        self.assertEqual(invalid['history'], value['history'])
        fresh = self.wait(watch, lambda item: item['samples'] > value['samples'])
        self.assertEqual(fresh['action_reason_codes'], [ACTION_REASON])

    def test_atomic_arming_barrier_clears_actions_but_preserves_history_and_discards_old_io(self):
        sampler = Sampler([frame('physical_bypass'), frame('physical_bypass'), frame('physical_bypass'), frame()])
        watch = self.watcher(sampler)
        watch.start()
        first = self.wait(watch, lambda item: item['samples'] >= 1)
        watch.acknowledge(first['event_seq'])
        # Simulate the newer observational event that a separate status/ACK
        # sequence cannot consume. It still predates the user's arming barrier.
        second = self.wait(watch, lambda item: item['samples'] > first['samples'])
        self.assertEqual(second['action_reason_codes'], [ACTION_REASON])
        entered, release = threading.Event(), threading.Event()
        self.releases.append(release)
        sampler.entered, sampler.release = entered, release
        watch.invalidate()
        self.assertTrue(entered.wait(1))
        before = watch.status()
        armed = watch.invalidate(clear_actions=True)
        self.assertEqual(armed['action_reason_codes'], [])
        self.assertEqual(armed['history'], before['history'])
        self.assert_current_empty(armed)
        release.set()
        fresh = self.wait(watch, lambda item: item['samples'] > second['samples'])
        self.assertEqual(fresh['action_reason_codes'], [])
        self.assertEqual(fresh['evidence']['groups'][0]['route_counts']['physical_bypass'], 0)

    def test_observed_short_risk_is_preserved_after_safe_current_frame(self):
        risky, safe = frame('physical_bypass'), frame()
        safe['history'] = copy.deepcopy(risky['history'])
        watch = self.watcher(Sampler([risky, safe]))
        watch.start()
        first = self.wait(watch, lambda item: item['samples'] >= 1)
        watch.invalidate()
        later = self.wait(watch, lambda item: item['samples'] > first['samples'])
        self.assertEqual(later['evidence']['groups'][0]['route_counts']['physical_bypass'], 0)
        self.assertEqual(later['history']['groups'][0]['physical_bypass_connection_total'], 1)
        self.assertEqual(later['action_reason_codes'], [ACTION_REASON])

    def test_stop_clears_current_and_action_but_preserves_numeric_history(self):
        watch = self.watcher(Sampler([frame('physical_bypass')]))
        watch.start()
        previous = self.wait(watch, lambda item: item['samples'] >= 1)
        stopped = watch.stop()
        self.assertEqual(stopped['action_reason_codes'], [])
        self.assertEqual(stopped['history'], previous['history'])
        self.assert_current_empty(stopped)

    def test_ordinary_sample_exception_retains_history_and_never_echoes_exception(self):
        sampler = Sampler([frame('physical_bypass')])
        watch = self.watcher(sampler)
        watch.start()
        first = self.wait(watch, lambda item: item['samples'] >= 1)
        sampler.error = RuntimeError(PRIVATE)
        watch.invalidate()
        failed = self.wait(watch, lambda item: item['samples'] > first['samples'])
        self.assertEqual(failed['state'], 'unknown')
        self.assert_current_empty(failed)
        self.assertEqual(failed['history']['groups'][0]['physical_bypass_connection_total'], 1)
        self.assertEqual(failed['action_reason_codes'], [ACTION_REASON])
        self.assertNotIn(PRIVATE, json.dumps(failed))

    def test_unexpected_worker_exit_is_visible_and_explicit_restart_recovers(self):
        broken = Sampler(error=SystemExit(PRIVATE))
        healthy = Sampler()
        values = iter((broken, healthy))
        watch = self.watcher(evidence_factory=lambda: next(values))
        watch.start()
        failure = self.wait(watch, lambda item: not item['running'])
        self.assertEqual(failure['state'], 'unknown')
        self.assertIn('traffic_worker_stopped', failure['reason_codes'])
        self.assertNotIn(PRIVATE, json.dumps(failure))
        watch.start()
        self.assertEqual(self.wait(watch, lambda item: item['samples'] >= 1)['state'], 'observed')

    def test_lsof_fallback_has_effective_slow_cadence_even_when_invalidated(self):
        sampler = Sampler([frame(backend='lsof_fallback')])
        watch = self.watcher(sampler)
        watch.start()
        value = self.wait(watch, lambda item: item['samples'] >= 1)
        self.assertEqual(value['backend'], 'lsof_fallback')
        self.assertEqual(value['requested_interval_ms'], 250)
        self.assertEqual(value['interval_ms'], 2000)
        self.assertEqual(value['stale_after_ms'], 6500)
        for _ in range(4):
            watch.invalidate()
        threading.Event().wait(.03)
        self.assertEqual(sampler.calls, 1)

    def test_fixed_schema_rejects_malformed_counts_and_strips_extra_values(self):
        valid = frame()
        valid.update(path=PRIVATE, address=PRIVATE)
        valid['groups'][0].update(pid=PRIVATE, source_ip=PRIVATE)
        malformed = frame()
        malformed['groups'][0]['route_counts']['physical_bypass'] = True
        watch = self.watcher(Sampler([valid, malformed]))
        watch.start()
        first = self.wait(watch, lambda item: item['samples'] >= 1)
        self.assertNotIn(PRIVATE, json.dumps(first))
        watch.invalidate()
        second = self.wait(watch, lambda item: item['samples'] > first['samples'])
        self.assertEqual(second['state'], 'unknown')
        self.assert_current_empty(second)
        self.assertEqual(second['action_reason_codes'], [])

    def test_concurrent_start_creates_only_one_worker(self):
        factory = Mock(side_effect=lambda: Sampler())
        watch = self.watcher(evidence_factory=factory)
        barrier = threading.Barrier(4)
        failures = []
        def start():
            try:
                barrier.wait(1)
                watch.start()
            except Exception as error:
                failures.append(type(error).__name__)
        threads = [threading.Thread(target=start) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(1)
        self.wait(watch, lambda item: item['samples'] >= 1)
        self.assertFalse(failures)
        self.assertEqual(factory.call_count, 1)


if __name__ == '__main__':
    unittest.main()

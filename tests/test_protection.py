"""New explicit protection authorization: every destructive primitive is mocked here."""
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import signal
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mac_guard
from protection import FastProtector


class FakeNetwork:
    events = None
    def __init__(self, safe=True):
        self.safe = safe
        self.closed = False
    def sample(self):
        return dict(safe=self.safe, reasons=[] if self.safe else ['tun_down'], interfaces=['utun4'])
    def wait(self, timeout):
        time.sleep(timeout)
        return False
    def close(self):
        self.closed = True


class FakeProcesses:
    def __init__(self):
        self.available = []
        self.terminated = []
    def candidates(self):
        return list(self.available)
    def terminate(self, identity):
        self.terminated.append(identity)
        self.available.remove(identity)
        return 'terminated'


class FakeTelemetry:
    def __init__(self):
        self.value = dict(state='safe', reason_codes=[], field_types=[], last_check_age_ms=0,
                          last_scan_ms=0, backend='poll', files_checked=1, event_seq=1)
        self.started = False
        self.acknowledged = []
    def sample(self):
        return dict(self.value)
    def configure(self, interval_ms):
        self.interval_ms = interval_ms
    def set_callback(self, callback):
        self.callback = callback
    def start(self):
        self.started = True
    def stop(self):
        self.started = False
    def acknowledge(self, event_seq):
        self.acknowledged.append(event_seq)


class Clock:
    def __init__(self):
        self.value = 100
    def __call__(self):
        return self.value


class ProtectionStateTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.network = FakeNetwork()
        self.processes = FakeProcesses()
        self.guard = FastProtector(supported=True, clock=self.clock, telemetry_factory=FakeTelemetry)
        self.guard._network, self.guard._processes = self.network, self.processes
        self.telemetry = self.guard._telemetry = FakeTelemetry()
        self.guard.configure('US', True)
        self.guard._state['running'] = True
    def pulse(self, **extra):
        event = dict(target='US', ok=True, loc='US', colo='LAX', utun_up=True, changed_ip=False)
        event.update(extra)
        self.guard.observe_pulse(event, self.clock())
    def test_strict_startup_pending_blocks_and_then_verified_safe(self):
        self.processes.available = [1]
        self.guard._step()
        self.assertEqual(self.processes.terminated, [1])
        self.assertIn('remote_pending', self.guard.status()['reason_codes'])
        self.pulse()
        self.guard._step()
        self.assertEqual(self.guard.status()['status'], 'safe')
    def test_local_fault_immediately_terminates_without_waiting_for_geo(self):
        self.pulse()
        self.network.safe = False
        self.processes.available = [5]
        self.guard._step()
        status = self.guard.status()
        self.assertEqual(self.processes.terminated, [5])
        self.assertEqual(status['terminated_total'], 1)
        self.assertIn('tun_down', status['reason_codes'])
        self.assertEqual(status['last_action']['terminated'], 1)
    def test_relaunch_while_blocked_is_stopped_again_and_never_reopened(self):
        self.network.safe = False
        self.processes.available = [1]
        self.guard._step()
        self.processes.available = [2]
        self.guard._step()
        self.assertEqual(self.processes.terminated, [1, 2])
        self.network.safe = True
        self.guard._step()
        self.assertIn('route_pending', self.guard.status()['reason_codes'])
        self.pulse()
        self.guard._step()
        self.assertEqual(self.guard.status()['status'], 'safe')
        self.assertFalse(self.processes.available)
    def test_remote_failure_country_restriction_and_ip_change(self):
        for changes, code in (({'ok': False}, 'remote_unreachable'), ({'loc': 'JP'}, 'country_mismatch'),
                              ({'loc': 'CN'}, 'restricted_egress'), ({'changed_ip': True}, 'ip_changed'),
                              ({'colo': 'TAO', 'anomaly_reasons': ['出口进入受限地区']}, 'restricted_egress')):
            with self.subTest(changes=changes):
                self.pulse(**changes)
                self.guard._step()
                self.assertIn(code, self.guard.status()['reason_codes'])
    def test_pending_wake_rejects_pre_wake_inflight_success(self):
        self.pulse()
        self.clock.value += 1
        self.guard.on_wake()
        self.guard.observe_pulse(dict(target='US', ok=True, loc='US', colo='LAX', utun_up=True), 100)
        self.guard._step()
        self.assertIn('wake_pending', self.guard.status()['reason_codes'])
        self.pulse()
        self.guard._step()
        self.assertEqual(self.guard.status()['status'], 'safe')
    def test_out_of_order_and_previous_target_do_not_disarm(self):
        self.pulse(ok=False)
        self.guard.observe_pulse(dict(target='JP', ok=True, loc='JP', utun_up=True), self.clock())
        self.guard.observe_pulse(dict(target='US', ok=True, loc='US', utun_up=True), self.clock() - 1)
        self.guard._step()
        self.assertIn('remote_unreachable', self.guard.status()['reason_codes'])
        self.guard.configure('JP', True)
        self.guard._step()
        self.assertIn('remote_pending', self.guard.status()['reason_codes'])
    def test_route_recovery_requires_a_new_probe_and_critical_route_event_reblocks(self):
        self.pulse()
        self.guard._step()
        self.guard.on_route_change()
        self.guard._step()
        self.assertIn('route_pending', self.guard.status()['reason_codes'])
        self.pulse()
        self.guard._step()
        self.assertEqual(self.guard.status()['status'], 'safe')

    def test_probe_staleness_fail_closed(self):
        self.pulse()
        self.clock.value += 66
        self.guard._step()
        self.assertIn('remote_stale', self.guard.status()['reason_codes'])
    def test_disable_and_pause_never_signal(self):
        self.processes.available = [3]
        self.guard.configure('US', False)
        self.guard._step()
        self.assertFalse(self.processes.terminated)
        self.guard._enabled = True
        self.guard._state['running'] = False
        self.guard._step()
        self.assertFalse(self.processes.terminated)
    def test_missing_process_backend_cannot_report_healthy_protection(self):
        self.guard._processes = None
        self.pulse()
        self.guard._step()
        self.assertNotEqual(self.guard.status()['status'], 'safe')
        self.assertIn('process_unknown', self.guard.status()['reason_codes'])

    def test_permission_failure_is_reported_not_success(self):
        self.processes.available = [3]
        self.processes.terminate = lambda identity: 'denied'
        self.guard._step()
        self.assertEqual(self.guard.status()['terminated_total'], 0)
        self.assertIn('termination_denied', self.guard.status()['reason_codes'])
    def test_unknown_snapshot_fail_closed_without_raw_exception(self):
        self.network.sample = Mock(side_effect=ValueError('SECRET-RAW-ADDRESS'))
        self.guard._step()
        self.assertIn('kernel_unknown', self.guard.status()['reason_codes'])
        self.assertNotIn('SECRET', json.dumps(self.guard.status()))
    def test_malformed_snapshot_schema_is_fail_closed(self):
        for local in ({'safe': 'false', 'reasons': [], 'interfaces': []},
                      {'safe': True, 'reasons': 'SECRET-RAW-VALUE', 'interfaces': []},
                      {'safe': True, 'reasons': [], 'interfaces': 'utun4'},
                      {'safe': True, 'reasons': [5], 'interfaces': []}):
            with self.subTest(local=local):
                self.network.sample = Mock(return_value=local)
                self.guard._step()
                self.assertIn('kernel_unknown', self.guard.status()['reason_codes'])
                self.assertNotIn('SECRET-RAW-VALUE', json.dumps(self.guard.status()))

    def test_unsupported_platform_never_enumerates_or_kills(self):
        processes = Mock()
        guard = FastProtector(process_factory=processes, supported=False)
        guard.start(enabled=True)
        self.assertEqual(guard.status()['status'], 'unsupported')
        processes.assert_not_called()
        guard.stop()
    def test_slow_notification_callback_does_not_block_fast_worker(self):
        network, processes = FakeNetwork(False), FakeProcesses()
        callback_started, callback_release = threading.Event(), threading.Event()
        def callback(snapshot):
            callback_started.set()
            callback_release.wait(2)
        guard = FastProtector(network_factory=lambda: network, process_factory=lambda: processes,
                              supported=True, callback=callback, telemetry_factory=FakeTelemetry)
        guard.start(interval_ms=50)
        try:
            self.assertTrue(callback_started.wait(1))
            before = guard.status()['samples']
            time.sleep(.18)
            self.assertGreaterEqual(guard.status()['samples'] - before, 2)
        finally:
            callback_release.set()
            guard.stop()
        self.assertTrue(network.closed)
        self.assertFalse(guard._thread.is_alive())

    def test_local_recovery_rejects_a_success_started_before_recovery(self):
        self.pulse()
        self.guard._step()
        self.clock.value = 101
        self.network.safe = False
        self.guard._step()
        self.clock.value = 103
        self.network.safe = True
        self.guard._step()
        self.guard.observe_pulse(dict(target='US', ok=True, loc='US', colo='LAX', utun_up=True), 102)
        self.guard._step()
        self.assertIn('route_pending', self.guard.status()['reason_codes'])
        self.clock.value = 104
        self.pulse()
        self.guard._step()
        self.assertEqual(self.guard.status()['status'], 'safe')

    def test_last_action_retains_its_own_event_sequence_after_recovery(self):
        self.processes.available = [15]
        self.guard._step()
        blocked = self.guard.status()
        action_sequence = blocked['last_action']['event_seq']
        self.assertEqual(action_sequence, blocked['event_seq'])
        self.pulse()
        self.guard._step()
        safe = self.guard.status()
        self.assertGreater(safe['event_seq'], action_sequence)
        self.assertEqual(safe['last_action']['event_seq'], action_sequence)
        self.pulse(ok=False)
        self.guard._step()
        later_block = self.guard.status()
        self.assertGreater(later_block['event_seq'], action_sequence)
        self.assertEqual(later_block['last_action']['event_seq'], action_sequence)

    def test_telemetry_risk_terminates_even_with_healthy_routes_and_fresh_us_probe(self):
        self.pulse()
        for field in ('country', 'locale', 'timezone'):
            self.telemetry.value.update(state='risk', reason_codes=['telemetry_cn_' + field],
                                        field_types=[field], event_seq=self.telemetry.value['event_seq'] + 1)
            self.processes.available = [field]
            self.guard._step()
            self.assertIn(field, self.processes.terminated)
            self.assertIn('telemetry_cn_' + field, self.guard.status()['reason_codes'])
            self.assertIn(self.telemetry.value['event_seq'], self.telemetry.acknowledged)

    def test_telemetry_recovery_requires_a_new_public_result_and_never_reopens(self):
        self.pulse()
        self.telemetry.value.update(state='risk', reason_codes=['telemetry_cn_locale'], field_types=['locale'])
        self.processes.available = [20]
        self.guard._step()
        self.clock.value += 2
        self.telemetry.value.update(state='safe', reason_codes=[], field_types=[])
        self.guard._step()
        self.assertEqual(self.processes.terminated, [20])
        self.assertIn('telemetry_pending', self.guard.status()['reason_codes'])
        self.guard.observe_pulse(dict(target='US', ok=True, loc='US', utun_up=True), self.clock() - 1)
        self.guard._step()
        self.assertIn('telemetry_pending', self.guard.status()['reason_codes'])
        self.pulse()
        self.guard._step()
        self.assertEqual(self.guard.status()['status'], 'safe')
        self.assertFalse(self.processes.available)

    def test_unknown_stale_and_stopped_file_observer_warn_without_termination(self):
        self.pulse()
        self.processes.available = [123]
        for changes, reason in (({'state': 'unknown'}, 'telemetry_file_unknown'),
                                ({'state': 'checking'}, 'telemetry_file_pending'),
                                ({'state': 'stopped'}, 'telemetry_file_pending'),
                                ({'state': 'safe', 'last_check_age_ms': 9000}, 'telemetry_file_stale')):
            with self.subTest(changes=changes):
                self.telemetry.value.update({'last_check_age_ms': 0, 'reason_codes': [], **changes})
                self.guard._step()
                self.assertIn(reason, self.guard.status()['telemetry']['reason_codes'])
                self.assertEqual(self.guard.status()['status'], 'safe')
        self.telemetry.sample = Mock(side_effect=ValueError('SECRET-USER-ID'))
        self.guard._step()
        self.assertIn('telemetry_file_unknown', self.guard.status()['telemetry']['reason_codes'])
        self.assertFalse(self.processes.terminated)
        self.assertNotIn('SECRET', json.dumps(self.guard.status()))

    def test_missing_file_is_a_coverage_gap_without_positive_cn_evidence(self):
        self.pulse()
        self.telemetry.value.update(state='missing')
        self.guard._step()
        self.assertEqual(self.guard.status()['status'], 'safe')
        self.assertEqual(self.guard.status()['telemetry']['state'], 'missing')
        self.assertFalse(self.processes.terminated)

    def test_file_snapshot_schema_rejects_values_and_raw_exceptions(self):
        self.pulse()
        for changes in ({'field_types': ['SECRET-COUNTRY-VALUE']},
                        {'reason_codes': ['SECRET-USER-ID']}, {'last_check_age_ms': float('nan')},
                        {'last_check_age_ms': True}, {'state': 'SECRET-JSON'},
                        {'state': 'risk', 'reason_codes': []}):
            with self.subTest(changes=changes):
                self.telemetry.sample = Mock(return_value={**FakeTelemetry().value, **changes})
                self.guard._step()
                self.assertIn('telemetry_file_unknown', self.guard.status()['telemetry']['reason_codes'])
                self.assertNotIn('SECRET', json.dumps(self.guard.status()))

    def test_disabled_or_paused_guard_never_samples_or_acknowledges_file_risk(self):
        self.telemetry.sample = Mock(side_effect=AssertionError('must not read files'))
        self.guard.configure('US', False)
        self.guard._step()
        self.telemetry.sample.assert_not_called()
        self.assertFalse(self.telemetry.acknowledged)

    def test_file_risk_is_not_acknowledged_when_process_handling_is_unconfirmed(self):
        self.telemetry.value.update(state='risk', reason_codes=['telemetry_cn_country'], field_types=['country'])
        self.processes.available = [22]
        self.processes.terminate = Mock(return_value='denied')
        self.guard._step()
        self.assertFalse(self.telemetry.acknowledged)
        self.processes.terminate.return_value = 'rejected'
        self.guard._step()
        self.assertFalse(self.telemetry.acknowledged)
        self.processes.candidates = Mock(side_effect=OSError('PRIVATE-DETAIL'))
        self.guard._step()
        self.assertFalse(self.telemetry.acknowledged)
        self.assertNotIn('PRIVATE-DETAIL', json.dumps(self.guard.status()))



class ProtectionConcurrencyTests(unittest.TestCase):
    def manual_guard(self, network=None, processes=None):
        guard = FastProtector(supported=True, telemetry_factory=FakeTelemetry)
        guard.configure('US', True)
        guard._network = network or FakeNetwork(False)
        guard._processes = processes or FakeProcesses()
        guard._telemetry = FakeTelemetry()
        guard._state['running'] = True
        return guard

    def run_thread(self, function):
        errors = []
        def run():
            try:
                function()
            except BaseException as exc:
                errors.append(exc)
        worker = threading.Thread(target=run)
        worker.start()
        return worker, errors

    def test_disable_invalidates_inflight_sample_before_any_signal(self):
        sample_entered, release = threading.Event(), threading.Event()
        class InflightNetwork(FakeNetwork):
            def sample(self):
                sample_entered.set()
                if not release.wait(2):
                    raise AssertionError('fixture sample not released')
                return super().sample()
        processes = FakeProcesses()
        processes.available = [10]
        guard = self.manual_guard(InflightNetwork(False), processes)
        worker, errors = self.run_thread(guard._step)
        try:
            self.assertTrue(sample_entered.wait(1))
            guard.configure('US', False)
            self.assertEqual(guard.status()['status'], 'paused')
        finally:
            release.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors)
        self.assertFalse(processes.terminated)

    def test_stop_invalidates_inflight_sample_before_any_signal(self):
        sample_entered, release = threading.Event(), threading.Event()
        network = FakeNetwork(False)
        original = network.sample
        def sample():
            sample_entered.set()
            if not release.wait(2):
                raise AssertionError('fixture sample not released')
            return original()
        network.sample = sample
        processes = FakeProcesses()
        processes.available = [11]
        guard = self.manual_guard(network, processes)
        worker, errors = self.run_thread(guard._step)
        try:
            self.assertTrue(sample_entered.wait(1))
            guard.stop()
        finally:
            release.set()
            worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertFalse(errors)
        self.assertFalse(processes.terminated)
        self.assertFalse(guard.status()['running'])

    def test_target_change_discards_a_previous_generation_sample(self):
        entered, release = threading.Event(), threading.Event()
        network = FakeNetwork(False)
        def sample():
            entered.set()
            if not release.wait(2):
                raise AssertionError('fixture sample not released')
            return {'safe': False, 'reasons': ['tun_down'], 'interfaces': []}
        network.sample = sample
        processes = FakeProcesses()
        processes.available = [12]
        guard = self.manual_guard(network, processes)
        worker, errors = self.run_thread(guard._step)
        try:
            self.assertTrue(entered.wait(1))
            guard.configure('JP', True)
        finally:
            release.set()
            worker.join(2)
        self.assertFalse(errors)
        self.assertFalse(processes.terminated)

    def test_disable_waits_for_signal_critical_section_and_then_stays_disarmed(self):
        signal_entered, release_signal, disabled = threading.Event(), threading.Event(), threading.Event()
        processes = FakeProcesses()
        processes.available = [13]
        original = processes.terminate
        def terminate(identity):
            signal_entered.set()
            if not release_signal.wait(2):
                raise AssertionError('fixture action not released')
            return original(identity)
        processes.terminate = terminate
        guard = self.manual_guard(processes=processes)
        worker, errors = self.run_thread(guard._step)
        disabling = None
        disable_errors = []
        try:
            self.assertTrue(signal_entered.wait(1))
            def disable():
                guard.configure('US', False)
                disabled.set()
            disabling, disable_errors = self.run_thread(disable)
            self.assertFalse(disabled.wait(.05), 'disable cannot return while an earlier signal is in progress')
        finally:
            release_signal.set()
            worker.join(2)
            if disabling:
                disabling.join(2)
        self.assertFalse(errors + disable_errors)
        self.assertTrue(disabled.is_set())
        self.assertEqual(processes.terminated, [13])
        processes.available = [14]
        guard._step()
        self.assertEqual(processes.terminated, [13], 'no new signal after disable returns')

    def test_concurrent_start_creates_one_reader_and_one_worker(self):
        factory_calls = []
        factory_lock = threading.Lock()
        network = FakeNetwork(False)
        def factory():
            with factory_lock:
                factory_calls.append(True)
            return network
        guard = FastProtector(network_factory=factory, process_factory=FakeProcesses, supported=True,
                              telemetry_factory=FakeTelemetry)
        barrier = threading.Barrier(4)
        workers, failures = [], []
        for _ in range(4):
            worker, errors = self.run_thread(lambda: (barrier.wait(2), guard.start(interval_ms=50)))
            workers.append(worker)
            failures.append(errors)
        try:
            for worker in workers:
                worker.join(2)
                self.assertFalse(worker.is_alive())
            self.assertFalse([error for errors in failures for error in errors])
            self.assertEqual(len(factory_calls), 1)
            self.assertTrue(guard._thread.is_alive())
        finally:
            guard.stop()
        self.assertFalse(guard._thread.is_alive())
        self.assertTrue(network.closed)

    def test_observer_start_failure_keeps_network_worker_active_and_file_state_unverified(self):
        class BrokenTelemetry(FakeTelemetry):
            def start(self):
                raise OSError('SECRET-FILE-DETAIL')
        network, processes = FakeNetwork(), FakeProcesses()
        processes.available = [23]
        guard = FastProtector(network_factory=lambda: network, process_factory=lambda: processes,
                              telemetry_factory=BrokenTelemetry, supported=True)
        guard.start(interval_ms=50)
        try:
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline and not processes.terminated:
                time.sleep(.003)
            self.assertEqual(processes.terminated, [23])
            self.assertTrue(guard.status()['running'])
            self.assertIn('telemetry_file_unknown', guard.status()['telemetry']['reason_codes'])
            self.assertFalse(guard.status()['telemetry_backend_available'])
            self.assertNotIn('SECRET', json.dumps(guard.status()))
        finally:
            guard.stop()

    def test_worker_fault_is_visible_and_restart_uses_a_new_reader(self):
        failed = threading.Event()
        callbacks = []
        class BrokenWait(FakeNetwork):
            def wait(self, timeout):
                raise RuntimeError('SECRET-WORKER-DETAIL')
        broken, healthy = BrokenWait(), FakeNetwork()
        factories = iter((broken, healthy))
        def callback(value):
            callbacks.append(value)
            if value.get('status') == 'error':
                failed.set()
        guard = FastProtector(network_factory=lambda: next(factories), process_factory=FakeProcesses,
                              supported=True, callback=callback, telemetry_factory=FakeTelemetry)
        guard.start(interval_ms=50)
        try:
            self.assertTrue(failed.wait(1))
            self.assertFalse(guard.status()['running'])
            self.assertEqual(guard.status()['status'], 'error')
            self.assertNotIn('SECRET-WORKER-DETAIL', json.dumps(guard.status()))
            self.assertTrue(broken.closed)
            guard._thread.join(1)
            guard.start(interval_ms=50)
            guard.observe_pulse(dict(target='US', ok=True, loc='US', colo='LAX', utun_up=True), time.monotonic())
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline and guard.status()['status'] != 'safe':
                time.sleep(.002)
            self.assertEqual(guard.status()['status'], 'safe')
            self.assertTrue(guard.status()['running'])
        finally:
            guard.stop()
        self.assertTrue(healthy.closed)



class KernelRouteTests(unittest.TestCase):
    def routes(self, *rows):
        return [(ipaddress.ip_network(net), iface, flags) for net, iface, flags in rows]
    def test_split_routes_tunnel_and_scoped_backup_are_safe(self):
        routes = self.routes(('0.0.0.0/0', 'en0', 1 | 0x1000000), ('0.0.0.0/1', 'utun4', 1), ('128.0.0.0/1', 'utun4', 1))
        self.assertTrue(mac_guard.evaluate_network(routes, {'utun4': 1}, False)['safe'])
    def test_dns_host_routes_cannot_hide_a_physical_default(self):
        routes = self.routes(('0.0.0.0/0', 'en0', 1), ('1.1.1.1/32', 'utun4', 1), ('8.8.8.8/32', 'utun4', 1))
        self.assertFalse(mac_guard.evaluate_network(routes, {'utun4': 1, 'en0': 1}, False)['safe'])

    def test_lower_tunnel_half_without_upper_coverage_cannot_pass(self):
        for rows in ((('0.0.0.0/1', 'utun4', 1),),
                     (('0.0.0.0/1', 'utun4', 1), ('0.0.0.0/0', 'en0', 1))):
            with self.subTest(rows=rows):
                self.assertFalse(mac_guard.evaluate_network(self.routes(*rows), {'utun4': 1, 'en0': 1}, False)['safe'])

    def test_more_specific_physical_route_is_unsafe_even_with_utun(self):
        routes = self.routes(('0.0.0.0/0', 'utun4', 1), ('1.1.1.1/32', 'en0', 1))
        result = mac_guard.evaluate_network(routes, {'utun4': 1, 'en0': 1}, False)
        self.assertFalse(result['safe'])
        self.assertIn('ipv4_bypass', result['reasons'])
    def test_down_interface_and_missing_routes_cannot_pass(self):
        routes = self.routes(('0.0.0.0/0', 'utun4', 1))
        self.assertIn('tun_down', mac_guard.evaluate_network(routes, {'utun4': 0}, False)['reasons'])
        self.assertIn('ipv4_route_missing', mac_guard.evaluate_network([], {}, False)['reasons'])
    def test_ipv6_leak_and_reject_route(self):
        routes = self.routes(('0.0.0.0/0', 'utun4', 1), ('::/0', 'en0', 1))
        self.assertIn('ipv6_bypass', mac_guard.evaluate_network(routes, {'utun4': 1, 'en0': 1}, True)['reasons'])
        self.assertTrue(mac_guard.evaluate_network(routes, {'utun4': 1}, False)['safe'])
        self.assertFalse(mac_guard.evaluate_network(self.routes(('0.0.0.0/0', 'utun4', 1 | 8)), {'utun4': 1}, False)['safe'])
    def test_ipv6_dns_only_tunnel_cannot_hide_a_physical_global_default(self):
        for narrow in ('2606:4700:4700::1111/128', '2606:4700::/32', '2606::/16'):
            with self.subTest(narrow=narrow):
                routes = self.routes(('0.0.0.0/0', 'utun4', 1), ('::/0', 'en0', 1), (narrow, 'utun4', 1))
                result = mac_guard.evaluate_network(routes, {'utun4': 1, 'en0': 1}, True)
                self.assertFalse(result['safe'])
                self.assertIn('ipv6_bypass', result['reasons'])
                self.assertEqual(result['ipv6_state'], 'bypass')

    def test_ipv6_general_global_route_or_default_tunnel_is_safe(self):
        for broad in ('2000::/3', '::/0'):
            with self.subTest(broad=broad):
                rows = [('0.0.0.0/0', 'utun4', 1), (broad, 'utun4', 1)]
                if broad == '2000::/3':
                    rows.append(('::/0', 'en0', 1))
                result = mac_guard.evaluate_network(self.routes(*rows), {'utun4': 1, 'en0': 1}, True)
                self.assertTrue(result['safe'])
                self.assertNotIn('ipv6_bypass', result['reasons'])
                self.assertEqual(result['ipv6_state'], 'tunneled')

    def test_no_ipv6_route_or_explicit_drop_is_not_a_proven_ipv6_bypass(self):
        for ipv6 in ([], [('::/0', 'en0', 1 | 8)], [('2000::/3', 'en0', 1 | 0x1000)]):
            with self.subTest(ipv6=ipv6):
                rows = [('0.0.0.0/0', 'utun4', 1)] + ipv6
                result = mac_guard.evaluate_network(self.routes(*rows), {'utun4': 1, 'en0': 1}, True)
                self.assertTrue(result['safe'], 'IPv4 remains protected and there is no usable IPv6 exit in this fixture')
                self.assertNotIn('ipv6_bypass', result['reasons'])
                self.assertEqual(result['ipv6_state'], 'blocked' if ipv6 else 'no_general_route')

    def test_rejecting_only_ipv6_dns_host_cannot_hide_physical_default(self):
        routes = self.routes(('0.0.0.0/0', 'utun4', 1), ('::/0', 'en0', 1),
                             ('2606:4700:4700::1111/128', 'utun4', 1 | 8))
        result = mac_guard.evaluate_network(routes, {'utun4': 1, 'en0': 1}, True)
        self.assertFalse(result['safe'])
        self.assertIn('ipv6_bypass', result['reasons'])

    def route_message(self, network='0.0.0.0/0', kind=2, flags=1):
        header = mac_guard.RouteHeader()
        header.version, header.kind, header.index, header.flags, header.addrs = 5, kind, 4, flags, 5
        network = ipaddress.ip_network(network)
        if network.version == 4:
            destination = bytes([16, 2, 0, 0]) + network.network_address.packed + bytes(8)
            mask = bytes([16, 0, 0, 0]) + network.netmask.packed + bytes(8)
        else:
            destination = bytes([28, 30, 0, 0]) + bytes(4) + network.network_address.packed + bytes(4)
            mask = bytes([28, 0, 0, 0]) + bytes(4) + network.netmask.packed + bytes(4)
        header.length = ctypes.sizeof(header) + len(destination) + len(mask)
        return bytes(header) + destination + mask

    def test_route_event_noise_does_not_trigger_reverification(self):
        name = lambda index: 'utun4'
        for message in (self.route_message(kind=4),
                        self.route_message(flags=1 | 0x1000000),
                        self.route_message('1.1.1.1/32', flags=1 | 0x20000),
                        self.route_message('203.0.113.1/32', kind=1)):
            self.assertEqual(mac_guard.route_event_flags(message, name), (False, False))

    def test_effective_tunnel_route_removal_and_upper_half_are_critical(self):
        name = lambda index: 'utun4'
        for network in ('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1'):
            for kind in (2, 3):
                with self.subTest(network=network, kind=kind):
                    self.assertEqual(mac_guard.route_event_flags(self.route_message(network, kind), name), (True, True))
        self.assertEqual(mac_guard.route_event_flags(self.route_message(kind=1), name), (True, False))
        self.assertEqual(mac_guard.route_event_flags(self.route_message(kind=1), lambda index: 'en0'), (True, False))

    def test_global_ipv6_route_removal_is_critical_and_scoped_backup_is_not(self):
        name = lambda index: 'utun4'
        for kind in (2, 3):
            message = self.route_message('2000::/3', kind)
            self.assertEqual(mac_guard.route_event_flags(message, name), (True, True))
        scoped = self.route_message('2000::/3', kind=2, flags=1 | 0x1000000)
        self.assertEqual(mac_guard.route_event_flags(scoped, name), (False, False))

    def test_interface_event_header_is_parsed_separately_from_route_header(self):
        def message(kind, flags):
            raw = bytearray(16)
            struct.pack_into('=HBBIIH', raw, 0, len(raw), 5, kind, 0, flags, 4)
            return bytes(raw)
        name = lambda index: 'utun4'
        self.assertEqual(mac_guard.route_event_flags(message(0xE, 0), name), (True, True))
        self.assertEqual(mac_guard.route_event_flags(message(0xE, 1), name), (True, False))
        self.assertEqual(mac_guard.route_event_flags(message(0xD, 1), name), (True, True))
        self.assertEqual(mac_guard.route_event_flags(message(0xE, 0), lambda index: 'lo0'), (False, False))
        self.assertEqual(mac_guard.route_event_flags(message(0xE, 0), lambda index: 'en0'), (True, False))

    def test_malformed_route_events_do_not_raise_or_claim_a_change(self):
        valid = self.route_message()
        for raw in (b'', valid[:3], valid[:-1], b'\0\0\5\2'):
            self.assertEqual(mac_guard.route_event_flags(raw, lambda index: 'utun4'), (False, False))

    def test_binary_route_parser_and_truncation(self):
        header = mac_guard.RouteHeader()
        header.version, header.kind, header.index, header.flags, header.addrs = 5, 4, 4, 1, 5
        destination = bytes([16, 2, 0, 0, 0, 0, 0, 0]) + bytes(8)
        mask = bytes(4)  # /0 netmask sa_len == 0 still occupies four bytes
        header.length = ctypes.sizeof(header) + len(destination) + len(mask)
        data = bytes(header) + destination + mask
        routes = mac_guard.parse_routes(data, lambda index: 'utun4')
        self.assertEqual(str(routes[0][0]), '0.0.0.0/0')
        self.assertEqual(routes[0][1], 'utun4')
        with self.assertRaises(ValueError):
            mac_guard.parse_routes(data[:-1], lambda index: 'utun4')


@unittest.skipIf(sys.platform == 'win32', 'Darwin process identity contract')
class ProcessIdentityTests(unittest.TestCase):
    def provider(self):
        provider = object.__new__(mac_guard.ClaudeProcesses)
        provider.uid = os.getuid()
        return provider
    def test_pid_reuse_different_uid_and_path_cannot_be_killed(self):
        identity = mac_guard.ProcessIdentity(12345, os.getuid(), 100, 1, '/Applications/Claude.app/Contents/MacOS/Claude')
        for other in (None, mac_guard.ProcessIdentity(12345, os.getuid(), 101, 1, identity.path),
                      mac_guard.ProcessIdentity(12345, os.getuid(), 100, 1, '/usr/bin/python3')):
            provider = self.provider()
            provider.identity = Mock(return_value=other)
            with patch.object(mac_guard.os, 'kill') as kill:
                self.assertEqual(provider.terminate(identity), 'rejected')
                kill.assert_not_called()
        provider = self.provider()
        provider.identity = Mock(return_value=identity)
        foreign = mac_guard.ProcessIdentity(12345, os.getuid() + 1, 100, 1, identity.path)
        with patch.object(mac_guard.os, 'kill') as kill:
            self.assertEqual(provider.terminate(foreign), 'rejected')
            kill.assert_not_called()
    def test_system_self_and_invalid_pids_are_rejected_before_identity_reads(self):
        provider = self.provider()
        provider.identity = Mock()
        with patch.object(mac_guard.os, 'kill') as kill:
            for pid in (-10, 0, 1, os.getpid()):
                identity = mac_guard.ProcessIdentity(pid, os.getuid(), 100, 1, '/Applications/Claude.app/Contents/MacOS/Claude')
                self.assertEqual(provider.terminate(identity), 'rejected')
            provider.identity.assert_not_called()
            kill.assert_not_called()

    def test_only_verified_claude_identity_gets_single_pid_sigkill(self):
        provider = self.provider()
        identity = mac_guard.ProcessIdentity(12345, os.getuid(), 100, 1, '/Applications/Claude.app/Contents/MacOS/Claude')
        provider.identity = lambda pid: identity
        with patch.object(mac_guard.os, 'kill') as kill:
            self.assertEqual(provider.terminate(identity), 'terminated')
            kill.assert_called_once_with(12345, signal.SIGKILL)
        with patch.object(mac_guard.os, 'kill', side_effect=PermissionError):
            self.assertEqual(provider.terminate(identity), 'denied')
    def test_broad_names_prefix_paths_cli_and_other_apps_are_rejected(self):
        provider = self.provider()
        provider._allowed_roots = lambda: [Path('/Applications/Claude.app')]
        for path in ('/tmp/Claude', '/usr/local/bin/claude', '/Applications/Claude.app.evil/Contents/MacOS/Claude',
                     '/Applications/Safari.app/Contents/MacOS/Claude', '/Applications/Claude.app/Contents/Resources/node'):
            self.assertFalse(provider.allowed_path(path), path)
        self.assertTrue(provider.allowed_path('/Applications/Claude.app/Contents/MacOS/Claude'))
        self.assertTrue(provider.allowed_path('/Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/Contents/MacOS/Claude Helper (Renderer)'))

    def test_crashpad_scope_is_canonical_and_confined_to_verified_claude_bundle(self):
        provider = self.provider()
        provider._allowed_roots = lambda: [Path('/Applications/Claude.app')]
        canonical = '/Applications/Claude.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Helpers/chrome_crashpad_handler'
        self.assertTrue(provider.allowed_path(canonical))
        for path in (canonical.replace('/Claude.app/', '/Google Chrome.app/'),
                     canonical.replace('/Versions/A/', '/'),
                     canonical + '.other', '/tmp/chrome_crashpad_handler'):
            self.assertFalse(provider.allowed_path(path))

    def test_crashpad_candidate_name_is_only_a_prefilter_for_validated_identity(self):
        provider = self.provider()
        provider._allowed_roots = lambda: [Path('/Applications/Claude.app')]
        accepted = mac_guard.ProcessIdentity(400011, os.getuid(), 1, 1,
            '/Applications/Claude.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Helpers/chrome_crashpad_handler')
        class Lib:
            def proc_listpids(self, mode, uid, values, size):
                if values is not None:
                    values[0], values[1] = 400011, 400012
                return 8
            def proc_name(self, pid, name, size):
                name.value = b'chrome_crashpad'  # also tolerates a shortened comm field
                return len(name.value)
        provider.lib = Lib()
        provider.identity = Mock(side_effect=lambda pid: accepted if pid == 400011 else None)
        self.assertEqual(provider.candidates(), [accepted])
        self.assertEqual(provider.identity.call_count, 2)


if __name__ == '__main__':
    unittest.main()

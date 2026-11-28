"""Monitor ownership of the background connection worker; no native observation."""
import http.client
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server


def worker():
    result = Mock()
    result.status.return_value = dict(running=True, state='not_running', event_seq=7, action_reason_codes=[],
                                     evidence={}, history={})
    return result


class TrafficMonitorTests(unittest.TestCase):
    def test_monitor_owns_worker_start_stop_and_status_never_samples(self):
        traffic = worker()
        traffic.sample.side_effect = AssertionError('status must not observe sockets')
        controller = server.MonitorController(traffic=traffic)
        with patch.object(server, 'run_pulse', return_value={}):
            controller.start('US', 15)
            self.assertTrue(controller.status()['running'])
            self.assertEqual(controller.status()['traffic']['event_seq'], 7)
            controller.start('US', 15)  # worker.start owns idempotence, never a second monitor thread
            controller.stop()
        self.assertEqual(traffic.start.call_count, 2)
        traffic.stop.assert_called_once()
        traffic.sample.assert_not_called()
        self.assertFalse(controller.status()['running'])

    def test_slow_public_probe_does_not_block_connection_cache_status(self):
        traffic = worker()
        entered, release = threading.Event(), threading.Event()
        def probe(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(2))
        controller = server.MonitorController(traffic=traffic)
        with patch.object(server, 'run_pulse', side_effect=probe):
            controller.start()
            try:
                self.assertTrue(entered.wait(1))
                self.assertEqual(controller.status()['traffic']['state'], 'not_running')
                traffic.sample.assert_not_called()
            finally:
                release.set()
                controller.stop()

    def test_wake_invalidates_connection_evidence_without_synchronous_sampling(self):
        traffic = worker()
        controller = server.MonitorController(traffic=traffic)
        controller._running = True
        controller.on_wake()
        traffic.invalidate.assert_called_once()
        traffic.sample.assert_not_called()

    def test_enabling_actions_discards_old_observational_latch_before_arming(self):
        traffic, guard, calls = worker(), Mock(), []
        guard.status.return_value = dict(enabled=False, supported=True)
        traffic.invalidate.side_effect = lambda **kwargs: calls.append(('invalidate', kwargs))
        guard.configure.side_effect = lambda *args: calls.append(('arm',))
        controller = server.MonitorController(protection=guard, traffic=traffic)
        with patch.object(server, 'get_prefs', return_value=server.PREFS_DEFAULTS):
            controller.configure('US', 30)
        self.assertEqual(calls, [('invalidate', {'clear_actions': True}), ('arm',)])
        traffic.acknowledge.assert_not_called()

    def test_traffic_failure_does_not_disable_network_protection_or_expose_exception(self):
        traffic, guard = worker(), Mock()
        guard.status.return_value = dict(enabled=True, running=True)
        traffic.start.side_effect = OSError('PRIVATE-FD-DETAIL')
        controller = server.MonitorController(protection=guard, traffic=traffic)
        with patch.object(server, 'run_pulse', return_value={}):
            controller.start()
            try:
                self.assertTrue(controller.status()['running'])
                self.assertIn('覆盖未知', controller.status()['traffic_error'])
                self.assertNotIn('PRIVATE', json.dumps(controller.status()))
                guard.start.assert_called_once()
            finally:
                controller.stop()
        guard.stop.assert_called_once()

    def test_protection_start_failure_stops_the_connection_worker(self):
        traffic, guard = worker(), Mock()
        guard.start.side_effect = RuntimeError('private failure')
        controller = server.MonitorController(protection=guard, traffic=traffic)
        with self.assertRaises(RuntimeError):
            controller.start()
        traffic.stop.assert_called_once()
        self.assertFalse(controller.status()['running'])

    def test_background_version_metadata_runs_without_a_full_scan_and_cannot_suppress_pulse(self):
        version = Mock()
        entered = threading.Event()
        def sample():
            entered.set()
            raise OSError('private version error')
        version.sample.side_effect = sample
        controller = server.MonitorController(version_observer=version)
        with patch.object(server, 'run_pulse', return_value={}) as pulse:
            controller.start()
            self.assertTrue(entered.wait(1))
            controller.stop()
        version.sample.assert_called()
        pulse.assert_called()

    def test_traffic_endpoint_reads_cache_only(self):
        traffic = worker()
        httpd = server.ThreadingHTTPServer(('127.0.0.1', 0), server.RegionGuardHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.object(server, 'CLAUDE_TRAFFIC', traffic):
                conn = http.client.HTTPConnection('127.0.0.1', httpd.server_port, timeout=2)
                try:
                    conn.request('GET', '/api/traffic/status')
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(response.read())['event_seq'], 7)
                finally:
                    conn.close()
                traffic.sample.assert_not_called()
                traffic.status.assert_called_once()
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(2)

    def test_scan_check_distinguishes_public_route_risk_from_controller_direct(self):
        group = dict(id='ClaudeDesktop', socket_count=1, matched_count=1,
                     transport_counts={'direct': 1}, route_counts={'physical_bypass': 0},
                     private_path='PRIVATE-APP', destination_ip='PRIVATE-ADDRESS')
        frame = dict(state='observed', groups=[group])
        row = server.traffic_coverage_check(frame)
        self.assertEqual((row['status'], row['severity']), ('WARN', 'low'))
        self.assertNotIn('PRIVATE', json.dumps(row))
        group['route_counts']['physical_bypass'] = 1
        row = server.traffic_coverage_check(frame)
        self.assertEqual((row['status'], row['severity']), ('WARN', 'high'))
        self.assertIn('物理路由例外', row['observed'])
        self.assertNotIn('PRIVATE', json.dumps(row))


if __name__ == '__main__':
    unittest.main()

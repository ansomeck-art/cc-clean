"""Shutdown orchestration gates: no real processes, native UI, network, or user files."""
import signal
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server
import tray_app


class ProtectionShutdownIntegrationTests(unittest.TestCase):
    def fixtures(self):
        calls = []
        guard = Mock()
        guard.stop.side_effect = lambda: calls.append('disarm')
        monitor = Mock()
        monitor.protection = guard
        monitor.stop.side_effect = lambda: calls.append('stop_monitor')
        return calls, monitor

    def test_file_risk_recovery_requests_an_immediate_new_public_probe(self):
        import collections
        import tempfile
        protector = Mock()
        protector.status.return_value = dict(enabled=True, running=True, status='blocked',
                                              reason_codes=['telemetry_pending'])
        controller = server.MonitorController(protection=protector)
        controller._running = True
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(server, 'PROTECTION_LOG_PATH', str(Path(temporary) / 'protection.jsonl')), \
             patch.object(server, 'PROTECTION_HISTORY', collections.deque(maxlen=100)):
            controller._on_protection_event(dict(local_safe=True, reason_codes=['telemetry_pending']))
        self.assertTrue(controller._reconfigure.is_set())

    def test_delayed_action_event_notifies_even_if_current_state_already_recovered(self):
        import collections
        import json
        import tempfile
        current = dict(enabled=True, supported=True, running=True, status='safe', event_seq=2,
                       poll_interval_ms=100, reason_codes=[], reasons=[], terminated_total=1,
                       last_action={'terminated': 1, 'event_seq': 1})
        historical = {**current, 'status': 'blocked', 'event_seq': 1,
                      'reason_codes': ['tun_down'], 'reasons': ['TUN 接口离线']}
        protector = Mock()
        protector.status.side_effect = lambda: dict(current)
        controller = server.MonitorController(protection=protector)
        controller._running = True
        delivered = []
        controller.register_listener(delivered.append)
        pulse = dict(target='US', timestamp='fixture', ok=True, ip='203.0.113.1', loc='US', colo='LAX',
                     utun_up=True, latency_ms=10, anomaly=False, anomaly_reasons=[])
        gate = tray_app.NotificationGate()
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(server, 'PROTECTION_LOG_PATH', str(Path(temp) / 'protection.jsonl')), \
             patch.object(server, 'PROTECTION_HISTORY', collections.deque(maxlen=100)), \
             patch.object(server, 'PULSE_HISTORY', collections.deque([pulse], maxlen=500)):
            controller._on_protection_event(historical)
            event = delivered[-1]
            self.assertEqual(event['protection']['status'], 'safe')
            self.assertEqual(event['protection']['event_seq'], 2)
            self.assertEqual(event['protection_event']['status'], 'blocked')
            self.assertEqual(event['protection_event']['last_action']['event_seq'], 1)
            self.assertEqual(tray_app.status_view(event)['state'], 'green', 'UI must show the current recovered state')
            message = gate.consume(event, now=0)
            self.assertIsNotNone(message)
            self.assertIn('1 个', message[1])
            self.assertIn('强退指令', message[1])
            self.assertIsNone(gate.consume(event, now=1), 'historical action must notify only once')
            stored = json.loads(Path(server.PROTECTION_LOG_PATH).read_text().splitlines()[0])
            self.assertEqual(stored['status'], 'blocked')
            self.assertEqual(stored['last_action']['event_seq'], 1)
            controller._on_protection_event(dict(current))
            recovered = delivered[-1]
            self.assertEqual(tray_app.status_view(recovered)['state'], 'green')
            self.assertIn('不会自动重启', gate.consume(recovered, now=2)[1])

    def test_delayed_old_action_does_not_rearm_or_redden_a_stopped_monitor(self):
        import collections
        import tempfile
        protector = Mock()
        protector.status.return_value = dict(enabled=True, running=False, status='paused', event_seq=3,
                                            reason_codes=[], reasons=[], poll_interval_ms=100)
        controller = server.MonitorController(protection=protector)
        historical = dict(enabled=True, running=True, status='blocked', event_seq=2,
                          reason_codes=['tun_down'], reasons=['TUN 接口离线'],
                          last_action={'terminated': 1, 'event_seq': 2})
        delivered = []
        controller.register_listener(delivered.append)
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(server, 'PROTECTION_LOG_PATH', str(Path(temp) / 'protection.jsonl')), \
             patch.object(server, 'PROTECTION_HISTORY', collections.deque(maxlen=100)):
            controller._on_protection_event(historical)
        self.assertFalse(delivered[-1]['running'])
        self.assertEqual(tray_app.status_view(delivered[-1])['state'], 'gray')
        self.assertIsNone(tray_app.NotificationGate().consume(delivered[-1], now=0))

    def test_tray_quit_disarms_before_cancelled_probe_can_report_failure(self):
        calls, monitor = self.fixtures()
        runtime = tray_app.TrayRuntime(silent=True)
        runtime.httpd = Mock()
        runtime.http_thread = Mock()
        runtime.http_thread.is_alive.return_value = False
        with patch.object(server, 'MONITOR', monitor), \
             patch.object(server, 'shutdown_observers', side_effect=lambda: calls.append('cancel_probes')):
            runtime.close()
        self.assertEqual(calls, ['disarm', 'cancel_probes', 'stop_monitor'])
        runtime.httpd.server_close.assert_called_once()
        runtime.close()
        self.assertEqual(calls, ['disarm', 'cancel_probes', 'stop_monitor'], 'close must be idempotent')

    def test_cli_quit_disarms_before_cancelled_probe_can_report_failure(self):
        calls, monitor = self.fixtures()
        httpd = Mock()
        httpd.serve_forever.side_effect = KeyboardInterrupt
        with patch.object(server, 'MONITOR', monitor), \
             patch.object(server, 'shutdown_observers', side_effect=lambda: calls.append('cancel_probes')), \
             patch.object(server, 'SHUTDOWN_EVENT', threading.Event()), \
             patch.object(server, 'create_http_server', return_value=(httpd, 8765)), \
             patch.object(sys, 'argv', ['server.py', '--no-open']), patch('builtins.print'):
            server.main()
        self.assertEqual(calls, ['disarm', 'cancel_probes', 'stop_monitor'])
        httpd.server_close.assert_called_once()

"""Milestone 3 callback, preference, scheduling and port gates."""
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server
import test_foundation


class PreferencesHTTPTests(test_foundation.HTTPGuardTests):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.pref_patch = patch.object(server, 'PREFS_PATH', str(Path(self.temp.name) / 'prefs.json'))
        self.state_patch = patch.object(server, '_PREFS', dict(server.PREFS_DEFAULTS))
        self.monitor_patch = patch.object(server, 'MONITOR', server.MonitorController())
        self.pref_patch.start()
        self.state_patch.start()
        self.monitor_patch.start()
        super().setUp()

    def tearDown(self):
        super().tearDown()
        self.monitor_patch.stop()
        self.state_patch.stop()
        self.pref_patch.stop()
        self.temp.cleanup()

    def test_prefs_roundtrip_and_private_file(self):
        headers = {'X-Region-Guard': '1', 'Content-Type': 'application/json'}
        status, data = self.request('POST', '/api/prefs', headers, json.dumps({'target': 'JP', 'interval_sec': 15, 'notify_enabled': False}))
        self.assertEqual(status, 200)
        prefs = json.loads(data)
        self.assertEqual(prefs['target'], 'JP')
        self.assertEqual(prefs['run_mode'], 'cli')
        self.assertFalse(prefs['notify_enabled'])
        self.assertEqual(server.MONITOR.status()['target'], 'JP')
        self.assertEqual(os.stat(server.PREFS_PATH).st_mode & 0o777, 0o600)
        self.assertNotIn('run_mode', json.loads(Path(server.PREFS_PATH).read_text()))
        self.assertEqual(json.loads(self.request(path='/api/prefs')[1]), prefs)
        self.assertEqual(server._load_prefs(), prefs)

    def test_prefs_invalid_requests_do_not_write(self):
        headers = {'X-Region-Guard': '1'}
        for value in ({'target': 'CN'}, {'interval_sec': True}, {'notify_enabled': 'yes'}, {'run_mode': 'menubar'}, {'interval_sec': 14}):
            self.assertEqual(self.request('POST', '/api/prefs', headers, json.dumps(value))[0], 400)
        self.assertEqual(self.request('POST', '/api/prefs', headers, '{broken')[0], 400)
        self.assertFalse(Path(server.PREFS_PATH).exists())

    def test_protection_preferences_http_validate_and_persist(self):
        headers = {'X-Region-Guard': '1', 'Content-Type': 'application/json'}
        status, data = self.request('POST', '/api/prefs', headers,
                                    json.dumps({'protection_enabled': False, 'local_interval_ms': 50}))
        self.assertEqual(status, 200)
        prefs = json.loads(data)
        self.assertFalse(prefs['protection_enabled'])
        self.assertEqual(prefs['local_interval_ms'], 50)
        stored = Path(server.PREFS_PATH).read_bytes()
        for value in ({'local_interval_ms': 1}, {'local_interval_ms': True}, {'protection_enabled': 'yes'}):
            self.assertEqual(self.request('POST', '/api/prefs', headers, json.dumps(value))[0], 400)
            self.assertEqual(Path(server.PREFS_PATH).read_bytes(), stored)

    def test_monitor_start_failure_is_a_bounded_service_unavailable_response(self):
        headers = {'X-Region-Guard': '1'}
        with patch.object(server.MONITOR, 'start', side_effect=RuntimeError('SECRET-START-DETAIL')):
            status, data = self.request('POST', '/api/monitor/start', headers, json.dumps({'target': 'US', 'interval': 15}))
        self.assertEqual(status, 503)
        self.assertNotIn('SECRET', data.decode())



class MonitorTests(unittest.TestCase):
    def test_listener_start_pulse_stop_and_exception_isolation(self):
        controller = server.MonitorController()
        events = []
        controller.register_listener(lambda snapshot: 1 / 0)
        remove = controller.register_listener(lambda snapshot: events.append(snapshot))
        with patch.object(server, 'run_pulse', return_value={}) as pulse:
            controller.start('US', 15)
            controller.configure('JP', 60)
            controller.stop()
        self.assertTrue(events[0]['running'])
        self.assertFalse(events[-1]['running'])
        self.assertEqual(events[-1]['target'], 'JP')
        remove()
        count = len(events)
        controller.publish()
        self.assertEqual(len(events), count)
        self.assertGreaterEqual(pulse.call_count, 1)

    def test_shutdown_cancels_only_our_commands_and_blocks_new_ones(self):
        started, terminated = threading.Event(), threading.Event()
        class Command:
            returncode = 0
            def communicate(self, timeout=None):
                started.set()
                if not terminated.wait(2):
                    raise AssertionError("command was not cancelled")
                return b"", b""
            def terminate(self):
                terminated.set()
        command = Command()
        with patch.object(server, 'SHUTDOWN_EVENT', threading.Event()), \
             patch.object(server, '_ACTIVE_COMMANDS', set()), \
             patch.object(server.subprocess, 'Popen', return_value=command) as popen:
            worker = threading.Thread(target=server.run_cmd, args=(['fixture-command'],))
            worker.start()
            self.assertTrue(started.wait(1))
            server.shutdown_observers()
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(server.run_cmd(['another-command'])[0], 124)
            self.assertEqual(popen.call_count, 1)
            self.assertFalse(server._ACTIVE_COMMANDS)

    def test_controller_protection_start_configure_wake_and_stop(self):
        from unittest.mock import Mock
        protection = Mock()
        protection.status.return_value = {"enabled": True, "running": True}
        controller = server.MonitorController(protection=protection)
        with patch.object(server, 'run_pulse', return_value={}):
            controller.start('US', 15)
            controller.configure('JP', 60)
            controller.on_wake()
            self.assertIsNotNone(controller.status()['protection'])
            controller.stop()
        protection.start.assert_called_once_with('US', server.PREFS_DEFAULTS['protection_enabled'], 100, 15)
        protection.configure.assert_called_with('JP', server.PREFS_DEFAULTS['protection_enabled'], 100, 60)
        protection.on_wake.assert_called_once()
        protection.stop.assert_called_once()

    def test_existing_network_worker_is_stopped_if_protector_restart_fails(self):
        from unittest.mock import Mock
        protector = Mock()
        protector.status.return_value = {'enabled': True, 'running': True}
        protector.start.side_effect = [None, RuntimeError('fixture unavailable')]
        controller = server.MonitorController(protection=protector)
        entered = threading.Event()
        def pulse(*args, **kwargs):
            entered.set()
            controller._stop_event.wait(2)
            return {}
        with patch.object(server, 'run_pulse', side_effect=pulse):
            try:
                controller.start('US', 15)
                self.assertTrue(entered.wait(1))
                worker = controller._thread
                with self.assertRaises(RuntimeError):
                    controller.start('US', 30)
                self.assertFalse(controller.status()['running'])
                self.assertTrue(controller._stop_event.is_set(), 'failed start must also stop the existing network loop')
                worker.join(1)
                self.assertFalse(worker.is_alive())
                protector.stop.assert_called_once()
            finally:
                controller.stop()

    def test_pulse_uses_fresh_native_snapshot_and_forwards_probe_start_time(self):
        from unittest.mock import Mock
        protector = Mock()
        protector.status.return_value = dict(enabled=True, running=True, local_safe=True,
                                             last_check_age_ms=10, interfaces=['utun7'])
        controller = server.MonitorController(protection=protector)
        with tempfile.TemporaryDirectory() as temp, patch.object(server, 'MONITOR', controller), \
             patch.object(server, 'IS_MACOS', True), \
             patch.object(server, 'PULSE_LOG_PATH', str(Path(temp) / 'pulse.jsonl')), \
             patch.object(server, 'PULSE_HISTORY', server.collections.deque(maxlen=500)), \
             patch.object(server, 'BASELINE_IP', None), \
             patch.object(server.time, 'monotonic', return_value=321.5), \
             patch.object(server, '_trace_domain', return_value={'ok': True, 'ip': '203.0.113.1', 'loc': 'US', 'colo': 'LAX'}), \
             patch.object(server, '_check_tun_cross_platform') as slow_tun:
            result = server.run_pulse('US')
            self.assertTrue(result['event']['utun_up'])
            self.assertEqual(result['event']['utun_ips'], ['utun7'])
            slow_tun.assert_not_called()
            protector.observe_pulse.assert_called_once_with(result['event'], 321.5)

    def test_enabling_protection_wakes_remote_probe_once_not_on_unrelated_preferences(self):
        from unittest.mock import Mock
        state = {'enabled': False, 'supported': True, 'running': True}
        protector = Mock()
        protector.status.side_effect = lambda: dict(state)
        protector.configure.side_effect = lambda target, enabled, interval_ms, remote_interval: state.update(enabled=enabled and state['supported'])
        controller = server.MonitorController(protection=protector)
        controller._running = True
        with patch.object(server, '_PREFS', {**server.PREFS_DEFAULTS, 'protection_enabled': True}):
            controller.configure('US', 30, emit=False)
            self.assertTrue(controller._reconfigure.is_set(), 'enabling strict mode needs immediate fresh remote verification')
            controller._reconfigure.clear()
            controller.configure('US', 30, emit=False)
            self.assertFalse(controller._reconfigure.is_set(), 'unchanged enabled state must not create an extra Internet request')
            state.update(enabled=False, supported=False)
            controller.configure('US', 30, emit=False)
            self.assertFalse(controller._reconfigure.is_set(), 'unsupported platforms must not pretend to arm protection')

    def test_protection_preferences_validate_and_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(server, 'PREFS_PATH', str(Path(temp) / 'prefs.json')), \
             patch.object(server, '_PREFS', dict(server.PREFS_DEFAULTS)), \
             patch.object(server, 'MONITOR', server.MonitorController()):
            result = server.update_prefs({'protection_enabled': False, 'local_interval_ms': 50})
            self.assertFalse(result['protection_enabled'])
            self.assertEqual(result['local_interval_ms'], 50)
            self.assertEqual(server._load_prefs()['local_interval_ms'], 50)
            for value in ({'local_interval_ms': True}, {'local_interval_ms': 1}, {'protection_enabled': 'true'}):
                with self.assertRaises(ValueError):
                    server.update_prefs(value)

    def test_dual_clock_wake_logic(self):
        self.assertTrue(server._wake_gap(40, 30, 30))
        self.assertTrue(server._wake_gap(80, 80, 30))
        self.assertFalse(server._wake_gap(30, 30, 30))
        self.assertFalse(server._wake_gap(-10, 30, 30))

    def test_wake_followup_and_stop_use_event_wait(self):
        controller = server.MonitorController()
        class Event:
            def __init__(self):
                self.stopped = False
                self.waits = []
            def is_set(self):
                return self.stopped
            def wait(self, seconds):
                self.waits.append(seconds)
                return False
        event = Event()
        calls = []
        def pulse(target, wake_detected):
            calls.append(wake_detected)
            if len(calls) == 3:
                event.stopped = True
        with patch.object(server.time, 'time', side_effect=[0, 0, 0, 50, 50]), \
             patch.object(server.time, 'monotonic', side_effect=[0, 0, 0, 30, 30]), \
             patch.object(controller._reconfigure, 'wait'), patch.object(server, 'run_pulse', side_effect=pulse):
            controller._loop(event)
        self.assertEqual(calls, [False, True, False])
        self.assertIn(2.0, event.waits)

    def test_manual_pulse_notifies_and_wake_alone_is_not_anomaly(self):
        controller = server.MonitorController()
        events = []
        controller.register_listener(events.append)
        with tempfile.TemporaryDirectory() as temp, patch.object(server, 'MONITOR', controller), \
             patch.object(server, 'PULSE_LOG_PATH', str(Path(temp) / 'pulse.jsonl')), \
             patch.object(server, 'PULSE_HISTORY', server.collections.deque(maxlen=500)), \
             patch.object(server, 'BASELINE_IP', None), \
             patch.object(server, '_trace_domain', return_value={'ok': True, 'ip': '203.0.113.1', 'loc': 'US', 'colo': 'LAX'}), \
             patch.object(server, '_check_tun_cross_platform', return_value=(True, ['utun4'], [], [])):
            result = server.run_pulse('US', wake_detected=True)
            self.assertFalse(result['event']['anomaly'])
            self.assertTrue(result['event']['wake_detected'])
            self.assertEqual(len(events), 1)
            self.assertEqual(os.stat(server.PULSE_LOG_PATH).st_mode & 0o777, 0o600)

    def test_dynamic_port_fallback_and_loopback_only(self):
        held, port = server.create_http_server(preferred_port=0)
        fallback = None
        try:
            fallback, other = server.create_http_server(preferred_port=port)
            self.assertNotEqual(port, other)
            self.assertEqual(fallback.server_address[0], '127.0.0.1')
        finally:
            held.server_close()
            if fallback:
                fallback.server_close()
        with self.assertRaises(ValueError):
            server.create_http_server('0.0.0.0')

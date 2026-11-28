"""Milestone 4 pure logic and isolated lifecycle gates, with no OS/network mutations."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server
import tray_app as tray


def snapshot(anomaly=False, running=True, wake=False, stamp='1', latency=100):
    return dict(running=running, target='US', interval_sec=30, latest=dict(
        timestamp=stamp, target='US', ip='203.0.113.1', colo='LAX', latency_ms=latency,
        utun_up=not anomaly, utun_ips=['utun4'], wake_detected=wake, anomaly=anomaly,
        anomaly_reasons=['TUN隧道离线'] if anomaly else []))


class TrayTests(unittest.TestCase):
    def test_connection_unknown_is_visible_without_becoming_a_process_action(self):
        value = snapshot()
        value['traffic'] = dict(running=True, state='unknown', limited=True)
        view = tray.status_view(value)
        self.assertEqual(view['state'], 'yellow')
        self.assertIn('连接待观察', view['status'])
        value['traffic'] = dict(running=True, state='not_running', limited=False)
        self.assertEqual(tray.status_view(value)['state'], 'green')

    def test_four_states_and_waiting(self):
        self.assertEqual(tray.status_view(snapshot())['state'], 'green')
        self.assertEqual(tray.status_view(snapshot(anomaly=True))['state'], 'red')
        self.assertEqual(tray.status_view(snapshot(latency=1201))['state'], 'yellow')
        self.assertEqual(tray.status_view(snapshot(wake=True))['state'], 'yellow')
        self.assertEqual(tray.status_view(snapshot(running=False))['state'], 'gray')
        self.assertEqual(tray.status_view(dict(running=True, target='JP', latest=None))['state'], 'yellow')

    def test_edges_recovery_cooldown_mute_and_stopped(self):
        gate = tray.NotificationGate()
        self.assertIsNone(gate.consume(snapshot(), now=0))
        self.assertIsNotNone(gate.consume(snapshot(True, stamp='2'), now=1))
        self.assertIsNone(gate.consume(snapshot(True, stamp='3'), now=2))
        self.assertIsNone(gate.consume(snapshot(True, wake=True, stamp='4'), now=20))
        self.assertIsNotNone(gate.consume(snapshot(True, wake=True, stamp='5'), now=301))
        self.assertIn('已恢复', gate.consume(snapshot(stamp='6'), now=302)[0])
        self.assertIsNone(gate.consume(snapshot(True, stamp='7'), enabled=False, now=700))
        self.assertIsNone(gate.consume(snapshot(True, running=False, stamp='8'), now=701))
        self.assertIsNone(gate.consume(snapshot(stamp='9'), now=702))

    def test_protection_overrides_stale_good_pulse_and_notifications_deduplicate(self):
        data = snapshot()
        data['protection'] = dict(enabled=True, running=True, status='blocked', reason_codes=['tun_down'],
                                  reasons=['TUN 接口离线'], event_seq=1, poll_interval_ms=100,
                                  terminated_total=2, last_action={'terminated': 2, 'event_seq': 1})
        self.assertEqual(tray.status_view(data)['state'], 'red')
        gate = tray.NotificationGate()
        message = gate.consume(data, now=0)
        self.assertIn('强退指令', message[1])
        self.assertIsNone(gate.consume(data, now=1))
        data['protection'].update(event_seq=2)
        self.assertIsNone(gate.consume(data, now=2))
        data['protection'].update(event_seq=3, status='safe', reason_codes=[], reasons=[])
        self.assertIn('不会自动重启', gate.consume(data, now=3)[1])
        data['protection'].update(enabled=False)
        self.assertEqual(tray.status_view(data)['state'], 'green')

    def test_late_action_is_not_lost_and_stale_recovery_cannot_claim_current_safe(self):
        current = dict(enabled=True, running=True, status='safe', event_seq=2, reason_codes=[], reasons=[])
        event = dict(enabled=True, running=True, status='blocked', event_seq=1, reason_codes=['tun_down'], reasons=['TUN离线'],
                     last_action={'at': 'fixture', 'terminated': 1, 'event_seq': 1})
        data = snapshot()
        data['protection'] = current
        gate = tray.NotificationGate()
        self.assertIsNone(gate.consume(data, now=0))  # a newer safe snapshot was already seen
        data['protection_event'] = event
        notice = gate.consume(data, now=1)
        self.assertIn('刚才', notice[1])
        self.assertIn('当前安全条件已恢复', notice[1])
        self.assertIsNone(gate.consume(data, now=2))
        current.update(status='blocked', event_seq=4, reason_codes=['country_mismatch'], reasons=['地区不匹配'])
        data['protection_event'] = dict(enabled=True, running=True, status='safe', event_seq=3, reason_codes=[], reasons=[])
        self.assertIsNone(gate.consume(data, now=3), 'historical safe event cannot announce recovery while current is blocked')
        self.assertTrue(gate._guard_blocked)
        current.update(enabled=False, running=False, status='paused')
        data['protection_event'] = {**event, 'event_seq': 5, 'last_action': {'at': 'new', 'terminated': 1, 'event_seq': 5}}
        self.assertIsNone(gate.consume(data, now=4), 'disabled current guard suppresses old queued notifications')

    def test_failed_worker_is_red_and_never_claims_auto_exit_available(self):
        data = snapshot()
        data['protection'] = dict(enabled=True, running=False, status='error', event_seq=1,
                                  reasons=['线程停止'], reason_codes=['kernel_unknown'])
        view = tray.status_view(data)
        self.assertEqual(view['state'], 'red')
        self.assertIn('自动退出不可用', view['tunnel'])
        self.assertNotIn('自动退出开启', view['tunnel'])
        notice = tray.NotificationGate().consume(data)
        self.assertIn('保护失效', notice[0])

    def test_disabled_guard_can_initialize_native_observers_without_signaling(self):
        from protection import FastProtector
        network = Mock()
        processes = Mock()
        telemetry = Mock()
        guard = FastProtector(network_factory=lambda: network, process_factory=lambda: processes,
                              telemetry_factory=lambda: telemetry, supported=True)
        guard.start(enabled=False)
        try:
            import time
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline and not guard.status()['process_backend_available']:
                time.sleep(.002)
            self.assertTrue(guard.status()['kernel_backend_available'])
            self.assertTrue(guard.status()['process_backend_available'])
            self.assertTrue(guard.status()['telemetry_backend_available'])
            processes.candidates.assert_not_called()
            processes.terminate.assert_not_called()
            network.sample.assert_not_called()
            telemetry.start.assert_not_called()
            telemetry.sample.assert_not_called()
        finally:
            guard.stop()

    def test_missing_telemetry_file_is_visible_as_unverified_in_native_menu(self):
        data = snapshot()
        data['protection'] = dict(enabled=True, running=True, status='safe', poll_interval_ms=100,
                                  telemetry={'state': 'missing'})
        view = tray.status_view(data)
        self.assertEqual(view['state'], 'yellow')
        self.assertIn('文件未验证', view['status'])
        self.assertIn('未发现/未验证', view['tunnel'])

    def test_file_risk_uses_existing_force_exit_notification_path(self):
        data = snapshot()
        data['protection'] = dict(enabled=True, running=True, status='blocked', event_seq=1,
                                  reason_codes=['telemetry_cn_timezone'], reasons=['本地地区字段风险'],
                                  telemetry={'state': 'risk'},
                                  last_action={'terminated': 1, 'event_seq': 1})
        self.assertEqual(tray.status_view(data)['state'], 'red')
        notice = tray.NotificationGate().consume(data)
        self.assertIn('强退指令', notice[1])
        self.assertIn('本地地区字段风险', notice[1])

    def test_native_menu_discloses_multi_source_scope_and_missing_sources(self):
        from protection import stopped_artifact_sources
        sources = stopped_artifact_sources()
        for source in sources:
            source['state'] = 'observed'
        data = snapshot()
        data['protection'] = dict(enabled=True, running=True, status='safe', poll_interval_ms=100,
                                  telemetry={'state': 'safe', 'sources': sources})
        view = tray.status_view(data)
        self.assertIn('8/8 已观察', view['tunnel'])
        self.assertIn('地区仅核验字段源', view['tunnel'])
        sources[0]['state'] = 'missing'
        view = tray.status_view(data)
        self.assertEqual(view['state'], 'yellow')
        self.assertIn('部分来源未验证', view['status'])

    def test_notification_argv_injection_and_timeout(self):
        text = '\" & do shell script \"touch /tmp/MUST_NOT_EXIST\" & \"'
        with patch.object(tray.subprocess, 'run', return_value=Mock(returncode=0)) as run:
            self.assertTrue(tray.send_notification(text, text))
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ['/usr/bin/osascript', '-e', tray.NOTIFICATION_SCRIPT])
        self.assertNotIn(text, argv[2])
        self.assertEqual(argv[3:], [text, text])
        self.assertEqual(run.call_args.kwargs['timeout'], 4)

    @unittest.skipIf(sys.platform == 'win32', 'POSIX flock gate')
    def test_flock_exclusive_release_and_stable_inode(self):
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp) / 'instance.lock')
            first, second = tray.InstanceLock(path), tray.InstanceLock(path)
            try:
                self.assertTrue(first.acquire())
                inode = os.stat(path).st_ino
                self.assertFalse(second.acquire())
                self.assertEqual(os.stat(path).st_ino, inode)
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
                first.release()
                self.assertTrue(second.acquire())
                self.assertEqual(os.stat(path).st_ino, inode)
            finally:
                first.release()
                second.release()

    def test_wake_timing_and_duplicate_coalescing(self):
        runtime = tray.TrayRuntime(silent=True)
        try:
            with patch.object(runtime, 'schedule') as schedule, patch.object(server.MONITOR, 'status', return_value={'running': True}):
                runtime.on_wake()
                runtime.on_wake()
            self.assertEqual([call.args[0] for call in schedule.call_args_list], [1.5, 4.5, 6.5])
        finally:
            runtime.close()

    def test_instance_runtime_health_and_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            controller = server.MonitorController()
            with patch.object(server, 'MONITOR', controller), \
                 patch.object(server, 'RUNTIME_INFO_PATH', str(Path(temp) / 'runtime.json')), \
                 patch.object(server, 'LOCK_FILE_PATH', str(Path(temp) / 'instance.lock')), \
                 patch.object(server, '_PREFS', {**server.PREFS_DEFAULTS, 'auto_start_monitor': False}):
                runtime = tray.TrayRuntime(preferred_port=0, silent=True)
                try:
                    self.assertTrue(runtime.start())
                    self.assertEqual(tray.existing_dashboard(), runtime.url)
                    self.assertEqual(os.stat(server.RUNTIME_INFO_PATH).st_mode & 0o777, 0o600)
                    duplicate = tray.TrayRuntime(silent=True)
                    try:
                        with patch.object(tray, 'open_dashboard') as open_url:
                            self.assertFalse(duplicate.start())
                            open_url.assert_called_once_with(runtime.url)
                    finally:
                        # A second process has its own MONITOR in production. Avoid stopping
                        # the first instance's in-process fixture controller in this test.
                        duplicate.work.shutdown()
                    port = runtime.httpd.server_port
                finally:
                    runtime.close()
                self.assertFalse(Path(server.RUNTIME_INFO_PATH).exists())
                self.assertFalse(runtime.http_thread.is_alive())
                self.assertFalse(controller.status()['running'])
                server.RUN_MODE = 'cli'

    def test_unhealthy_holder_cannot_be_stolen_or_killed(self):
        runtime = tray.TrayRuntime(silent=True)
        try:
            with patch.object(runtime.lock, 'acquire', return_value=False), \
                 patch.object(tray, 'existing_dashboard', return_value=None), \
                 patch.object(tray.os, 'unlink') as unlink:
                with self.assertRaises(RuntimeError):
                    runtime.start()
                unlink.assert_not_called()
        finally:
            runtime.close()

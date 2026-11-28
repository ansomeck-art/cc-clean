"""Private session protocol regressions. No processes, sockets or trust changes."""
from contextlib import ExitStack
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telemetry_runtime import COUNTERS, TelemetryService
from telemetry_worker import ControlChannel, UploadFilter


def counters(**changes):
    return dict(dict.fromkeys(COUNTERS, 0), **changes)


class Headers(dict):
    def items(self, multi=False):
        return super().items()


def flow():
    return types.SimpleNamespace(metadata={}, request=types.SimpleNamespace(
        pretty_url='https://api.anthropic.com/api/event_logging/v2/batch',
        method='POST', scheme='https', host='api.anthropic.com',
        headers=Headers(), raw_content=b'{"country":"US"}'))


def client():
    value = Mock()
    value.poll.return_value = None
    return value


class MemoryWorker:
    """Use the real worker control/filter code through an in-memory private pipe."""
    def __init__(self, service):
        self.service = service
        self.exit_code = None
        self.stdout = io.StringIO()
        self.commands = []
        self.order = []
        self.drop_acks = set()
        self.before_ack = None
        self.held = []
        self.hold_arm = False
        self.arm_seen = threading.Event()
        self.terminate, self.kill = Mock(), Mock()
        policy = Mock()
        policy.eligible.return_value = True
        policy.inspect.return_value = {'action': 'pass', 'reason': 'checked'}
        self.filter = UploadFilter(policy, publish=self.publish)
        self.channel = ControlChannel(self.filter)
        self.stdin = types.SimpleNamespace(write=self.write, flush=lambda: None, close=self.close)

    def poll(self):
        return self.exit_code

    def wait(self, timeout=None):
        return self.exit_code

    def close(self):
        self.exit_code = 0  # Model EOF shutdown, never a real process/signal.

    def write(self, text):
        message = json.loads(text)
        self.commands.append(message)
        self.order.append(message['command'])
        self.channel.feed(text.encode())
        return len(text)

    def publish(self, message):
        if message['event'] == 'session_ack':
            if self.before_ack:
                self.before_ack(message)
            if message['command'] in self.drop_acks:
                return
            if self.hold_arm and message['command'] == 'arm_session':
                self.held.append(message)
                self.arm_seen.set()
                return
        self.service._accept_message(self, message)

    def release_arm(self):
        for message in self.held:
            self.service._accept_message(self, message)
        self.held.clear()


class TelemetrySessionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory(prefix='regionguard-test-session-'))
        self.service = TelemetryService(directory)
        self.worker = MemoryWorker(self.service)
        self.service.process, self.service.port, self.service._trusted = self.worker, 12345, True
        self.stack.enter_context(patch.object(self.service, 'start'))
        self.stack.enter_context(patch.object(self.service, 'refresh_trust', return_value=True))
        self.stack.enter_context(patch.object(self.service, '_claude_executable', return_value=Path('/fake/Claude')))
        self.stack.enter_context(patch('telemetry_runtime.subprocess.run', return_value=Mock(returncode=1)))
        self.launch = self.stack.enter_context(patch('telemetry_runtime.subprocess.Popen', side_effect=lambda *a, **k: client()))

    def stats(self, session_id, value=1, active=True, process=None, session=None):
        return self.service._accept_message(process or self.worker, {
            'event': 'stats', 'stats': counters(tls_requests=max(value, 100)),
            'session_id': session_id, 'session_active': active,
            'session_stats': counters(tls_requests=value) if session is None else session})

    def test_historical_totals_and_queued_old_epoch_do_not_confirm_a_new_launch(self):
        self.worker.filter.stats['tls_requests'] = 40
        self.stats(None, 40)
        first = self.service.launch_claude()
        old_session = first['session_id']
        self.assertEqual(first['state'], 'awaiting_traffic')
        self.assertFalse(first['traffic_confirmed'])
        self.worker.filter.requestheaders(flow())
        self.assertTrue(self.service.status()['traffic_confirmed'])
        self.service.client.poll.return_value = 0
        second = self.service.launch_claude()
        self.assertNotEqual(old_session, second['session_id'])
        self.assertEqual(second['state'], 'awaiting_traffic')
        self.assertGreater(second['stats']['tls_requests'], 0)
        self.stats(old_session, 99)
        self.assertEqual(self.service.status()['session_stats'], counters())
        self.assertFalse(self.service.status()['traffic_confirmed'])

    def test_arm_is_acknowledged_before_launch_and_activation_follows_launch(self):
        def start_client(*args, **kwargs):
            self.worker.order.append('client')
            self.assertTrue(self.service._session_armed)
            self.assertFalse(self.service._session_active)
            self.assertIn('--proxy-server=http://127.0.0.1:12345', args[0])
            self.assertIn('--disable-quic', args[0])
            return client()
        self.launch.side_effect = start_client
        result = self.service.launch_claude()
        self.assertEqual(self.worker.order, ['arm_session', 'client', 'activate_session'])
        self.assertRegex(result['session_id'], r'^[0-9a-f]{32}$')
        self.assertFalse(result['traffic_confirmed'])

    def test_launch_gap_and_pre_activation_body_cannot_credit_the_new_session(self):
        gap_flow = flow()
        def start_client(*args, **kwargs):
            self.worker.filter.requestheaders(gap_flow)
            return client()
        self.launch.side_effect = start_client
        self.service.launch_claude()
        self.worker.filter.request(gap_flow)
        current = self.service.status()
        self.assertEqual(current['session_stats'], counters())
        self.assertGreater(current['stats']['tls_requests'], 0)
        self.assertGreater(current['stats']['checked'], 0)
        self.assertFalse(current['traffic_confirmed'])
        self.worker.filter.requestheaders(flow())
        self.assertTrue(self.service.status()['traffic_confirmed'])

    def test_pre_ack_stale_and_malformed_stats_never_confirm(self):
        def before_ack(message):
            if message['command'] == 'activate_session':
                self.stats(message['session_id'], 3)
        self.worker.before_ack = before_ack
        session_id = self.service.launch_claude()['session_id']
        self.assertEqual(self.service.status()['session_stats'], counters())
        self.stats('e' * 32, 9)
        self.stats(session_id, 9, active=False)
        self.stats(session_id, session=counters(tls_requests=True))
        self.stats(session_id, session={'tls_requests': 1})
        self.assertFalse(self.service.status()['traffic_confirmed'])
        self.stats(session_id, 1)
        self.assertTrue(self.service.status()['traffic_confirmed'])

    def test_arm_ack_timeout_never_launches_a_client_and_closes_the_worker_pipe(self):
        self.worker.drop_acks.add('arm_session')
        with patch('telemetry_runtime.SESSION_ACK_TIMEOUT', .001):
            with self.assertRaisesRegex(RuntimeError, '未获确认'):
                self.service.launch_claude()
        self.launch.assert_not_called()
        self.assertEqual(self.service.status()['state'], 'error')
        self.assertIsNone(self.service.status()['session_id'])
        self.assertEqual(self.worker.exit_code, 0)
        self.worker.terminate.assert_not_called()
        self.worker.kill.assert_not_called()

    def test_wrong_epoch_phase_or_active_flag_cannot_acknowledge_arm(self):
        self.worker.drop_acks.add('arm_session')
        def before_ack(message):
            if message['command'] == 'arm_session':
                for changes in ({'session_id': 'e' * 32}, {'command': 'activate_session'}, {'active': True}):
                    self.service._accept_message(self.worker, dict(message, **changes))
        self.worker.before_ack = before_ack
        with patch('telemetry_runtime.SESSION_ACK_TIMEOUT', .001):
            with self.assertRaisesRegex(RuntimeError, '未获确认'):
                self.service.launch_claude()
        self.launch.assert_not_called()
        self.assertFalse(self.service.status()['traffic_confirmed'])

    def test_activate_timeout_revokes_proof_and_never_retries_direct(self):
        self.worker.drop_acks.add('activate_session')
        with patch('telemetry_runtime.SESSION_ACK_TIMEOUT', .001):
            with self.assertRaisesRegex(RuntimeError, '未获确认'):
                self.service.launch_claude()
        self.launch.assert_called_once()
        status = self.service.status()
        self.assertEqual(status['state'], 'error')
        self.assertFalse(status['traffic_confirmed'])
        self.assertFalse(status['client_started'])
        self.assertEqual(status['session_stats'], counters())
        self.assertIsNone(status['session_id'])
        self.service.client.terminate.assert_not_called()
        self.service.client.kill.assert_not_called()

    def test_client_launch_failure_disarms_worker_and_redacts_os_error(self):
        self.launch.side_effect = OSError('SECRET-FILE')
        with self.assertRaisesRegex(RuntimeError, '本次筛选会话未获确认') as failure:
            self.service.launch_claude()
        self.assertNotIn('SECRET', str(failure.exception))
        self.assertIsNone(self.service.status()['session_id'])
        self.assertFalse(self.worker.filter.session_active)
        self.assertIsNone(self.worker.filter.session_id)
        self.assertEqual(self.worker.order, ['arm_session', 'disarm_session'])

    def test_client_exit_and_worker_replacement_at_same_port_revoke_proof(self):
        first = self.service.launch_claude()
        self.stats(first['session_id'])
        self.service.client.poll.return_value = 0
        self.assertIsNone(self.service.status()['session_id'])
        self.assertFalse(self.service.status()['traffic_confirmed'])
        self.service.launch_claude()
        self.worker.filter.requestheaders(flow())
        old_worker = self.worker
        self.worker = MemoryWorker(self.service)
        self.service.process = self.worker  # Even an identical port is a new owner.
        self.assertFalse(self.service.status()['client_started'])
        self.assertIsNone(self.service.status()['session_id'])
        third = self.service.launch_claude()
        self.stats(first['session_id'], process=old_worker)
        self.assertEqual(self.service.status()['session_id'], third['session_id'])
        self.assertFalse(self.service.status()['traffic_confirmed'])

    def test_worker_eof_and_late_old_reader_cannot_pollute_replacement(self):
        first = self.service.launch_claude()
        self.stats(first['session_id'])
        old_worker = self.worker
        self.service._read(old_worker)  # EOF while its controlled client is alive.
        self.assertFalse(self.service.status()['traffic_confirmed'])
        self.assertEqual(self.service.status()['state'], 'error')
        self.worker = MemoryWorker(self.service)
        self.service.process, self.service.port, self.service.error = self.worker, 12345, ''
        current = self.service.launch_claude()
        old_worker.stdout = io.StringIO(json.dumps({'event': 'error', 'payload': 'SECRET'}) + '\n')
        self.service._read(old_worker)
        after = self.service.status()
        self.assertEqual(after['session_id'], current['session_id'])
        self.assertEqual(after['state'], 'awaiting_traffic')
        self.assertNotIn('SECRET', str(after))

    def test_restart_resets_worker_totals_and_never_reuses_an_old_living_client(self):
        session_id = self.service.launch_claude()['session_id']
        self.stats(session_id)
        old_client = self.service.client
        self.worker.exit_code = 1
        replacement = MemoryWorker(self.service)
        ready = {'event': 'ready', 'port': 12345, 'fingerprint': 'f' * 64,
                 'session_id': None, 'session_active': False}
        reader = types.SimpleNamespace(start=lambda: self.service._accept_message(replacement, ready))
        with patch('telemetry_runtime.subprocess.Popen', return_value=replacement), \
             patch('telemetry_runtime.threading.Thread', return_value=reader):
            result = TelemetryService.start(self.service)
        self.assertEqual(result['state'], 'ready')
        self.assertEqual(result['stats'], counters())
        self.assertEqual(result['session_stats'], counters())
        self.assertIsNone(result['session_id'])
        self.assertFalse(result['traffic_confirmed'])
        self.assertFalse(result['client_started'])
        self.assertIsNone(old_client.poll())

    def test_worker_error_message_revokes_evidence_before_stdout_closes(self):
        session_id = self.service.launch_claude()['session_id']
        self.stats(session_id)
        self.service._accept_message(self.worker, {'event': 'error', 'message': 'SECRET'})
        status = self.service.status()
        self.assertEqual(status['state'], 'error')
        self.assertFalse(status['traffic_confirmed'])
        self.assertIsNone(status['session_id'])
        self.assertNotIn('SECRET', str(status))

    def test_repeated_initial_ready_cannot_reset_an_established_session_or_port(self):
        session_id = self.service.launch_claude()['session_id']
        self.stats(session_id)
        self.service._accept_message(self.worker, {
            'event': 'ready', 'port': 54321, 'fingerprint': 'f' * 64,
            'session_id': None, 'session_active': False})
        status = self.service.status()
        self.assertEqual(status['session_id'], session_id)
        self.assertEqual(status['proxy_url'], 'http://127.0.0.1:12345')
        self.assertTrue(status['traffic_confirmed'])

    def test_stop_closes_parent_pipe_revokes_proof_and_leaves_client_untouched(self):
        session_id = self.service.launch_claude()['session_id']
        self.stats(session_id)
        owned_client = self.service.client
        stopped = self.service.stop()
        self.assertEqual(stopped['state'], 'stopped')
        self.assertFalse(stopped['traffic_confirmed'])
        self.assertFalse(stopped['client_started'])
        self.assertIsNone(stopped['session_id'])
        self.assertEqual(owned_client.poll(), None)
        owned_client.terminate.assert_not_called()
        owned_client.kill.assert_not_called()

    def test_stop_and_launch_serialize_around_the_session_handshake(self):
        self.worker.hold_arm = True
        failures = []
        def launch():
            try:
                self.service.launch_claude()
            except Exception as exc:
                failures.append(exc)
        launch_thread = threading.Thread(target=launch)
        launch_thread.start()
        self.assertTrue(self.worker.arm_seen.wait(1))
        stopped = threading.Event()
        stop_thread = threading.Thread(target=lambda: (self.service.stop(), stopped.set()))
        stop_thread.start()
        try:
            self.assertFalse(stopped.wait(.02))
        finally:
            self.worker.release_arm()
            launch_thread.join(2)
            stop_thread.join(2)
        self.assertFalse(launch_thread.is_alive())
        self.assertFalse(stop_thread.is_alive())
        self.assertFalse(failures)
        self.assertFalse(self.service.status()['traffic_confirmed'])
        self.assertEqual(self.service.status()['state'], 'stopped')


class WorkerSessionTests(unittest.TestCase):
    def test_fragmented_bounded_controls_ignore_unknown_input_and_ack_only_valid_commands(self):
        publish = Mock()
        upload_filter = UploadFilter(Mock(), publish=publish)
        channel = ControlChannel(upload_filter)
        channel.feed(b'x' * 2048)
        self.assertLessEqual(len(channel.buffer), 512)
        channel.feed(b'\n{"command":"unknown","session_id":"SECRET"}\n[]\n')
        self.assertIsNone(upload_filter.session_id)
        publish.assert_not_called()
        command = json.dumps({'command': 'arm_session', 'session_id': 'a' * 32}).encode() + b'\n'
        channel.feed(command[:17])
        publish.assert_not_called()
        channel.feed(command[17:])
        self.assertEqual(upload_filter.session_id, 'a' * 32)
        self.assertFalse(upload_filter.session_active)
        self.assertEqual(publish.call_args.args[0], {
            'event': 'session_ack', 'command': 'arm_session', 'session_id': 'a' * 32, 'active': False})

    def test_old_flow_finishing_after_new_activation_counts_only_toward_history(self):
        policy = Mock()
        policy.eligible.return_value = True
        policy.inspect.return_value = {'action': 'pass', 'reason': 'checked'}
        upload_filter = UploadFilter(policy, publish=Mock())
        for command in ('arm_session', 'activate_session'):
            upload_filter.control({'command': command, 'session_id': 'a' * 32})
        previous = flow()
        upload_filter.requestheaders(previous)
        for command in ('arm_session', 'activate_session'):
            upload_filter.control({'command': command, 'session_id': 'b' * 32})
        upload_filter.request(previous)
        self.assertEqual(upload_filter.session_stats, counters())
        self.assertEqual(upload_filter.stats['checked'], 1)
        self.assertEqual(upload_filter.stats['tls_requests'], 1)
        current = flow()
        upload_filter.requestheaders(current)
        upload_filter.request(current)
        self.assertEqual(upload_filter.session_stats, counters(tls_requests=1, checked=1))

    def test_unarmed_filter_still_blocks_and_controls_never_expand_policy_scope(self):
        policy = Mock()
        policy.eligible.return_value = True
        policy.inspect.return_value = {'action': 'block', 'reason': 'cn_fields'}
        upload_filter = UploadFilter(policy, publish=Mock())
        request = flow()
        with patch.object(upload_filter, '_reject') as reject:
            upload_filter.requestheaders(request)
            upload_filter.request(request)
        reject.assert_called_once_with(request, 'block')
        self.assertEqual(upload_filter.stats['blocked'], 1)
        self.assertEqual(upload_filter.session_stats, counters())
        self.assertFalse(request.request.stream)


if __name__ == '__main__':
    unittest.main()

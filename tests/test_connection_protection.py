"""Connection bypass action boundary; only in-memory fake process identities."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from protection import FastProtector
from test_protection import Clock, FakeNetwork, FakeProcesses, FakeTelemetry


class ConnectionProtectionTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.cache = dict(state='observed', running=True, event_seq=12, action_reason_codes=[])
        self.provider = Mock(side_effect=lambda: copy.deepcopy(self.cache))
        self.ack = Mock()
        self.processes = FakeProcesses()
        self.guard = FastProtector(supported=True, clock=self.clock,
                                   connection_provider=self.provider, connection_acknowledge=self.ack)
        self.guard._network = FakeNetwork()
        self.guard._processes = self.processes
        self.guard._telemetry = FakeTelemetry()
        self.guard.configure('US', True)
        self.guard._state['running'] = True
        self.pulse()

    def pulse(self, started=None):
        self.guard.observe_pulse(dict(target='US', ok=True, loc='US', colo='IAD', utun_up=True),
                                 self.clock() if started is None else started)

    def test_known_bypass_terminates_and_confirms_only_verified_fixture(self):
        self.cache['action_reason_codes'] = ['connection_route_bypass']
        self.processes.available = [40001]
        self.guard._step()
        self.assertEqual(self.processes.terminated, [40001])
        self.assertIn('connection_route_bypass', self.guard.status()['reason_codes'])
        self.ack.assert_called_once_with(12)

    def test_direct_unknown_and_unavailable_observation_never_request_an_action(self):
        self.processes.available = [40002]
        for state in ('checking', 'unknown', 'not_running', 'observed', 'stopped'):
            self.cache.update(state=state, action_reason_codes=[],
                              evidence={'groups': [{'transport_counts': {'direct': 5, 'unknown': 10}}]})
            self.guard._step()
            self.assertEqual(self.guard.status()['status'], 'safe')
        self.provider.side_effect = RuntimeError('PRIVATE-CONTROLLER-DETAIL')
        self.guard._step()
        self.assertEqual(self.guard.status()['status'], 'safe')
        self.assertFalse(self.processes.terminated)
        self.ack.assert_not_called()
        self.assertNotIn('PRIVATE', json.dumps(self.guard.status()))

    def test_unhandled_bypass_remains_actionable_when_current_frame_is_unknown(self):
        self.cache.update(state='unknown', last_check_age_ms=None,
                          action_reason_codes=['connection_route_bypass'])
        self.processes.available = [40003]
        self.guard._step()
        self.assertEqual(self.processes.terminated, [40003])
        self.ack.assert_called_once_with(12)

    def test_invalid_action_schema_never_creates_a_false_positive(self):
        self.processes.available = [40004]
        for change in ({'state': 'PRIVATE'}, {'action_reason_codes': ['DIRECT']},
                       {'action_reason_codes': 'connection_route_bypass'},
                       {'event_seq': True}, {'event_seq': -1}, {'event_seq': 'PRIVATE'}):
            with self.subTest(change=change):
                self.cache = {**dict(state='observed', event_seq=12, action_reason_codes=['connection_route_bypass']), **change}
                self.guard._step()
                self.assertEqual(self.guard.status()['status'], 'safe')
        self.assertFalse(self.processes.terminated)
        self.ack.assert_not_called()

    def test_denied_rejected_and_identity_failures_do_not_acknowledge(self):
        self.cache['action_reason_codes'] = ['connection_route_bypass']
        self.processes.available = [40005]
        for outcome in ('denied', 'rejected'):
            self.processes.terminate = Mock(return_value=outcome)
            self.guard._step()
            self.ack.assert_not_called()
        self.processes.candidates = Mock(side_effect=OSError('PRIVATE-IDENTITY'))
        self.guard._step()
        self.assertIn('process_unknown', self.guard.status()['reason_codes'])
        self.ack.assert_not_called()
        self.assertNotIn('PRIVATE', json.dumps(self.guard.status()))

    def test_risk_recovery_requires_a_new_public_result(self):
        self.cache['action_reason_codes'] = ['connection_route_bypass']
        self.guard._step()
        self.clock.value += 1
        self.cache['action_reason_codes'] = []
        self.guard._step()
        self.assertIn('route_pending', self.guard.status()['reason_codes'])
        self.pulse(self.clock() - .1)
        self.guard._step()
        self.assertIn('route_pending', self.guard.status()['reason_codes'])
        self.pulse()
        self.guard._step()
        self.assertEqual(self.guard.status()['status'], 'safe')

    def test_disabled_guard_does_not_read_or_acknowledge_connection_cache(self):
        self.guard.configure('US', False)
        self.provider.side_effect = AssertionError('disabled observation access')
        self.guard._step()
        self.provider.assert_not_called()
        self.ack.assert_not_called()


if __name__ == '__main__':
    unittest.main()

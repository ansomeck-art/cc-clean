"""Multi-source guard boundary; process actions use memory-only fixtures."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from protection import ARTIFACT_MODES, FastProtector
from test_protection import Clock, FakeNetwork, FakeProcesses, FakeTelemetry


def sources():
    return [dict(id=source_id, mode=mode, state='observed', reason_codes=[],
                 field_types=(['locale', 'timezone'] if source_id == 'sentry_scope' else []),
                 change_count=0, file_count=1, total_bytes=100, files_checked=1,
                 last_check_age_ms=0, counters={}, limited=False)
            for source_id, mode in ARTIFACT_MODES.items()]


class ArtifactGuardIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.processes = FakeProcesses()
        self.observer = FakeTelemetry()
        self.observer.value.update(sources=sources(), risk_source_ids=[], field_types=['locale', 'timezone'])
        self.guard = FastProtector(supported=True, clock=self.clock, telemetry_factory=lambda: self.observer)
        self.guard._network = FakeNetwork()
        self.guard._processes = self.processes
        self.guard._telemetry = self.observer
        self.guard.configure('US', True)
        self.guard._state['running'] = True
        self.pulse()

    def pulse(self, started=None):
        self.guard.observe_pulse(dict(target='US', ok=True, loc='US', colo='LAX', utun_up=True),
                                 self.clock() if started is None else started)

    def source(self, source_id):
        return next(source for source in self.observer.value['sources'] if source['id'] == source_id)

    def test_any_fields_or_structured_log_cn_source_stops_verified_fixture(self):
        for source_id in ('sentry_scope', 'app_config', 'electron_preferences', 'claude_logs'):
            with self.subTest(source=source_id):
                self.observer.value['sources'] = sources()
                self.source(source_id).update(state='risk', reason_codes=['telemetry_cn_locale'], field_types=['locale'])
                # The DTO boundary preserves a positive source even if an aggregate
                # bug labels the newest frame safe.
                self.processes.available = [source_id]
                self.guard._step()
                status = self.guard.status()
                self.assertIn(source_id, self.processes.terminated)
                self.assertIn('telemetry_cn_locale', status['reason_codes'])
                self.assertIn(source_id, status['telemetry']['risk_source_ids'])
                self.assertTrue(any('危险来源' in reason for reason in status['reasons']))

    def test_ordinary_cookie_identity_queue_and_config_metadata_changes_do_not_signal(self):
        self.processes.available = [90]
        self.guard._step()
        for source_id in ('cookie_store', 'installation_id', 'desktop_config', 'sentry_queue'):
            self.source(source_id).update(change_count=20, total_bytes=5 * 1024 * 1024)
        self.guard._step()
        self.assertEqual(self.guard.status()['status'], 'safe')
        self.assertFalse(self.processes.terminated)

    def test_regular_log_error_counts_are_advisory_not_china_evidence(self):
        self.source('claude_logs')['counters'] = dict(region=1, banned=1, stripe=1, network=1)
        self.processes.available = [91]
        self.guard._step()
        self.assertEqual(self.guard.status()['status'], 'safe')
        self.assertFalse(self.processes.terminated)

    def test_latched_risk_keeps_its_source_after_latest_source_recovers(self):
        self.observer.value.update(state='risk', reason_codes=['telemetry_cn_country'],
                                   risk_source_ids=['app_config'])
        self.processes.available = [92]
        self.guard._step()
        status = self.guard.status()
        self.assertEqual(self.processes.terminated, [92])
        self.assertEqual(status['telemetry']['risk_source_ids'], ['app_config'])
        self.assertIn(self.observer.value['event_seq'], self.observer.acknowledged)

    def test_risk_recovery_requires_new_public_success(self):
        self.observer.value.update(state='risk', reason_codes=['telemetry_cn_country'], risk_source_ids=['app_config'])
        self.guard._step()
        self.clock.value += 1
        self.observer.value.update(state='safe', reason_codes=[], risk_source_ids=[])
        self.guard._step()
        self.assertIn('telemetry_pending', self.guard.status()['reason_codes'])
        self.pulse(started=self.clock() - .1)
        self.guard._step()
        self.assertIn('telemetry_pending', self.guard.status()['reason_codes'])
        self.pulse()
        self.guard._step()
        self.assertEqual(self.guard.status()['status'], 'safe')

    def test_source_unknown_or_stale_is_visible_but_never_a_kill_reason(self):
        self.processes.available = [93]
        self.source('app_config').update(state='unknown', reason_codes=['telemetry_file_unknown'])
        self.guard._step()
        self.assertIn('telemetry_file_unknown', self.guard.status()['telemetry']['reason_codes'])
        self.assertEqual(self.guard.status()['status'], 'safe')
        self.observer.value['sources'] = sources()
        self.source('claude_logs')['last_check_age_ms'] = 10000
        self.guard._step()
        self.assertIn('telemetry_file_stale', self.guard.status()['telemetry']['reason_codes'])
        self.assertEqual(self.guard.status()['status'], 'safe')
        self.assertFalse(self.processes.terminated)

    def test_extra_values_are_not_serialized_and_bad_sources_remain_unverified(self):
        self.source('app_config').update(path='/PRIVATE/PATH', locale='PRIVATE-LOCALE',
                                         device_name='PRIVATE-DEVICE', cookie_value='PRIVATE-COOKIE')
        self.guard._step()
        self.assertNotIn('PRIVATE', json.dumps(self.guard.status()))
        original = copy.deepcopy(self.observer.value)
        corruptions = [
            lambda raw: raw['sources'].pop(),
            lambda raw: raw['sources'][0].update(id='PRIVATE-ID'),
            lambda raw: raw['sources'][0].update(mode='PRIVATE-MODE'),
            lambda raw: raw['sources'][0].update(field_types=['PRIVATE-VALUE']),
            lambda raw: raw['sources'][0].update(change_count=True),
            lambda raw: raw['sources'][0].update(last_check_age_ms=float('nan')),
            lambda raw: raw['sources'][0].update(counters={'region': -1}),
            lambda raw: raw['sources'][0].update(limited='PRIVATE-FLAG'),
            lambda raw: raw['sources'][1].update(state='risk', reason_codes=['telemetry_cn_country']),
            lambda raw: raw.update(risk_source_ids=['cookie_store']),
        ]
        for corrupt in corruptions:
            with self.subTest(corrupt=corrupt):
                self.observer.value = copy.deepcopy(original)
                corrupt(self.observer.value)
                self.guard._step()
                self.assertIn('telemetry_file_unknown', self.guard.status()['telemetry']['reason_codes'])
                self.assertNotIn('PRIVATE', json.dumps(self.guard.status()))

    def test_missing_culture_and_transient_checks_never_invalidate_network_success(self):
        self.processes.available = [94]
        for state, codes in (('observed', []), ('checking', ['telemetry_file_pending']),
                             ('unknown', ['telemetry_file_unknown']), ('observed', [])):
            self.observer.value.update(state=state, reason_codes=codes, field_types=[])
            self.source('sentry_scope').update(state=state, reason_codes=codes, field_types=[])
            self.guard._step()
            self.assertEqual(self.guard.status()['status'], 'safe')
            self.assertFalse(self.guard.status()['reason_codes'])
        self.assertFalse(self.processes.terminated)

    def test_stale_latched_cn_still_terminates_after_current_observer_recovery(self):
        self.observer.value.update(state='risk', reason_codes=['telemetry_cn_country'],
                                   risk_source_ids=['app_config'], last_check_age_ms=10000)
        self.processes.available = [95]
        self.guard._step()
        self.assertEqual(self.processes.terminated, [95])
        self.assertIn('telemetry_cn_country', self.guard.status()['reason_codes'])

    def test_restart_latch_without_new_observation_age_keeps_known_risk(self):
        self.observer.value.update(state='risk', reason_codes=['telemetry_cn_country'],
                                   risk_source_ids=['app_config'], last_check_age_ms=None)
        for source in self.observer.value['sources']:
            source.update(state='checking', reason_codes=['telemetry_file_pending'], last_check_age_ms=None)
        self.source('app_config').update(state='risk', reason_codes=['telemetry_cn_country'])
        self.processes.available = [96]
        self.guard._step()
        self.assertEqual(self.processes.terminated, [96])
        self.assertEqual(self.guard.status()['telemetry']['state'], 'risk')
        self.assertIsNone(self.guard.status()['telemetry']['last_check_age_ms'])
        self.assertIn('telemetry_cn_country', self.guard.status()['reason_codes'])

    def test_disabled_guard_never_samples_sources_or_acknowledges_risk(self):
        from unittest.mock import Mock
        self.observer.sample = Mock(side_effect=AssertionError('unexpected read'))
        self.guard.configure('US', False)
        self.guard._step()
        self.observer.sample.assert_not_called()
        self.assertFalse(self.observer.acknowledged)


if __name__ == '__main__':
    unittest.main()

"""Public-probe and UI classifications use fixed, credential-free fixtures."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server
from service_diagnostics import classify_http


class EdgeDiagnosticsTests(unittest.TestCase):
    def probe(self, status, headers='', rc=0, error=''):
        response = 'HTTP/2 %s\r\n%s\r\n\n__RG_META__%s|' % (status, headers, status)
        with patch.object(server, 'run_cmd', return_value=(rc, response, error)) as command:
            result = server._probe_claude_edge_redirect()
        self.assertEqual(command.call_count, 1)
        self.assertNotIn('PRIVATE', json.dumps(result))
        return result

    def test_plain_403_is_unknown_forbidden_without_region_or_ban_claim(self):
        edge = self.probe(403)
        self.assertFalse(edge['blocked'])
        self.assertFalse(edge['cf_challenge'])
        self.assertEqual(edge['diagnostic']['reason_codes'], ['http_forbidden_unknown'])
        check = server.edge_gate_check(edge)
        self.assertEqual(check['status'], 'WARN')
        self.assertNotEqual(check['severity'], 'critical')

    def test_cf_challenge_and_permission_denial_are_distinct(self):
        challenge = self.probe(403, 'Cf-Mitigated: challenge\r\n')
        self.assertTrue(challenge['cf_challenge'])
        self.assertFalse(challenge['blocked'])
        permission = self.probe(403, 'x-claude-error-code: permission_error\r\n')
        self.assertEqual(permission['diagnostic']['reason_codes'], ['permission_denied'])
        self.assertFalse(permission['blocked'])
        self.assertFalse(permission['cf_challenge'])

    def test_same_origin_region_redirect_and_unrelated_redirect_are_distinct(self):
        for location in ('/app-unavailable-in-region', 'https://claude.ai/app-unavailable-in-region'):
            edge = self.probe(302, 'Location: ' + location + '\r\n')
            self.assertTrue(edge['blocked'])
            self.assertEqual(edge['redirect_url'], '/app-unavailable-in-region')
        for location in ('https://PRIVATE.example/app-unavailable-in-region',
                         '/login?next=app-unavailable-in-region'):
            edge = self.probe(302, 'Location: ' + location + '\r\n')
            self.assertFalse(edge['blocked'])
            self.assertEqual(edge['redirect_url'], '')

    def test_timeout_has_no_raw_stderr_and_no_region_claim(self):
        edge = self.probe('000', rc=28, error='PRIVATE-DESTINATION timed out')
        self.assertFalse(edge['blocked'])
        self.assertEqual(edge['diagnostic']['reason_codes'], ['network_timeout'])
        self.assertEqual(server.edge_gate_check(edge)['status'], 'WARN')

    def test_advisory_diagnostics_cannot_leak_values_or_replace_region_evidence(self):
        telemetry = {'sources': [{'id': 'claude_logs', 'diagnostics': {
            'permission_denied': 2, 'http_forbidden_unknown': 1, 'PRIVATE-ID': 'PRIVATE-COOKIE'}}]}
        check = server.service_response_check(telemetry)
        self.assertNotIn('PRIVATE', json.dumps(check))
        self.assertIn('权限拒绝 2', check['observed'])
        self.assertIn('明确地区拒绝 0', check['observed'])
        self.assertEqual(check['severity'], 'low')


if __name__ == '__main__':
    unittest.main()

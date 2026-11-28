"""Controller, security boundaries and certificate policy tests; never install a CA."""
import io
from pathlib import Path
import ssl
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telemetry_runtime import COUNTERS, HOSTS, TelemetryService, telemetry_filter_check
import server


class SoftwareFilterTests(unittest.TestCase):
    def test_policy_engine_error_holds_known_upload_before_upstream(self):
        from telemetry_worker import UploadFilter
        policy = Mock()
        policy.eligible.side_effect = RuntimeError('SECRET')
        upload_filter = UploadFilter(policy, publish=Mock())
        flow = types.SimpleNamespace(metadata={}, request=types.SimpleNamespace(
            pretty_url='https://api.anthropic.com/api/event_logging/v2/batch', method='POST',
            scheme='https', host='api.anthropic.com', headers={}))
        with patch.object(upload_filter, '_reject') as reject:
            upload_filter.requestheaders(flow)
        reject.assert_called_once_with(flow, 'hold')
        self.assertEqual(upload_filter.stats['held'], 1)
        self.assertFalse(flow.request.stream)

    def test_readiness_never_implies_a_client_is_protected(self):
        with tempfile.TemporaryDirectory() as directory:
            service = TelemetryService(directory)
            self.assertEqual(service.status()['state'], 'stopped')
            service.process = Mock()
            service.process.poll.return_value = None
            service.port = 12345
            self.assertEqual(service.status()['state'], 'needs_trust')
            service._trusted = True
            self.assertEqual(service.status()['state'], 'ready')
            service.client = Mock()
            service.client.poll.return_value = None
            service.client_port = 12345
            # A living client/port and historical worker traffic are insufficient.
            service.stats['tls_requests'] = 100
            self.assertEqual(service.status()['state'], 'ready')
            service.session_id = service.client_session_id = 'a' * 32
            service._session_worker = service.process
            service._session_armed = service._session_active = True
            self.assertEqual(service.status()['state'], 'awaiting_traffic')
            self.assertFalse(service.status()['traffic_confirmed'])
            service.session_stats['tls_requests'] = 1
            self.assertEqual(service.status()['state'], 'connected')
            service.port = 12346
            self.assertEqual(service.status()['state'], 'ready')
            service.process.poll.return_value = 1
            self.assertFalse(service.status()['running'])

    def test_worker_output_cannot_publish_payloads_or_claim_a_dead_worker_is_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            service = TelemetryService(directory)
            process = Mock()
            process.stdout = io.StringIO('{"event":"stats","stats":{"checked":3,"blocked":true,"payload":"SECRET"}}\n')
            service.process = process
            service._read(process)
            self.assertEqual(set(service.stats), set(COUNTERS))
            self.assertEqual(service.stats['checked'], 3)
            self.assertEqual(service.stats['blocked'], 0)
            self.assertIsNone(service.port)
            self.assertNotIn('SECRET', str(service.status()))

    def test_existing_claude_is_not_killed_or_relaunched(self):
        with tempfile.TemporaryDirectory() as directory:
            service = TelemetryService(directory)
            with patch.object(service, 'start'), patch.object(service, 'refresh_trust', return_value=True), \
                 patch('telemetry_runtime.subprocess.run', return_value=Mock(returncode=0)), \
                 patch('telemetry_runtime.subprocess.Popen') as launch:
                with self.assertRaisesRegex(RuntimeError, '正常退出'):
                    service.launch_claude()
                launch.assert_not_called()

    def test_certificate_trust_uses_chromium_compatible_ssl_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            service = TelemetryService(directory)
            service.directory.mkdir()
            # Native calls are mocked. This test cannot touch the real keychain.
            security = types.SimpleNamespace(
                SecCertificateCreateWithData=Mock(return_value='CERT'),
                SecItemAdd=Mock(return_value=(0, None)), SecPolicyCreateSSL=Mock(return_value='SSL'),
                SecTrustSettingsSetTrustSettings=Mock(return_value=0),
                kSecClass='class', kSecClassCertificate='certificate', kSecValueRef='ref',
                errSecDuplicateItem=-25299, kSecTrustSettingsPolicy='policy',
                kSecTrustSettingsPolicyString='hostname', kSecTrustSettingsResult='result',
                kSecTrustSettingsResultTrustRoot=1, kSecTrustSettingsDomainUser=0)
            foundation = types.SimpleNamespace(NSData=types.SimpleNamespace(
                dataWithBytes_length_=Mock(return_value=b'DER')))
            with patch.dict(sys.modules, {'Security': security, 'Foundation': foundation}), \
                 patch.object(service, 'start'), patch.object(service, 'refresh_trust', return_value=True), \
                 patch.object(service, '_native_certificate', return_value='CONSTRAINED-CERT'):
                service.trust_certificate()
            cert, domain, settings = security.SecTrustSettingsSetTrustSettings.call_args.args
            self.assertEqual((cert, domain), ('CONSTRAINED-CERT', 0))
            self.assertEqual(settings, [{'policy': 'SSL', 'result': 1}])
            self.assertFalse(any('stripe' in host for host in HOSTS))

    def test_legacy_native_trust_success_does_not_imply_chromium_compatibility(self):
        with tempfile.TemporaryDirectory() as directory:
            service = TelemetryService(directory)
            service.directory.mkdir()
            (service.directory / 'trust-probe.pem').write_text('test-public-certificate')
            with patch.object(service, '_has_chromium_compatible_trust', return_value=False), \
                 patch('telemetry_runtime.subprocess.run') as verify:
                self.assertFalse(service.refresh_trust(force=True))
                verify.assert_not_called()

    def test_scan_uses_internal_status_without_vpn_module_metadata(self):
        from readonly_telemetry import telemetry_filter_check as retired_check
        with patch.object(server.mac_platform, 'mac_audit_proxy', return_value={'checks': []}), \
             patch.object(server.TELEMETRY_SERVICE, 'status', return_value={'state': 'retired'}), \
             patch.object(server.CLIENT_VERSION, 'sample', return_value={'state': 'unknown'}), \
             patch.object(server.CLAUDE_TRAFFIC, 'sample', return_value={'state': 'unknown'}):
            result = server.audit_clash_proxy()
        self.assertEqual(result['checks'][0], retired_check())


if __name__ == '__main__':
    unittest.main()

"""Payment routing and warning regressions: local fixtures only, no network changes."""
import gzip
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_common
import mac_platform
import proxy_runtime
import server


class DiagnosticTests(unittest.TestCase):
    def test_payment_routes_require_live_transport_evidence_and_redact_nodes(self):
        secret = 'SECRET-NODE-NAME'
        proxies = {secret: {'type': 'Vless', 'server': 'SECRET-SERVER'},
                   'group': {'type': 'Selector'}}
        row = {'chains': [secret, 'group'], 'metadata': {'host': 'js.stripe.com',
               'processPath': '/SECRET-PROCESS', 'sourceIP': 'SECRET-IP'}}
        result = proxy_runtime.classify_payment_route(row, proxies)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['transport'], 'VLESS')
        self.assertNotIn('SECRET', json.dumps(result))
        for chains in ([], ['unknown'], ['group']):
            self.assertEqual(proxy_runtime.classify_payment_route({'chains': chains}, proxies)['status'], 'INFO')
        for name in ('DIRECT', 'REJECT', 'REJECT-DROP'):
            self.assertEqual(proxy_runtime.classify_payment_route({'chains': [name, secret]}, proxies)['status'], 'FAIL')

    def test_payment_observer_ignores_old_and_unrelated_connections_and_keeps_bypass(self):
        runtime = Mock()
        observer = proxy_runtime.PaymentRouteObserver(runtime)
        observer.proxies = {'SECRET': {'type': 'Vless'}}
        observer.existing_ids = {'old'}
        def row(identity, host, chains):
            return {'id': identity, 'metadata': {'host': host}, 'chains': chains}
        runtime.read.return_value = {'connections': [
            row('old', 'api.stripe.com', ['SECRET']), row('new', 'unrelated.example', ['DIRECT']),
            row('one', 'js.stripe.com', ['SECRET']), row('two', 'm.stripe.network', ['DIRECT'])]}
        observer.sample()
        self.assertNotIn('api.stripe.com', observer.routes)
        self.assertNotIn('unrelated.example', observer.routes)
        self.assertEqual(observer.routes['js.stripe.com']['status'], 'PASS')
        runtime.read.return_value = {'connections': [row('three', 'm.stripe.network', ['SECRET'])]}
        observer.sample()
        self.assertEqual(observer.routes['m.stripe.network']['status'], 'FAIL')
        self.assertEqual(proxy_runtime.payment_route_check(observer.routes)['status'], 'FAIL')
        self.assertEqual(proxy_runtime.payment_route_check({})['status'], 'INFO')
        good = {host: {'status': 'PASS', 'label': 'VLESS'} for host in proxy_runtime.PAYMENT_HOSTS}
        self.assertEqual(proxy_runtime.payment_route_check(good)['status'], 'PASS')

    def test_local_controller_failure_does_not_claim_payment_success(self):
        runtime = Mock()
        runtime.read.side_effect = OSError('SECRET-SOCKET-ERROR')
        observer = proxy_runtime.PaymentRouteObserver(runtime).start()
        self.assertEqual(observer.finish(), {})
        self.assertEqual(proxy_runtime.payment_route_check(observer.finish())['status'], 'INFO')
        runtime.tun_state = proxy_runtime.HakoRuntime.tun_state.__get__(runtime)
        self.assertEqual(runtime.tun_state(), {})

    def test_filter_status_comes_from_software_service(self):
        from telemetry_runtime import telemetry_filter_check
        for state in ('stopped', 'needs_trust', 'ready', 'awaiting_traffic', 'connected'):
            result = telemetry_filter_check({'state': state})
            self.assertEqual(result['status'], 'INFO')
            self.assertNotIn('已生效', result['observed'])
        self.assertIn('软件内', telemetry_filter_check()['observed'])

    def test_legacy_nxdomain_is_not_a_payment_failure_but_dns_uncertainty_remains_warning(self):
        for dns_ok, dns, status in ((True, {'Status': 3}, 'INFO'),
                                    (True, {'Status': 2}, 'WARN'), (False, None, 'WARN'),
                                    (True, {'Status': 0, 'Answer': []}, 'WARN')):
            with self.subTest(dns=dns), patch.object(server, 'run_cmd', return_value=(35, '000|', 'TLS failed')), \
                 patch.object(server, 'curl_json', return_value=(dns_ok, dns, 1, '')):
                result = server._probe_third_party('Statsig', 'https://statsig.anthropic.com/', 'legacy')
            self.assertFalse(result['ok'])
            self.assertEqual(result['status'], status)
            self.assertEqual(result['error'], 'TLS failed')
        with patch.object(server, 'run_cmd', return_value=(35, '000|', 'TLS failed')), \
             patch.object(server, 'curl_json') as dns:
            self.assertFalse(server._probe_third_party('Stripe', 'https://api.stripe.com/', 'critical')['ok'])
            dns.assert_not_called()

    def test_all_curl_probes_remove_proxy_environment(self):
        environment = {'HTTP_PROXY': 'SECRET', 'https_proxy': 'SECRET', 'ALL_PROXY': 'SECRET', 'NO_PROXY': '*'}
        with patch.dict(server.os.environ, environment), \
             patch.object(server, 'run_cmd', return_value=(0, '200|', '')) as run:
            server._probe_third_party('Stripe', 'https://js.stripe.com/v3/', 'critical')
            for key in environment:
                self.assertNotIn(key, run.call_args.kwargs['env'])
            server._probe_claude_edge_redirect()
            for key in environment:
                self.assertNotIn(key, run.call_args.kwargs['env'])

    def test_cloudflare_html_without_trace_does_not_verify_egress(self):
        with patch.object(server, 'curl_fetch', return_value=(True, '<html>not a trace</html>', 10, '')):
            result = server._trace_domain('downloads.claude.ai')
        self.assertFalse(result['ok'])
        self.assertFalse(result['trace_available'])
        self.assertTrue(result['reachable'])
        with patch.object(server, 'curl_fetch', return_value=(True, 'ip=8.8.8.8\nloc=US\ncolo=IAD', 10, '')):
            self.assertTrue(server._trace_domain('claude.ai')['ok'])

    def test_native_packet_tunnel_does_not_require_mihomo_yaml_flags(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            config = home / 'Library/Group Containers/group.com.hako.network/working/active/config.yaml'
            config.parent.mkdir(parents=True)
            config.write_text('mode: global\ndns:\n  nameserver: [https://dns.example/dns-query]\n')
            with patch.object(mac_platform.HakoRuntime, 'tun_state', return_value={'enabled': True, 'packet_flow': True}):
                result = mac_platform.mac_audit_proxy(lambda *a, **k: (0, '', ''), home)
            tun = next(c for c in result['checks'] if c['id'] == 'clash_tun_cfg')
            self.assertEqual(tun['status'], 'INFO')
            self.assertIn('Network Extension', tun['detail'])
            with patch.object(mac_platform.HakoRuntime, 'tun_state', return_value={}):
                result = mac_platform.mac_audit_proxy(lambda *a, **k: (0, '', ''), home)
            self.assertEqual(next(c for c in result['checks'] if c['id'] == 'clash_tun_cfg')['status'], 'WARN')

    def test_every_mode_and_index_rules_cannot_hide_payment_bypass(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'config.yaml'
            path.write_text('''mode: global
x-clash-every-mode-rules:
    - DOMAIN-SUFFIX,stripe.network,DIRECT
    - DOMAIN-SUFFIX,stripe.com,SECRET-NODE
x-clash-rule-index:
    path: /SECRET/INDEX
    prepend:
        - DOMAIN-SUFFIX,anthropic.com,DIRECT
''')
            result = audit_common.safe_parse_clash_yaml(str(path))
        self.assertTrue(any('stripe' in hit for hit in result['direct_risk_rules']))
        self.assertTrue(any('anthropic' in hit for hit in result['direct_risk_rules']))
        self.assertNotIn('SECRET', json.dumps(result))

    def test_normal_cache_and_installation_are_information_but_errors_remain_visible(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            cdir = home / 'Library/Application Support/Claude'
            (cdir / 'sentry/queue').mkdir(parents=True)
            (cdir / 'sentry/scope_v3.json').write_text(json.dumps({'event': {'contexts': {
                'culture': {'locale': 'en-US', 'timezone': 'America/New_York'}}}}))
            (cdir / 'sentry/queue/one').write_text('PRIVATE-ENVELOPE')
            (cdir / 'fcache').write_bytes(b'CLF\0\0' + gzip.compress(b'{"orgUuid":null}'))
            (cdir / 'ant-did').write_text('SECRET-ID')
            logs = home / 'Library/Logs/Claude'
            logs.mkdir(parents=True)
            (logs / 'main.log').write_text('normal startup\n')
            result = audit_common.inspect_telemetry(str(cdir))
            self.assertEqual(result['sentry_status'], 'INFO')
            self.assertEqual(result['fcache_status'], 'INFO')
            report = mac_platform.mac_audit_claude_browser_residue(lambda *a, **k: (0, '', ''), home, app_paths=[])
            checks = {c['id']: c for c in report['checks']}
            for cid in ('claude_ant-did', 'claude_logs', 'claude_system_paths'):
                self.assertEqual(checks[cid]['status'], 'INFO')
            self.assertNotIn('SECRET', json.dumps(report))
            (logs / 'main.log').write_text('Failed to load Stripe.js\n')
            report = mac_platform.mac_audit_claude_browser_residue(lambda *a, **k: (0, '', ''), home, app_paths=[])
            self.assertEqual(next(c for c in report['checks'] if c['id'] == 'claude_logs')['status'], 'WARN')
            (cdir / 'fcache').write_bytes(b'unrecognized')
            self.assertEqual(audit_common.inspect_telemetry(str(cdir))['fcache_status'], 'WARN')

    def test_safari_itp_record_is_not_a_live_cookie(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            path = home / 'Library/Containers/com.apple.Safari/Data/Library/WebKit/WebsiteData/Default/ResourceLoadStatistics/observations.db'
            path.parent.mkdir(parents=True)
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE ObservedDomains(registrableDomain TEXT)')
                db.execute("INSERT INTO ObservedDomains VALUES('stripe.com')")
            result = mac_platform.scan_safari(home)
        self.assertEqual(result['status'], 'INFO')
        self.assertIn('stripe.com', result['itp_domains'])
        self.assertEqual(result['domains'], [])


if __name__ == '__main__':
    unittest.main()

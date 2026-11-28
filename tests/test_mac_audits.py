"""Milestone 2: macOS fixtures only; no external network or OS changes."""
import errno
import gzip
import json
import os
from pathlib import Path
import plistlib
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mac_platform as mac
import server
from test_foundation import HTTPGuardTests, FoundationTests


class MacAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.cdir = self.home / 'Library/Application Support/Claude'
        self.cdir.mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, relative, data):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
        return path

    def json(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))

    def command(self, argv, timeout=4):
        return 0, '', ''

    def test_apple_languages_primary_secondary_and_clean(self):
        for languages, status in ((['zh-Hans-CN', 'en-US'], 'FAIL'),
                                  (['en-US', 'zh-Hans-CN'], 'WARN'), (['en-US'], 'PASS')):
            with self.subTest(languages=languages):
                self.assertEqual(mac.language_check(languages)['status'], status)
        self.assertEqual(mac.language_check(['zh_CN.UTF-8'])['status'], 'FAIL')
        self.assertEqual(mac.language_check([])['status'], 'INFO')

    def test_language_plist_preferred_over_defaults(self):
        path = self.home / 'Library/Preferences/.GlobalPreferences.plist'
        path.parent.mkdir(parents=True)
        with path.open('wb') as handle:
            plistlib.dump({'AppleLanguages': ['zh-Hans-CN', 'en-US'], 'AppleLocale': 'en_US'}, handle)
        result = mac.mac_audit_system(server.TARGETS['US'], self.command, self.home)
        language = next(c for c in result['checks'] if c['id'] == 'user_locale')
        self.assertEqual(language['status'], 'FAIL')

    def test_sentry_normal_binding_info_and_restricted_fail(self):
        for culture, expected in (({'locale': 'en-US', 'timezone': 'America/New_York'}, 'INFO'),
                                  ({'locale': 'en-US', 'timezone': 'Asia/Shanghai'}, 'FAIL'),
                                  ({'locale': 'zh-Hans', 'timezone': 'America/New_York'}, 'FAIL')):
            self.json(self.cdir / 'sentry/scope_v3.json', {
                'scope': {'user': {'id': 'SECRET-DEVICE-UUID'}}, 'event': {'contexts': {'culture': culture}}})
            result = server._inspect_desktop_telemetry_artifacts_posix(str(self.cdir))
            self.assertEqual(result['sentry_status'], expected)
            self.assertNotIn('SECRET-DEVICE-UUID', json.dumps(result))

    def test_fcache_clf_org_presence_is_fail_without_uuid(self):
        secret = '3a200000-private-org-fixture'
        (self.cdir / 'fcache').write_bytes(b'CLF\0\0' + gzip.compress(json.dumps({'orgUuid': secret, 'mode': 'SECRET-API-KEY'}).encode()))
        result = server._inspect_desktop_telemetry_artifacts_posix(str(self.cdir))
        self.assertEqual(result['fcache_status'], 'FAIL')
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn('SECRET-API-KEY', json.dumps(result))

    def test_ant_registry_states_inventory_and_redaction(self):
        path = self.cdir / 'ant-device-registry.json'
        self.json(path, {'accounts': {'SECRET-ACCOUNT-UUID': {'fingerprint': 'pk1:SECRET-HARDWARE-HASH'},
                                      'SECOND-UUID': {'fingerprint': 'pku1:SECRET-PENDING-HASH'}}})
        result = mac.inspect_device_registry(path)
        self.assertTrue(result['bound'])
        self.assertTrue(result['pending'])
        self.assertEqual(result['entries'], 2)
        report = mac.mac_audit_claude_browser_residue(self.command, self.home, app_paths=[])
        self.assertTrue(any('ant-device-registry.json' in row['name'] for row in report['inventory']))
        for secret in ('SECRET-ACCOUNT-UUID', 'SECRET-HARDWARE-HASH', 'SECRET-PENDING-HASH', 'SECOND-UUID'):
            self.assertNotIn(secret, json.dumps(report))

    def test_safari_eperm_is_never_pass(self):
        original = mac._state
        def stat(path):
            if 'com.apple.Safari' in str(path):
                raise PermissionError(errno.EPERM, 'fixture denied')
            return original(path)
        with patch.object(mac, '_state', side_effect=stat):
            result = mac.scan_safari(self.home)
        self.assertIn(result['status'], ('INFO', 'WARN'))
        self.assertIn('TCC', result['observed'])
        self.assertIn('完全磁盘访问权限', result['detail'])

    def test_safari_custom_profile_detected_and_does_not_leak_name(self):
        self.write('Library/Containers/com.apple.Safari/Data/Library/WebKit/WebsiteData/Custom/SECRET-PROFILE-UUID/LocalStorage/item/origin', 'https://claude.ai')
        result = mac.scan_safari(self.home)
        self.assertIn('claude.ai', result['website_data_domains'])
        self.assertEqual(result['status'], 'WARN')
        self.assertNotIn('SECRET-PROFILE-UUID', json.dumps(result))

    def test_safari_history_tcc_and_db_error_are_not_pass(self):
        for state in ('denied', 'error', 'changed', 'limited'):
            with patch.object(mac, '_safe_sqlite_query', return_value=(state, [])):
                self.assertNotEqual(mac.scan_safari(self.home)['status'], 'PASS')

    def test_clash_and_surge_precise_process_and_secret_redaction(self):
        path = self.write('clash.yaml', '''mode: rule
proxies:
  - name: SECRET-NODE
    server: secret-node.example
    password: SECRET-PASSWORD
    uuid: SECRET-UUID
proxy-providers:
  provider:
    url: https://secret-subscription.example/SECRET-TOKEN
tun: {enable: true, strict-route: true, auto-route: true}
dns:
  nameserver: [system, https://dns.alidns.com/dns-query?token=SECRET-DNS-TOKEN]
rules:
  - PROCESS-NAME,not-claude.exe,DIRECT
  - PROCESS-PATH,/private/node-launcher,DIRECT
  - PROCESS-NAME,Claude,DIRECT
  - PROCESS-PATH,C:\\Tools\\node.exe,DIRECT
  - DOMAIN-SUFFIX,anthropic.com,DIRECT
  - DOMAIN-SUFFIX,sentry.io,REJECT
''')
        result = server._safe_parse_clash_yaml(str(path))
        self.assertEqual(result['process_direct_risks'], ['PROCESS-NAME,claude,DIRECT', 'PROCESS-NAME,node.exe,DIRECT'])
        self.assertTrue(result['tun_strict_route'])
        self.assertTrue(result['direct_risk_rules'])
        self.assertTrue(result['reject_risk_rules'])
        for secret in ('SECRET', 'secret-node.example', 'secret-subscription.example', 'C:\\Tools'):
            self.assertNotIn(secret, json.dumps(result))
        surge = self.write('surge.conf', '''[Proxy]
node = ss, secret-node.example, 443, password=SECRET-PASSWORD
[Proxy Group]
secret-group = select, node
[General]
skip-proxy = *.anthropic.com, *.stripe.com
dns-server = system, 223.5.5.5
always-real-ip = *.claude.ai
ipv6 = true
[Rule]
PROCESS-NAME,not-claude,DIRECT
PROCESS-NAME,Claude,DIRECT
''')
        parsed = server._safe_parse_surge_conf(str(surge))
        self.assertIn('anthropic', parsed['skip_proxy_risks'])
        self.assertEqual(len(parsed['process_direct_risks']), 1)
        self.assertNotIn('SECRET', json.dumps(parsed))
        self.assertNotIn('secret-node.example', json.dumps(parsed))

    def test_system_proxy_exceptions_are_critical_and_redacted(self):
        text = '''<dictionary> {
HTTPEnable : 1
HTTPProxy : secret-proxy.example
HTTPPort : 1234
ExceptionsList : <array> {
0 : *.anthropic.com
1 : local
}
}'''
        result = mac.mac_sys_proxy(lambda *a, **k: (0, text, ''), False)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['severity'], 'critical')
        self.assertNotIn('secret-proxy', json.dumps(result))
        self.assertNotIn('1234', json.dumps(result))
        result = mac.mac_sys_proxy(lambda *a, **k: (0, 'HTTPEnable : 1', ''), False)
        self.assertEqual(result['status'], 'WARN')
        self.assertIn('UDP STUN', result['detail'])

    def test_nwi_priority_ipv6_mask_and_vm_bridge(self):
        addr = '240e:1234:5678:abcd:1234:5678:1111:2222'
        def cmd(argv, timeout):
            if argv[-1] == '--nwi':
                return 0, 'IPv4 network interface information\n en0 : flags : 0x5\n utun4 : flags : 0x5\nIPv6 network interface information\n en0 : flags : 0x5', ''
            if argv[0] == '/sbin/ifconfig':
                return 0, 'en0: flags=8863<UP,BROADCAST,RUNNING>\n inet6 ' + addr + '\nutun4: flags=8051<UP,POINTOPOINT,RUNNING>\nbridge100: flags=8863<UP,BROADCAST,RUNNING>', ''
            return 0, 'default 198.18.0.1 UGSc utun4\n', ''
        result = mac.mac_check_tun_details(cmd)
        checks = {c['id']: c for c in result['checks']}
        self.assertEqual(checks['mac_nwi_priority']['status'], 'WARN')
        self.assertEqual(checks['mac_physical_ipv6']['status'], 'FAIL')
        self.assertIn('mac_vm_bridge', checks)
        self.assertNotIn(addr, json.dumps(result))
        self.assertNotIn('1111:2222', json.dumps(result))

    def test_proxy_discovery_mtime_and_fixed_tcc_path(self):
        older = self.write('.config/mihomo/config.yaml', 'mode: global')
        newer = self.write('Library/Application Support/mihomo-party/work/config.yaml', 'mode: rule')
        os.utime(older, (1, 1))
        os.utime(newer, (2, 2))
        result = mac._discover_macos_proxy_configs(self.home)
        self.assertEqual(result[0][0], 'Mihomo Party')
        self.assertEqual(len(result), 2)

    def test_sqlite_wal_cookie_domain_only_and_source_untouched(self):
        root = self.home / 'Chrome'
        profile = root / 'Default'
        profile.mkdir(parents=True)
        db = profile / 'Cookies'
        connection = sqlite3.connect(db)
        try:
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('PRAGMA wal_autocheckpoint=0')
            connection.execute('CREATE TABLE cookies(host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB)')
            connection.execute("INSERT INTO cookies VALUES('.claude.ai','session','SECRET-COOKIE',X'010203')")
            connection.commit()
            before = db.read_bytes(), Path(str(db) + '-wal').read_bytes()
            state, rows = mac._safe_sqlite_query(db, 'SELECT DISTINCT host_key FROM cookies')
            self.assertEqual((state, rows), ('ok', [('.claude.ai',)]))
            result = mac.scan_chromium('Chrome', root)
            self.assertEqual(result['status'], 'WARN')
            self.assertNotIn('SECRET-COOKIE', json.dumps(result))
            self.assertEqual(before, (db.read_bytes(), Path(str(db) + '-wal').read_bytes()))
        finally:
            connection.close()

    def test_browser_doh_extensions_indexeddb_firefox_and_orion(self):
        root = self.home / 'Chrome'
        self.json(root / 'Local State', {'dns_over_https': {'templates': 'https://doh.pub/dns-query?secret=PRIVATE'}})
        self.json(root / 'Default/Extensions/SECRET-ID/1/manifest.json', {'permissions': ['proxy']})
        (root / 'Default/IndexedDB/https_claude.ai_0.indexeddb.leveldb').mkdir(parents=True)
        result = mac.scan_chromium('Chrome', root)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('代理扩展=1', result['observed'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        firefox = self.home / 'Firefox'
        self.write('Firefox/Profiles/SECRET-PROFILE/prefs.js', 'user_pref("network.trr.uri", "https://dns.alidns.com/dns-query");\nuser_pref("network.trr.mode", 3);')
        (firefox / 'Profiles/SECRET-PROFILE/storage/default/https+++claude.ai').mkdir(parents=True)
        result = mac.scan_firefox('Firefox', firefox)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('TRR模式=3', result['observed'])
        self.assertNotIn('SECRET', json.dumps(result))
        self.write('Library/Application Support/Orion/Defaults/WebsiteData/Default/cache/origin', 'https://claude.ai')
        report = mac.mac_audit_claude_browser_residue(self.command, self.home, app_paths=[])
        self.assertEqual(next(c for c in report['checks'] if c['id'] == 'browser_orion')['status'], 'WARN')

    def test_no_blind_tcc_parent_enumeration_or_keychain_reads(self):
        original = Path.iterdir
        forbidden = {self.home / 'Library/Containers', self.home / 'Library/Group Containers', self.home / '.Trash'}
        def iterdir(path):
            self.assertNotIn(path, forbidden)
            return original(path)
        with patch.object(Path, 'iterdir', iterdir):
            mac.mac_audit_claude_browser_residue(self.command, self.home, app_paths=[])

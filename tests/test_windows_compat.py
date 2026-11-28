"""Windows sharing gates run without registry access or Windows system commands."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import win_platform as win


class WindowsCompatibilityTests(unittest.TestCase):
    def test_proxy_state_and_bypass_are_retained_without_endpoints(self):
        tun = dict(dns_servers=[], tun_dns=[], physical_dns=[], physical_private_dns=[], cn_dns=[])
        queried = []
        def read(root, key, name, default=None):
            queried.append(name)
            if name in {'ProxyServer', 'AutoConfigURL'}:
                self.fail('proxy/PAC bytes must never be read')
            return {'ProxyEnable': 1, 'ProxyOverride': '*.anthropic.com;SECRET-PRIVATE-HOST'}.get(name, default)
        with patch.object(win, '_read_reg', side_effect=read), \
             patch.object(win, '_reg_value_present', return_value=True), \
             patch.object(win, '_run_win_cmd', return_value=(0, 'Proxy Server(s) : secret-proxy.example:1234', '')):
            result = win.win_check_dns_and_proxy(tun)
        self.assertTrue(result['proxy_enable'])
        self.assertIn('anthropic', result['proxy_bypass_risk'])
        self.assertTrue(result['winhttp_proxy'])
        for secret in ('secret-proxy', '1234', 'SECRET-PRIVATE-HOST'):
            self.assertNotIn(secret, json.dumps(result))

    def test_no_proxy_state_remains_empty(self):
        tun = dict(dns_servers=[], tun_dns=[], physical_dns=[], physical_private_dns=[], cn_dns=[])
        with patch.object(win, '_read_reg', return_value=0), patch.object(win, '_reg_value_present', return_value=False), \
             patch.object(win, '_run_win_cmd', return_value=(0, 'Direct access (no proxy server).', '')):
            result = win.win_check_dns_and_proxy(tun)
        self.assertFalse(result['proxies'])
        self.assertFalse(result['proxy_enable'])
        self.assertFalse(result['winhttp_proxy'])

    def test_v6_risk_families_shared_and_exact_domain_matching(self):
        for domain in ('assets.claude.ai', 'bridge.claudeusercontent.com', 'config.claude.com',
                       'pivot.claude.ai', 'browser-intake-us5-datadoghq.com'):
            self.assertTrue(win._match_risk_domain(domain))
        self.assertFalse(win._match_risk_domain('anthropic.com.evil.example'))

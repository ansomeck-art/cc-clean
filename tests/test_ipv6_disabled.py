"""Check real networksetup parsing without changing any system settings."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server


ORDER = """An asterisk (*) denotes that a network service is disabled.
(1) Ethernet
(Hardware Port: Ethernet, Device: en0)
(2) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)
(3) My Wireless
(Hardware Port: Wi-Fi, Device: en1)
(4) Clash
(Hardware Port: com.hako.network, Device: )
(5) Other VPN
(Hardware Port: VPN, Device: utun4)
"""


class IPv6DisabledTests(unittest.TestCase):
    def check(self, states=None, order=ORDER, order_rc=0):
        states = states or {}
        seen = []

        def fake_run(args, timeout):
            seen.append(args)
            if args[1] == "-listnetworkserviceorder":
                return order_rc, order, ""
            self.assertEqual(args[1], "-getinfo", "inspection must never mutate settings")
            self.assertNotIn(args[2], ["Clash", "Other VPN"])
            value = states.get(args[2], "Off")
            if isinstance(value, tuple):
                return value
            return 0, "DHCP Configuration\nIPv6: " + value + "\nIPv6 IP address: none\n", ""

        with patch.object(server, "run_cmd", side_effect=fake_run):
            result = server._check_macos_ipv6_disabled()
        return result, seen

    def test_all_interfaces_off_including_renamed_wifi_pass(self):
        result, seen = self.check()
        self.assertEqual(result["status"], "PASS")
        self.assertIn("My Wireless: Off", result["observed"])
        self.assertEqual(len(seen), 4)
        self.assertEqual(result["fix_cmd"], "")

    def test_automatic_without_public_address_is_still_not_forced_off(self):
        result, _ = self.check({"My Wireless": "Automatic"})
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("My Wireless: Automatic", result["observed"])
        self.assertIn("'My Wireless'", result["fix_cmd"])
        self.assertIn("不表示已发现泄漏", result["detail"])

    def test_link_local_only_is_not_off(self):
        result, _ = self.check({"Ethernet": "Link-local only"})
        self.assertEqual(result["status"], "FAIL")

    def test_disabled_physical_service_is_also_checked(self):
        order = "(*) Spare Ethernet\n(Hardware Port: USB LAN, Device: en5)\n"
        result, seen = self.check({"Spare Ethernet": "Automatic"}, order=order)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(seen[-1][-1], "Spare Ethernet")

    def test_service_read_failure_is_unknown_not_pass(self):
        result, _ = self.check({"My Wireless": (1, "", "permission denied")})
        self.assertEqual(result["status"], "WARN")
        self.assertIn("未知", result["observed"])

    def test_missing_ipv6_field_is_unknown_not_pass(self):
        result, _ = self.check({"Ethernet": (0, "DHCP Configuration\n", "")})
        self.assertEqual(result["status"], "WARN")

    def test_service_enumeration_failure_is_not_pass(self):
        result, _ = self.check(order="", order_rc=1)
        self.assertEqual(result["status"], "WARN")

    def test_empty_or_unrecognized_services_are_not_pass(self):
        result, _ = self.check(order="(1) Clash\n(Hardware Port: VPN, Device: utun4)\n")
        self.assertEqual(result["status"], "WARN")

    def test_unclosed_interface_and_unknown_interface_do_not_pass(self):
        result, _ = self.check({"Ethernet": "Automatic", "My Wireless": (124, "", "timeout")})
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("未能确认", result["detail"])


if __name__ == "__main__":
    unittest.main()

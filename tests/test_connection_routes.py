"""Destination-specific routing fixtures; never change routes or contact hosts."""
import ipaddress
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from connection_routes import ConnectionRouteReader, classify_destination
from traffic_evidence import OwnedSocket


def route(network, interface='utun5', flags=1):
    return ipaddress.ip_network(network), interface, flags


class ConnectionRouteTests(unittest.TestCase):
    def setUp(self):
        self.interfaces = {'utun5': 1, 'en1': 1, 'ppp0': 1}

    def classify(self, routes, destination='8.8.4.4'):
        return classify_destination(destination, routes, self.interfaces)

    def test_actual_destination_physical_exception_overrides_tunnel_default(self):
        self.assertEqual(self.classify([route('0.0.0.0/0'), route('8.8.4.4/32', 'en1')]), 'physical_bypass')
        self.assertEqual(self.classify([route('0.0.0.0/0'), route('9.9.9.9/32', 'en1')]), 'tun')

    def test_scoped_physical_backup_does_not_override_unscoped_route(self):
        self.assertEqual(self.classify([route('0.0.0.0/0'), route('8.8.4.4/32', 'en1', 1 | 0x1000000)]), 'tun')

    def test_tied_interfaces_are_unknown_instead_of_a_guessed_route(self):
        self.assertEqual(self.classify([route('0.0.0.0/0'), route('0.0.0.0/0', 'en1')]), 'unknown')

    def test_reject_and_blackhole_are_blocked_instead_of_bypass(self):
        for flag in (0x8, 0x1000):
            self.assertEqual(self.classify([route('0.0.0.0/0', 'en1', 1 | flag)]), 'blocked')

    def test_local_broadcast_multicast_flags_cannot_create_a_public_bypass(self):
        for flag in (0x200000, 0x400000, 0x800000):
            self.assertEqual(self.classify([route('0.0.0.0/0'), route('8.8.4.4/32', 'en1', 1 | flag)]), 'local')

    def test_defunct_routes_are_ignored_but_active_clone_is_not_hidden(self):
        for flag in (0x2000000, 0x20000000):
            self.assertEqual(self.classify([route('0.0.0.0/0'), route('8.8.4.4/32', 'en1', 1 | flag)]), 'tun')
            self.assertEqual(self.classify([route('8.8.4.4/32', 'en1', 1 | flag)]), 'unknown')
        self.assertEqual(self.classify([route('8.8.4.4/32', 'en1', 1 | 0x20000)]), 'physical_bypass')

    def test_down_missing_and_nonphysical_interfaces_are_unknown(self):
        for interface in ('en2', 'ppp0', 'lo0', 'other'):
            self.assertEqual(self.classify([route('0.0.0.0/0', interface)]), 'unknown')
        self.interfaces['en1'] = 0
        self.assertEqual(self.classify([route('0.0.0.0/0', 'en1')]), 'unknown')

    def test_ipv6_destination_exception_is_independent_of_generic_probes(self):
        rows = [route('::/0'), route('2606:4700:4700::1001/128', 'en1')]
        self.assertEqual(self.classify(rows, '2606:4700:4700::1001'), 'physical_bypass')
        self.assertEqual(self.classify(rows, '2606:4700:4700::1111'), 'tun')

    def test_nonpublic_and_fake_ips_are_local_not_physical_egress_evidence(self):
        for address in ('127.0.0.1', '192.168.1.2', '198.18.0.1', '::1', 'fe80::1', '224.0.0.1'):
            self.assertEqual(self.classify([route('0.0.0.0/0', 'en1')], address), 'local')

    def test_missing_udp_peer_and_bad_data_are_unknown(self):
        for address in (None, '', 'PRIVATE-NOT-AN-ADDRESS'):
            self.assertEqual(self.classify([], address), 'unknown')
        self.assertEqual(self.classify([('PRIVATE-ROUTE', 'en1', 1)]), 'unknown')
        self.assertEqual(self.classify([route('0.0.0.0/0', flags=0)]), 'unknown')

    def test_reader_is_lazy_for_constructor_local_and_unconnected_udp(self):
        factory = Mock(side_effect=AssertionError('unexpected native read'))
        reader = ConnectionRouteReader(factory)
        values = [OwnedSocket(20, 'tcp', '127.0.0.1', 12, '127.0.0.1', 80),
                  OwnedSocket(20, 'udp', None, None, None, None)]
        result = reader(values)
        self.assertEqual([result[value] for value in values], ['local', 'unknown'])
        reader.close()
        factory.assert_not_called()

    def test_reader_passes_only_observed_destinations_and_closes_owned_reader(self):
        network = Mock()
        network._interfaces.return_value = self.interfaces, False
        network._routes.return_value = [route('0.0.0.0/0'), route('8.8.4.4/32', 'en1')]
        factory = Mock(return_value=network)
        reader = ConnectionRouteReader(factory)
        value = OwnedSocket(20, 'tcp', '192.168.1.2', 12, '8.8.4.4', 443)
        self.assertEqual(reader([value])[value], 'physical_bypass')
        self.assertEqual(reader([value])[value], 'physical_bypass')
        factory.assert_called_once()
        network._routes.assert_called_with(destinations=[(4, int(ipaddress.ip_address('8.8.4.4')))])
        reader.close()
        reader.close()
        network.close.assert_called_once()

    def test_reader_failure_does_not_destroy_other_evidence_or_expose_errors(self):
        network = Mock()
        network._interfaces.side_effect = OSError('PRIVATE-ERROR')
        reader = ConnectionRouteReader(lambda: network)
        value = OwnedSocket(20, 'tcp', '192.168.1.2', 12, '8.8.4.4', 443)
        result = reader([value])
        self.assertEqual(result[value], 'unknown')
        self.assertNotIn('PRIVATE', repr(list(result.values())))


if __name__ == '__main__':
    unittest.main()

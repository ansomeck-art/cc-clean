"""Synthetic process/socket/controller snapshots only; never inspect real traffic."""
import copy
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import traffic_evidence as traffic
from mac_guard import ProcessIdentity

MAIN = '/Applications/Claude.app/Contents/MacOS/Claude'
HELPER = '/Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/Contents/MacOS/Claude Helper (Renderer)'
CRASHPAD = '/Applications/Claude.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Helpers/chrome_crashpad_handler'
PRIVATE = 'PRIVATE-NODE-HOST-IDENTIFIER-ERROR'


def identity(pid=400001, path=MAIN, start=100, uid=None):
    return ProcessIdentity(pid, os.getuid() if uid is None else uid, start, 1, path)


def owned(pid=400001, source='198.51.100.2', source_port=55001, destination='203.0.113.8', destination_port=443):
    return traffic.OwnedSocket(pid, 'tcp', source, source_port, destination, destination_port)


def row(identifier='initial', socket=None, kind='Tun', chain=None, path=MAIN):
    socket = socket or owned()
    return {'id': identifier, 'chains': [PRIVATE] if chain is None else chain,
            'metadata': {'network': socket.network, 'type': kind, 'sourceIP': socket.source_ip,
                         'sourcePort': str(socket.source_port), 'destinationIP': socket.destination_ip,
                         'destinationPort': str(socket.destination_port), 'processPath': path,
                         'host': PRIVATE, 'process': 'Claude', 'processPid': socket.pid}}


class Processes:
    def __init__(self, identities):
        self.values = list(identities)
        self.identity = Mock(side_effect=lambda pid: next((item for item in self.values if item.pid == pid), None))
        self.terminate = Mock(side_effect=AssertionError('no process signals'))

    def candidates(self):
        return list(self.values)

    def allowed_path(self, path):
        return path in (MAIN, HELPER, CRASHPAD)


class Runtime:
    def __init__(self, rows=None):
        self.configs = {'mode': 'global', 'tun': {'enable': True}, 'mixed-port': 7890}
        self.proxies = {PRIVATE: {'type': 'Vless', 'server': PRIVATE}}
        self.rows = [row()] if rows is None else rows
        self.read = Mock(side_effect=self.get)

    def get(self, endpoint):
        return copy.deepcopy({'/configs': self.configs, '/proxies': {'proxies': self.proxies},
                              '/connections': {'connections': self.rows}}[endpoint])


class TrafficEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.processes = Processes([identity()])
        self.runtime = Runtime()
        self.reader = Mock(return_value=[owned()])
        self.routes = Mock(side_effect=lambda sockets: {socket: 'unknown' for socket in sockets})
        self.factory = Mock(return_value=self.processes)
        self.observer = traffic.ClaudeTrafficEvidence(self.runtime, self.factory, self.reader, self.routes)

    def group(self, result, name='ClaudeDesktop'):
        return next(group for group in result['groups'] if group['id'] == name)

    def clean(self, result):
        encoded = json.dumps(result)
        for secret in (PRIVATE, '400001', '55001', '198.51.100.', '203.0.113.', '/Applications/'):
            self.assertNotIn(secret, encoded)
        self.assertIs(result['all_traffic_covered'], False)
        self.assertEqual([group['id'] for group in result['groups']], list(traffic.GROUPS))
        for group in result['groups']:
            for dimension in ('ingress_counts', 'transport_counts', 'route_counts'):
                self.assertEqual(sum(group[dimension].values()), group['socket_count'])

    def test_constructor_and_reset_never_observe_or_start_anything(self):
        self.observer.reset()
        self.factory.assert_not_called()
        self.reader.assert_not_called()
        self.runtime.read.assert_not_called()

    def test_no_verified_process_never_reads_controller_or_lsof(self):
        self.processes.values.clear()
        result = self.observer.sample()
        self.assertEqual(result['state'], 'not_running')
        self.reader.assert_not_called()
        self.runtime.read.assert_not_called()
        self.clean(result)

    def test_no_socket_is_unknown_even_with_tun_global_configuration(self):
        self.reader.return_value = []
        result = self.observer.sample()
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(self.group(result)['process_count'], 1)
        self.runtime.read.assert_not_called()
        self.clean(result)

    def test_tun_ingress_and_proxy_transport_are_separate_partial_observations(self):
        result = self.observer.sample()
        self.assertEqual(result['state'], 'observed')
        self.assertEqual(result['route_evidence'], {'tun_enabled': True, 'global_mode': True})
        group = self.group(result)
        self.assertEqual(group['ingress_counts'], dict(tun=1, local_proxy=0, unknown=0))
        self.assertEqual(group['transport_counts'], dict(proxy=1, direct=0, unknown=0))
        self.assertEqual(group['new_connection_count'], 0)
        self.assertEqual({call.args[0] for call in self.runtime.read.call_args_list},
                         {'/configs', '/proxies', '/connections'})
        self.clean(result)

    def test_tun_direct_rule_does_not_get_mislabeled_as_proxy_or_physical_bypass(self):
        self.runtime.rows = [row(chain=['DIRECT'])]
        result = self.observer.sample()
        group = self.group(result)
        self.assertEqual(group['ingress_counts']['tun'], 1)
        self.assertEqual(group['transport_counts'], dict(proxy=0, direct=1, unknown=0))
        self.assertIn('DIRECT 不等同物理直连', result['coverage'])
        self.clean(result)

    def test_unmatched_socket_stays_unknown_despite_names_pid_tun_and_global(self):
        self.runtime.rows[0]['metadata']['sourcePort'] = '55002'
        result = self.observer.sample()
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(self.group(result)['matched_count'], 0)
        self.assertEqual(self.group(result)['transport_counts']['unknown'], 1)
        self.clean(result)

    def test_grouping_uses_verified_paths_and_excludes_unrelated_controller_rows(self):
        self.processes.values.append(identity(400002, HELPER))
        helper = owned(400002, source_port=55002)
        self.reader.return_value = [owned(), helper, helper]
        self.runtime.rows += [row('helper', helper, path=HELPER), row('other', owned(400003, source_port=55003))]
        result = self.observer.sample()
        for name in traffic.GROUPS:
            self.assertEqual(self.group(result, name)['process_count'], 1)
            self.assertEqual(self.group(result, name)['socket_count'], 1)
            self.assertEqual(self.group(result, name)['matched_count'], 1)
        self.clean(result)

    def test_crashpad_uses_helper_group_only_for_exact_verified_claude_canonical_path(self):
        self.processes.values = [identity(400002, CRASHPAD)]
        socket = owned(400002)
        self.reader.return_value = [socket]
        self.runtime.rows = [row('crashpad', socket, path=CRASHPAD)]
        result = self.observer.sample()
        self.assertEqual(self.group(result, 'ClaudeHelper')['matched_count'], 1)
        self.assertEqual(self.group(result)['process_count'], 0)
        for path in (CRASHPAD.replace('/Claude.app/', '/Safari.app/'),
                     CRASHPAD.replace('/Versions/A/', '/Versions/Current/'), '/usr/bin/chrome_crashpad_handler'):
            self.processes.values = [identity(400002, path)]
            self.assertEqual(self.observer.sample()['state'], 'unknown')

    def test_explicit_local_proxy_requires_configured_port_and_matching_controller_source(self):
        socket = owned(source='127.0.0.1', destination='127.0.0.1', destination_port=7890)
        self.reader.return_value = [socket]
        connection = row(socket=socket, kind='HTTP')
        connection['metadata'].update(destinationIP='203.0.113.8', destinationPort='443', inboundPort='7890')
        self.runtime.rows = [connection]
        result = self.observer.sample()
        self.assertEqual(self.group(result)['ingress_counts']['local_proxy'], 1)
        self.clean(result)
        self.runtime.configs['mixed-port'] = 0
        result = self.observer.sample()
        self.assertEqual(self.group(result)['transport_counts']['unknown'], 1)
        self.assertEqual(result['state'], 'unknown')

    def test_controller_process_path_conflict_is_unknown_not_attribution(self):
        self.runtime.rows[0]['metadata']['processPath'] = '/Applications/Safari.app/Contents/MacOS/Safari'
        result = self.observer.sample()
        self.assertEqual(self.group(result)['matched_count'], 0)
        self.clean(result)

    def test_same_tuple_multiple_controller_rows_are_ambiguous(self):
        self.runtime.rows.append(row('another'))
        result = self.observer.sample()
        self.assertEqual(self.group(result)['matched_count'], 0)
        self.assertEqual(self.group(result)['transport_counts']['unknown'], 1)
        self.clean(result)

    def test_unrecognized_rejected_or_mixed_transport_is_unknown(self):
        for chains in ([PRIVATE], ['REJECT'], ['DIRECT', PRIVATE]):
            with self.subTest(chains=chains):
                self.runtime.rows = [row(chain=chains)]
                self.runtime.proxies[PRIVATE]['type'] = 'Selector' if chains == [PRIVATE] else 'Vless'
                result = self.observer.sample()
                self.assertEqual(self.group(result)['transport_counts']['unknown'], 1)
                self.clean(result)

    def test_baseline_counts_only_current_matching_ids_new_since_first_snapshot(self):
        first = self.observer.sample()
        self.assertEqual(self.group(first)['new_connection_count'], 0)
        self.runtime.rows = [row('later'), row('unrelated', owned(400003, source_port=55003))]
        second = self.observer.sample()
        self.assertEqual(self.group(second)['new_connection_count'], 1)
        repeated = self.group(self.observer.sample())
        self.assertEqual(repeated['new_connection_count'], 0)
        self.assertEqual(repeated['new_connection_total'], 1)
        self.observer.reset()
        self.assertEqual(self.group(self.observer.sample())['new_connection_count'], 0)
        self.clean(second)

    def test_new_verified_process_generation_has_its_own_key_without_resetting_lifecycle(self):
        self.observer.sample()
        self.processes.values = [identity(start=200)]
        self.runtime.rows = [row('later')]
        result = self.observer.sample()
        self.assertEqual(self.group(result)['new_connection_count'], 1)
        self.assertEqual(self.group(result)['observed_connection_total'], 2)
        self.clean(result)

    def test_pid_reuse_uid_or_path_change_revokes_all_positive_counts(self):
        for changed in (identity(start=101), identity(uid=os.getuid() + 1),
                        identity(path='/usr/bin/claude')):
            with self.subTest(changed=changed):
                self.processes.identity.side_effect = [identity(), changed]
                result = self.observer.sample()
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(self.group(result)['matched_count'], 0)
                self.assertEqual(self.group(result)['process_count'], 0)
                self.clean(result)

    def test_cli_broad_names_foreign_uid_and_self_are_not_selected(self):
        for candidate in (identity(path='/usr/local/bin/claude'), identity(uid=os.getuid() + 1),
                          identity(pid=os.getpid())):
            with self.subTest(candidate=candidate):
                self.processes.values = [candidate]
                result = self.observer.sample()
                self.assertEqual(result['state'], 'unknown')
                self.reader.assert_not_called()
                self.clean(result)

    def test_socket_and_controller_failure_do_not_publish_raw_errors_or_invent_direct(self):
        self.runtime.read.side_effect = OSError(PRIVATE)
        result = self.observer.sample()
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(self.group(result)['transport_counts'], dict(proxy=0, direct=0, unknown=1))
        self.clean(result)
        self.reader.side_effect = ValueError(PRIVATE)
        self.clean(self.observer.sample())

    def test_invalid_connection_schema_and_duplicate_ids_are_unknown(self):
        for rows in ([row(), row()], {'raw': PRIVATE}, [PRIVATE]):
            with self.subTest(rows=rows):
                self.runtime.rows = rows
                result = self.observer.sample()
                self.assertEqual(result['state'], 'unknown')
                self.assertEqual(self.group(result)['matched_count'], 0)
                self.clean(result)

    def test_unowned_or_invalid_socket_records_do_not_establish_evidence(self):
        for sockets in ([owned(400003)], [PRIVATE], [traffic.OwnedSocket(400001, 'tcp', 'invalid', 1, 'invalid', 2)]):
            with self.subTest(sockets=sockets):
                self.reader.return_value = sockets
                result = self.observer.sample()
                self.assertEqual(result['state'], 'unknown')
                self.clean(result)

    def test_no_packets_or_claude_signals_are_used(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')), \
             patch.object(os, 'kill', side_effect=AssertionError('signal forbidden')):
            self.assertEqual(self.observer.sample()['state'], 'observed')
        self.processes.terminate.assert_not_called()

    def test_adding_helper_does_not_recount_existing_owner_connections(self):
        self.observer.sample()
        self.processes.values.append(identity(400002, HELPER))
        helper = owned(400002, source_port=55002)
        self.reader.return_value = [owned(), helper]
        self.runtime.rows.append(row('new-helper', helper, path=HELPER))
        value = self.observer.sample()
        self.assertEqual(self.group(value)['new_connection_delta'], 0)
        self.assertEqual(self.group(value, 'ClaudeHelper')['new_connection_delta'], 1)
        self.assertEqual(self.group(value)['observed_connection_total'], 1)

    def test_not_running_then_new_owner_does_not_inherit_old_pid_evidence(self):
        self.observer.sample()
        self.processes.values.clear()
        self.assertEqual(self.observer.sample()['state'], 'not_running')
        self.processes.values = [identity(start=200)]
        result = self.observer.sample()
        self.assertEqual(self.group(result)['new_connection_delta'], 1)
        self.assertEqual(self.group(result)['new_connection_total'], 1)

    def test_lru_is_bounded_and_evictions_are_disclosed(self):
        self.observer._capacity = 2
        for index in range(12):
            self.runtime.rows = [row('synthetic-' + str(index))]
            result = self.observer.sample()
        self.assertLessEqual(len(self.observer._seen), 2)
        self.assertGreater(result['history']['dedupe_evictions'], 0)
        self.assertTrue(result['history']['limited'])
        self.assertTrue(result['limited'])
        self.clean(result)

    def test_short_observed_direct_risk_remains_in_lifecycle_history(self):
        self.runtime.rows = [row(chain=['DIRECT'])]
        first = self.observer.sample()
        self.assertEqual(self.group(first)['direct_connection_delta'], 1)
        self.reader.return_value = []
        later = self.observer.sample()
        self.assertEqual(self.group(later)['transport_counts']['direct'], 0)
        self.assertEqual(later['history']['groups'][0]['direct_connection_total'], 1)
        self.assertTrue(later['history']['direct_observed'])
        self.observer.reset()
        self.assertEqual(self.observer.sample()['history']['groups'][0]['direct_connection_total'], 0)

    def test_bounded_controller_recheck_resolves_new_socket_creation_lag(self):
        reads = []
        def runtime_read(endpoint):
            if endpoint == '/connections':
                reads.append(True)
                if len(reads) == 1:
                    return {'connections': []}
            return self.runtime.get(endpoint)
        self.runtime.read.side_effect = runtime_read
        result = self.observer.sample()
        self.assertEqual(len(reads), 2)
        self.assertEqual(self.group(result)['matched_count'], 1)
        self.clean(result)

    def test_native_route_dimension_survives_controller_unavailability(self):
        self.routes.side_effect = lambda sockets: {socket: 'physical_bypass' for socket in sockets}
        self.runtime.read.side_effect = OSError(PRIVATE)
        result = self.observer.sample()
        self.assertEqual(result['state'], 'observed')
        self.assertEqual(self.group(result)['route_counts']['physical_bypass'], 1)
        self.assertEqual(self.group(result)['transport_counts']['unknown'], 1)
        self.assertEqual(self.group(result)['physical_bypass_connection_delta'], 1)
        self.assertIn('controller_unavailable', result['reason_codes'])
        self.clean(result)

    def test_route_failure_does_not_erase_existing_proxy_correlation(self):
        self.routes.side_effect = OSError(PRIVATE)
        result = self.observer.sample()
        self.assertEqual(result['state'], 'observed')
        self.assertEqual(self.group(result)['route_counts']['unknown'], 1)
        self.assertEqual(self.group(result)['transport_counts']['proxy'], 1)
        self.assertEqual(self.group(result)['physical_bypass_connection_total'], 0)
        self.clean(result)

    def test_unconnected_udp_is_counted_unknown_without_becoming_direct_or_bypass(self):
        self.reader.return_value = [traffic.OwnedSocket(400001, 'udp', None, 55001, None, None)]
        result = self.observer.sample()
        self.assertEqual(self.group(result)['socket_count'], 1)
        self.assertEqual(self.group(result)['transport_counts']['unknown'], 1)
        self.assertEqual(self.group(result)['route_counts']['unknown'], 1)
        self.clean(result)

    def test_sampler_close_clears_private_dedup_and_closes_its_route_reader(self):
        self.observer.sample()
        self.observer.close()
        self.assertFalse(self.observer._seen)
        self.routes.close.assert_called_once()
        self.assertEqual(self.observer.sample()['state'], 'unknown')


class LsofBoundaryTests(unittest.TestCase):
    def record(self, pid, protocol, name, state='ESTABLISHED', descriptor='9u'):
        return f'p{pid}\0\nf{descriptor}\0P{protocol}\0n{name}\0TST={state}\0\n'.encode()

    def test_parser_uses_pid_and_socket_fields_not_command_names_and_deduplicates(self):
        raw = self.record(400001, 'TCP', '198.51.100.2:55001->203.0.113.8:443')
        raw += self.record(400001, 'TCP', '198.51.100.2:55001->203.0.113.8:443', descriptor='10u')
        raw += self.record(400002, 'TCP', '[::1]:55002->[::1]:7890')
        raw += self.record(400003, 'TCP', '198.51.100.2:55003->203.0.113.8:443')
        parsed = traffic.parse_lsof(raw, {400001, 400002})
        self.assertEqual(len(parsed), 2)
        self.assertEqual({item.pid for item in parsed}, {400001, 400002})

    def test_listeners_unconnected_udp_and_unestablished_tcp_remain_visible_metadata(self):
        raw = self.record(400001, 'TCP', '*:7890', 'LISTEN')
        raw += self.record(400001, 'UDP', '*:55001', '')
        raw += self.record(400001, 'TCP', '198.51.100.2:55001->203.0.113.8:443', 'SYN_SENT')
        values = traffic.parse_lsof(raw, {400001})
        self.assertEqual(len(values), 3)
        self.assertEqual(sum(value.destination_ip is None for value in values), 2)

    def test_ipv4_mapped_addresses_normalize_without_dns(self):
        raw = self.record(400001, 'UDP', '[::ffff:198.51.100.2]:55001->[::ffff:203.0.113.8]:443', '')
        self.assertEqual(traffic.parse_lsof(raw, {400001})[0],
                         traffic.OwnedSocket(400001, 'udp', '198.51.100.2', 55001, '203.0.113.8', 443))

    def test_argv_always_selects_only_validated_pid_set_and_never_shells_out(self):
        args = traffic.lsof_argv([400002, 400001])
        self.assertEqual(args, ['/usr/sbin/lsof', '-nP', '-a', '-p', '400001,400002', '-i', '-F0pfPnT'])
        for pids in ([], ['400001'], [0], [1], [-1], [os.getpid()], [2**31], list(range(10, 140))):
            with self.subTest(pids=pids):
                with self.assertRaises(ValueError):
                    traffic.lsof_argv(pids)

    def test_raw_parser_limits_and_invalid_utf8_are_rejected(self):
        for raw in (b'x' * (traffic.MAX_LSOF_BYTES + 1), b'\xff'):
            with self.assertRaises(ValueError):
                traffic.parse_lsof(raw, {400001})

    def test_helper_uses_bounded_pipe_and_only_its_own_timeout_cleanup(self):
        process = Mock()
        process.stdout.fileno.return_value = 44
        process.wait.return_value = 0
        process.poll.return_value = 0
        raw = self.record(400001, 'TCP', '198.51.100.2:55001->203.0.113.8:443')
        with patch.object(traffic.subprocess, 'Popen', return_value=process) as launch, \
             patch.object(traffic.select, 'select', return_value=([44], [], [])), \
             patch.object(traffic.os, 'read', side_effect=[raw, b'']):
            self.assertEqual(len(traffic.read_owned_sockets([400001])), 1)
        self.assertEqual(launch.call_args.args[0], traffic.lsof_argv([400001]))
        self.assertNotIn('shell', launch.call_args.kwargs)
        process.kill.assert_not_called()
        process.stdout.close.assert_called_once()
        process.poll.return_value = None
        with patch.object(traffic.subprocess, 'Popen', return_value=process), \
             patch.object(traffic.select, 'select', return_value=([], [], [])):
            with self.assertRaises(ValueError):
                traffic.read_owned_sockets([400001])
        process.kill.assert_called_once_with()

    def test_helper_output_cap_discards_snapshot_and_only_stops_owned_helper(self):
        process = Mock()
        process.stdout.fileno.return_value = 44
        process.poll.return_value = None
        with patch.object(traffic.subprocess, 'Popen', return_value=process), \
             patch.object(traffic.select, 'select', return_value=([44], [], [])), \
             patch.object(traffic.os, 'read', return_value=b'x' * 33), \
             patch.object(traffic, 'MAX_LSOF_BYTES', 32):
            with self.assertRaisesRegex(ValueError, 'limit'):
                traffic.read_owned_sockets([400001])
        process.kill.assert_called_once_with()
        process.stdout.close.assert_called_once()

    def test_default_reader_prefers_native_without_spawning_lsof(self):
        class Unavailable(OSError):
            pass
        module = types.SimpleNamespace(NativeConnectionsUnavailable=Unavailable,
                                       read_native_owned_sockets=Mock(return_value=[owned()]))
        reader = traffic._PreferredSocketReader()
        with patch.dict(sys.modules, {'native_connections': module}), \
             patch.object(traffic, 'read_owned_sockets', side_effect=AssertionError('no fallback spawn')):
            self.assertEqual(reader([400001]), [owned()])
        self.assertEqual(reader.backend, 'native')
        self.assertEqual(reader.interval_floor_ms, 0)

    def test_native_unavailable_fallback_is_explicitly_slow_and_limited(self):
        class Unavailable(OSError):
            pass
        module = types.SimpleNamespace(NativeConnectionsUnavailable=Unavailable,
                                       read_native_owned_sockets=Mock(side_effect=Unavailable('fixed unavailable')))
        reader = traffic._PreferredSocketReader()
        with patch.dict(sys.modules, {'native_connections': module}), \
             patch.object(traffic, 'read_owned_sockets', return_value=[owned()]) as fallback:
            self.assertEqual(reader([400001]), [owned()])
        fallback.assert_called_once_with([400001])
        self.assertEqual(reader.backend, 'lsof_fallback')
        self.assertEqual(reader.interval_floor_ms, 2000)

    def test_unexpected_native_failure_does_not_silently_spawn_fallback(self):
        class Unavailable(OSError):
            pass
        module = types.SimpleNamespace(NativeConnectionsUnavailable=Unavailable,
                                       read_native_owned_sockets=Mock(side_effect=ValueError(PRIVATE)))
        with patch.dict(sys.modules, {'native_connections': module}), \
             patch.object(traffic, 'read_owned_sockets') as fallback:
            with self.assertRaises(ValueError):
                traffic._PreferredSocketReader()([400001])
        fallback.assert_not_called()


if __name__ == '__main__':
    unittest.main()

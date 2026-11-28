"""Read-only connection correlation, never an all-traffic or egress guarantee.

The optional lsof command selects only revalidated Claude PIDs. Hako access uses
its existing current-user socket and GET allowlist. Addresses/paths/controller
IDs are private join keys, never DTO fields or logs. No traffic is generated.
"""
from collections import OrderedDict
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import select
import subprocess
import threading
import time

from mac_guard import ClaudeProcesses, ProcessIdentity
from proxy_runtime import HakoRuntime, TRANSPORTS

MAX_PROCESSES = 128
MAX_SOCKETS = 4096
MAX_CONNECTIONS = 8192
MAX_LSOF_BYTES = 2 * 1024 * 1024
LSOF_TIMEOUT = 2.0
GROUPS = ('ClaudeDesktop', 'ClaudeHelper')
BACKENDS = ('native', 'lsof_fallback', 'injected', 'none')
ROUTES = ('tun', 'physical_bypass', 'blocked', 'local', 'unknown')
HISTORY_KEYS = ('observed_connection_total', 'new_connection_total', 'direct_connection_total',
                'unknown_connection_total', 'physical_bypass_connection_total')
MAX_SEEN_CONNECTIONS = 4096
REASON_CODES = frozenset(('no_verified_claude', 'no_observed_connections', 'traffic_evidence_unavailable',
                          'controller_unavailable', 'route_evidence_unavailable',
                          'no_attributable_controller_connections', 'connection_snapshot_race',
                          'traffic_stale', 'traffic_checking', 'traffic_stopped', 'traffic_worker_stopped'))
_HELPERS = frozenset(('Claude Helper', 'Claude Helper (Renderer)', 'Claude Helper (GPU)',
                      'Claude Helper (Plugin)', 'Claude Helper (Alerts)'))
_PROXY_INGRESS = frozenset(('http', 'https', 'http(s)', 'socks', 'socks4', 'socks5', 'mixed'))
COVERAGE = ('仅持续观察已验证 Claude Desktop/Helper 的 TCP/UDP socket 元数据与 Hako 记录；无对端 socket 为未知。'
            'TUN 是入站证据，代理/DIRECT 是控制器路由选择；DIRECT 不等同物理直连或中国出口。'
            '目的路由是普通未限定作用域的最长前缀结果，不证明 socket 绑定接口、逐包出接口或已发送数据。'
            '两组计数分别按入站与传输维度统计；未匹配连接为未知，不证明全部流量已接管。'
            '不证明应用层传输；不覆盖未读到的短连接、读取间隙或其他应用/CLI。'
            '首次成功样本建立基线；增量与本次观察生命周期累计分开，计数不是唯一服务器事件数。'
            '内部去重有界，淘汰后重见可重复计数；历史与待处理风险不代表当前覆盖。')


@dataclass(frozen=True)
class OwnedSocket:
    pid: int
    network: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int


def _ip(value):
    if not isinstance(value, str) or len(value) > 128:
        return None
    try:
        address = ipaddress.ip_address(value.split('%', 1)[0])
        if getattr(address, 'ipv4_mapped', None) is not None:
            address = address.ipv4_mapped
        return str(address)
    except ValueError:
        return None


def _port(value):
    if type(value) is str and value.isascii() and value.isdigit() and len(value) <= 5:
        value = int(value)
    return value if type(value) is int and 0 < value < 65536 else None


def _endpoint(value):
    address, separator, port = value.rpartition(':')
    address = address.removeprefix('[').removesuffix(']')
    return (_ip(address), _port(port)) if separator else (None, None)


def lsof_argv(pids):
    if (not pids or len(pids) > MAX_PROCESSES or
            any(type(pid) is not int or not 1 < pid < 2**31 or pid == os.getpid() for pid in pids)):
        raise ValueError('invalid selected process set')
    return ['/usr/sbin/lsof', '-nP', '-a', '-p', ','.join(str(pid) for pid in sorted(set(pids))),
            '-i', '-F0pfPnT']


def parse_lsof(raw, allowed_pids):
    """Parse private NUL-delimited lsof fields without trusting command names."""
    if type(raw) is not bytes or len(raw) > MAX_LSOF_BYTES:
        raise ValueError('socket snapshot limit')
    text = raw.decode('utf-8')
    sockets, pid, record = set(), None, {}

    def flush():
        if pid not in allowed_pids or record.get('P') not in ('TCP', 'UDP'):
            return
        name = record.get('n', '')
        if not name:
            return
        source, _, destination = name.partition('->')
        source_ip, source_port = _endpoint(source)
        destination_ip, destination_port = _endpoint(destination) if destination else (None, None)
        sockets.add(OwnedSocket(pid, record['P'].lower(), source_ip, source_port,
                                destination_ip, destination_port))
        if len(sockets) > MAX_SOCKETS:
            raise ValueError('socket count limit')

    for field in text.split('\0'):
        field = field.lstrip('\n')
        if not field:
            continue
        key, value = field[0], field[1:]
        if key == 'p':
            flush()
            pid = int(value) if value.isascii() and value.isdigit() and len(value) <= 10 else None
            record = {}
        elif key == 'f':
            flush()
            record = {}
        elif key == 'T' and value.startswith('ST='):
            record['state'] = value[3:]
        elif key in ('P', 'n'):
            record[key] = value
    flush()
    return list(sockets)


def read_owned_sockets(pids):
    """Bounded helper stdout; never invoke lsof without the selected PID set."""
    process = subprocess.Popen(lsof_argv(pids), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL,
                               env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
    data, deadline = bytearray(), time.monotonic() + LSOF_TIMEOUT
    try:
        descriptor = process.stdout.fileno()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([descriptor], [], [], remaining)[0]:
                raise ValueError('socket snapshot timeout')
            block = os.read(descriptor, min(65536, MAX_LSOF_BYTES + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            if len(data) > MAX_LSOF_BYTES:
                raise ValueError('socket snapshot limit')
        code = process.wait(timeout=max(.001, deadline - time.monotonic()))
        if code not in (0, 1):
            raise ValueError('socket snapshot unavailable')
        return parse_lsof(bytes(data), set(pids))
    finally:
        if process.poll() is None:
            process.kill()  # Only this owned read-only helper, never a Claude PID.
            process.wait(timeout=1)
        process.stdout.close()


def _group(identity):
    path = Path(identity.path)
    if path.parts[-3:] == ('Contents', 'MacOS', 'Claude'):
        return 'ClaudeDesktop'
    name = path.name
    if name in _HELPERS and path.parts[-4:] == (name + '.app', 'Contents', 'MacOS', name):
        return 'ClaudeHelper'
    if path.parts[-7:] == ('Contents', 'Frameworks', 'Electron Framework.framework', 'Versions',
                            'A', 'Helpers', 'chrome_crashpad_handler'):
        return 'ClaudeHelper'  # caller already required the exact verified Claude root
    return None


def _groups():
    return [dict(id=group, process_count=0, socket_count=0, matched_count=0, new_connection_count=0,
                 new_connection_delta=0, new_connection_total=0, observed_connection_total=0,
                 direct_connection_delta=0, direct_connection_total=0,
                 physical_bypass_connection_delta=0, physical_bypass_connection_total=0,
                 unknown_connection_total=0,
                 ingress_counts=dict(tun=0, local_proxy=0, unknown=0),
                 transport_counts=dict(proxy=0, direct=0, unknown=0),
                 route_counts=dict.fromkeys(ROUTES, 0)) for group in GROUPS]


def empty_history():
    return dict(groups=[dict(id=group, **dict.fromkeys(HISTORY_KEYS, 0)) for group in GROUPS],
                direct_observed=False, dedupe_evictions=0, limited=False)


def empty_evidence(state='unknown', reason_codes=()):
    return dict(state=state, groups=_groups(), route_evidence=dict(tun_enabled=None, global_mode=None),
                all_traffic_covered=False, coverage=COVERAGE, reason_codes=list(reason_codes),
                backend='none', interval_floor_ms=0, limited=False, history=empty_history())


class _PreferredSocketReader:
    """Native first; unavailable native support permits a visibly slower fallback."""
    def __init__(self):
        self.backend = 'none'
        self.interval_floor_ms = 0

    def __call__(self, pids):
        try:
            from native_connections import NativeConnectionsUnavailable, read_native_owned_sockets
        except ImportError:
            NativeConnectionsUnavailable = ImportError
            read_native_owned_sockets = None
        if read_native_owned_sockets is not None:
            try:
                self.backend, self.interval_floor_ms = 'native', 0
                return read_native_owned_sockets(pids)
            except NativeConnectionsUnavailable:
                pass
        self.backend, self.interval_floor_ms = 'lsof_fallback', 2000
        return read_owned_sockets(pids)


def _transport(row, proxies):
    chains = row.get('chains')
    if not isinstance(chains, list) or not chains or not all(isinstance(name, str) for name in chains):
        return 'unknown'
    types = []
    for name in chains:
        node = proxies.get(name)
        value = node.get('type') if isinstance(node, dict) else None
        if isinstance(value, str):
            types.append(value.lower())
        if name.upper() == 'DIRECT':
            types.append('direct')
        if name.upper().startswith('REJECT'):
            return 'unknown'
    direct, proxy = 'direct' in types, any(value in TRANSPORTS for value in types)
    return 'direct' if direct and not proxy else 'proxy' if proxy and not direct else 'unknown'


def _matches(socket, row, identity, proxy_ports):
    metadata = row.get('metadata')
    if not isinstance(metadata, dict) or not all((socket.source_ip, socket.source_port,
                                                socket.destination_ip, socket.destination_port)):
        return None
    network = metadata.get('network')
    if (not isinstance(network, str) or network.lower() != socket.network or
            _ip(metadata.get('sourceIP')) != socket.source_ip or
            _port(metadata.get('sourcePort')) != socket.source_port):
        return None
    path = metadata.get('processPath')
    if path and path != identity.path:
        return None  # A conflicting process attribution is not positive evidence.
    kind = metadata.get('type')
    kind = kind.lower() if isinstance(kind, str) else ''
    if kind in _PROXY_INGRESS and ipaddress.ip_address(socket.destination_ip).is_loopback:
        inbound = metadata.get('inboundPort')
        if socket.destination_port in proxy_ports and (inbound is None or _port(inbound) == socket.destination_port):
            return 'local_proxy'
    if (_ip(metadata.get('destinationIP')) == socket.destination_ip and
            _port(metadata.get('destinationPort')) == socket.destination_port):
        return 'tun' if kind == 'tun' else 'unknown'
    return None


class ClaudeTrafficEvidence:
    """Passive snapshots with bounded per-owner connection and risk deduplication.

    Construction is inert. A watch worker owns sampling and closing the optional
    route reader. New-connection counts are deltas; history lasts until reset.
    """
    def __init__(self, runtime=None, processes_factory=ClaudeProcesses, socket_reader=None,
                 route_reader=None, seen_capacity=MAX_SEEN_CONNECTIONS):
        if type(seen_capacity) is not int or not 1 <= seen_capacity <= 65536:
            raise ValueError('invalid connection cache capacity')
        self.runtime = runtime
        self.processes_factory = processes_factory
        self.socket_reader = socket_reader if socket_reader is not None else _PreferredSocketReader()
        self._route_reader = route_reader
        self._lock = threading.Lock()
        self._capacity = seen_capacity
        self._closed = False
        self._reset()

    def _reset(self):
        self._seen = OrderedDict()
        self._totals = {group: dict.fromkeys(HISTORY_KEYS, 0) for group in GROUPS}
        self._primed = False
        self._sample_seq = self._evictions = 0
        self._history_limited = False

    def reset(self):
        with self._lock:
            self._reset()

    def close(self):
        with self._lock:
            self._closed = True
            self._seen.clear()
            reader, self._route_reader = self._route_reader, None
            if reader is not None and callable(getattr(reader, 'close', None)):
                reader.close()

    def _history(self):
        return dict(groups=[dict(id=group, **self._totals[group]) for group in GROUPS],
                    direct_observed=any(value['direct_connection_total'] for value in self._totals.values()),
                    dedupe_evictions=self._evictions, limited=self._history_limited or self._evictions > 0)

    def _touch(self, key):
        value = self._seen.pop(key, None)
        new = value is None
        if new:
            value = {}
        self._seen[key] = value
        while len(self._seen) > self._capacity:
            self._seen.popitem(last=False)
            self._evictions += 1
        return value, new

    def _finish(self, result):
        backend = getattr(self.socket_reader, 'backend', 'injected')
        result['backend'] = backend if backend in BACKENDS else 'injected'
        floor = getattr(self.socket_reader, 'interval_floor_ms', 0)
        result['interval_floor_ms'] = 2000 if result['backend'] == 'lsof_fallback' else 0
        if type(floor) is int and 0 <= floor <= 10000:
            result['interval_floor_ms'] = max(result['interval_floor_ms'], floor)
        result['limited'] |= result['backend'] == 'lsof_fallback' or self._evictions > 0
        self._history_limited |= result['limited']
        result['history'] = self._history()
        for group in result['groups']:
            group.update(self._totals[group['id']])
            group['new_connection_count'] = group['new_connection_delta']
        result['reason_codes'] = sorted(set(result['reason_codes']))
        return result

    @staticmethod
    def _controller(runtime):
        configs = runtime.read('/configs')
        proxy_data = runtime.read('/proxies')
        connection_data = runtime.read('/connections')
        if not all(isinstance(value, dict) for value in (configs, proxy_data, connection_data)):
            raise ValueError('controller schema')
        proxies, rows = proxy_data.get('proxies'), connection_data.get('connections')
        if not isinstance(proxies, dict) or len(proxies) > MAX_CONNECTIONS:
            raise ValueError('controller schema')
        return configs, proxies, ClaudeTrafficEvidence._rows(rows)

    @staticmethod
    def _rows(rows):
        if (not isinstance(rows, list) or len(rows) > MAX_CONNECTIONS or
                any(not isinstance(row, dict) for row in rows)):
            raise ValueError('controller schema')
        values = [row for row in rows if isinstance(row.get('id'), str) and 0 < len(row['id']) <= 256]
        if len({row['id'] for row in values}) != len(values):
            raise ValueError('ambiguous controller snapshot')
        return values

    @staticmethod
    def _correlate(sockets, rows, owners, configs):
        ports = {_port(configs.get(key)) for key in ('port', 'socks-port', 'mixed-port')}
        ports.discard(None)
        indexed = {}
        for row in rows:
            metadata = row.get('metadata')
            if not isinstance(metadata, dict) or not isinstance(metadata.get('network'), str):
                continue
            key = (metadata['network'].lower(), _ip(metadata.get('sourceIP')), _port(metadata.get('sourcePort')))
            indexed.setdefault(key, []).append(row)
        matches = {}
        for socket in sockets:
            rows = indexed.get((socket.network, socket.source_ip, socket.source_port), ())
            candidates = [(row, _matches(socket, row, owners[socket.pid][0], ports)) for row in rows]
            candidates = [(row, ingress) for row, ingress in candidates if ingress is not None]
            if len(candidates) == 1:
                matches[socket] = candidates[0]
        return matches

    def sample(self):
        with self._lock:
            return self._sample()

    def _sample(self):
        result = empty_evidence()
        groups = {group['id']: group for group in result['groups']}
        if self._closed:
            result['reason_codes'] = ['traffic_worker_stopped']
            return self._finish(result)
        try:
            processes = self.processes_factory()
            candidates = processes.candidates()
            if not isinstance(candidates, (list, tuple)) or len(candidates) > MAX_PROCESSES:
                raise ValueError('process count limit')
            owners = {}
            for identity in candidates:
                if (not isinstance(identity, ProcessIdentity) or type(identity.pid) is not int or
                        not 1 < identity.pid < 2**31 or identity.pid == os.getpid() or identity.uid != os.getuid() or
                        not processes.allowed_path(identity.path) or processes.identity(identity.pid) != identity):
                    raise ValueError('process identity unavailable')
                group = _group(identity)
                if group is None or identity.pid in owners:
                    raise ValueError('unsupported process identity')
                owners[identity.pid] = identity, group
            if not owners:
                self._primed = True
                result.update(state='not_running', reason_codes=['no_verified_claude'])
                return self._finish(result)
            for identity, group in owners.values():
                groups[group]['process_count'] += 1
            sockets = self.socket_reader(sorted(owners))
            if (not isinstance(sockets, (list, tuple)) or len(sockets) > MAX_SOCKETS or
                    any(not isinstance(socket, OwnedSocket) or type(socket.pid) is not int or socket.pid not in owners or
                        socket.network not in ('tcp', 'udp') or
                        any(value is not None and _ip(value) != value for value in
                            (socket.source_ip, socket.destination_ip)) or
                        any(value is not None and (type(value) is not int or _port(value) != value) for value in
                            (socket.source_port, socket.destination_port)) for socket in sockets)):
                raise ValueError('invalid owned socket snapshot')
            sockets = set(sockets)
            for socket in sockets:
                groups[owners[socket.pid][1]]['socket_count'] += 1
            if not sockets:
                self._primed = True
                result['reason_codes'] = ['no_observed_connections']
                return self._finish(result)

            routes = {}
            try:
                if self._route_reader is None:
                    from connection_routes import ConnectionRouteReader
                    self._route_reader = ConnectionRouteReader()
                raw_routes = self._route_reader(list(sockets))
                if not isinstance(raw_routes, dict):
                    raise ValueError('route schema')
                for socket in sockets:
                    route = raw_routes.get(socket, 'unknown')
                    routes[socket] = route if type(route) is str and route in ROUTES else 'unknown'
            except Exception:
                result['reason_codes'].append('route_evidence_unavailable')
                result['limited'] = True

            matches, proxies, controller_valid = {}, {}, False
            try:
                runtime = self.runtime if self.runtime is not None else HakoRuntime()
                configs, proxies, rows = self._controller(runtime)
                matches = self._correlate(sockets, rows, owners, configs)
                # One bounded recheck can resolve socket/controller creation lag.
                if len(matches) < len(sockets):
                    response = runtime.read('/connections')
                    if not isinstance(response, dict):
                        raise ValueError('controller schema')
                    rows = self._rows(response.get('connections'))
                    matches = self._correlate(sockets, rows, owners, configs)
                    if len(matches) < len(sockets):
                        result['reason_codes'].append('connection_snapshot_race')
                tun = configs.get('tun')
                if isinstance(tun, dict) and type(tun.get('enable')) is bool:
                    result['route_evidence']['tun_enabled'] = tun['enable']
                if configs.get('mode') in ('global', 'rule', 'direct'):
                    result['route_evidence']['global_mode'] = configs['mode'] == 'global'
                controller_valid = True
            except Exception:
                matches = {}
                result['reason_codes'].append('controller_unavailable')
                result['limited'] = True

            for identity, group in owners.values():
                if processes.identity(identity.pid) != identity:
                    raise ValueError('process identity changed')
            self._sample_seq += 1
            for socket in sockets:
                identity, group_id = owners[socket.pid]
                group, totals = groups[group_id], self._totals[group_id]
                owner = (identity.pid, identity.uid, identity.start_sec, identity.start_usec, identity.path)
                socket_record, _ = self._touch(('socket', owner, socket))
                if socket_record.get('last_sample') != self._sample_seq - 1:
                    socket_record['bypass_active'] = False
                socket_record['last_sample'] = self._sample_seq
                route = routes.get(socket, 'unknown')
                group['route_counts'][route] += 1
                if route == 'physical_bypass':
                    if not socket_record.get('bypass_active'):
                        totals['physical_bypass_connection_total'] += 1
                        group['physical_bypass_connection_delta'] += 1
                    socket_record['bypass_active'] = True
                elif route != 'unknown':
                    socket_record['bypass_active'] = False
                match = matches.get(socket)
                if match is None:
                    group['ingress_counts']['unknown'] += 1
                    group['transport_counts']['unknown'] += 1
                    if not socket_record.get('unknown_seen'):
                        totals['unknown_connection_total'] += 1
                        socket_record['unknown_seen'] = True
                    continue
                row, ingress = match
                record, new = self._touch(('controller', owner, row['id']))
                if new:
                    totals['observed_connection_total'] += 1
                    if self._primed:
                        totals['new_connection_total'] += 1
                        group['new_connection_delta'] += 1
                group['matched_count'] += 1
                group['ingress_counts'][ingress] += 1
                transport = _transport(row, proxies)
                group['transport_counts'][transport] += 1
                if transport == 'direct' and not record.get('direct_seen'):
                    totals['direct_connection_total'] += 1
                    group['direct_connection_delta'] += 1
                    record['direct_seen'] = True
                if transport == 'unknown' and not socket_record.get('unknown_seen'):
                    totals['unknown_connection_total'] += 1
                    socket_record['unknown_seen'] = True
            if controller_valid:
                self._primed = True
            if matches or any(value != 'unknown' for value in routes.values()):
                result['state'] = 'observed'
            else:
                result['reason_codes'].append('no_attributable_controller_connections')
            return self._finish(result)
        except Exception:
            # Invalid ownership revokes every current positive dimension.
            result.update(state='unknown', reason_codes=['traffic_evidence_unavailable'])
            result['groups'] = _groups()
            result['route_evidence'] = dict(tun_enabled=None, global_mode=None)
            result['limited'] = True
            return self._finish(result)

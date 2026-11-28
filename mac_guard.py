"""Read-only Darwin kernel snapshots and narrowly identified Claude Desktop processes.

Only ClaudeProcesses.terminate uses a mutation: SIGKILL to a revalidated, same-user
Claude.app executable, explicitly authorized for the protection feature.
No packet/socket interception, route writes, command-line or credential inspection.
"""
import ctypes
import ipaddress
import os
from pathlib import Path
import plistlib
import select
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass

GLOBAL_IPV6 = ipaddress.IPv6Network('2000::/3')
GLOBAL_IPV6_START = int(GLOBAL_IPV6.network_address)


class RouteHeader(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint16), ('version', ctypes.c_uint8), ('kind', ctypes.c_uint8),
                ('index', ctypes.c_uint16), ('flags', ctypes.c_int32), ('addrs', ctypes.c_int32),
                ('refcnt', ctypes.c_int32), ('parentflags', ctypes.c_int32), ('reserved', ctypes.c_int32),
                ('use', ctypes.c_int32), ('inits', ctypes.c_uint32), ('metrics', ctypes.c_uint32 * 14)]


class IfAddrs(ctypes.Structure):
    pass


IfAddrs._fields_ = [('next', ctypes.POINTER(IfAddrs)), ('name', ctypes.c_char_p),
                   ('flags', ctypes.c_uint), ('addr', ctypes.c_void_p), ('netmask', ctypes.c_void_p),
                   ('dstaddr', ctypes.c_void_p), ('data', ctypes.c_void_p)]


class BsdInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in
                ('flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid', 'ruid', 'rgid', 'svuid', 'svgid', 'reserved')]
    _fields_ += [('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in ('nfiles', 'pgid', 'jobc', 'tdev', 'tpgid')]
    _fields_ += [('nice', ctypes.c_int32), ('start_sec', ctypes.c_uint64), ('start_usec', ctypes.c_uint64)]


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    uid: int
    start_sec: int
    start_usec: int
    path: str


def parse_routes(raw, interface_name, destinations=None, include_broad=False):
    """NET_RT_DUMP2, Darwin 32-bit sockaddr alignment on both x86_64 and arm64."""
    routes = []
    offset, header_size = 0, ctypes.sizeof(RouteHeader)
    while offset < len(raw):
        if offset + header_size > len(raw):
            raise ValueError('truncated route header')
        header = RouteHeader.from_buffer_copy(raw, offset)
        end = offset + header.length
        if header.length < header_size or end > len(raw) or header.version != 5:
            raise ValueError('invalid route record')
        addresses, cursor = {}, offset + header_size
        for bit in range(8):
            if not header.addrs & (1 << bit):
                continue
            if cursor + 2 > end:
                raise ValueError('truncated sockaddr')
            size = raw[cursor]
            step = (size + 3) & ~3 if size else 4
            if cursor + step > end:
                raise ValueError('invalid sockaddr size')
            addresses[bit] = raw[cursor:cursor + size]
            cursor += step
        destination = addresses.get(0, b'')
        if len(destination) >= 2 and destination[1] in (2, 30):
            family = destination[1]
            length, start = (4, 4) if family == 2 else (16, 8)
            if len(destination) < start + length:
                raise ValueError('invalid route address')
            mask = addresses.get(2)
            if mask is None:
                prefix = length * 8 if header.flags & 4 else 0
            else:
                mask_bytes = (mask[start:start + length] + b'\0' * length)[:length]
                inverse = ((1 << (length * 8)) - 1) ^ int.from_bytes(mask_bytes, 'big')
                if inverse & (inverse + 1):
                    raise ValueError('non-contiguous route mask')
                prefix = length * 8 - inverse.bit_length()
            if destinations is not None:
                number = int.from_bytes(destination[start:start + length], 'big')
                mask_number = ((1 << (length * 8)) - 1) ^ ((1 << (length * 8 - prefix)) - 1)
                broad = include_broad and (
                    (family == 2 and prefix <= 1) or
                    (family == 30 and prefix <= 3 and (number ^ GLOBAL_IPV6_START) & mask_number == 0))
                if not broad and not any(
                        size == length and (number ^ target) & mask_number == 0 for size, target in destinations):
                    offset = end
                    continue
            address = ipaddress.ip_address(destination[start:start + length])
            network = ipaddress.ip_network((address, prefix), strict=False)
            routes.append((network, interface_name(header.index), header.flags))
        offset = end
    return routes


def evaluate_network(routes, interfaces, physical_v6):
    """Require unscoped general public routes through an active utun.

    A more-specific physical route overrides a tunnel default. Interface-scoped
    backup routes do not override the unscoped route used for ordinary sockets.
    IPv6 general routing is evaluated over 2000::/3, rather than all non-public
    address classes or a single DNS host. Missing/rejected general IPv6 routes
    mean no currently usable general IPv6 exit was observed, not proof of a
    tunneled IPv6 stack. Arbitrary per-destination exceptions are not exhaustively
    proven by this bounded local check.
    """
    reasons, selected = [], {}
    def route_to(destination, broad_only=False):
        address = ipaddress.ip_address(destination)
        broad_prefix = 1 if address.version == 4 else 3
        matches = [(network.prefixlen, iface, flags) for network, iface, flags in routes
                   if network.version == address.version and address in network and flags & 1
                   and not flags & 0x1000000
                   and (not broad_only or network.prefixlen <= broad_prefix)]  # RTF_IFSCOPE
        if not matches:
            return None
        best = max(prefix for prefix, _, _ in matches)
        return [(iface, flags) for prefix, iface, flags in matches if prefix == best]
    # A handful of DNS-host routes is not TUN ownership. Require a tunnel default
    # or both split /1 routes before using specific destinations as extra checks.
    checks = [('1.1.1.1', True), ('208.67.222.222', True),
              ('1.1.1.1', False), ('8.8.8.8', False)]
    for target, broad_only in checks:
        matches = route_to(target, broad_only)
        if not matches:
            reasons.append('ipv4_route_missing')
            continue
        for iface, flags in matches:
            selected[iface] = True
            if flags & (0x8 | 0x1000):  # reject/blackhole => offline, not a proven healthy tunnel
                reasons.append('route_unreachable')
            elif not iface.startswith('utun'):
                reasons.append('ipv4_bypass')
            elif not interfaces.get(iface, 0) & 1:
                reasons.append('tun_down')
    ipv6_state = 'not_observed'
    if physical_v6:
        ipv6_state = 'no_general_route'
        broad = route_to(str(GLOBAL_IPV6.network_address), broad_only=True)
        if broad:
            usable = False
            for iface, flags in broad:
                if flags & (0x8 | 0x1000):
                    continue
                usable = True
                if not iface.startswith('utun'):
                    reasons.append('ipv6_bypass')
                    ipv6_state = 'bypass'
                elif not interfaces.get(iface, 0) & 1:
                    reasons.append('tun_down')
                    if ipv6_state != 'bypass':
                        ipv6_state = 'tun_down'
                else:
                    selected[iface] = True
            if not usable:
                ipv6_state = 'blocked'
            elif ipv6_state == 'no_general_route':
                ipv6_state = 'tunneled'
        # A narrow DNS-host tunnel/reject cannot hide a physical default route.
        # Conversely, an explicit physical exception to a tunnel default for this
        # probe remains visible; unrelated proxy-node host exceptions are ignored.
        for iface, flags in route_to('2606:4700:4700::1111') or []:
            if flags & (0x8 | 0x1000):
                continue
            if not iface.startswith('utun'):
                reasons.append('ipv6_bypass')
                ipv6_state = 'bypass'
            elif not interfaces.get(iface, 0) & 1:
                reasons.append('tun_down')
                if ipv6_state != 'bypass':
                    ipv6_state = 'tun_down'
            else:
                selected[iface] = True
    return dict(safe=not reasons, reasons=sorted(set(reasons)),
                interfaces=sorted(name for name in selected if name.startswith('utun')),
                ipv6_state=ipv6_state,
                source='darwin-sysctl/getifaddrs')


def route_event_flags(message, interface_name):
    """Return (relevant, critical) without reacting to per-host cache churn.

    Route sockets also carry interface/address records, whose header is not a
    RouteHeader. Their stable prefix is decoded separately from rt_msghdr.
    """
    if len(message) < 4 or message[2] != 5:
        return False, False
    declared = struct.unpack_from('=H', message)[0]
    if declared > len(message) or declared < 4:
        return False, False
    kind = message[3]
    if kind in (0xC, 0xD, 0xE, 0x12):  # NEWADDR, DELADDR, IFINFO, IFINFO2
        if declared < 14:
            return False, False
        index = struct.unpack_from('=H', message, 12)[0]
        name = interface_name(index)
        relevant = name.startswith(('utun', 'en', 'ppp', 'pdp_ip'))
        if not relevant:
            return False, False
        flags = struct.unpack_from('=I', message, 8)[0]
        critical = name.startswith('utun') and (
            kind == 0xD or (kind in (0xE, 0x12) and not flags & 1))
        return True, critical
    if kind not in (1, 2, 3):  # ADD, DELETE, CHANGE; GET responses are not changes
        return False, False
    destinations = [(4, int(ipaddress.ip_address(host))) for host in ('1.1.1.1', '8.8.8.8')]
    destinations.append((16, int(ipaddress.ip_address('2606:4700:4700::1111'))))
    try:
        changes = parse_routes(message[:declared], interface_name, destinations, include_broad=True)
    except (ValueError, OSError, struct.error):
        return False, False
    # Interface-scoped backups and WASCLONED hosts are not effective-default changes.
    changes = [(network, iface, flags) for network, iface, flags in changes
               if not flags & (0x1000000 | 0x20000)]
    critical = kind in (2, 3) and any(
        iface.startswith('utun') and (
            (network.version == 4 and network.prefixlen <= 1) or
            (network.version == 6 and GLOBAL_IPV6.subnet_of(network)))
        for network, iface, _ in changes)
    return bool(changes), critical


class DarwinNetwork:
    """In-process reads: no curl, ifconfig, netstat or subprocess per sample."""
    def __init__(self):
        if sys.platform != 'darwin':
            raise OSError('Darwin only')
        self.libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        self.libc.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                                    ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
        self.libc.sysctl.restype = ctypes.c_int
        self.libc.getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(IfAddrs))]
        self.libc.getifaddrs.restype = ctypes.c_int
        self.libc.freeifaddrs.argtypes = [ctypes.POINTER(IfAddrs)]
        self.libc.if_indextoname.argtypes = [ctypes.c_uint, ctypes.c_char_p]
        self.libc.if_indextoname.restype = ctypes.c_char_p
        self._known_interfaces = {}
        self.events = None
        self.critical_change = False
        try:
            self.events = socket.socket(17, socket.SOCK_RAW, 0)  # PF_ROUTE, receive only
            self.events.setblocking(False)
        except OSError:
            if self.events:
                self.events.close()
            self.events = None  # 100ms polling remains available without route socket permission

    def _interface_name(self, index):
        name = ctypes.create_string_buffer(32)
        if self.libc.if_indextoname(index, name):
            value = name.value.decode('ascii', errors='replace')
            if len(self._known_interfaces) >= 2048:
                self._known_interfaces.clear()
            self._known_interfaces[index] = value
            return value
        # The interface may already be gone by the time its deletion message is
        # consumed. Retain the last observed name so a utun deletion is not lost.
        return self._known_interfaces.get(index, '')

    def _routes(self, destinations=None):
        mib = (ctypes.c_int * 6)(4, 17, 0, 0, 7, 0)  # CTL_NET/PF_ROUTE/AF_UNSPEC/NET_RT_DUMP2
        for _ in range(3):
            size = ctypes.c_size_t()
            if self.libc.sysctl(mib, 6, None, ctypes.byref(size), None, 0):
                raise OSError('route snapshot unavailable')
            if not 0 < size.value <= 8 * 1024 * 1024:
                raise OSError('route snapshot size invalid')
            buffer = ctypes.create_string_buffer(size.value)
            if self.libc.sysctl(mib, 6, buffer, ctypes.byref(size), None, 0) == 0:
                names = {}
                def name(index):
                    if index not in names:
                        names[index] = self._interface_name(index)
                    return names[index]
                if destinations is None:
                    destinations = [(4, int(ipaddress.ip_address(host))) for host in ('1.1.1.1', '8.8.8.8')]
                    destinations.append((16, int(ipaddress.ip_address('2606:4700:4700::1111'))))
                return parse_routes(buffer.raw[:size.value], name, destinations, include_broad=True)
        raise OSError('route snapshot changed repeatedly')

    def _interfaces(self):
        first = ctypes.POINTER(IfAddrs)()
        if self.libc.getifaddrs(ctypes.byref(first)):
            raise OSError('interface snapshot unavailable')
        interfaces, physical_v6 = {}, False
        try:
            entry, count = first, 0
            while entry:
                item = entry.contents
                name = item.name.decode('ascii', errors='replace') if item.name else ''
                interfaces[name] = item.flags
                if item.addr and item.flags & 1 and not name.startswith(('lo', 'utun', 'bridge', 'vmnet')):
                    header = ctypes.string_at(item.addr, 2)
                    if header[1] == 30 and header[0] >= 28:
                        address = ipaddress.IPv6Address(ctypes.string_at(item.addr + 8, 16))
                        if not (address.is_link_local or address.is_loopback or address.is_multicast or address.is_unspecified):
                            physical_v6 = True  # no address/host identifier leaves this method
                entry = item.next
                count += 1
                if count > 10000:
                    raise OSError('interface limit')
        finally:
            self.libc.freeifaddrs(first)
        return interfaces, physical_v6

    def sample(self):
        interfaces, physical_v6 = self._interfaces()
        routes = self._routes()
        result = evaluate_network(routes, interfaces, physical_v6)
        # Host-route cache churn on the same utun must not cause false forced exits.
        result['fingerprint'] = (tuple(result['interfaces']), bool(physical_v6), result['ipv6_state'])
        return result

    def wait(self, timeout):
        if not self.events:
            time.sleep(min(timeout, .1))
            return False
        readable, _, _ = select.select([self.events], [], [], timeout)
        if not readable:
            return False
        self.critical_change = False
        relevant = False
        for _ in range(128):
            try:
                message = self.events.recv(65536)  # never send a route message
                changed, critical = route_event_flags(message, self._interface_name)
                relevant |= changed
                self.critical_change |= critical
            except BlockingIOError:
                break
        return relevant

    def close(self):
        if self.events:
            self.events.close()
            self.events = None


class ClaudeProcesses:
    """Only main + Helper executables inside two explicitly allowed Claude.app roots."""
    def __init__(self, roots=None):
        if sys.platform != 'darwin':
            raise OSError('Darwin only')
        self.lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        self.lib.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_listpids.restype = ctypes.c_int
        self.lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_pidinfo.restype = ctypes.c_int
        self.lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        self.lib.proc_pidpath.restype = ctypes.c_int
        self.lib.proc_name.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        self.lib.proc_name.restype = ctypes.c_int
        self.uid = os.getuid()
        selected_roots = roots if roots is not None else ('/Applications/Claude.app', Path.home() / 'Applications/Claude.app')
        self.roots = [Path(path).resolve() for path in selected_roots]
        self._verified_roots = []
        self._roots_at = float('-inf')

    def _allowed_roots(self):
        if time.monotonic() - self._roots_at < 1:
            return self._verified_roots
        roots = []
        for root in self.roots:
            try:
                with open(root / 'Contents/Info.plist', 'rb') as handle:
                    info = plistlib.loads(handle.read(65536))
                if info.get('CFBundleIdentifier') == 'com.anthropic.claudefordesktop' and info.get('CFBundleExecutable') == 'Claude':
                    roots.append(root)
            except (OSError, ValueError, AttributeError, plistlib.InvalidFileException):
                pass
        self._verified_roots, self._roots_at = roots, time.monotonic()
        return roots

    def allowed_path(self, path):
        path = Path(path)
        for root in self._allowed_roots():
            if path == root / 'Contents/MacOS/Claude':
                return True
            for name in ('Claude Helper', 'Claude Helper (Renderer)', 'Claude Helper (GPU)', 'Claude Helper (Plugin)', 'Claude Helper (Alerts)'):
                if path == root / f'Contents/Frameworks/{name}.app/Contents/MacOS/{name}':
                    return True
            if path == root / 'Contents/Frameworks/Electron Framework.framework/Versions/A/Helpers/chrome_crashpad_handler':
                return True
        return False

    def identity(self, pid):
        if pid <= 1 or pid == os.getpid():
            return None
        before, after = BsdInfo(), BsdInfo()
        if self.lib.proc_pidinfo(pid, 3, 0, ctypes.byref(before), ctypes.sizeof(before)) != ctypes.sizeof(before):
            return None
        if before.uid != self.uid or before.pid != pid:
            return None
        path = ctypes.create_string_buffer(4096)
        if self.lib.proc_pidpath(pid, path, len(path)) <= 0:
            return None
        decoded = os.fsdecode(path.value)
        if not self.allowed_path(decoded):
            return None
        if self.lib.proc_pidinfo(pid, 3, 0, ctypes.byref(after), ctypes.sizeof(after)) != ctypes.sizeof(after):
            return None
        if (before.uid, before.start_sec, before.start_usec) != (after.uid, after.start_sec, after.start_usec):
            return None
        return ProcessIdentity(pid, before.uid, before.start_sec, before.start_usec, decoded)

    def candidates(self):
        if not self._allowed_roots():
            return []
        size = self.lib.proc_listpids(4, self.uid, None, 0)  # PROC_UID_ONLY: no other user's processes
        if size <= 0 or size > 1024 * 1024:
            raise OSError('process enumeration unavailable')
        pids = (ctypes.c_int * (size // 4 + 256))()
        received = self.lib.proc_listpids(4, self.uid, pids, ctypes.sizeof(pids))
        if received <= 0 or received > ctypes.sizeof(pids):
            raise OSError('process enumeration changed')
        found = []
        for pid in pids[:received // 4]:
            name = ctypes.create_string_buffer(64)
            if (self.lib.proc_name(pid, name, len(name)) > 0 and
                    (name.value.startswith(b'Claude') or name.value.startswith(b'chrome_crashpad'))):
                identity = self.identity(pid)
                if identity:
                    found.append(identity)
        return found

    def terminate(self, identity):
        # PID reuse and executable changes are rechecked immediately before the signal.
        if identity.pid <= 1 or identity.pid == os.getpid() or identity.uid != self.uid or self.identity(identity.pid) != identity:
            return 'rejected'
        try:
            os.kill(identity.pid, signal.SIGKILL)
            return 'terminated'
        except ProcessLookupError:
            return 'gone'
        except PermissionError:
            return 'denied'  # never sudo, grant permissions or change process privileges

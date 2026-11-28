"""Read-only routing evidence for observed Claude socket destinations.

Addresses are private in-memory join keys. No function probes a destination,
sends route messages, changes routing or serializes socket/route metadata.
"""
import ipaddress
import threading

from mac_guard import DarwinNetwork

MAX_SOCKETS = 4096
MAX_ROUTES = 32768
ROUTE_STATES = ('tun', 'physical_bypass', 'blocked', 'local', 'unknown')


def _address(value):
    if not isinstance(value, str) or not 0 < len(value) <= 128:
        return None
    try:
        address = ipaddress.ip_address(value)
        return getattr(address, 'ipv4_mapped', None) or address
    except ValueError:
        return None


def _route_index(routes):
    if not isinstance(routes, (list, tuple)) or len(routes) > MAX_ROUTES:
        return None
    buckets = {4: {}, 6: {}}
    try:
        for network, interface, flags in routes:
            if (not isinstance(network, (ipaddress.IPv4Network, ipaddress.IPv6Network))
                    or not isinstance(interface, str) or type(flags) is not int):
                return None
            if not flags & 1 or flags & (0x1000000 | 0x2000000 | 0x20000000):
                continue
            prefix = buckets[network.version].setdefault(network.prefixlen, {})
            prefix.setdefault(int(network.network_address), set()).add(
                (interface, flags & (0x8 | 0x1000 | 0x200000 | 0x400000 | 0x800000)))
    except (TypeError, ValueError):
        return None
    return {version: [(prefix, ((1 << (32 if version == 4 else 128)) - 1) ^
                       ((1 << ((32 if version == 4 else 128) - prefix)) - 1), entries)
                      for prefix, entries in sorted(values.items(), reverse=True)]
            for version, values in buckets.items()}


def _indexed_destination(address, index, interfaces):
    if index is None or not isinstance(interfaces, dict):
        return 'unknown'
    selected = None
    for _prefix, mask, entries in index[address.version]:
        selected = entries.get(int(address) & mask)
        if selected:
            break
    if not selected or len(selected) != 1:
        return 'unknown'
    interface, route_flags = next(iter(selected))
    if route_flags & (0x200000 | 0x400000 | 0x800000):
        return 'local'  # RTF_LOCAL / BROADCAST / MULTICAST are not public egress
    if route_flags & (0x8 | 0x1000):
        return 'blocked'
    value = interfaces.get(interface)
    if type(value) is not int or not value & 1:
        return 'unknown'
    if interface.startswith('utun') and interface[4:].isdigit():
        return 'tun'
    # Do not call PPP, loopback, or an unidentified interface physical bypass.
    if interface.startswith('en') and interface[2:].isdigit():
        return 'physical_bypass'
    return 'unknown'


def classify_destination(destination, routes, interfaces):
    """Only an unambiguous active physical public route is bypass evidence."""
    address = _address(destination)
    if address is None:
        return 'unknown'
    if not address.is_global or address.is_multicast:
        return 'local'
    return _indexed_destination(address, _route_index(routes), interfaces)


class ConnectionRouteReader:
    """Lazily owns one native reader, used only by the connection worker."""
    def __init__(self, network_factory=DarwinNetwork):
        self._factory = network_factory
        self._network = None
        self._lock = threading.Lock()

    def __call__(self, sockets):
        if not isinstance(sockets, (list, tuple)) or len(sockets) > MAX_SOCKETS:
            raise ValueError('connection route observation limit')
        try:
            result = {item: classify_destination(item.destination_ip, (), {}) for item in sockets}
        except (TypeError, AttributeError):
            raise ValueError('invalid connection route input') from None
        public = {item: _address(item.destination_ip) for item in sockets if result[item] != 'local'}
        public = {item: address for item, address in public.items() if address is not None}
        if not public:
            return result
        with self._lock:
            try:
                if self._network is None:
                    self._network = self._factory()
                interfaces, _ = self._network._interfaces()
                destinations = sorted({(4 if address.version == 4 else 16, int(address)) for address in public.values()})
                routes = self._network._routes(destinations=destinations)
                index = _route_index(routes)
                decisions = {address: _indexed_destination(address, index, interfaces) for address in set(public.values())}
                for item, address in public.items():
                    result[item] = decisions[address]
            except Exception:
                for item in public:
                    result[item] = 'unknown'
        return result

    def close(self):
        with self._lock:
            network, self._network = self._network, None
            if network is not None:
                network.close()

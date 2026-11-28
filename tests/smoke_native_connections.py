"""Own-process loopback validation; prints only fixed results, layout and timing.

Use --library for a separately compiled test bridge. No real Claude process or
user connection is selected, and no process signal or external request occurs.
"""
import argparse
from contextlib import ExitStack
import ctypes
import json
import math
import os
from pathlib import Path
import socket
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_connections as native


def run(library_path=None, iterations=30):
    if not 1 <= iterations <= 200:
        raise ValueError("invalid fixture count")
    library = native._load_library(library_path)
    layout = (ctypes.c_uint32 * 10)()
    if library.rg_native_socket_abi(layout, 10):
        raise RuntimeError("native ABI unavailable")
    with ExitStack() as stack:
        def sock(family, kind):
            value = socket.socket(family, kind)
            stack.callback(value.close)
            return value
        listener = sock(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client = stack.enter_context(socket.create_connection(listener.getsockname(), timeout=1))
        accepted, _ = listener.accept()
        stack.callback(accepted.close)
        receiver = sock(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))
        udp = sock(socket.AF_INET, socket.SOCK_DGRAM)
        udp.connect(receiver.getsockname())
        sock(socket.AF_INET, socket.SOCK_DGRAM)  # deliberately unbound, peerless
        tcp_source, tcp_destination = client.getsockname(), client.getpeername()
        udp_source, udp_destination = udp.getsockname(), udp.getpeername()
        ipv6_source = ipv6_destination = None
        try:
            receiver6 = sock(socket.AF_INET6, socket.SOCK_DGRAM)
            receiver6.bind(("::1", 0))
            udp6 = sock(socket.AF_INET6, socket.SOCK_DGRAM)
            udp6.connect(receiver6.getsockname())
            ipv6_source, ipv6_destination = udp6.getsockname(), udp6.getpeername()
        except OSError:
            pass

        def snapshot():
            return native.read_native_owned_sockets([os.getpid()], library_path=library_path, allow_self=True)
        def matched(rows, network, source, destination):
            return any(row.network == network and row.source_ip == source[0] and row.source_port == source[1]
                       and row.destination_ip == destination[0] and row.destination_port == destination[1] for row in rows)
        times = []
        for _ in range(iterations):
            started = time.perf_counter()
            rows = snapshot()
            times.append((time.perf_counter() - started) * 1000)
            if not matched(rows, "tcp", tcp_source, tcp_destination) or not matched(rows, "udp", udp_source, udp_destination):
                raise RuntimeError("own loopback observation missing")
            if not any(row.network == "udp" and row.source_port == udp_destination[1]
                       and row.destination_ip is None and row.destination_port is None for row in rows):
                raise RuntimeError("own unconnected UDP observation missing")
            if not any(row.network == "udp" and row.source_port is None and row.destination_ip is None for row in rows):
                raise RuntimeError("own unbound UDP observation missing")
            if ipv6_source is not None and not matched(rows, "udp", ipv6_source, ipv6_destination):
                raise RuntimeError("own IPv6 observation missing")
        accepted.shutdown(socket.SHUT_WR)
        if client.recv(1) != b"" or not matched(snapshot(), "tcp", tcp_source, tcp_destination):
            raise RuntimeError("own half-closed TCP observation missing")
        return dict(ok=True, backend="darwin_libproc", iterations=iterations,
                    own_loopback_tcp=True, own_half_closed_tcp=True, own_connected_udp=True,
                    own_unconnected_udp=True, own_ipv6_udp=ipv6_source is not None,
                    sdk_layout=dict(zip(("abi_version", "row_size", "proc_bsdinfo_size", "proc_fdinfo_size",
                        "socket_fdinfo_size", "socket_info_offset", "socket_union_offset", "in_sockinfo_size",
                        "tcp_sockinfo_size", "inet_address_offset"), list(layout))),
                    timing_ms=dict(median=round(statistics.median(times), 3),
                        p95=round(sorted(times)[max(0, math.ceil(.95 * len(times)) - 1)], 3), max=round(max(times), 3)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library")
    parser.add_argument("--iterations", type=int, default=30)
    args = parser.parse_args()
    try:
        result = run(args.library, args.iterations)
    except Exception:
        print(json.dumps(dict(ok=False, reason="native_fixture_unavailable")))
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Native fixtures are this process's own loopback sockets; no Claude access."""
import ctypes
import ipaddress
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_connections as native


def row(pid=20, network=6, state=2, family=4, connected=True):
    result = native._Row()
    result.pid, result.network, result.family = pid, network, family
    result.tcp_state = state if network == 6 else 0xffffffff
    result.flags = 15 if connected else 3
    result.source_port, result.destination_port = 12345, 23456 if connected else 0
    source = ipaddress.ip_address("127.0.0.1" if family == 4 else "::1").packed
    result.source_addr[:len(source)] = source
    if connected:
        result.destination_addr[:len(source)] = source
    return result


class FakeLibrary:
    def __init__(self, items=(), outcome=0, reported_count=None):
        self.items, self.outcome, self.reported_count = items, outcome, reported_count
        self.calls = []

    def rg_read_owned_sockets(self, pids, size, rows, cap, own, count):
        self.calls.append((list(pids), size, cap, own))
        for index, item in enumerate(self.items):
            rows[index] = item
        ctypes.cast(count, ctypes.POINTER(ctypes.c_uint32))[0] = (
            len(self.items) if self.reported_count is None else self.reported_count)
        return self.outcome


class BoundaryTests(unittest.TestCase):
    def test_empty_selection_never_loads_or_enumerates(self):
        with patch.object(native, "_load_library", side_effect=AssertionError("must not load")):
            self.assertEqual(native.read_native_owned_sockets([]), [])

    def test_input_pids_and_flags_are_strictly_bounded(self):
        invalid = ([0], [1], [-1], [True], ["20"], [2**31], [20, 20], [20] * 129, {20}, None)
        with patch.object(native, "_load_library", side_effect=AssertionError("invalid input reached bridge")):
            for pids in invalid:
                with self.subTest(pids=pids), self.assertRaises(native.NativeConnectionsUnavailable):
                    native.read_native_owned_sockets(pids)
            with self.assertRaises(native.NativeConnectionsUnavailable):
                native.read_native_owned_sockets([os.getpid()])
            with self.assertRaises(native.NativeConnectionsUnavailable):
                native.read_native_owned_sockets([20], allow_self=1)

    def test_selected_pids_are_the_only_native_input_and_owned_socket_type_matches(self):
        library = FakeLibrary([row(pid=20), row(pid=21, network=17, connected=False)])
        with patch.object(native, "_load_library", return_value=library):
            result = native.read_native_owned_sockets([21, 20])
        from traffic_evidence import OwnedSocket
        self.assertTrue(all(isinstance(item, OwnedSocket) for item in result))
        self.assertEqual(library.calls, [([20, 21], 2, native.MAX_SOCKETS, 0)])
        self.assertEqual(result[0].destination_port, 23456)
        self.assertIsNone(result[1].destination_ip)
        self.assertIsNone(result[1].destination_port)

    def test_pending_and_closing_tcp_states_are_not_established_only(self):
        for state in (0, 2, 3, 4, 5, 6, 7, 8, 9, 10):
            with self.subTest(state=state):
                self.assertEqual(len(native._decode_rows([row(state=state)], 1, {20})), 1)

    def test_invalid_private_abi_rows_fail_unknown_instead_of_partial_success(self):
        malformed = []
        for name, value in (("pid", 99), ("network", 1), ("family", 30), ("flags", 16),
                            ("reserved", 1), ("tcp_state", 1), ("tcp_state", 11),
                            ("source_port", 0), ("destination_port", 65536)):
            item = row()
            setattr(item, name, value)
            malformed.append(item)
        udp = row(network=17)
        udp.tcp_state = 4
        malformed.append(udp)
        padded = row()
        padded.source_addr[15] = 1
        malformed.append(padded)
        missing = row()
        missing.flags &= ~4
        malformed.append(missing)
        for item in malformed:
            with self.subTest(), self.assertRaises(native.NativeConnectionsUnavailable):
                native._decode_rows([row(), item], 2, {20})

    def test_ipv4_mapped_ipv6_is_canonicalized(self):
        item = row(family=6)
        mapped = ipaddress.ip_address("::ffff:127.0.0.1").packed
        item.source_addr[:] = mapped
        item.destination_addr[:] = mapped
        result = native._decode_rows([item], 1, {20})[0]
        self.assertEqual(result.source_ip, "127.0.0.1")
        self.assertEqual(result.destination_ip, "127.0.0.1")

    def test_unbound_udp_is_retained_with_missing_ports_and_peer(self):
        item = row(network=17, connected=False)
        item.flags, item.source_port = 1, 0
        item.source_addr[:] = bytes(16)
        result = native._decode_rows([item], 1, {20})[0]
        self.assertIsNone(result.source_ip)
        self.assertIsNone(result.source_port)
        self.assertIsNone(result.destination_ip)

    def test_native_errors_and_overflow_never_become_zero_sockets(self):
        for library in (FakeLibrary(outcome=1), FakeLibrary(outcome=2), FakeLibrary(outcome=3),
                        FakeLibrary([row()], reported_count=native.MAX_SOCKETS + 1)):
            with self.subTest(), patch.object(native, "_load_library", return_value=library), \
                    self.assertRaisesRegex(native.NativeConnectionsUnavailable, "^native connection snapshot unavailable$"):
                native.read_native_owned_sockets([20])

    def test_exception_text_and_library_path_are_not_exported(self):
        with patch.object(native, "_load_library", side_effect=OSError("secret-fixture-library-path")):
            with self.assertRaises(native.NativeConnectionsUnavailable) as raised:
                native.read_native_owned_sockets([20])
        self.assertNotIn("secret", str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)

    def test_non_darwin_platform_is_fixed_unavailable(self):
        with patch.object(native.sys, "platform", "win32"), self.assertRaises(native.NativeConnectionsUnavailable):
            native._load_library()

    def test_backend_availability_never_reads_processes_or_exposes_errors(self):
        library = FakeLibrary()
        with patch.object(native, "_load_library", return_value=library):
            self.assertIs(native.native_backend_available(), True)
        self.assertEqual(library.calls, [])
        with patch.object(native, "_load_library", side_effect=OSError("secret-fixture-library")):
            self.assertIs(native.native_backend_available(), False)

    def test_source_and_frozen_library_locations_are_fixed(self):
        with patch.object(native.sys, "frozen", False, create=True):
            self.assertEqual(native._default_path().name, "_native_connections.dylib")
            self.assertEqual(native._default_path().parent.name, "native_connections")
        with patch.object(native.sys, "frozen", True, create=True), \
                patch.object(native.sys, "_MEIPASS", "/private/fixture-frameworks", create=True):
            self.assertEqual(native._default_path(), Path("/private/fixture-frameworks/_native_connections.dylib"))

    def test_library_symlink_or_writable_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="rg-native-trust-") as directory:
            root = Path(directory).resolve()
            target = root / "fixture.dylib"
            target.write_bytes(b"fixture")
            target.chmod(0o777)
            with self.assertRaises(native.NativeConnectionsUnavailable):
                native._library_signature(target)
            target.chmod(0o700)
            link = root / "alias.dylib"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                native._library_signature(link)


@unittest.skipUnless(sys.platform == "darwin", "Darwin SDK/libproc required")
class NativeSDKTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="rg-native-sdk-")
        cls.library_path = Path(cls.temporary.name).resolve() / "_native_fixture.dylib"
        source = Path(__file__).resolve().parents[1] / "native_connections.c"
        command = ["/usr/bin/xcrun", "clang", "-dynamiclib", "-O2", "-Wall", "-Wextra", "-Werror",
                   "-DRG_NATIVE_TESTING=1", str(source), "-lproc", "-o", str(cls.library_path)]
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        if result.returncode:
            cls.temporary.cleanup()
            raise RuntimeError("native SDK fixture compilation failed")
        cls.library = native._load_library(cls.library_path)
        cls.library.rg_native_decode_fixture.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(native._Row)]
        cls.library.rg_native_decode_fixture.restype = ctypes.c_int
        cls.library.rg_native_owner_fixture.argtypes = [ctypes.c_uint32]
        cls.library.rg_native_owner_fixture.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def snapshot(self):
        return native.read_native_owned_sockets([os.getpid()], library_path=self.library_path, allow_self=True)

    def test_sdk_compiled_layout_is_native_and_private_bridge_is_64_bytes(self):
        layout = (ctypes.c_uint32 * 10)()
        self.assertEqual(self.library.rg_native_socket_abi(layout, 10), 0)
        self.assertEqual(list(layout)[:2], [1, 64])
        self.assertEqual(layout[3], 8)
        self.assertGreater(layout[4], layout[5] + layout[6] + layout[8])
        self.assertEqual(native._Row.source_addr.offset, 32)

    def test_sdk_tcp_states_include_syn_and_closing_and_skip_only_listen(self):
        for state in range(11):
            item = native._Row()
            result = self.library.rg_native_decode_fixture(0, state, ctypes.byref(item))
            self.assertEqual(result, 0 if state == 1 else 1)
            if result:
                self.assertEqual(item.tcp_state, state)
                self.assertEqual(native._decode_rows([item], 1, {20})[0].destination_port, 23456)
        item = native._Row()
        self.assertEqual(self.library.rg_native_decode_fixture(0, 11, ctypes.byref(item)), -1)

    def test_sdk_udp_peerless_and_ipv6_decoding(self):
        for scenario, network, peer in ((1, "udp", True), (2, "udp", False), (3, "tcp", True), (4, "udp", True)):
            item = native._Row()
            self.assertEqual(self.library.rg_native_decode_fixture(scenario, 4, ctypes.byref(item)), 1)
            result = native._decode_rows([item], 1, {20})[0]
            self.assertEqual(result.network, network)
            self.assertEqual(result.destination_port is not None, peer)
        for scenario in (6, 7, 8):
            item = native._Row()
            self.assertEqual(self.library.rg_native_decode_fixture(scenario, 4, ctypes.byref(item)), -1)

    def test_sdk_owner_uid_pid_and_flags_are_checked_without_other_processes(self):
        self.assertEqual(self.library.rg_native_owner_fixture(0), 0)
        for scenario in range(1, 8):
            self.assertNotEqual(self.library.rg_native_owner_fixture(scenario), 0)

    def test_real_own_loopback_tcp_and_half_closed_connection(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client = accepted = None
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            client = socket.create_connection(listener.getsockname(), timeout=1)
            accepted, _ = listener.accept()
            source, destination = client.getsockname(), client.getpeername()
            def found():
                return any(item.network == "tcp" and item.source_ip == source[0] and item.source_port == source[1]
                           and item.destination_ip == destination[0] and item.destination_port == destination[1]
                           for item in self.snapshot())
            self.assertTrue(found(), "own connected TCP tuple missing")
            accepted.shutdown(socket.SHUT_WR)
            self.assertEqual(client.recv(1), b"")
            self.assertTrue(found(), "own half-closed TCP tuple missing")
        finally:
            for item in (accepted, client, listener):
                if item is not None:
                    item.close()

    def test_real_own_udp_with_and_without_peer_including_unbound(self):
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connected = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        unbound = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            receiver.bind(("127.0.0.1", 0))
            connected.connect(receiver.getsockname())
            source = connected.getsockname()
            items = self.snapshot()
            self.assertTrue(any(item.network == "udp" and item.source_port == source[1]
                                and item.destination_port == receiver.getsockname()[1] for item in items))
            self.assertTrue(any(item.network == "udp" and item.source_port == receiver.getsockname()[1]
                                and item.destination_ip is None and item.destination_port is None for item in items))
            self.assertTrue(any(item.network == "udp" and item.source_port is None and item.destination_ip is None for item in items))
        finally:
            connected.close()
            receiver.close()
            unbound.close()

    def test_real_own_ipv6_loopback_udp(self):
        receiver = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        connected = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            try:
                receiver.bind(("::1", 0))
            except OSError:
                self.skipTest("IPv6 loopback unavailable")
            connected.connect(receiver.getsockname())
            source = connected.getsockname()
            self.assertTrue(any(item.network == "udp" and item.source_ip == "::1" and item.source_port == source[1]
                                and item.destination_ip == "::1" and item.destination_port == receiver.getsockname()[1]
                                for item in self.snapshot()))
        finally:
            receiver.close()
            connected.close()

    def test_native_self_requires_explicit_fixture_opt_in(self):
        pids = (ctypes.c_int32 * 1)(os.getpid())
        rows = (native._Row * 1)()
        count = ctypes.c_uint32(999)
        outcome = self.library.rg_read_owned_sockets(pids, 1, rows, 1, 0, ctypes.byref(count))
        self.assertNotEqual(outcome, 0)
        self.assertEqual(count.value, 0)


if __name__ == "__main__":
    unittest.main()

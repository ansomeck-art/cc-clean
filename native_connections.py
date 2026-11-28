"""Private native socket join keys for an already verified Claude PID list.

No subprocesses, all-process scans, names, signals, packets or decryption. The
SDK-compiled bridge consumes Darwin structs and exposes only a 64-byte private
ABI. Returned addresses belong in correlation memory, never in a user DTO/log.
"""
import ctypes
import ipaddress
import os
from pathlib import Path
import stat
import sys
import threading


MAX_PROCESSES = 128
MAX_SOCKETS = 4096
ABI_VERSION = 1
_MESSAGE = "native connection snapshot unavailable"
_LOCK = threading.Lock()
_CACHE = {}


class NativeConnectionsUnavailable(RuntimeError):
    def __init__(self):
        super().__init__(_MESSAGE)


class _Row(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_int32), ("network", ctypes.c_uint32), ("family", ctypes.c_uint32),
                ("flags", ctypes.c_uint32), ("source_port", ctypes.c_uint32), ("destination_port", ctypes.c_uint32),
                ("tcp_state", ctypes.c_uint32), ("reserved", ctypes.c_uint32),
                ("source_addr", ctypes.c_uint8 * 16), ("destination_addr", ctypes.c_uint8 * 16)]


def _default_path():
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "_native_connections.dylib"
    return Path(__file__).absolute().parent / "build/native_connections/_native_connections.dylib"


def _library_signature(path):
    """Validate the selected build artifact, without following any path symlink."""
    if ".." in path.parts:
        raise NativeConnectionsUnavailable()
    uid = os.getuid()
    handles = []
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        root = os.open(path.anchor, flags | os.O_DIRECTORY)
        handles.append(root)
        parent = root
        for index, part in enumerate(path.parts[1:], 1):
            directory = index < len(path.parts) - 1
            fd = os.open(part, flags | (os.O_DIRECTORY if directory else os.O_NONBLOCK), dir_fd=parent)
            handles.append(fd)
            info = os.fstat(fd)
            if info.st_uid not in (0, uid):
                raise NativeConnectionsUnavailable()
            if directory:
                if not stat.S_ISDIR(info.st_mode):
                    raise NativeConnectionsUnavailable()
                parent = fd
            elif (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or
                  not 0 < info.st_size <= 16 * 1024 * 1024):
                raise NativeConnectionsUnavailable()
        return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
    finally:
        for fd in reversed(handles):
            os.close(fd)


def _load_library(library_path=None):
    if sys.platform != "darwin":
        raise NativeConnectionsUnavailable()
    path = _default_path() if library_path is None else Path(os.path.abspath(os.fspath(library_path)))
    try:
        before = _library_signature(path)
        with _LOCK:
            cached = _CACHE.get(str(path))
            if cached is not None:
                if cached[0] != before:
                    raise NativeConnectionsUnavailable()
                return cached[1]
            library = ctypes.CDLL(str(path))
            library.rg_native_socket_abi.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32]
            library.rg_native_socket_abi.restype = ctypes.c_int
            layout = (ctypes.c_uint32 * 10)()
            if (ctypes.sizeof(_Row) != 64 or library.rg_native_socket_abi(layout, 10) != 0
                    or layout[0] != ABI_VERSION or layout[1] != ctypes.sizeof(_Row)
                    or layout[3] != 8 or not all(0 < layout[index] < 65536 for index in (2, 4, 5, 6, 7, 8, 9))):
                raise NativeConnectionsUnavailable()
            library.rg_read_owned_sockets.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.c_uint32,
                ctypes.POINTER(_Row), ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
            library.rg_read_owned_sockets.restype = ctypes.c_int
            if _library_signature(path) != before:
                raise NativeConnectionsUnavailable()
            _CACHE[str(path)] = before, library
            return library
    except Exception:
        raise NativeConnectionsUnavailable() from None


def _address(raw, family, present):
    data = bytes(raw)
    if family == 4:
        if any(data[4:]):
            raise NativeConnectionsUnavailable()
        data = data[:4]
    if not present:
        if any(data):
            raise NativeConnectionsUnavailable()
        return None
    address = ipaddress.ip_address(data)
    if getattr(address, "ipv4_mapped", None) is not None:
        address = address.ipv4_mapped
    if address.is_unspecified:
        return None
    return str(address)


def _port(value, present):
    if present and 0 < value < 65536:
        return int(value)
    if not present and value == 0:
        return None
    raise NativeConnectionsUnavailable()


def _decode_rows(rows, count, allowed):
    # Late import avoids traffic_evidence -> native_connections -> OwnedSocket cycles.
    from traffic_evidence import OwnedSocket
    if not 0 <= count <= MAX_SOCKETS:
        raise NativeConnectionsUnavailable()
    result = []
    for row in rows[:count]:
        if (row.pid not in allowed or row.network not in (6, 17) or row.family not in (4, 6)
                or row.flags & ~15 or row.reserved or
                row.network == 6 and (not 0 <= row.tcp_state <= 10 or row.tcp_state == 1) or
                row.network == 17 and row.tcp_state != 0xffffffff):
            raise NativeConnectionsUnavailable()
        source = _address(row.source_addr, row.family, row.flags & 1)
        destination = _address(row.destination_addr, row.family, row.flags & 4)
        if destination is not None and ipaddress.ip_address(destination).is_unspecified:
            raise NativeConnectionsUnavailable()
        result.append(OwnedSocket(int(row.pid), "tcp" if row.network == 6 else "udp", source,
                                 _port(row.source_port, row.flags & 2), destination,
                                 _port(row.destination_port, row.flags & 8)))
    return result


def read_native_owned_sockets(pids, *, library_path=None, allow_self=False):
    """Return verified-PID TCP states/UDP endpoints or one fixed unavailable error.

    LISTEN sockets are excluded. Unconnected UDP remains an observation with a
    missing peer. ``allow_self=True`` is an explicit own-loopback fixture hook;
    production callers retain the default. Endpoint/PID membership is checked
    again at this boundary. Caller still revalidates full Claude identities.
    """
    if (type(pids) not in (list, tuple) or len(pids) > MAX_PROCESSES or type(allow_self) is not bool
            or any(type(pid) is not int or not 1 < pid < 2**31 or not allow_self and pid == os.getpid() for pid in pids)
            or len(set(pids)) != len(pids)):
        raise NativeConnectionsUnavailable()
    if not pids:
        return []
    try:
        library = _load_library(library_path)
        selected = (ctypes.c_int32 * len(pids))(*sorted(pids))
        rows = (_Row * MAX_SOCKETS)()
        count = ctypes.c_uint32()
        outcome = library.rg_read_owned_sockets(selected, len(pids), rows, MAX_SOCKETS,
                                                int(allow_self), ctypes.byref(count))
        if outcome != 0 or count.value > MAX_SOCKETS:
            raise NativeConnectionsUnavailable()
        return _decode_rows(rows, count.value, set(pids))
    except Exception:
        raise NativeConnectionsUnavailable() from None


def native_backend_available():
    """Check only the fixed bridge file/ABI; never query a PID or descriptor."""
    try:
        _load_library()
        return True
    except Exception:
        return False

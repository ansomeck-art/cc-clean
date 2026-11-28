"""Read-only observation of Claude's local Sentry culture/environment metadata.

The worker owns all filesystem work. ``sample`` only copies a sanitized cache;
it never reads a file or waits for a scan. Events accelerate stat polling but are
not a promise of instantaneous observation or of coverage of uploaded telemetry.
"""
import json
import os
from pathlib import Path
import re
import select
import stat
import sys
import threading
import time


MAX_SCOPE_BYTES = 1024 * 1024
INTERVALS_MS = frozenset((50, 100, 250, 500))
COVERAGE = ("仅观察本地 Sentry scope 的明确文化/环境元数据；不判断账号国籍。"
            "文件缺失表示未验证；不读取离线队列正文，不覆盖上传请求或未观察到的瞬时变化。")
_PENDING = "telemetry_file_pending"
_UNKNOWN = "telemetry_file_unknown"
_COUNTRY_KEYS = frozenset(("country", "countrycode", "countryisocode", "countryiso2", "countryiso3",
                           "countrycodeiso2", "countrycodeiso3", "ipcountry", "geocountry",
                           "geocountrycode", "clientcountry", "systemcountry", "oscountry",
                           "usercountry", "countryname", "countryofresidence"))
_REGION_KEYS = frozenset(("region", "regioncode", "georegion", "clientregion", "systemregion", "osregion"))
_LOCALE_KEYS = frozenset(("locale", "locales", "systemlocale", "oslocale", "userlocale", "applocale",
                          "browserlocale", "devicelocale", "preferredlocales", "languages",
                          "preferredlanguages"))
_TZ_KEYS = frozenset(("timezone", "tz", "timezoneid", "timezonename", "ostimezone", "systemtimezone",
                      "clienttimezone", "browsertimezone", "geotimezone", "devicetimezone"))
_CHINA = frozenset(("cn", "chn", "prc", "156", "china", "mainlandchina", "chinamainland",
                    "prchina", "peoplesrepublicofchina", "中国", "中国大陆", "中华人民共和国"))
_CHINA_TZ = frozenset(("asia/shanghai", "asia/chongqing", "asia/chungking", "asia/harbin",
                       "asia/urumqi", "asia/kashgar", "prc"))


def _key(value):
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("ambiguous metadata")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError("invalid metadata number")


def _inspect(raw):
    """Return only static classifications; never traverse arbitrary event content."""
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_invalid_constant)
        if not isinstance(obj, dict):
            raise ValueError("invalid scope")
        containers, cultures, incomplete = [], [], False
        for envelope in (obj, obj.get("event")):
            if not isinstance(envelope, dict):
                continue
            containers.append(envelope)
            for name in ("metadata", "environment", "env"):
                if isinstance(envelope.get(name), dict):
                    containers.append(envelope[name])
            contexts = envelope.get("contexts")
            if isinstance(contexts, dict):
                if "culture" in contexts:
                    culture = contexts["culture"]
                    if isinstance(culture, dict):
                        cultures.append(culture)
                        containers.append(culture)
                    else:
                        incomplete = True
                for name in ("environment", "geo", "os", "device"):
                    if isinstance(contexts.get(name), dict):
                        containers.append(contexts[name])

        fields, reasons = set(), set()
        for metadata in containers:
            for name, value in metadata.items():
                normalized = _key(name)
                kind = ("country" if normalized in _COUNTRY_KEYS or normalized in _REGION_KEYS else
                        "locale" if normalized in _LOCALE_KEYS else
                        "timezone" if normalized in _TZ_KEYS else None)
                if not kind:
                    continue
                fields.add(kind)
                values = value if isinstance(value, list) else [value]
                if not values or len(values) > 64:
                    incomplete = True
                    continue
                for item in values:
                    if (type(item) not in (str, int) or isinstance(item, bool)
                            or not str(item).strip() or len(str(item)) > 256):
                        incomplete = True
                        continue
                    text = str(item).strip()
                    if kind == "country":
                        country = re.sub(r"[\s.'’()_-]", "", text.lower())
                        if country in _CHINA or (normalized in _REGION_KEYS and
                                                 re.fullmatch(r"cn(?:[-_][a-z0-9]+)*", text, re.I)):
                            reasons.add("telemetry_cn_country")
                    elif kind == "locale":
                        locale = text.replace("_", "-").split(".")[0]
                        if re.match(r"^[a-z]{2,3}(?:-[a-z]{4})?-cn(?:-|$)", locale, re.I):
                            reasons.add("telemetry_cn_locale")
                    elif text.lower() in _CHINA_TZ:
                        reasons.add("telemetry_cn_timezone")

        # Optional culture fields are often absent while Electron initializes.
        # Missing evidence is observation-only, never affirmative China evidence.
        complete = bool(cultures) and all(
            all(isinstance(culture.get(name), str) and 0 < len(culture[name].strip()) <= 256
                for name in ("locale", "timezone")) for culture in cultures)
        if reasons:
            return "risk", sorted(reasons), sorted(fields)
        if incomplete:
            return "unknown", [_UNKNOWN], sorted(fields)
        if not complete:
            return "observed", [], sorted(fields)
        return "safe", [], sorted(fields)
    except (ValueError, TypeError, AttributeError, UnicodeError, RecursionError, OverflowError):
        return "unknown", [_UNKNOWN], []


def _file_stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


class _Probe:
    def __init__(self):
        self.descriptors = []
        self.file_fd = None
        self.state = "unknown"
        self.signature = None

    def close(self):
        for _level, fd, _stamp, _directory in reversed(self.descriptors):
            try:
                os.close(fd)
            except OSError:
                pass
        self.descriptors.clear()


class _BackendFailed(Exception):
    pass


class _KqueueEvents:
    """Worker-owned vnode subscriptions, with a private wake pipe for lifecycle calls."""
    label = "kqueue+stat"

    def __init__(self):
        self._lock = threading.Lock()
        self._queue = select.kqueue()
        self._read_fd = self._write_fd = None
        self._watched = {}
        try:
            self._read_fd, self._write_fd = os.pipe()
            os.set_blocking(self._read_fd, False)
            os.set_blocking(self._write_fd, False)
            self._queue.control([select.kevent(self._read_fd, filter=select.KQ_FILTER_READ,
                flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR)], 0, 0)
        except Exception:
            self.close()
            raise

    def synchronize(self, probe):
        directories = [item for item in probe.descriptors if item[3]][-3:]
        desired = directories + [item for item in probe.descriptors if not item[3]]
        keys = {(level, stamp[0], stamp[1], directory): fd
                for level, fd, stamp, directory in desired}
        for key in list(self._watched):
            if key not in keys:
                os.close(self._watched.pop(key))  # closing removes the vnode subscription
        notes = 0
        for name in ("KQ_NOTE_WRITE", "KQ_NOTE_EXTEND", "KQ_NOTE_ATTRIB", "KQ_NOTE_DELETE",
                     "KQ_NOTE_RENAME", "KQ_NOTE_REVOKE"):
            notes |= getattr(select, name, 0)
        for key, source in keys.items():
            if key not in self._watched:
                fd = os.dup(source)
                try:
                    self._queue.control([select.kevent(fd, filter=select.KQ_FILTER_VNODE,
                        flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR, fflags=notes)], 0, 0)
                except Exception:
                    os.close(fd)
                    raise
                self._watched[key] = fd

    def wake(self):
        with self._lock:
            if self._write_fd is not None:
                try:
                    os.write(self._write_fd, b"\0")
                except OSError:
                    pass

    def wait(self, timeout):
        events = self._queue.control(None, 32, timeout)
        for event in events:
            if event.ident == self._read_fd:
                try:
                    while os.read(self._read_fd, 4096):
                        pass
                except BlockingIOError:
                    pass
        return bool(events)

    def close(self):
        with self._lock:
            for fd in self._watched.values():
                os.close(fd)
            self._watched.clear()
            for name in ("_read_fd", "_write_fd"):
                fd = getattr(self, name)
                if fd is not None:
                    os.close(fd)
                    setattr(self, name, None)
            if self._queue is not None:
                self._queue.close()
                self._queue = None


class ClaudeTelemetryWatch:
    """Asynchronous, sanitized cache for one fixed Sentry scope file.

    ``reader(fd, limit)`` and ``clock()`` can be injected for isolated tests. A
    reader must return at most ``limit + 1`` bytes from the already validated fd.
    ``acknowledge`` consumes a risk latch, not the current file's classification.
    A stopped or unexpectedly exited worker requires an explicit ``start``;
    unexpected exits and restarts preserve unacknowledged risks.
    No method signals Claude, modifies its files, or configures network traffic.
    """
    def __init__(self, scope_path=None, interval_ms=100, clock=time.monotonic, reader=None):
        if type(interval_ms) is not int or interval_ms not in INTERVALS_MS:
            raise ValueError("unsupported observation interval")
        path = Path(scope_path) if scope_path is not None else (
            Path.home() / "Library/Application Support/Claude/sentry/scope_v3.json")
        if ".." in path.parts:
            raise ValueError("scope path must be normalized")
        self._path = Path(os.path.abspath(os.fspath(path)))
        self._uid = os.getuid() if hasattr(os, "getuid") else None
        self._clock = clock
        self._reader = reader or self._read
        self._lock = threading.RLock()
        self._lifecycle = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread = self._backend = None
        self._interval_ms = interval_ms
        self._generation = 0
        self._explicitly_stopped = False
        self._failed = False
        self._callback = None
        self._checked_at = None
        self._cache_signature = self._cache_result = None
        self._risk_latch = None
        self._state = dict(state="checking", reason_codes=[_PENDING], field_types=[], last_scan_ms=0,
                           backend="stat", coverage=COVERAGE, files_checked=0, event_seq=0)

    @staticmethod
    def _read(fd, limit):
        chunks, size = [], 0
        while size <= limit:
            block = os.read(fd, min(65536, limit + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
        return b"".join(chunks)

    def set_callback(self, callback):
        if callback is not None and not callable(callback):
            raise TypeError("callback must be callable")
        with self._lock:
            self._callback = callback

    def _notify(self, callback):
        if callback is not None:
            try:
                callback()
            except Exception:
                pass  # neither exception text nor metadata may leave this worker

    def _view(self):
        view = dict(self._state)
        if self._risk_latch is not None and view["state"] != "stopped":
            view.update(self._risk_latch)
        view["reason_codes"] = list(view["reason_codes"])
        view["field_types"] = list(view["field_types"])
        view["last_check_age_ms"] = (None if self._checked_at is None else
                                      round(max(0, self._clock() - self._checked_at) * 1000, 3))
        return view

    def sample(self):
        with self._lock:
            lazy = not self._explicitly_stopped and not self._failed and self._thread is None
        if lazy:
            self._start(lazy=True)
        with self._lock:
            return self._view()

    def configure(self, interval_ms):
        if type(interval_ms) is not int or interval_ms not in INTERVALS_MS:
            raise ValueError("unsupported observation interval")
        with self._lock:
            self._interval_ms = interval_ms
            self._wake.set()
            if self._backend is not None:
                self._backend.wake()

    def start(self):
        self._start(lazy=False)
        with self._lock:
            return self._view()

    def _start(self, lazy):
        with self._lifecycle:
            with self._lock:
                if lazy and (self._explicitly_stopped or self._failed):
                    return
                if self._thread is not None and self._thread.is_alive():
                    if self._stop.is_set():
                        raise RuntimeError("previous observer is still stopping")
                    return
                self._explicitly_stopped = False
                self._failed = False
                self._generation += 1
                generation = self._generation
                self._stop = threading.Event()
                self._wake = threading.Event()
                self._checked_at = None
                self._cache_signature = self._cache_result = None
                self._state.update(state="checking", reason_codes=[_PENDING], field_types=[], backend="stat")
                self._state["event_seq"] += 1
                self._thread = threading.Thread(target=self._run, args=(generation, self._stop),
                                                name="rg-telemetry-watch", daemon=True)
                self._thread.start()
                callback = self._callback
        self._notify(callback)

    def stop(self):
        with self._lifecycle:
            with self._lock:
                self._explicitly_stopped = True
                self._generation += 1
                self._stop.set()
                self._wake.set()
                if self._backend is not None:
                    self._backend.wake()
                thread = self._thread
                changed = self._state["state"] != "stopped"
                self._risk_latch = None
                self._state.update(state="stopped", reason_codes=[], field_types=[])
                if changed:
                    self._state["event_seq"] += 1
                callback = self._callback if changed else None
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=.5)
        self._notify(callback)
        with self._lock:
            return self._view()

    def acknowledge(self, event_seq):
        with self._lock:
            callback = None
            if (type(event_seq) is int and 0 <= event_seq <= self._state["event_seq"]
                    and self._risk_latch is not None and self._risk_latch["event_seq"] <= event_seq):
                self._risk_latch = None
                callback = self._callback
        self._notify(callback)

    def _open(self):
        probe = _Probe()
        try:
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(self._path.anchor, directory_flags)
            try:
                info = os.fstat(fd)
            except Exception:
                os.close(fd)
                raise
            probe.descriptors.append((0, fd, _file_stamp(info), True))
            parts = self._path.parts[1:]
            if not parts:
                return probe
            for level, part in enumerate(parts, 1):
                directory = level < len(parts)
                flags = (directory_flags if directory else
                         os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
                try:
                    child = os.open(part, flags, dir_fd=fd)
                except FileNotFoundError:
                    probe.state = "missing"
                    probe.signature = ("missing", level, tuple((x[0], x[2][0], x[2][1])
                                                               for x in probe.descriptors))
                    return probe
                try:
                    info = os.fstat(child)
                except Exception:
                    os.close(child)
                    raise
                probe.descriptors.append((level, child, _file_stamp(info), directory))
                if directory:
                    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, self._uid):
                        return probe
                    fd = child
                else:
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != self._uid
                            or not info.st_mode & stat.S_IRUSR or info.st_size > MAX_SCOPE_BYTES):
                        return probe
                    probe.file_fd = child
                    probe.signature = ("file", _file_stamp(info), tuple((x[0], x[2][0], x[2][1], x[2][2], x[2][3])
                                                                        for x in probe.descriptors[:-1]))
                    probe.state = "file"
            return probe
        except (OSError, ValueError, AttributeError, NotImplementedError):
            return probe

    def _publish(self, generation, result, started, *, checked=True, observation=False, file_read=False):
        with self._lock:
            if generation != self._generation or self._stop.is_set():
                return
            state, reasons, fields = result
            changed = (state, reasons, fields) != (
                self._state["state"], self._state["reason_codes"], self._state["field_types"])
            self._state.update(state=state, reason_codes=list(reasons), field_types=list(fields))
            if checked:
                self._checked_at = self._clock()
                self._state["last_scan_ms"] = round(max(0, self._checked_at - started) * 1000, 3)
            if file_read:
                self._state["files_checked"] += 1
            if changed or observation:
                self._state["event_seq"] += 1
                if state == "risk":
                    self._risk_latch = dict(state=state, reason_codes=list(reasons), field_types=list(fields),
                                            event_seq=self._state["event_seq"])
                callback = self._callback
            else:
                callback = None
        self._notify(callback)

    def _check(self, generation, backend):
        started = self._clock()
        before = self._open()
        after = None
        try:
            if backend is not None:
                try:
                    backend.synchronize(before)
                except (OSError, ValueError):
                    raise _BackendFailed() from None
            if before.state == "unknown":
                self._cache_signature = self._cache_result = None
                self._publish(generation, ("unknown", [_UNKNOWN], []), started)
                return
            if before.state == "file" and before.signature != self._cache_signature:
                self._publish(generation, ("checking", [_PENDING], []), started, checked=False)
                try:
                    raw = self._reader(before.file_fd, MAX_SCOPE_BYTES)
                    if not isinstance(raw, bytes) or len(raw) > MAX_SCOPE_BYTES:
                        raise ValueError("scope limit")
                    result = _inspect(raw)
                except (OSError, ValueError, TypeError, RecursionError, OverflowError):
                    result = ("unknown", [_UNKNOWN], [])
                after = self._open()
                if after.state != "file" or before.signature != after.signature:
                    self._cache_signature = self._cache_result = None
                    self._publish(generation, ("checking", [_PENDING], []), started)
                    return
                self._cache_signature, self._cache_result = before.signature, result
                self._publish(generation, result, started, observation=True, file_read=True)
                return
            after = self._open()
            if before.state != after.state or before.signature != after.signature:
                self._cache_signature = self._cache_result = None
                self._publish(generation, ("checking", [_PENDING], []), started)
            elif before.state == "missing":
                self._cache_signature = self._cache_result = None
                self._publish(generation, ("missing", [], []), started)
            else:
                self._publish(generation, self._cache_result, started)
        finally:
            before.close()
            if after is not None:
                after.close()

    def _run(self, generation, stop):
        backend = None
        try:
            if sys.platform == "darwin" and hasattr(select, "kqueue"):
                try:
                    backend = _KqueueEvents()
                except (OSError, ValueError):
                    pass
            with self._lock:
                if generation != self._generation:
                    return
                self._backend = backend
                self._state["backend"] = "kqueue+stat" if backend is not None else "stat"
            while not stop.is_set():
                self._wake.clear()
                try:
                    self._check(generation, backend)
                except _BackendFailed:
                    backend.close()
                    backend = None
                    with self._lock:
                        self._backend = None
                        self._state["backend"] = "stat"
                    try:
                        self._check(generation, None)
                    except Exception:
                        self._publish(generation, ("unknown", [_UNKNOWN], []), self._clock())
                except Exception:
                    self._publish(generation, ("unknown", [_UNKNOWN], []), self._clock())
                    if backend is not None:
                        backend.close()
                        backend = None
                        with self._lock:
                            self._backend = None
                            self._state["backend"] = "stat"
                with self._lock:
                    timeout = self._interval_ms / 1000
                if not stop.is_set() and not self._wake.is_set():
                    if backend is not None:
                        try:
                            backend.wait(timeout)
                        except (OSError, ValueError):
                            backend.close()
                            backend = None
                            with self._lock:
                                self._backend = None
                                self._state["backend"] = "stat"
                    else:
                        self._wake.wait(timeout)
        except BaseException:
            pass  # worker failures never serialize a Python exception or private input
        finally:
            if not stop.is_set():
                with self._lock:
                    if generation == self._generation:
                        self._failed = True  # only an explicit start may recover this worker
                self._publish(generation, ("unknown", [_UNKNOWN], []), self._clock(), checked=False)
            if backend is not None:
                try:
                    backend.close()
                except Exception:
                    pass
            with self._lock:
                if self._backend is backend:
                    self._backend = None
                if self._thread is threading.current_thread():
                    self._thread = None


TelemetryWatcher = ClaudeTelemetryWatch

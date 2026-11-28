"""Bounded read-only observation of eight fixed Claude artifact groups.

Filesystem work belongs to one worker. Public snapshots contain fixed categories
and counts, never paths, filenames, field values, identifiers or exception text.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import threading
import time

import artifact_policy
from service_diagnostics import DIAGNOSTIC_KEYS, inspect_log_diagnostics
from telemetry_watch import ClaudeTelemetryWatch, MAX_SCOPE_BYTES, _BackendFailed, _Probe, _file_stamp


SOURCE_MODES = {
    "sentry_scope": "fields", "sentry_queue": "metadata", "app_config": "fields",
    "electron_preferences": "fields", "desktop_config": "metadata", "cookie_store": "metadata",
    "installation_id": "metadata", "claude_logs": "log_codes",
}
SOURCE_IDS = tuple(SOURCE_MODES)
COUNTER_KEYS = ("region", "banned", "evicted", "telemetry", "device", "stripe", "network")
MAX_LOG_BYTES = 512 * 1024
MAX_LOG_FILES = 16
MAX_LOG_ENTRIES = 256
MAX_QUEUE_ENTRIES = 512
MAX_PARTIAL_LINE = 64 * 1024
_UNKNOWN = "telemetry_file_unknown"
_PENDING = "telemetry_file_pending"
_CN_CODES = frozenset(("telemetry_cn_country", "telemetry_cn_locale", "telemetry_cn_timezone"))
_FIELDS = frozenset(("country", "locale", "timezone"))
COVERAGE = ("固定八组本地来源；仅检查允许的文化/地区字段与有界日志窗口。"
            "队列、桌面配置、Cookie 与安装标识只观察元数据，不读取正文或标识。"
            "日志首次每文件最多尾部512KiB，之后增量每轮每文件最多512KiB；最多16个日志与512个队列项。"
            "缺失表示未验证；普通计数或文件变化不是中国地区证据；不覆盖全部历史、内存或上传流量。")


def _source(source_id):
    return dict(id=source_id, state="checking", mode=SOURCE_MODES[source_id], reason_codes=[_PENDING],
                field_types=[], change_count=0, file_count=0, total_bytes=0, files_checked=0,
                last_check_age_ms=None, counters=dict.fromkeys(COUNTER_KEYS, 0),
                diagnostics=dict.fromkeys(DIAGNOSTIC_KEYS, 0), limited=False)


def _result(state, codes=(), fields=(), **extra):
    return dict(state=state, reason_codes=list(codes), field_types=list(fields), **extra)


def _policy_result(value, scope=False):
    if (not isinstance(value, dict) or value.get("state") not in ("safe", "observed", "risk", "unknown")
            or not isinstance(value.get("reason_codes"), (list, tuple))
            or not all(code in _CN_CODES | {_UNKNOWN, _PENDING} for code in value["reason_codes"])
            or not isinstance(value.get("field_types"), (list, tuple))
            or not all(field in _FIELDS for field in value["field_types"])):
        return _result("unknown", [_UNKNOWN])
    state = value["state"]
    codes = sorted(set(value["reason_codes"]))
    if state == "risk" and not any(code in _CN_CODES for code in codes):
        return _result("unknown", [_UNKNOWN])
    if state == "unknown":
        codes = [_UNKNOWN]
    return _result(state, codes, sorted(set(value["field_types"])))


class ClaudeArtifactWatch(ClaudeTelemetryWatch):
    """Same cache/lifecycle/ACK contract as ClaudeTelemetryWatch, for fixed sources.

    ``home`` is injectable for isolated fixtures. ``reader(fd, limit)`` reads from
    the validated descriptor's current offset; metadata-only sources never call
    it. Stop and unexpected exits require an explicit restart. Unacknowledged
    CN classifications survive recovery and unexpected worker restarts.
    """
    def __init__(self, home=None, interval_ms=100, clock=time.monotonic, reader=None):
        home = Path.home() if home is None else Path(home)
        if ".." in home.parts:
            raise ValueError("observation root must be normalized")
        self._home = Path(os.path.abspath(os.fspath(home)))
        self._claude = self._home / "Library/Application Support/Claude"
        self._logs = self._home / "Library/Logs/Claude"
        super().__init__(self._claude / "sentry/scope_v3.json", interval_ms, clock, reader)
        self._state.update(coverage=COVERAGE, sources=[_source(key) for key in SOURCE_IDS], risk_source_ids=[])
        self._source_checked = dict.fromkeys(SOURCE_IDS)
        self._latched_sources = {}
        self._runtime = {}

    @staticmethod
    def _read(fd, limit):
        chunks, size = [], 0
        while size < limit:
            block = os.read(fd, min(65536, limit - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
        return b"".join(chunks)

    def _start(self, lazy):
        with self._lifecycle:
            with self._lock:
                if lazy and (self._explicitly_stopped or self._failed):
                    return
                if self._thread is not None and self._thread.is_alive():
                    if self._stop.is_set():
                        raise RuntimeError("previous observer is still stopping")
                    return
                self._explicitly_stopped = self._failed = False
                self._generation += 1
                generation = self._generation
                self._stop = threading.Event()
                self._wake = threading.Event()
                self._checked_at = None
                self._source_checked = dict.fromkeys(SOURCE_IDS)
                self._last_signature = None
                self._runtime = {key: dict(dto=_source(key), signature=None, cache=None, logs={}, checked_at=None)
                                 for key in SOURCE_IDS}
                self._state.update(state="checking", reason_codes=[_PENDING], field_types=[], backend="stat",
                                   sources=[_source(key) for key in SOURCE_IDS], risk_source_ids=[], files_checked=0)
                self._state["event_seq"] += 1
                self._thread = threading.Thread(target=self._run, args=(generation, self._stop),
                                                name="rg-artifact-watch", daemon=True)
                self._thread.start()
                callback = self._callback
        self._notify(callback)

    def _view(self):
        view = super()._view()
        view["risk_source_ids"] = list(view.get("risk_source_ids", []))
        sources = []
        now = self._clock()
        for original in self._state["sources"]:
            item = dict(original)
            latched = self._latched_sources.get(item["id"]) if self._risk_latch is not None else None
            if latched is not None:
                item.update(state="risk", reason_codes=latched["reason_codes"], field_types=latched["field_types"])
            if view["state"] == "stopped":
                item.update(state="stopped", reason_codes=[], field_types=[])
            item["reason_codes"] = list(item["reason_codes"])
            item["field_types"] = list(item["field_types"])
            item["counters"] = dict(item["counters"])
            item["diagnostics"] = dict(item["diagnostics"])
            checked = self._source_checked[item["id"]]
            item["last_check_age_ms"] = None if checked is None else round(max(0, now - checked) * 1000, 3)
            sources.append(item)
        view["sources"] = sources
        return view

    def acknowledge(self, event_seq):
        with self._lock:
            callback = None
            if (type(event_seq) is int and 0 <= event_seq <= self._state["event_seq"]
                    and self._risk_latch is not None and self._risk_latch["event_seq"] <= event_seq):
                self._risk_latch = None
                self._latched_sources.clear()
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
                self._latched_sources.clear()
                for runtime in self._runtime.values():
                    runtime["logs"].clear()
                self._runtime = {}
                self._state.update(state="stopped", reason_codes=[], field_types=[], risk_source_ids=[])
                if changed:
                    self._state["event_seq"] += 1
                callback = self._callback if changed else None
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=.5)
        self._notify(callback)
        with self._lock:
            return self._view()

    def _publish(self, generation, result, started, **kwargs):
        """Inherited worker failure path: expose uncertainty without clearing a latch."""
        with self._lock:
            if generation != self._generation or self._stop.is_set():
                return
            if self._failed:
                for runtime in self._runtime.values():
                    runtime["logs"].clear()
            self._state.update(state="unknown", reason_codes=[_UNKNOWN], field_types=[])
            self._state["event_seq"] += 1
            callback = self._callback
        self._notify(callback)

    def _pending(self, generation, source_id):
        with self._lock:
            if generation != self._generation or self._stop.is_set():
                return
            sources = [dict(item) for item in self._state["sources"]]
            item = next(item for item in sources if item["id"] == source_id)
            if item["state"] == "checking":
                return
            item.update(state="checking", reason_codes=[_PENDING], field_types=[])
            self._state.update(state="checking", reason_codes=[_PENDING], field_types=[], sources=sources)
            self._state["event_seq"] += 1
            callback = self._callback
        self._notify(callback)

    def _probe(self, path, kind="read", limit=None):
        """Anchor every component; metadata leaves are lstat'ed, never opened."""
        probe = _Probe()
        probe.info = None
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(path.anchor, flags)
            try:
                info = os.fstat(fd)
            except BaseException:
                os.close(fd)
                raise
            probe.descriptors.append((0, fd, _file_stamp(info), True))
            parts = path.parts[1:]
            for level, name in enumerate(parts, 1):
                directory = level < len(parts) or kind == "directory"
                try:
                    if not directory and kind == "metadata":
                        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        child = None
                    else:
                        child = os.open(name, flags if directory else
                                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
                        try:
                            info = os.fstat(child)
                        except BaseException:
                            os.close(child)
                            raise
                except FileNotFoundError:
                    probe.state = "missing"
                    probe.signature = ("missing", level, tuple((x[0], x[2][0], x[2][1]) for x in probe.descriptors))
                    return probe
                if child is not None:
                    probe.descriptors.append((level, child, _file_stamp(info), directory))
                if directory:
                    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, self._uid):
                        return probe
                    fd = child
                elif not stat.S_ISREG(info.st_mode) or info.st_uid != self._uid:
                    return probe
                elif kind == "read" and (not info.st_mode & stat.S_IRUSR or limit is not None and info.st_size > limit):
                    probe.info = info
                    return probe
                if level == len(parts):
                    if directory and info.st_uid != self._uid:
                        return probe
                    probe.info = info
                    probe.file_fd = child
                    ancestors = probe.descriptors[:-1] if child is not None else probe.descriptors
                    probe.signature = ("directory" if directory else "file", _file_stamp(info),
                                       tuple((x[0], x[2][0], x[2][1], x[2][2], x[2][3]) for x in ancestors))
                    probe.state = "directory" if directory else "file"
            return probe
        except (OSError, ValueError, AttributeError, NotImplementedError):
            return probe

    @staticmethod
    def _watch(probe, watches):
        selected = [item for item in probe.descriptors if item[3]][-2:]
        selected += [item for item in probe.descriptors if not item[3]]
        for _level, fd, stamp, directory in selected:
            key = (stamp[0], stamp[1], directory)
            if key not in watches and len(watches) < 64:
                watches[key] = (os.dup(fd), stamp)

    def _open_watched(self, path, watches, kind="read", limit=None):
        probe = self._probe(path, kind, limit)
        try:
            self._watch(probe, watches)
        except BaseException:
            probe.close()
            raise
        return probe

    def _json(self, source_id, path, generation, watches):
        runtime = self._runtime[source_id]
        before = self._open_watched(path, watches, limit=MAX_SCOPE_BYTES)
        after = None
        try:
            if before.state == "unknown":
                return _result("unknown", [_UNKNOWN], file_count=int(before.info is not None),
                               total_bytes=before.info.st_size if before.info is not None else 0,
                               limited=bool(before.info and before.info.st_size > MAX_SCOPE_BYTES)), None, False
            if before.state == "missing":
                after = self._probe(path)
                if after.state != "missing" or before.signature != after.signature:
                    return _result("checking", [_PENDING]), None, False
                return _result("missing"), before.signature, False
            info = dict(file_count=1, total_bytes=before.info.st_size)
            if before.signature == runtime["signature"] and runtime["cache"] is not None:
                result = dict(runtime["cache"])
                parsed = False
            else:
                self._pending(generation, source_id)
                try:
                    raw = self._reader(before.file_fd, MAX_SCOPE_BYTES)
                    if not isinstance(raw, bytes) or len(raw) > MAX_SCOPE_BYTES or len(raw) != before.info.st_size:
                        result = _result("unknown", [_UNKNOWN], limited=True)
                    else:
                        result = _policy_result(artifact_policy.inspect_json(source_id, raw), source_id == "sentry_scope")
                except Exception:
                    result = _result("unknown", [_UNKNOWN])
                parsed = True
            after = self._probe(path, limit=MAX_SCOPE_BYTES)
            if after.state != "file" or before.signature != after.signature:
                return _result("checking", [_PENDING], **info), None, False
            result.update(info)
            runtime["cache"] = dict(result)
            return result, before.signature, parsed
        finally:
            before.close()
            if after is not None:
                after.close()

    def _metadata(self, paths, watches):
        signatures, count, size, uncertain = [], 0, 0, False
        for path in paths:
            before = self._open_watched(path, watches, kind="metadata")
            after = None
            try:
                if before.state == "unknown":
                    uncertain = True
                    continue
                after = self._probe(path, kind="metadata")
                if before.state != after.state or before.signature != after.signature:
                    uncertain = True
                    continue
                signatures.append(before.signature)
                if before.state == "file":
                    count += 1
                    size += before.info.st_size
            finally:
                before.close()
                if after is not None:
                    after.close()
        if uncertain:
            return _result("unknown", [_UNKNOWN], file_count=count, total_bytes=size), None, False
        return _result("observed" if count else "missing", file_count=count, total_bytes=size), tuple(signatures), False

    def _queue(self, watches):
        path = self._claude / "sentry/queue"
        before = self._open_watched(path, watches, kind="directory")
        after = None
        try:
            if before.state != "directory":
                return _result("missing" if before.state == "missing" else "unknown",
                               [] if before.state == "missing" else [_UNKNOWN]), before.signature, False
            entries, total, limited, uncertain = [], 0, False, False
            with os.scandir(before.file_fd) as iterator:
                for index, entry in enumerate(iterator):
                    if index >= MAX_QUEUE_ENTRIES:
                        limited = True
                        break
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if info.st_uid != self._uid or stat.S_ISLNK(info.st_mode):
                            uncertain = True
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            limited = True  # no recursion or opening of other entry types
                            continue
                        entries.append((entry.name, _file_stamp(info)))
                        total += info.st_size
                    except OSError:
                        uncertain = True
            after = self._probe(path, "directory")
            if after.state != "directory" or before.signature != after.signature:
                uncertain = True
            state = "unknown" if uncertain else "observed"
            result = _result(state, [_UNKNOWN] if uncertain else [], file_count=len(entries), total_bytes=total, limited=limited)
            return result, (before.signature, tuple(sorted(entries))) if not uncertain else None, False
        finally:
            before.close()
            if after is not None:
                after.close()

    @staticmethod
    def _log_name(name):
        return bool(name.endswith(".log") or re.search(r"\.log\.[1-9][0-9]{0,2}$", name))

    def _log_file(self, path, runtime, generation, watches):
        before = self._open_watched(path, watches)
        after = None
        try:
            if before.state != "file":
                return _result("unknown", [_UNKNOWN]), None, False, 0
            size = before.info.st_size
            previous = runtime.get("entry")
            identity = (before.info.st_dev, before.info.st_ino)
            if previous is not None and before.signature == previous["signature"] and previous["offset"] >= size:
                after = self._probe(path)
                if after.state == "file" and before.signature == after.signature:
                    return dict(previous["result"]), previous, False, size
            continuing = (previous is not None and identity == previous["identity"] and size >= previous["size"]
                          and (size > previous["size"] or before.signature == previous["signature"]))
            small = size <= MAX_LOG_BYTES
            large_recheck = not small and previous is not None and before.signature != previous["signature"]
            if large_recheck:
                continuing = False  # first verify the changed tail's overlap
            offset = previous["offset"] if continuing else max(0, size - MAX_LOG_BYTES)
            carry = previous["carry"] if continuing else b""
            count = min(MAX_LOG_BYTES, max(0, size - offset))
            limited = bool((previous or {}).get("limited")) or offset > 0 or size - offset > MAX_LOG_BYTES
            if count == 0 and continuing:
                result = dict(previous["result"])
                return result, previous, False, size
            self._pending(generation, "claude_logs")
            boundary = not continuing and offset > 0
            read_offset = 0 if small else offset - 1 if boundary else offset
            read_count = size if small else min(MAX_LOG_BYTES, size - read_offset)
            os.lseek(before.file_fd, read_offset, os.SEEK_SET)
            raw = self._reader(before.file_fd, read_count) if read_count else b""
            if not isinstance(raw, bytes) or len(raw) != read_count:
                return _result("unknown", [_UNKNOWN], limited=True), None, False, size
            after = self._probe(path)
            if (after.state != "file" or (after.info.st_dev, after.info.st_ino) != identity
                    or after.info.st_size < size or before.signature[2] != after.signature[2]
                    or before.info.st_mode != after.info.st_mode or before.info.st_uid != after.info.st_uid
                    or (after.info.st_size == size and before.signature != after.signature)):
                return _result("checking", [_PENDING], limited=limited), None, False, size
            prefix_digest = None
            next_offset = read_offset + read_count
            starts_at_line = True
            if boundary:
                starts_at_line = raw[:1] == b"\n"
                raw = raw[1:]
            window_start, window_bytes = (0, raw) if small else (offset, raw)
            if small:
                # A larger same-inode file can be copytruncate+rewrite, not an append.
                # For a bounded small file verify the entire old prefix before reusing
                # its offset; only genuinely new bytes enter policy/counter parsing.
                prefix_digest = hashlib.sha256(raw).digest()
                if continuing and (previous.get("prefix_digest") is None or
                                   hashlib.sha256(raw[:previous["offset"]]).digest() != previous["prefix_digest"]):
                    continuing = False
                if continuing:
                    raw = raw[offset:]
                else:
                    carry = b""
                    offset = 0
            elif large_recheck and identity == previous["identity"]:
                old_start = previous.get("window_start", previous["offset"])
                old_bytes = previous.get("window_bytes", b"")
                overlap_start = max(window_start, old_start)
                overlap_end = min(next_offset, old_start + len(old_bytes))
                continuing = (overlap_end > overlap_start and previous["offset"] >= window_start
                              and next_offset >= previous["offset"]
                              and window_bytes[overlap_start - window_start:overlap_end - window_start]
                              == old_bytes[overlap_start - old_start:overlap_end - old_start])
                if continuing:
                    raw = window_bytes[previous["offset"] - window_start:]
                    carry = previous["carry"]
            if not small and not continuing and boundary:
                # Read the preceding byte within the same 512KiB budget. If it is
                # LF, the first record is complete and must not be discarded. The
                # possible final byte left outside this window is read next cycle.
                if not starts_at_line:
                    raw = raw.partition(b"\n")[2]
            if not small and continuing and not large_recheck and previous is not None:
                old_window = previous.get("window_bytes", b"")
                if previous.get("window_start", 0) + len(old_window) == read_offset:
                    window_bytes = (old_window + window_bytes)[-MAX_LOG_BYTES:]
                    window_start = next_offset - len(window_bytes)
            if continuing and previous.get("tail_classified") and (not raw or raw.startswith(b"\n")):
                # A complete JSON tail was already inspected before its LF arrived.
                # Completing that same record must not create a second risk latch.
                carry = b""
                raw = raw[1:] if raw.startswith(b"\n") else raw
            block = carry + raw
            end = block.rfind(b"\n")
            complete, tail = (block[:end + 1], block[end + 1:]) if end >= 0 else (b"", block)
            oversize_line = len(tail) > MAX_PARTIAL_LINE or len(complete) > MAX_LOG_BYTES
            if oversize_line:
                result = _result("unknown", [_UNKNOWN], limited=True)
                tail = b""
            elif complete:
                classified = artifact_policy.inspect_log_chunk(complete)
                result = _policy_result(classified)
                counters = classified.get("counters", {})
                result["counters"] = {key: value if type(value := counters.get(key, 0)) is int and value >= 0 else 0
                                      for key in COUNTER_KEYS}
                diagnostic = inspect_log_diagnostics(complete)
                result['diagnostics'] = diagnostic['diagnostics']
                limited |= diagnostic['limited']
            else:
                result = _result("observed")
            tail_classified = False
            if not oversize_line and tail.strip().startswith(b"{"):
                if tail.rstrip().endswith(b"}"):
                    tail_result = _policy_result(artifact_policy.inspect_log_chunk(tail))
                    tail_classified = tail_result["state"] in ("risk", "observed")
                    state, codes, fields = self._aggregate([result, tail_result], metadata=False)
                    result.update(state="observed" if state == "safe" else state,
                                  reason_codes=codes, field_types=fields)
                elif result["state"] != "risk":
                    result.update(state="checking", reason_codes=[_PENDING])
            result["limited"] = limited or oversize_line
            entry = dict(identity=identity, signature=after.signature, offset=next_offset, size=after.info.st_size,
                         prefix_digest=prefix_digest, carry=tail, result=dict(result), limited=result["limited"],
                         window_start=window_start, window_bytes=window_bytes, tail_classified=tail_classified)
            return result, entry, True, after.info.st_size
        finally:
            before.close()
            if after is not None:
                after.close()

    def _log_group(self, generation, watches):
        before = self._open_watched(self._logs, watches, kind="directory")
        after = None
        runtime = self._runtime["claude_logs"]
        try:
            if before.state != "directory":
                runtime["logs"] = {}
                return _result("missing" if before.state == "missing" else "unknown",
                               [] if before.state == "missing" else [_UNKNOWN]), before.signature, False
            names, limited = [], False
            with os.scandir(before.file_fd) as iterator:
                for index, entry in enumerate(iterator):
                    if index >= MAX_LOG_ENTRIES:
                        limited = True
                        break
                    if self._log_name(entry.name):
                        names.append(entry.name)
            names.sort()
            if len(names) > MAX_LOG_FILES:
                names, limited = names[:MAX_LOG_FILES], True
            results, signatures, total, reads = [], [], 0, 0
            counters = dict.fromkeys(COUNTER_KEYS, 0)
            diagnostics = dict.fromkeys(DIAGNOSTIC_KEYS, 0)
            current = {}
            for name in names:
                item_runtime = dict(entry=runtime["logs"].get(name))
                result, entry, parsed, size = self._log_file(self._logs / name, item_runtime, generation, watches)
                results.append(result)
                total += size
                limited |= result.get("limited", False)
                reads += int(parsed)
                if entry is not None:
                    current[name] = entry
                    signatures.append((name, entry["signature"], entry["offset"]))
                if parsed:
                    for key in COUNTER_KEYS:
                        counters[key] += result.get("counters", {}).get(key, 0)
                    for key in DIAGNOSTIC_KEYS:
                        diagnostics[key] += result.get('diagnostics', {}).get(key, 0)
            with self._lock:
                if self._stop.is_set():
                    current.clear()
                    return _result("checking", [_PENDING]), None, False
                runtime["logs"] = current
            after = self._probe(self._logs, "directory")
            if after.state != "directory" or before.signature != after.signature:
                results.append(_result("checking", [_PENDING]))
            state, codes, fields = self._aggregate(results, metadata=False)
            if not names and state == "safe":
                state = "observed"
            elif state == "safe":
                state = "observed"
            return _result(state, codes, fields, file_count=len(names), total_bytes=total, limited=limited,
                           counters=counters, diagnostics=diagnostics,
                           read_count=reads), (before.signature, tuple(signatures)), bool(reads)
        finally:
            before.close()
            if after is not None:
                after.close()

    @staticmethod
    def _aggregate(results, metadata=True):
        risky = [item for item in results if item["state"] == "risk"]
        fields = sorted({field for item in results for field in item.get("field_types", [])})
        if risky:
            return "risk", sorted({code for item in risky for code in item["reason_codes"] if code in _CN_CODES}), fields
        if any(item["state"] == "unknown" for item in results):
            return "unknown", [_UNKNOWN], fields
        if any(item["state"] == "checking" for item in results):
            return "checking", [_PENDING], fields
        if metadata and results and all(item["state"] == "missing" for item in results):
            return "missing", [], fields
        if metadata and any(item.get("id") == "sentry_scope" and item["state"] == "observed" for item in results):
            return "observed", [], fields
        return "safe", [], fields

    def _check(self, generation, backend):
        started = self._clock()
        watches, observed, new_risks = {}, False, set()
        try:
            for source_id in SOURCE_IDS:
                if self._stop.is_set():
                    return
                runtime = self._runtime[source_id]
                try:
                    if source_id in ("sentry_scope", "app_config", "electron_preferences"):
                        name = {"sentry_scope": "sentry/scope_v3.json", "app_config": "config.json",
                                "electron_preferences": "Preferences"}[source_id]
                        result, signature, parsed = self._json(source_id, self._claude / name, generation, watches)
                    elif source_id == "sentry_queue":
                        result, signature, parsed = self._queue(watches)
                    elif source_id == "claude_logs":
                        result, signature, parsed = self._log_group(generation, watches)
                    else:
                        paths = {"desktop_config": [self._claude / "claude_desktop_config.json"],
                                 "installation_id": [self._claude / "ant-did"],
                                 "cookie_store": [directory / ("Cookies" + suffix)
                                                  for directory in (self._claude, self._claude / "Network")
                                                  for suffix in ("", "-wal", "-shm")]}[source_id]
                        result, signature, parsed = self._metadata(paths, watches)
                except Exception:
                    result, signature, parsed = _result("unknown", [_UNKNOWN]), None, False
                old = runtime["dto"]
                changed = signature is not None and signature != runtime["signature"]
                dto = dict(old)
                dto.update(file_count=0, total_bytes=0, limited=False)
                dto.update({key: result[key] for key in ("state", "reason_codes", "field_types", "file_count", "total_bytes", "limited")
                            if key in result})
                dto["counters"] = {key: old["counters"][key] + result.get("counters", {}).get(key, 0) for key in COUNTER_KEYS}
                dto['diagnostics'] = {key: old['diagnostics'][key] + result.get('diagnostics', {}).get(key, 0)
                                      for key in DIAGNOSTIC_KEYS}
                dto["files_checked"] += result.get("read_count", int(parsed))
                if changed and runtime["signature"] is not None:
                    dto["change_count"] += 1
                if dto["state"] == "risk" and (parsed or changed or old["state"] != "risk"):
                    new_risks.add(source_id)
                runtime.update(dto=dto, signature=signature)
                runtime["checked_at"] = self._clock()
                observed |= changed or parsed
            if backend is not None:
                combined = _Probe()
                combined.descriptors = [(index, fd, stamp, False) for index, (fd, stamp) in enumerate(watches.values())]
                try:
                    backend.synchronize(combined)
                except (OSError, ValueError):
                    raise _BackendFailed() from None
            self._publish_sources(generation, started, observed, new_risks)
        finally:
            for fd, _stamp in watches.values():
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _publish_sources(self, generation, started, observation, new_risks):
        with self._lock:
            if generation != self._generation or self._stop.is_set():
                return
            sources = [dict(self._runtime[key]["dto"]) for key in SOURCE_IDS]
            state, codes, fields = self._aggregate(sources)
            signature = (state, tuple(codes), tuple(fields), tuple((item["id"], item["state"],
                         tuple(item["reason_codes"]), tuple(item["field_types"]), item["change_count"],
                         item["files_checked"], item["file_count"], item["total_bytes"], item["limited"],
                         tuple(item["counters"].values()), tuple(item['diagnostics'].values())) for item in sources))
            changed = signature != getattr(self, "_last_signature", None) or observation
            self._last_signature = signature
            completed = self._clock()
            self._source_checked = {key: self._runtime[key]["checked_at"] for key in SOURCE_IDS}
            # A later slow source must not rejuvenate an earlier, now-old sample.
            self._checked_at = min(self._source_checked.values())
            risk_ids = [item["id"] for item in sources if item["state"] == "risk"]
            self._state.update(state=state, reason_codes=codes, field_types=fields, sources=sources,
                               risk_source_ids=risk_ids, last_scan_ms=round(max(0, completed - started) * 1000, 3),
                               files_checked=sum(item["files_checked"] for item in sources))
            if changed:
                self._state["event_seq"] += 1
                for item in sources:
                    if item["state"] == "risk" and item["id"] in new_risks:
                        self._latched_sources[item["id"]] = dict(reason_codes=list(item["reason_codes"]), field_types=list(item["field_types"]))
                if new_risks and self._latched_sources:
                    self._risk_latch = dict(state="risk", event_seq=self._state["event_seq"],
                        reason_codes=sorted({code for item in self._latched_sources.values() for code in item["reason_codes"]}),
                        field_types=sorted({field for item in self._latched_sources.values() for field in item["field_types"]}),
                        risk_source_ids=[key for key in SOURCE_IDS if key in self._latched_sources])
                callback = self._callback
            else:
                callback = None
        self._notify(callback)

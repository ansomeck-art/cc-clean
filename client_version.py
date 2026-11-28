"""Read-only Claude bundle version checks and a private, sanitized baseline.

Invoke ``sample``/``check`` from an ordinary scan, never from a protection tick.
The only writes are a 0600 baseline inside the caller's private data directory.
No client configuration, queue, log, account file or running process is inspected.
"""
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import stat
import threading


BASELINE_NAME = "claude-version-baseline.json"
MAX_INFO_BYTES = 256 * 1024
MAX_BASELINE_BYTES = 4096
_VERSION = re.compile(r"[0-9]{1,10}(?:\.[0-9]{1,10}){1,4}\Z")


def _version(value):
    return type(value) is str and len(value) <= 48 and bool(_VERSION.fullmatch(value))


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _read(fd, maximum):
    chunks, size = [], 0
    while size < maximum:
        part = os.read(fd, min(65536, maximum - size))
        if not part:
            break
        chunks.append(part)
        size += len(part)
    return b"".join(chunks)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("ambiguous baseline")
        result[key] = value
    return result


class ClaudeVersionObserver:
    """No-I/O construction; normal scans return only validated version strings.

    ``app_paths`` is an injection point for isolated tests. Production defaults
    inspect exactly the two known Claude.app locations. Pending review survives
    restarts; unreadable/untrusted files never replace an established baseline.
    """
    def __init__(self, data_dir, app_paths=None):
        directory = Path(data_dir)
        paths = tuple(app_paths) if app_paths is not None else (
            Path("/Applications/Claude.app"), Path.home() / "Applications/Claude.app")
        if not 1 <= len(paths) <= 2:
            raise ValueError("expected one or two client bundles")
        if ".." in directory.parts or any(".." in Path(path).parts for path in paths):
            raise ValueError("version paths must be normalized")
        self._directory = Path(os.path.abspath(os.fspath(directory)))
        self._apps = tuple(Path(os.path.abspath(os.fspath(path))) for path in paths)
        self._uid = os.getuid() if hasattr(os, "getuid") else None
        self._lock = threading.RLock()
        self._state = self._view("unverified", [], [], False)

    @staticmethod
    def _view(state, versions, previous, pending):
        return dict(state=state, current_version=versions[0] if versions else "",
                    previous_version=previous[0] if previous else "", versions=list(versions),
                    previous_versions=list(previous), review_required=bool(pending))

    def status(self):
        with self._lock:
            return {**self._state, "versions": list(self._state["versions"]),
                    "previous_versions": list(self._state["previous_versions"])}

    def _directory_fd(self, path, *, create=False, private=False):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        fd = os.open(path.anchor, flags)
        try:
            for index, part in enumerate(path.parts[1:], 1):
                try:
                    child = os.open(part, flags, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                    child = os.open(part, flags, dir_fd=fd)
                try:
                    info = os.fstat(child)
                    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, self._uid):
                        raise ValueError("untrusted directory")
                    if private and index == len(path.parts) - 1 and (
                            info.st_uid != self._uid or info.st_mode & 0o077):
                        raise ValueError("data directory is not private")
                except BaseException:
                    os.close(child)
                    raise
                os.close(fd)
                fd = child
            if private:
                info = os.fstat(fd)
                if info.st_uid != self._uid or info.st_mode & 0o077:
                    raise ValueError("data directory is not private")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _info(self, app):
        directory = app / "Contents"
        fd = self._directory_fd(directory)
        leaf = None
        verify_dir = verify_leaf = None
        try:
            leaf = os.open("Info.plist", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            before = os.fstat(leaf)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, self._uid)
                    or not before.st_mode & 0o444 or not 0 < before.st_size <= MAX_INFO_BYTES):
                raise ValueError("untrusted client metadata")
            raw = _read(leaf, before.st_size)
            if len(raw) != before.st_size or _stamp(before) != _stamp(os.fstat(leaf)):
                raise ValueError("unstable client metadata")
            verify_dir = self._directory_fd(directory)
            if _stamp(os.fstat(fd))[:4] != _stamp(os.fstat(verify_dir))[:4]:
                raise ValueError("replaced metadata directory")
            verify_leaf = os.open("Info.plist", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                                  dir_fd=verify_dir)
            if _stamp(before) != _stamp(os.fstat(verify_leaf)):
                raise ValueError("replaced client metadata")
            obj = plistlib.loads(raw)
            if type(obj) is not dict or obj.get("CFBundleIdentifier") != "com.anthropic.claudefordesktop":
                raise ValueError("unexpected client bundle")
            value = obj.get("CFBundleShortVersionString") if type(obj) is dict else None
            if not _version(value):
                raise ValueError("unsupported version format")
            return value
        finally:
            for handle in (leaf, verify_leaf, verify_dir, fd):
                if handle is not None:
                    os.close(handle)

    def _baseline(self, directory_fd):
        try:
            fd = os.open(BASELINE_NAME, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != self._uid
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or not 0 < before.st_size <= MAX_BASELINE_BYTES):
                raise ValueError("untrusted version baseline")
            raw = _read(fd, before.st_size)
            if len(raw) != before.st_size or _stamp(before) != _stamp(os.fstat(fd)):
                raise ValueError("unstable version baseline")
            current = os.stat(BASELINE_NAME, dir_fd=directory_fd, follow_symlinks=False)
            if _stamp(current) != _stamp(before):
                raise ValueError("replaced version baseline")
            obj = json.loads(raw, object_pairs_hook=_pairs)
            if (type(obj) is not dict or set(obj) != {"schema", "versions", "previous_versions", "pending"}
                    or type(obj["schema"]) is not int or obj["schema"] != 1 or type(obj["pending"]) is not bool):
                raise ValueError("unsupported baseline schema")
            for name in ("versions", "previous_versions"):
                values = obj[name]
                if type(values) is not list or len(values) > 2 or not all(_version(value) for value in values):
                    raise ValueError("invalid baseline versions")
                if values != sorted(set(values)):
                    raise ValueError("ambiguous baseline versions")
            if not obj["versions"] or (obj["pending"] and not obj["previous_versions"]):
                raise ValueError("incomplete version baseline")
            return obj
        finally:
            os.close(fd)

    def _save(self, directory_fd, obj):
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        name = ".client-version-" + secrets.token_hex(8) + ".tmp"
        fd = None
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                         mode=0o600, dir_fd=directory_fd)
            os.fchmod(fd, 0o600)
            at = 0
            while at < len(raw):
                written = os.write(fd, raw[at:])
                if written <= 0:
                    raise OSError("baseline write incomplete")
                at += written
            os.fsync(fd)
            verify = self._directory_fd(self._directory, private=True)
            try:
                old = os.fstat(directory_fd)
                current = os.fstat(verify)
                if (old.st_dev, old.st_ino) != (current.st_dev, current.st_ino):
                    raise ValueError("replaced private directory")
            finally:
                os.close(verify)
            os.replace(name, BASELINE_NAME, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass

    def sample(self):
        """Perform a bounded ordinary scan and atomically publish a sanitized hint."""
        with self._lock:
            versions, unknown = [], False
            for app in self._apps:
                try:
                    versions.append(self._info(app))
                except FileNotFoundError:
                    pass
                except (OSError, ValueError, TypeError, AttributeError, plistlib.InvalidFileException,
                        UnicodeError, RecursionError, OverflowError):
                    unknown = True
            versions = sorted(set(versions))
            directory_fd = None
            try:
                directory_fd = self._directory_fd(self._directory, create=bool(versions) and not unknown, private=True)
                baseline = self._baseline(directory_fd)
                previous = baseline["previous_versions"] if baseline else []
                pending = baseline["pending"] if baseline else False
                if unknown:
                    self._state = self._view("unknown", versions, previous, pending)
                elif not versions:
                    self._state = self._view("missing", [], previous, pending)
                else:
                    if baseline is None:
                        baseline = dict(schema=1, versions=versions, previous_versions=[], pending=False)
                        self._save(directory_fd, baseline)
                    elif versions != baseline["versions"]:
                        baseline = dict(schema=1, versions=versions, previous_versions=baseline["versions"], pending=True)
                        self._save(directory_fd, baseline)
                    self._state = self._view("changed" if baseline["pending"] else "observed", versions,
                                             baseline["previous_versions"], baseline["pending"])
            except FileNotFoundError:
                self._state = self._view("unknown" if unknown else "missing", versions, [], False)
            except (OSError, ValueError, TypeError, AttributeError, UnicodeError, RecursionError, OverflowError):
                self._state = self._view("unknown", versions, [], bool(self._state["review_required"]))
            finally:
                if directory_fd is not None:
                    os.close(directory_fd)
            return self.status()

    def check(self):
        return self.sample()

    def mark_reviewed(self, expected_versions):
        """Explicitly clear the private pending hint for exactly the shown versions.

        Does not open a client bundle or update its recorded versions. An old
        page cannot clear a newer baseline. This is an acknowledgement of the
        version hint, not an attestation of the client's geographic safety.
        """
        if (type(expected_versions) is not list or not 1 <= len(expected_versions) <= 2
                or not all(_version(value) for value in expected_versions)
                or len(set(expected_versions)) != len(expected_versions)):
            raise ValueError("invalid expected versions")
        expected = sorted(expected_versions)
        with self._lock:
            directory_fd = None
            try:
                directory_fd = self._directory_fd(self._directory, private=True)
                baseline = self._baseline(directory_fd)
                if baseline is None or baseline["versions"] != expected:
                    raise RuntimeError("client version baseline changed")
                if baseline["pending"]:
                    baseline = {**baseline, "pending": False}
                    self._save(directory_fd, baseline)
                self._state = self._view("observed", baseline["versions"], baseline["previous_versions"], False)
                return self.status()
            except (OSError, ValueError, TypeError, AttributeError, RecursionError, OverflowError):
                raise RuntimeError("client version baseline unavailable") from None
            finally:
                if directory_fd is not None:
                    os.close(directory_fd)


ClientVersionObserver = ClaudeVersionObserver

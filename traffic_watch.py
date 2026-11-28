"""Cache-only public API for a bounded, passive background connection observer.

No observer thread can terminate Claude. Fresh current evidence, lifecycle
history, and an acknowledged physical-bypass latch are separate projections.
"""
import copy
import threading
import time

from traffic_evidence import (
    BACKENDS, COVERAGE, GROUPS, HISTORY_KEYS, MAX_PROCESSES, MAX_SOCKETS, REASON_CODES,
    ClaudeProcesses, ClaudeTrafficEvidence, empty_evidence, empty_history,
)

ACTION_REASON = 'connection_route_bypass'
INTERVALS_MS = frozenset((250, 500, 1000, 2000, 5000))


def _count(value):
    if type(value) is not int or not 0 <= value < 2**63:
        raise ValueError('invalid fixed counter')
    return value


def _clean_history(value):
    if not isinstance(value, dict) or not isinstance(value.get('groups'), list) or len(value['groups']) != len(GROUPS):
        raise ValueError('invalid history')
    by_id = {}
    for group in value['groups']:
        if not isinstance(group, dict) or group.get('id') not in GROUPS or group['id'] in by_id:
            raise ValueError('invalid history group')
        by_id[group['id']] = dict(id=group['id'], **{key: _count(group.get(key, 0)) for key in HISTORY_KEYS})
    history = empty_history()
    history.update(groups=[by_id[group] for group in GROUPS],
                   dedupe_evictions=_count(value.get('dedupe_evictions', 0)), limited=value.get('limited') is True)
    history['direct_observed'] = any(group['direct_connection_total'] for group in history['groups'])
    return history


def _merge_history(previous, current):
    history = empty_history()
    history['groups'] = [dict(id=before['id'], **{
        key: max(before[key], after[key]) for key in HISTORY_KEYS})
        for before, after in zip(previous['groups'], current['groups'])]
    history['dedupe_evictions'] = max(previous['dedupe_evictions'], current['dedupe_evictions'])
    history['limited'] = previous['limited'] or current['limited']
    history['direct_observed'] = any(group['direct_connection_total'] for group in history['groups'])
    return history


def _clean_evidence(value):
    if not isinstance(value, dict) or value.get('state') not in ('observed', 'unknown', 'not_running'):
        raise ValueError('invalid evidence state')
    result = empty_evidence(value['state'])
    groups = value.get('groups')
    if not isinstance(groups, list) or len(groups) != len(GROUPS):
        raise ValueError('invalid evidence groups')
    by_id = {}
    for group in groups:
        if not isinstance(group, dict) or group.get('id') not in GROUPS or group['id'] in by_id:
            raise ValueError('invalid evidence group')
        template = next(item for item in result['groups'] if item['id'] == group['id'])
        clean = dict(id=group['id'])
        for key, default in template.items():
            if key == 'id':
                continue
            if isinstance(default, dict):
                raw = group.get(key, {})
                if not isinstance(raw, dict):
                    raise ValueError('invalid evidence dimension')
                clean[key] = {name: _count(raw.get(name, 0)) for name in default}
            else:
                clean[key] = _count(group.get(key, 0))
        if (clean['process_count'] > MAX_PROCESSES or clean['socket_count'] > MAX_SOCKETS or
                clean['matched_count'] > clean['socket_count'] or
                any(sum(clean[key].values()) != clean['socket_count'] for key in
                    ('ingress_counts', 'transport_counts', 'route_counts'))):
            raise ValueError('inconsistent evidence dimensions')
        if value['state'] != 'observed' and (clean['matched_count'] or
                any(count for name, count in clean['route_counts'].items() if name != 'unknown')):
            raise ValueError('unconfirmed positive evidence')
        by_id[group['id']] = clean
    result['groups'] = [by_id[group] for group in GROUPS]
    route = value.get('route_evidence', {})
    if not isinstance(route, dict):
        raise ValueError('invalid route projection')
    result['route_evidence'] = {key: route.get(key) if type(route.get(key)) is bool else None
                                for key in result['route_evidence']}
    codes = value.get('reason_codes', [])
    if not isinstance(codes, list) or any(code not in REASON_CODES for code in codes):
        raise ValueError('invalid evidence reasons')
    result['reason_codes'] = sorted(set(codes))
    backend = value.get('backend', 'none')
    result['backend'] = backend if backend in BACKENDS else 'none'
    result['interval_floor_ms'] = 2000 if result['backend'] == 'lsof_fallback' else 0
    result['limited'] = value.get('limited') is True or result['backend'] == 'lsof_fallback'
    result['history'] = _clean_history(value.get('history', empty_history()))
    return result


class ClaudeTrafficWatch:
    """Constructor is inert; status/sample/get_status never run an observation.

    A lifecycle starts at start/reset. Stop preserves numeric history but revokes
    current evidence and action latches. Invalidation revokes current evidence
    while preserving history and unhandled, previously observed bypass actions.
    """
    def __init__(self, runtime=None, processes_factory=ClaudeProcesses, socket_reader=None,
                 route_reader=None, *, evidence_factory=None, interval_ms=500, clock=time.monotonic):
        if type(interval_ms) is not int or interval_ms not in INTERVALS_MS:
            raise ValueError('unsupported connection observation interval')
        self._factory = evidence_factory or (lambda: ClaudeTrafficEvidence(
            runtime, processes_factory, socket_reader, route_reader))
        self._clock = clock
        self._lock = threading.RLock()
        self._lifecycle = threading.Lock()
        self._thread = None
        self._pending_thread = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._running = False
        self._generation = self._reset_version = self._run_id = 0
        self._requested_interval = self._interval = interval_ms
        self._samples = self._event_seq = 0
        self._backend = 'none'
        self._limited = False
        self._state = 'stopped'
        self._checked_at = None
        self._last_sample_ms = 0
        self._evidence = empty_evidence('unknown', ['traffic_stopped'])
        self._history = empty_history()
        self._action_seq = None
        self._checking_since = None
        self._fallback_after = 0

    def _revoke(self, state, reason):
        self._state, self._checked_at = state, None
        self._checking_since = self._clock()
        self._evidence = empty_evidence('unknown', [reason])

    def start(self):
        with self._lifecycle:
            with self._lock:
                if self._running:
                    return self.status()
                finishing = self._thread is not None and self._thread.is_alive()
                self._generation += 1
                self._reset_version += 1
                self._run_id += 1
                self._stop, self._wake = threading.Event(), threading.Event()
                self._running = True
                self._samples = 0
                self._history = empty_history()
                self._action_seq = None
                self._interval = self._requested_interval
                self._backend, self._limited = 'none', False
                self._last_sample_ms = 0
                self._event_seq += 1
                self._revoke('checking', 'traffic_checking')
                thread = threading.Thread(target=self._run, args=(self._run_id, self._stop, self._wake),
                                          name='rg-connection-watch', daemon=True)
                if finishing:
                    self._pending_thread = thread
                else:
                    self._thread = thread
            try:
                if not finishing:
                    thread.start()
            except Exception:
                with self._lock:
                    self._running = False
                    self._revoke('unknown', 'traffic_worker_stopped')
                raise RuntimeError('connection observer could not start') from None
        return self.status()

    def stop(self):
        with self._lifecycle, self._lock:
            self._generation += 1
            self._running = False
            self._action_seq = None
            self._pending_thread = None
            self._stop.set()
            self._wake.set()
            self._event_seq += 1
            self._revoke('stopped', 'traffic_stopped')
        return self.status()  # never join a worker blocked in IO on an HTTP thread

    def reset(self):
        with self._lock:
            self._generation += 1
            self._reset_version += 1
            self._samples = 0
            self._history = empty_history()
            self._action_seq = None
            self._event_seq += 1
            self._revoke('checking' if self._running else 'stopped',
                         'traffic_checking' if self._running else 'traffic_stopped')
            self._wake.set()
        return self.status()

    def invalidate(self, *, clear_actions=False):
        if type(clear_actions) is not bool:
            raise ValueError('clear_actions must be boolean')
        with self._lock:
            self._generation += 1
            if clear_actions:
                self._action_seq = None
            self._event_seq += 1
            self._revoke('checking' if self._running else 'stopped',
                         'traffic_checking' if self._running else 'traffic_stopped')
            self._wake.set()
        return self.status()

    on_wake = invalidate

    def acknowledge(self, event_seq):
        with self._lock:
            if (type(event_seq) is int and self._action_seq is not None and
                    self._action_seq <= event_seq <= self._event_seq):
                self._action_seq = None
                self._event_seq += 1

    def configure(self, interval_ms):
        if type(interval_ms) is not int or interval_ms not in INTERVALS_MS:
            raise ValueError('unsupported connection observation interval')
        with self._lock:
            self._requested_interval = interval_ms
            self._interval = max(interval_ms, 2000 if self._backend == 'lsof_fallback' else 0)
        return self.invalidate()

    def status(self):
        with self._lock:
            evidence, history = copy.deepcopy(self._evidence), copy.deepcopy(self._history)
            threshold = max(1500, 3 * self._interval + 500)
            age = None if self._checked_at is None else round(max(0, self._clock() - self._checked_at) * 1000, 3)
            state, limited = self._state, self._limited
            if self._running and age is not None and age > threshold:
                state, limited = 'unknown', True
                evidence = empty_evidence('unknown', ['traffic_stale'])
            elif (self._running and age is None and self._checking_since is not None and
                    (self._clock() - self._checking_since) * 1000 > threshold):
                state, limited = 'unknown', True
                evidence = empty_evidence('unknown', ['traffic_stale'])
            return dict(running=self._running, state=state, interval_ms=self._interval,
                        requested_interval_ms=self._requested_interval, stale_after_ms=threshold,
                        samples=self._samples, event_seq=self._event_seq, last_check_age_ms=age,
                        last_sample_ms=self._last_sample_ms, backend=self._backend,
                        limited=limited, coverage=COVERAGE, all_traffic_covered=False,
                        reason_codes=list(evidence['reason_codes']), evidence=evidence, history=history,
                        action_reason_codes=[ACTION_REASON] if self._action_seq is not None else [])

    sample = status
    get_status = status

    def _run(self, run_id, stop, wake):
        sampler, sampler_version, last_started, floor = None, None, None, 0
        try:
            while not stop.is_set():
                with self._lock:
                    generation, reset_version = self._generation, self._reset_version
                    requested = self._requested_interval
                with self._lock:
                    fallback_after = self._fallback_after
                if fallback_after > self._clock() or last_started is not None and floor:
                    remaining = max(fallback_after, last_started + floor / 1000 if last_started is not None else 0) - self._clock()
                    if remaining > 0:
                        wake.clear()
                        wake.wait(min(remaining, 2))
                        continue  # invalidation cannot hot-loop the lsof fallback
                if sampler_version != reset_version:
                    if sampler is not None:
                        try:
                            sampler.close()
                        except Exception:
                            pass
                    sampler = self._factory()
                    sampler_version = reset_version
                if stop.is_set():
                    break
                started = self._clock()
                last_started = started
                try:
                    observed = _clean_evidence(sampler.sample())
                except Exception:
                    observed = empty_evidence('unknown', ['traffic_evidence_unavailable'])
                    with self._lock:
                        observed['backend'] = self._backend
                    observed['interval_floor_ms'] = 2000 if observed['backend'] == 'lsof_fallback' else 0
                    observed['limited'] = True
                finished = self._clock()
                floor = observed['interval_floor_ms']
                with self._lock:
                    if floor:
                        self._fallback_after = max(self._fallback_after, started + floor / 1000)
                    if self._running and run_id == self._run_id and generation == self._generation and not stop.is_set():
                        self._evidence = observed
                        self._history = _merge_history(self._history, observed['history'])
                        observed['history'] = copy.deepcopy(self._history)
                        self._state = observed['state']
                        self._backend = observed['backend']
                        self._limited = observed['limited']
                        self._interval = max(requested, floor)
                        self._samples += 1
                        self._event_seq += 1
                        self._checked_at = started
                        self._last_sample_ms = round(max(0, finished - started) * 1000, 3)
                        if any(group['route_counts']['physical_bypass'] for group in observed['groups']):
                            self._action_seq = self._event_seq
                    interval = max(self._requested_interval, floor)
                    needs_refresh = generation != self._generation or reset_version != self._reset_version
                    wake.clear()  # invalidate sets this under the same lock, so no wake is lost
                if needs_refresh:
                    continue
                delay = max(0, started + interval / 1000 - self._clock())
                if not stop.is_set():
                    wake.wait(delay)
        except BaseException:
            with self._lock:
                if self._running and run_id == self._run_id and not stop.is_set():
                    self._running = False
                    self._event_seq += 1
                    self._revoke('unknown', 'traffic_worker_stopped')
        finally:
            if sampler is not None:
                try:
                    sampler.close()
                except Exception:
                    pass
            # A rapid stop/start reuses one outstanding IO lane. Only the latest
            # requested lifecycle starts after the old reader has closed.
            with self._lifecycle:
                with self._lock:
                    if self._thread is threading.current_thread():
                        self._thread = None  # IO cleanup is complete, even before this thread returns
                    pending = self._pending_thread
                    self._pending_thread = None
                    if pending is not None and self._running and not self._stop.is_set():
                        self._thread = pending
                    else:
                        pending = None
                if pending is not None:
                    try:
                        pending.start()
                    except Exception:
                        with self._lock:
                            self._running = False
                            self._event_seq += 1
                            self._revoke('unknown', 'traffic_worker_stopped')

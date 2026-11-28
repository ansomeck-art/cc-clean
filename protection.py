"""100ms local protection worker, independent of slow Internet probes and UI callbacks."""
import copy
import datetime
import math
import os
import queue
import sys
import threading
import time

from mac_guard import ClaudeProcesses, DarwinNetwork
from artifact_watch import ClaudeArtifactWatch
from service_diagnostics import DIAGNOSTIC_KEYS

REASONS = {
    'ipv4_route_missing': '未发现有效公网 IPv4 路由',
    'ipv4_bypass': '公网 IPv4 路由绕过 TUN',
    'ipv6_bypass': '物理 IPv6 存在绕过 TUN 的路由',
    'tun_down': 'TUN 接口离线',
    'route_unreachable': '公网路由不可达',
    'kernel_unknown': '本地路由安全状态无法读取',
    'remote_pending': '公网安全状态尚未确认',
    'wake_pending': '系统唤醒，正在重新确认安全状态',
    'remote_unreachable': '公网探测失败或断网',
    'country_mismatch': '出口国家与目标不一致',
    'restricted_egress': '出口进入受限地区',
    'ip_changed': '公网出口 IP 跳变',
    'remote_stale': '公网探测结果已过期',
    'route_pending': 'TUN 路由发生变化，正在重新确认出口',
    'process_unknown': 'Claude 进程身份检查不可用',
    'termination_denied': '系统未允许终止已确认的 Claude 进程',
    'connection_route_bypass': 'Claude 公网目的地址存在绕过 TUN 的路由',
    'telemetry_cn_country': '受检文件出现中国国家或地区字段',
    'telemetry_cn_locale': '受检文件出现明确 CN 区域偏好',
    'telemetry_cn_timezone': '受检文件出现大陆时区',
    'telemetry_file_unknown': '受检文件无法安全核验',
    'telemetry_file_pending': '正在核验本地文件',
    'telemetry_file_stale': '本地文件观察器结果已过期',
    'telemetry_pending': '本地文件风险解除，正在重新确认出口',
}

TELEMETRY_COVERAGE = '8 组固定来源；地区字段、日志码及元数据分开观察；不读取 Cookie 值、设备 ID、MCP 配置内容或离线队列正文'
TELEMETRY_REASONS = frozenset(code for code in REASONS if code.startswith('telemetry_') and code != 'telemetry_pending')
TELEMETRY_RISK_REASONS = frozenset(code for code in TELEMETRY_REASONS if code.startswith('telemetry_cn_'))
ARTIFACT_MODES = dict(sentry_scope='fields', sentry_queue='metadata', app_config='fields',
                      electron_preferences='fields', desktop_config='metadata', cookie_store='metadata',
                      installation_id='metadata', claude_logs='log_codes')
ARTIFACT_LABELS = dict(sentry_scope='Sentry 地区快照', sentry_queue='Sentry 离线队列', app_config='应用配置',
                       electron_preferences='语言偏好', desktop_config='桌面配置', cookie_store='Cookie 存储',
                       installation_id='安装标识', claude_logs='Claude 日志')
ARTIFACT_COUNTERS = ('region', 'banned', 'evicted', 'telemetry', 'device', 'stripe', 'network')


def stopped_artifact_sources():
    return [dict(id=source_id, mode=mode, state='stopped', reason_codes=[], field_types=[],
                 change_count=0, file_count=0, total_bytes=0, files_checked=0,
                 last_check_age_ms=None, counters=dict.fromkeys(ARTIFACT_COUNTERS, 0),
                 diagnostics=dict.fromkeys(DIAGNOSTIC_KEYS, 0), limited=False)
            for source_id, mode in ARTIFACT_MODES.items()]


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec='milliseconds')


class FastProtector:
    def __init__(self, network_factory=DarwinNetwork, process_factory=ClaudeProcesses,
                 supported=None, clock=time.monotonic, callback=None,
                 telemetry_factory=ClaudeArtifactWatch, connection_provider=None, connection_acknowledge=None):
        self.supported = sys.platform == 'darwin' if supported is None else supported
        self.network_factory, self.process_factory = network_factory, process_factory
        self.telemetry_factory = telemetry_factory
        self.connection_provider = connection_provider
        self.connection_acknowledge = connection_acknowledge
        self.clock, self.callback = clock, callback
        self._lock = threading.RLock()
        self._action_lock = threading.Lock()
        self._lifecycle = threading.Lock()
        self._stop = threading.Event()
        self._refresh = threading.Event()
        self._thread = self._dispatch_thread = None
        self._queue = queue.Queue(maxsize=32)
        self._network = self._processes = self._telemetry = None
        self._target, self._interval_ms, self._remote_interval = 'US', 100, 30
        self._enabled = False
        self._generation = 0
        self._remote = None
        self._remote_after = self.clock()
        self._remote_at = None
        self._wake_pending = False
        self._route_pending = False
        self._telemetry_pending = False
        self._last_telemetry_blocked = None
        self._last_connection_blocked = None
        self._last_local_safe = None
        self._last_fingerprint = None
        self._last_local_at = None
        self._state = dict(enabled=False, supported=self.supported, running=False, status='paused',
                           poll_interval_ms=100, reason_codes=[], reasons=[], interfaces=[],
                           last_sample_ms=0, last_action_ms=0, samples=0, terminated_total=0,
                           last_action=None, event_seq=0, route_events=False, last_check_at=None, local_safe=None,
                           kernel_backend_available=False, process_backend_available=False,
                           telemetry_backend_available=False,
                           telemetry=dict(state='stopped', reason_codes=[], field_types=[],
                                          last_check_age_ms=None, backend='none', coverage=TELEMETRY_COVERAGE,
                                          sources=stopped_artifact_sources(), risk_source_ids=[]))
        self._last_signature = None
        self._last_failed_action = None

    def set_callback(self, callback):
        self.callback = callback

    def _pause_file_status(self):
        """Caller holds the state lock; old evidence never looks active after stop."""
        self._state['telemetry'].update(state='stopped', reason_codes=[], field_types=[], risk_source_ids=[])
        for source in self._state['telemetry'].get('sources', []):
            source.update(state='stopped', reason_codes=[], field_types=[])

    def status(self):
        with self._lock:
            value = copy.deepcopy(self._state)
            value['last_check_age_ms'] = round((self.clock() - self._last_local_at) * 1000, 1) if self._last_local_at is not None else None
            return value

    def _enqueue(self):
        snapshot = self.status()
        try:
            self._queue.put_nowait(snapshot)
        except queue.Full:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait(snapshot)
            except queue.Full:
                pass

    def _dispatch(self, stop_event, notifications):
        while True:
            try:
                value = notifications.get(timeout=.1)
            except queue.Empty:
                if stop_event.is_set():
                    return
                continue
            if value is None:
                return
            try:
                if self.callback:
                    self.callback(value)
            except Exception:
                pass  # listener/disk/notification failures must not block protection

    def configure(self, target, enabled=True, interval_ms=100, remote_interval=30):
        if type(enabled) is not bool:
            raise ValueError('local protection enable must be boolean')
        if type(interval_ms) is not int or interval_ms not in (50, 100, 250, 500):
            raise ValueError('local guard interval must be 50, 100, 250 or 500 ms')
        if type(remote_interval) is not int or not 1 <= remote_interval <= 3600:
            raise ValueError('remote interval must be a positive integer')
        with self._action_lock:
            with self._lock:
                was_enabled = self._enabled
                changed = target != self._target
                self._target, self._enabled = target, enabled and self.supported
                self._interval_ms, self._remote_interval = interval_ms, remote_interval
                self._generation += 1
                if changed or (self._enabled and not was_enabled):
                    self._remote, self._remote_at = None, None
                    self._remote_after = self.clock()
                    self._wake_pending = self._route_pending = False
                    self._telemetry_pending = False
                    self._last_telemetry_blocked = None
                    self._last_connection_blocked = None
                    self._last_local_safe = self._last_fingerprint = None
                self._state.update(enabled=self._enabled, poll_interval_ms=interval_ms)
                if not self._enabled:
                    self._state.update(status='paused', reason_codes=[], reasons=[])
                    self._pause_file_status()
                elif self._state['running']:
                    self._state.update(status='checking')
        self._refresh.set()
        self._enqueue()

    def start(self, target='US', enabled=True, interval_ms=100, remote_interval=30):
        with self._lifecycle:
            self.configure(target, enabled, interval_ms, remote_interval)
            if not self.supported:
                with self._lock:
                    self._state.update(status='unsupported')
                return
            if self._thread and self._thread.is_alive():
                if self._stop.is_set():
                    raise RuntimeError('previous local guard is still finishing')
                return
            if self._dispatch_thread and self._dispatch_thread.is_alive():
                self._stop.set()
                try:
                    self._queue.put_nowait(None)
                except queue.Full:
                    pass
                self._dispatch_thread.join(2)
            with self._lock:
                self._stop = threading.Event()
                self._queue = queue.Queue(maxsize=32)
                self._remote, self._remote_at = None, None
                self._remote_after = self.clock()
                self._last_local_safe = self._last_fingerprint = None
                self._last_telemetry_blocked = None
                self._last_connection_blocked = None
                self._telemetry_pending = False
                self._last_signature = self._last_failed_action = None
                self._state.update(running=True, status='checking' if self._enabled else 'paused')
            self._dispatch_thread = threading.Thread(target=self._dispatch, args=(self._stop, self._queue), name='rg-protection-events', daemon=True)
            self._thread = threading.Thread(target=self._loop, name='rg-local-protection', daemon=True)
            self._dispatch_thread.start()
            self._thread.start()

    def stop(self):
        with self._lifecycle:
            with self._action_lock:
                with self._lock:
                    self._state.update(running=False, status='paused', reason_codes=[], reasons=[])
                    self._pause_file_status()
                    self._stop.set()
            self._refresh.set()
            thread = self._thread
            if thread and thread is not threading.current_thread():
                thread.join(3)
            self._enqueue()
            try:
                self._queue.put_nowait(None)
            except queue.Full:
                pass
            if self._dispatch_thread and self._dispatch_thread is not threading.current_thread():
                self._dispatch_thread.join(2)

    def on_wake(self):
        with self._action_lock:
            with self._lock:
                if not self._state['running'] or not self._enabled:
                    return
                self._wake_pending = True
                self._remote = None
                self._remote_after = self.clock()
                self._generation += 1
        self._refresh.set()

    def on_route_change(self):
        with self._action_lock:
            with self._lock:
                if not self._state['running'] or not self._enabled:
                    return
                self._route_pending = True
                self._remote = None
                self._remote_after = self.clock()
                self._generation += 1
        self._refresh.set()

    def observe_pulse(self, event, started_at):
        """Ignore pre-wake, previous-target and out-of-order results."""
        with self._action_lock:
            with self._lock:
                if (not self._state['running'] or not self._enabled or event.get('target') != self._target
                        or started_at < self._remote_after):
                    return
                if self._remote and started_at < self._remote['started_at']:
                    return
                codes = []
                if not event.get('ok'):
                    codes.append('remote_unreachable')
                elif event.get('loc') != self._target:
                    codes.append('country_mismatch')
                if event.get('loc') in {'CN', 'HK', 'MO', 'RU', 'BY', 'KP', 'IR', 'CU', 'SY'}:
                    codes.append('restricted_egress')
                if event.get('colo') in {'HKG', 'MFM', 'PVG', 'PEK', 'CAN', 'SZX', 'CTU', 'SHA', 'DME', 'SVO', 'MSQ', 'THR'}:
                    codes.append('restricted_egress')
                if '出口进入受限地区' in (event.get('anomaly_reasons') or []):
                    codes.append('restricted_egress')
                if not event.get('utun_up'):
                    codes.append('tun_down')
                if event.get('changed_ip'):
                    codes.append('ip_changed')
                self._remote = dict(started_at=started_at, codes=sorted(set(codes)))
                self._remote_at = self.clock()
                self._wake_pending = self._route_pending = False
                self._telemetry_pending = False
        self._refresh.set()

    def _telemetry_snapshot(self):
        """Only fixed labels and numeric evidence may cross the observer boundary."""
        fallback = dict(state='unknown', reason_codes=['telemetry_file_unknown'], field_types=[],
                        last_check_age_ms=None, last_scan_ms=0, backend='none',
                        coverage=TELEMETRY_COVERAGE, files_checked=0, event_seq=0,
                        sources=[], risk_source_ids=[])
        try:
            raw = self._telemetry.sample()
            if not isinstance(raw, dict) or raw.get('state') not in {'checking', 'safe', 'observed', 'risk', 'unknown', 'missing', 'stopped'}:
                return fallback
            codes = raw.get('reason_codes', [])
            fields = raw.get('field_types', [])
            if (not isinstance(codes, (list, tuple)) or any(code not in TELEMETRY_REASONS for code in codes)
                    or not isinstance(fields, (list, tuple)) or any(field not in {'country', 'locale', 'timezone'} for field in fields)):
                return fallback
            value = {**fallback, 'state': raw['state'], 'reason_codes': sorted(set(codes)),
                     'field_types': sorted(set(fields))}
            for key in ('last_check_age_ms', 'last_scan_ms'):
                number = raw.get(key)
                if (key == 'last_check_age_ms' and number is None and raw['state'] == 'risk'
                        and any(code in TELEMETRY_RISK_REASONS for code in codes)):
                    # Restart can retain an observed risk before its new worker
                    # has an age. Missing freshness cannot erase positive evidence.
                    continue
                if type(number) not in (int, float) or not math.isfinite(number) or number < 0:
                    if key == 'last_check_age_ms':
                        return fallback
                    continue
                value[key] = round(number, 3)
            for key in ('files_checked', 'event_seq'):
                number = raw.get(key)
                if type(number) is int and 0 <= number < 2**63:
                    value[key] = number
            if 'sources' in raw:
                sources = raw['sources']
                if (not isinstance(sources, list) or len(sources) != len(ARTIFACT_MODES)
                        or any(not isinstance(source, dict) for source in sources)):
                    return fallback
                by_id = {}
                for source in sources:
                    source_id = source.get('id')
                    if (source_id not in ARTIFACT_MODES or source_id in by_id
                            or source.get('mode') != ARTIFACT_MODES[source_id]
                            or source.get('state') not in {'safe', 'risk', 'unknown', 'missing', 'observed', 'checking', 'stopped'}):
                        return fallback
                    source_codes, source_fields = source.get('reason_codes', []), source.get('field_types', [])
                    if (not isinstance(source_codes, list) or any(code not in TELEMETRY_REASONS for code in source_codes)
                            or not isinstance(source_fields, list) or any(field not in {'country', 'locale', 'timezone'} for field in source_fields)):
                        return fallback
                    if source['state'] == 'risk' and not any(code.startswith('telemetry_cn_') for code in source_codes):
                        return fallback
                    if source['mode'] == 'metadata' and (source_fields or any(code.startswith('telemetry_cn_') for code in source_codes)):
                        return fallback
                    if 'limited' in source and type(source['limited']) is not bool:
                        return fallback
                    clean = dict(id=source_id, mode=source['mode'], state=source['state'],
                                 reason_codes=sorted(set(source_codes)), field_types=sorted(set(source_fields)),
                                 limited=source.get('limited') is True)
                    for key in ('change_count', 'file_count', 'total_bytes', 'files_checked'):
                        count = source.get(key, 0)
                        if type(count) is not int or not 0 <= count < 2**63:
                            return fallback
                        clean[key] = count
                    age = source.get('last_check_age_ms')
                    if age is not None and (type(age) not in (int, float) or not math.isfinite(age) or age < 0):
                        return fallback
                    if age is None and source['state'] in {'safe', 'observed'}:
                        return fallback
                    clean['last_check_age_ms'] = round(age, 3) if age is not None else None
                    if (age is not None and age > max(500, self._interval_ms * 3 + 250)
                            and clean['state'] != 'risk'):
                        clean.update(state='unknown', reason_codes=['telemetry_file_stale'])
                    counters = source.get('counters', {})
                    if not isinstance(counters, dict):
                        return fallback
                    clean['counters'] = {}
                    for key in ARTIFACT_COUNTERS:
                        count = counters.get(key, 0)
                        if type(count) is not int or not 0 <= count < 2**63:
                            return fallback
                        clean['counters'][key] = count
                    diagnostics = source.get('diagnostics', {})
                    if not isinstance(diagnostics, dict):
                        return fallback
                    clean['diagnostics'] = {}
                    for key in DIAGNOSTIC_KEYS:
                        count = diagnostics.get(key, 0)
                        if type(count) is not int or not 0 <= count < 2**63:
                            return fallback
                        clean['diagnostics'][key] = count if source_id == 'claude_logs' else 0
                    by_id[source_id] = clean
                value['sources'] = [by_id[source_id] for source_id in ARTIFACT_MODES]
                risk_ids = raw.get('risk_source_ids', [source['id'] for source in value['sources'] if source['state'] == 'risk'])
                if not isinstance(risk_ids, list) or any(source_id not in ARTIFACT_MODES or ARTIFACT_MODES[source_id] == 'metadata' for source_id in risk_ids):
                    return fallback
                value['risk_source_ids'] = sorted(set(risk_ids))
                positive = [source for source in value['sources'] if any(code.startswith('telemetry_cn_') for code in source['reason_codes'])]
                if positive:
                    value['state'] = 'risk'
                    value['reason_codes'] = sorted(set(value['reason_codes'] + [code for source in positive for code in source['reason_codes'] if code.startswith('telemetry_cn_')]))
                    value['risk_source_ids'] = sorted(set(value['risk_source_ids'] + [source['id'] for source in positive]))
                elif value['state'] not in {'risk', 'checking', 'stopped'} and any(source['state'] == 'unknown' for source in value['sources']):
                    reason = 'telemetry_file_stale' if any('telemetry_file_stale' in source['reason_codes'] for source in value['sources']) else 'telemetry_file_unknown'
                    value.update(state='unknown', reason_codes=[reason])
            backend = raw.get('backend')
            if backend in {'kqueue', 'kqueue+poll', 'kqueue+stat', 'stat', 'poll', 'none'}:
                value['backend'] = backend
            # Positive, latched CN evidence survives stale timestamps. Uncertainty
            # alone is only a coverage warning and cannot create a kill reason.
            if value['state'] != 'risk' and value['last_check_age_ms'] > max(500, self._interval_ms * 3 + 250):
                value.update(state='unknown', reason_codes=['telemetry_file_stale'])
            elif value['state'] in {'checking', 'stopped'}:
                value['reason_codes'] = ['telemetry_file_pending']
            elif value['state'] == 'unknown':
                value['reason_codes'] = ['telemetry_file_stale'] if 'telemetry_file_stale' in value['reason_codes'] else ['telemetry_file_unknown']
            elif value['state'] == 'risk':
                value['reason_codes'] = [code for code in value['reason_codes'] if code.startswith('telemetry_cn_')]
                if not value['reason_codes']:
                    return fallback
            else:
                # Missing has no positive country evidence; disclose the coverage gap.
                value['reason_codes'] = []
            return value
        except Exception:
            return fallback

    def _connection_risk(self):
        """Only a fixed, explicitly observed bypass latch may request an action.

        This is a cache-only callback. Unknown connection coverage, an unavailable
        controller, and a controller's DIRECT choice alone never request a kill.
        """
        if self.connection_provider is None:
            return False, None
        try:
            value = self.connection_provider()
            if not isinstance(value, dict) or value.get('state') not in {'checking', 'observed', 'unknown', 'not_running'}:
                return False, None
            codes, sequence = value.get('action_reason_codes', []), value.get('event_seq')
            if (type(codes) is not list or any(code != 'connection_route_bypass' for code in codes)
                    or type(sequence) is not int or not 0 <= sequence < 2**63):
                return False, None
            return bool(codes), sequence
        except Exception:
            return False, None

    def _step(self):
        started = self.clock()
        with self._lock:
            generation = self._generation
            armed = self._enabled and self._state['running'] and not self._stop.is_set()
        if not armed:
            return
        telemetry = self._telemetry_snapshot()
        connection_blocked, connection_sequence = self._connection_risk()
        try:
            local = self._network.sample()
            if (not isinstance(local, dict) or type(local.get('safe')) is not bool
                    or not isinstance(local.get('reasons'), (list, tuple))
                    or not all(isinstance(code, str) for code in local['reasons'])
                    or not isinstance(local.get('interfaces', []), (list, tuple))
                    or not all(isinstance(name, str) for name in local.get('interfaces', []))):
                raise ValueError('invalid kernel snapshot schema')
            codes = list(local.get('reasons') or [])
            if any(code not in REASONS for code in codes):
                codes = ['kernel_unknown']
            if not local.get('safe') and not codes:
                codes = ['kernel_unknown']
        except Exception:
            local, codes = {}, ['kernel_unknown']
        codes.extend(code for code in telemetry['reason_codes'] if code in TELEMETRY_RISK_REASONS)
        if connection_blocked:
            codes.append('connection_route_bypass')
        sampled_at = self.clock()
        with self._action_lock:
            with self._lock:
                if (generation != self._generation or not self._enabled or
                        not self._state['running'] or self._stop.is_set()):
                    return
                local_safe = bool(local.get('safe'))
                fingerprint = local.get('fingerprint')
                route_changed = (self._last_local_safe is False and local_safe) or (
                    local_safe and fingerprint is not None and self._last_fingerprint is not None
                    and fingerprint != self._last_fingerprint)
                if route_changed:
                    self._remote, self._remote_at = None, None
                    self._remote_after = sampled_at
                    self._route_pending = True
                self._last_local_safe, self._last_fingerprint = local_safe, fingerprint
                if self._last_connection_blocked is True and not connection_blocked:
                    self._remote, self._remote_at = None, None
                    self._remote_after = sampled_at
                    self._route_pending = True
                self._last_connection_blocked = connection_blocked
                telemetry_blocked = any(code in TELEMETRY_RISK_REASONS for code in telemetry['reason_codes'])
                if self._last_telemetry_blocked is True and not telemetry_blocked:
                    self._remote, self._remote_at = None, None
                    self._remote_after = sampled_at
                    self._telemetry_pending = True
                self._last_telemetry_blocked = telemetry_blocked
                self._last_local_at = sampled_at
                if self._remote is None:
                    codes.append('wake_pending' if self._wake_pending else ('route_pending' if self._route_pending else (
                        'telemetry_pending' if self._telemetry_pending else 'remote_pending')))
                elif sampled_at - self._remote_at > self._remote_interval * 2 + 5:
                    codes.append('remote_stale')
                else:
                    codes.extend(self._remote['codes'])
                if self._processes is None:
                    codes.append('process_unknown')
            action = None
            if codes:
                action_started = self.clock()
                counts = dict(terminated=0, rejected=0, denied=0, gone=0)
                try:
                    candidates = self._processes.candidates()
                    for identity in candidates:
                        # This action lock serializes disable/stop with signaling.
                        outcome = self._processes.terminate(identity)
                        if outcome in counts:
                            counts[outcome] += 1
                except Exception:
                    codes.append('process_unknown')
                if counts['denied']:
                    codes.append('termination_denied')
                if any(counts.values()):
                    failure_key = (tuple(sorted(set(codes))), tuple(counts.items()))
                    repeated_failure = (not counts['terminated'] and self._last_failed_action is not None
                                        and self._last_failed_action[0] == failure_key
                                        and self.clock() - self._last_failed_action[1] < 5)
                    if not repeated_failure:
                        action = dict(at=now(), cause_codes=sorted(set(codes)), **counts)
                        if not counts['terminated']:
                            self._last_failed_action = failure_key, self.clock()
                action_ms = (self.clock() - action_started) * 1000
            else:
                action_ms = 0
            with self._lock:
                codes = sorted(set(code for code in codes if code in REASONS))
                self._state.update(status='blocked' if codes else 'safe',
                                   reason_codes=codes, reasons=[REASONS[code] for code in codes],
                                   interfaces=local.get('interfaces') or [], last_check_at=now(), local_safe=bool(local.get('safe')),
                                   last_sample_ms=round((sampled_at - started) * 1000, 3),
                                   last_action_ms=round(action_ms, 3), samples=self._state['samples'] + 1,
                                   telemetry=telemetry)
                if telemetry['risk_source_ids']:
                    self._state['reasons'].append('危险来源：' + '、'.join(ARTIFACT_LABELS[source_id] for source_id in telemetry['risk_source_ids']))
                self._state['route_events'] = bool(getattr(self._network, 'events', None))
                if action:
                    self._state['last_action'] = action
                    self._state['terminated_total'] += action['terminated']
                signature = (self._state['status'], tuple(codes), telemetry['state'], tuple(telemetry['field_types']),
                             tuple(telemetry['risk_source_ids']), tuple((source['id'], source['state']) for source in telemetry['sources']))
                changed = signature != self._last_signature or action is not None
                if changed:
                    self._state['event_seq'] += 1
                    if action is not None:
                        action['event_seq'] = self._state['event_seq']
                    self._last_signature = signature
            if (telemetry['state'] == 'risk' and 'process_unknown' not in codes
                    and not counts['denied'] and not counts['rejected']):
                try:
                    self._telemetry.acknowledge(telemetry['event_seq'])
                except Exception:
                    pass  # an unacknowledged risk remains fail-closed on the next step
            if (connection_blocked and 'process_unknown' not in codes
                    and not counts['denied'] and not counts['rejected'] and self.connection_acknowledge is not None):
                try:
                    self.connection_acknowledge(connection_sequence)
                except Exception:
                    pass  # the observer retains an unhandled positive bypass
        if changed:
            self._enqueue()  # logging, HTTP snapshots and UI callbacks happen on another thread

    def _loop(self):
        try:
            try:
                self._network = self.network_factory()
            except Exception:
                self._network = None
            try:
                self._processes = self.process_factory()
            except Exception:
                self._processes = None
            try:
                self._telemetry = self.telemetry_factory()
                self._telemetry.set_callback(self._refresh.set)
            except Exception:
                self._telemetry = None
            with self._lock:
                self._state['route_events'] = bool(getattr(self._network, 'events', None))
                self._state['kernel_backend_available'] = self._network is not None
                self._state['process_backend_available'] = self._processes is not None
                self._state['telemetry_backend_available'] = self._telemetry is not None
            telemetry_started = False
            telemetry_interval = None
            while not self._stop.is_set():
                tick = self.clock()
                self._refresh.clear()
                with self._lock:
                    enabled, interval_ms = self._enabled, self._interval_ms
                if self._telemetry:
                    try:
                        if telemetry_interval != interval_ms:
                            self._telemetry.configure(interval_ms)
                            telemetry_interval = interval_ms
                        if enabled and not telemetry_started:
                            self._telemetry.start()
                            telemetry_started = True
                        elif not enabled and telemetry_started:
                            self._telemetry.stop()
                            telemetry_started = False
                    except Exception:
                        try:
                            self._telemetry.stop()
                        except Exception:
                            pass
                        self._telemetry = None
                        with self._lock:
                            self._state['telemetry_backend_available'] = False
                self._step()
                with self._lock:
                    period = self._interval_ms / 1000
                    enabled = self._enabled
                remaining = max(.001, period - (self.clock() - tick))
                # Small bounded waits also respond quickly to new remote results / stop.
                deadline = self.clock() + remaining
                while not self._stop.is_set() and not self._refresh.is_set():
                    remaining = deadline - self.clock()
                    if remaining <= 0:
                        break
                    if self._network and enabled:
                        try:
                            if self._network.wait(min(remaining, .02)):
                                if getattr(self._network, 'critical_change', False):
                                    self.on_route_change()
                                break
                        except OSError:
                            self._stop.wait(min(remaining, .02))
                    else:
                        self._refresh.wait(min(remaining, .02))
        except Exception:
            pass  # expose a bounded failure state instead of leaking exception contents
        finally:
            if self._telemetry:
                try:
                    self._telemetry.stop()
                except Exception:
                    pass
            if self._network:
                try:
                    self._network.close()
                except Exception:
                    pass
            with self._lock:
                if self._stop.is_set():
                    self._state.update(running=False, status='paused')
                    self._pause_file_status()
                else:
                    self._state.update(running=False, status='error', reason_codes=['kernel_unknown'],
                                       reasons=['本地保护线程已停止，无法确认保护有效'])
                    self._state['event_seq'] += 1
            if not self._stop.is_set():
                self._enqueue()

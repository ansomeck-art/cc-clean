"""Own the upload worker and its Claude launch, independently of network guarding."""
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import subprocess
import sys
import threading
import time
from telemetry_certificates import HOSTS, CERTIFICATE_NAME, validate_authority_certificate

COUNTERS = ('checked', 'blocked', 'held', 'unattributed', 'tls_requests')
SESSION_ACK_TIMEOUT = 5


class SessionHandshakeError(RuntimeError):
    pass


class TelemetryService:
    def __init__(self, data_dir):
        self.directory = Path(data_dir) / 'telemetry-filter'
        self.lock = threading.RLock()
        self.mutation = threading.Lock()
        self.process = self.client = None
        self.client_port = None
        self.client_session_id = None
        self.ready = threading.Event()
        self.port = None
        self.fingerprint = ''
        self.error = ''
        self.stats = dict.fromkeys(COUNTERS, 0)
        self.session_stats = dict.fromkeys(COUNTERS, 0)
        self.session_id = None
        self._session_worker = None
        self._session_armed = self._session_active = False
        self._ack = threading.Event()
        self._pending_ack = None
        self._ack_ok = False
        self._trusted = False
        self._trust_at = 0

    @staticmethod
    def _command():
        if getattr(sys, 'frozen', False):
            return [sys.executable, '--telemetry-worker']
        return [sys.executable, str(Path(__file__).with_name('telemetry_worker.py'))]

    def _revoke_session(self):
        """Caller holds lock. Never retain proof across a worker/client boundary."""
        self.session_id = self._session_worker = self.client_session_id = self.client_port = None
        self._session_armed = self._session_active = False
        self.session_stats = dict.fromkeys(COUNTERS, 0)
        self._pending_ack, self._ack_ok = None, False
        self._ack.set()

    @staticmethod
    def _counters(value):
        value = value if isinstance(value, dict) else {}
        return {key: count if type(count := value.get(key)) is int and 0 <= count < 2 ** 63 else 0
                for key in COUNTERS}

    def _accept_message(self, process, message):
        with self.lock:
            if process is not self.process:
                return False
            if not isinstance(message, dict):
                return False
            if message.get('event') == 'ready':
                port, fingerprint = message.get('port'), message.get('fingerprint', '')
                if (type(port) is not int or not 0 < port < 65536 or
                        not isinstance(fingerprint, str) or re.fullmatch(r'[0-9a-f]{64}', fingerprint) is None or
                        message.get('session_id') is not None or message.get('session_active') is not False):
                    return False
                if self.port is not None:
                    return True  # A repeated ready cannot change an established worker/session.
                self.port, self.fingerprint = port, fingerprint
                self.ready.set()
            elif message.get('event') == 'stats':
                stats = self._counters(message.get('stats'))
                # Worker totals are historical; they never establish a launch session.
                self.stats = {key: max(self.stats[key], stats[key]) for key in COUNTERS}
                session = message.get('session_stats')
                if (self._session_active and self._session_worker is process and self.session_id is not None and
                        message.get('session_id') == self.session_id and message.get('session_active') is True and
                        isinstance(session, dict) and set(session) == set(COUNTERS) and
                        all(type(session[key]) is int and 0 <= session[key] <= stats[key] for key in COUNTERS)):
                    self.session_stats = {key: max(self.session_stats[key], session[key]) for key in COUNTERS}
            elif message.get('event') == 'session_ack':
                command, session_id = message.get('command'), message.get('session_id')
                if (self._pending_ack != (process, command, session_id) or
                        session_id != self.session_id or self._session_worker is not process):
                    return True
                active = command == 'activate_session'
                if message.get('active') is not active or (active and not self._session_armed):
                    return True
                self._session_armed, self._session_active = True, active
                self.session_stats = dict.fromkeys(COUNTERS, 0)
                self._ack_ok = True
                self._ack.set()
            elif message.get('event') == 'error':
                self.error = '软件内筛选服务启动失败'
                self.port = None
                self._revoke_session()
                self.ready.set()
            return True

    def _read(self, process):
        try:
            while True:
                line = process.stdout.readline(16385)
                if not line or len(line) > 16384:
                    break
                if not self._accept_message(process, json.loads(line)):
                    return
        except (OSError, ValueError, TypeError, AttributeError):
            pass
        finally:
            with self.lock:
                if process is self.process:
                    self.port = None
                    self._revoke_session()
                    self.error = self.error or '软件内筛选服务已停止'
                    self.ready.set()

    def start(self):
        if sys.platform != 'darwin':
            raise RuntimeError('软件内筛选目前支持 macOS')
        with self.mutation:
            with self.lock:
                if self.process is not None and self.process.poll() is None and self.port and not self.error:
                    return self.status()
                self.ready.clear()
                if self.process is not None:
                    self._stop_worker()
                self.error, self.port = '', None
                self.stats = dict.fromkeys(COUNTERS, 0)
                self._revoke_session()
                env = os.environ.copy()
                # The worker's own egress follows the OS/VPN routing unchanged.
                for name in list(env):
                    if name.lower() in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}:
                        env.pop(name)
                try:
                    self.process = subprocess.Popen(self._command() + ['--confdir', str(self.directory)],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                        env=env, text=True, bufsize=1)
                except (OSError, subprocess.SubprocessError):
                    self.error = '软件内筛选服务未能启动'
                    raise RuntimeError(self.error) from None
                threading.Thread(target=self._read, args=(self.process,),
                                 name='rg-upload-worker', daemon=True).start()
            self.ready.wait(20)
            with self.lock:
                if not self.port or self.process.poll() is not None:
                    self._stop_worker()
                    raise RuntimeError(self.error or '软件内筛选服务未能就绪')
        self.refresh_trust(force=True)
        return self.status()

    def _stop_worker(self):
        process = self.process
        self.process, self.port = None, None
        self._revoke_session()
        if process is not None:
            try:
                if process.stdin:
                    process.stdin.close()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
            finally:
                if process.stdout:
                    process.stdout.close()

    def stop(self):
        with self.mutation, self.lock:
            self._stop_worker()
            self.error = ''
        return self.status()

    def refresh_trust(self, force=False):
        with self.lock:
            if not force and time.monotonic() - self._trust_at < 30:
                return self._trusted
            self._trust_at = time.monotonic()
        probe = self.directory / 'trust-probe.pem'
        trusted = sys.platform == 'darwin' and probe.is_file() and self._has_chromium_compatible_trust()
        if trusted:
            try:
                for host in HOSTS:
                    result = subprocess.run(['/usr/bin/security', 'verify-cert', '-q', '-L',
                        '-c', str(probe), '-p', 'ssl', '-n', host], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=5)
                    if result.returncode:
                        trusted = False
                        break
            except (OSError, subprocess.TimeoutExpired):
                trusted = False
        with self.lock:
            self._trusted = trusted
        return trusted

    def _native_certificate(self):
        import Foundation
        import Security
        import ssl
        data = (self.directory / CERTIFICATE_NAME).read_bytes()
        validate_authority_certificate(data)
        der = ssl.PEM_cert_to_DER_cert(data.decode('ascii'))
        cert = Security.SecCertificateCreateWithData(None, Foundation.NSData.dataWithBytes_length_(der, len(der)))
        if cert is None:
            raise RuntimeError('无法读取 RegionGuard 服务证书')
        return cert

    def _has_chromium_compatible_trust(self):
        """SecTrust success alone does not prove Chromium accepts hostname policies."""
        try:
            import Security
            cert = self._native_certificate()
            code, settings = Security.SecTrustSettingsCopyTrustSettings(
                cert, Security.kSecTrustSettingsDomainUser, None)
            if code != 0 or not settings:
                return False
            ssl_policy = Security.SecPolicyCopyProperties(Security.SecPolicyCreateSSL(True, None))[Security.kSecPolicyOid]
            for setting in settings:
                if any(key in setting for key in (Security.kSecTrustSettingsPolicyString,
                       Security.kSecTrustSettingsApplication, Security.kSecTrustSettingsAllowedError)):
                    continue
                policy = setting.get(Security.kSecTrustSettingsPolicy)
                if policy is None:
                    continue
                if (Security.SecPolicyCopyProperties(policy).get(Security.kSecPolicyOid) == ssl_policy and
                        setting.get(Security.kSecTrustSettingsResult) == Security.kSecTrustSettingsResultTrustRoot):
                    return True
        except Exception:
            pass
        return False

    def trust_certificate(self):
        """Trust only an authority with critical constraints for the six exact hosts."""
        self.start()
        import Security
        cert = self._native_certificate()
        result, _ = Security.SecItemAdd({Security.kSecClass: Security.kSecClassCertificate,
                                         Security.kSecValueRef: cert}, None)
        if result not in (0, Security.errSecDuplicateItem):
            raise RuntimeError('证书未添加到用户钥匙串')
        policy = Security.SecPolicyCreateSSL(True, None)
        settings = [{Security.kSecTrustSettingsPolicy: policy,
                     Security.kSecTrustSettingsResult: Security.kSecTrustSettingsResultTrustRoot}]
        result = Security.SecTrustSettingsSetTrustSettings(cert, Security.kSecTrustSettingsDomainUser, settings)
        if result != 0 or not self.refresh_trust(force=True):
            raise RuntimeError('证书信任尚未完成；可重试系统确认')
        return self.status()

    @staticmethod
    def _claude_executable():
        for bundle in (Path('/Applications/Claude.app'), Path.home() / 'Applications/Claude.app'):
            try:
                info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
                if info.get('CFBundleIdentifier') != 'com.anthropic.claudefordesktop':
                    continue
                executable = bundle / 'Contents/MacOS' / info['CFBundleExecutable']
                if executable.is_file() and not executable.is_symlink():
                    return executable
            except (OSError, ValueError, KeyError):
                continue
        raise RuntimeError('未找到 Claude Desktop')

    def _session_command(self, process, command, session_id):
        """Only launch's mutation owner may request a bounded worker handshake."""
        pending = (process, command, session_id)
        with self.lock:
            if (process is not self.process or process.poll() is not None or not self.port or
                    self._session_worker is not process or self.session_id != session_id):
                raise SessionHandshakeError('筛选服务已停止；本次启动未获确认')
            self._pending_ack, self._ack_ok = pending, False
            self._ack.clear()
            try:
                process.stdin.write(json.dumps({'command': command, 'session_id': session_id}) + '\n')
                process.stdin.flush()
            except (OSError, ValueError, AttributeError):
                raise SessionHandshakeError('筛选会话控制不可用；本次启动未获确认') from None
        self._ack.wait(SESSION_ACK_TIMEOUT)
        with self.lock:
            if (self._pending_ack != pending or not self._ack_ok or process is not self.process or
                    process.poll() is not None or not self.port):
                raise SessionHandshakeError('筛选会话确认超时或服务已停止；本次启动未获确认')
            self._pending_ack, self._ack_ok = None, False

    def _disarm(self, process, session_id):
        # Evidence is already revoked locally. This best-effort command also stops
        # the worker counting a failed/abandoned launch; filtering itself continues.
        if process is not None and session_id is not None and process is self.process:
            try:
                process.stdin.write(json.dumps({'command': 'disarm_session', 'session_id': session_id}) + '\n')
                process.stdin.flush()
            except (OSError, ValueError, AttributeError):
                pass

    def launch_claude(self):
        self.start()
        with self.mutation:
            with self.lock:
                old_process, old_session = self._session_worker, self.session_id
                self._revoke_session()
                self._disarm(old_process, old_session)
            try:
                if not self.refresh_trust(force=True):
                    raise RuntimeError('请先完成 RegionGuard 证书信任')
                existing = subprocess.run(['/usr/bin/pgrep', '-x', 'Claude'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
                if existing.returncode == 0:
                    raise RuntimeError('请先在 Claude 中保存工作并正常退出，再从这里启动')
                if existing.returncode != 1:
                    raise RuntimeError('无法确认 Claude 进程状态')
                executable = self._claude_executable()
                with self.lock:
                    process, port = self.process, self.port
                    if process is None or process.poll() is not None or not port:
                        raise RuntimeError('筛选服务已停止，请重试')
                    self.session_id = session_id = secrets.token_hex(16)
                    self._session_worker = process
                self._session_command(process, 'arm_session', session_id)
                url = 'http://127.0.0.1:' + str(port)
                env = os.environ.copy()
                for name in list(env):
                    if name.lower() in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}:
                        env.pop(name)
                for name in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'):
                    env[name] = url
                env['NO_PROXY'] = env['no_proxy'] = 'localhost,127.0.0.1,::1'
                env['NODE_EXTRA_CA_CERTS'] = str(self.directory / CERTIFICATE_NAME)
                with self.lock:
                    if process is not self.process or process.poll() is not None or self.port != port:
                        raise SessionHandshakeError('筛选服务已停止；本次启动未获确认')
                    self.client = subprocess.Popen([str(executable), '--proxy-server=' + url,
                                                   '--disable-quic'], env=env,
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.client_port, self.client_session_id = port, session_id
                self._session_command(process, 'activate_session', session_id)
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                with self.lock:
                    failed_process, failed_session = self._session_worker, self.session_id
                    self._revoke_session()
                    if isinstance(exc, SessionHandshakeError):
                        self.error = str(exc)
                        self._stop_worker()  # An unacknowledged proxy never adds a direct fallback.
                    else:
                        self._disarm(failed_process, failed_session)
                if isinstance(exc, RuntimeError):
                    raise
                raise RuntimeError('无法启动 Claude；本次筛选会话未获确认') from None
        return self.status()

    def status(self):
        with self.lock:
            running = self.process is not None and self.process.poll() is None and self.port is not None
            client = (running and self.client is not None and self.client.poll() is None and
                      self.client_port == self.port and self.session_id is not None and
                      self.client_session_id == self.session_id and self._session_worker is self.process)
            if (not running or (self.session_id is not None and self._session_worker is not self.process) or
                    ((self._session_active or self.client_session_id is not None) and not client)):
                self._revoke_session()
            confirmed = bool(client and self._trusted and self._session_active and self.session_stats['tls_requests'])
            state = 'error' if self.error else 'stopped' if not running else (
                'needs_trust' if not self._trusted else 'connected' if confirmed else
                'awaiting_traffic' if client else 'ready')
            return {'owner': 'RegionGuard', 'state': state, 'running': running,
                    'proxy_url': 'http://127.0.0.1:' + str(self.port) if running else '',
                    'certificate_trusted': self._trusted, 'fingerprint': self.fingerprint,
                    'client_started': client, 'stats': dict(self.stats), 'error': self.error,
                    'session_id': self.session_id, 'session_stats': dict(self.session_stats),
                    'traffic_confirmed': confirmed,
                    'client_exit_code': self.client.poll() if self.client is not None else None,
                    'hosts': list(HOSTS), 'coverage': '仅经过本服务的已识别 Claude 遥测；忽略代理的流量未覆盖'}


def telemetry_filter_check(snapshot=None):
    snapshot = snapshot or {}
    state = snapshot.get('state', 'stopped')
    labels = {'stopped': '软件内筛选未启动', 'error': '软件内筛选服务异常',
              'needs_trust': '软件内筛选已就绪；等待证书信任', 'ready': '等待通过 RegionGuard 启动 Claude',
              'awaiting_traffic': 'Claude 已启动；等待实际 HTTPS 请求验证',
              'connected': '本次启动后已观察到经本服务的 HTTPS 请求；按路径逐条筛选'}
    return {'id': 'telemetry_upload_filter', 'title': 'RegionGuard 软件内遥测上传筛选',
            'status': 'WARN' if state == 'error' else 'INFO', 'severity': 'low',
            'observed': labels.get(state, '筛选状态不可确认'),
            'detail': '筛选由 RegionGuard 独立运行。中国地区字段命中时拦截整条遥测；正常遥测原样上传。'
                      '本地文件可照常写入。仅经过本服务的请求受保护；不以 100ms 或 15 秒轮询代替上传前检查。',
            'fix_advice': '', 'fix_cmd': ''}

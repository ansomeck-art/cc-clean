"""RegionGuard-owned HTTPS upload filter. Never imports or configures a VPN.

The worker speaks numeric counters and non-sensitive session acknowledgements on
its private pipes. HTTP flows,
headers, URLs, request bodies and TLS keys are never logged or serialized.
"""
import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import signal
import sys
from urllib.parse import urlsplit
from telemetry_certificates import HOSTS, prepare_server_identity

MAX_BODY = 1048576
COUNTERS = ('checked', 'blocked', 'held', 'unattributed', 'tls_requests')
MAX_CONTROL_LINE = 512


def known_endpoint(url, method):
    """Fallback scope when the policy engine errors; never fail open on a known path."""
    try:
        parts = urlsplit(url)
        if parts.scheme != 'https' or (parts.port or 443) != 443 or method.upper() != 'POST':
            return False
        host, path = parts.hostname, parts.path
        return bool((host in HOSTS[:3] and re.fullmatch(r'/api/event_logging/(?:v2/)?batch/?', path)) or
                    (host == HOSTS[2] and re.fullmatch(r'/v1/b/?', path)) or
                    (host == HOSTS[3] and re.fullmatch(r'/api/[0-9]+/(?:envelope|store)/?', path)) or
                    (host in HOSTS[4:] and re.fullmatch(r'/api/v2/(?:rum|logs)/?', path)))
    except ValueError:
        return False


def emit(value):
    print(json.dumps(value, separators=(',', ':')), flush=True)


class Policy:
    """One context on the worker's event-loop thread; no cross-thread JS values."""
    def __init__(self):
        import Foundation
        import objc
        framework = Foundation.NSBundle.bundleWithPath_(
            '/System/Library/Frameworks/JavaScriptCore.framework')
        if not framework.load():
            raise RuntimeError('policy_engine_unavailable')
        self.context = objc.lookUpClass('JSContext').alloc().init()
        root = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent)) / 'telemetry_filter'
        bundle = (root / 'policy-bundle.js').read_bytes()
        manifest = json.loads((root / 'manifest.json').read_text())
        if hashlib.sha256(bundle).hexdigest() != manifest['sha256']:
            raise RuntimeError('policy_integrity_failed')
        self.context.evaluateScript_(bundle.decode('utf-8'))
        if self.context.exception() is not None:
            raise RuntimeError('policy_engine_failed')

    def _evaluate(self, script):
        value = self.context.evaluateScript_(script)
        if self.context.exception() is not None or value is None:
            raise RuntimeError('policy_evaluation_failed')
        return value

    def eligible(self, url, method):
        return self._evaluate('RegionGuardFilter.endpoint(' + json.dumps(url) + ',' +
                              json.dumps(method) + ')').toBool()

    def inspect(self, url, method, headers, body):
        if len(body) > MAX_BODY:
            return {'action': 'hold', 'reason': 'body_limit'}
        fixture = {'url': url, 'method': method, 'headers': headers,
                   'bodyBase64': base64.b64encode(body).decode('ascii')}
        result = self._evaluate('RegionGuardFilter.inspectJSON(' +
                                json.dumps(json.dumps(fixture)) + ')').toString()
        decision = json.loads(result)
        if decision.get('action') not in {'pass', 'hold', 'block'}:
            raise RuntimeError('policy_result_invalid')
        return decision


class UploadFilter:
    def __init__(self, policy, publish=emit):
        self.policy, self.publish = policy, publish
        self.stats = dict.fromkeys(COUNTERS, 0)
        self.session_id = None
        self.session_active = False
        self.session_stats = dict.fromkeys(COUNTERS, 0)

    def control(self, message):
        """Called only on the flow event loop, between request hooks.

        Arming must be acknowledged before the parent starts a client. Activation
        happens afterwards, so traffic in that launch gap cannot prove receipt.
        """
        if not isinstance(message, dict) or set(message) != {'command', 'session_id'}:
            return
        command, session_id = message['command'], message['session_id']
        if not isinstance(session_id, str) or re.fullmatch(r'[0-9a-f]{32}', session_id) is None:
            return
        if command == 'arm_session' and session_id != self.session_id:
            self.session_id, self.session_active = session_id, False
        elif command == 'activate_session' and session_id == self.session_id and not self.session_active:
            self.session_active = True
        elif command == 'disarm_session' and session_id == self.session_id:
            self.session_id, self.session_active = None, False
        else:
            return
        self.session_stats = dict.fromkeys(COUNTERS, 0)
        self.publish({'event': 'session_ack', 'command': command,
                      'session_id': session_id, 'active': self.session_active})

    def _count(self, counter, flow):
        self.stats[counter] += 1
        if (self.session_active and self.session_id is not None and flow is not None and
                flow.metadata.get('rg_session_id') == self.session_id):
            self.session_stats[counter] += 1
        self.publish({'event': 'stats', 'stats': dict(self.stats),
                      'session_id': self.session_id, 'session_active': self.session_active,
                      'session_stats': dict(self.session_stats)})

    def _record(self, decision, flow=None):
        action, reason = decision['action'], decision.get('reason')
        counter = ('blocked' if action == 'block' else 'held' if action == 'hold' else
                   'checked' if reason == 'checked' else 'unattributed')
        self._count(counter, flow)

    @staticmethod
    def _reject(flow, action):
        from mitmproxy import http
        flow.response = http.Response.make(403 if action == 'block' else 503,
            json.dumps({'error': 'REGION_GUARD_CN_TELEMETRY' if action == 'block' else
                        'REGION_GUARD_TELEMETRY_UNVERIFIED'}).encode(),
            {'Content-Type': 'application/json', 'Cache-Control': 'no-store',
             'X-Region-Guard': 'cn-telemetry-blocked' if action == 'block' else 'telemetry-unverified'})

    def requestheaders(self, flow):
        # A body may finish after a new session starts. Keep its original epoch.
        flow.metadata['rg_session_id'] = self.session_id if self.session_active else None
        engine_failed = False
        try:
            eligible = self.policy.eligible(flow.request.pretty_url, flow.request.method)
        except Exception:
            eligible = known_endpoint(flow.request.pretty_url, flow.request.method)
            engine_failed = True
        flow.metadata['rg_eligible'] = eligible
        if flow.request.scheme == 'https' and flow.request.host in HOSTS:
            self._count('tls_requests', flow)
        if eligible:
            # A request hook on a streamed body would run after upload. All eligible
            # requests must be fully buffered; non-telemetry uploads may stream.
            flow.request.stream = False
            if engine_failed:
                self._reject(flow, 'hold')
                flow.metadata['rg_recorded'] = True
                self._record({'action': 'hold', 'reason': 'filter_exception'}, flow)
                return
            length = flow.request.headers.get('content-length', '')
            if length.isdigit() and int(length) > MAX_BODY:
                self._reject(flow, 'hold')
                flow.metadata['rg_recorded'] = True
                self._record({'action': 'hold', 'reason': 'body_limit'}, flow)
        else:
            flow.request.stream = True

    def request(self, flow):
        if not flow.metadata.get('rg_eligible') or flow.metadata.get('rg_recorded'):
            return
        try:
            decision = self.policy.inspect(flow.request.pretty_url, flow.request.method,
                                           [{'field': k, 'value': v} for k, v in
                                            flow.request.headers.items(multi=True)],
                                           flow.request.raw_content or b'')
        except Exception:
            decision = {'action': 'hold', 'reason': 'filter_exception'}
        self._record(decision, flow)
        if decision['action'] != 'pass':
            self._reject(flow, decision['action'])
        # Allowed flows are deliberately untouched, including raw compression.

    def responseheaders(self, flow):
        flow.response.stream = True  # Do not buffer conversation/SSE responses.


def private_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError('unsafe_filter_directory')
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.stat().st_uid != os.getuid():
        raise RuntimeError('unsafe_filter_directory')
    path.chmod(0o700)
    return path


class ControlChannel:
    """Bounded JSON lines on the existing parent-death pipe; no data-plane input."""
    def __init__(self, upload_filter):
        self.upload_filter = upload_filter
        self.buffer = bytearray()
        self.discarding = False

    def feed(self, data):
        parts = data.split(b'\n')
        for index, part in enumerate(parts):
            if not self.discarding:
                if len(self.buffer) + len(part) > MAX_CONTROL_LINE:
                    self.buffer.clear()
                    self.discarding = True
                else:
                    self.buffer.extend(part)
            if index < len(parts) - 1:
                if not self.discarding:
                    try:
                        self.upload_filter.control(json.loads(self.buffer))
                    except (ValueError, UnicodeError):
                        pass  # Malformed/unknown controls never change the policy.
                self.buffer.clear()
                self.discarding = False


async def serve(confdir, port=0, extra_addons=(), extra_options=None, parent_pipe=True):
    from mitmproxy import certs, options
    from mitmproxy.tools.dump import DumpMaster
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    directory = private_directory(confdir)
    if not (directory / 'mitmproxy-ca.pem').exists():
        certs.CertStore.create_store(directory, 'mitmproxy', 2048,
                                    organization='RegionGuard', cn='RegionGuard Telemetry Filter')
    certificate, identity, server_cert, authority_public, authority = prepare_server_identity(directory)
    opts = options.Options(listen_host='127.0.0.1', listen_port=port, confdir=str(directory),
                           mode=['regular'], ssl_insecure=False, upstream_cert=False,
                           certs=[host + '=' + str(identity) for host in HOSTS],
                           allow_hosts=[r'^(?:' + '|'.join(re.escape(host) for host in HOSTS) + r'):443$'])
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.options.update(connection_strategy='lazy', http2=True,
                          stream_large_bodies=None, store_streamed_bodies=False)
    if extra_options:
        master.options.update(**extra_options)
    upload_filter = UploadFilter(Policy())
    master.addons.add(upload_filter, *extra_addons)

    class Ready:
        def running(self):
            from cryptography.hazmat.primitives import hashes
            (directory / 'trust-probe.pem').write_bytes(certificate.read_bytes())
            for file in directory.iterdir():
                if file.is_file():
                    file.chmod(0o600)
            addresses = master.addons.get('proxyserver').listen_addrs()
            if not addresses:
                master.shutdown()
                raise RuntimeError('filter_not_listening')
            emit({'event': 'ready', 'port': addresses[0][1],
                  'fingerprint': authority.fingerprint(hashes.SHA256()).hex(),
                  'certificate': str(authority_public), 'session_id': upload_filter.session_id,
                  'session_active': upload_filter.session_active})
    master.addons.add(Ready())
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, master.shutdown)
    if parent_pipe:
        # Parent death closes this private pipe. Never leave a detached interceptor.
        channel = ControlChannel(upload_filter)
        def stdin_ready():
            data = os.read(sys.stdin.fileno(), 1024)
            if not data:
                loop.remove_reader(sys.stdin.fileno())
                master.shutdown()
            else:
                channel.feed(data)
        loop.add_reader(sys.stdin.fileno(), stdin_ready)
    try:
        await master.run()
    finally:
        if parent_pipe:
            loop.remove_reader(sys.stdin.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--confdir', required=True)
    args = parser.parse_args()
    try:
        asyncio.run(serve(args.confdir))
    except Exception:
        emit({'event': 'error', 'code': 'filter_start_failed'})
        raise SystemExit(1)


if __name__ == '__main__':
    main()

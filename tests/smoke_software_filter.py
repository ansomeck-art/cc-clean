"""Real HTTPS pre-upload proof against a loopback collector, never Claude servers.

No certificate is added to a keychain. Both TLS sides trust only isolated test CAs.
"""
import asyncio
import gzip
import http.client
import http.server
import json
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from telemetry_worker import HOSTS, serve


def worker(directory, collector_port, upstream_ca):
    class RedirectOnlyToTestCollector:
        def server_connect(self, data):
            host = data.server.address[0]
            if host not in HOSTS + ('api.stripe.com',):
                raise RuntimeError('test_must_never_access_external_network')
            data.server.address = ('127.0.0.1', collector_port)
            data.server.sni = host
    asyncio.run(serve(directory, extra_addons=[RedirectOnlyToTestCollector()],
                      extra_options={'ssl_verify_upstream_trusted_ca': upstream_ca}))


def main():
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from mitmproxy import certs
    received, connections = [], []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            received.append((self.path, body, self.headers.get('Content-Encoding'),
                             self.headers.get('Authorization')))
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'OK')

    class Collector(http.server.ThreadingHTTPServer):
        daemon_threads = True

        def get_request(self):
            sock, address = super().get_request()
            connections.append(True)
            return sock, address

    with tempfile.TemporaryDirectory(prefix='regionguard-test-e2e-') as temporary:
        directory = Path(temporary)
        upstream = directory / 'upstream'
        certs.CertStore.create_store(upstream, 'collector', 2048)
        store = certs.CertStore.from_store(upstream, 'collector', 2048)
        leaf = store.get_cert('api.anthropic.com', [x509.DNSName(h) for h in HOSTS + ('api.stripe.com',)])
        certificate, key = upstream / 'leaf.pem', upstream / 'leaf-key.pem'
        certificate.write_bytes(leaf.cert.to_pem())
        key.write_bytes(leaf.privatekey.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certificate, key)
        collector = Collector(('127.0.0.1', 0), Handler)
        collector.socket = tls.wrap_socket(collector.socket, server_side=True)
        thread = threading.Thread(target=collector.serve_forever, daemon=True)
        thread.start()
        process = subprocess.Popen([sys.executable, str(Path(__file__)), '--worker',
            str(directory / 'filter'), str(collector.server_port), str(upstream / 'collector-ca-cert.pem')],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        events = []
        try:
            deadline = time.monotonic() + 20
            ready = None
            while time.monotonic() < deadline:
                if select.select([process.stdout], [], [], .2)[0]:
                    line = process.stdout.readline()
                    if not line:
                        break
                    event = json.loads(line)
                    events.append(event)
                    if event.get('event') == 'ready':
                        ready = event
                        break
                if process.poll() is not None:
                    break
            if ready is None:
                process.terminate()
                _, err = process.communicate(timeout=5)
                raise AssertionError('worker not ready: ' + err[-2000:])
            # Exercise the actual bounded private pipe and event-loop ACK path.
            # This arms a synthetic epoch only; no Claude client is launched.
            session_id = 'a' * 32
            for command, active in (('arm_session', False), ('activate_session', True)):
                process.stdin.write(json.dumps({'command': command, 'session_id': session_id}) + '\n')
                process.stdin.flush()
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if not select.select([process.stdout], [], [], .2)[0]:
                        continue
                    message = json.loads(process.stdout.readline())
                    events.append(message)
                    if message.get('event') == 'session_ack' and message.get('command') == command:
                        assert message['session_id'] == session_id and message['active'] is active
                        break
                else:
                    raise AssertionError('isolated worker did not acknowledge synthetic epoch')
            context = ssl.create_default_context(cafile=ready['certificate'])

            def upload(body, path='/api/event_logging/v2/batch', host='api.anthropic.com', headers=None):
                conn = http.client.HTTPSConnection('127.0.0.1', ready['port'], context=context, timeout=5)
                conn.set_tunnel(host, 443)
                conn.request('POST', path, body=body, headers=headers or {'Content-Type': 'application/json'})
                response = conn.getresponse()
                result = response.status, response.read()
                conn.close()
                return result

            # Most important assertion: no upstream TCP handshake or HTTP request.
            assert upload(b'{"country":"CN","private":"SECRET-SYNTHETIC"}')[0] == 403
            assert upload(b'not JSON')[0] == 503
            assert upload(gzip.compress(b'{"timezone":"Asia/Shanghai"}'),
                          headers={'Content-Encoding': 'gzip'})[0] == 403
            assert received == [] and connections == [], 'blocked request reached collector'

            normal = b'{"country":"US","message":"China CN and Chinese text are allowed"}'
            assert upload(normal, headers={'Authorization': 'SECRET-SYNTHETIC'})[0] == 200
            assert received[-1][1] == normal and received[-1][3] == 'SECRET-SYNTHETIC'
            compressed = gzip.compress(b'{"country":"US"}', mtime=123)
            assert upload(compressed, headers={'Content-Encoding': 'gzip'})[0] == 200
            assert received[-1][1] == compressed and received[-1][2] == 'gzip'
            assert upload(b'{"country":"CN"}', path='/v1/messages')[0] == 200
            assert received[-1][1] == b'{"country":"CN"}'
            count = len(received)
            assert upload(b'{"country":"US"}', headers={'X-Country-Code': 'CN'})[0] == 403
            assert len(received) == count
            assert upload(b'{"service":"other-app","country":"CN"}', host=HOSTS[4],
                          path='/api/v2/rum')[0] == 200
            count = len(received)
            assert upload(b'{"service":"claude-ai","country":"CN"}', host=HOSTS[4],
                          path='/api/v2/rum')[0] == 403
            assert len(received) == count

            # HTTP/2 stream is also gated before its DATA reaches the collector.
            from h2.connection import H2Connection
            from h2.events import ResponseReceived, StreamEnded
            raw = socket.create_connection(('127.0.0.1', ready['port']), timeout=5)
            raw.sendall(b'CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n')
            header = b''
            while not header.endswith(b'\r\n\r\n'):
                header += raw.recv(1)
            assert b'200' in header
            context.set_alpn_protocols(['h2'])
            conn = context.wrap_socket(raw, server_hostname='api.anthropic.com')
            assert conn.selected_alpn_protocol() == 'h2'
            h2 = H2Connection()
            h2.initiate_connection()
            conn.sendall(h2.data_to_send())
            body = b'{"country":"CN"}'
            h2.send_headers(1, [(':method', 'POST'), (':scheme', 'https'),
                (':authority', 'api.anthropic.com'), (':path', '/api/event_logging/v2/batch'),
                ('content-length', str(len(body)))])
            h2.send_data(1, body, end_stream=True)
            conn.sendall(h2.data_to_send())
            ended, status = False, None
            while not ended:
                data = conn.recv(65536)
                assert data, 'HTTP/2 connection ended before response'
                for event in h2.receive_data(data):
                    if isinstance(event, ResponseReceived):
                        status = dict(event.headers).get(b':status')
                    if isinstance(event, StreamEnded):
                        ended = True
                outgoing = h2.data_to_send()
                if outgoing:
                    conn.sendall(outgoing)
            conn.close()
            assert status == b'403' and len(received) == count

            # Out-of-scope Stripe TLS uses its original server certificate, never
            # one issued by RegionGuard, and its CN request remains untouched.
            stripe_context = ssl.create_default_context(cafile=str(upstream / 'collector-ca-cert.pem'))
            stripe = http.client.HTTPSConnection('127.0.0.1', ready['port'], context=stripe_context, timeout=5)
            stripe.set_tunnel('api.stripe.com', 443)
            stripe.connect()
            assert stripe.sock.getpeercert(binary_form=True) == leaf.cert._cert.public_bytes(serialization.Encoding.DER)
            stripe.request('POST', '/v1/payment_intents', body=b'{"country":"CN"}')
            response = stripe.getresponse()
            assert response.status == 200
            response.read()
            stripe.close()

            # The private pipe contains only numeric counters and readiness data.
            process.stdin.close()
            process.wait(timeout=8)
            assert process.returncode == 0
            remaining = process.stdout.read()
            observations = [json.loads(line) for line in remaining.splitlines() if line]
            current = [item for item in observations if item.get('event') == 'stats']
            assert current and all(item['session_id'] == session_id and item['session_active'] for item in current)
            assert current[-1]['session_stats']['tls_requests'] > 0
            assert current[-1]['session_stats']['blocked'] > 0
            assert 'SECRET-SYNTHETIC' not in remaining and 'Authorization' not in remaining
            assert not any(file.suffix in ('.har', '.jsonl') for file in directory.rglob('*'))
            assert (directory / 'filter/mitmproxy-ca.pem').stat().st_mode & 0o077 == 0
            print('Software HTTPS: pre-upload CN/unknown/gzip/HTTP2 blocking, byte-identical forwarding, '
                  'scoped telemetry, opaque Stripe TLS, private session ACK/counters and parent-exit cleanup passed')
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            for stream in (process.stdout, process.stderr):
                if stream:
                    stream.close()
            collector.shutdown()
            collector.server_close()
            thread.join(timeout=3)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--worker':
        worker(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    else:
        main()

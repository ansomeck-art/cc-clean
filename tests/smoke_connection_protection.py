"""Native owned-child sockets -> logical route fault -> narrow real test signal.

No Claude runs, real routing changes, controller reads, packet inspection or
Internet traffic. Process-role aliases exist only in this injected fixture.
"""
import ipaddress
import json
import math
import os
from pathlib import Path
import select
import socket
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from connection_routes import classify_destination
from mac_guard import ProcessIdentity
from native_connections import read_native_owned_sockets
from protection import FastProtector
from smoke_fast_protection import NoFileFixture, OwnedChildProcesses
from smoke_telemetry_watch import SafeNetwork
from traffic_watch import ClaudeTrafficWatch

MAIN = '/Applications/Claude.app/Contents/MacOS/Claude'
CRASHPAD = '/Applications/Claude.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Helpers/chrome_crashpad_handler'


def wait_until(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.005)
    raise AssertionError('owned connection fixture did not reach its expected state')


def run_case(role):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(4)
    code = ('import socket,sys,time\n'
            'c=socket.socket();c.connect(("127.0.0.1",int(sys.argv[1])))\n'
            'u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n'
            'print("ready",flush=True)\n'
            'time.sleep(30)\n')
    child = subprocess.Popen([sys.executable, '-c', code, str(listener.getsockname()[1])],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    peer = None
    watch = guard = None
    try:
        peer, child_address = listener.accept()
        assert select.select([child.stdout], [], [], 4)[0]
        assert child.stdout.readline() == b'ready\n'
        reader_identity, signaler = OwnedChildProcesses(), OwnedChildProcesses()
        reader_identity.child = child
        alias = MAIN if role == 'ClaudeDesktop' else CRASHPAD
        class Processes:
            def identity(self, pid):
                value = reader_identity.identity(pid)
                return ProcessIdentity(value.pid, value.uid, value.start_sec, value.start_usec, alias) if value else None
            def candidates(self):
                value = self.identity(child.pid)
                return [value] if value else []
            def allowed_path(self, path):
                return path == alias
        class Runtime:
            def read(self, endpoint):
                if endpoint == '/configs':
                    return {'mode': 'global', 'tun': {'enable': True}}
                if endpoint == '/proxies':
                    return {'proxies': {'PRIVATE-FIXTURE-NODE': {'type': 'Vless'}}}
                assert endpoint == '/connections'
                return {'connections': [{'id': 'PRIVATE-FIXTURE-CONNECTION', 'chains': ['PRIVATE-FIXTURE-NODE'],
                    'metadata': {'network': 'tcp', 'type': 'Tun', 'sourceIP': child_address[0],
                                 'sourcePort': child_address[1], 'destinationIP': '127.0.0.1',
                                 'destinationPort': listener.getsockname()[1], 'processPath': alias}}]}
        fault = {'active': False}
        def routes(values):
            # The native FD snapshot is real; only its route safety result is
            # injected. Never alter or test a real physical route on this host.
            fixture = [(ipaddress.ip_network('0.0.0.0/0'), 'utun5', 1)]
            if fault['active']:
                fixture.append((ipaddress.ip_network('8.8.4.4/32'), 'en1', 1))
            decision = classify_destination('8.8.4.4', fixture, {'utun5': 1, 'en1': 1})
            return {value: decision if value.network == 'tcp' else 'unknown' for value in values}
        watch = ClaudeTrafficWatch(runtime=Runtime(), processes_factory=Processes, route_reader=routes, interval_ms=500)
        guard = FastProtector(network_factory=SafeNetwork, process_factory=lambda: signaler,
                              telemetry_factory=NoFileFixture, supported=True,
                              connection_provider=watch.status, connection_acknowledge=watch.acknowledge)
        watch.start()
        guard.start(interval_ms=100)
        def ready():
            guard.observe_pulse(dict(target='US', ok=True, loc='US', colo='IAD', utun_up=True), time.monotonic())
            snapshot = watch.status()
            return snapshot if snapshot['samples'] >= 2 and snapshot['state'] == 'observed' and guard.status()['status'] == 'safe' else None
        snapshot = wait_until(ready)
        group = next(group for group in snapshot['evidence']['groups'] if group['id'] == role)
        assert group['matched_count'] == 1 and group['socket_count'] >= 2
        assert group['route_counts']['unknown'] >= 1  # visible unconnected UDP
        assert snapshot['backend'] == 'native'
        signaler.child = child
        time.sleep(.15)
        assert child.poll() is None and signaler.signal_at is None
        began = time.perf_counter()
        fault['active'] = True  # no wake injection: wait for the real periodic sampler
        child.wait(timeout=4)
        assert child.returncode == -9 and signaler.signal_at is not None
        action = wait_until(lambda: guard.status().get('last_action'))
        assert 'connection_route_bypass' in action['cause_codes']
        assert 'PRIVATE' not in json.dumps(watch.status())
        return (signaler.signal_at - began) * 1000
    finally:
        if guard is not None:
            guard.stop()
        if watch is not None:
            watch.stop()
            thread = watch._thread
            if thread is not None:
                thread.join(5)
                assert not thread.is_alive()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        child.stdout.close()
        if peer is not None:
            peer.close()
        listener.close()


def main():
    assert sys.platform == 'darwin'
    timings = [run_case(role) for role in ('ClaudeDesktop', 'ClaudeHelper')]
    result = dict(ok=True, backend='native', connection_interval_ms=500, guard_interval_ms=100,
                  native_owned_child_socket_snapshots=True, unconnected_udp_visible=True,
                  unknown_udp_did_not_signal=True, crashpad_role_fixture=True,
                  logical_route_injection_only=True, real_owned_child_terminations=len(timings),
                  fault_to_signal_median_ms=round(statistics.median(timings), 3),
                  fault_to_signal_p95_ms=round(sorted(timings)[math.ceil(.95 * len(timings)) - 1], 3),
                  actual_claude_touched=False, packet_payload_inspected=False,
                  system_network_or_trust_changes=False, worker_threads_stopped=True)
    (ROOT / 'build/connection-protection-smoke.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()

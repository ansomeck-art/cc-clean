"""Real private-file events to real signals, using only owned disposable children.

The fixture never edits Claude files, changes networking, installs trust, or
enumerates a real Claude target. The production signal function rechecks the
UID/start-time identity of the one child this fixture exposes.
"""
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from protection import FastProtector
from smoke_fast_protection import OwnedChildProcesses
from telemetry_watch import ClaudeTelemetryWatch


class SafeNetwork:
    events = None
    def sample(self):
        return dict(safe=True, reasons=[], interfaces=['utun-fixture'], fingerprint='isolated')
    def wait(self, timeout):
        threading.Event().wait(timeout)
        return False
    def close(self):
        pass


def pulse(guard):
    guard.observe_pulse(dict(target='US', ok=True, loc='US', colo='LAX', utun_up=True,
                             changed_ip=False), time.monotonic())


def await_safe(guard):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        value = guard.status()
        if value.get('telemetry', {}).get('state') == 'safe':
            pulse(guard)
        if value['status'] == 'safe':
            return
        time.sleep(.003)
    raise AssertionError('isolated guard did not confirm safe fixture')


def write_scope(path, timezone):
    # Include a private sentinel outside culture to prove it never enters output.
    body = {'event': {'contexts': {'culture': {'locale': 'en-US', 'timezone': timezone}},
                      'user': {'id': 'PRIVATE-FIXTURE-ID-NEVER-OUTPUT'}}}
    temporary = path.with_suffix('.fixture-tmp')
    temporary.write_text(json.dumps(body))
    temporary.chmod(0o600)
    os.replace(temporary, path)


def p95(values):
    return round(sorted(values)[math.ceil(len(values) * .95) - 1], 3)


def main():
    assert sys.platform == 'darwin'
    signal_times, exit_times = [], []
    with tempfile.TemporaryDirectory(prefix='regionguard-test-file-events-') as temporary:
        scope = Path(temporary).resolve() / 'sentry/scope_v3.json'
        scope.parent.mkdir(mode=0o700)
        write_scope(scope, 'America/New_York')
        processes = OwnedChildProcesses()
        observer = ClaudeTelemetryWatch(scope_path=scope, interval_ms=100)
        guard = FastProtector(network_factory=SafeNetwork, process_factory=lambda: processes,
                              telemetry_factory=lambda: observer, supported=True)
        guard.start(interval_ms=100)
        try:
            await_safe(guard)
            for _ in range(6):
                child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    processes.child = child
                    processes.signal_at = None
                    began = time.perf_counter()
                    deadline = time.monotonic() + 4
                    write_scope(scope, 'Asia/Shanghai')
                    child.wait(timeout=4)
                    observed_exit_ms = (time.perf_counter() - began) * 1000
                    # Child exit can precede the signaling thread publishing its
                    # success timestamp/state; wait within the original bound.
                    while time.monotonic() < deadline:
                        status = guard.status()
                        if processes.signal_at is not None and 'telemetry_cn_timezone' in status['reason_codes']:
                            break
                        time.sleep(.002)
                    assert child.returncode == -9 and processes.signal_at is not None
                    signal_times.append((processes.signal_at - began) * 1000)
                    exit_times.append(observed_exit_ms)
                    assert 'telemetry_cn_timezone' in status['reason_codes']
                    assert 'PRIVATE-FIXTURE' not in json.dumps(status)
                finally:
                    processes.child = None
                    if child.poll() is None:
                        child.kill()
                        child.wait(2)
                write_scope(scope, 'America/New_York')
                await_safe(guard)
            backend = guard.status()['telemetry']['backend']
        finally:
            guard.stop()
        assert not guard._thread.is_alive()
    assert max(signal_times) < 1500  # bounded empirical gate; no real-time promise
    result = dict(configured_local_interval_ms=100, file_event_backend=backend,
                  actual_atomic_file_changes=len(signal_times), real_owned_child_terminations=len(signal_times),
                  file_change_to_signal_median_ms=round(statistics.median(signal_times), 3),
                  file_change_to_signal_p95_ms=p95(signal_times),
                  file_change_to_signal_max_ms=round(max(signal_times), 3),
                  observed_exit_p95_ms=p95(exit_times), only_private_fixture_files=True,
                  unrelated_processes_touched=False, no_network_changes=True, no_trust_changes=True)
    output = ROOT / 'build/telemetry-watch-smoke.json'
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()

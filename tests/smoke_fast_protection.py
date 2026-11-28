"""Native read-only sample benchmark + real SIGKILL of ONLY owned disposable children.

The production path whitelist remains enforced in unit tests. This opt-in fixture
provider intentionally exposes only its own child PID to the production signal
routine. No real Claude, network setting or third-party file is changed.
"""
import ctypes
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import threading
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mac_guard
from protection import FastProtector


class NoFileFixture:
    """Route benchmark is isolated from the user's actual Claude files."""
    def set_callback(self, callback):
        pass
    def configure(self, interval_ms):
        pass
    def start(self):
        pass
    def stop(self):
        pass
    def sample(self):
        return dict(state='missing', reason_codes=[], field_types=[], last_check_age_ms=0,
                    files_checked=0, event_seq=1, backend='poll')


class OwnedChildProcesses:
    def __init__(self):
        self.child = None
        self.signal_at = None
        self.native = mac_guard.ClaudeProcesses()
        self.signaler = object.__new__(mac_guard.ClaudeProcesses)
        self.signaler.uid = os.getuid()
        self.signaler.identity = self.identity
    def identity(self, pid):
        child = self.child
        if child is None or pid != child.pid or child.poll() is not None:
            return None
        info = mac_guard.BsdInfo()
        size = ctypes.sizeof(info)
        if self.native.lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), size) != size or info.uid != os.getuid():
            return None
        return mac_guard.ProcessIdentity(pid, info.uid, info.start_sec, info.start_usec, 'owned-disposable-fixture')
    def candidates(self):
        identity = self.identity(self.child.pid) if self.child else None
        return [identity] if identity else []
    def terminate(self, identity):
        # os.kill is not mocked: production UID/start-time revalidation and single-PID SIGKILL execute.
        outcome = self.signaler.terminate(identity)
        if outcome == 'terminated':
            self.signal_at = time.perf_counter()
        return outcome


def await_status(guard, status):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if guard.status()['status'] == status:
            return
        time.sleep(.002)
    raise AssertionError('protection state did not reach ' + status)


def pulse(guard):
    guard.observe_pulse(dict(target='US', ok=True, loc='US', colo='LAX', utun_up=True), time.monotonic())


def main():
    assert sys.platform == 'darwin'
    reader = mac_guard.DarwinNetwork()
    samples = []
    try:
        for _ in range(100):
            start = time.perf_counter()
            actual = reader.sample()
            samples.append((time.perf_counter() - start) * 1000)
    finally:
        reader.close()
    fault = threading.Event()
    class InjectedNetwork(mac_guard.DarwinNetwork):
        def sample(self):
            value = super().sample()  # exercise actual kernel read at the configured cadence
            # Logical fault injection only; never drop packets, change routes or stop the VPN.
            value.update(safe=not fault.is_set(), reasons=['tun_down'] if fault.is_set() else [])
            value['fingerprint'] = 'controlled-fixture'
            return value
    processes = OwnedChildProcesses()
    guard = FastProtector(network_factory=InjectedNetwork, process_factory=lambda: processes, supported=True,
                          telemetry_factory=NoFileFixture)
    guard.start(interval_ms=100)
    latencies, signal_latencies = [], []
    try:
        pulse(guard)
        await_status(guard, 'safe')
        for _ in range(12):
            child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                processes.child = child
                processes.signal_at = None
                began = time.perf_counter()
                deadline = time.monotonic() + 3
                fault.set()  # do not wake the worker: measure the worst-case periodic 100ms lane
                child.wait(timeout=3)
                latencies.append((time.perf_counter() - began) * 1000)
                while processes.signal_at is None and time.monotonic() < deadline:
                    time.sleep(.002)
                assert processes.signal_at is not None
                signal_latencies.append((processes.signal_at - began) * 1000)
                assert child.returncode == -9
                await_status(guard, 'blocked')
            finally:
                processes.child = None
                if child.poll() is None:
                    child.kill()
                    child.wait(2)
            fault.clear()
            # Allow local recovery to establish its fresh-probe floor before submitting success.
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not guard.status().get('local_safe'):
                time.sleep(.002)
            pulse(guard)
            await_status(guard, 'safe')
    finally:
        guard.stop()
    assert not guard._thread.is_alive()
    assert max(latencies) < 1000, latencies  # empirical gate, not a real-time/zero-leak guarantee
    result = dict(kernel_samples=100, sample_median_ms=round(statistics.median(samples), 3),
                  sample_p95_ms=round(sorted(samples)[94], 3), sample_max_ms=round(max(samples), 3),
                  configured_local_interval_ms=100, real_owned_child_terminations=len(latencies),
                  fault_to_signal_median_ms=round(statistics.median(signal_latencies), 3),
                  fault_to_signal_p95_ms=round(sorted(signal_latencies)[-2], 3),
                  fault_to_signal_max_ms=round(max(signal_latencies), 3),
                  termination_median_ms=round(statistics.median(latencies), 3),
                  termination_p95_ms=round(sorted(latencies)[-2], 3), termination_max_ms=round(max(latencies), 3),
                  fault_injection='logical_snapshot_only', unrelated_processes_touched=False,
                  actual_kernel_safe=actual['safe'], no_packet_interception=True)
    output = Path(__file__).resolve().parents[1] / 'build/fast-protection-smoke.json'
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()

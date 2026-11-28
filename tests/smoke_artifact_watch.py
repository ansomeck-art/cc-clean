"""Real multi-source file events and signals, restricted to disposable owned fixtures."""
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifact_watch import ClaudeArtifactWatch
from protection import FastProtector
from smoke_fast_protection import OwnedChildProcesses
from smoke_telemetry_watch import SafeNetwork, await_safe
from telemetry_watch import ClaudeTelemetryWatch


def atomic_json(path, value):
    temporary = path.with_name(path.name + '.fixture-tmp')
    temporary.write_text(json.dumps(value) + '\n')
    temporary.chmod(0o600)
    os.replace(temporary, path)


def main():
    assert sys.platform == 'darwin'
    timings, exits, cases = [], [], []
    with tempfile.TemporaryDirectory(prefix='regionguard-test-artifacts-') as temporary:
        home = Path(temporary).resolve()
        app = home / 'Library/Application Support/Claude'
        logs = home / 'Library/Logs/Claude'
        (app / 'sentry/queue').mkdir(parents=True, mode=0o700)
        logs.mkdir(parents=True, mode=0o700)
        scope = app / 'sentry/scope_v3.json'
        config = app / 'config.json'
        preferences = app / 'Preferences'
        log = logs / 'main.log'
        normal_scope = {'event': {'contexts': {'culture': {'locale': 'en-US', 'timezone': 'America/New_York'}}}}
        normal_config = {'locale': 'en-US'}
        normal_preferences = {'spellcheck': {'dictionaries': ['en-US']}}
        normal_log = {'level': 'info', 'contexts': {'culture': {'locale': 'en-US', 'timezone': 'America/New_York'}}}
        for path, value in ((scope, normal_scope), (config, normal_config),
                            (preferences, normal_preferences), (log, normal_log)):
            atomic_json(path, value)
        metadata_files = [app / 'Cookies', app / 'ant-did', app / 'claude_desktop_config.json',
                          app / 'sentry/queue/envelope-fixture']
        for path in metadata_files:
            path.write_bytes(b'PRIVATE-FIXTURE-NOT-TO-BE-READ')
            path.chmod(0o600)
        # A normal metadata-only store may be much larger than the JSON limit.
        with metadata_files[0].open('ab') as handle:
            handle.truncate(2 * 1024 * 1024)
        forbidden = {(path.stat().st_dev, path.stat().st_ino) for path in metadata_files}
        def reader(fd, limit):
            info = os.fstat(fd)
            assert (info.st_dev, info.st_ino) not in forbidden, 'metadata-only content was read'
            return ClaudeTelemetryWatch._read(fd, limit)
        observer = ClaudeArtifactWatch(home=home, interval_ms=100, reader=reader)
        processes = OwnedChildProcesses()
        guard = FastProtector(network_factory=SafeNetwork, process_factory=lambda: processes,
                              telemetry_factory=lambda: observer, supported=True)
        guard.start(interval_ms=100)
        changes = [
            ('sentry_scope', scope, {'event': {'contexts': {'culture': {'locale': 'en-US', 'timezone': 'Asia/Shanghai'}}}}, normal_scope),
            ('app_config', config, {'locale': 'en-CN'}, normal_config),
            ('electron_preferences', preferences, {'spellcheck': {'dictionaries': ['zh-CN']}}, normal_preferences),
            ('claude_logs', log, {'level': 'warn', 'contexts': {'culture': {'locale': 'en-US', 'timezone': 'Asia/Shanghai'}}}, normal_log),
        ]
        try:
            await_safe(guard)
            assert len(guard.status()['telemetry']['sources']) == 8
            healthy = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                processes.child = healthy
                processes.signal_at = None
                atomic_json(scope, {'event': {'contexts': {}}})
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    snapshot = guard.status()
                    if snapshot['telemetry']['state'] == 'observed':
                        break
                    time.sleep(.005)
                assert snapshot['telemetry']['state'] == 'observed'
                time.sleep(.25)  # observe several real guard ticks with no culture
                assert healthy.poll() is None and processes.signal_at is None
                assert not guard.status()['reason_codes']
            finally:
                processes.child = None
                if healthy.poll() is None:
                    healthy.terminate()
                    healthy.wait(timeout=2)
            atomic_json(scope, normal_scope)
            await_safe(guard)
            for _ in range(2):
                for source_id, path, bad, good in changes:
                    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    try:
                        processes.child = child
                        processes.signal_at = None
                        began = time.perf_counter()
                        deadline = time.monotonic() + 4
                        atomic_json(path, bad)
                        child.wait(timeout=4)
                        exit_ms = (time.perf_counter() - began) * 1000
                        while time.monotonic() < deadline:
                            status = guard.status()
                            if processes.signal_at is not None and source_id in status['telemetry']['risk_source_ids']:
                                break
                            time.sleep(.002)
                        assert child.returncode == -9 and processes.signal_at is not None
                        assert source_id in status['telemetry']['risk_source_ids']
                        assert 'PRIVATE-FIXTURE' not in json.dumps(status)
                        latency = (processes.signal_at - began) * 1000
                        timings.append(latency)
                        exits.append(exit_ms)
                        cases.append({'source': source_id, 'file_change_to_signal_ms': round(latency, 3)})
                    finally:
                        processes.child = None
                        if child.poll() is None:
                            child.kill()
                            child.wait(timeout=2)
                    atomic_json(path, good)
                    await_safe(guard)
            backend = guard.status()['telemetry']['backend']
        finally:
            guard.stop()
        assert not guard._thread.is_alive()
    assert max(timings) < 1500  # Empirical gate, not a real-time guarantee.
    result = dict(configured_local_interval_ms=100, backend=backend, observed_groups=8,
                  actual_fixture_changes=len(timings), real_owned_child_terminations=len(timings),
                  file_change_to_signal_median_ms=round(statistics.median(timings), 3),
                  file_change_to_signal_p95_ms=round(sorted(timings)[math.ceil(len(timings) * .95) - 1], 3),
                  file_change_to_signal_max_ms=round(max(timings), 3),
                  observed_exit_p95_ms=round(sorted(exits)[math.ceil(len(exits) * .95) - 1], 3),
                  metadata_body_reads=0, only_private_fixtures=True, actual_claude_touched=False,
                  missing_culture_did_not_signal=True,
                  network_or_trust_changes=False, cases=cases)
    (ROOT / 'build/artifact-watch-smoke.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()

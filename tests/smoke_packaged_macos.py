"""Real signed DMG gate. Runs only our app; preserves its preferences, never changes networking."""
import argparse
import http.client
import json
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import sys
import tempfile
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server
import tray_app

ROOT = Path(__file__).resolve().parents[1]


def request(port, path, method='GET', payload=None, expected=200):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=25)
    try:
        body = json.dumps(payload) if payload is not None else None
        conn.request(method, path, body, headers={'X-Region-Guard': '1', 'Content-Type': 'application/json'})
        response = conn.getresponse()
        data = response.read()
        assert response.status == expected, (path, response.status)
        return json.loads(data) if path.startswith('/api/') else data
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--hold', action='store_true', help='leave a bounded window for real-browser/menu inspection')
    parser.add_argument('--image', type=Path, default=ROOT / 'dist/RegionGuard-macOS.dmg')
    parser.add_argument('--result', type=Path, default=ROOT / 'dist/package-smoke-result.json')
    args = parser.parse_args()
    assert sys.platform == 'darwin'
    isolated = tempfile.TemporaryDirectory(prefix='regionguard-test-package-')
    runtime_path = Path(isolated.name) / 'runtime.json'
    pref_path = Path(isolated.name) / 'prefs.json'
    pref_path.write_text(json.dumps({**server.PREFS_DEFAULTS, 'auto_start_monitor': False,
                                    'protection_enabled': False, 'notify_enabled': False}))
    environment = {**os.environ, 'REGIONGUARD_DATA_DIR': isolated.name}
    mount = ROOT / 'build/verify-readonly-dmg'
    mount.mkdir(parents=True, exist_ok=True)
    mounted = False
    process = None
    port = None
    result = {}
    try:
        subprocess.run(['/usr/bin/hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', str(mount),
                        str(args.image)], check=True, stdout=subprocess.DEVNULL)
        mounted = True
        app = mount / 'RegionGuard.app'
        info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
        assert info['LSUIElement'] is True and info['NSHighResolutionCapable'] is True
        subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)], check=True)
        assert os.statvfs(mount).f_flag & os.ST_RDONLY
        process = subprocess.Popen([str(app / 'Contents/MacOS/RegionGuard'), '--silent', '--port', '0'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=environment)
        for _ in range(150):
            if process.poll() is not None:
                raise AssertionError('packaged app exited: ' + process.stderr.read(4000).decode(errors='replace'))
            if runtime_path.exists():
                try:
                    metadata = json.loads(runtime_path.read_text())
                    if metadata['pid'] == process.pid and tray_app.existing_dashboard(runtime_path):
                        port = metadata['port']
                        break
                except (ValueError, KeyError):
                    pass
            time.sleep(.1)
        assert port is not None, 'app health did not become ready'
        for _ in range(100):
            if request(port, '/api/headers').get('native_ready'):
                break
            time.sleep(.1)
        else:
            raise AssertionError('native UI did not become ready')
        assert request(port, '/api/headers')['native_connections_available'] is True
        result['frozen_native_socket_library_loaded'] = True
        assert request(port, '/api/prefs')['run_mode'] == 'menubar'
        html = request(port, '/').decode()
        assert 'runModeBadge' in html and 'fingerprint-checks.js' in html and 'locale-checks.js' in html
        assert 'protectionEnabled' in html and 'localGuardInterval' in html
        assert 'localTelemetryStatus' in html
        assert 'fileSourcesBody' in html
        assert 'trafficObservationBody' in html and 'trafficObservationStatus' in html
        assert 'telemetryHeading' in html and 'HTTPS 正文解密继续退役' in html
        assert '通过筛选启动 Claude' not in html and '准备软件内筛选' not in html
        upload = request(port, '/api/telemetry/status')
        assert upload['state'] == 'retired' and upload['retired'] is True
        assert not upload['running'] and not upload['client_started']
        assert upload['stats']['tls_requests'] == 0
        assert upload['session_id'] is None and upload['traffic_confirmed'] is False
        assert upload['session_stats']['tls_requests'] == 0
        for action in ('start', 'trust', 'launch'):
            rejected = request(port, '/api/telemetry/' + action, 'POST', expected=409)
            assert '已停用' in rejected['error']
        assert request(port, '/api/telemetry/stop', 'POST')['state'] == 'retired'
        assert not (Path(isolated.name) / 'telemetry-filter').exists()
        result['https_decryption_retired'] = True
        from PyInstaller.archive.readers import CArchiveReader
        archive = CArchiveReader(str(app / 'Contents/MacOS/RegionGuard'))
        pyz_name = next(name for name in archive.toc if name.startswith('PYZ'))
        modules = archive.open_embedded_archive(pyz_name).toc
        for name in modules:
            assert not name.startswith(('mitmproxy', 'telemetry_worker', 'telemetry_runtime', 'telemetry_certificates'))
        assert not (app / 'Contents/Resources/telemetry_filter').exists()
        result['no_decryption_engine_bundled'] = True
        result['no_certificate_or_client_activation'] = True
        request(port, '/api/prefs', 'POST', {'target': 'JP', 'interval_sec': 15, 'notify_enabled': False})
        status = request(port, '/api/monitor/status')
        assert status['target'] == 'JP' and status['interval_sec'] == 15
        assert status['protection']['supported'] is True
        assert status['protection']['running'] is False  # this package smoke never arms real Claude termination
        # Load the native backends inside the actual frozen application, while the
        # protection preference remains explicitly disabled. No target is signaled.
        request(port, '/api/monitor/start', 'POST', {'target': 'JP', 'interval': 15})
        for _ in range(100):
            observer = request(port, '/api/monitor/status')['protection']
            assert observer['enabled'] is False
            assert observer['terminated_total'] == 0
            if (observer.get('kernel_backend_available') and observer.get('process_backend_available')
                    and observer.get('telemetry_backend_available')):
                break
            time.sleep(.05)
        else:
            raise AssertionError('frozen native protection backends did not load')
        result['frozen_native_backends'] = True
        result['frozen_telemetry_observer'] = True
        sources = observer['telemetry']['sources']
        assert len(sources) == 8 and len({source['id'] for source in sources}) == 8
        assert all(source['state'] == 'stopped' and source['files_checked'] == 0 for source in sources)
        result['multi_source_watch_declared_without_user_reads'] = True
        result['zero_real_termination_signals'] = True
        current_traffic = request(port, '/api/traffic/status')
        assert current_traffic['running'] is True and current_traffic['interval_ms'] >= 500
        assert current_traffic['all_traffic_covered'] is False
        previous_samples = current_traffic['samples']
        for _ in range(100):
            current_traffic = request(port, '/api/traffic/status')
            if current_traffic['samples'] >= previous_samples + 2:
                break
            time.sleep(.05)
        else:
            raise AssertionError('connection worker did not sample independently of scans')
        assert current_traffic['all_traffic_covered'] is False
        assert len(current_traffic['evidence']['groups']) == 2
        assert request(port, '/api/monitor/status')['traffic']['running'] is True
        result['background_connections_without_scan_or_browser'] = True
        before = runtime_path.read_bytes()
        duplicate = subprocess.run([str(app / 'Contents/MacOS/RegionGuard'), '--silent'], timeout=12,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=environment)
        assert duplicate.returncode == 0, duplicate.stderr.decode(errors='replace')
        assert before == runtime_path.read_bytes(), 'duplicate replaced the instance marker'
        result.update(readonly_mount=True, signed_bundle=True, external_runtime=True, duplicate_reused=True,
                      prefs_api=True, lsui_element=True, isolated_state=True, protection_ui=True)
        print(json.dumps({'ready_for_ui': True, 'port': port, 'pid': process.pid, 'app': str(app)}, ensure_ascii=False), flush=True)
        if args.hold:
            marker = ROOT / 'build/package-smoke.continue'
            started = time.time()
            for _ in range(1500):
                if marker.exists() and marker.stat().st_mtime >= started:
                    break
                if process.poll() is not None:
                    break
                time.sleep(.2)
        # Verify that dashboard/monitor use did not alter one byte of the signed app.
        subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)], check=True)
        if process.poll() is None:
            request(port, '/api/monitor/stop', 'POST')
            assert request(port, '/api/traffic/status')['state'] == 'stopped'
            result['connection_observer_stopped_with_monitor'] = True
            # Goes through AppHelper's native termination callback and normal cleanup;
            # unlike Apple Events this does not require macOS Automation permission.
            process.send_signal(signal.SIGINT)
        process.wait(timeout=35)
        assert process.returncode == 0
        assert not runtime_path.exists(), 'runtime marker survived normal app exit'
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
        try:
            try:
                connection.connect()
            except OSError:
                pass
            else:
                raise AssertionError('HTTP listener survived app exit')
        finally:
            connection.close()
        result['normal_exit_no_listener'] = True
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)
        if process is not None and process.stderr:
            process.stderr.close()
        if mounted:
            subprocess.run(['/usr/bin/hdiutil', 'detach', str(mount)], check=True, stdout=subprocess.DEVNULL)
        isolated.cleanup()
    output = args.result
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print('Packaged DMG: read-only mount, signatures, duplicate launch, preference API and clean normal exit passed', flush=True)


if __name__ == '__main__':
    main()

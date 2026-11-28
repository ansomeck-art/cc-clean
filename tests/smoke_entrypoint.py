"""Real shell tray entry in an isolated own state directory; never touches a running user instance."""
import json
import http.client
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server
import tray_app


def main():
    with tempfile.TemporaryDirectory(prefix='regionguard-test-entry-') as temporary:
        runtime_path = Path(temporary) / 'runtime.json'
        prefs_path = Path(temporary) / 'prefs.json'
        prefs_path.write_text(json.dumps({**server.PREFS_DEFAULTS, 'auto_start_monitor': False,
                                         'protection_enabled': False, 'notify_enabled': False}))
        process = None
        try:
            environment = {**os.environ, 'REGIONGUARD_DATA_DIR': temporary}
            process = subprocess.Popen(['./start.sh', '--tray', '--silent', '--port', '0'], env=environment,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            ready = False
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError(process.stderr.read(2000).decode(errors='replace'))
                try:
                    runtime = json.loads(runtime_path.read_text())
                    if runtime['pid'] == process.pid and tray_app.existing_dashboard(runtime_path):
                        ready = True
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(.1)
            assert ready
            for _ in range(100):
                connection = http.client.HTTPConnection('127.0.0.1', runtime['port'], timeout=2)
                connection.request('GET', '/api/headers')
                native_ready = json.loads(connection.getresponse().read()).get('native_ready')
                connection.close()
                if native_ready:
                    break
                time.sleep(.1)
            else:
                raise AssertionError('native UI did not become ready')
            process.send_signal(signal.SIGINT)
            process.wait(15)
            assert process.returncode == 0
            assert not runtime_path.exists()
            print('Isolated start.sh --tray: live server, native entry and graceful signal cleanup passed')
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(3)
            if process and process.stderr:
                process.stderr.close()


if __name__ == '__main__':
    main()

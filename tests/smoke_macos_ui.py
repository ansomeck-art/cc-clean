"""Opt-in real AppKit smoke gate. Uses isolated app-owned state and synthetic probes."""
import json
from pathlib import Path
import sys
import tempfile
import threading
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import AppKit
from PyObjCTools import AppHelper
import server
import tray_app
from test_tray import snapshot


def main():
    errors = []
    original_loop = AppHelper.runEventLoop
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        with patch.object(server, 'LOCK_FILE_PATH', str(root / 'instance.lock')), \
             patch.object(server, 'RUNTIME_INFO_PATH', str(root / 'runtime.json')), \
             patch.object(server, 'PREFS_PATH', str(root / 'prefs.json')), \
             patch.object(server, '_PREFS', {**server.PREFS_DEFAULTS, 'auto_start_monitor': False, 'notify_enabled': False}), \
             patch.object(server, 'MONITOR', server.MonitorController()), \
             patch.object(tray_app, 'open_dashboard'):
            runtime = tray_app.TrayRuntime(preferred_port=0, silent=True)
            runtime.start()
            def guarded(function):
                try:
                    function()
                except BaseException as exc:
                    errors.append(exc)
                    AppHelper.stopEventLoop()
            def loop(**kwargs):
                app = AppKit.NSApplication.sharedApplication()
                delegate = app.delegate()
                assert app.activationPolicy() == AppKit.NSApplicationActivationPolicyAccessory
                assert delegate.status_item.button().title() == '⚪ RG · 待机'
                def emit(data):
                    data['prefs'] = server.get_prefs()
                    runtime.submit(delegate.enqueue, data)
                cases = [(snapshot(), '🟢'), (snapshot(latency=1500), '🟡'),
                         (snapshot(True), '🔴'), (snapshot(running=False), '⚪')]
                for index, (data, prefix) in enumerate(cases):
                    AppHelper.callLater(index * .3, emit, data)
                    def verify(prefix=prefix):
                        assert delegate.status_item.button().title().startswith(prefix)
                    AppHelper.callLater(index * .3 + .15, guarded, verify)
                protected = snapshot()
                protected['protection'] = dict(enabled=True, running=True, status='blocked',
                    reason_codes=['tun_down'], reasons=['TUN 接口离线'], event_seq=1,
                    poll_interval_ms=100, terminated_total=1, last_action={'terminated': 1, 'event_seq': 1})
                AppHelper.callLater(1.05, emit, protected)
                def verify_protection():
                    assert delegate.status_item.button().title().startswith('🔴')
                    assert delegate.protection_item.state() == 1
                    assert delegate.local_intervals[100].state() == 1
                AppHelper.callLater(1.2, guarded, verify_protection)
                def change_target():
                    delegate.setTarget_(delegate.targets['JP'])
                AppHelper.callLater(1.3, guarded, change_target)
                def verify_sync():
                    assert server.get_prefs()['target'] == 'JP'
                    assert delegate.targets['JP'].state() == 1
                    assert delegate.targets['US'].state() == 0
                AppHelper.callLater(1.7, guarded, verify_sync)
                def wake_event():
                    with patch.object(runtime, 'on_wake') as wake:
                        delegate.workspace.postNotificationName_object_(AppKit.NSWorkspaceDidWakeNotification, None)
                        wake.assert_called_once()
                AppHelper.callLater(1.8, guarded, wake_event)
                AppHelper.callLater(2.1, AppHelper.stopEventLoop)
                return original_loop(**kwargs)
            try:
                with patch.object(AppHelper, 'runEventLoop', side_effect=loop):
                    tray_app._run_macos_menubar(runtime)
            finally:
                runtime.close()
            assert not Path(server.RUNTIME_INFO_PATH).exists()
            assert not runtime.http_thread.is_alive()
    if errors:
        raise errors[0]
    print('Real AppKit: accessory/no-Dock policy, main-thread four states, target checkmarks, workspace wake and cleanup passed')


if __name__ == '__main__':
    main()

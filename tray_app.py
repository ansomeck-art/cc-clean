#!/usr/bin/env python3
"""Native menu bar with user-authorized, narrowly scoped Claude termination protection."""
import argparse
import concurrent.futures
import http.client
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import threading
import time
import webbrowser

# The retired worker mode cannot initialize a decryption service or the UI.
if __name__ == '__main__' and '--telemetry-worker' in sys.argv:
    raise SystemExit('HTTPS decryption is retired in this version')

import server

NOTIFICATION_SCRIPT = ('on run argv\ndisplay notification (item 2 of argv) with title '
                       '(item 1 of argv) sound name "Funk"\nend run')


def status_view(snapshot):
    target = snapshot.get('target', 'US')
    latest = snapshot.get('latest') or {}
    protection = snapshot.get('protection') or {}
    telemetry = protection.get('telemetry') or {}
    traffic = snapshot.get('traffic')
    traffic_gap = isinstance(traffic, dict) and (traffic.get('state') not in {'observed', 'not_running'}
                                                or traffic.get('limited') is True)
    sources = telemetry.get('sources') or []
    source_gap = any(isinstance(source, dict) and (source.get('state') in {'unknown', 'missing', 'checking', 'stopped'}
                     or (source.get('id') == 'sentry_scope' and source.get('state') == 'observed')
                     or source.get('limited')) for source in sources) if isinstance(sources, list) else True
    armed = protection.get('enabled') and (protection.get('running') or protection.get('status') == 'error')
    if not snapshot.get('running'):
        state, title = 'gray', '⚪ RG · 待机'
    elif (armed and protection.get('status') in {'blocked', 'error'}) or snapshot.get('monitor_error') or latest.get('anomaly'):
        state, title = 'red', '🔴 RG · 告警'
    elif (armed and (protection.get('status') != 'safe' or telemetry.get('state') in {'observed', 'unknown', 'checking', 'stopped', 'missing'} or source_gap)) or traffic_gap or not latest or latest.get('wake_detected') or latest.get('latency_ms', 0) > 1200:
        state, title = 'yellow', '🟡 RG · ' + target
    else:
        state, title = 'green', '🟢 RG · ' + target
    label = {'gray': '已暂停', 'red': '告警', 'yellow': '复核中', 'green': '正常'}[state]
    if state == 'yellow' and telemetry.get('state') == 'missing':
        label = '文件未验证'
    elif state == 'yellow' and source_gap:
        label = '部分来源未验证'
    elif state == 'yellow' and traffic_gap:
        label = '连接待观察'
    status = f"状态: {label} · {target} ({latest.get('ip', '-')} / {latest.get('colo', '-')} · {latest.get('latency_ms', 0)}ms)"
    tunnels = latest.get('utun_ips') or []
    tunnel = ' / '.join(tunnels[:3]) if tunnels else '未确认'
    if armed:
        status += f" · 强退指令 {protection.get('terminated_total', 0)} 次"
        process_unconfirmed = any(code in protection.get('reason_codes', []) for code in ('process_unknown', 'termination_denied'))
        if protection.get('status') == 'error':
            cadence = "进程保护失效 · 自动退出不可用 · 请先手动退出 Claude"
        elif process_unconfirmed:
            cadence = "进程处理未确认 · 请先手动退出 Claude"
        else:
            cadence = f"本地 {protection.get('poll_interval_ms', 100)}ms · 公网 {snapshot.get('interval_sec', 30)}s · 自动退出开启"
        file_label = {'checking': '核验中（仅提示）', 'observed': '待观察（不强退）', 'safe': '受检字段未见指定风险', 'risk': '地区风险',
                      'unknown': '无法核验', 'missing': '未发现/未验证', 'stopped': '已停止'}.get(telemetry.get('state'))
        if isinstance(sources, list) and len(sources) == 8:
            observed = sum(isinstance(source, dict) and source.get('state') in {'safe', 'observed', 'risk'} for source in sources)
            cadence += f' · 文件来源: {observed}/8 已观察（地区仅核验字段源）'
        elif file_label:
            cadence += ' · Sentry 文件: ' + file_label
        if isinstance(traffic, dict):
            connection_label = {'observed': '部分连接证据', 'not_running': '未检测到 Claude',
                                'checking': '核验中', 'unknown': '待观察', 'stopped': '已停止'}.get(traffic.get('state'), '待观察')
            cadence += ' · 后台连接: ' + connection_label
        return dict(state=state, title=title, status=status, tunnel=cadence)
    return dict(state=state, title=title, status=status,
                tunnel=f"隧道: {tunnel} {'在线' if latest.get('utun_up') else '离线/未知'} · 每 {snapshot.get('interval_sec', 30)}s" + (' 守护中' if snapshot.get('running') else ' 已暂停'))


class NotificationGate:
    """Edge-triggered notifications; never repeat a signature within five minutes."""
    def __init__(self):
        self.was_anomaly = False
        self.last_event = None
        self.last_alert_signature = None
        self.last_alert_ts = float('-inf')
        self._guard_seq = None
        self._guard_blocked = False
        self._guard_signature = None
        self._guard_ts = float('-inf')
        self._guard_action_seen = set()
        self._guard_action_signature = None
        self._guard_action_ts = float('-inf')

    def _consume_guard(self, guard, enabled, at, current):
        sequence = guard.get('event_seq')
        action = guard.get('last_action') or {}
        action_key = (action.get('at'), action.get('event_seq'))
        new_action = (action.get('terminated', 0) > 0 and action.get('event_seq') == sequence
                      and action_key not in self._guard_action_seen)
        if new_action:
            if len(self._guard_action_seen) > 128:
                self._guard_action_seen.clear()
            self._guard_action_seen.add(action_key)
        else:
            if sequence == self._guard_seq:
                return None
            if isinstance(sequence, int) and isinstance(self._guard_seq, int) and sequence < self._guard_seq:
                return None
        later_already_seen = isinstance(sequence, int) and isinstance(self._guard_seq, int) and sequence < self._guard_seq
        if not later_already_seen:
            self._guard_seq = sequence
        blocked = guard.get('status') in {'blocked', 'error'}
        current_blocked = current.get('status') in {'blocked', 'error'}
        codes = tuple(guard.get('reason_codes') or [])
        signature = guard.get('status'), codes
        recovered = self._guard_blocked and guard.get('status') == 'safe' and current.get('status') == 'safe'
        if current_blocked:
            self._guard_blocked = True
        elif not later_already_seen:
            self._guard_blocked = blocked
        pending_only = codes and all(code in {'remote_pending', 'wake_pending', 'route_pending', 'telemetry_pending', 'telemetry_file_pending'} for code in codes)
        if new_action and (signature != self._guard_action_signature or at - self._guard_action_ts >= 300):
            self._guard_action_signature, self._guard_action_ts = signature, at
            self._guard_signature, self._guard_ts = signature, at
            message = f"刚才已对 {action['terminated']} 个已确认的 Claude 进程发送强退指令。触发原因：" + '；'.join(guard.get('reasons') or [])
            if current.get('status') == 'safe':
                message += '。当前安全条件已恢复，Claude 需手动重开。'
            elif current.get('status') == 'error':
                message += '。当前保护失效，自动退出不可用。'
            return ('Region Guard · 进程保护记录', message[:400]) if enabled else None
        if blocked and not pending_only and (signature != self._guard_signature or at - self._guard_ts >= 300):
            self._guard_signature, self._guard_ts = signature, at
            message = '；'.join(guard.get('reasons') or [])
            if guard.get('status') == 'error':
                return ('Region Guard · 保护失效', '自动退出不可用，请手动退出 Claude。' + message[:300]) if enabled else None
            return ('Region Guard · 进程保护', message[:400]) if enabled else None
        if recovered:
            return ('Region Guard · 安全条件恢复', 'Claude 不会自动重启；请在确认守护状态正常后手动打开。') if enabled else None
        return None

    def consume(self, snapshot, enabled=True, now=None):
        current = snapshot.get('protection') or {}
        guard = snapshot.get('protection_event') or current
        if snapshot.get('running') and current.get('enabled') and (current.get('running') or current.get('status') == 'error'):
            if not guard.get('enabled') or not (guard.get('running') or guard.get('status') == 'error'):
                return None
            return self._consume_guard(guard, enabled, time.monotonic() if now is None else now, current)
        self._guard_seq, self._guard_blocked = None, False
        latest = snapshot.get('latest')
        if not snapshot.get('running'):
            self.was_anomaly = False
            self.last_event = None
            return None
        if not latest:
            return None
        identity = (latest.get('timestamp'), latest.get('target'), latest.get('ip'), latest.get('anomaly'),
                    latest.get('wake_detected'), tuple(latest.get('anomaly_reasons') or []))
        if identity == self.last_event:
            return None
        self.last_event = identity
        now = time.monotonic() if now is None else now
        anomaly = bool(latest.get('anomaly'))
        reasons = latest.get('anomaly_reasons') or []
        signature = (snapshot.get('target'), tuple(sorted(reason.split('(')[0] for reason in reasons)))
        recovered = self.was_anomaly and not anomaly
        candidate = anomaly and (not self.was_anomaly or latest.get('wake_detected') or signature != self.last_alert_signature)
        self.was_anomaly = anomaly
        if candidate and (signature != self.last_alert_signature or now - self.last_alert_ts >= 300):
            self.last_alert_signature, self.last_alert_ts = signature, now
            return ('Region Guard · 网络告警', '；'.join(reasons)[:400] or '后台网络状态异常') if enabled else None
        if recovered:
            return ('Region Guard · 已恢复', f"{snapshot.get('target', 'US')} 出口与 TUN 已恢复；请查看监测台。") if enabled else None
        return None


def send_notification(title, message):
    """All notification text is argv data, never interpolated into AppleScript code."""
    try:
        completed = subprocess.run(['/usr/bin/osascript', '-e', NOTIFICATION_SCRIPT, title, message],
                                   timeout=4, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class InstanceLock:
    """Never unlink a flock inode: a still-live holder must retain exclusivity."""
    def __init__(self, path=None):
        self.path = path or server.LOCK_FILE_PATH
        self.fd = None
        self.mutex = None

    def acquire(self):
        if sys.platform == 'win32':
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.CreateMutexW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
            kernel.CreateMutexW.restype = wintypes.HANDLE
            self.mutex = kernel.CreateMutexW(None, False, 'Local\\RegionGuard.MenuBar')
            if not self.mutex:
                raise OSError('cannot create instance mutex')
            if ctypes.get_last_error() == 183:
                self.release()
                return False
            return True
        import fcntl
        flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
        self.fd = os.open(self.path, flags, 0o600)
        os.fchmod(self.fd, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            os.close(self.fd)
            self.fd = None
            return False

    def release(self):
        if self.fd is not None:
            import fcntl
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None
        if self.mutex is not None:
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel.CloseHandle(self.mutex)
            self.mutex = None


def existing_dashboard(runtime_path=None):
    """Proxy-independent one-second health check, with strict runtime metadata validation."""
    from audit_common import read_json
    try:
        runtime = read_json(runtime_path or server.RUNTIME_INFO_PATH, 4096)
        port, pid = runtime.get('port'), runtime.get('pid')
        if type(port) is not int or not 1 <= port <= 65535 or type(pid) is not int or pid <= 0:
            return None
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
        try:
            connection.request('GET', '/api/headers')
            response = connection.getresponse()
            payload = json.loads(response.read(65536))
            if response.status == 200 and payload.get('service') == 'RegionGuard':
                return f'http://127.0.0.1:{port}/'
        finally:
            connection.close()
    except (OSError, ValueError, TypeError, AttributeError, http.client.HTTPException):
        pass
    return None


def open_dashboard(url):
    if sys.platform == 'darwin':
        subprocess.run(['/usr/bin/open', url], timeout=4, check=False)
    else:
        webbrowser.open(url)


class TrayRuntime:
    def __init__(self, preferred_port=8765, silent=False):
        self.preferred_port, self.silent = preferred_port, silent
        self.lock = InstanceLock()
        self.httpd = None
        self.http_thread = None
        self.timers = []
        self.work = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix='rg-tray')
        self.closing = False
        self.url = None
        self.unsubscribe = None
        self._task_lock = threading.Lock()
        self._waking = False
        self._unregister_open = None

    def start(self):
        if not self.lock.acquire():
            # A dead process releases flock automatically; retry without killing a live process
            # or unlinking its lock (either would violate the read-only/exclusive-instance contract).
            for attempt in range(3):
                url = existing_dashboard()
                if url:
                    open_dashboard(url)
                    return False
                if self.lock.acquire():
                    break
                if attempt < 2:
                    threading.Event().wait(.2)
            else:
                raise RuntimeError('已有实例尚未响应；请稍后重试或从菜单正常退出。')
        try:
            server.SHUTDOWN_EVENT.clear()
            server.RUN_MODE = 'menubar'
            self.httpd, port = server.create_http_server(preferred_port=self.preferred_port)
            self.url = f'http://127.0.0.1:{port}/'
            self.http_thread = threading.Thread(target=self.httpd.serve_forever, name='rg-http', daemon=True)
            self.http_thread.start()
            server._atomic_write(server.RUNTIME_INFO_PATH, json.dumps(dict(pid=os.getpid(), port=port, started_at=server.now_iso())))
            prefs = server.get_prefs()
            server.MONITOR.configure(prefs['target'], prefs['interval_sec'])
            if prefs['auto_start_monitor']:
                server.MONITOR.start(prefs['target'], prefs['interval_sec'])
            if not self.silent:
                self.schedule(.4, lambda: open_dashboard(self.url))
            return True
        except BaseException:
            self.close()
            raise

    def submit(self, function, *args, **kwargs):
        with self._task_lock:
            if not self.closing:
                return self.work.submit(function, *args, **kwargs)
        return None

    def schedule(self, delay, function):
        timer = threading.Timer(delay, lambda: self.submit(function))
        timer.daemon = True
        with self._task_lock:
            if self.closing:
                return
            self.timers.append(timer)
            timer.start()

    def probe(self, wake_detected=False):
        if not self.closing:
            return server.run_pulse(server.get_prefs()['target'], wake_detected=wake_detected)

    def on_wake(self):
        if self.closing or not server.MONITOR.status()['running']:
            return
        # Duplicate workspace notifications within one wake sequence are coalesced.
        with self._task_lock:
            if self._waking:
                return
            self._waking = True
        server.MONITOR.on_wake()  # fast local protection is independent of delayed Internet rechecks
        self.schedule(1.5, lambda: self.probe(wake_detected=True))
        def followup():
            try:
                self.probe(wake_detected=True)
            finally:
                with self._task_lock:
                    self._waking = False
        self.schedule(4.5, followup)
        # A final ordinary sample removes the yellow 'wake verification' state.
        self.schedule(6.5, lambda: self.probe(wake_detected=False))

    def close(self):
        with self._task_lock:
            if self.closing:
                return
            self.closing = True
            timers = tuple(self.timers)
        for timer in timers:
            timer.cancel()
        if self.unsubscribe:
            self.unsubscribe()
        if server.MONITOR.protection is not None:
            server.MONITOR.protection.stop()  # disarm before cancelling our Internet probes on quit
        if self.httpd:
            server.shutdown_observers()
        server.MONITOR.stop()
        if self.httpd:
            if self.http_thread and self.http_thread.is_alive():
                self.httpd.shutdown()
            self.httpd.server_close()
        if self.http_thread:
            self.http_thread.join(3)
        self.work.shutdown(wait=True, cancel_futures=True)
        # Only remove our own runtime marker, and only while we still hold the instance lock.
        if self.lock.fd is not None or self.lock.mutex is not None:
            try:
                from audit_common import read_json
                if read_json(server.RUNTIME_INFO_PATH, 4096).get('pid') == os.getpid():
                    os.unlink(server.RUNTIME_INFO_PATH)
            except (OSError, ValueError, AttributeError):
                pass
        self.lock.release()


def _run_macos_menubar(runtime):
    try:
        import objc
        import AppKit
        import Foundation
        from PyObjCTools import AppHelper
    except ImportError as exc:
        raise RuntimeError('菜单栏模式需要 PyObjC；请运行构建脚本或在项目虚拟环境安装 pyobjc-framework-Cocoa。') from exc

    class MenuDelegate(Foundation.NSObject):
        @objc.python_method
        def setup(self):
            self.gate = NotificationGate()
            self.stop_requested = threading.Event()
            # Enter Python regularly so ordinary POSIX signals are serviced while AppKit
            # waits for events; background CLI launches must also shut down cleanly.
            self.signal_timer = Foundation.NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
                0.25, self, 'pollSignals:', None, True)
            self.status_item = AppKit.NSStatusBar.systemStatusBar().statusItemWithLength_(AppKit.NSVariableStatusItemLength)
            self.menu = AppKit.NSMenu.alloc().init()
            self.menu.setAutoenablesItems_(False)
            self.status_line = self.item('状态: 初始化中', enabled=False)
            self.tunnel_line = self.item('隧道: 初始化中', enabled=False)
            self.menu.addItem_(AppKit.NSMenuItem.separatorItem())
            self.item('打开全景监测台', 'openDashboard:', 'o')
            self.item('立即探测一次', 'probeNow:', 'r')
            self.monitor_item = self.item('开启后台持续监控', 'toggleMonitor:')
            self.notify_item = self.item('异常桌面弹窗通知', 'toggleNotify:')
            self.protection_item = self.item('异常时自动强制退出 Claude', 'toggleProtection:')
            self.protection_item.setToolTip_('严格保护：启动/唤醒未确认安全也会退出。可能丢失未保存内容，恢复后不会自动重开。')
            self.local_intervals = {}
            local_parent = self.item('本地检测间隔')
            local_menu = AppKit.NSMenu.alloc().init()
            local_menu.setAutoenablesItems_(False)
            for value in (50, 100, 250, 500):
                item = AppKit.NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(f'{value} 毫秒', 'setLocalInterval:', '')
                item.setTarget_(self)
                item.setRepresentedObject_(value)
                local_menu.addItem_(item)
                self.local_intervals[value] = item
            local_parent.setSubmenu_(local_menu)
            self.targets, self.intervals = {}, {}
            for title, values, mapping, action in (
                ('目标地区', ('US', 'SG', 'JP', 'GB', 'TW', 'AU', 'CA', 'DE'), self.targets, 'setTarget:'),
                ('公网复核频率', (15, 30, 60), self.intervals, 'setInterval:'),
            ):
                parent = self.item(title)
                submenu = AppKit.NSMenu.alloc().init()
                submenu.setAutoenablesItems_(False)
                for value in values:
                    item = AppKit.NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(str(value) + (' 秒' if type(value) is int else ''), action, '')
                    item.setTarget_(self)
                    item.setRepresentedObject_(value)
                    submenu.addItem_(item)
                    mapping[value] = item
                parent.setSubmenu_(submenu)
            self.menu.addItem_(AppKit.NSMenuItem.separatorItem())
            autostart = Path.home() / 'Library/LaunchAgents/com.regionguard.menubar.plist'
            item = self.item('登录 macOS 时自动启动（只读检查）', enabled=False)
            item.setState_(int(autostart.is_file()))
            self.item('查看自启配置说明', 'showAutostart:')
            self.item('退出 Region Guard', 'quit:', 'q')
            self.status_item.setMenu_(self.menu)
            self.workspace = AppKit.NSWorkspace.sharedWorkspace().notificationCenter()
            self.workspace.addObserver_selector_name_object_(self, 'workspaceDidWake:', AppKit.NSWorkspaceDidWakeNotification, None)
            runtime.unsubscribe = server.MONITOR.register_listener(self.enqueue)
            self.applySnapshot_(server.MONITOR.status())

        @objc.python_method
        def item(self, title, action=None, key='', enabled=True):
            item = AppKit.NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(title, action, key)
            item.setTarget_(self)
            item.setEnabled_(enabled)
            self.menu.addItem_(item)
            return item

        @objc.python_method
        def enqueue(self, snapshot):
            # All controls, including menu checkmarks and native notifications, are main-thread only.
            if not runtime.closing:
                self.performSelectorOnMainThread_withObject_waitUntilDone_('applySnapshot:', snapshot, False)

        def applySnapshot_(self, snapshot):
            if runtime.closing:
                return
            assert Foundation.NSThread.isMainThread()
            view = status_view(snapshot)
            self.status_item.button().setTitle_(view['title'])
            self.status_item.button().setToolTip_(view['status'])
            self.status_line.setTitle_(view['status'])
            self.tunnel_line.setTitle_(view['tunnel'])
            self.monitor_item.setState_(int(bool(snapshot['running'])))
            prefs = snapshot.get('prefs') or server.get_prefs()
            self.notify_item.setState_(int(prefs['notify_enabled']))
            self.protection_item.setState_(int(prefs['protection_enabled']))
            for interval, item in self.local_intervals.items():
                item.setState_(int(interval == prefs['local_interval_ms']))
            for target, item in self.targets.items():
                item.setState_(int(target == prefs['target']))
            for interval, item in self.intervals.items():
                item.setState_(int(interval == prefs['interval_sec']))
            message = self.gate.consume(snapshot, prefs['notify_enabled'])
            if message:
                runtime.submit(self.deliver, *message)

        @objc.python_method
        def deliver(self, title, message):
            if not send_notification(title, message):
                self.performSelectorOnMainThread_withObject_waitUntilDone_('nativeNotify:', [title, message], False)

        def nativeNotify_(self, payload):
            assert Foundation.NSThread.isMainThread()
            try:
                notice = Foundation.NSUserNotification.alloc().init()
                notice.setTitle_(payload[0])
                notice.setInformativeText_(payload[1])
                Foundation.NSUserNotificationCenter.defaultUserNotificationCenter().deliverNotification_(notice)
            except Exception:
                pass  # user's OS notification permissions remain authoritative

        @objc.IBAction
        def openDashboard_(self, sender):
            runtime.submit(open_dashboard, runtime.url)

        @objc.IBAction
        def probeNow_(self, sender):
            runtime.submit(runtime.probe)

        @objc.IBAction
        def toggleMonitor_(self, sender):
            def toggle():
                prefs = server.get_prefs()
                running = server.MONITOR.status()['running']
                server.update_prefs({'auto_start_monitor': not running})
                if running:
                    server.MONITOR.stop()
                else:
                    server.MONITOR.start(prefs['target'], prefs['interval_sec'])
            runtime.submit(toggle)

        @objc.IBAction
        def toggleNotify_(self, sender):
            runtime.submit(server.update_prefs, {'notify_enabled': not server.get_prefs()['notify_enabled']})

        @objc.IBAction
        def toggleProtection_(self, sender):
            runtime.submit(server.update_prefs, {'protection_enabled': not server.get_prefs()['protection_enabled']})

        @objc.IBAction
        def setLocalInterval_(self, sender):
            runtime.submit(server.update_prefs, {'local_interval_ms': int(sender.representedObject())})

        @objc.IBAction
        def setTarget_(self, sender):
            runtime.submit(server.update_prefs, {'target': str(sender.representedObject())})

        @objc.IBAction
        def setInterval_(self, sender):
            runtime.submit(server.update_prefs, {'interval_sec': int(sender.representedObject())})

        @objc.IBAction
        def showAutostart_(self, sender):
            runtime.submit(open_dashboard, runtime.url + '#autostart-guide')

        @objc.IBAction
        def quit_(self, sender):
            # NSApp.terminate_ would exit Python before our cleanup. Stop run() and
            # post an event so it returns even when invoked from a timer/termination callback.
            app = AppKit.NSApplication.sharedApplication()
            app.stop_(None)
            event = AppKit.NSEvent.otherEventWithType_location_modifierFlags_timestamp_windowNumber_context_subtype_data1_data2_(
                AppKit.NSApplicationDefined, (0, 0), 0, 0, 0, None, 0, 0, 0)
            app.postEvent_atStart_(event, True)

        def pollSignals_(self, timer):
            if self.stop_requested.is_set():
                self.quit_(None)

        def workspaceDidWake_(self, notification):
            runtime.on_wake()

        def applicationShouldHandleReopen_hasVisibleWindows_(self, app, visible):
            runtime.submit(open_dashboard, runtime.url)
            return False

        def applicationShouldTerminate_(self, sender):
            self.quit_(sender)
            return AppKit.NSTerminateCancel

    app = AppKit.NSApplication.sharedApplication()
    app.setActivationPolicy_(AppKit.NSApplicationActivationPolicyAccessory)
    delegate = MenuDelegate.alloc().init()
    app.setDelegate_(delegate)
    delegate.setup()
    previous_signals = {}
    def request_exit(signum, frame):
        delegate.stop_requested.set()
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_signals[signum] = signal.signal(signum, request_exit)
    server.NATIVE_READY = True
    try:
        AppHelper.runEventLoop(installInterrupt=False)
    finally:
        server.NATIVE_READY = False
        for signum, previous in previous_signals.items():
            signal.signal(signum, previous)
        delegate.signal_timer.invalidate()
        delegate.workspace.removeObserver_(delegate)
        AppKit.NSStatusBar.systemStatusBar().removeStatusItem_(delegate.status_item)


def _run_windows_pystray(runtime):
    """Optional Phase 6 integration; existing Windows CLI and packaging stay usable."""
    try:
        import pystray
        from PIL import Image, ImageDraw
    except ImportError as exc:
        raise RuntimeError('Windows 原生托盘可选依赖: pystray Pillow；现有 server.py CLI 无需这些依赖。') from exc
    def icon_image(color):
        image = Image.new('RGBA', (32, 32))
        ImageDraw.Draw(image).ellipse((6, 6, 26, 26), fill=color)
        return image
    icon = pystray.Icon('RegionGuard', icon_image('gray'), 'RegionGuard')
    icon.menu = pystray.Menu(
        pystray.MenuItem('打开监测台', lambda *_: runtime.submit(open_dashboard, runtime.url), default=True),
        pystray.MenuItem('立即探测', lambda *_: runtime.submit(runtime.probe)),
        pystray.MenuItem('退出', lambda *_: icon.stop()),
    )
    def listener(snapshot):
        view = status_view(snapshot)
        icon.icon, icon.title = icon_image(view['state']), view['status']
    runtime.unsubscribe = server.MONITOR.register_listener(listener)
    icon.run()


def main():
    parser = argparse.ArgumentParser(description='RegionGuard 原生菜单栏守护')
    parser.add_argument('--silent', action='store_true')
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    if sys.platform not in {'darwin', 'win32'}:
        raise SystemExit('此平台请运行 python3 server.py')
    runtime = TrayRuntime(args.port, args.silent)
    try:
        if runtime.start():
            if sys.platform == 'darwin':
                _run_macos_menubar(runtime)
            else:
                _run_windows_pystray(runtime)
    finally:
        runtime.close()


if __name__ == '__main__':
    main()

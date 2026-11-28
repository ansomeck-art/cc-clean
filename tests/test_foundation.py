"""Foundation gates: only fixture files, mocked commands and loopback HTTP."""
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server
import win_platform
from audit_common import count_log_tail


class HTTPGuardTests(unittest.TestCase):
    def setUp(self):
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.RegionGuardHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_port

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(2)

    def request(self, method="GET", path="/api/headers", headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        status, data = response.status, response.read()
        conn.close()
        return status, data

    def test_host_rebinding_and_port(self):
        for host in ("evil.com", f"127.0.0.1:{self.port + 1}", f"localhost.evil.com:{self.port}"):
            with self.subTest(host=host):
                self.assertEqual(self.request(headers={"Host": host})[0], 403)
        self.assertEqual(self.request()[0], 200)

    def test_csrf_and_same_origin(self):
        with patch.object(server.MONITOR, "stop", return_value={"running": False}) as stop:
            self.assertEqual(self.request("POST", "/api/monitor/stop")[0], 403)
            base = {"X-Region-Guard": "1"}
            for extra in ({"Origin": "https://evil.com"}, {"Sec-Fetch-Site": "cross-site"},
                          {"Origin": "null"}, {"Origin": "http://localhost:1"}):
                self.assertEqual(self.request("POST", "/api/monitor/stop", {**base, **extra})[0], 403)
            stop.assert_not_called()
            headers = {**base, "Origin": f"http://127.0.0.1:{self.port}", "Sec-Fetch-Site": "same-origin"}
            self.assertEqual(self.request("POST", "/api/monitor/stop", headers)[0], 200)
            stop.assert_called_once()

    def test_frontend_modules_served(self):
        for asset in ("fingerprint-checks.js", "locale-checks.js"):
            self.assertEqual(self.request(path="/static/" + asset)[0], 200)
        for asset in ('telemetry-filter.sgmodule', 'telemetry-filter.js'):
            self.assertEqual(self.request(path='/static/' + asset)[0], 404)

    def test_filter_mutations_require_same_origin_header(self):
        for action, method in (('start', 'start'), ('stop', 'stop'),
                               ('trust', 'trust_certificate'), ('launch', 'launch_claude')):
            with patch.object(server.TELEMETRY_SERVICE, method, return_value={'state': 'stopped'}) as call:
                path = '/api/telemetry/' + action
                self.assertEqual(self.request('POST', path)[0], 403)
                self.assertEqual(self.request('POST', path, {'X-Region-Guard': '1',
                                                            'Origin': 'https://evil.com'})[0], 403)
                call.assert_not_called()
                self.assertEqual(self.request('POST', path, {'X-Region-Guard': '1'})[0], 200)
                call.assert_called_once()


class FoundationTests(unittest.TestCase):
    def test_frozen_user_dir_is_private_and_external(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(server, "IS_MACOS", True), \
             patch.object(server.os.path, "expanduser", return_value=os.path.join(temp, "RegionGuard")), \
             patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "executable", "/Applications/RegionGuard.app/Contents/MacOS/RegionGuard"):
            result = server._resolve_user_data_dir()
            self.assertNotIn(".app/", result)
            self.assertEqual(os.stat(result).st_mode & 0o777, 0o700)

    def test_isolated_runtime_override_cannot_target_bundle_or_arbitrary_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            private = os.path.join(temp, "regionguard-test-isolated")
            with patch.dict(os.environ, {"REGIONGUARD_DATA_DIR": private}):
                self.assertEqual(server._resolve_user_data_dir(), private)
                self.assertEqual(os.stat(private).st_mode & 0o777, 0o700)
            for invalid in (os.path.join(temp, "ThirdParty"), os.path.join(temp, "App.app", "RegionGuard"), "relative/RegionGuard"):
                with patch.dict(os.environ, {"REGIONGUARD_DATA_DIR": invalid}):
                    with self.assertRaises(ValueError):
                        server._resolve_user_data_dir()

    def test_singleflight_reuses_result(self):
        entered, release = threading.Event(), threading.Event()
        barrier = threading.Barrier(8)
        result = {"fixture": True}
        def scan(target):
            entered.set()
            self.assertTrue(release.wait(2))
            return result
        def request():
            barrier.wait(2)
            return server.run_full_scan("us")
        with patch.object(server, "_run_full_scan", side_effect=scan) as mock_scan:
            with concurrent.futures.ThreadPoolExecutor(8) as pool:
                futures = [pool.submit(request) for _ in range(8)]
                self.assertTrue(entered.wait(2))
                # All followers must reach Future.result before the owner completes.
                import time
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    with server._SCAN_LOCK:
                        flight = server._SCAN_FLIGHTS.get("US")
                    if flight and len(flight._condition._waiters) == 7:
                        break
                    time.sleep(.005)
                release.set()
                self.assertTrue(all(f.result(2) is result for f in futures))
            self.assertEqual(mock_scan.call_count, 1)
        self.assertFalse(server._SCAN_FLIGHTS)

    def test_curl_does_not_inherit_proxy_environment(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "fixture-secret", "all_proxy": "fixture-secret"}), \
             patch.object(server, "run_cmd", return_value=(0, "ok", "")) as cmd:
            server.curl_fetch("https://example.com", ipv6_only=True)
        env = cmd.call_args.kwargs["env"]
        self.assertFalse(any(k.lower() in {"http_proxy", "https_proxy", "all_proxy"} for k in env))
        self.assertEqual(cmd.call_args.args[0][1], "-q")

    def test_log_categories_are_mutually_exclusive_and_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.log"
            path.write_bytes(b"region_blocked\n" + b"x" * (4 * 1024 * 1024) + b"\n"
                             b"account_banned bad_device_id account_banned\n"
                             b"desktop_telemetry_upload_lost [EventLogging] POST threw\n")
            counts = count_log_tail(path)
        self.assertEqual(counts["region"], 0)
        self.assertEqual(counts["banned"], 1)
        self.assertEqual(counts["telemetry"], 1)

    def test_windows_normal_device_binding_is_informational(self):
        with tempfile.TemporaryDirectory() as temp:
            sentry = Path(temp) / "sentry"
            sentry.mkdir()
            (sentry / "scope_v3.json").write_text(json.dumps({
                "scope": {"user": {"id": "private-fixture"}},
                "event": {"contexts": {"culture": {"locale": "en-US", "timezone": "America/New_York"}}}}))
            result = win_platform._inspect_desktop_telemetry_artifacts(temp, "fixture")
        self.assertEqual(result["sentry_status"], "INFO")
        self.assertNotIn("private-fixture", json.dumps(result))

"""Retired product entrypoints cannot decrypt, spawn, edit trust or launch clients."""
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from readonly_telemetry import ReadonlyTelemetryService, telemetry_filter_check
import server


class RetiredTelemetryTests(unittest.TestCase):
    def test_all_public_operations_are_inert_without_filesystem_or_process_io(self):
        with patch.object(os, 'open', side_effect=AssertionError('unexpected file read')), \
             patch.object(Path, 'read_bytes', side_effect=AssertionError('unexpected certificate read')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('unexpected process launch')):
            service = ReadonlyTelemetryService('/PRIVATE-NOT-USED')
            self.assertFalse(service.refresh_trust(force=True))
            for action in (service.start, service.launch_claude, service.trust_certificate):
                with self.assertRaisesRegex(RuntimeError, '已停用'):
                    action()
            for state in (service.status(), service.stop()):
                self.assertEqual(state['state'], 'retired')
                self.assertFalse(state['running'])
                self.assertFalse(state['traffic_confirmed'])
                self.assertFalse(state['client_started'])
                self.assertNotIn('PRIVATE', json.dumps(state))
                self.assertNotIn('proxy_url', state)
            self.assertEqual(telemetry_filter_check()['status'], 'INFO')

    def test_product_http_entrypoints_refuse_start_trust_and_proxy_launch(self):
        httpd = server.ThreadingHTTPServer(('127.0.0.1', 0), server.RegionGuardHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            for action in ('start', 'trust', 'launch'):
                conn = http.client.HTTPConnection('127.0.0.1', httpd.server_port, timeout=2)
                try:
                    conn.request('POST', '/api/telemetry/' + action, '{}',
                                 {'X-Region-Guard': '1', 'Content-Type': 'application/json'})
                    response = conn.getresponse()
                    self.assertEqual(response.status, 409)
                    self.assertIn('已停用', json.loads(response.read())['error'])
                finally:
                    conn.close()
            self.assertEqual(server.TELEMETRY_SERVICE.status()['state'], 'retired')
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(2)

    def test_version_review_is_explicit_same_origin_and_forwards_expected_version(self):
        observer = Mock()
        observer.status.return_value = dict(state='changed', versions=['6.1'], review_required=True)
        observer.mark_reviewed.return_value = dict(state='observed', versions=['6.1'], review_required=False)
        httpd = server.ThreadingHTTPServer(('127.0.0.1', 0), server.RegionGuardHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        def request(method, path, headers=None):
            conn = http.client.HTTPConnection('127.0.0.1', httpd.server_port, timeout=2)
            try:
                conn.request(method, path, json.dumps({'expected_versions': ['6.1']}) if method == 'POST' else None,
                             headers or {})
                response = conn.getresponse()
                return response.status, json.loads(response.read())
            finally:
                conn.close()
        try:
            with patch.object(server, 'CLIENT_VERSION', observer):
                status, body = request('GET', '/api/client-version/status')
                self.assertEqual(status, 200)
                self.assertTrue(body['review_required'])
                observer.sample.assert_not_called()
                observer.mark_reviewed.assert_not_called()
                self.assertEqual(request('POST', '/api/client-version/review')[0], 403)
                observer.mark_reviewed.assert_not_called()
                status, body = request('POST', '/api/client-version/review', {'X-Region-Guard': '1'})
                self.assertEqual(status, 200)
                self.assertFalse(body['review_required'])
                observer.mark_reviewed.assert_called_once_with(['6.1'])
                observer.mark_reviewed.side_effect = RuntimeError('client version baseline changed')
                self.assertEqual(request('POST', '/api/client-version/review', {'X-Region-Guard': '1'})[0], 409)
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(2)


if __name__ == '__main__':
    unittest.main()

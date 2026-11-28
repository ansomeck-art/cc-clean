"""Pure synthesized HTTP/log fixtures; no requests or user log reads."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service_diagnostics import (DIAGNOSTIC_KEYS, DIAGNOSTIC_LABELS, MAX_BODY_BYTES, MAX_LOG_BYTES,
                                 MAX_LOG_LINES, classify_http, inspect_log_diagnostics)


class HTTPDiagnosticsTests(unittest.TestCase):
    def assertCodes(self, expected, **kwargs):
        result = classify_http(**kwargs)
        self.assertEqual(set(result["reason_codes"]), set(expected))
        self.assertEqual(set(result["diagnostics"]), set(DIAGNOSTIC_KEYS))
        self.assertTrue(all(type(value) is int and value in (0, 1) for value in result["diagnostics"].values()))
        return result

    def test_fixed_nine_categories_and_labels(self):
        self.assertEqual(len(DIAGNOSTIC_KEYS), 9)
        self.assertEqual(set(DIAGNOSTIC_KEYS), set(DIAGNOSTIC_LABELS))
        self.assertCodes([], status=200)

    def test_ordinary_403_never_becomes_region_or_ban(self):
        for body in (None, "Forbidden", "China user mentioned in unrelated prose", "<html>Forbidden</html>"):
            with self.subTest(body=body):
                self.assertCodes(["http_forbidden_unknown"], status=403, body=body)

    def test_explicit_region_header_and_structured_codes(self):
        for code in ("region_blocked", "region_unavailable", "app-unavailable-in-region"):
            with self.subTest(code=code):
                self.assertCodes(["region_denied"], status=403, headers={"X-Claude-Error-Code": code})
                self.assertCodes(["region_denied"], status=403, body=json.dumps({"error": {"code": code}}))

    def test_body_message_mentions_are_not_region_evidence(self):
        for obj in ({"message": "region_unavailable account_banned"},
                    {"messages": [{"error": {"type": "account_banned"}}]},
                    {"content": {"code": "region_blocked"}}):
            self.assertCodes(["http_forbidden_unknown"], status=403, body=json.dumps(obj))

    def test_permission_error_is_distinct_from_region_and_ban(self):
        self.assertCodes(["permission_denied"], status=403,
                         body=json.dumps({"error": {"type": "permission_error", "message": "Access not permitted"}}))

    def test_bootstrap_error_details_are_allowed_but_unrelated_details_are_not(self):
        self.assertCodes(["permission_denied", "ip_restricted"], status=403,
                         body=json.dumps({"error": {"type": "permission_error",
                                                    "details": {"error_code": "ip_not_in_allowed_range"}}}))
        self.assertCodes(["region_denied"], status=403,
                         body=json.dumps({"error": {"details": {"error_code": "region_unavailable"}}}))
        self.assertCodes(["permission_denied"], status=403,
                         body=json.dumps({"error": {"details": {"error_code": "tenant_restriction_violation"}}}))
        self.assertCodes(["http_forbidden_unknown"], status=403,
                         body=json.dumps({"details": {"error_code": "account_banned"}}))

    def test_ip_restriction_requires_an_explicit_error_or_message(self):
        self.assertCodes(["permission_denied", "ip_restricted"], status=403,
                         body=json.dumps({"error": {"type": "permission_error", "message": "Your IP address is not allowed"}}))
        self.assertCodes(["http_forbidden_unknown"], status=403, body=json.dumps({"allowedIP": ["fixture"]}))
        self.assertCodes(["ip_restricted"], status=403, body=json.dumps({"error_code": "ip_not_allowed"}))

    def test_challenge_header_is_precise(self):
        self.assertCodes(["edge_challenge"], status=403, headers={"Cf-Mitigated": "challenge"})
        self.assertCodes(["http_forbidden_unknown"], status=403, headers={"Cf-Mitigated": "unknown"})
        self.assertCodes(["http_forbidden_unknown"], status=403, body="Cloudflare challenge mentioned in a page")

    def test_only_explicit_account_banned_is_a_ban(self):
        self.assertCodes(["account_banned"], status=403, body=json.dumps({"error": {"type": "account_banned"}}))
        for code in ("bad_device_id", "account_disabled", "account_suspended", "authentication_error"):
            self.assertCodes(["http_forbidden_unknown"], status=403, body=json.dumps({"error": {"type": code}}))

    def test_timeout_connection_failure_and_other_http_are_distinct(self):
        for error in ("timeout", "ETIMEDOUT", "Operation timed out after 2000ms", {"code": "ERR_TIMED_OUT"}):
            self.assertCodes(["network_timeout"], error=error)
        for error in ("network_error", "ECONNRESET", "connection refused", {"code": "ENOTFOUND"}):
            self.assertCodes(["network_error"], error=error)
        for status in (408, 504):
            self.assertCodes(["network_timeout"], status=status)
        for status in (401, 404, 429, 500, 503):
            self.assertCodes(["http_error"], status=status)

    def test_raw_curl_headers_use_last_response_block(self):
        headers = ("HTTP/1.1 200 Connection established\r\n\r\n"
                   "HTTP/2 403\r\ncf-mitigated: challenge\r\nSet-Cookie: secret-fixture\r\n\r\n")
        self.assertCodes(["edge_challenge"], status=403, headers=headers)
        headers = "HTTP/2 403\r\nx-claude-error-code: region_unavailable\r\n\r\nHTTP/2 403\r\n\r\n"
        self.assertCodes(["http_forbidden_unknown"], status=403, headers=headers)

    def test_exact_same_origin_region_redirect(self):
        self.assertCodes(["region_denied"], status=302, headers={"Location": "/app-unavailable-in-region"})
        self.assertCodes(["region_denied"], status=307,
                         headers="Location: https://claude.ai/app-unavailable-in-region?source=fixture\r\n",
                         request_url="https://claude.ai/")
        for location in ("https://external.example/app-unavailable-in-region", "//external.example/app-unavailable-in-region",
                         "/app-unavailable-in-region-extra", "/other?next=/app-unavailable-in-region",
                         "/APP-UNAVAILABLE-IN-REGION", "https://claude.ai:8443/app-unavailable-in-region",
                         "https://claude.ai@external.example/app-unavailable-in-region"):
            with self.subTest(location=location):
                self.assertCodes([], status=302, headers={"Location": location}, request_url="https://claude.ai/")
        self.assertCodes([], status=200, headers={"Location": "/app-unavailable-in-region"})

    def test_invalid_and_oversized_inputs_do_not_echo_or_guess(self):
        result = self.assertCodes(["http_forbidden_unknown"], status=403, body=b"x" * (MAX_BODY_BYTES + 1))
        self.assertTrue(result["limited"])
        self.assertCodes(["http_forbidden_unknown"], status=403,
                         body=b'{"error":{"type":"account_banned"},"error":{}}')
        self.assertCodes(["http_forbidden_unknown"], status=403, body=b"\xff")
        for status in (True, "403", -1, 999):
            self.assertEqual(classify_http(status=status)["state"], "unknown")

    def test_no_secret_strings_escape_and_objects_are_not_stringified(self):
        class Secret:
            def __str__(self):
                raise AssertionError("must not stringify untrusted objects")
        result = classify_http(403, headers={"Authorization": Secret(), "Cookie": "secret-fixture-cookie"},
                               body=json.dumps({"messages": ["secret-fixture-body"]}), error=Secret())
        self.assertNotIn("secret-fixture", json.dumps(result))
        self.assertEqual(result["reason_codes"], ["http_forbidden_unknown"])


class LogDiagnosticsTests(unittest.TestCase):
    def test_prose_fixed_codes_and_403_are_distinct(self):
        result = inspect_log_diagnostics(b"[main] region_unavailable\npermission_error\ncf-mitigated: challenge\n"
                                        b"account_banned\nHTTP 403 Forbidden\nHTTP 500\nETIMEDOUT\nECONNREFUSED\n")
        for key in ("region_denied", "permission_denied", "edge_challenge", "account_banned",
                    "http_forbidden_unknown", "http_error", "network_timeout", "network_error"):
            self.assertEqual(result["diagnostics"][key], 1)

    def test_prefixed_network_error_tokens_are_recognized(self):
        result = inspect_log_diagnostics(b"[main] request failed: ETIMEDOUT\n[main] fetch failed: ECONNRESET\n")
        self.assertEqual(result["diagnostics"]["network_timeout"], 1)
        self.assertEqual(result["diagnostics"]["network_error"], 1)

    def test_one_line_counts_each_category_at_most_once(self):
        result = inspect_log_diagnostics(b"region_blocked region_unavailable region_blocked HTTP 403\n")
        self.assertEqual(result["diagnostics"]["region_denied"], 1)
        self.assertEqual(result["diagnostics"]["http_forbidden_unknown"], 0)

    def test_permissions_and_explicit_ip_message_are_separate(self):
        result = inspect_log_diagnostics(b"permission_error: Your IP address is not allowed\n")
        self.assertEqual(result["reason_codes"], ["permission_denied", "ip_restricted"])

    def test_bad_device_id_does_not_become_ban_in_new_diagnostics(self):
        result = inspect_log_diagnostics(b"bad_device_id HTTP 403\n")
        self.assertEqual(result["diagnostics"]["account_banned"], 0)
        self.assertEqual(result["diagnostics"]["http_forbidden_unknown"], 1)

    def test_structured_http_and_error_envelopes(self):
        lines = [{"response": {"status": 403, "headers": {"cf-mitigated": "challenge"}}},
                 {"status": 403, "error": {"type": "permission_error", "message": "IP is not allowed"}},
                 {"error_code": "account_banned"}]
        result = inspect_log_diagnostics("\n".join(json.dumps(value) for value in lines).encode())
        for key in ("edge_challenge", "permission_denied", "ip_restricted", "account_banned"):
            self.assertEqual(result["diagnostics"][key], 1)
        self.assertEqual(result["diagnostics"]["http_forbidden_unknown"], 0)

    def test_json_chat_and_arbitrary_nested_data_are_ignored(self):
        obj = {"message": "account_banned region_unavailable HTTP 403", "content": {"code": "account_banned"},
               "request": {"error": {"type": "region_blocked"}}, "messages": [{"code": "permission_error"}]}
        result = inspect_log_diagnostics(json.dumps(obj).encode())
        self.assertFalse(result["reason_codes"])

    def test_token_boundaries_do_not_match_unrelated_identifiers(self):
        self.assertFalse(inspect_log_diagnostics(b"not_region_blocked_fixture account_banned_example\n")["reason_codes"])

    def test_negative_region_flags_do_not_become_explicit_denials(self):
        for name in ("is_country_restricted", "signups_disabled_in_region"):
            for value in ("false", "0"):
                with self.subTest(name=name, value=value):
                    self.assertFalse(inspect_log_diagnostics(f"{name}={value}".encode())["reason_codes"])
                    obj = {name: False if value == "false" else 0}
                    self.assertFalse(inspect_log_diagnostics(json.dumps(obj).encode())["reason_codes"])
            for value in ("true", "1"):
                self.assertEqual(inspect_log_diagnostics(f"{name}={value}".encode())["reason_codes"], ["region_denied"])
                obj = {name: True if value == "true" else 1}
                self.assertEqual(inspect_log_diagnostics(json.dumps(obj).encode())["reason_codes"], ["region_denied"])

    def test_other_explicit_negative_flags_do_not_become_service_errors(self):
        for line in (b"account_banned=false", b"region_blocked=0", b"ip_restricted: false"):
            self.assertFalse(inspect_log_diagnostics(line)["reason_codes"])

    def test_legal_unicode_line_separators_inside_json_are_not_log_boundaries(self):
        obj = {"message": "fixture\u2028account_banned\u2029region_unavailable"}
        result = inspect_log_diagnostics(json.dumps(obj, ensure_ascii=False).encode())
        self.assertEqual(result["state"], "observed")
        self.assertFalse(result["reason_codes"])

    def test_bounds_malformed_utf8_and_duplicate_keys_are_fixed_unknown(self):
        for raw in (b"x" * (MAX_LOG_BYTES + 1), b"\xff", b'{"error_code":"account_banned","error_code":"other"}'):
            result = inspect_log_diagnostics(raw)
            self.assertEqual(result["state"], "unknown")
            self.assertFalse(result["reason_codes"])
        result = inspect_log_diagnostics(b"ordinary\n" * (MAX_LOG_LINES + 1))
        self.assertTrue(result["limited"])

    def test_original_seven_counters_are_not_changed_by_this_module(self):
        import artifact_policy
        result = artifact_policy.inspect_log_chunk(b"bad_device_id\nregion_unavailable\n")
        self.assertEqual(tuple(result["counters"]), ("region", "banned", "evicted", "telemetry", "device", "stripe", "network"))
        self.assertEqual(result["counters"]["banned"], 1)

    def test_diagnostic_outputs_never_contain_log_lines(self):
        raw = b"account_banned account=secret-fixture-account token=secret-fixture-token\n"
        result = inspect_log_diagnostics(raw)
        self.assertNotIn("secret-fixture", json.dumps(result))
        self.assertEqual(result["diagnostics"]["account_banned"], 1)


if __name__ == "__main__":
    unittest.main()

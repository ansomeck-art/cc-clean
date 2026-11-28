"""Pure, bounded service-error classifications; no raw text leaves this module.

These are advisory observations of explicit error codes, not evidence of account
nationality or an instruction to terminate a process. Callers supply only already
available local log bytes or their ordinary public, credential-free HTTP probes.
"""
import json
import re
from urllib.parse import urlsplit


DIAGNOSTIC_KEYS = ("region_denied", "permission_denied", "ip_restricted", "edge_challenge",
                   "account_banned", "network_timeout", "network_error", "http_forbidden_unknown", "http_error")
DIAGNOSTIC_LABELS = dict(region_denied="明确地区拒绝", permission_denied="权限拒绝", ip_restricted="IP 访问限制",
                        edge_challenge="边缘挑战", account_banned="明确封禁代码", network_timeout="网络超时",
                        network_error="网络连接失败", http_forbidden_unknown="403 原因未明", http_error="其他 HTTP 错误")
MAX_BODY_BYTES = 64 * 1024
MAX_LOG_BYTES = 512 * 1024
MAX_LOG_LINES = 8192
MAX_HEADER_COUNT = 64
_CODE_MAP = {
    "region_blocked": "region_denied", "region_unavailable": "region_denied",
    "app-unavailable-in-region": "region_denied", "is_country_restricted": "region_denied",
    "signups_disabled_in_region": "region_denied", "unsupported_country": "region_denied",
    "country_not_supported": "region_denied", "permission_error": "permission_denied",
    "permission_denied": "permission_denied", "ip_not_allowed": "ip_restricted",
    "ip_address_not_allowed": "ip_restricted", "ip_restricted": "ip_restricted",
    "ip_not_in_allowed_range": "ip_restricted", "tenant_restriction_violation": "permission_denied",
    "account_banned": "account_banned",
}
_TIMEOUT_CODES = frozenset(("etimedout", "err_timed_out", "timeout", "request_timeout", "connect_timeout"))
_NETWORK_CODES = frozenset(("econnreset", "econnrefused", "econnaborted", "enotfound", "eai_again",
                            "err_connection_reset", "err_connection_refused", "err_name_not_resolved",
                            "err_network_changed", "err_network_io_suspended", "enetunreach", "ehostunreach", "network_error"))
_TIMEOUT_MARKER = re.compile(r"(?<![a-z0-9_])(?:" + "|".join(re.escape(code) for code in _TIMEOUT_CODES) +
                             r")(?![a-z0-9_])", re.I)
_NETWORK_MARKER = re.compile(r"(?<![a-z0-9_])(?:" + "|".join(re.escape(code) for code in _NETWORK_CODES) +
                             r")(?![a-z0-9_])", re.I)
_MARKERS = re.compile(r"(?<![a-z0-9_])(" + "|".join(re.escape(key) for key in
                       sorted(set(_CODE_MAP) - {"is_country_restricted", "signups_disabled_in_region"},
                              key=len, reverse=True)) + r")(?![a-z0-9_])", re.I)
_REGION_FLAG = re.compile(r"(?<![a-z0-9_])(?:is_country_restricted|signups_disabled_in_region)"
                          r"[\s\"']*[:=][\s\"']*(?:true|1)(?![a-z0-9_])", re.I)
_CHALLENGE = re.compile(r"\bcf-mitigated\b[\s\"']*[:=][\s\"']*challenge\b", re.I)
_IP_DENIED = re.compile(r"\b(?:your\s+)?ip(?:\s+address)?\s+(?:(?:is|was|has\s+been)\s+)?"
                        r"(?:not\s+(?:allowed|permitted|authorized)|(?:explicitly\s+)?(?:denied|blocked))\b", re.I)
_HTTP_STATUS = re.compile(r"\b(?:HTTP(?:/\d(?:\.\d)?)?\s*|status(?:[ _-]*code)?[\s:=]*)([45]\d{2})\b|"
                          r"\b(403)\s+Forbidden\b", re.I)


def empty_diagnostics():
    return dict.fromkeys(DIAGNOSTIC_KEYS, 0)


def _result(codes=(), *, limited=False, valid=True, counters=None):
    diagnostics = empty_diagnostics() if counters is None else dict(counters)
    for code in codes:
        if code in diagnostics:
            diagnostics[code] = 1
    return dict(state="observed" if valid else "unknown",
                reason_codes=[key for key in DIAGNOSTIC_KEYS if diagnostics[key]],
                diagnostics=diagnostics, limited=bool(limited))


def _text(raw, limit):
    if type(raw) is str:
        if len(raw) > limit or len(raw.encode("utf-8")) > limit:
            raise ValueError("input bound")
        return raw
    if type(raw) in (bytes, bytearray) and len(raw) <= limit:
        return bytes(raw).decode("utf-8")
    raise ValueError("unsupported input")


def _pairs(items):
    result = {}
    for name, value in items:
        if name in result:
            raise ValueError("ambiguous JSON")
        result[name] = value
    return result


def _constant(_value):
    raise ValueError("invalid JSON constant")


def _json(text):
    depth = tokens = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char in "{[":
            depth += 1
            tokens += 1
        elif char in "}]":
            depth -= 1
        elif char in ",:":
            tokens += 1
        if depth > 32 or tokens > 10000:
            raise ValueError("JSON structure bound")
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)


def _code(value):
    return value.strip().lower() if type(value) is str and len(value) <= 128 else ""


def _headers(headers):
    if headers is None:
        return {}, False
    if type(headers) in (str, bytes, bytearray):
        try:
            text = _text(headers, 16 * 1024).replace("\r\n", "\n")
        except (ValueError, UnicodeError):
            return {}, True
        blocks = [block for block in text.split("\n\n") if block.strip()]
        http_blocks = [block for block in blocks if re.match(r"^HTTP/\S+\s+\d{3}\b", block.lstrip(), re.I)]
        block = http_blocks[-1] if http_blocks else text
        pairs = []
        for line in block.split("\n"):
            if ":" in line:
                name, value = line.split(":", 1)
                pairs.append((name.strip(), value.strip()))
        headers = pairs
    if type(headers) is dict:
        pairs = headers.items()
    elif type(headers) in (list, tuple):
        pairs = headers
    else:
        return {}, True
    result, limited = {}, len(headers) > MAX_HEADER_COUNT
    for index, pair in enumerate(pairs):
        if index >= MAX_HEADER_COUNT:
            break
        if type(pair) not in (tuple, list) or len(pair) != 2:
            limited = True
            continue
        name, value = pair
        if type(name) is not str or len(name) > 128:
            limited = True
            continue
        name = name.lower()
        if name not in ("x-claude-error-code", "cf-mitigated", "location"):
            continue  # never inspect or stringify cookies/authorization headers
        if type(value) is not str or len(value) > (2048 if name == "location" else 256):
            limited = True
            continue
        result.setdefault(name, []).append(value.strip() if name == "location" else value.strip().lower())
    return result, limited


def _region_location(value, request_url):
    try:
        location = urlsplit(value)
        if location.path != "/app-unavailable-in-region" or location.fragment:
            return False
        if not location.scheme and not location.netloc:
            return value.startswith("/") and not value.startswith("//")
        if type(request_url) is not str or len(request_url) > 4096:
            return False
        request = urlsplit(request_url)
        def origin(parts):
            if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
                return None
            return (parts.scheme, parts.hostname.lower(), parts.port or (443 if parts.scheme == "https" else 80))
        return origin(location) is not None and origin(location) == origin(request)
    except (ValueError, TypeError, AttributeError):
        return False


def _codes_from_object(obj):
    """Only named service-error fields; never recurse into prompts/messages/content."""
    codes = set()
    if type(obj) is not dict:
        return codes
    containers = [obj]
    if type(obj.get("error")) is dict:
        containers.append(obj["error"])
        if type(obj["error"].get("details")) is dict:
            containers.append(obj["error"]["details"])
    elif type(obj.get("error")) is str:
        value = _code(obj["error"])
        if value in _CODE_MAP:
            codes.add(_CODE_MAP[value])
    for container in containers:
        if any(container.get(name) is True or type(container.get(name)) is int and container[name] == 1
               for name in ("is_country_restricted", "signups_disabled_in_region")):
            codes.add("region_denied")
        for name in ("type", "code", "error_code"):
            value = _code(container.get(name))
            if value in _CODE_MAP:
                codes.add(_CODE_MAP[value])
            elif value in _TIMEOUT_CODES:
                codes.add("network_timeout")
            elif value in _NETWORK_CODES:
                codes.add("network_error")
        message = container.get("message")
        # Only an error object or a service-error envelope can supply a permission
        # message; a generic JSON chat/message string is not a service refusal.
        service_error = (container is not obj or "permission_denied" in codes or
                         _code(container.get("type")) == "error")
        if service_error and type(message) is str and len(message) <= MAX_BODY_BYTES and _IP_DENIED.search(message):
            codes.add("ip_restricted")
    return codes


def _network(error):
    codes = set()
    if error is None:
        return codes, False
    if type(error) is dict:
        for name in ("code", "type"):
            value = _code(error.get(name))
            if value in _TIMEOUT_CODES:
                codes.add("network_timeout")
            elif value in _NETWORK_CODES:
                codes.add("network_error")
        error = error.get("message", "")
    try:
        text = _text(error, 4096).strip().lower()
    except (ValueError, UnicodeError):
        return codes, True
    if _TIMEOUT_MARKER.search(text) or re.search(r"\btimed?\s*out\b|\btimeout\b|\bcurl(?:\s+error)?[\s:(]*28\b", text):
        codes.add("network_timeout")
    elif (_NETWORK_MARKER.search(text) or any(value in text for value in
          ("connection refused", "connection reset", "could not resolve host", "failed to connect",
           "network is unreachable", "name or service not known", "tls handshake failed"))):
        codes.add("network_error")
    return codes, False


def classify_http(status=None, headers=None, body=None, error=None, request_url=None):
    """Classify an already available HTTP result, without requests or credentials.

    A bare 403 is always ``http_forbidden_unknown``. ``permission_error`` does
    not establish a region block or account ban. Only explicit ``account_banned``
    identifies that diagnostic; ``bad_device_id`` is deliberately insufficient.
    """
    valid_status = status is None or type(status) is int and 100 <= status <= 599
    if not valid_status:
        status = None
    codes, limited = _network(error)
    values, header_limited = _headers(headers)
    limited |= header_limited
    for value in values.get("x-claude-error-code", []):
        if value in _CODE_MAP:
            codes.add(_CODE_MAP[value])
    if "challenge" in values.get("cf-mitigated", []):
        codes.add("edge_challenge")
    if status in (301, 302, 303, 307, 308) and any(_region_location(value, request_url) for value in values.get("location", [])):
        codes.add("region_denied")
    if body is not None:
        try:
            text = _text(body, MAX_BODY_BYTES).strip()
            if text.startswith("{"):
                codes.update(_codes_from_object(_json(text)))
            elif _code(text) in _CODE_MAP:
                codes.add(_CODE_MAP[_code(text)])
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
            limited = True
    if status in (408, 504):
        codes.add("network_timeout")
    if not codes and status is not None and status >= 400:
        codes.add("http_forbidden_unknown" if status == 403 else "http_error")
    return _result(codes, limited=limited, valid=valid_status and (bool(codes) or not limited))


def _structured_log(obj):
    codes = _codes_from_object(obj)
    envelopes = [obj]
    if type(obj.get("response")) is dict:
        envelopes.append(obj["response"])
    for envelope in envelopes:
        status = next((envelope[key] for key in ("status", "status_code", "http_status")
                       if type(envelope.get(key)) is int), None)
        body = {key: envelope[key] for key in ("error", "error_code", "code", "type") if key in envelope}
        response = classify_http(status=status, headers=envelope.get("headers"), body=json.dumps(body))
        codes.update(response["reason_codes"])
    if any(code not in ("http_forbidden_unknown", "http_error") for code in codes):
        codes.difference_update(("http_forbidden_unknown", "http_error"))
    return codes


def inspect_log_diagnostics(raw):
    """Return fixed advisory counts for bounded, already-read local log bytes.

    The existing seven artifact counters remain independent and unchanged. Each
    line counts at most once in each diagnostic. JSON user-content containers are
    ignored; prose recognizes fixed error tokens and explicit HTTP status syntax.
    """
    counters = empty_diagnostics()
    try:
        text = _text(raw, MAX_LOG_BYTES)
    except (ValueError, UnicodeError):
        return _result(valid=False, limited=True)
    limited, malformed = False, False
    for index, line in enumerate(text.split("\n")):
        if index >= MAX_LOG_LINES:
            limited = True
            break
        if len(line.encode("utf-8")) > MAX_BODY_BYTES:
            limited = True
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{"):
            try:
                obj = _json(stripped)
                codes = _structured_log(obj) if type(obj) is dict else set()
            except (ValueError, TypeError, AttributeError, RecursionError, OverflowError):
                malformed = True
                continue
        else:
            codes = {_CODE_MAP[match.group(1).lower()] for match in _MARKERS.finditer(line)
                     if not re.match(r"[\s\"']*[:=][\s\"']*(?:false|0)(?![a-z0-9_])", line[match.end():], re.I)}
            if _REGION_FLAG.search(line):
                codes.add("region_denied")
            if _CHALLENGE.search(line):
                codes.add("edge_challenge")
            if _IP_DENIED.search(line):
                codes.add("ip_restricted")
            network_codes, _ = _network(line)
            codes.update(network_codes)
            if _TIMEOUT_MARKER.search(line):
                codes.add("network_timeout")
            if _NETWORK_MARKER.search(line):
                codes.add("network_error")
            status_match = _HTTP_STATUS.search(line)
            if not codes and status_match:
                status = int(status_match.group(1) or status_match.group(2))
                codes.add("http_forbidden_unknown" if status == 403 else
                          "network_timeout" if status in (408, 504) else "http_error")
        for code in codes:
            if code in counters:
                counters[code] += 1
    return _result(counters=counters, limited=limited, valid=not malformed and not limited)

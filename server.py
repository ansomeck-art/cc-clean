#!/usr/bin/env python3
"""
Region Guard — Local Cross-Platform (Windows / macOS) Region, Network Leak & Risk Audit Web Server.

Pure Python 3.9+ standard library backend bound strictly to 127.0.0.1.
Audits remain read-only; explicitly enabled macOS protection can terminate verified Claude Desktop processes;
never reads or exposes secrets, tokens, passwords, or cookie values.
"""

import argparse
import collections
import concurrent.futures
import datetime
import email.utils
import errno
import http.server
import ipaddress
import json
import locale
import os
import platform
import plistlib
import re
import shlex
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zlib
import mac_platform
from proxy_runtime import PaymentRouteObserver, payment_route_check
from readonly_telemetry import ReadonlyTelemetryService, telemetry_filter_check
from service_diagnostics import DIAGNOSTIC_KEYS, DIAGNOSTIC_LABELS, classify_http
from client_version import ClaudeVersionObserver
from traffic_watch import ClaudeTrafficWatch
from native_connections import native_backend_available
from protection import FastProtector
from audit_common import count_log_tail, safe_parse_clash_yaml, safe_parse_surge_conf, inspect_telemetry
from typing import Any, Deque, Dict, List, Optional, Tuple

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")
PLATFORM_KEY = "windows" if IS_WINDOWS else ("macos" if IS_MACOS else "linux")
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

if IS_WINDOWS:
    import ctypes
    import win_platform  # type: ignore
else:
    ctypes = None  # type: ignore
    win_platform = None  # type: ignore


def _detect_platform_label() -> str:
    arch = platform.machine() or ""
    if IS_WINDOWS:
        rel = platform.release() or ""
        try:
            ver_parts = platform.version().split(".")
            build = int(ver_parts[2]) if len(ver_parts) >= 3 else 0
            if rel == "10" and build >= 22000:
                rel = "11"
        except Exception:
            pass
        return f"Windows {rel} ({arch})".strip()
    if IS_MACOS:
        mac_ver = platform.mac_ver()[0] or ""
        return f"macOS {mac_ver} ({arch})".strip()
    return f"{platform.system()} ({arch})".strip()


PLATFORM_LABEL = _detect_platform_label()


def _resolve_curl_bin() -> str:
    if IS_WINDOWS:
        sys32_curl = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "curl.exe")
        if os.path.isfile(sys32_curl):
            return sys32_curl
        return shutil.which("curl.exe") or shutil.which("curl") or "curl.exe"
    if IS_MACOS and os.path.isfile("/usr/bin/curl"):
        return "/usr/bin/curl"
    return shutil.which("curl") or "/usr/bin/curl"


CURL_BIN = _resolve_curl_bin()
WHOIS_BIN = ("/usr/bin/whois" if IS_MACOS and os.path.isfile("/usr/bin/whois") else (shutil.which("whois") or ""))


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESOURCE_DIR = getattr(sys, "_MEIPASS", BASE_DIR)
RUNTIME_DIR = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else BASE_DIR


def _resolve_user_data_dir() -> str:
    if IS_MACOS:
        path = os.path.expanduser("~/Library/Application Support/RegionGuard")
    elif IS_WINDOWS:
        path = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "RegionGuard")
    else:
        path = os.path.expanduser("~/.local/share/region-guard")
    override = os.environ.get("REGIONGUARD_DATA_DIR")
    if override:
        path = os.path.abspath(override)
        name = os.path.basename(path)
        if (not os.path.isabs(override) or not (name == "RegionGuard" or name.startswith("regionguard-test-"))
                or ".app/" in (os.path.realpath(path) + "/").lower() or os.path.islink(path)):
            raise ValueError("invalid private RegionGuard data directory")
    uid = str(os.getuid()) if hasattr(os, "getuid") else str(os.getpid())
    fallback = os.path.join(tempfile.gettempdir(), "region-guard-" + uid)
    for candidate in ((path,) if override else (path, fallback)):
        try:
            if ".app/" in os.path.realpath(candidate) + "/" or os.path.islink(candidate):
                continue
            os.makedirs(candidate, mode=0o700, exist_ok=True)
            if not IS_WINDOWS:
                if os.stat(candidate).st_uid != os.getuid():
                    continue
                os.chmod(candidate, 0o700)
            return candidate
        except OSError:
            continue
    raise RuntimeError("无法创建 RegionGuard 私有运行目录")


USER_DATA_DIR = _resolve_user_data_dir()
TELEMETRY_SERVICE = ReadonlyTelemetryService(USER_DATA_DIR)
CLIENT_VERSION = ClaudeVersionObserver(USER_DATA_DIR)
CLAUDE_TRAFFIC = ClaudeTrafficWatch(interval_ms=500)
STATIC_DIR = os.path.join(RESOURCE_DIR, "static")
ALLOWED_STATIC = {
    "index.html": "text/html; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
    "fingerprint-checks.js": "application/javascript; charset=utf-8",
    "locale-checks.js": "application/javascript; charset=utf-8",
}

RESTRICTED_COUNTRIES = {"CN", "HK", "MO", "RU", "BY", "KP", "IR", "CU", "SY"}
RESTRICTED_COLOS = {
    "HKG", "MFM", "PVG", "PEK", "CAN", "SZX", "CTU", "SHA", "WUH", "TSN",
    "CKG", "NKG", "XIY", "HGH", "FOC", "KMG", "TAO", "DLC", "SHE", "HRB",
    "CGO", "CSX", "TNA", "SYX", "HAK", "URC", "LHW", "TYN", "HET", "INC",
    "XMN", "DME", "SVO", "LED", "MSQ", "THR",
}
HOSTING_ASN_KEYWORDS = (
    "SHARED-USE", "HOSTING", "CLOUD", "DATACENTER", "DATA CENTER", "SERVER",
    "COLOCATION", "VPS", "VPN", "PROXY", "DIGITALOCEAN", "VULTR", "LINODE",
    "AKAMAI", "OVH", "HETZNER", "AMAZON", "AWS", "GOOGLE", "MICROSOFT",
    "AZURE", "ORACLE", "ALIBABA", "TENCENT", "HUAWEI", "BYTEDANCE", "VOLCENGINE",
    "BAIDU", "UCLOUD", "KINGSOFT", "CLOUDFLARE", "FASTLY", "CONTABO", "CHOOPA",
    "LEASEWEB", "M247", "DATACAMP", "PACKETHUB", "ZENLAYER", "DMIT", "BANDWAGON",
    "IT7", "RACKNERD", "CLAWCLOUD", "NETCUP", "SCALEWAY", "UPCLOUD", "KAMATERA",
    "IONOS", "GODADDY", "BLUEHOST", "CDN77", "G-CORE", "GCORE", "XTOM", "MISAKA",
    "AKARI", "HYTRON", "BAGE", "NEAROUTE", "EONS", "COGENT", "HURRICANE",
    "MULLVAD", "NORDVPN", "SURFSHARK", "EXPRESSVPN", "PROTON", "CYBERGHOST",
)
RDNS_HOSTING_KEYWORDS = (
    "vps", "cloud", "server", "hosting", "datacenter", "proxy", "vpn", "exit",
    "vultr", "linode", "amazonaws", "googleusercontent", "contaboserver",
    "racknerd", "dmit", "hetzner", "ovh.", "digitalocean", "scaleway", "m247",
)
RESTRICTED_TIMEZONES = {
    "Asia/Shanghai",
    "Asia/Chongqing",
    "Asia/Harbin",
    "Asia/Urumqi",
    "Asia/Kashgar",
    "Asia/Hong_Kong",
    "Asia/Macau",
    "PRC",
    "Hongkong",
}
CLAUDE_RISK_DOMAINS = (
    "claude.ai",
    "claude.com",
    "anthropic.com",
    "claudeusercontent.com",
    "claudemcpcontent.com",
    "hcaptcha.com",
    "stripe.com",
    "stripe.network",
    "assets.claude.ai", "bridge.claudeusercontent.com", "config.claude.com",
    "pivot.claude.ai", "browser-intake-us5-datadoghq.com", "sentry.io", "statsig.com",
)
CN_DNS_SERVERS = {
    "114.114.114.114",
    "114.114.115.115",
    "223.5.5.5",
    "223.6.6.6",
    "119.29.29.29",
    "182.254.116.116",
    "180.76.76.76",
    "1.2.4.8",
    "2400:3200::1",
    "2400:3200:baba::1",
    "240c::6666",
    "240c::6644",
}

TARGETS: Dict[str, Dict[str, Any]] = {
    "SG": {
        "code": "SG",
        "name": "新加坡 (Singapore)",
        "keywords": ["singapore"],
        "timezones": ["Asia/Singapore"],
        "utc_offsets_sec": [28800],
        "js_offset_mins": [-480],
        "expected_colos": ["SIN"],
        "locales": ["en_SG", "en-SG", "en-US", "en_US"],
    },
    "US": {
        "code": "US",
        "name": "美国 (United States)",
        "keywords": ["united states", "usa"],
        "timezones": [
            "America/Los_Angeles",
            "America/New_York",
            "America/Chicago",
            "America/Denver",
            "America/Phoenix",
            "Pacific/Honolulu",
        ],
        "utc_offsets_sec": [-28800, -25200, -21600, -18000, -14400, -36000],
        "js_offset_mins": [480, 420, 360, 300, 240, 600],
        "expected_colos": ["SJC", "LAX", "SEA", "ORD", "DFW", "IAD", "EWR", "MIA", "ATL", "DEN"],
        "locales": ["en_US", "en-US"],
    },
    "JP": {
        "code": "JP",
        "name": "日本 (Japan)",
        "keywords": ["japan"],
        "timezones": ["Asia/Tokyo"],
        "utc_offsets_sec": [32400],
        "js_offset_mins": [-540],
        "expected_colos": ["NRT", "HND", "KIX"],
        "locales": ["ja_JP", "ja-JP", "en_JP", "en-US", "en_US"],
    },
    "GB": {
        "code": "GB",
        "name": "英国 (United Kingdom)",
        "keywords": ["united kingdom", "britain", "england"],
        "timezones": ["Europe/London"],
        "utc_offsets_sec": [0, 3600],
        "js_offset_mins": [0, -60],
        "expected_colos": ["LHR", "MAN"],
        "locales": ["en_GB", "en-GB", "en-US", "en_US"],
    },
    "TW": {
        "code": "TW",
        "name": "台湾 (Taiwan)",
        "keywords": ["taiwan"],
        "timezones": ["Asia/Taipei"],
        "utc_offsets_sec": [28800],
        "js_offset_mins": [-480],
        "expected_colos": ["TPE", "KHH"],
        "locales": ["zh_TW", "zh-TW", "zh-Hant", "en_TW", "en-US"],
    },
    "AU": {
        "code": "AU",
        "name": "澳大利亚 (Australia)",
        "keywords": ["australia"],
        "timezones": ["Australia/Sydney", "Australia/Melbourne", "Australia/Brisbane", "Australia/Perth"],
        "utc_offsets_sec": [36000, 39600, 34200, 28800],
        "js_offset_mins": [-600, -660, -570, -480],
        "expected_colos": ["SYD", "MEL", "BNE", "PER"],
        "locales": ["en_AU", "en-AU", "en-US", "en_US"],
    },
    "CA": {
        "code": "CA",
        "name": "加拿大 (Canada)",
        "keywords": ["canada"],
        "timezones": ["America/Toronto", "America/Vancouver", "America/Edmonton", "America/Montreal"],
        "utc_offsets_sec": [-28800, -25200, -21600, -18000, -14400],
        "js_offset_mins": [480, 420, 360, 300, 240],
        "expected_colos": ["YYZ", "YVR", "YUL", "YYC"],
        "locales": ["en_CA", "en-CA", "fr_CA", "fr-CA", "en-US"],
    },
    "DE": {
        "code": "DE",
        "name": "德国 (Germany)",
        "keywords": ["germany"],
        "timezones": ["Europe/Berlin"],
        "utc_offsets_sec": [3600, 7200],
        "js_offset_mins": [-60, -120],
        "expected_colos": ["FRA", "MUC", "DUS", "TXL"],
        "locales": ["de_DE", "de-DE", "en_DE", "en-US", "en_US"],
    },
}


PULSE_LOG_PATH = os.path.join(USER_DATA_DIR, "pulse-events.jsonl")
PREFS_PATH = os.path.join(USER_DATA_DIR, "prefs.json")
RUNTIME_INFO_PATH = os.path.join(USER_DATA_DIR, "runtime.json")
LOCK_FILE_PATH = os.path.join(USER_DATA_DIR, "instance.lock")
SHUTDOWN_EVENT = threading.Event()
_COMMAND_LOCK = threading.Lock()
_ACTIVE_COMMANDS = set()
HISTORY_LOCK = threading.Lock()
PULSE_HISTORY: Deque[Dict[str, Any]] = collections.deque(maxlen=500)
BASELINE_IP: Optional[str] = None


def now_iso() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def _decode_cmd_bytes(raw: bytes) -> str:
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if IS_WINDOWS and ctypes is not None:
        try:
            cp = ctypes.windll.kernel32.GetOEMCP()
            if cp:
                return raw.decode(f"cp{cp}", errors="replace")
        except Exception:
            pass
    enc = locale.getpreferredencoding(False) or "utf-8"
    return raw.decode(enc, errors="replace")


def shutdown_observers():
    """Stop only subprocesses launched by RegionGuard; never other applications."""
    SHUTDOWN_EVENT.set()
    TELEMETRY_SERVICE.stop()
    CLAUDE_TRAFFIC.stop()
    with _COMMAND_LOCK:
        commands = tuple(_ACTIVE_COMMANDS)
    for command in commands:
        try:
            command.terminate()
        except OSError:
            pass


def run_cmd(cmd: List[str], timeout: int = 8, env=None) -> Tuple[int, str, str]:
    command = None
    if SHUTDOWN_EVENT.is_set():
        return 124, "", "RegionGuard closing"
    try:
        if env is None and cmd and os.path.basename(cmd[0]).lower() in {"curl", "curl.exe"}:
            env = {k: v for k, v in os.environ.items() if k.lower() not in
                   {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
        kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        if IS_WINDOWS:
            kwargs["creationflags"] = CREATE_NO_WINDOW
        command = subprocess.Popen(cmd, **kwargs)
        with _COMMAND_LOCK:
            _ACTIVE_COMMANDS.add(command)
            if SHUTDOWN_EVENT.is_set():
                command.terminate()
        try:
            stdout, stderr = command.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            command.kill()
            command.communicate()
            return 124, "", "timeout"
        return command.returncode, _decode_cmd_bytes(stdout), _decode_cmd_bytes(stderr)
    except Exception:
        return 1, "", "command unavailable"
    finally:
        if command is not None:
            with _COMMAND_LOCK:
                _ACTIVE_COMMANDS.discard(command)



def _curl_base_cmd(timeout: int) -> List[str]:
    cmd = [CURL_BIN, "-q", "-sS", "--max-time", str(timeout)]
    if IS_WINDOWS:
        # Avoid Windows Schannel online CRL/OCSP revocation stalls behind proxies (keeps full TLS cert verification)
        cmd.append("--ssl-no-revoke")
    return cmd


def _network_env():
    return {k: v for k, v in os.environ.items() if k.lower() not in
            {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}


def curl_fetch(
    url: str,
    timeout: int = 6,
    ipv6_only: bool = False,
    head_only: bool = False,
) -> Tuple[bool, str, float, str]:
    """Run system curl to match OS network & TLS trust stack (macOS SecureTransport / Windows Schannel)."""
    cmd = _curl_base_cmd(timeout) + ["-L"]
    if ipv6_only:
        cmd.append("-6")
    if head_only:
        cmd.append("-I")
    cmd.append(url)
    t0 = time.monotonic()
    rc, out, err = run_cmd(cmd, timeout=timeout + 2, env=_network_env())
    ms = round((time.monotonic() - t0) * 1000.0, 1)
    if rc != 0:
        return False, "", ms, (err.strip() or f"curl exit {rc}")
    return True, out, ms, ""


def curl_json(url: str, timeout: int = 6) -> Tuple[bool, Any, float, str]:
    ok, body, ms, err = curl_fetch(url, timeout=timeout)
    if not ok:
        return False, None, ms, err
    try:
        return True, json.loads(body), ms, ""
    except Exception as exc:
        return False, None, ms, f"json error: {exc}"


def parse_cf_trace(body: str) -> Dict[str, str]:
    res: Dict[str, str] = {}
    for line in body.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            res[k.strip()] = v.strip()
    return res


def has_cjk(text: str) -> bool:
    return any("\u4e00" <= ch <= "\u9fff" for ch in text)


def has_non_ascii(text: str) -> bool:
    return any(ord(ch) > 127 for ch in text)


def make_check(
    cid: str,
    title: str,
    status: str,
    observed: str,
    detail: str,
    fix_advice: str = "",
    fix_cmd: str = "",
    severity: str = "auto",
) -> Dict[str, str]:
    if severity == "auto":
        sev = "high" if status == "FAIL" else "low"
    else:
        sev = severity
    return {
        "id": cid,
        "title": title,
        "status": status,
        "severity": sev,
        "observed": observed,
        "detail": detail,
        "fix_advice": fix_advice,
        "fix_cmd": fix_cmd,
    }


def _check_utun_status() -> Tuple[bool, List[str], List[str], List[str]]:
    details = mac_platform.mac_check_tun_details(run_cmd)
    return details["tun_up"], details["tun_ips"], details["default_routes"], details["global_v6"]


def _check_macos_ipv6_disabled() -> Dict[str, Any]:
    return mac_platform.check_ipv6_disabled(run_cmd)


# ---------------------------------------------------------------------------
# Category 1: Egress IP, Multi-DB GeoIP & WHOIS/BGP Reputation
# ---------------------------------------------------------------------------
def _query_geoip_ipinfo(ip: str = "") -> Dict[str, Any]:
    url = f"https://ipinfo.io/{urllib.parse.quote(ip)}/json" if ip else "https://ipinfo.io/json"
    ok, data, ms, err = curl_json(url, timeout=6)
    if not ok or not isinstance(data, dict):
        return {"source": "IPinfo", "status": "ERR", "error": err, "latency_ms": ms}
    return {
        "source": "IPinfo",
        "ip": data.get("ip", ip),
        "country": data.get("country", ""),
        "city": data.get("city", ""),
        "region": data.get("region", ""),
        "timezone": data.get("timezone", ""),
        "org": data.get("org", ""),
        "proxy": None,
        "latency_ms": ms,
        "status": "OK",
    }


def _query_geoip_ipapi(ip: str = "") -> Dict[str, Any]:
    target_seg = urllib.parse.quote(ip) if ip else ""
    url = (
        f"http://ip-api.com/json/{target_seg}?fields=status,country,countryCode,"
        "regionName,city,timezone,isp,org,as,hosting,proxy,mobile,query"
    )
    ok, data, ms, err = curl_json(url, timeout=6)
    if not ok or not isinstance(data, dict) or data.get("status") != "success":
        return {"source": "ip-api.com", "status": "ERR", "error": err or "failed", "latency_ms": ms}
    return {
        "source": "ip-api.com",
        "ip": data.get("query", ip),
        "country": data.get("countryCode", ""),
        "city": data.get("city", ""),
        "region": data.get("regionName", ""),
        "timezone": data.get("timezone", ""),
        "org": f"{data.get('as', '')} / {data.get('org', '')}".strip(" /"),
        "proxy": bool(data.get("proxy") or data.get("hosting")),
        "hosting": data.get("hosting"),
        "mobile": data.get("mobile"),
        "latency_ms": ms,
        "status": "OK",
    }


def _query_geoip_ifconfig() -> Dict[str, Any]:
    ok, data, ms, err = curl_json("https://ifconfig.co/json", timeout=6)
    if not ok or not isinstance(data, dict):
        return {"source": "ifconfig.co", "status": "ERR", "error": err, "latency_ms": ms}
    return {
        "source": "ifconfig.co",
        "ip": data.get("ip", ""),
        "country": data.get("country_iso", ""),
        "city": data.get("city", ""),
        "region": data.get("region_name", ""),
        "timezone": data.get("time_zone", ""),
        "org": f"{data.get('asn', '')} {data.get('asn_org', '')}".strip(),
        "proxy": None,
        "latency_ms": ms,
        "status": "OK",
    }


def _query_geoip_ipwhois(ip: str) -> Dict[str, Any]:
    ok, data, ms, err = curl_json(f"https://ipwho.is/{urllib.parse.quote(ip)}", timeout=6)
    if not ok or not isinstance(data, dict) or not data.get("success", True):
        return {"source": "ipwho.is", "status": "ERR", "error": err or "failed", "latency_ms": ms}
    conn = data.get("connection") or {}
    tz = data.get("timezone") or {}
    return {
        "source": "ipwho.is",
        "ip": data.get("ip", ip),
        "country": data.get("country_code", ""),
        "city": data.get("city", ""),
        "region": data.get("region", ""),
        "timezone": tz.get("id", "") if isinstance(tz, dict) else "",
        "org": f"AS{conn.get('asn', '')} {conn.get('isp', '')}".strip(),
        "proxy": None,
        "latency_ms": ms,
        "status": "OK",
    }


def _query_geoip_ip2location(ip: str) -> Dict[str, Any]:
    ok, data, ms, err = curl_json(f"https://api.ip2location.io/?ip={urllib.parse.quote(ip)}", timeout=6)
    if not ok or not isinstance(data, dict) or "country_code" not in data:
        return {"source": "ip2location.io", "status": "ERR", "error": err or "rate/err", "latency_ms": ms}
    return {
        "source": "ip2location.io",
        "ip": data.get("ip", ip),
        "country": data.get("country_code", ""),
        "city": data.get("city_name", ""),
        "region": data.get("region_name", ""),
        "timezone": data.get("time_zone", ""),
        "org": f"AS{data.get('asn', '')} {data.get('as', '')}".strip(),
        "proxy": data.get("is_proxy"),
        "latency_ms": ms,
        "status": "OK",
    }


def _query_geoip_ipsb(ip: str) -> Dict[str, Any]:
    ok, data, ms, err = curl_json(f"https://api.ip.sb/geoip/{urllib.parse.quote(ip)}", timeout=6)
    if not ok or not isinstance(data, dict) or "country_code" not in data:
        return {"source": "api.ip.sb", "status": "ERR", "error": err, "latency_ms": ms}
    return {
        "source": "api.ip.sb",
        "ip": data.get("ip", ip),
        "country": data.get("country_code", ""),
        "city": data.get("city", ""),
        "region": data.get("region", ""),
        "timezone": data.get("timezone", ""),
        "org": f"AS{data.get('asn', '')} {data.get('asn_organization', '')}".strip(),
        "proxy": None,
        "latency_ms": ms,
        "status": "OK",
    }


def _query_geoip_dbip(ip: str) -> Dict[str, Any]:
    ok, data, ms, err = curl_json(f"https://api.db-ip.com/v2/free/{urllib.parse.quote(ip)}", timeout=6)
    if not ok or not isinstance(data, dict) or "countryCode" not in data:
        return {"source": "db-ip.com", "status": "ERR", "error": err, "latency_ms": ms}
    return {
        "source": "db-ip.com",
        "ip": data.get("ipAddress", ip),
        "country": data.get("countryCode", ""),
        "city": data.get("city", ""),
        "region": data.get("stateProv", ""),
        "timezone": "",
        "org": "",
        "proxy": None,
        "latency_ms": ms,
        "status": "OK",
    }


def _query_geoip_geojs(ip: str) -> Dict[str, Any]:
    ok, data, ms, err = curl_json(f"https://get.geojs.io/v1/ip/geo/{urllib.parse.quote(ip)}.json", timeout=6)
    if not ok or not isinstance(data, dict) or "country_code" not in data:
        return {"source": "geojs.io", "status": "ERR", "error": err, "latency_ms": ms}
    return {
        "source": "geojs.io",
        "ip": data.get("ip", ip),
        "country": data.get("country_code", ""),
        "city": data.get("city", ""),
        "region": data.get("region", ""),
        "timezone": data.get("timezone", ""),
        "org": f"AS{data.get('asn', '')} {data.get('organization_name', '')}".strip(),
        "proxy": None,
        "latency_ms": ms,
        "status": "OK",
    }


def _query_geoip_ripe_maxmind(ip: str) -> Dict[str, Any]:
    url = f"https://stat.ripe.net/data/maxmind-geo-lite/data.json?resource={urllib.parse.quote(ip)}"
    ok, data, ms, err = curl_json(url, timeout=6)
    if not ok or not isinstance(data, dict):
        return {"source": "RIPE MaxMind", "status": "ERR", "error": err, "latency_ms": ms}
    locs = (data.get("data") or {}).get("located_resources") or []
    country, city = "", ""
    if locs and isinstance(locs[0], dict):
        inner = locs[0].get("locations") or []
        if inner and isinstance(inner[0], dict):
            country = inner[0].get("country", "")
            city = inner[0].get("city", "")
    return {
        "source": "RIPE MaxMind",
        "ip": ip,
        "country": country,
        "city": city,
        "region": "",
        "timezone": "",
        "org": "",
        "proxy": None,
        "latency_ms": ms,
        "status": "OK" if country else "ERR",
        "error": "" if country else "empty",
    }


def _query_geoip_ipapi_is(ip: str) -> Dict[str, Any]:
    """11th GeoIP + Fraud/Abuser/Datacenter/VPN/Tor reputation engine (free, no key)."""
    ok, data, ms, err = curl_json(f"https://api.ipapi.is/?q={urllib.parse.quote(ip)}", timeout=6)
    if not ok or not isinstance(data, dict) or "location" not in data:
        return {"source": "ipapi.is", "status": "ERR", "error": err or "rate/err", "latency_ms": ms}
    loc = data.get("location") or {}
    asn = data.get("asn") or {}
    comp = data.get("company") or {}
    is_dc = bool(data.get("is_datacenter"))
    is_vpn = bool(data.get("is_vpn"))
    is_proxy = bool(data.get("is_proxy"))
    is_tor = bool(data.get("is_tor"))
    is_abuser = bool(data.get("is_abuser"))
    org_txt = f"AS{asn.get('asn', '')} {asn.get('org') or comp.get('name') or ''}".strip()
    return {
        "source": "ipapi.is",
        "ip": data.get("ip", ip),
        "country": loc.get("country_code", ""),
        "city": loc.get("city", ""),
        "region": loc.get("state", ""),
        "timezone": loc.get("timezone", ""),
        "org": org_txt,
        "proxy": is_vpn or is_proxy or is_tor or is_dc,
        "is_datacenter": is_dc,
        "is_vpn": is_vpn,
        "is_proxy": is_proxy,
        "is_tor": is_tor,
        "is_abuser": is_abuser,
        "company_type": str(comp.get("type") or ""),
        "asn_type": str(asn.get("type") or ""),
        "abuser_score": str(comp.get("abuser_score") or asn.get("abuser_score") or ""),
        "latency_ms": ms,
        "status": "OK",
    }


def _query_ripe_prefix(ip: str) -> Dict[str, Any]:
    url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={urllib.parse.quote(ip)}"
    ok, data, ms, err = curl_json(url, timeout=6)
    if not ok or not isinstance(data, dict):
        return {}
    d = data.get("data") or {}
    return {"resource": d.get("resource", ""), "asns": d.get("asns") or []}


def _query_blackbox(ip: str) -> str:
    ok, body, _, _ = curl_fetch(f"https://blackbox.ipinfo.app/lookup/{urllib.parse.quote(ip)}", timeout=5)
    return body.strip() if ok else ""


def _query_proxycheck(ip: str) -> Dict[str, Any]:
    url = f"https://proxycheck.io/v2/{urllib.parse.quote(ip)}?vpn=1&asn=1"
    ok, data, _, _ = curl_json(url, timeout=6)
    if ok and isinstance(data, dict) and ip in data and isinstance(data[ip], dict):
        return data[ip]
    return {}


def _query_whois(ip: str) -> Dict[str, Any]:
    if not WHOIS_BIN:
        return {}
    rc, out, err = run_cmd([WHOIS_BIN, ip], timeout=9)
    if rc != 0 and not out:
        return {"error": err}
    info: Dict[str, Any] = {
        "countries": [],
        "netname": "",
        "geofeed": "",
        "org_names": [],
        "created": [],
        "addresses": [],
        "remarks": [],
        "origin": "",
    }
    for line in out.splitlines():
        s = line.strip()
        if not s or s.startswith(("%", "#")):
            continue
        if ":" not in s:
            continue
        k, v = s.split(":", 1)
        kl = k.strip().lower()
        val = v.strip()
        if not val:
            continue
        if kl == "country" and val.upper() not in info["countries"]:
            info["countries"].append(val.upper())
        elif kl in {"netname", "network-name"} and not info["netname"]:
            info["netname"] = val
        elif kl == "geofeed" and not info["geofeed"]:
            info["geofeed"] = val
        elif kl in {"org-name", "orgname", "organization"} and val not in info["org_names"]:
            info["org_names"].append(val)
        elif kl == "created" and len(info["created"]) < 3:
            info["created"].append(val)
        elif kl == "address" and len(info["addresses"]) < 4:
            info["addresses"].append(val)
        elif kl == "origin" and not info["origin"]:
            info["origin"] = val
        elif kl == "remarks" and len(info["remarks"]) < 4:
            info["remarks"].append(val)
    return info


def _query_rdap(ip: str) -> Dict[str, Any]:
    ok, data, _, _ = curl_json(f"https://rdap.org/ip/{urllib.parse.quote(ip)}", timeout=6)
    if not ok or not isinstance(data, dict):
        return {}
    out: Dict[str, Any] = {"countries": [], "netname": "", "org_names": [], "geofeed": "", "created": []}
    c = str(data.get("country") or "").strip().upper()
    if c:
        out["countries"].append(c)
    if data.get("name"):
        out["netname"] = str(data.get("name")).strip()
    for ev in data.get("events") or []:
        if isinstance(ev, dict) and ev.get("eventAction") in {"registration", "last changed"} and ev.get("eventDate"):
            out["created"].append(f"{ev['eventAction']}:{str(ev['eventDate'])[:10]}")
    for link in data.get("links") or []:
        if isinstance(link, dict):
            href = str(link.get("href") or "")
            rel = str(link.get("rel") or "").lower()
            if "geofeed" in rel or "geofeed" in href.lower():
                out["geofeed"] = href
                break
    for rem in data.get("remarks") or []:
        if isinstance(rem, dict):
            for d in rem.get("description") or []:
                m = re.search(r"https?://\S*geofeed\S*", str(d), re.I)
                if m and not out["geofeed"]:
                    out["geofeed"] = m.group(0)
    for ent in data.get("entities") or []:
        if not isinstance(ent, dict):
            continue
        vc = ent.get("vcardArray")
        if isinstance(vc, list) and len(vc) > 1 and isinstance(vc[1], list):
            for prop in vc[1]:
                if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
                    fn_val = str(prop[3]).strip()
                    if fn_val and fn_val not in out["org_names"]:
                        out["org_names"].append(fn_val)
        elif ent.get("handle"):
            h = str(ent["handle"]).strip()
            if h and h not in out["org_names"]:
                out["org_names"].append(h)
    return out


def _doh_query(name: str, qtype: str = "A", timeout: int = 5) -> Tuple[bool, Dict[str, Any]]:
    url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(name)}&type={urllib.parse.quote(qtype)}"
    cmd = _curl_base_cmd(timeout) + ["-H", "Accept: application/dns-json", url]
    rc, out, _ = run_cmd(cmd, timeout=timeout + 2, env=_network_env())
    if rc != 0 or not out.strip():
        return False, {}
    try:
        data = json.loads(out)
        return isinstance(data, dict), data if isinstance(data, dict) else {}
    except Exception:
        return False, {}


def _query_rdns(ip: str) -> str:
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
        return ""
    rev = ".".join(reversed(ip.split(".")))
    ok, data = _doh_query(f"{rev}.in-addr.arpa", qtype="PTR", timeout=5)
    if ok:
        for ans in data.get("Answer") or []:
            if isinstance(ans, dict) and ans.get("type") == 12 and ans.get("data"):
                return str(ans["data"]).rstrip(".")
    return ""


def _query_dnsbl_doh(ip: str) -> Dict[str, Any]:
    if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
        return {"checked": 0, "hits": [], "pbl_residential": False, "spamhaus_ratelimited": False}
    rev = ".".join(reversed(ip.split(".")))
    zones = [
        "zen.spamhaus.org",
        "dnsbl.dronebl.org",
        "b.barracudacentral.org",
        "dnsbl-1.uceprotect.net",
    ]
    hits: List[str] = []
    checked = 0
    pbl_res = False
    sh_ratelimit = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as subpool:
        futs = {z: subpool.submit(_doh_query, f"{rev}.{z}", "A", 5) for z in zones}
        for z, fut in futs.items():
            ok, data = fut.result()
            if not ok:
                continue
            checked += 1
            ans_ips = [
                str(a.get("data", "")).strip()
                for a in (data.get("Answer") or [])
                if isinstance(a, dict) and a.get("type") == 1 and a.get("data")
            ]
            if not ans_ips:
                continue
            if z == "zen.spamhaus.org":
                if any(a.startswith("127.255.255.") for a in ans_ips):
                    sh_ratelimit = True
                    continue
                if any(a in {"127.0.0.10", "127.0.0.11"} for a in ans_ips):
                    pbl_res = True
                real_sh = [a for a in ans_ips if a.startswith("127.0.0.") and a not in {"127.0.0.10", "127.0.0.11"}]
                if real_sh:
                    hits.append(f"{z}({','.join(real_sh)})")
            else:
                real_hits = [a for a in ans_ips if a.startswith("127.0.0.")]
                if real_hits:
                    hits.append(f"{z}({','.join(real_hits)})")
    return {
        "checked": checked,
        "hits": hits,
        "pbl_residential": pbl_res,
        "spamhaus_ratelimited": sh_ratelimit,
    }


def _query_mullvad() -> Dict[str, Any]:
    ok, data, _, _ = curl_json("https://am.i.mullvad.net/json", timeout=6)
    return data if ok and isinstance(data, dict) else {}


def _query_ipleak() -> Dict[str, Any]:
    ok, data, _, _ = curl_json("https://ipv4.ipleak.net/json/", timeout=6)
    return data if ok and isinstance(data, dict) else {}


def _query_edns_reliable() -> Tuple[bool, Any, float, str]:
    # Prefer plain HTTP first so slow proxies avoid double TLS handshakes on random redirect subdomain
    ok, data, ms, err = curl_json("http://edns.ip-api.com/json", timeout=8)
    if ok and isinstance(data, dict) and isinstance(data.get("dns"), dict):
        return True, data, ms, ""
    return curl_json("https://edns.ip-api.com/json", timeout=8)


def _probe_third_party(name: str, url: str, category: str = "risk") -> Dict[str, Any]:
    cmd = _curl_base_cmd(8) + ["-o", os.devnull, "-w", "%{http_code}|%{redirect_url}", "-I", url]
    t0 = time.monotonic()
    rc, out, err = run_cmd(cmd, timeout=10, env=_network_env())
    ms = round((time.monotonic() - t0) * 1000.0, 1)
    parts = out.strip().split("|", 1)
    code_str = parts[0] if parts else ""
    redir = parts[1] if len(parts) > 1 else ""
    ok = rc == 0 and code_str.isdigit() and 200 <= int(code_str) < 500
    result = {
        "name": name,
        "url": url,
        "domain": urllib.parse.urlparse(url).netloc,
        "category": category,
        "http_code": int(code_str) if code_str.isdigit() else 0,
        "redirect_url": redir,
        "latency_ms": ms,
        "ok": ok,
        "error": "" if ok else (err.strip() or f"HTTP {code_str or rc}"),
    }
    if category == "legacy" and not ok:
        # Fake-IP resolves even retired names locally. Check public DNS before
        # attributing a legacy host's TLS failure to the user's payment route.
        dns_ok, dns, _, _ = curl_json("https://dns.google/resolve?" + urllib.parse.urlencode(
            {"name": result["domain"], "type": "A"}), timeout=5)
        retired = bool(dns_ok and isinstance(dns, dict) and dns.get("Status") == 3)
        result.update(status="INFO" if retired else "WARN", retired=retired,
                      note="公共 DNS 返回 NXDOMAIN；旧版辅助域名，不计为支付故障" if retired
                      else "旧版辅助域名不可达；未确认停用，保留排查提示")
    return result


def _probe_claude_edge_redirect() -> Dict[str, Any]:
    cmd = _curl_base_cmd(8) + [
        "-D-",
        "-o",
        os.devnull,
        "-w",
        "\n__RG_META__%{http_code}|%{redirect_url}",
        "https://claude.ai/login",
    ]
    t0 = time.monotonic()
    rc, out, err = run_cmd(cmd, timeout=10, env=_network_env())
    ms = round((time.monotonic() - t0) * 1000.0, 1)
    hdrs, _, meta = out.rpartition("\n__RG_META__")
    parts = meta.strip().split("|", 1)
    code_str = parts[0] if parts else ""
    redir = parts[1] if len(parts) > 1 else ""
    code = int(code_str) if code_str.isdigit() else None
    diagnostic = classify_http(status=code, headers=hdrs,
                              request_url='https://claude.ai/login',
                              error='timeout' if rc == 28 else 'network_error' if rc else None)
    reasons = diagnostic['reason_codes']
    cf_challenge = 'edge_challenge' in reasons
    blocked = 'region_denied' in reasons
    ok = rc == 0 and code is not None and 200 <= code < 400 and not blocked and not cf_challenge
    return {
        "name": "Claude Login Edge",
        "url": "https://claude.ai/login",
        "domain": "claude.ai/login",
        "category": "edge",
        "http_code": code or 0,
        "redirect_url": '/app-unavailable-in-region' if blocked else '',
        "blocked": blocked,
        "cf_challenge": cf_challenge,
        "latency_ms": ms,
        "ok": ok,
        "diagnostic": diagnostic,
        "error": '、'.join(DIAGNOSTIC_LABELS[reason] for reason in reasons) if reasons else
                 ('' if ok else '公开登录入口未获可确认响应'),
    }


def edge_gate_check(edge):
    """A bare 403 cannot establish region rejection or an account ban."""
    diagnostic = edge.get('diagnostic') or {}
    codes = [key for key in DIAGNOSTIC_KEYS if key in diagnostic.get('reason_codes', [])]
    if edge.get('blocked'):
        return make_check('claude_edge_gate', 'Claude 公开登录入口响应分类', 'WARN',
                          '观察到明确地区拒绝',
                          '公开无凭据探测出现明确地区拒绝标识；这不是账号封禁或国籍判定。',
                          '核对当前出口与服务支持范围；保留客户端标识和 Cookie。', severity='high')
    if edge.get('cf_challenge'):
        return make_check('claude_edge_gate', 'Claude 公开登录入口响应分类', 'INFO',
                          'Cloudflare 人机验证',
                          'cf-mitigated: challenge 仅证明此公开探测遇到挑战；实际登录需在真实浏览器确认。',
                          severity='low')
    if codes:
        return make_check('claude_edge_gate', 'Claude 公开登录入口响应分类', 'WARN',
                          '、'.join(DIAGNOSTIC_LABELS[key] for key in codes),
                          '响应原因与地区拒绝、权限/IP 限制、人机验证及网络故障分开记录。'
                          '普通 403 原因未确认，不判封号，不清理 ant-did 或 Cookie。', severity='low')
    if not edge.get('ok'):
        return make_check('claude_edge_gate', 'Claude 公开登录入口响应分类', 'WARN',
                          '公开探测未获确认', '当前响应不足以推断账号或地区状态。', severity='low')
    return make_check('claude_edge_gate', 'Claude 公开登录入口响应分类', 'INFO',
                      '公开入口可响应', '只验证无凭据入口响应，不证明真实客户端登录或账号权限正常。')


def service_response_check(telemetry):
    counts = dict.fromkeys(DIAGNOSTIC_KEYS, 0)
    for source in telemetry.get('sources', []):
        if isinstance(source, dict) and source.get('id') == 'claude_logs':
            values = source.get('diagnostics', {})
            if isinstance(values, dict):
                counts = {key: value if type(value := values.get(key)) is int and 0 <= value < 2**63 else 0
                          for key in DIAGNOSTIC_KEYS}
    total = sum(counts.values())
    return make_check('service_response_diagnostics', 'Claude 服务拒绝与网络错误分类',
                      'WARN' if total else 'INFO',
                      ' · '.join(DIAGNOSTIC_LABELS[key] + ' ' + str(counts[key]) for key in DIAGNOSTIC_KEYS),
                      '仅为本次文件观察窗口内的分类计数，未解密上传或读取响应正文。'
                      '403 未知不等于地区限制或封号；零计数不证明账号安全，不建议清理安装标识。',
                      severity='low')


def client_version_check(snapshot):
    current = snapshot.get('current_version', '')
    version = current if isinstance(current, str) and re.fullmatch(r'[0-9]{1,10}(?:\.[0-9]{1,10}){1,4}', current) else ''
    changed = snapshot.get('review_required') is True
    return make_check('client_version_review', 'Claude 版本变化复核提醒', 'WARN' if changed else 'INFO',
                      ('检测到版本变化，请复核只读检查范围' if changed else
                       '当前安装版本 ' + version if version else '安装版本未获确认'),
                      '只读取已知应用的版本元数据；版本变化仅提醒，不触发强退、不读队列正文。'
                      '安装版本不等于当前正在运行的进程版本。', severity='low')


def traffic_coverage_check(snapshot):
    state = snapshot.get('state')
    route = snapshot.get('route_evidence') or {}
    groups = snapshot.get('groups', [])
    counts = dict(socket=0, matched=0, proxy=0, direct=0, unknown=0, route_bypass=0)
    for group in groups if isinstance(groups, list) else []:
        if not isinstance(group, dict) or group.get('id') not in {'ClaudeDesktop', 'ClaudeHelper'}:
            continue
        def number(value):
            return value if type(value) is int and 0 <= value <= 2**31 else 0
        counts['socket'] += number(group.get('socket_count'))
        counts['matched'] += number(group.get('matched_count'))
        transports = group.get('transport_counts') or {}
        if isinstance(transports, dict):
            for key in ('proxy', 'direct', 'unknown'):
                counts[key] += number(transports.get(key))
        route_counts = group.get('route_counts') or {}
        if isinstance(route_counts, dict):
            counts['route_bypass'] += number(route_counts.get('physical_bypass'))
    def flag(name):
        return '已观察' if route.get(name) is True else '未启用' if route.get(name) is False else '未知'
    return make_check('claude_traffic_coverage', 'Claude 实际连接的只读覆盖证据',
                      'WARN' if counts['direct'] or counts['route_bypass'] else 'INFO',
                      '发现公网目的地址的物理路由例外' if counts['route_bypass'] else
                      '客户端未运行，暂无连接证据' if state == 'not_running' else
                      '已观察到部分连接元数据，全部覆盖未验证' if state == 'observed' else '连接证据未获确认',
                      'TUN ' + flag('tun_enabled') + ' · Global ' + flag('global_mode') + '。'
                      '当前 socket {socket} · 已匹配 {matched} · 代理 {proxy} · DIRECT {direct} · 未知 {unknown}。'.format(**counts) +
                      '仅将已验证 Claude 进程的 socket 与代理连接元数据关联，不抓包、不解密 HTTPS。'
                      'DIRECT 仅指控制器路由选择，不等于物理绕过或中国出口。'
                      '目的路由表证据不等于逐包实际接口证明。'
                      '未匹配连接保留未知；配置模式、路由与当前样本不能证明所有遥测或未来连接均经过代理。',
                      severity='high' if counts['route_bypass'] else 'low')


def _ntp_probe(host: str = "", port: int = 123) -> Dict[str, Any]:
    if not host:
        host = "time.windows.com" if IS_WINDOWS else "time.apple.com"
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.5)
        pkt = b"\x1b" + 47 * b"\x00"
        t0 = time.monotonic()
        sock.sendto(pkt, (host, port))
        data, _ = sock.recvfrom(1024)
        ms = round((time.monotonic() - t0) * 1000.0, 1)
        return {"host": f"{host}:{port}", "ok": len(data) >= 48, "latency_ms": ms}
    except socket.timeout:
        return {"host": f"{host}:{port}", "ok": False, "error": "timeout"}
    except Exception as exc:
        return {"host": f"{host}:{port}", "ok": False, "error": str(exc)}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Category 2: Domain Split-Routing, DNS/EDNS, IPv6, UDP/STUN, Clock, Routes
# ---------------------------------------------------------------------------
def _trace_domain(domain: str) -> Dict[str, Any]:
    ok, body, ms, err = curl_fetch(f"https://{domain}/cdn-cgi/trace", timeout=6)
    if not ok:
        return {
            "domain": domain,
            "ip": "",
            "loc": "",
            "colo": "",
            "warp": "off",
            "latency_ms": ms,
            "ok": False,
            "error": err,
        }
    parsed = parse_cf_trace(body)
    try:
        trace_available = bool(ipaddress.ip_address(parsed.get("ip", "")).is_global and
                               re.fullmatch(r"[A-Z]{2}", parsed.get("loc", "")))
    except ValueError:
        trace_available = False
    return {
        "domain": domain,
        "ip": parsed.get("ip", ""),
        "loc": parsed.get("loc", ""),
        "colo": parsed.get("colo", ""),
        "http": parsed.get("http", ""),
        "tls": parsed.get("tls", ""),
        "warp": parsed.get("warp", "off"),
        "gateway": parsed.get("gateway", "off"),
        "sni": parsed.get("sni", ""),
        "latency_ms": ms,
        "ok": trace_available,
        "reachable": True,
        "trace_available": trace_available,
        "error": "" if trace_available else "HTTP 可达，但未提供 Cloudflare trace，出口未核验",
    }


def _check_split_dns_resolution() -> Dict[str, Any]:
    """
    Resolve critical Anthropic/Stripe/hCaptcha/Statsig/Cloudflare domains via OS resolver
    to detect DNS poisoning (0.0.0.0/127.0.0.1) or Fake-IP split divergence (e.g. claude.ai
    gets 198.18.x.x Fake-IP while m.stripe.network or statsig.anthropic.com bypasses Fake-IP).
    """
    domains = [
        "claude.ai",
        "api.anthropic.com",
        "downloads.claude.ai",
        "releases.claude.com",
        "assets.claude.ai",
        "bridge.claudeusercontent.com",
        "config.claude.com",
        "pivot.claude.ai",
        "browser-intake-us5-datadoghq.com",
        "www.claudeusercontent.com",
        "sandbox.claudemcpcontent.com",
        "statsig.anthropic.com",
        "o1158394.ingest.us.sentry.io",
        "m.stripe.network",
        "api.stripe.com",
        "api.hcaptcha.com",
        "challenges.cloudflare.com",
    ]
    resolved: Dict[str, str] = {}
    poisoned: List[str] = []
    fakeip_doms: List[str] = []
    realip_doms: List[str] = []

    def _is_fake_ip(ip: str) -> bool:
        return ip.startswith(("198.18.", "198.19."))

    for dom in domains:
        if SHUTDOWN_EVENT.is_set():
            break
        try:
            infos = socket.getaddrinfo(dom, 443, socket.AF_INET, socket.SOCK_STREAM)
            ip = infos[0][4][0] if infos else ""
            resolved[dom] = ip
            if ip in {"0.0.0.0", "127.0.0.1"} or ip.startswith("127."):
                poisoned.append(f"{dom}->{ip}")
            elif _is_fake_ip(ip):
                fakeip_doms.append(dom)
            elif ip:
                realip_doms.append(f"{dom}({ip})")
        except Exception:
            resolved[dom] = "ERR"

    return {
        "resolved": resolved,
        "poisoned": poisoned,
        "fakeip_domains": fakeip_doms,
        "realip_domains": realip_doms,
    }


def _check_cn_ip_url(domain: str, url: str) -> Dict[str, Any]:
    ok, body, ms, err = curl_fetch(url, timeout=6)
    ip = ""
    loc_note = ""
    if ok:
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", body)
        if m:
            ip = m.group(1)
        if "来自于：" in body:
            loc_note = body.split("来自于：", 1)[1].strip().splitlines()[0][:60]
    return {
        "domain": domain,
        "ip": ip,
        "loc": loc_note or ("proxied/non-CN" if ip else ""),
        "colo": "CN-test",
        "latency_ms": ms,
        "ok": ok,
        "error": err,
    }


def _stun_probe(host: str, port: int) -> Dict[str, Any]:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        txid = os.urandom(12)
        req = struct.pack("!HHI12s", 0x0001, 0, 0x2112A442, txid)
        sock.sendto(req, (host, port))
        data, _ = sock.recvfrom(2048)
        idx = 20
        while idx + 4 <= len(data):
            atype, alen = struct.unpack("!HH", data[idx : idx + 4])
            val = data[idx + 4 : idx + 4 + alen]
            if atype == 0x0020 and alen >= 8 and val[1] == 1:
                xip = struct.unpack("!I", val[4:8])[0] ^ 0x2112A442
                ip = socket.inet_ntoa(struct.pack("!I", xip))
                return {"host": f"{host}:{port}", "ok": True, "ip": ip}
            if atype == 0x0001 and alen >= 8 and val[1] == 1:
                ip = socket.inet_ntoa(val[4:8])
                return {"host": f"{host}:{port}", "ok": True, "ip": ip}
            idx += 4 + ((alen + 3) & ~3)
        return {"host": f"{host}:{port}", "ok": True, "ip": ""}
    except socket.timeout:
        return {"host": f"{host}:{port}", "ok": False, "error": "timeout"}
    except Exception as exc:
        return {"host": f"{host}:{port}", "ok": False, "error": str(exc)}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _check_clock_drift() -> Dict[str, Any]:
    local_utc = datetime.datetime.now(datetime.timezone.utc)
    ok, headers, ms, err = curl_fetch("https://claude.ai", timeout=5, head_only=True)
    if not ok:
        return {"ok": False, "error": err}
    for line in headers.splitlines():
        if line.lower().startswith("date:"):
            raw_date = line.split(":", 1)[1].strip()
            try:
                srv_dt = email.utils.parsedate_to_datetime(raw_date)
                if srv_dt.tzinfo is None:
                    srv_dt = srv_dt.replace(tzinfo=datetime.timezone.utc)
                drift = (local_utc - srv_dt).total_seconds()
                return {
                    "ok": True,
                    "drift_sec": round(drift, 1),
                    "local_utc": local_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "server_utc": srv_dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                }
            except Exception as exc:
                return {"ok": False, "error": str(exc)}
    return {"ok": False, "error": "no Date header"}


def _check_dns_and_proxy_scutil() -> Dict[str, Any]:
    _, dns_out, _ = run_cmd(["/usr/sbin/scutil", "--dns"], timeout=4)
    _, proxy_out, _ = run_cmd(["/usr/sbin/scutil", "--proxy"], timeout=4)

    scoped_private_dns: List[str] = []
    utun_dns: List[str] = []
    cur_ns: List[str] = []
    cur_iface = ""
    cur_flags = ""

    def flush_block() -> None:
        if not cur_ns:
            return
        if "utun" in cur_iface:
            for ns in cur_ns:
                utun_dns.append(f"{ns} ({cur_iface})")
        elif "Scoped" in cur_flags and cur_iface:
            for ns in cur_ns:
                if ns.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3")):
                    scoped_private_dns.append(f"{ns} ({cur_iface})")

    for line in dns_out.splitlines():
        s = line.strip()
        if s.startswith("resolver #"):
            flush_block()
            cur_ns = []
            cur_iface = ""
            cur_flags = ""
        elif s.startswith("nameserver["):
            cur_ns.append(s.split(":", 1)[1].strip())
        elif s.startswith("if_index"):
            cur_iface = s.split(":", 1)[1].strip()
        elif s.startswith("flags"):
            cur_flags = s.split(":", 1)[1].strip()
    flush_block()

    sys_proxies = []
    for line in proxy_out.splitlines():
        if any(k in line for k in ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable"]):
            sys_proxies.append(line.strip())

    return {
        "utun_dns": list(dict.fromkeys(utun_dns)),
        "scoped_private_dns": list(dict.fromkeys(scoped_private_dns)),
        "sys_proxies": sys_proxies,
    }


# ---------------------------------------------------------------------------
# Category 3: Clash / VPN Sanitized Config Inspection
# ---------------------------------------------------------------------------
def _safe_parse_clash_yaml(path: str) -> Dict[str, Any]:
    return safe_parse_clash_yaml(path)


def _safe_parse_surge_conf(path: str) -> Dict[str, Any]:
    return safe_parse_surge_conf(path)


def _safe_sqlite_query(path: str, sql: str):
    return mac_platform._safe_sqlite_query(path, sql)


def audit_clash_proxy() -> Dict[str, Any]:
    result = mac_platform.mac_audit_proxy(run_cmd)
    result['checks'].insert(0, telemetry_filter_check(TELEMETRY_SERVICE.status()))
    if IS_MACOS:
        result['checks'].append(service_response_check((MONITOR.status().get('protection') or {}).get('telemetry') or {}))
        result['checks'].append(client_version_check(CLIENT_VERSION.sample()))
        traffic = CLAUDE_TRAFFIC.status()
        result['checks'].append(traffic_coverage_check(traffic.get('evidence') or {}))
    return result


def audit_macos_system(target_cfg: Dict[str, Any]) -> Dict[str, Any]:
    return mac_platform.mac_audit_system(target_cfg, run_cmd)


def _scan_safari_claude_storage() -> Dict[str, Any]:
    return mac_platform.scan_safari()


def _inspect_desktop_telemetry_artifacts_posix(cdir: str) -> Dict[str, Any]:
    return inspect_telemetry(cdir)


def audit_claude_safari_residue() -> Dict[str, Any]:
    return mac_platform.mac_audit_claude_browser_residue(run_cmd)


# ---------------------------------------------------------------------------
# Cross-Platform Helper Dispatch
# ---------------------------------------------------------------------------
def _check_tun_cross_platform() -> Tuple[bool, List[str], List[str], List[str]]:
    if IS_WINDOWS and win_platform is not None:
        return win_platform.win_check_tun_status()
    if IS_MACOS:
        return _check_utun_status()
    # Basic Linux fallback
    _, ip_out, _ = run_cmd(["ip", "-4", "route", "show", "default"], timeout=4)
    routes = [l.strip() for l in ip_out.splitlines() if l.strip()]
    tun_up = any(k in ip_out.lower() for k in ("tun", "utun", "meta", "mihomo", "clash", "wg", "198.18."))
    return tun_up, [], routes, []


def _audit_linux_system_basic(target_cfg: Dict[str, Any]) -> Dict[str, Any]:
    local_dt = datetime.datetime.now().astimezone()
    offset_sec = int(local_dt.utcoffset().total_seconds()) if local_dt.utcoffset() else 0
    tz_ok = offset_sec in target_cfg["utc_offsets_sec"]
    checks = [
        make_check(
            "sys_timezone",
            "Linux 系统时区偏移",
            "PASS" if tz_ok else "WARN",
            f"UTC{offset_sec/3600:+.1f} ({local_dt.tzname() or '-'})",
            "Linux 基础环境检测（完整 OS 深度指纹体检目前支持 Windows 与 macOS）。",
        )
    ]
    return {"title": "Linux 系统环境 (基础)", "checks": checks}


def _audit_linux_residue_basic() -> Dict[str, Any]:
    cc_json = os.path.expanduser("~/.claude.json")
    cc_dir = os.path.expanduser("~/.claude")
    has_cc = os.path.exists(cc_json) or os.path.exists(cc_dir)
    checks = [
        make_check(
            "claude_code_cli",
            "Claude Code CLI 状态 (~/.claude*)",
            "WARN" if has_cc else "PASS",
            "存在 ~/.claude* 配置" if has_cc else "0 残留",
            "换新号前请清理 ~/.claude.json 与 ~/.claude 目录。" if has_cc else "未检测到 Claude Code CLI 残留。",
        )
    ]
    return {"title": "Claude 本地文件残留 (Linux)", "checks": checks, "inventory": []}


# ---------------------------------------------------------------------------
# Full Scan Orchestrator
# ---------------------------------------------------------------------------
_SCAN_LOCK = threading.Lock()
_SCAN_FLIGHTS: Dict[str, concurrent.futures.Future] = {}


def run_full_scan(target_code: str) -> Dict[str, Any]:
    target_code = target_code.upper() if target_code.upper() in TARGETS else "US"
    with _SCAN_LOCK:
        flight = _SCAN_FLIGHTS.get(target_code)
        owner = flight is None
        if owner:
            flight = concurrent.futures.Future()
            _SCAN_FLIGHTS[target_code] = flight
    if not owner:
        return flight.result()
    try:
        result = _run_full_scan(target_code)
        flight.set_result(result)
        return result
    except BaseException as exc:
        flight.set_exception(exc)
        raise
    finally:
        with _SCAN_LOCK:
            _SCAN_FLIGHTS.pop(target_code, None)


def _run_full_scan(target_code: str) -> Dict[str, Any]:
    t0 = time.monotonic()
    target_code = target_code.upper()
    if target_code not in TARGETS:
        target_code = "SG"
    target_cfg = TARGETS[target_code]

    cf_domains = [
        "claude.ai",
        "api.anthropic.com",
        "assets.claude.ai",
        "downloads.claude.ai",
        "a-api.anthropic.com",
        "console.anthropic.com",
        "platform.claude.com",
        "code.claude.com",
        "releases.claude.com",
        "sandbox.claudemcpcontent.com",
        "challenges.cloudflare.com",
    ]

    payment_observer = PaymentRouteObserver().start() if IS_MACOS else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=44) as pool:
        # Phase A: immediate parallel launch
        f_primary = pool.submit(_trace_domain, "claude.ai")
        f_ipinfo = pool.submit(_query_geoip_ipinfo)
        f_ipapi = pool.submit(_query_geoip_ipapi)
        f_ifconfig = pool.submit(_query_geoip_ifconfig)
        f_edns = pool.submit(_query_edns_reliable)
        f_mullvad = pool.submit(_query_mullvad)
        f_ipleak = pool.submit(_query_ipleak)
        f_ipv6 = pool.submit(curl_fetch, "https://www.cloudflare.com/cdn-cgi/trace", 5, True)
        f_clock = pool.submit(_check_clock_drift)
        f_stun_cf = pool.submit(_stun_probe, "stun.cloudflare.com", 3478)
        f_stun_gg = pool.submit(_stun_probe, "stun.l.google.com", 19302)
        f_ntp = pool.submit(_ntp_probe)
        f_edge = pool.submit(_probe_claude_edge_redirect)
        f_split_dns = pool.submit(_check_split_dns_resolution)
        tp_specs = [
            ("Stripe JS", "https://js.stripe.com/v3/", "critical"),
            ("Stripe API", "https://api.stripe.com/", "critical"),
            ("Stripe Radar", "https://m.stripe.network/", "critical"),
            ("hCaptcha JS", "https://js.hcaptcha.com/1/api.js", "critical"),
            ("hCaptcha API", "https://api.hcaptcha.com/", "critical"),
            ("hCaptcha Assets", "https://newassets.hcaptcha.com/", "critical"),
            ("CF Turnstile", "https://challenges.cloudflare.com/turnstile/v0/api.js", "critical"),
            ("Anthropic Statsig (旧版)", "https://statsig.anthropic.com/", "legacy"),
            ("Claude Model Catalog", "https://downloads.claude.ai/model-catalog/v1/catalog.json", "telemetry"),
            ("Claude Portal", "https://claude.com/", "critical"),
            ("Google OAuth", "https://accounts.google.com/Generate204", "critical"),
            ("Apple OAuth", "https://appleid.apple.com/", "critical"),
            ("Claude Artifact Sandbox", "https://www.claudeusercontent.com/", "telemetry"),
            ("Claude MCP Proxy", "https://mcp-proxy.anthropic.com/", "telemetry"),
            ("Datadog RUM", "https://browser-intake-us5-datadoghq.com/", "telemetry"),
            ("Sentry", "https://o1158394.ingest.us.sentry.io/", "telemetry"),
            ("Intercom", "https://widget.intercom.io/", "telemetry"),
        ]
        f_tp = [(name, pool.submit(_probe_third_party, name, url, cat)) for name, url, cat in tp_specs]

        # Platform-specific system, TUN, proxy & residue audits
        if IS_WINDOWS and win_platform is not None:
            f_win_tun = pool.submit(win_platform.win_check_tun_details)
            f_scutil = pool.submit(win_platform.win_check_dns_and_proxy)
            f_clash = pool.submit(win_platform.win_audit_clash_proxy, _safe_parse_clash_yaml)
            f_os_sys = pool.submit(win_platform.win_audit_system, target_cfg)
            f_residue = pool.submit(win_platform.win_audit_claude_browser_residue)
            f_utun = None
        elif IS_MACOS:
            f_win_tun = None
            f_utun = pool.submit(_check_utun_status)
            f_scutil = pool.submit(_check_dns_and_proxy_scutil)
            f_clash = pool.submit(audit_clash_proxy)
            f_os_sys = pool.submit(audit_macos_system, target_cfg)
            f_residue = pool.submit(audit_claude_safari_residue)
        else:
            f_win_tun = None
            f_utun = pool.submit(_check_tun_cross_platform)
            f_scutil = None
            f_clash = None
            f_os_sys = pool.submit(_audit_linux_system_basic, target_cfg)
            f_residue = pool.submit(_audit_linux_residue_basic)

        f_domains = {d: pool.submit(_trace_domain, d) for d in cf_domains[1:]}
        f_cn1 = pool.submit(_check_cn_ip_url, "myip.ipip.net", "https://myip.ipip.net")
        f_cn2 = pool.submit(_check_cn_ip_url, "ip.3322.net", "http://ip.3322.net")

        primary_trace = f_primary.result()
        ipinfo_self = f_ipinfo.result()
        ipapi_self = f_ipapi.result()
        ifconfig_res = f_ifconfig.result()

        claude_ip = primary_trace.get("ip") or ""
        egress_ip = (
            claude_ip
            or ipinfo_self.get("ip")
            or ipapi_self.get("ip")
            or ifconfig_res.get("ip")
            or ""
        )

        # Phase B: IP-dependent GeoIP/WHOIS/DNSBL/reputation queries in parallel
        # If default overseas proxy group returned a DIFFERENT IP than claude.ai, also query IPinfo/ip-api for claude.ai's TRUE IP!
        ip_futures: Dict[str, concurrent.futures.Future] = {}
        if egress_ip:
            if claude_ip and ipinfo_self.get("ip") and ipinfo_self.get("ip") != claude_ip:
                ip_futures["ipinfo_true"] = pool.submit(_query_geoip_ipinfo, claude_ip)
            if claude_ip and ipapi_self.get("ip") and ipapi_self.get("ip") != claude_ip:
                ip_futures["ipapi_true"] = pool.submit(_query_geoip_ipapi, claude_ip)
            ip_futures["ipwhois"] = pool.submit(_query_geoip_ipwhois, egress_ip)
            ip_futures["ip2loc"] = pool.submit(_query_geoip_ip2location, egress_ip)
            ip_futures["ipsb"] = pool.submit(_query_geoip_ipsb, egress_ip)
            ip_futures["dbip"] = pool.submit(_query_geoip_dbip, egress_ip)
            ip_futures["geojs"] = pool.submit(_query_geoip_geojs, egress_ip)
            ip_futures["ripe_mm"] = pool.submit(_query_geoip_ripe_maxmind, egress_ip)
            ip_futures["ipapi_is"] = pool.submit(_query_geoip_ipapi_is, egress_ip)
            ip_futures["ripe_pfx"] = pool.submit(_query_ripe_prefix, egress_ip)
            ip_futures["blackbox"] = pool.submit(_query_blackbox, egress_ip)
            ip_futures["proxycheck"] = pool.submit(_query_proxycheck, egress_ip)
            ip_futures["whois"] = pool.submit(_query_whois, egress_ip)
            ip_futures["rdap"] = pool.submit(_query_rdap, egress_ip)
            ip_futures["rdns"] = pool.submit(_query_rdns, egress_ip)
            ip_futures["dnsbl"] = pool.submit(_query_dnsbl_doh, egress_ip)

        edns_res = f_edns.result()
        mullvad_res = f_mullvad.result()
        ipleak_res = f_ipleak.result()
        ipv6_res = f_ipv6.result()
        clock_res = f_clock.result()
        stun_cf = f_stun_cf.result()
        stun_gg = f_stun_gg.result()
        ntp_res = f_ntp.result()
        edge_res = f_edge.result()
        split_dns_res = f_split_dns.result()
        tp_results = [edge_res] + [fut.result() for _, fut in f_tp]
        payment_routes = payment_observer.finish() if payment_observer else {}
        for row in tp_results:
            if row["domain"] in payment_routes:
                row["route"] = payment_routes[row["domain"]]

        win_tun_details: Optional[Dict[str, Any]] = None
        if f_win_tun is not None:
            win_tun_details = f_win_tun.result()
            utun_up = bool(win_tun_details["tun_up"])
            utun_ips = list(win_tun_details["tun_ips"])
            default_routes = list(win_tun_details["default_routes"])
            global_v6 = list(win_tun_details["global_v6"])
        elif f_utun is not None:
            utun_up, utun_ips, default_routes, global_v6 = f_utun.result()
        else:
            utun_up, utun_ips, default_routes, global_v6 = False, [], [], []

        scutil_info = f_scutil.result() if f_scutil is not None else {"scoped_private_dns": []}
        cat_clash = f_clash.result() if f_clash is not None else {"title": "代理配置", "checks": []}
        cat_os_sys = f_os_sys.result()
        cat_residue = f_residue.result()

        domain_rows: List[Dict[str, Any]] = [primary_trace] + [f_domains[d].result() for d in cf_domains[1:]]
        cn_rows: List[Dict[str, Any]] = [f_cn1.result(), f_cn2.result()]

        ipinfo_res = ip_futures["ipinfo_true"].result() if "ipinfo_true" in ip_futures else ipinfo_self
        ipapi_res = ip_futures["ipapi_true"].result() if "ipapi_true" in ip_futures else ipapi_self
        ipwhois_res = ip_futures["ipwhois"].result() if "ipwhois" in ip_futures else {"source": "ipwho.is", "status": "ERR", "error": "no ip"}
        ip2loc_res = ip_futures["ip2loc"].result() if "ip2loc" in ip_futures else {"source": "ip2location.io", "status": "ERR", "error": "no ip"}
        ipsb_res = ip_futures["ipsb"].result() if "ipsb" in ip_futures else {"source": "api.ip.sb", "status": "ERR", "error": "no ip"}
        dbip_res = ip_futures["dbip"].result() if "dbip" in ip_futures else {"source": "db-ip.com", "status": "ERR", "error": "no ip"}
        geojs_res = ip_futures["geojs"].result() if "geojs" in ip_futures else {"source": "geojs.io", "status": "ERR", "error": "no ip"}
        ripe_mm_res = ip_futures["ripe_mm"].result() if "ripe_mm" in ip_futures else {"source": "RIPE MaxMind", "status": "ERR", "error": "no ip"}
        ipapi_is_res = ip_futures["ipapi_is"].result() if "ipapi_is" in ip_futures else {"source": "ipapi.is", "status": "ERR", "error": "no ip"}
        ripe_pfx = ip_futures["ripe_pfx"].result() if "ripe_pfx" in ip_futures else {}
        blackbox = ip_futures["blackbox"].result() if "blackbox" in ip_futures else ""
        proxycheck = ip_futures["proxycheck"].result() if "proxycheck" in ip_futures else {}
        whois_info = dict(ip_futures["whois"].result()) if "whois" in ip_futures else {}
        rdap_info = ip_futures["rdap"].result() if "rdap" in ip_futures else {}
        rdns = ip_futures["rdns"].result() if "rdns" in ip_futures else ""
        dnsbl_res = ip_futures["dnsbl"].result() if "dnsbl" in ip_futures else {"checked": 0, "hits": [], "pbl_residential": False, "spamhaus_ratelimited": False}

        if rdap_info:
            w_countries = list(whois_info.get("countries") or [])
            for c in rdap_info.get("countries") or []:
                if c and c not in w_countries:
                    w_countries.append(c)
            whois_info["countries"] = w_countries

            w_orgs = list(whois_info.get("org_names") or [])
            for o in rdap_info.get("org_names") or []:
                if o and o not in w_orgs:
                    w_orgs.append(o)
            whois_info["org_names"] = w_orgs

            if not whois_info.get("netname") and rdap_info.get("netname"):
                whois_info["netname"] = rdap_info["netname"]
            if not whois_info.get("geofeed") and rdap_info.get("geofeed"):
                whois_info["geofeed"] = rdap_info["geofeed"]

    # -----------------------------------------------------------------------
    # Build Category 1: ip_reputation
    # -----------------------------------------------------------------------
    cf_warp = str(primary_trace.get("warp", "off") or "off").lower()
    cf_row = {
        "source": "Cloudflare (claude.ai)",
        "ip": primary_trace.get("ip", ""),
        "country": primary_trace.get("loc", ""),
        "city": f"colo={primary_trace.get('colo', '')}",
        "region": "",
        "timezone": "",
        "org": f"{primary_trace.get('http', '')} / {primary_trace.get('tls', '')}" + (f" / WARP={cf_warp}" if cf_warp != "off" else ""),
        "proxy": cf_warp != "off",
        "latency_ms": primary_trace.get("latency_ms", 0),
        "status": "OK" if primary_trace.get("ok") else "ERR",
        "error": primary_trace.get("error", ""),
    }
    geoip_matrix = [
        cf_row,
        ipinfo_res,
        ipapi_res,
        ipapi_is_res,
        ipwhois_res,
        ip2loc_res,
        ipsb_res,
        dbip_res,
        geojs_res,
        ifconfig_res,
        ripe_mm_res,
    ]
    for row in geoip_matrix:
        cc = (row.get("country") or "").upper()
        if row.get("status") != "OK":
            row["match"] = "ERR"
        elif cc == target_cfg["code"]:
            row["match"] = "PASS"
        elif cc in RESTRICTED_COUNTRIES:
            row["match"] = "FAIL"
        else:
            row["match"] = "WARN"

    ip_checks: List[Dict[str, str]] = []
    cf_loc = primary_trace.get("loc", "").upper()
    cf_colo = primary_trace.get("colo", "").upper()
    expected_colos = set(target_cfg.get("expected_colos") or [])
    if not primary_trace.get("ok"):
        ip_checks.append(
            make_check(
                "cf_trace",
                "Cloudflare 入口归属与接入机房 (claude.ai)",
                "FAIL",
                primary_trace.get("error", "请求失败"),
                "无法连接 claude.ai/cdn-cgi/trace，请检查代理连通性。",
                "检查代理客户端节点是否可用" + ("，并确认已开启 TUN 模式。" if IS_WINDOWS else "。"),
            )
        )
    elif cf_loc == target_cfg["code"]:
        if cf_colo in RESTRICTED_COLOS:
            ip_checks.append(
                make_check(
                    "cf_trace",
                    "Cloudflare 入口归属与接入机房 (claude.ai)",
                    "FAIL",
                    f"IP={egress_ip} | loc={cf_loc} | colo={cf_colo} (受限区域机房!)",
                    f"Cloudflare 识别国家为 {cf_loc}，但实际 BGP 接入机房为受限/高敏地区 PoP ({cf_colo})！极易在跨境广播路由或节点中转异常时触发风控。",
                    f"更换实际落地接入 {target_cfg['name']} 本土机房（{', '.join(sorted(expected_colos)[:4])}）的原生节点。",
                    severity="high",
                )
            )
        elif expected_colos and cf_colo and cf_colo not in expected_colos:
            ip_checks.append(
                make_check(
                    "cf_trace",
                    "Cloudflare 入口归属与接入机房 (claude.ai)",
                    "WARN",
                    f"IP={egress_ip} | loc={cf_loc} | colo={cf_colo} (跨区 PoP)",
                    f"Cloudflare 识别国家与目标 {target_cfg['code']} 一致，但边缘接入机房 {cf_colo} 不在 {target_cfg['code']} 常见本土机房列表 ({', '.join(sorted(expected_colos)[:5])}) 内，常见于绕路/跨国广播段。",
                    "若频繁弹人机盾或延迟高，建议更换本土直连机房节点。",
                )
            )
        else:
            ip_checks.append(
                make_check(
                    "cf_trace",
                    "Cloudflare 入口归属与接入机房 (claude.ai)",
                    "PASS",
                    f"IP={egress_ip} | loc={cf_loc} | colo={cf_colo}" + (f" | WARP={cf_warp}" if cf_warp != "off" else ""),
                    f"Cloudflare 边缘识别国家码与本土机房均与目标地区 {target_cfg['code']} 一致。",
                )
            )
    else:
        cf_sev = "critical" if cf_loc in RESTRICTED_COUNTRIES else "high"
        ip_checks.append(
            make_check(
                "cf_trace",
                "Cloudflare 入口归属与接入机房 (claude.ai)",
                "FAIL",
                f"IP={egress_ip} | loc={cf_loc or '?'} | colo={cf_colo or '?'}",
                f"Cloudflare 将当前出口识别为 {cf_loc}，与目标 {target_cfg['code']} 不一致。",
                f"在代理客户端更换出口为 {target_cfg['name']} 的节点。",
                severity=cf_sev,
            )
        )

    ok_dbs = [r for r in geoip_matrix if r.get("status") == "OK" and r.get("country")]
    restricted_dbs = [r for r in ok_dbs if r["country"].upper() in RESTRICTED_COUNTRIES]
    mismatch_dbs = [r for r in ok_dbs if r["country"].upper() != target_cfg["code"]]
    if restricted_dbs:
        desc = ", ".join(f"{r['source']}={r['country']}" for r in restricted_dbs)
        ip_checks.append(
            make_check(
                "geoip_consistency",
                "11 大 GeoIP 数据库一致性",
                "FAIL",
                f"{len(ok_dbs) - len(mismatch_dbs)}/{len(ok_dbs)} 一致；受限库: {desc}",
                f"部分 GeoIP 数据库将该 IP 识别为受限地区（{desc}），Stripe/hCaptcha/风控极易直接拒签。",
                "更换全部主流 GeoIP 库均识别为目标地区的干净 IP。",
                severity="critical",
            )
        )
    elif mismatch_dbs:
        desc = ", ".join(f"{r['source']}={r['country']}({r.get('city', '')})" for r in mismatch_dbs)
        ip_checks.append(
            make_check(
                "geoip_consistency",
                "11 大 GeoIP 数据库一致性",
                "WARN",
                f"{len(ok_dbs) - len(mismatch_dbs)}/{len(ok_dbs)} 一致；冲突: {desc}",
                f"存在多库归属冲突（{desc}），常见于跨国广播/过户未同步的租赁段，部分第三方风控库仍按旧归属判定。",
                "建议更换所有主流 GeoIP 库均一致的本土原生 IP。",
                severity="high",
            )
        )
    elif ok_dbs:
        ip_checks.append(
            make_check(
                "geoip_consistency",
                "11 大 GeoIP 数据库一致性",
                "PASS",
                f"{len(ok_dbs)}/{len(ok_dbs)} 全部匹配 {target_cfg['code']}",
                "所有已响应的 GeoIP 数据库均一致归属目标国家。",
            )
        )
    else:
        ip_checks.append(make_check("geoip_consistency", "11 大 GeoIP 数据库一致性", "FAIL", "全部查询失败", "无法核验 GeoIP。", severity="high"))

    # Broadcast / Leased / Proxy / Datacenter / Fraud Score / ASN / WARP reputation check
    rep_flags: List[str] = []
    geofeed = whois_info.get("geofeed", "")
    org_names = whois_info.get("org_names") or []
    whois_countries = whois_info.get("countries") or []
    asn_list = ripe_pfx.get("asns") or []
    asn_str = ""
    if asn_list and isinstance(asn_list[0], dict):
        asn_str = f"AS{asn_list[0].get('asn', '')} {asn_list[0].get('holder', '')}"
    elif ipinfo_res.get("org"):
        asn_str = ipinfo_res.get("org", "")
    elif ipapi_is_res.get("org"):
        asn_str = ipapi_is_res.get("org", "")

    if cf_warp != "off":
        rep_flags.append(f"经由 Cloudflare WARP 出口 (warp={cf_warp}，高度共享易触发风控)")
    if "ipxo" in geofeed.lower():
        rep_flags.append(f"IPXO 租赁广播段 (geofeed={geofeed})")
    if any(re.match(r"^Company\s+[0-9A-Za-z]{10,}$", n) for n in org_names):
        rep_flags.append(f"WHOIS 为隐私马甲实体 ({', '.join(org_names)})")
    if any(c not in {"", target_cfg["code"]} for c in whois_countries):
        rep_flags.append(f"WHOIS 注册国家含 {'/'.join(whois_countries)}")
    il_cc = str(ipleak_res.get("country_code") or "").upper()
    il_reg = str(ipleak_res.get("registered_country_code") or "").upper()
    if il_cc and il_reg and il_cc != il_reg:
        rep_flags.append(f"跨国广播段 (ipleak 使用地={il_cc}, 注册地={il_reg})")
    if any(k in asn_str.upper() for k in HOSTING_ASN_KEYWORDS):
        rep_flags.append(f"机房/云厂商/商用共享 ASN ({asn_str})")
    if blackbox == "Y":
        rep_flags.append("ipinfo blackbox 标记为代理/VPN")
    if proxycheck.get("proxy") == "yes" or ipapi_res.get("proxy") or ip2loc_res.get("proxy") is True:
        rep_flags.append(f"代理风险库标记 (proxycheck={proxycheck.get('proxy')}, type={proxycheck.get('type')})")
    if ipapi_is_res.get("status") == "OK":
        is_tags: List[str] = []
        if ipapi_is_res.get("is_tor"):
            is_tags.append("Tor出口")
        if ipapi_is_res.get("is_abuser"):
            is_tags.append("滥用记录(is_abuser)")
        if ipapi_is_res.get("is_vpn"):
            is_tags.append("VPN")
        if ipapi_is_res.get("is_proxy"):
            is_tags.append("Proxy")
        if ipapi_is_res.get("is_datacenter") or ipapi_is_res.get("company_type") == "hosting":
            is_tags.append(f"机房({ipapi_is_res.get('company_type') or 'datacenter'})")
        if is_tags:
            score_s = f", abuser_score={ipapi_is_res.get('abuser_score')}" if ipapi_is_res.get("abuser_score") else ""
            rep_flags.append(f"ipapi.is 风险标记: {'/'.join(is_tags)}{score_s}")
    pc_type = str(proxycheck.get("type", "")).strip()
    if pc_type and pc_type.lower() not in {"residential", "wireless", "mobile"}:
        rep_flags.append(f"IP 类型为 {pc_type}（非原生民用住宅宽带）")
    tz_set = {str(r.get("timezone")).strip() for r in ok_dbs if r.get("timezone") and "/" in str(r.get("timezone"))}
    if len(tz_set) > 1:
        rep_flags.append(f"多库城市/时区不一致 ({', '.join(sorted(tz_set))})")
    if not rdns:
        rep_flags.append("无 PTR 反向解析 (rDNS)")
    elif any(k in rdns.lower() for k in RDNS_HOSTING_KEYWORDS):
        rep_flags.append(f"rDNS 含机房/VPS 命名特征 ({rdns})")

    if not egress_ip:
        ip_checks.append(
            make_check(
                "ip_reputation_signals",
                "IP 广播租赁 / 机房 / 滥用评分 / 代理信誉检测",
                "INFO",
                "未获取到出口 IP，跳过信誉检测",
                "请先确认网络与代理连通性。",
            )
        )
    elif rep_flags:
        is_tor_or_abuser = bool(ipapi_is_res.get("is_tor") or ipapi_is_res.get("is_abuser"))
        is_hard_proxy = (
            blackbox == "Y"
            or proxycheck.get("proxy") == "yes"
            or bool(ipapi_is_res.get("is_vpn"))
            or bool(ipapi_is_res.get("is_proxy"))
            or is_tor_or_abuser
            or cf_warp != "off"
        )
        ip_checks.append(
            make_check(
                "ip_reputation_signals",
                "IP 广播租赁 / 机房 / 滥用评分 / 代理信誉检测",
                "FAIL" if is_hard_proxy else "WARN",
                f"命中 {len(rep_flags)} 项风险特征",
                "；".join(rep_flags) + "。此类 IP 虽常被标为“住宅 IP”，但极易在 Cloudflare / Stripe / Anthropic 风控模型中暴露广播租赁、机房或滥用属性。",
                "如用于长期高敏感 Claude 账号，建议选用目标国本土宽带运营商（ISP 类型）静态独享 IP。",
                severity="critical" if is_tor_or_abuser else ("high" if is_hard_proxy else "low"),
            )
        )
    else:
        comp_t = ipapi_is_res.get("company_type") or "isp"
        ip_checks.append(
            make_check(
                "ip_reputation_signals",
                "IP 广播租赁 / 机房 / 滥用评分 / 代理信誉检测",
                "PASS",
                f"ASN={asn_str or '-'} | 类型={comp_t} | rDNS={rdns or '-'}",
                "未命中 IPXO 广播租赁、数据中心、滥用评分、WARP 或高风险代理特征。",
            )
        )

    # DNSBL & Mullvad Abuse Blacklist Check
    mullvad_bl = (mullvad_res.get("blacklisted") or {}) if isinstance(mullvad_res, dict) else {}
    mullvad_is_bl = bool(mullvad_bl.get("blacklisted"))
    mullvad_hits = [str(x) for x in (mullvad_bl.get("results") or [])]
    mullvad_exit = bool(mullvad_res.get("mullvad_exit_ip"))
    dnsbl_hits = list(dnsbl_res.get("hits") or [])
    all_bl_hits = dnsbl_hits + ([f"Mullvad-BL({', '.join(mullvad_hits)})"] if mullvad_is_bl else [])
    if mullvad_exit:
        all_bl_hits.append("Mullvad 已知 VPN 出口节点")
    if ipapi_is_res.get("is_tor"):
        all_bl_hits.append("Tor 出口节点")

    bl_notes: List[str] = []
    if dnsbl_res.get("pbl_residential"):
        bl_notes.append("Spamhaus PBL(动态住宅宽带特征)")
    if dnsbl_res.get("spamhaus_ratelimited"):
        bl_notes.append("Spamhaus 公共DNS限流跳过")
    if mullvad_res:
        bl_notes.append("Mullvad库已核验")
    if ipapi_is_res.get("status") == "OK" and ipapi_is_res.get("abuser_score"):
        bl_notes.append(f"ipapi.is={ipapi_is_res['abuser_score']}")

    if all_bl_hits:
        ip_checks.append(
            make_check(
                "ip_dnsbl",
                "IP 滥用黑名单与高风险 VPN/Tor 池 (DNSBL + Mullvad + ipapi.is)",
                "FAIL",
                f"命中黑名单 {len(all_bl_hits)} 项: {', '.join(all_bl_hits)}",
                "当前出口 IP 已被列入公共滥用/肉鸡黑名单、Tor 或公开商业 VPN 出口库，极易直接触发高风控拦截。",
                "立即更换干净且不在公共黑名单中的代理节点。",
                severity="critical",
            )
        )
    elif dnsbl_res.get("checked", 0) == 0 and not mullvad_res and ipapi_is_res.get("status") != "OK":
        ip_checks.append(
            make_check(
                "ip_dnsbl",
                "IP 滥用黑名单与高风险 VPN/Tor 池 (DNSBL + Mullvad + ipapi.is)",
                "INFO",
                "黑名单库查询超时/不可达 (0 已核验)",
                "当前无法访问公共 DNSBL / Mullvad / ipapi.is 接口，请确认代理联网后重试。",
            )
        )
    else:
        ip_checks.append(
            make_check(
                "ip_dnsbl",
                "IP 滥用黑名单与高风险 VPN/Tor 池 (DNSBL + Mullvad + ipapi.is)",
                "PASS",
                f"已核验 {dnsbl_res.get('checked', 0)} 个 DNSBL 库" + (f" · {', '.join(bl_notes)}" if bl_notes else ""),
                "未命中 DroneBL、Barracuda、UCEPROTECT、Spamhaus(非PBL)、Mullvad 与 Tor 黑名单。",
            )
        )

    # IP Timezone check against target
    ip_tz = ipinfo_res.get("timezone") or ipapi_res.get("timezone") or ipapi_is_res.get("timezone") or geojs_res.get("timezone") or ""
    if ip_tz:
        tz_match = ip_tz in target_cfg["timezones"]
        ip_checks.append(
            make_check(
                "ip_timezone",
                "出口 IP 地理时区",
                "PASS" if tz_match else "WARN",
                ip_tz,
                "出口 IP 所在时区与目标地区一致。" if tz_match else f"出口 IP 时区 {ip_tz} 与目标常用时区 {target_cfg['timezones']} 不完全一致。",
            )
        )

    pc_or_is_type = proxycheck.get("type") or ipapi_is_res.get("company_type") or "未知"
    egress_summary = {
        "ip": egress_ip,
        "loc": cf_loc,
        "colo": cf_colo,
        "asn": asn_str,
        "timezone": ip_tz,
        "rdns": rdns or "无",
        "geofeed": geofeed or "无",
        "whois_countries": ", ".join(whois_countries) if whois_countries else "未知",
        "whois_orgs": ", ".join(org_names) if org_names else "未知",
        "proxy_type": pc_or_is_type,
        "abuser_score": ipapi_is_res.get("abuser_score", "") or "-",
    }

    # -----------------------------------------------------------------------
    # Build Category 2: routing_leaks
    # -----------------------------------------------------------------------
    leak_checks: List[Dict[str, str]] = []
    domain_matrix = domain_rows + cn_rows

    cf_ok = [r for r in domain_rows if r["ok"] and r.get("ip") and r.get("loc")]
    no_trace = [r["domain"] for r in domain_rows if r.get("reachable") and not r.get("trace_available")]
    cf_bad = [r for r in domain_rows if r["domain"] not in no_trace and
              (not r["ok"] or r.get("loc") != target_cfg["code"])]
    cf_ips = {r["ip"] for r in cf_ok if r["ip"]}
    cf_locs = {r["loc"] for r in cf_ok if r["loc"]}
    if not cf_bad and len(cf_ips) == 1 and cf_locs == {target_cfg["code"]}:
        leak_checks.append(
            make_check(
                "domain_consistency",
                "Anthropic / Cloudflare 全域名出口一致性",
                "INFO" if no_trace else "PASS",
                f"{len(cf_ok)}/{len(domain_rows)} 域名已核验经 {next(iter(cf_ips))} ({target_cfg['code']})",
                "已返回 trace 的域名出口一致。" + ("以下域名未提供 trace，无法核验出口：" + "、".join(no_trace) if no_trace else "全部域名均已核验。"),
            )
        )
    else:
        bad_doms = [
            f"{r['domain']}({r.get('loc') or r.get('error')})"
            for r in domain_rows
            if r["domain"] not in no_trace and (not r["ok"] or r.get("loc") != target_cfg["code"])
        ]
        leak_checks.append(
            make_check(
                "domain_consistency",
                "Anthropic / Cloudflare 全域名出口一致性",
                "FAIL",
                f"存在分流/失败域名: {', '.join(bad_doms) if bad_doms else f'多出口 IP {cf_ips}'}",
                "部分 Anthropic 或 Cloudflare 域名未走同一目标节点，会导致服务端与验证服务看到不同 IP/国家。",
                "核对 Anthropic 与验证服务的分流规则；Stripe 专用 VPN 路由由支付分流项单独核验。",
            )
        )

    # Multi-Group Proxy Split-Exit Detection (AI Group IP vs Default Overseas Proxy Group IP!)
    default_probes = [
        ("IPinfo", ipinfo_self.get("ip", ""), ipinfo_self.get("country", "")),
        ("ip-api", ipapi_self.get("ip", ""), ipapi_self.get("country", "")),
        ("ifconfig.co", ifconfig_res.get("ip", ""), ifconfig_res.get("country", "")),
        ("ipleak.net", str(ipleak_res.get("ip") or ""), str(ipleak_res.get("country_code") or "")),
    ]
    diff_default = [
        f"{src}={dip}({dcc or '?'})"
        for src, dip, dcc in default_probes
        if dip and claude_ip and dip != claude_ip
    ]
    if claude_ip and diff_default:
        leak_checks.append(
            make_check(
                "ai_vs_default_proxy_split",
                "AI 专属节点组 vs 默认海外代理组双出口分裂检测",
                "FAIL",
                f"claude.ai={claude_ip}({cf_loc}) ≠ 默认海外出口: {', '.join(diff_default[:3])}",
                "致命分流分裂！claude.ai 走了 AI 专属代理组，但其他海外域名（包括 Stripe / hCaptcha / Google OAuth / Datadog / Sentry 所在的默认 PROXY 组）却走了另一台服务器或另一国家！同一次登录/支付中，Anthropic 与 Stripe/hCaptcha 看到两个完全不同的 IP 与国家，这是 Rule 分流模式下最高发的隐蔽封号原因之一！",
                "使用 Claude 时切为 Global 全局模式，或将默认 PROXY 代理组与 AI 代理组选为同一个固定节点（并确保 stripe.com / stripe.network / hcaptcha.com / googleapis.com / statsig.anthropic.com 同组）。",
                severity="critical",
            )
        )
    elif claude_ip:
        seen_same = [src for src, dip, _ in default_probes if dip == claude_ip]
        leak_checks.append(
            make_check(
                "ai_vs_default_proxy_split",
                "AI 专属节点组 vs 默认海外代理组双出口分裂检测",
                "PASS",
                f"AI 出口与常规海外出口完全一致 ({claude_ip} · 核验 {len(seen_same)} 源)",
                "claude.ai 与通用海外接口走同一出口节点，不存在 AI 组与默认代理组分裂问题。",
            )
        )

    # Split-DNS / Fake-IP Divergence Check (catches stripe.network / statsig.anthropic.com bypassing Fake-IP!)
    poisoned_dns = split_dns_res.get("poisoned") or []
    fakeip_doms = split_dns_res.get("fakeip_domains") or []
    realip_doms = split_dns_res.get("realip_domains") or []
    if poisoned_dns:
        leak_checks.append(
            make_check(
                "split_dns_divergence",
                "风控关键域名本地 DNS 污染与 Fake-IP 分叉检测",
                "FAIL",
                f"命中 DNS 污染/劫持: {', '.join(poisoned_dns)}",
                "关键风控/遥测域名被解析至 0.0.0.0 或 127.0.0.1（常见于广告屏蔽规则或本地 hosts 误杀 Stripe/Statsig/hCaptcha）。",
                "检查 hosts、AdGuard、Clash 去广告规则，放行 stripe.network / statsig.anthropic.com / hcaptcha.com。",
                severity="high",
            )
        )
    elif fakeip_doms and realip_doms:
        leak_checks.append(
            make_check(
                "split_dns_divergence",
                "风控关键域名本地 DNS 污染与 Fake-IP 分叉检测",
                "WARN",
                f"Fake-IP({len(fakeip_doms)}域) 与 真实IP({', '.join(realip_doms[:4])}) 混杂分叉",
                "部分核心域名（如 claude.ai）走了 Clash Fake-IP，但 m.stripe.network / statsig.anthropic.com / hCaptcha 等返回了真实公网 IP，可能被 fake-ip-filter 放行并走直连造成 IP 分裂！",
                "检查 Clash 的 fake-ip-filter 与分流规则，确保 stripe.network、statsig.anthropic.com、hcaptcha.com 与 claude.ai 同走代理。",
                severity="high",
            )
        )
    elif not fakeip_doms and not realip_doms:
        total_dns_doms = len(split_dns_res.get("resolved") or {}) or 13
        leak_checks.append(
            make_check(
                "split_dns_divergence",
                "风控关键域名本地 DNS 污染与 Fake-IP 分叉检测",
                "WARN",
                f"本地 DNS 解析全部失败 (0/{total_dns_doms})",
                "无法通过系统 DNS 解析 claude.ai / downloads.claude.ai / stripe.network / statsig.anthropic.com，请检查本机 DNS 或代理状态。",
            )
        )
    else:
        total_dns_doms = len(split_dns_res.get("resolved") or {}) or 13
        mode_tag = (
            f"全部统一 Fake-IP ({len(fakeip_doms)}/{total_dns_doms})"
            if fakeip_doms
            else f"全部统一真实解析 ({len(realip_doms)}/{total_dns_doms})"
        )
        leak_checks.append(
            make_check(
                "split_dns_divergence",
                "风控关键域名本地 DNS 污染与 Fake-IP 分叉检测",
                "PASS",
                mode_tag,
                "claude.ai、api.anthropic.com、downloads.claude.ai、releases.claude.com、claudeusercontent.com、sentry.io、m.stripe.network 等全部域名解析模式一致且无 DNS 劫持。",
            )
        )

    # Classify public responses without inferring region or bans from HTTP 403.
    leak_checks.append(edge_gate_check(edge_res))

    # Proxy chain latency / multi-hop RTT audit
    ok_latencies = [float(r["latency_ms"]) for r in domain_rows if r.get("ok") and r.get("latency_ms")]
    if ok_latencies:
        avg_ms = round(sum(ok_latencies) / len(ok_latencies), 1)
        max_ms = round(max(ok_latencies), 1)
        if avg_ms > 2500.0:
            leak_checks.append(
                make_check(
                    "proxy_latency",
                    "代理链路延迟与超时风险",
                    "WARN",
                    f"平均 {avg_ms} ms (峰值 {max_ms} ms)",
                    "完整 HTTP 探测平均耗时超过 2500ms（包含 DNS、建连、TLS 与服务器响应，并非 RTT）；可能影响资源加载，不能据此断言存在多重中转。",
                    "建议更换直连延迟更低、链路更稳定的节点。",
                    severity="high",
                )
            )
        elif avg_ms > 1200.0:
            leak_checks.append(
                make_check(
                    "proxy_latency",
                    "代理链路延迟与超时风险",
                    "WARN",
                    f"平均 {avg_ms} ms (峰值 {max_ms} ms)",
                    "代理链路延迟偏高（1200~2500ms），加载支付或验证资源可能偶尔卡顿。",
                    severity="low",
                )
            )
        else:
            leak_checks.append(
                make_check(
                    "proxy_latency",
                    "代理链路延迟与超时风险",
                    "PASS",
                    f"平均 {avg_ms} ms (峰值 {max_ms} ms)",
                    "节点响应速度良好。",
                )
            )

    tp_only = tp_results[1:]
    crit_fail = [r for r in tp_only if not r["ok"] and r.get("category") == "critical"]
    tele_fail = [r for r in tp_only if not r["ok"] and r.get("category") == "telemetry"]
    required_tp = [r for r in tp_only if r.get("category") != "legacy"]
    ok_tp_cnt = sum(1 for r in required_tp if r["ok"])
    tp_summary = "；".join(f"{r['name']}:{r['http_code'] or 'ERR'}({r['latency_ms']}ms)" for r in tp_only)
    if crit_fail:
        leak_checks.append(
            make_check(
                "third_party_endpoints",
                "第三方支付 / 人机验证接口连通性",
                "FAIL",
                f"关键接口异常 {len(crit_fail)} 项 ({', '.join(r['name'] for r in crit_fail)})",
                f"{tp_summary}。必需资源不可达可能影响登录、支付或人机验证；探测结果不能判定实际交易是否获批。",
                "检查节点链路质量或分流规则，确保 stripe.com、stripe.network、hcaptcha.com、challenges.cloudflare.com 畅通。",
            )
        )
    elif tele_fail:
        leak_checks.append(
            make_check(
                "third_party_endpoints",
                "第三方支付 / 人机验证接口连通性",
                "WARN",
                f"遥测/客服接口异常 ({', '.join(r['name'] for r in tele_fail)})",
                tp_summary,
            )
        )
    else:
        leak_checks.append(
            make_check(
                "third_party_endpoints",
                "第三方支付 / 人机验证接口连通性",
                "PASS",
                f"{ok_tp_cnt}/{len(required_tp)} 第三方支付与验证接口可达",
                tp_summary + "。只读 HTTP 探测（含无凭据根路径的 4xx 响应）仅验证服务响应，不代表支付成功；路由见支付分流项。",
            )
        )

    for row in tp_only:
        if row.get("category") == "legacy" and not row["ok"]:
            leak_checks.append(make_check("legacy_statsig", "旧版 Statsig 辅助域名", row["status"],
                                          row["note"], row["error"]))
    if IS_MACOS:
        leak_checks.append(payment_route_check(payment_routes))

    # CN IP split routing check
    cn_ips = [r["ip"] for r in cn_rows if r.get("ip")]
    if cn_ips and all(ip == egress_ip for ip in cn_ips):
        leak_checks.append(
            make_check(
                "cn_split_check",
                "国内探测点路由方向 (myip.ipip.net / 3322)",
                "PASS",
                f"同走代理 ({egress_ip})",
                "国内探测点也经目标代理出口，当前处于强全局隔离状态。",
            )
        )
    elif cn_ips:
        leak_checks.append(
            make_check(
                "cn_split_check",
                "国内探测点路由方向 (myip.ipip.net / 3322)",
                "INFO",
                f"走直连 ({', '.join(set(cn_ips))})",
                "国内域名正在直连（规则分流）。请确认分流规则不会漏掉任何海外验证/统计域名（如 stripe.network / statsig.anthropic.com），且 DNS 不泄漏。",
            )
        )
    else:
        leak_checks.append(make_check("cn_split_check", "国内探测点路由方向", "INFO", "探测超时或不可达", "未获取到国内探测点返回值。"))

    # EDNS / DNS leak
    edns_ok, edns_data, edns_ms, edns_err = edns_res
    if edns_ok and isinstance(edns_data, dict) and isinstance(edns_data.get("dns"), dict):
        dns_ip = edns_data["dns"].get("ip", "")
        dns_geo = edns_data["dns"].get("geo", "")
        is_restricted_dns = any(k in dns_geo.lower() for k in ["china", "hong kong", "beijing", "shanghai", "guangdong", "shenzhen", "telecom", "unicom", "mobile"])
        is_target_dns = dns_ip == egress_ip or any(kw in dns_geo.lower() for kw in target_cfg.get("keywords", []))
        if is_target_dns:
            leak_checks.append(
                make_check(
                    "edns_leak",
                    "DNS 出口 / EDNS 防泄漏测试",
                    "PASS",
                    f"{dns_ip} ({dns_geo})",
                    "权威 DNS 看到的解析出口与当前目标代理一致，无本地 DNS 泄漏。",
                )
            )
        elif is_restricted_dns:
            leak_checks.append(
                make_check(
                    "edns_leak",
                    "DNS 出口 / EDNS 防泄漏测试",
                    "FAIL",
                    f"{dns_ip} ({dns_geo})",
                    "检测到 DNS 解析出口位于受限/本地运营商网络！",
                    "开启代理 DNS 接管（fake-ip / redir-host）并将上游 DNS 改为海外 DoH/DoT。",
                    severity="critical",
                )
            )
        else:
            leak_checks.append(
                make_check(
                    "edns_leak",
                    "DNS 出口 / EDNS 防泄漏测试",
                    "WARN",
                    f"{dns_ip} ({dns_geo})",
                    f"DNS 解析出口 ({dns_geo}) 与主代理 IP ({egress_ip}) 不同，但未见明显受限地区运营商。",
                    severity="low",
                )
            )
    else:
        leak_checks.append(
            make_check(
                "edns_leak",
                "DNS 出口 / EDNS 防泄漏测试",
                "WARN",
                f"查询超时/失败 ({edns_err})",
                "edns.ip-api.com 未在时限内响应（可能受网络波动影响），可重新扫描确认。",
                severity="low",
            )
        )

    # IPv6 leak check (avoid false positive when curl -6 is mapped through IPv4 proxy without real IPv6)
    v6_ok, v6_body, _, v6_err = ipv6_res
    if v6_ok:
        v6_parsed = parse_cf_trace(v6_body)
        v6_ip = v6_parsed.get("ip", "")
        v6_loc = v6_parsed.get("loc", "").upper()
        is_actual_v6 = ":" in v6_ip
        if not is_actual_v6 and not global_v6:
            leak_checks.append(
                make_check(
                    "ipv6_leak",
                    "IPv6 防泄漏检测",
                    "PASS",
                    f"本机无公网 IPv6（curl -6 经代理回落至 IPv4 {v6_ip} / {v6_loc}）",
                    "本机未分配公网 IPv6，curl -6 被代理映射到 IPv4 出口，不存在真实 IPv6 直连泄漏。",
                )
            )
        elif v6_loc == target_cfg["code"]:
            leak_checks.append(
                make_check(
                    "ipv6_leak",
                    "IPv6 防泄漏检测",
                    "PASS",
                    f"IPv6 走目标节点 (ip={v6_ip}, loc={v6_loc})",
                    "IPv6 出口与目标地区一致，无直连泄漏。",
                )
            )
        else:
            leak_checks.append(
                make_check(
                    "ipv6_leak",
                    "IPv6 防泄漏检测",
                    "FAIL",
                    f"真实 IPv6={v6_ip}, loc={v6_loc or '?'} | 本机公网v6={global_v6 or '无'}",
                    f"真实 IPv6 流量未走目标地区 {target_cfg['code']}，可能直接通过本地运营商 IPv6 泄漏！",
                    "在系统网卡属性或 Clash 中禁用 IPv6（ipv6: false）。",
                    severity="critical",
                )
            )
    else:
        if global_v6:
            leak_checks.append(
                make_check(
                    "ipv6_leak",
                    "IPv6 防泄漏检测",
                    "WARN",
                    f"外网 v6 不可达，但本机存在公网 v6: {', '.join(global_v6)}",
                    "curl -6 超时未泄漏，但网卡分配了公网 IPv6 地址，建议彻底关闭 IPv6 以防浏览器 Happy Eyeballs 或部分程序走直连。",
                    severity="high",
                )
            )
        else:
            leak_checks.append(
                make_check(
                    "ipv6_leak",
                    "IPv6 防泄漏检测",
                    "PASS",
                    "IPv6 不可达且无公网 IPv6 地址",
                    "不存在 IPv6 直连泄漏风险。",
                )
            )

    # UDP / STUN & NTP leak check
    stun_results = [stun_cf, stun_gg]
    stun_ips = [r["ip"] for r in stun_results if r.get("ok") and r.get("ip")]
    ntp_note = (
        f"NTP UDP 123: 正常({ntp_res.get('latency_ms')}ms)"
        if ntp_res.get("ok")
        else f"NTP UDP 123: 超时/阻断({ntp_res.get('error', 'timeout')})"
    )
    if not stun_ips:
        leak_checks.append(
            make_check(
                "udp_stun_leak",
                "UDP / STUN / NTP 穿透测试 (底层防 WebRTC/QUIC 泄漏)",
                "PASS",
                f"UDP STUN 超时/被阻断 | {ntp_note}",
                f"系统底层 UDP STUN 未回传真实公网 IP，当前不会通过 UDP/WebRTC 漏出本地公网 IP。（{ntp_note}，若 UDP 123 不通会导致系统自动校时失效）",
            )
        )
    elif all(ip == egress_ip for ip in stun_ips):
        leak_checks.append(
            make_check(
                "udp_stun_leak",
                "UDP / STUN / NTP 穿透测试 (底层防 WebRTC/QUIC 泄漏)",
                "PASS",
                f"UDP 出口一致 ({stun_ips[0]}) | {ntp_note}",
                f"UDP STUN 通过代理节点转发且出口 IP 与 TCP 一致。（{ntp_note}）",
            )
        )
    else:
        leak_checks.append(
            make_check(
                "udp_stun_leak",
                "UDP / STUN / NTP 穿透测试 (底层防 WebRTC/QUIC 泄漏)",
                "FAIL",
                f"UDP 返回 {set(stun_ips)} != TCP {egress_ip} | {ntp_note}",
                "致命泄漏！UDP STUN 返回的公网 IP 与 TCP 出口不同，说明 UDP 流量正在绕过代理直连（会直接暴露真实所在地 IP）。",
                "在代理客户端开启 TUN + UDP 转发，或在浏览器中禁用 WebRTC 非代理 UDP。",
                severity="critical",
            )
        )

    # Clock drift
    if clock_res.get("ok"):
        drift = abs(clock_res["drift_sec"])
        c_status = "PASS" if drift <= 10.0 else ("WARN" if drift <= 60.0 else "FAIL")
        leak_checks.append(
            make_check(
                "clock_drift",
                "本机 UTC 时钟同步误差",
                c_status,
                f"偏差 {clock_res['drift_sec']:+.1f} 秒",
                f"本机 {clock_res['local_utc']} vs 服务器 {clock_res['server_utc']}。",
                "偏差超过 60 秒会影响 TLS/防重放校验，建议同步系统时间。" if c_status != "PASS" else "",
            )
        )
    else:
        leak_checks.append(make_check("clock_drift", "本机 UTC 时钟同步误差", "INFO", "无法获取响应头", str(clock_res.get("error", ""))))

    # Tunnel & Kill-Switch route audit (Platform-Aware: Windows vs macOS)
    if IS_WINDOWS and win_tun_details is not None:
        non_tun_defaults = win_tun_details["non_tun_defaults"]
        tun_lowest = win_tun_details["tun_has_lowest_metric"]
        v6_def = win_tun_details["ipv6_default_routes"]
        phys_priv_dns = win_tun_details["physical_private_dns"]
        if not utun_up:
            leak_checks.append(
                make_check(
                    "killswitch_routes",
                    "TUN 隧道与断流保护 (Kill-Switch) 风险",
                    "FAIL",
                    f"未检测到 Windows TUN 虚拟网卡；路由={default_routes[:3]}",
                    "当前未启用 TUN 虚拟网卡接管（可能仅开了系统代理或直连），Claude Code CLI、UDP 及非 WinINET 应用极易直连漏 IP。",
                    "在 Clash Verge Rev / Mihomo Party / v2rayN 中以管理员或服务模式开启 TUN 模式。",
                    severity="high",
                )
            )
        elif not tun_lowest:
            leak_checks.append(
                make_check(
                    "killswitch_routes",
                    "TUN 隧道与断流保护 (Kill-Switch) 风险",
                    "FAIL",
                    f"TUN 网卡存在 ({', '.join(utun_ips)})，但默认路由跃点数 (Metric) 高于物理网卡！",
                    f"当前默认路由: {default_routes}。Windows 优先选择 Metric 最小的默认路由，物理网卡优先级高于 TUN 会导致流量绕过 TUN 直连！",
                    "重启代理客户端的 TUN 模式并开启 auto-route / strict-route，确保 TUN 默认路由 Metric 最低。",
                    severity="critical",
                )
            )
        elif non_tun_defaults or phys_priv_dns or v6_def:
            leak_checks.append(
                make_check(
                    "killswitch_routes",
                    "TUN 隧道与断流保护 (Kill-Switch) 风险",
                    "WARN",
                    f"TUN 接管中 ({', '.join(utun_ips)}，最低 Metric)，底层网卡保留备用默认路由/私网 DNS",
                    f"存在物理网卡默认路由 {non_tun_defaults[:3]} 及物理私网 DNS {phys_priv_dns[:3]}。"
                    + (f" 且存在 IPv6 默认路由 {v6_def[:2]}。" if v6_def else "")
                    + " 平时走 TUN 正常，但 Windows 休眠唤醒或代理重启瞬间，后台程序会走物理网卡直连漏出真实 IP！",
                    "休眠/合盖前退出 Claude Desktop，并确保代理客户端开启 strict-route 与服务模式自启。",
                )
            )
        else:
            leak_checks.append(
                make_check(
                    "killswitch_routes",
                    "TUN 隧道与断流保护 (Kill-Switch) 风险",
                    "PASS",
                    f"TUN 接管中 ({', '.join(utun_ips)})",
                    "默认路由与 DNS 均由 Windows TUN 独占接管。",
                )
            )
    else:
        non_utun_defaults = [r for r in default_routes if "utun" not in r]
        if not utun_up:
            leak_checks.append(
                make_check(
                    "killswitch_routes",
                    "TUN 隧道与断流保护 (Kill-Switch) 风险",
                    "FAIL",
                    f"未检测到 utun 默认路由；路由={default_routes}",
                    "当前流量未走虚拟网卡 TUN 接管，极易在未挂代理环境变量的客户端中直连。",
                    "请在 Clash 中开启 Enhanced Mode / TUN 模式。",
                )
            )
        elif non_utun_defaults or scutil_info.get("scoped_private_dns"):
            leak_checks.append(
                make_check(
                    "killswitch_routes",
                    "TUN 隧道与断流保护 (Kill-Switch) 风险",
                    "WARN",
                    f"TUN 活跃 ({', '.join(utun_ips)})，但底层网卡仍有默认路由/私网 DNS",
                    f"存在物理网卡备用路由 {non_utun_defaults} 及 Scoped DNS {scutil_info.get('scoped_private_dns')}。它们与 macOS TUN 并存属于常见配置，不能据此断言正在泄漏；隧道断开后的系统级阻断尚未验证。进程保护与系统防火墙阻断是不同机制。",
                    "保持后台进程保护开启；如需系统级断隧道阻断，请核验代理客户端的断网保护能力。",
                )
            )
        else:
            leak_checks.append(
                make_check(
                    "killswitch_routes",
                    "TUN 隧道与断流保护 (Kill-Switch) 风险",
                    "PASS",
                    f"TUN 接管中 ({', '.join(utun_ips)})",
                    "默认路由与 DNS 均由 TUN 接管。",
                )
            )

    claude_file_inventory = cat_residue.pop("inventory", []) if isinstance(cat_residue, dict) else []

    categories = {
        "ip_reputation": {"title": "出口 IP 与 11 大 GeoIP / 信誉库验真", "checks": ip_checks},
        "routing_leaks": {"title": "分流、DNS、IPv6、UDP/STUN 与断流检测", "checks": leak_checks},
        "clash_proxy": cat_clash,
        "os_system": cat_os_sys,
        "claude_residue": cat_residue,
    }

    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0}
    critical_fail = 0
    high_fail = 0
    high_warn = 0
    low_warn = 0
    deductions: List[Dict[str, Any]] = []
    for cat in categories.values():
        cat_title = cat.get("title", "")
        for chk in cat["checks"]:
            st = chk["status"]
            sev = chk.get("severity", "low")
            if st in counts:
                counts[st] += 1
            if st == "FAIL":
                pts = 30 if sev == "critical" else 15
                if sev == "critical":
                    critical_fail += 1
                else:
                    high_fail += 1
                deductions.append({
                    "id": chk.get("id", ""),
                    "category": cat_title,
                    "title": chk.get("title", ""),
                    "status": st,
                    "severity": sev,
                    "points": pts,
                    "observed": chk.get("observed", ""),
                })
            elif st == "WARN":
                pts = 6 if sev == "high" else 2
                if sev == "high":
                    high_warn += 1
                else:
                    low_warn += 1
                deductions.append({
                    "id": chk.get("id", ""),
                    "category": cat_title,
                    "title": chk.get("title", ""),
                    "status": st,
                    "severity": sev,
                    "points": pts,
                    "observed": chk.get("observed", ""),
                })

    deductions.sort(key=lambda x: x["points"], reverse=True)
    penalty = critical_fail * 30 + high_fail * 15 + high_warn * 6 + low_warn * 2
    score = max(0, min(100, 100 - penalty))
    if critical_fail > 0 or score < 50:
        grade = "D"
    elif score < 70 or counts["FAIL"] > 0:
        grade = "C"
    elif score < 85 or high_warn > 0:
        grade = "B"
    elif score < 95:
        grade = "A"
    else:
        grade = "S"
    duration_ms = round((time.monotonic() - t0) * 1000.0, 1)

    return {
        "timestamp": now_iso(),
        "duration_ms": duration_ms,
        "platform": PLATFORM_KEY,
        "platform_label": PLATFORM_LABEL,
        "target": target_cfg,
        "targets_available": [{"code": k, "name": v["name"]} for k, v in TARGETS.items()],
        "egress_summary": egress_summary,
        "geoip_matrix": geoip_matrix,
        "domain_matrix": domain_matrix,
        "third_party_matrix": tp_results,
        "claude_file_inventory": claude_file_inventory,
        "categories": categories,
        "counts": counts,
        "redline_count": critical_fail,
        "overall_score": score,
        "grade": grade,
        "total_penalty": penalty,
        "deductions": deductions,
    }


RUN_MODE = "cli"
NATIVE_READY = False
PREFS_DEFAULTS = {"target": "US", "interval_sec": 30, "auto_start_monitor": True, "notify_enabled": True,
                  "protection_enabled": IS_MACOS, "local_interval_ms": 100}
_PREFS_LOCK = threading.RLock()
_PREFS = dict(PREFS_DEFAULTS)
PULSE_LOCK = threading.Lock()
PROTECTION_HISTORY = collections.deque(maxlen=100)
PROTECTION_HISTORY_LOCK = threading.Lock()
PROTECTION_LOG_PATH = os.path.join(USER_DATA_DIR, "protection-events.jsonl")


def _atomic_write(path: str, text: str) -> None:
    """Only our own runtime files. Never write inside the signed bundle."""
    fd, temporary = tempfile.mkstemp(prefix=".regionguard-", dir=os.path.dirname(path))
    try:
        if not IS_WINDOWS:
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)  # only the temporary file this call created


def _validate_prefs(changes):
    if not isinstance(changes, dict) or any(key not in PREFS_DEFAULTS for key in changes):
        raise ValueError("unknown preference")
    result = dict(changes)
    if "target" in result:
        if not isinstance(result["target"], str) or result["target"].upper() not in TARGETS:
            raise ValueError("invalid target")
        result["target"] = result["target"].upper()
    if "interval_sec" in result and (type(result["interval_sec"]) is not int or result["interval_sec"] not in {15, 30, 60}):
        raise ValueError("interval must be 15, 30 or 60")
    if "local_interval_ms" in result and (type(result["local_interval_ms"]) is not int or result["local_interval_ms"] not in {50, 100, 250, 500}):
        raise ValueError("local interval must be 50, 100, 250 or 500 ms")
    for key in ("auto_start_monitor", "notify_enabled", "protection_enabled"):
        if key in result and type(result[key]) is not bool:
            raise ValueError("preference must be boolean")
    return result


def _load_prefs():
    global _PREFS
    values = dict(PREFS_DEFAULTS)
    try:
        from audit_common import read_json
        loaded = read_json(PREFS_PATH, 65536)
        for key in PREFS_DEFAULTS:
            if key in loaded:
                try:
                    values.update(_validate_prefs({key: loaded[key]}))
                except ValueError:
                    pass
    except (OSError, ValueError, TypeError):
        pass
    with _PREFS_LOCK:
        _PREFS = values
    return get_prefs()


def get_prefs():
    with _PREFS_LOCK:
        return {**_PREFS, "run_mode": RUN_MODE}


def update_prefs(changes):
    changes = _validate_prefs(changes)
    with _PREFS_LOCK:
        values = {**_PREFS, **changes}
        _atomic_write(PREFS_PATH, json.dumps(values, ensure_ascii=False))
        _PREFS.update(values)
        MONITOR.configure(values["target"], values["interval_sec"], emit=False)
    MONITOR._emit()
    return get_prefs()


def _load_pulse_history() -> None:
    global BASELINE_IP
    try:
        with open(PULSE_LOG_PATH, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read(2 * 1024 * 1024).splitlines()
        with HISTORY_LOCK:
            PULSE_HISTORY.clear()
            BASELINE_IP = None
            for line in lines[-500:]:
                try:
                    event = json.loads(line)
                    if isinstance(event, dict) and isinstance(event.get("timestamp"), str):
                        PULSE_HISTORY.append(event)
                        if BASELINE_IP is None and event.get("ok"):
                            BASELINE_IP = event.get("ip")
                except (ValueError, TypeError):
                    pass
    except OSError:
        pass


def _append_pulse_log(event: Dict[str, Any]) -> None:
    # Called under HISTORY_LOCK after appending; never reload an unbounded log.
    try:
        _atomic_write(PULSE_LOG_PATH, "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in PULSE_HISTORY))
    except OSError:
        pass


def _clear_pulse_log() -> None:
    try:
        _atomic_write(PULSE_LOG_PATH, "")
    except OSError:
        pass


def run_pulse(target_code: str, wake_detected: bool = False) -> Dict[str, Any]:
    with PULSE_LOCK:
        started_at = time.monotonic()
        result = _run_pulse(target_code, wake_detected)
    MONITOR.observe_pulse(result["event"], started_at)
    MONITOR.publish()
    return result


def _run_pulse(target_code: str, wake_detected: bool = False) -> Dict[str, Any]:
    global BASELINE_IP
    target_code = target_code.upper()
    if target_code not in TARGETS:
        target_code = "SG"

    trace = _trace_domain("claude.ai")
    fast = MONITOR.protection.status() if MONITOR.protection is not None else {}
    if IS_MACOS and fast.get("running") and fast.get("enabled") and fast.get("last_check_age_ms") is not None and fast["last_check_age_ms"] < 1000:
        utun_up, utun_ips = fast.get("local_safe") is True, fast.get("interfaces", [])
    else:
        utun_up, utun_ips, _, _ = _check_tun_cross_platform()

    ip = trace.get("ip", "")
    loc = trace.get("loc", "").upper()
    colo = trace.get("colo", "").upper()
    ok = bool(trace.get("ok") and ip)

    with HISTORY_LOCK:
        prev = next((e for e in reversed(PULSE_HISTORY) if e.get("target") == target_code), None)
        if BASELINE_IP is None and ok:
            BASELINE_IP = ip
        changed_ip = bool(prev and prev.get("ip") and prev["ip"] != "-" and ip and prev["ip"] != ip)
        changed_loc = bool(prev and prev.get("loc") and prev["loc"] != "-" and loc and prev["loc"] != loc)
        anomaly_reasons: List[str] = []
        if not ok:
            anomaly_reasons.append(f"连接失败({trace.get('error', 'err')})")
        elif loc != target_code:
            anomaly_reasons.append(f"地区不匹配({loc} != {target_code})")
        if loc in RESTRICTED_COUNTRIES or colo in RESTRICTED_COLOS:
            anomaly_reasons.append("出口进入受限地区")
        if not utun_up:
            anomaly_reasons.append("TUN隧道离线")
        if changed_ip:
            anomaly_reasons.append(f"IP跳变({prev['ip']} -> {ip})")

        event = {
            "timestamp": now_iso(),
            "target": target_code,
            "ok": ok,
            "ip": ip or "-",
            "loc": loc or "-",
            "colo": colo or "-",
            "latency_ms": trace.get("latency_ms", 0),
            "utun_up": utun_up,
            "utun_ips": utun_ips,
            "changed_ip": changed_ip,
            "changed_loc": changed_loc,
            "wake_detected": wake_detected,
            "anomaly": bool(anomaly_reasons),
            "anomaly_reasons": anomaly_reasons,
            "error": trace.get("error", ""),
        }
        PULSE_HISTORY.append(event)
        _append_pulse_log(event)
        hist_count = len(PULSE_HISTORY)
        baseline = BASELINE_IP

    return {"event": event, "history_count": hist_count, "baseline_ip": baseline}


def _wake_gap(wall_delta, mono_delta, interval):
    return (wall_delta - mono_delta) > 8.0 or wall_delta > (interval + 15)


class MonitorController:
    """One worker, independent listeners, shared target/interval and dual-clock wake checks."""
    def __init__(self, protection=None, traffic=None, version_observer=None):
        self.protection = protection
        self.traffic = traffic
        self.version_observer = version_observer
        if protection is not None:
            protection.set_callback(self._on_protection_event)
        self._wake_requested = False
        self._lock = threading.RLock()
        self._lifecycle = threading.Lock()
        self._running = False
        self._target = "US"
        self._interval_sec = 30
        self._stop_event = threading.Event()
        self._reconfigure = threading.Event()
        self._thread = None
        self._listeners = []
        self._error = ""
        self._traffic_error = ""

    def _on_protection_event(self, snapshot):
        # Runs on a separate dispatch thread, never on the 100ms critical path.
        with PROTECTION_HISTORY_LOCK:
            PROTECTION_HISTORY.append({"timestamp": now_iso(), **snapshot})
            text = "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in PROTECTION_HISTORY)
            try:
                _atomic_write(PROTECTION_LOG_PATH, text)
            except OSError:
                pass
        if snapshot.get("local_safe") and any(code in snapshot.get("reason_codes", []) for code in ("route_pending", "wake_pending", "telemetry_pending")):
            self._reconfigure.set()
        self._emit(protection_event=snapshot)

    def observe_pulse(self, event, started_at):
        if self.protection is not None:
            self.protection.observe_pulse(event, started_at)

    def on_wake(self):
        with self._lock:
            if not self._running:
                return
            self._wake_requested = True
            self._reconfigure.set()
        if self.protection is not None:
            self.protection.on_wake()
        if self.traffic is not None:
            try:
                self.traffic.invalidate()
            except Exception:
                self._traffic_error = '连接观察状态待复核'

    def register_listener(self, callback):
        with self._lock:
            if callback not in self._listeners:
                self._listeners.append(callback)
        def unregister():
            with self._lock:
                if callback in self._listeners:
                    self._listeners.remove(callback)
        return unregister

    def publish(self):
        with self._lock:
            self._error = ""
        self._emit()

    def _emit(self, protection_event=None):
        snapshot = self.status()
        if protection_event is not None:
            # Preserve the exact transition/action for notifications even if the
            # current fast state has already recovered by the time callbacks run.
            snapshot["protection_event"] = protection_event
        with self._lock:
            callbacks = tuple(self._listeners)
        for callback in callbacks:
            try:
                callback(snapshot)
            except Exception:
                pass  # a UI listener cannot terminate the monitor

    def configure(self, target, interval, emit=True):
        with self._lock:
            changed = self._target != target or self._interval_sec != interval
            self._target, self._interval_sec = target, interval
            if changed:
                self._reconfigure.set()
        if self.protection is not None:
            prefs = get_prefs()
            previous_protection = self.protection.status()
            if self.traffic is not None and prefs['protection_enabled'] and not previous_protection.get('enabled'):
                # A purely observational period must not arm old action evidence.
                try:
                    self.traffic.invalidate(clear_actions=True)
                except Exception:
                    self._traffic_error = '连接观察状态待复核'
            self.protection.configure(target, prefs["protection_enabled"], prefs["local_interval_ms"], interval)
            if (prefs["protection_enabled"] and not previous_protection.get("enabled")
                    and previous_protection.get("supported", True)):
                self._reconfigure.set()  # enabling protection must not wait a full public-probe interval
        if emit:
            self._emit()

    def start(self, target_code="US", interval_sec=30):
        values = _validate_prefs({"target": target_code, "interval_sec": interval_sec})
        with self._lifecycle:
            with self._lock:
                previous = self._thread if self._stop_event.is_set() else None
            if previous is not None and previous.is_alive():
                previous.join(timeout=22)
                if previous.is_alive():
                    raise RuntimeError("previous monitor probe is still finishing")
            with self._lock:
                self._target, self._interval_sec = values["target"], values["interval_sec"]
                self._running = True
            if self.traffic is not None:
                try:
                    self.traffic.start()
                    self._traffic_error = ''
                except Exception:
                    self._traffic_error = '后台连接观察未能启动；当前覆盖未知'
            if self.protection is not None:
                prefs = get_prefs()
                try:
                    self.protection.start(values["target"], prefs["protection_enabled"], prefs["local_interval_ms"], interval_sec)
                except Exception:
                    with self._lock:
                        self._running = False
                        self._stop_event.set()
                        self._reconfigure.set()
                        failed_thread = self._thread
                    self.protection.stop()
                    if self.traffic is not None:
                        self.traffic.stop()
                    if failed_thread is not None and failed_thread is not threading.current_thread():
                        failed_thread.join(timeout=2)
                    raise
            with self._lock:
                if self._thread is not None and self._thread.is_alive():
                    self._running = True
                    self._reconfigure.set()
                else:
                    self._stop_event = threading.Event()
                    self._reconfigure = threading.Event()
                    self._running = True
                    self._thread = threading.Thread(target=self._loop, args=(self._stop_event,), name="rg-monitor", daemon=True)
                    self._thread.start()
        self._emit()
        return self.status()

    def stop(self):
        with self._lifecycle:
            with self._lock:
                self._running = False
                self._stop_event.set()
                self._reconfigure.set()
                thread = self._thread
            if self.protection is not None:
                self.protection.stop()
            if self.traffic is not None:
                self.traffic.stop()
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=15)
        self._emit()
        return self.status()

    def _loop(self, stop_event):
        last_wall, last_mono = time.time(), time.monotonic()
        first = True
        while not stop_event.is_set():
            with self._lock:
                target, interval = self._target, self._interval_sec
                wake_requested = self._wake_requested
                self._wake_requested = False
                self._reconfigure.clear()
            wall, mono = time.time(), time.monotonic()
            wake = wake_requested or (not first and _wake_gap(wall - last_wall, mono - last_mono, interval))
            if wake and not wake_requested and self.protection is not None:
                self.protection.on_wake()
            first = False
            if self.version_observer is not None:
                try:
                    self.version_observer.sample()  # never blocks the 100ms action worker
                except Exception:
                    pass  # a version hint cannot suppress the independent public safety probe
            try:
                run_pulse(target, wake_detected=wake)
                if wake and not stop_event.wait(2.0):
                    run_pulse(target, wake_detected=False)
            except Exception:
                with self._lock:
                    self._error = "后台探测未完成，请重试"
                self._emit()
            last_wall, last_mono = time.time(), time.monotonic()
            if stop_event.is_set():
                break
            self._reconfigure.wait(interval)

    def status(self):
        with self._lock:
            running = self._running
            target, interval, error = self._target, self._interval_sec, self._error
        with HISTORY_LOCK:
            items, baseline = list(PULSE_HISTORY), BASELINE_IP
        # A previous target's result cannot paint the newly selected target green.
        latest = next((event for event in reversed(items) if event.get("target") == target), None)
        traffic = None
        if self.traffic is not None:
            try:
                traffic = self.traffic.status()  # memory cache; no process, socket or controller IO
            except Exception:
                traffic = dict(running=False, state='unknown', reason_codes=['traffic_observer_unavailable'])
        return dict(running=running, target=target, interval_sec=interval, baseline_ip=baseline,
                    total_count=len(items), anomaly_count=sum(bool(e.get("anomaly")) for e in items),
                    jump_count=sum(bool(e.get("changed_ip")) for e in items),
                    wake_count=sum(bool(e.get("wake_detected")) for e in items),
                    latest=latest, items=items, monitor_error=error, prefs=get_prefs(),
                    protection=self.protection.status() if self.protection is not None else None,
                    traffic=traffic, traffic_error=self._traffic_error)


PROTECTOR = FastProtector(connection_provider=CLAUDE_TRAFFIC.status,
                          connection_acknowledge=CLAUDE_TRAFFIC.acknowledge)
MONITOR = MonitorController(protection=PROTECTOR, traffic=CLAUDE_TRAFFIC if IS_MACOS else None,
                            version_observer=CLIENT_VERSION if IS_MACOS else None)
_load_prefs()
MONITOR.configure(_PREFS["target"], _PREFS["interval_sec"])
_load_pulse_history()


# ---------------------------------------------------------------------------
# HTTP Server (Strictly Read-Only Detection & Scoring)
# ---------------------------------------------------------------------------
class RegionGuardHandler(http.server.BaseHTTPRequestHandler):
    server_version = "RegionGuard/3.5.0"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _check_request_security(self, is_post: bool = False) -> bool:
        if self.client_address[0] not in {"127.0.0.1", "::1", "::ffff:127.0.0.1"}:
            self._send_json(403, {"error": "forbidden client"})
            return False
        hosts = self.headers.get_all("Host", [])
        host = hosts[0] if len(hosts) == 1 else ""
        try:
            authority = urllib.parse.urlsplit("http://" + host)
            valid = (authority.hostname in {"127.0.0.1", "localhost", "::1"}
                     and not authority.username and not authority.password
                     and not authority.path and not authority.query and not authority.fragment
                     and (authority.port or 80) == self.server.server_port)
        except ValueError:
            valid = False
        if not valid:
            self._send_json(403, {"error": "forbidden host"})
            return False
        origin = self.headers.get("Origin")
        if origin:
            try:
                source = urllib.parse.urlsplit(origin)
                valid = (source.scheme == "http" and source.hostname == authority.hostname
                         and (source.port or 80) == self.server.server_port
                         and not source.username and not source.password and not source.path
                         and not source.query and not source.fragment)
            except ValueError:
                valid = False
            if not valid:
                self._send_json(403, {"error": "forbidden origin"})
                return False
        site = self.headers.get("Sec-Fetch-Site")
        if site and site not in {"same-origin", "none"}:
            self._send_json(403, {"error": "forbidden fetch site"})
            return False
        if is_post and self.headers.get("X-Region-Guard") != "1":
            self._send_json(403, {"error": "missing X-Region-Guard"})
            return False
        return True

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def _send_json(self, code: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, filename: str) -> None:
        if filename not in ALLOWED_STATIC:
            self.send_error(404, "Not found")
            return
        full_path = os.path.join(STATIC_DIR, filename)
        if not os.path.isfile(full_path):
            self.send_error(404, "Missing asset")
            return
        with open(full_path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ALLOWED_STATIC[filename])
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        if length == 0:
            return {}
        if length < 0 or length > 65536:
            raise ValueError("invalid body length")
        try:
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8", errors="replace"))
            if not isinstance(data, dict):
                raise ValueError("JSON object required")
            return data
        except (ValueError, UnicodeError):
            raise ValueError("invalid JSON body")

    def do_GET(self) -> None:
        if not self._check_request_security():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        target = (qs.get("target") or [get_prefs()["target"]])[0]

        if path == "/":
            self._send_static("index.html")
        elif path.startswith("/static/"):
            rel = path[len("/static/") :]
            self._send_static(rel)
        elif path == "/api/headers":
            self._send_json(
                200,
                {
                    "service": "RegionGuard",
                    "native_ready": NATIVE_READY,
                    "native_connections_available": native_backend_available(),
                    "accept_language": self.headers.get("Accept-Language", ""),
                    "user_agent": self.headers.get("User-Agent", ""),
                    "sec_ch_ua": self.headers.get("Sec-CH-UA", ""),
                    "sec_ch_ua_platform": self.headers.get("Sec-CH-UA-Platform", ""),
                    "sec_ch_ua_mobile": self.headers.get("Sec-CH-UA-Mobile", ""),
                    "sec_ch_ua_arch": self.headers.get("Sec-CH-UA-Arch", ""),
                    "sec_ch_ua_platform_version": self.headers.get("Sec-CH-UA-Platform-Version", ""),
                    "sec_ch_ua_full_version_list": self.headers.get("Sec-CH-UA-Full-Version-List", ""),
                    "dnt": self.headers.get("DNT", ""),
                    "remote_addr": self.client_address[0],
                    "platform": PLATFORM_KEY,
                    "platform_label": PLATFORM_LABEL,
                    "server_utc_ms": int(time.time() * 1000),
                },
            )
        elif path == "/api/scan":
            try:
                report = run_full_scan(target)
                self._send_json(200, report)
            except Exception as exc:
                self._send_json(500, {"error": "检测未能完成，请重试"})
        elif path == "/api/pulse":
            try:
                res = run_pulse(target)
                self._send_json(200, res)
            except Exception as exc:
                self._send_json(500, {"error": "检测未能完成，请重试"})
        elif path == "/api/history":
            with HISTORY_LOCK:
                items = list(PULSE_HISTORY)
                baseline = BASELINE_IP
            self._send_json(200, {"items": items, "baseline_ip": baseline})
        elif path == "/api/prefs":
            self._send_json(200, get_prefs())
        elif path == "/api/monitor/status":
            self._send_json(200, MONITOR.status())
        elif path == "/api/telemetry/status":
            TELEMETRY_SERVICE.refresh_trust()
            self._send_json(200, TELEMETRY_SERVICE.status())
        elif path == '/api/client-version/status':
            self._send_json(200, CLIENT_VERSION.status())
        elif path == '/api/traffic/status':
            self._send_json(200, CLAUDE_TRAFFIC.status())
        else:
            self.send_error(404, "Not found")

    def do_POST(self) -> None:
        global BASELINE_IP
        if not self._check_request_security(is_post=True):
            return
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        try:
            if parsed.path in {"/api/telemetry/start", "/api/telemetry/stop",
                               "/api/telemetry/trust", "/api/telemetry/launch"}:
                actions = {"start": TELEMETRY_SERVICE.start, "stop": TELEMETRY_SERVICE.stop,
                           "trust": TELEMETRY_SERVICE.trust_certificate,
                           "launch": TELEMETRY_SERVICE.launch_claude}
                try:
                    self._send_json(200, actions[parsed.path.rsplit('/', 1)[1]]())
                except RuntimeError as exc:
                    self._send_json(409, {"error": str(exc)})
            elif parsed.path == '/api/client-version/review':
                body = self._read_json_body()
                try:
                    self._send_json(200, CLIENT_VERSION.mark_reviewed(body.get('expected_versions')))
                except RuntimeError as exc:
                    self._send_json(409, {'error': str(exc)})
            elif parsed.path == "/api/history/clear":
                with HISTORY_LOCK:
                    PULSE_HISTORY.clear()
                    BASELINE_IP = None
                    _clear_pulse_log()
                MONITOR._emit()
                self._send_json(200, {"ok": True})
            elif parsed.path == "/api/prefs":
                self._send_json(200, update_prefs(self._read_json_body()))
            elif parsed.path == "/api/monitor/start":
                body = self._read_json_body()
                prefs = get_prefs()
                target = str((qs.get("target") or [body.get("target", prefs["target"])])[0])
                raw_interval = (qs.get("interval") or [body.get("interval", prefs["interval_sec"])])[0]
                interval = int(raw_interval)
                # Persist the same preferences whether the control comes from the browser or tray.
                update_prefs({"target": target, "interval_sec": interval, "auto_start_monitor": True})
                self._send_json(200, MONITOR.start(target, interval))
            elif parsed.path == "/api/monitor/stop":
                self._send_json(200, MONITOR.stop())
            else:
                self.send_error(404, "Not found")
        except (ValueError, TypeError):
            self._send_json(400, {"error": "invalid preferences or request body"})
        except RuntimeError:
            self._send_json(503, {"error": "守护未能启动，请稍后重试"})
        except OSError:
            self._send_json(500, {"error": "无法保存 RegionGuard 偏好"})


class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def create_http_server(host="127.0.0.1", preferred_port=8765):
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("server must bind to loopback")
    if type(preferred_port) is not int or not 0 <= preferred_port <= 65535:
        raise ValueError("invalid port")
    server_class = ThreadingHTTPServer
    if host == "::1":
        class IPv6HTTPServer(ThreadingHTTPServer):
            address_family = socket.AF_INET6
        server_class = IPv6HTTPServer
    candidates = [preferred_port]
    if preferred_port:
        candidates.extend(p for p in range(max(8766, preferred_port + 1), 8800) if p != preferred_port)
        candidates.append(0)
    for port in candidates:
        try:
            httpd = server_class((host, port), RegionGuardHandler)
            return httpd, httpd.server_port
        except OSError as exc:
            if exc.errno not in {errno.EADDRINUSE, errno.EACCES}:
                raise
    raise OSError("no available loopback port")


def main() -> None:
    parser = argparse.ArgumentParser(description="Region Guard local diagnostic web server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default 8765)")
    parser.add_argument("--open", action="store_true", help="Open dashboard in default browser after startup")
    parser.add_argument("--no-open", action="store_true", help="Do not auto-open browser (for frozen exe)")
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("Security guard: server only binds to loopback (127.0.0.1)")

    SHUTDOWN_EVENT.clear()
    srv, actual_port = create_http_server(args.host, args.port)
    url_host = "[::1]" if args.host == "::1" else args.host
    url = f"http://{url_host}:{actual_port}"
    print(f"Region Guard ({PLATFORM_LABEL}) running at {url}", flush=True)
    should_open = args.open or (getattr(sys, "frozen", False) and not args.no_open)
    if should_open:
        def _open_tab() -> None:
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception:
                pass
        threading.Timer(0.6, _open_tab).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if MONITOR.protection is not None:
            MONITOR.protection.stop()
        shutdown_observers()
        MONITOR.stop()
        srv.server_close()


if __name__ == "__main__":
    main()

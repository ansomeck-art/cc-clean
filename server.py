#!/usr/bin/env python3
"""
Region Guard — Local Cross-Platform (Windows / macOS) Region, Network Leak & Risk Audit Web Server.

Pure Python 3.9+ standard library backend bound strictly to 127.0.0.1.
Strictly read-only against OS, browser, proxy, and application state;
never reads or exposes secrets, tokens, passwords, or cookie values.
"""

import argparse
import collections
import concurrent.futures
import datetime
import email.utils
import http.server
import json
import locale
import os
import platform
import plistlib
import re
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
STATIC_DIR = os.path.join(RESOURCE_DIR, "static")
ALLOWED_STATIC = {
    "index.html": "text/html; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
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
    "hcaptcha.com",
    "stripe.com",
    "stripe.network",
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


PULSE_LOG_PATH = os.path.join(RUNTIME_DIR, "pulse-events.jsonl")
HISTORY_LOCK = threading.Lock()
PULSE_HISTORY: Deque[Dict[str, Any]] = collections.deque(maxlen=200)
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


def run_cmd(cmd: List[str], timeout: int = 8) -> Tuple[int, str, str]:
    try:
        kwargs: Dict[str, Any] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "timeout": timeout,
        }
        if IS_WINDOWS:
            kwargs["creationflags"] = CREATE_NO_WINDOW
        proc = subprocess.run(cmd, **kwargs)
        return proc.returncode, _decode_cmd_bytes(proc.stdout), _decode_cmd_bytes(proc.stderr)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:
        return 1, "", str(exc)


def _curl_base_cmd(timeout: int) -> List[str]:
    cmd = [CURL_BIN, "-sS", "--max-time", str(timeout)]
    if IS_WINDOWS:
        # Avoid Windows Schannel online CRL/OCSP revocation stalls behind proxies (keeps full TLS cert verification)
        cmd.append("--ssl-no-revoke")
    return cmd


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
    rc, out, err = run_cmd(cmd, timeout=timeout + 2)
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
    """Inspect active utun interfaces, default routes, and IPv6 addresses."""
    _, ifc_out, _ = run_cmd(["/sbin/ifconfig"], timeout=4)
    _, route_out, _ = run_cmd(["/usr/sbin/netstat", "-rn"], timeout=4)

    utun_ips: List[str] = []
    global_v6: List[str] = []
    cur_iface = ""
    for line in ifc_out.splitlines():
        m_iface = re.match(r"^([a-z0-9]+):", line)
        if m_iface:
            cur_iface = m_iface.group(1)
        elif cur_iface.startswith("utun") and "\tinet " in line:
            parts = line.split()
            if len(parts) >= 2:
                utun_ips.append(f"{cur_iface}: {parts[1]}")
        elif "\tinet6 " in line and cur_iface != "lo0":
            parts = line.split()
            if len(parts) >= 2:
                addr = parts[1].split("%")[0]
                if not addr.startswith(("fe80:", "::1")):
                    global_v6.append(f"{cur_iface}: {addr}")

    default_routes: List[str] = []
    for line in route_out.splitlines():
        if line.startswith("default ") or line.startswith("::/0"):
            cols = line.split()
            if cols:
                iface = cols[-1]
                gw = cols[1] if len(cols) > 1 else ""
                default_routes.append(f"{cols[0]} -> {gw} ({iface})")

    utun_up = any("utun" in r for r in default_routes) or any(
        "198.18." in u for u in utun_ips
    )
    return utun_up, utun_ips, default_routes, global_v6


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
    rc, out, _ = run_cmd(cmd, timeout=timeout + 2)
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
    rc, out, err = run_cmd(cmd, timeout=10)
    ms = round((time.monotonic() - t0) * 1000.0, 1)
    parts = out.strip().split("|", 1)
    code_str = parts[0] if parts else ""
    redir = parts[1] if len(parts) > 1 else ""
    ok = rc == 0 and code_str.isdigit() and 200 <= int(code_str) < 500
    return {
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
    rc, out, err = run_cmd(cmd, timeout=10)
    ms = round((time.monotonic() - t0) * 1000.0, 1)
    hdrs, _, meta = out.rpartition("\n__RG_META__")
    parts = meta.strip().split("|", 1)
    code_str = parts[0] if parts else ""
    redir = parts[1] if len(parts) > 1 else ""
    cf_challenge = "cf-mitigated: challenge" in hdrs.lower()
    region_redir = "app-unavailable-in-region" in redir.lower()
    blocked = region_redir or (code_str == "403" and not cf_challenge)
    ok = rc == 0 and code_str.isdigit() and 200 <= int(code_str) < 500 and not blocked
    return {
        "name": "Claude Login Edge",
        "url": "https://claude.ai/login",
        "domain": "claude.ai/login",
        "category": "edge",
        "http_code": int(code_str) if code_str.isdigit() else 0,
        "redirect_url": redir,
        "blocked": blocked,
        "cf_challenge": cf_challenge,
        "latency_ms": ms,
        "ok": ok,
        "error": (
            "redirected to app-unavailable-in-region"
            if region_redir
            else ("HTTP 403 (non-challenge)" if blocked else ("" if ok else (err.strip() or f"HTTP {code_str or rc}")))
        ),
    }


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
        "ok": True,
        "error": "",
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
        "statsig.anthropic.com",
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
    """Extract only non-secret fields (mode, dns, tun, ipv6, listeners, risk DIRECT rules, group names)."""
    result: Dict[str, Any] = {
        "exists": False,
        "mode": "",
        "ipv6": None,
        "dns_enable": None,
        "dns_enhanced_mode": "",
        "dns_nameserver": [],
        "dns_default_nameserver": [],
        "dns_proxy_server_nameserver": [],
        "dns_fallback": [],
        "tun_enable": None,
        "tun_stack": "",
        "tun_strict_route": None,
        "fakeip_risk_filters": [],
        "direct_risk_rules": [],
        "proxy_groups": [],
        "direct_listeners": [],
        "prepend_direct_count": 0,
    }
    if not os.path.isfile(path):
        return result
    result["exists"] = True
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except Exception:
        return result

    risk_rule_kw = ("claude", "anthropic", "stripe", "hcaptcha", "cloudflare", "statsig", "sentry", "datadog")
    top_sec = ""
    sub_sec = ""
    base_indent = -1
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        s = line.strip()
        low = s.lower()
        # Never touch secret/credential/node-server lines
        if re.match(r"^(?:-\s*)?(secret|password|token|uuid|server|private-key|url)\s*:", low):
            continue
        if indent == 0 and ":" in s and not s.startswith("-"):
            k, v = s.split(":", 1)
            top_sec = k.strip()
            sub_sec = ""
            base_indent = -1
            val = v.strip().strip('"').strip("'")
            if top_sec == "mode" and val:
                result["mode"] = val
            elif top_sec == "ipv6" and val:
                result["ipv6"] = val.lower() == "true"
            continue
        if top_sec in {"proxies", "proxy-providers"}:
            continue

        if top_sec == "dns":
            if ":" in s and not s.startswith("-"):
                k, v = s.split(":", 1)
                k = k.strip()
                val = v.strip().strip('"').strip("'")
                if k == "enable" and val:
                    result["dns_enable"] = val.lower() == "true"
                    sub_sec = ""
                elif k == "enhanced-mode" and val:
                    result["dns_enhanced_mode"] = val
                    sub_sec = ""
                elif k in {"nameserver", "default-nameserver", "proxy-server-nameserver", "fallback", "fake-ip-filter"}:
                    sub_sec = k
                else:
                    sub_sec = ""
            elif s.startswith("-") and sub_sec:
                val = s[1:].strip().strip('"').strip("'")
                if sub_sec == "fake-ip-filter":
                    if any(kw in val.lower() for kw in risk_rule_kw) and len(result["fakeip_risk_filters"]) < 8:
                        result["fakeip_risk_filters"].append(val[:64])
                else:
                    key_map = {
                        "nameserver": "dns_nameserver",
                        "default-nameserver": "dns_default_nameserver",
                        "proxy-server-nameserver": "dns_proxy_server_nameserver",
                        "fallback": "dns_fallback",
                    }
                    if sub_sec in key_map and val:
                        result[key_map[sub_sec]].append(val)
        elif top_sec == "tun":
            if ":" in s and not s.startswith("-"):
                k, v = s.split(":", 1)
                k = k.strip()
                val = v.strip().strip('"').strip("'")
                if k == "enable" and val:
                    result["tun_enable"] = val.lower() == "true"
                elif k == "stack" and val:
                    result["tun_stack"] = val
                elif k == "strict-route" and val:
                    result["tun_strict_route"] = val.lower() == "true"
        elif top_sec == "rules":
            if s.startswith("-") and "direct" in low and any(kw in low for kw in risk_rule_kw):
                val = s[1:].strip().strip('"').strip("'")
                if len(result["direct_risk_rules"]) < 8:
                    result["direct_risk_rules"].append(val[:72])
        elif top_sec == "proxy-groups":
            if s.startswith("- name:") or s.startswith("name:"):
                val = s.split(":", 1)[1].strip().strip('"').strip("'")
                if val:
                    result["proxy_groups"].append(val)
        elif top_sec == "listeners":
            if s.startswith("- "):
                base_indent = indent
                result["direct_listeners"].append({})
                rest = s[2:].strip()
                if ":" in rest:
                    k, v = rest.split(":", 1)
                    if k.strip() in {"name", "port", "proxy", "type"}:
                        result["direct_listeners"][-1][k.strip()] = v.strip().strip('"')
            elif result["direct_listeners"] and indent > base_indent and ":" in s:
                k, v = s.split(":", 1)
                if k.strip() in {"name", "port", "proxy", "type"}:
                    result["direct_listeners"][-1][k.strip()] = v.strip().strip('"')
        elif top_sec == "x-clash-rule-index":
            if s.startswith("prepend:"):
                sub_sec = "prepend"
            elif sub_sec == "prepend" and s.startswith("- ") and "DIRECT" in s:
                result["prepend_direct_count"] += 1

    return result


def audit_clash_proxy() -> Dict[str, Any]:
    checks: List[Dict[str, str]] = []
    _, ps_out, _ = run_cmd(["/bin/ps", "-axo", "comm"], timeout=4)
    proxy_procs = sorted(
        {
            line.strip()
            for line in ps_out.splitlines()
            if re.search(
                r"clash|mihomo|surge|sing-box|v2ray|xray|shadowrocket|stash|loon|tailscale|wireguard",
                line,
                re.I,
            )
        }
    )
    _, nc_out, _ = run_cmd(["/usr/sbin/scutil", "--nc", "list"], timeout=4)
    connected_vpns = [
        line.strip() for line in nc_out.splitlines() if "(Connected)" in line
    ]

    checks.append(
        make_check(
            "proxy_process",
            "代理 / VPN 运行状态",
            "PASS" if (proxy_procs or connected_vpns) else "WARN",
            f"进程 {len(proxy_procs)} 个; 已连接 VPN {len(connected_vpns)} 个",
            f"运行进程: {', '.join(proxy_procs) if proxy_procs else '无'}；已连接服务: {', '.join(connected_vpns) if connected_vpns else '无'}",
            "" if (proxy_procs or connected_vpns) else "请确认代理客户端已启动并连接。",
        )
    )

    active_yaml = os.path.expanduser(
        "~/Library/Group Containers/group.com.hako.network/working/active/config.yaml"
    )
    parsed = _safe_parse_clash_yaml(active_yaml)
    if parsed["exists"]:
        mode = parsed["mode"] or "unknown"
        if mode.lower() == "global":
            m_status = "PASS"
            m_detail = "当前为 Global 全局模式，所有流量统一走选定节点。"
            m_fix = ""
        elif mode.lower() == "rule":
            m_status = "WARN"
            m_detail = "当前为 Rule 规则模式，若分流规则遗漏或 DNS 回落本地，可能走直连泄露。"
            m_fix = "在访问敏感服务或排查风控时建议切为 Global，或严格核对 Anthropic/Stripe/hCaptcha 规则。"
        else:
            m_status = "FAIL"
            m_detail = f"当前模式为 {mode}，存在直连泄露风险。"
            m_fix = "在 Clash 客户端将模式切换为 Global 或严格的 Rule 模式。"
        checks.append(make_check("clash_mode", "Clash 代理模式", m_status, mode, m_detail, m_fix))

        ns_all = (
            parsed["dns_nameserver"]
            + parsed["dns_default_nameserver"]
            + parsed["dns_proxy_server_nameserver"]
        )
        has_system_dns = any(x.lower() == "system" for x in ns_all)
        dns_desc = (
            f"enhanced-mode={parsed['dns_enhanced_mode'] or '-'}, "
            f"nameserver={parsed['dns_nameserver'] or ['-']}, "
            f"default={parsed['dns_default_nameserver'] or ['-']}"
        )
        if has_system_dns:
            checks.append(
                make_check(
                    "clash_dns",
                    "Clash 内置 DNS 配置",
                    "WARN",
                    "包含 system DNS",
                    f"{dns_desc}。当前虽开了 fake-ip，但底层仍引用 system（即本机路由器 DNS），一旦切回 Rule 模式或断开瞬间会向本地路由器发起解析。",
                    "在 Clash 客户端设置中将 nameserver / default-nameserver 从 system 改为海外加密 DNS（如 https://1.1.1.1/dns-query 或 https://8.8.8.8/dns-query）。",
                )
            )
        else:
            checks.append(
                make_check(
                    "clash_dns",
                    "Clash 内置 DNS 配置",
                    "PASS",
                    dns_desc,
                    "未引用本地 system DNS，已使用独立上游 DNS。",
                )
            )

        direct_risk_rules = parsed.get("direct_risk_rules") or []
        fakeip_risk_filters = parsed.get("fakeip_risk_filters") or []
        if direct_risk_rules or fakeip_risk_filters:
            checks.append(
                make_check(
                    "clash_direct_risk_rules",
                    "Clash 规则与 Fake-IP 放行冲突",
                    "FAIL",
                    f"DIRECT 命中 {len(direct_risk_rules)} 条 | fake-ip-filter 命中 {len(fakeip_risk_filters)} 条",
                    f"检测到放行 Claude/风控域名的规则: {', '.join((direct_risk_rules + fakeip_risk_filters)[:5])}",
                    "移除 anthropic / claude / stripe / hcaptcha / statsig / cloudflare 相关的 DIRECT 或 fake-ip-filter 条目。",
                    severity="critical",
                )
            )

        direct_l = [
            f"{l.get('name', '?')}:{l.get('port', '?')}->{l.get('proxy', '?')}"
            for l in parsed["direct_listeners"]
            if l.get("proxy", "").upper() == "DIRECT"
        ]
        if direct_l or parsed["prepend_direct_count"] > 0:
            checks.append(
                make_check(
                    "clash_direct_bypass",
                    "Clash 直连监听与前置放行规则",
                    "INFO",
                    f"直连监听 {len(direct_l)} 个, 前置 DIRECT {parsed['prepend_direct_count']} 条",
                    f"直连端口: {', '.join(direct_l) if direct_l else '无'}。请确认没有把浏览器/Claude 配置到直连监听端口。",
                )
            )
    else:
        checks.append(
            make_check(
                "clash_config_missing",
                "Clash 配置文件探测",
                "INFO",
                "未发现 Clash working/active/config.yaml",
                "若你使用的是其他代理客户端，这是正常的；可参考上方通道与 DNS 实测结果。",
            )
        )

    profiles_json = os.path.expanduser(
        "~/Library/Group Containers/group.com.hako.network/working/store/profiles.json"
    )
    if os.path.isfile(profiles_json):
        try:
            pdata = json.load(open(profiles_json, "r", encoding="utf-8"))
            if isinstance(pdata, list):
                prof_summaries: List[str] = []
                risky_alt = False
                for item in pdata:
                    if not isinstance(item, dict):
                        continue
                    lbl = str(item.get("label") or item.get("id") or "?")
                    smap = item.get("selectedMap") if isinstance(item.get("selectedMap"), dict) else {}
                    g_pick = smap.get("GLOBAL", "-")
                    if lbl.lower() == "direct" or g_pick in {"DIRECT", "PROXY", "AUTO"}:
                        risky_alt = True
                    prof_summaries.append(f"{lbl}(GLOBAL={g_pick})")
                checks.append(
                    make_check(
                        "clash_profiles",
                        "Clash 备用配置档检查",
                        "WARN" if risky_alt else "INFO",
                        f"共 {len(prof_summaries)} 个配置: {', '.join(prof_summaries[:6])}",
                        "检测到 Direct 或含其他分流策略的备用配置档；切换配置档会导致节点或 DNS 瞬间回落。",
                        "使用 Claude 期间请勿误切回 Direct 或未审计的备用配置。" if risky_alt else "",
                    )
                )
        except Exception:
            pass

    return {"title": "代理与 Clash 配置 (脱敏)", "checks": checks}


# ---------------------------------------------------------------------------
# Category 4: macOS System Locale, Country, Timezone, Location, Hostname
# ---------------------------------------------------------------------------
def _read_system_country() -> str:
    plist_path = "/Library/Preferences/.GlobalPreferences.plist"
    try:
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)
            c = data.get("Country", "")
            if c:
                return str(c)
    except Exception:
        pass
    rc, out, _ = run_cmd(["/usr/bin/defaults", "read", "/Library/Preferences/.GlobalPreferences", "Country"], timeout=4)
    return out.strip() if rc == 0 else ""


def _read_auto_timezone() -> Optional[bool]:
    plist_path = "/Library/Preferences/com.apple.timezone.auto.plist"
    try:
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)
            if "Active" in data:
                return bool(data["Active"])
    except Exception:
        pass
    rc, out, _ = run_cmd(["/usr/bin/defaults", "read", "/Library/Preferences/com.apple.timezone.auto", "Active"], timeout=4)
    if rc == 0:
        return out.strip() in {"1", "true", "YES"}
    return None


def audit_macos_system(target_cfg: Dict[str, Any]) -> Dict[str, Any]:
    checks: List[Dict[str, str]] = []
    t_code = target_cfg["code"]

    # 1. System-level Country
    sys_country = _read_system_country()
    if sys_country.upper() == t_code:
        checks.append(make_check("sys_country", "系统级区域代码 (GlobalPreferences Country)", "PASS", sys_country, f"系统级区域已设置为 {t_code}。"))
    elif sys_country.upper() in RESTRICTED_COUNTRIES:
        checks.append(
            make_check(
                "sys_country",
                "系统级区域代码 (GlobalPreferences Country)",
                "FAIL",
                sys_country,
                f"系统级 /Library/Preferences/.GlobalPreferences.plist 中 Country 仍为 {sys_country}，与目标地区 {t_code} 冲突。",
                f"在终端执行管理员命令改为 {t_code}。",
                f'sudo defaults write /Library/Preferences/.GlobalPreferences Country -string "{t_code}"',
                severity="high",
            )
        )
    else:
        checks.append(
            make_check(
                "sys_country",
                "系统级区域代码 (GlobalPreferences Country)",
                "WARN",
                sys_country or "<unset>",
                f"系统级 Country 为 {sys_country or '未设置'}，与目标 {t_code} 不一致。",
                f"建议统一设置为 {t_code}。",
                f'sudo defaults write /Library/Preferences/.GlobalPreferences Country -string "{t_code}"',
                severity="high",
            )
        )

    # 2. User AppleLocale & AppleLanguages
    _, loc_out, _ = run_cmd(["/usr/bin/defaults", "read", "-g", "AppleLocale"], timeout=3)
    _, lang_out, _ = run_cmd(["/usr/bin/defaults", "read", "-g", "AppleLanguages"], timeout=3)
    user_locale = loc_out.strip()
    langs = [x.strip(' ",()') for x in lang_out.splitlines() if x.strip(' ",()')]
    primary_lang = langs[0] if langs else ""
    if (user_locale in target_cfg["locales"] or user_locale.endswith(f"_{t_code}")) and not any(
        x.lower().startswith("zh-cn") or x.lower().startswith("zh_cn") for x in langs
    ):
        checks.append(
            make_check(
                "user_locale",
                "用户级语言与地区 (AppleLocale / AppleLanguages)",
                "PASS",
                f"{user_locale} / {', '.join(langs[:3])}",
                "用户级系统区域与首选语言符合目标地区。",
            )
        )
    else:
        checks.append(
            make_check(
                "user_locale",
                "用户级语言与地区 (AppleLocale / AppleLanguages)",
                "WARN",
                f"{user_locale or '?'} / {', '.join(langs[:3])}",
                f"用户级地区或语言偏离目标 {t_code}（当前 {user_locale} / {primary_lang}）。",
                "在 System Settings -> General -> Language & Region 调整首选语言与 Region。",
            )
        )

    # 3. NSLinguisticDataAssetsRequested
    _, ling_out, _ = run_cmd(["/usr/bin/defaults", "read", "-g", "NSLinguisticDataAssetsRequested"], timeout=3)
    ling_items = [x.strip(' ",()') for x in ling_out.splitlines() if x.strip(' ",()')]
    if any(x.lower().startswith("zh") for x in ling_items):
        checks.append(
            make_check(
                "ling_assets",
                "语言资源请求历史 (NSLinguisticDataAssetsRequested)",
                "WARN",
                ", ".join(ling_items),
                "系统中留存了中文语言资源请求记录。",
                "可执行命令清理为仅 en。",
                'defaults write -g NSLinguisticDataAssetsRequested -array "en"',
            )
        )
    else:
        checks.append(
            make_check(
                "ling_assets",
                "语言资源请求历史 (NSLinguisticDataAssetsRequested)",
                "PASS",
                ", ".join(ling_items) or "en",
                "无中文语言资源请求残留。",
            )
        )

    # 4. System Timezone & Stale Process Reboot Check
    tz_link = ""
    tz_mtime = 0.0
    try:
        tz_link = os.readlink("/etc/localtime")
        tz_mtime = os.lstat("/etc/localtime").st_mtime
    except Exception:
        pass
    tz_name = tz_link.split("/zoneinfo/")[-1] if "/zoneinfo/" in tz_link else tz_link
    local_dt = datetime.datetime.now().astimezone()
    offset_sec = int(local_dt.utcoffset().total_seconds()) if local_dt.utcoffset() else 0

    _, boot_out, _ = run_cmd(["/usr/sbin/sysctl", "-n", "kern.boottime"], timeout=3)
    boot_m = re.search(r"sec\s*=\s*(\d+)", boot_out)
    boot_sec = int(boot_m.group(1)) if boot_m else 0

    tz_is_restricted = tz_name in RESTRICTED_TIMEZONES
    if tz_name:
        tz_ok = (tz_name in target_cfg["timezones"]) and (not tz_is_restricted)
    else:
        tz_ok = offset_sec in target_cfg["utc_offsets_sec"]

    if not tz_ok:
        tz_sev = "critical" if tz_is_restricted else "high"
        checks.append(
            make_check(
                "sys_timezone",
                "系统时区 (/etc/localtime)",
                "FAIL",
                f"{tz_name or '未知'} (UTC{offset_sec/3600:+.1f})",
                f"当前系统时区为 {tz_name or '未知'}，与目标地区 {target_cfg['name']} 不匹配（即使同为 UTC+8，Asia/Shanghai 也会被直接识别为中国区）。",
                f"将系统时区改为 {target_cfg['timezones'][0]} 并重启。",
                f"sudo systemsetup -settimezone {target_cfg['timezones'][0]}",
                severity=tz_sev,
            )
        )
    elif boot_sec and tz_mtime > boot_sec:
        tz_changed_str = datetime.datetime.fromtimestamp(tz_mtime).strftime("%Y-%m-%d %H:%M")
        boot_str = datetime.datetime.fromtimestamp(boot_sec).strftime("%Y-%m-%d %H:%M")
        checks.append(
            make_check(
                "sys_timezone",
                "系统时区与重启刷新状态",
                "WARN",
                f"{tz_name}（改于 {tz_changed_str}，上次开机 {boot_str}）",
                "系统时区本身已是目标时区，但你修改时区后尚未重启 Mac；开机前启动的常驻进程仍可能缓存修改前的旧时区。",
                "完成全部系统修改后完整重启一次 Mac，再打开 Claude 或浏览器。",
                severity="high",
            )
        )
    else:
        checks.append(
            make_check(
                "sys_timezone",
                "系统时区与重启刷新状态",
                "PASS",
                f"{tz_name} ({local_dt.strftime('%z')})",
                "系统时区与目标一致，且自上次重启以来未再发生时区跳变。",
            )
        )

    # 5. Auto Timezone
    auto_tz = _read_auto_timezone()
    if auto_tz is True:
        checks.append(
            make_check(
                "auto_timezone",
                "自动设置时区 (timezone.auto)",
                "WARN",
                "已开启 (Active = 1)",
                "开启自动时区会依据物理位置/Wi-Fi 定位自动覆盖当前时区，唤醒或重连网络时有切回真实时区的风险。",
                "关闭自动设置时区并锁定为目标时区。",
                "sudo defaults write /Library/Preferences/com.apple.timezone.auto Active -bool false",
                severity="high",
            )
        )
    elif auto_tz is False:
        checks.append(
            make_check(
                "auto_timezone",
                "自动设置时区 (timezone.auto)",
                "PASS",
                "已关闭 (Active = 0)",
                "已锁定手动时区，不会被位置服务自动覆盖。",
            )
        )
    else:
        checks.append(make_check("auto_timezone", "自动设置时区 (timezone.auto)", "INFO", "未知", "无法读取自动时区配置。"))

    # 6. Location Services
    _, loc_ps, _ = run_cmd(["/bin/ps", "-axo", "comm"], timeout=3)
    loc_procs = [p.strip() for p in loc_ps.splitlines() if p.strip().endswith(("/locationd", "/com.apple.geod"))]
    loc_enabled_pref = None
    _, loc_pref_out, _ = run_cmd(
        ["/usr/bin/defaults", "read", "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd", "LocationServicesEnabled"],
        timeout=3,
    )
    if loc_pref_out.strip() in {"0", "1"}:
        loc_enabled_pref = loc_pref_out.strip() == "1"

    if loc_enabled_pref is False:
        checks.append(make_check("location_services", "macOS 定位服务 (Wi-Fi 物理定位)", "PASS", "已关闭", "系统定位服务已关闭。"))
    else:
        checks.append(
            make_check(
                "location_services",
                "macOS 定位服务 (Wi-Fi 物理定位)",
                "WARN",
                f"相关守护进程运行中 ({len(loc_procs)} 个)" if loc_procs else "状态未关闭（受 TCC 保护需手动核对）",
                "macOS 定位依靠周边 Wi-Fi 物理信号（BSSID）测算位置，完全绕过代理隧道。",
                "在 System Settings -> Privacy & Security -> Location Services 关闭定位服务，或至少关闭 Safari / Claude 及 System Services -> Setting Time Zone。",
            )
        )

    # 7. Hostnames (ComputerName / LocalHostName / HostName / SMB NetBIOSName)
    _, cn, _ = run_cmd(["/usr/sbin/scutil", "--get", "ComputerName"], timeout=3)
    _, lhn, _ = run_cmd(["/usr/sbin/scutil", "--get", "LocalHostName"], timeout=3)
    rc_hn, hn, _ = run_cmd(["/usr/sbin/scutil", "--get", "HostName"], timeout=3)
    rc_smb, smb_nb, _ = run_cmd(
        ["/usr/bin/defaults", "read", "/Library/Preferences/SystemConfiguration/com.apple.smb.server", "NetBIOSName"],
        timeout=3,
    )
    cn = cn.strip()
    lhn = lhn.strip()
    hn_disp = hn.strip() if rc_hn == 0 and hn.strip() else "<unset>"
    smb_disp = smb_nb.strip() if rc_smb == 0 and smb_nb.strip() else "<unset>"

    bad_host_reasons: List[str] = []
    for label, val in [
        ("ComputerName", cn),
        ("LocalHostName", lhn),
        ("HostName", "" if hn_disp == "<unset>" else hn_disp),
        ("NetBIOSName", "" if smb_disp == "<unset>" else smb_disp),
    ]:
        if not val:
            continue
        if has_cjk(val) or has_non_ascii(val):
            bad_host_reasons.append(f"{label} 含非英文字符({val})")
        elif any(p in val.lower() for p in ["deimac", "demac", "diannao", "zh-cn"]):
            bad_host_reasons.append(f"{label} 含中文拼音特征({val})")

    host_obs = f"ComputerName={cn or '-'} | LocalHostName={lhn or '-'} | HostName={hn_disp} | NetBIOS={smb_disp}"
    if bad_host_reasons:
        checks.append(
            make_check(
                "hostnames",
                "电脑名、主机名与 SMB NetBIOS 特征",
                "FAIL",
                host_obs,
                f"检测到明显中文/拼音命名特征：{'; '.join(bad_host_reasons)}。Claude Desktop 会直接读取并上报为 remoteToolsDeviceName。",
                "将 ComputerName、LocalHostName、HostName 及 SMB NetBIOSName 统一改为纯英文名称。",
                'sudo scutil --set ComputerName "My-Mac" && sudo scutil --set LocalHostName "My-Mac" && sudo scutil --set HostName "My-Mac" && sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server NetBIOSName -string "My-Mac"',
                severity="high",
            )
        )
    else:
        checks.append(make_check("hostnames", "电脑名、主机名与 SMB NetBIOS 特征", "PASS", host_obs, "主机名与局域网 NetBIOS 名均为纯英文，无中文或拼音残留。"))

    # 8. Input Method (Selected + Current Layout ID + All Enabled)
    _, im_out, _ = run_cmd(["/usr/bin/defaults", "read", "com.apple.HIToolbox", "AppleSelectedInputSources"], timeout=3)
    _, en_im_out, _ = run_cmd(["/usr/bin/defaults", "read", "com.apple.HIToolbox", "AppleEnabledInputSources"], timeout=3)
    rc_lay, cur_layout_id, _ = run_cmd(
        ["/usr/bin/defaults", "read", "com.apple.HIToolbox", "AppleCurrentKeyboardLayoutInputSourceID"],
        timeout=3,
    )
    cur_layout_id = cur_layout_id.strip() if rc_lay == 0 else ""
    enabled_names: List[str] = []
    for line in en_im_out.splitlines():
        m_lay = re.search(r'"KeyboardLayout Name"\s*=\s*"?([^";]+)"?;', line)
        m_mode = re.search(r'"Input Mode"\s*=\s*"?([^";]+)"?;', line)
        if m_lay and m_lay.group(1).strip() not in enabled_names:
            enabled_names.append(m_lay.group(1).strip())
        elif m_mode:
            short_mode = m_mode.group(1).strip().split(".")[-1]
            if short_mode not in enabled_names:
                enabled_names.append(short_mode)

    is_cn_im = (
        any(k in im_out for k in ["SCIM", "Pinyin", "Sogou", "Rime"])
        or any(k in cur_layout_id for k in ["Pinyin", "SCIM", "Sogou", "Rime"])
    )
    im_label = "中文输入法 (SCIM/拼音)" if is_cn_im else "英文键盘"
    en_list_str = ", ".join(enabled_names) if enabled_names else "-"
    lay_part = f" | LayoutID={cur_layout_id.split('.')[-1]}" if cur_layout_id else ""
    checks.append(
        make_check(
            "input_method",
            "键盘输入法 (当前激活 & 布局 ID & 已启用)",
            "WARN" if is_cn_im else "PASS",
            f"当前={im_label}{lay_part} | 已启用=[{en_list_str}]",
            "平时打字保留中文输入法正常，但注册/登录新号或过人机验证时建议切到 ABC 英文键盘，避免键盘布局 ID 暴露拼音状态。" if is_cn_im else f"当前激活为英文键盘（已启用列表: {en_list_str}）。",
            "注册/登录 Claude 前在顶部菜单栏切至 ABC 英文键盘。" if is_cn_im else "",
        )
    )

    # 9. Wi-Fi Country Code
    _, wifi_out, _ = run_cmd(["/usr/sbin/system_profiler", "SPAirPortDataType"], timeout=6)
    cc_m = re.search(r"Country Code:\s*([A-Za-z0-9]+)", wifi_out)
    loc_m = re.search(r"Locale:\s*([A-Za-z0-9_]+)", wifi_out)
    wifi_cc = cc_m.group(1) if cc_m else ""
    wifi_loc = loc_m.group(1) if loc_m else ""
    if wifi_cc.upper() in RESTRICTED_COUNTRIES:
        w_status = "FAIL"
        w_detail = f"Wi-Fi 网卡当前广播国家码为 {wifi_cc}，说明周边路由器正在广播受限地区 802.11d 国家码。"
    elif wifi_cc.upper() == t_code:
        w_status = "PASS"
        w_detail = f"Wi-Fi 国家码与目标地区 {t_code} 一致。"
    else:
        w_status = "INFO"
        w_detail = f"Wi-Fi 网卡国家码={wifi_cc or '未知'} / Locale={wifi_loc or '未知'}（X2/RoW 为通用国际/未知区码，网页通常无法直接读取，但需警惕部分原生客户端）。"
    checks.append(make_check("wifi_cc", "Wi-Fi 无线国家码 (802.11d)", w_status, f"{wifi_cc or '-'} / {wifi_loc or '-'}", w_detail))

    # 10. launchd GUI Environment Vars (TZ / LANG / proxy)
    env_hits: Dict[str, str] = {}
    for var in ["TZ", "LANG", "LC_ALL", "http_proxy", "https_proxy", "all_proxy"]:
        rc_e, val_e, _ = run_cmd(["/bin/launchctl", "getenv", var], timeout=2)
        if rc_e == 0 and val_e.strip():
            env_hits[var] = val_e.strip()
    bad_env = [
        f"{k}={v}"
        for k, v in env_hits.items()
        if ("shanghai" in v.lower() or "zh_cn" in v.lower() or "zh-cn" in v.lower())
    ]
    if bad_env:
        checks.append(
            make_check(
                "launchd_env",
                "GUI launchd 环境变量 (TZ / LANG / 代理)",
                "WARN",
                ", ".join(bad_env),
                "launchd 中设置了偏离目标地区的 TZ/LANG 变量，所有桌面 App 启动时都会继承。",
                "执行 launchctl unsetenv 清理对应变量并重启相关 App。",
            )
        )
    else:
        checks.append(
            make_check(
                "launchd_env",
                "GUI launchd 环境变量 (TZ / LANG / 代理)",
                "PASS",
                ", ".join(f"{k}={v}" for k, v in env_hits.items()) or "全部未设置 (跟随系统)",
                "GUI 启动环境未注入中国区 TZ/LANG 或异常代理环境变量。",
            )
        )

    # 10b. Shell / CLI Proxy & Claude Env Audit (Process env + ~/.zshrc etc., redacted)
    shell_target_vars = {
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy",
        "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
        "TZ", "LANG", "LC_ALL",
    }
    shell_findings: List[str] = []
    shell_risky = False
    for vk in sorted(shell_target_vars):
        vv = os.environ.get(vk, "").strip()
        if not vv:
            continue
        if vk in {"LANG", "LC_ALL"} and vv in {"C.UTF-8", "C", "en_US.UTF-8", "en_SG.UTF-8"}:
            continue
        if any(s in vk for s in ["KEY", "TOKEN", "SECRET", "PASSWORD"]):
            shell_findings.append(f"env:{vk}=<REDACTED>")
        else:
            clean_v = re.sub(r"://[^/@\s]+@", "://<REDACTED>@", vv)
            shell_findings.append(f"env:{vk}={clean_v}")
            if "proxy" in vk.lower() or vk == "ANTHROPIC_BASE_URL" or any(x in vv.lower() for x in ["shanghai", "zh_cn", "zh-cn"]):
                shell_risky = True

    rc_files = [os.path.expanduser(p) for p in ["~/.zshrc", "~/.zprofile", "~/.zshenv", "~/.bash_profile", "~/.bashrc"]]
    pat_rc = re.compile(
        r"^\s*(?:export\s+)?(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|http_proxy|https_proxy|all_proxy|no_proxy|ANTHROPIC_[A-Z0-9_]+|CLAUDE_[A-Z0-9_]+|TZ|LANG|LC_ALL)\s*=\s*(.+)$"
    )
    for rcf in rc_files:
        if not os.path.isfile(rcf):
            continue
        try:
            with open(rcf, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    m = pat_rc.match(s)
                    if not m:
                        continue
                    k_rc, v_rc = m.group(1), m.group(2).strip().strip('"').strip("'")
                    if any(sec in k_rc for sec in ["KEY", "TOKEN", "SECRET", "PASSWORD"]):
                        shell_findings.append(f"{os.path.basename(rcf)}:{k_rc}=<REDACTED>")
                    else:
                        clean_v = re.sub(r"://[^/@\s]+@", "://<REDACTED>@", v_rc)
                        shell_findings.append(f"{os.path.basename(rcf)}:{k_rc}={clean_v}")
                        if "proxy" in k_rc.lower() or k_rc == "ANTHROPIC_BASE_URL" or any(x in v_rc.lower() for x in ["shanghai", "zh_cn", "zh-cn"]):
                            shell_risky = True
        except Exception:
            pass

    checks.append(
        make_check(
            "shell_proxy_env",
            "终端 Shell / CLI 代理与 Claude 环境变量",
            "WARN" if shell_risky else "PASS",
            ", ".join(shell_findings[:6]) if shell_findings else "无代理/中转站/异常区域变量",
            "发现终端代理或中转站配置，运行 Claude Code CLI 时可能走不同于 Clash TUN 的路径或覆盖区域设置。" if shell_risky else "终端环境与配置文件未注入异常代理、中转或中文区域变量。",
            "确认 Claude Code CLI 与桌面端共用同一出口，避免残留旧代理端口或 ANTHROPIC_BASE_URL。" if shell_risky else "",
            severity="high" if shell_risky else "low",
        )
    )

    # 11. /etc/hosts custom overrides
    custom_hosts: List[str] = []
    try:
        with open("/etc/hosts", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split()
                if len(parts) >= 2 and parts[1] not in {"localhost", "broadcasthost"}:
                    custom_hosts.append(s[:80])
    except Exception:
        pass
    if custom_hosts:
        checks.append(
            make_check(
                "etc_hosts",
                "/etc/hosts 自定义域名劫持检测",
                "WARN",
                f"发现 {len(custom_hosts)} 条自定义条目",
                f"条目: {'; '.join(custom_hosts[:5])}",
                "确认其中不包含 claude / anthropic / stripe / cloudflare 的陈旧绑定。",
            )
        )
    else:
        checks.append(make_check("etc_hosts", "/etc/hosts 自定义域名劫持检测", "PASS", "仅默认 localhost 条目", "未发现自定义 hosts 劫持。"))

    # 12. Installed Apps Awareness (Remote control / proxy / CN apps)
    try:
        apps = sorted(os.listdir("/Applications"))
        flagged = [
            a for a in apps
            if any(k in a.lower() for k in ["clash", "shadow", "surge", "awesun", "sunlogin", "todesk", "wechat", "qq", "tailscale", "wireguard", "vpn"])
        ]
        checks.append(
            make_check(
                "installed_apps_info",
                "本机网络/远控/常用软件环境提示",
                "INFO",
                ", ".join(flagged) if flagged else "无特殊项",
                "已安装列表仅作隔离参考（网页沙箱读不到此目录）；注意不要将浏览器或 Claude 走向日葵等直连远控通道。",
            )
        )
    except Exception:
        pass

    # 13. Apple AuthKit Locale, Spell Language & Collation
    _, ak_loc, _ = run_cmd(["/usr/bin/defaults", "read", "-g", "AKLastLocale"], timeout=3)
    _, sp_lang, _ = run_cmd(["/usr/bin/defaults", "read", "-g", "NSPreferredSpellServerLanguage"], timeout=3)
    _, col_ord, _ = run_cmd(["/usr/bin/defaults", "read", "-g", "AppleCollationOrder"], timeout=3)
    ak_loc = ak_loc.strip()
    sp_lang = sp_lang.strip()
    col_ord = col_ord.strip()
    ak_bad = [
        f"{k}={v}"
        for k, v in [("AKLastLocale", ak_loc), ("SpellLang", sp_lang), ("Collation", col_ord)]
        if v and any(x in v.lower() for x in ["zh_cn", "zh-cn", "zh_hans", "zh-hans"])
    ]
    ak_obs = f"AKLastLocale={ak_loc or '-'} | Spell={sp_lang or '自动'} | Collation={col_ord or '默认'}"
    if ak_bad:
        checks.append(
            make_check(
                "ak_locale_format",
                "Apple AuthKit 地区与系统拼写配置",
                "WARN",
                ak_obs,
                f"检测到中国区系统子项残留: {', '.join(ak_bad)}。",
                "检查 System Settings -> Language & Region 与 Keyboard -> Spelling，将拼写语言固定为 English 或 Automatic。",
            )
        )
    else:
        checks.append(
            make_check(
                "ak_locale_format",
                "Apple AuthKit 地区与系统拼写配置",
                "PASS",
                ak_obs,
                "Apple AuthKit 缓存地区、拼写语言与排序规则均无中国区残留。",
            )
        )

    # 14. Sleep / Power Nap Wake-Leak Risk (prevents sleep/wake ERR_NETWORK_CHANGED)
    rc_pm, pm_out, _ = run_cmd(["/usr/bin/pmset", "-g"], timeout=3)
    if rc_pm == 0 and pm_out:
        pm_map: Dict[str, str] = {}
        for line in pm_out.splitlines():
            m_pm = re.match(r"^\s*([a-zA-Z0-9_]+)\s+([^\s]+)", line)
            if m_pm:
                pm_map[m_pm.group(1).lower()] = m_pm.group(2)
        powernap = pm_map.get("powernap", "")
        standby = pm_map.get("standby", "")
        tcpkeep = pm_map.get("tcpkeepalive", "")
        pm_obs = f"powernap={powernap or '-'} | standby={standby or '-'} | tcpkeepalive={tcpkeep or '-'}"
        if powernap == "1":
            checks.append(
                make_check(
                    "power_sleep_leak",
                    "休眠与 Power Nap 后台断流风险",
                    "WARN",
                    pm_obs,
                    "Power Nap 已开启（1）：Mac 休眠期间会在后台自动唤醒网卡拉取数据，此时 Clash TUN 尚未就绪极易触发 net::ERR_NETWORK_CHANGED 或物理网卡直连漏出真实 IP（也是之前被风控的典型诱因）。",
                    "关闭 Power Nap，并在 Mac 休眠前退出 Claude Desktop 或浏览器敏感页面。",
                    "sudo pmset -a powernap 0",
                    severity="high",
                )
            )
        else:
            checks.append(
                make_check(
                    "power_sleep_leak",
                    "休眠与 Power Nap 后台断流风险",
                    "PASS",
                    pm_obs,
                    "Power Nap 已关闭，可降低休眠期间后台网络唤醒导致的代理断流风险。",
                )
            )

    # 15. Network Services, Multi-VPN Conflict & Interface Proxy/DNS Audit
    rc_ns, ns_out, _ = run_cmd(["/usr/sbin/networksetup", "-listallnetworkservices"], timeout=4)
    if rc_ns == 0 and ns_out:
        services = [
            l.strip()
            for l in ns_out.splitlines()
            if l.strip() and not l.startswith("An asterisk") and not l.startswith("*")
        ]
        vpn_svcs = [
            s for s in services
            if any(k in s.lower() for k in ["clash", "shadowrocket", "surge", "vpn", "wireguard", "tailscale", "mihomo", "stash"])
        ]
        cn_dns_hits: List[str] = []
        sys_proxy_hits: List[str] = []
        for iface in [s for s in services if s in {"Wi-Fi", "Ethernet"}][:2]:
            _, dns_o, _ = run_cmd(["/usr/sbin/networksetup", "-getdnsservers", iface], timeout=3)
            for dline in dns_o.splitlines():
                d_ip = dline.strip()
                if d_ip in CN_DNS_SERVERS:
                    cn_dns_hits.append(f"{iface}:{d_ip}")
            for flag, label in [("-getwebproxy", "HTTP"), ("-getsecurewebproxy", "HTTPS"), ("-getsocksfirewallproxy", "SOCKS")]:
                _, po, _ = run_cmd(["/usr/sbin/networksetup", flag, iface], timeout=3)
                if "Enabled: Yes" in po:
                    srv = re.search(r"Server:\s*(.+)", po)
                    prt = re.search(r"Port:\s*(\d+)", po)
                    sys_proxy_hits.append(f"{iface} {label}={srv.group(1).strip() if srv else '?'}:{prt.group(1) if prt else '?'}")
            _, pac_o, _ = run_cmd(["/usr/sbin/networksetup", "-getautoproxyurl", iface], timeout=3)
            if "Enabled: Yes" in pac_o:
                sys_proxy_hits.append(f"{iface} PAC=已开启")

        ns_obs = f"代理服务={vpn_svcs or ['无']} | 系统代理={sys_proxy_hits or ['无(纯TUN)']} | 网卡国内DNS={cn_dns_hits or ['无']}"
        if cn_dns_hits:
            checks.append(
                make_check(
                    "network_services_proxy",
                    "网卡 DNS、系统代理与多代理服务冲突",
                    "FAIL",
                    ns_obs,
                    f"物理网卡手动配置了国内公共 DNS ({', '.join(cn_dns_hits)})，代理断开瞬间会立即向国内 DNS 发送解析请求。",
                    "清空物理网卡的国内手动 DNS，或改为 1.1.1.1 / 8.8.8.8。",
                    severity="high",
                )
            )
        elif len(vpn_svcs) > 1:
            checks.append(
                make_check(
                    "network_services_proxy",
                    "网卡 DNS、系统代理与多代理服务冲突",
                    "WARN",
                    ns_obs,
                    f"系统中同时注册了多个代理/VPN 服务 ({', '.join(vpn_svcs)})，切勿同时开启以免路由表与 DNS 抢占造成分叉。",
                    "仅保持单一主力代理（如 Clash）连接，其他 VPN 服务保持断开。",
                )
            )
        else:
            checks.append(
                make_check(
                    "network_services_proxy",
                    "网卡 DNS、系统代理与多代理服务冲突",
                    "PASS",
                    ns_obs,
                    "物理网卡未配置国内公共 DNS，也无异常系统代理或多重代理冲突。",
                )
            )

    # 16. NTP Time Server (/etc/ntp.conf)
    ntp_servers: List[str] = []
    try:
        if os.path.isfile("/etc/ntp.conf"):
            with open("/etc/ntp.conf", "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    s = line.strip()
                    if s.startswith("server "):
                        ntp_servers.append(s.split()[1])
    except Exception:
        pass
    cn_ntp = [s for s in ntp_servers if any(k in s.lower() for k in ["cn.", "aliyun", "tencent", "ntsc", "baidu", "tuna", "ustc"])]
    if cn_ntp:
        checks.append(
            make_check(
                "ntp_time_server",
                "系统时间同步服务器 (/etc/ntp.conf)",
                "WARN",
                ", ".join(ntp_servers),
                f"时间服务器包含国内节点 ({', '.join(cn_ntp)})。",
                "建议改为 time.apple.com。",
                "sudo systemsetup -setnetworktimeserver time.apple.com",
            )
        )
    else:
        checks.append(
            make_check(
                "ntp_time_server",
                "系统时间同步服务器 (/etc/ntp.conf)",
                "PASS",
                ", ".join(ntp_servers) if ntp_servers else "系统默认 (time.apple.com)",
                "未配置国内 NTP 服务器。",
            )
        )

    # 17. MITM / Custom Root CA Trust Settings (TLS fingerprint / pinning safety)
    mitm_hits: List[str] = []
    for t_args in [["/usr/bin/security", "dump-trust-settings"], ["/usr/bin/security", "dump-trust-settings", "-d"]]:
        rc_t, t_out, _ = run_cmd(t_args, timeout=4)
        if rc_t == 0 and t_out:
            for line in t_out.splitlines():
                if "Cert " in line and any(
                    k in line.lower()
                    for k in ["charles", "proxyman", "mitmproxy", "fiddler", "burp", "whistle", "surge", "clash", "http toolkit"]
                ):
                    mitm_hits.append(line.strip()[:80])
    if mitm_hits:
        checks.append(
            make_check(
                "mitm_trust_certs",
                "自定义 MITM 抓包根证书检测",
                "WARN",
                f"发现 {len(mitm_hits)} 个抓包/代理根证书",
                f"检测到: {'; '.join(mitm_hits[:4])}。若开启 HTTPS 解密会破坏浏览器/Electron 原本的 JA3/JA4 TLS 指纹，极易触发 Cloudflare/风控拦截。",
                "登录 Claude 时务必关闭一切 HTTPS 解密/抓包代理。",
                severity="high",
            )
        )
    else:
        checks.append(
            make_check(
                "mitm_trust_certs",
                "自定义 MITM 抓包根证书检测",
                "PASS",
                "未发现抓包工具信任根证书",
                "系统与用户信任库中未发现 Charles / Proxyman / mitmproxy 等抓包根证书。",
            )
        )

    # 18. Hardware Device Identifier Awareness (strictly masked, never outputs raw UUID/serial)
    _, ioreg_out, _ = run_cmd(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], timeout=3)
    model_m = re.search(r'"model"\s*=\s*<"([^"]+)">', ioreg_out)
    has_hw_uuid = "IOPlatformUUID" in ioreg_out
    model_str = model_m.group(1) if model_m else "Mac"
    checks.append(
        make_check(
            "hardware_device_fingerprint",
            "主板不可改硬件标识提醒 (IOPlatformUUID)",
            "INFO",
            f"机型={model_str} | IOPlatformUUID={'存在(已脱敏不可改)' if has_hw_uuid else '未知'}",
            "Safari/浏览器网页沙箱无法读取主板 IOPlatformUUID；但原生 Claude Desktop 理论上可采集系统/硬件级特征。若本机曾被封号，新号建议优先使用全新独立浏览器配置文件（Safari 新 Profile），避免旧桌面端关联。",
        )
    )

    # 19. Auto-start before VPN risk (LaunchAgents / openAtLogin)
    mac_autostart: List[str] = []
    la_dir = os.path.expanduser("~/Library/LaunchAgents")
    if os.path.isdir(la_dir):
        try:
            for fn in os.listdir(la_dir):
                if "claude" in fn.lower() or "anthropic" in fn.lower():
                    mac_autostart.append(f"LaunchAgents/{fn}")
        except Exception:
            pass
    c_cfg_p = os.path.expanduser("~/Library/Application Support/Claude/config.json")
    if os.path.isfile(c_cfg_p):
        try:
            cd = json.load(open(c_cfg_p, "r", encoding="utf-8"))
            if cd.get("openAtLogin") is True:
                mac_autostart.append("Claude config.json openAtLogin=true")
        except Exception:
            pass
    if mac_autostart:
        checks.append(
            make_check(
                "claude_autostart_leak",
                "Claude 开机自启抢跑代理风险 (Boot-Leak)",
                "FAIL",
                f"发现 {len(mac_autostart)} 项: {', '.join(mac_autostart[:3])}",
                "Claude 开机自启可能早于 Clash/VPN TUN 建立连接，每次重启都会向 Anthropic 暴露真实本地 IP。",
                "在 System Settings -> General -> Login Items 与 Claude Settings 中关闭开机自启。",
                severity="high",
            )
        )
    else:
        checks.append(
            make_check(
                "claude_autostart_leak",
                "Claude 开机自启抢跑代理风险 (Boot-Leak)",
                "PASS",
                "未发现 Claude 开机自启项",
                "不存在 Claude 抢先于代理客户端联网的开机自启风险。",
            )
        )

    # 20. Global Git Identity Check for Claude Code CLI (privacy-safe: NEVER prints email)
    gc_path = os.path.expanduser("~/.gitconfig")
    git_cn_dom = ""
    git_cjk = False
    if os.path.isfile(gc_path):
        try:
            gc_txt = open(gc_path, "r", encoding="utf-8", errors="replace").read()
            m_em = re.search(r"^\s*email\s*=\s*(.+)$", gc_txt, re.M | re.I)
            if m_em:
                em_v = m_em.group(1).strip().strip('"').strip("'").lower()
                if "@" in em_v:
                    d_em = em_v.split("@", 1)[1]
                    if d_em in {"qq.com", "foxmail.com", "163.com", "126.com", "sina.com", "sina.cn", "sohu.com", "aliyun.com", "yeah.net", "139.com", "189.cn"}:
                        git_cn_dom = d_em
            m_nm = re.search(r"^\s*name\s*=\s*(.+)$", gc_txt, re.M | re.I)
            if m_nm and has_cjk(m_nm.group(1)):
                git_cjk = True
        except Exception:
            pass
    if git_cn_dom or git_cjk:
        gp = ([f"邮箱为国内域名(@{git_cn_dom}，已脱敏)"] if git_cn_dom else []) + (["user.name 含中文"] if git_cjk else [])
        checks.append(
            make_check(
                "git_identity_leak",
                "Git 全局身份配置 (Claude Code CLI 上下文)",
                "WARN",
                "；".join(gp),
                "Claude Code CLI 会读取 git config 作为提交/会话上下文，请避免与旧封号邮箱或中文标识混用。",
                "建议使用与新号一致的纯英文 Git 身份（git config --global user.name/user.email）。",
            )
        )
    else:
        checks.append(make_check("git_identity_leak", "Git 全局身份配置 (Claude Code CLI 上下文)", "PASS", "未发现国内邮箱后缀或中文 Git 用户名", "全局 ~/.gitconfig 无明显国内邮箱域名或中文用户名特征。"))

    return {"title": "macOS 系统环境与指纹", "checks": checks}


# ---------------------------------------------------------------------------
# Category 5: Claude Desktop, Claude Code, Keychain, System Wildcard & Safari Residue
# ---------------------------------------------------------------------------
def _match_claude_risk_domain(host: str) -> bool:
    h = (host or "").strip().lower().strip(".")
    if not h:
        return False
    return any(h == root or h.endswith("." + root) for root in CLAUDE_RISK_DOMAINS)


def _fmt_bytes(num: int) -> str:
    if num < 1024:
        return f"{num} B"
    if num < 1024 * 1024:
        return f"{num / 1024:.1f} KB"
    return f"{num / (1024 * 1024):.1f} MB"


def _dir_stats(path: str, max_files: int = 4000) -> Tuple[int, int]:
    if os.path.isfile(path) or os.path.islink(path):
        try:
            return 1, os.lstat(path).st_size
        except Exception:
            return 1, 0
    if not os.path.isdir(path):
        return 0, 0
    cnt = 0
    total = 0
    for root, _, files in os.walk(path):
        for fn in files:
            cnt += 1
            try:
                total += os.lstat(os.path.join(root, fn)).st_size
            except Exception:
                pass
            if cnt >= max_files:
                return cnt, total
    return cnt, total


def _scan_keychain_claude() -> List[str]:
    """Metadata-only Keychain search (never reads secrets/passwords)."""
    found: List[str] = []
    seen = set()
    keywords = ("claude", "anthropic", "hcaptcha", "stripe")

    # 1. Explicit existence checks (no -w)
    for svc in ("Claude Safe Storage", "Claude Code-credentials"):
        rc, _, _ = run_cmd(["/usr/bin/security", "find-generic-password", "-s", svc], timeout=3)
        if rc == 0 and svc not in seen:
            seen.add(svc)
            found.append(svc)

    # 2. Full Keychain metadata dump (no -d, zero secret access)
    rc_d, dump_out, _ = run_cmd(["/usr/bin/security", "dump-keychain"], timeout=5)
    if rc_d == 0 and dump_out:
        attr_pat = re.compile(r'(?:"svce"|"srvr"|0x00000007)\s*<blob>="([^"]+)"')
        for line in dump_out.splitlines():
            m = attr_pat.search(line)
            if not m:
                continue
            label = m.group(1).strip()
            low = label.lower()
            if any(k in low for k in keywords) and label not in seen:
                seen.add(label)
                found.append(label[:64])
    return found


def _scan_safari_claude_storage() -> Dict[str, Any]:
    """Read-only domain-only scan of Safari WebsiteData, ITP, DeviceIdHashSalts & History."""
    res: Dict[str, Any] = {
        "website_data_domains": [],
        "itp_domains": [],
        "salt_files": 0,
        "history_domains": {},
        "favicon_domains": {},
        "network_cache_exists": False,
    }

    # 1. WebKit WebsiteData origin files (origin hostnames only, never storage values)
    wd_default = os.path.expanduser(
        "~/Library/Containers/com.apple.Safari/Data/Library/WebKit/WebsiteData/Default"
    )
    if os.path.isdir(wd_default):
        matched_origins = set()
        for root, _, files in os.walk(wd_default):
            if "origin" not in files:
                continue
            fp = os.path.join(root, "origin")
            try:
                raw = open(fp, "rb").read(4096)
                txt = raw.decode("latin-1", errors="ignore").lower()
                for cand in re.findall(r"[a-z0-9.-]+\.[a-z]{2,}", txt):
                    if _match_claude_risk_domain(cand):
                        matched_origins.add(cand)
            except Exception:
                pass
        res["website_data_domains"] = sorted(matched_origins)

    # 2. WebKit ResourceLoadStatistics / ITP ObservedDomains (domain names only)
    obs_db = os.path.expanduser(
        "~/Library/Containers/com.apple.Safari/Data/Library/WebKit/WebsiteData/ResourceLoadStatistics/observations.db"
    )
    if os.path.isfile(obs_db):
        tmp = tempfile.mktemp(suffix=".db")
        try:
            shutil.copy2(obs_db, tmp)
            conn = sqlite3.connect(tmp)
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            if "ObservedDomains" in tables:
                rows = conn.execute("SELECT registrableDomain FROM ObservedDomains").fetchall()
                res["itp_domains"] = sorted({r[0].lower() for r in rows if r[0] and _match_claude_risk_domain(r[0])})
            conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    # 3. WebKit DeviceIdHashSalts (file count only)
    salt_dir = os.path.expanduser(
        "~/Library/Containers/com.apple.Safari/Data/Library/WebKit/WebsiteData/DeviceIdHashSalts"
    )
    if os.path.isdir(salt_dir):
        scnt, _ = _dir_stats(salt_dir, max_files=200)
        res["salt_files"] = scnt

    # 4. Safari History.db & Favicon Cache (strictly exact Claude/Anthropic/hCaptcha/Stripe domain counts)
    for key, dbp, sql in [
        ("history_domains", "~/Library/Safari/History.db", "SELECT url FROM history_items"),
        ("favicon_domains", "~/Library/Safari/Favicon Cache/favicons.db", "SELECT url FROM page_url"),
    ]:
        ep = os.path.expanduser(dbp)
        if not os.path.isfile(ep):
            continue
        tmp = tempfile.mktemp(suffix=".db")
        try:
            shutil.copy2(ep, tmp)
            conn = sqlite3.connect(tmp)
            rows = conn.execute(sql).fetchall()
            conn.close()
            hits: Dict[str, int] = {}
            for (u,) in rows:
                if not u:
                    continue
                m = re.match(r"https?://([^/:]+)", str(u).lower())
                host = m.group(1) if m else ""
                if _match_claude_risk_domain(host):
                    hits[host] = hits.get(host, 0) + 1
            res[key] = hits
        except Exception:
            pass
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    net_cache = os.path.expanduser("~/Library/Caches/com.apple.Safari/WebKitCache")
    res["network_cache_exists"] = os.path.isdir(net_cache)
    return res


def audit_claude_safari_residue() -> Dict[str, Any]:
    checks: List[Dict[str, str]] = []
    inventory: List[Dict[str, str]] = []

    def add_inv(module: str, name: str, path: str, purpose: str, observed: str, status: str) -> None:
        inventory.append(
            {
                "module": module,
                "name": name,
                "path": path,
                "purpose": purpose,
                "observed": observed,
                "status": status,
            }
        )

    # 1. Installed Claude App / CLI binaries & Running processes
    _, ps_c_out, _ = run_cmd(["/bin/ps", "-axo", "pid,comm"], timeout=3)
    running_claude: List[str] = []
    for line in ps_c_out.splitlines()[1:]:
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        pid_s, comm = parts
        base = os.path.basename(comm).lower()
        if "/applications/claude.app/" in comm.lower() or base in {"claude", "claude helper", "claude-code"}:
            running_claude.append(f"{pid_s} {base}")

    installed_apps = [p for p in ["/Applications/Claude.app", os.path.expanduser("~/Applications/Claude.app")] if os.path.exists(p)]
    cli_bins: List[str] = []
    rc_wh, wh_out, _ = run_cmd(["/usr/bin/which", "claude"], timeout=2)
    if rc_wh == 0 and wh_out.strip():
        cli_bins.append(wh_out.strip())
    for bp in [
        "/usr/local/bin/claude",
        "/opt/homebrew/bin/claude",
        os.path.expanduser("~/.local/bin/claude"),
        os.path.expanduser("~/.local/node/bin/claude"),
    ]:
        if os.path.exists(bp) and bp not in cli_bins:
            cli_bins.append(bp)

    proc_obs = (
        f"进程={len(running_claude)} ({', '.join(running_claude[:3])})" if running_claude else "进程=未运行"
    ) + f" | Desktop App={'已安装' if installed_apps else '未安装'} | CLI={'已安装(' + cli_bins[0] + ')' if cli_bins else '未安装'}"
    checks.append(
        make_check(
            "claude_proc",
            "Claude 安装状态与后台进程",
            "INFO" if (running_claude or installed_apps or cli_bins) else "PASS",
            proc_obs,
            "清理本机残留或切换新号前，必须确保所有 Claude Desktop / Claude Code 进程已完全退出。",
        )
    )
    add_inv(
        "运行与程序",
        "Claude.app / CLI / 进程",
        "/Applications/Claude.app · PATH/claude",
        "确认是否存在桌面端或 CLI 后台常驻进程持续上报遥测/心跳",
        proc_obs,
        "INFO" if (running_claude or installed_apps or cli_bins) else "PASS",
    )

    # 2. Claude Desktop Files & Deep Fingerprint Inspection (Read-only, zero secrets)
    claude_dir = os.path.expanduser("~/Library/Application Support/Claude")
    claude_sys_paths = [
        ("主数据目录", "~/Library/Application Support/Claude", claude_dir),
        ("桌面端日志", "~/Library/Logs/Claude", os.path.expanduser("~/Library/Logs/Claude")),
        ("更新器缓存 (ShipIt)", "~/Library/Caches/com.anthropic.claudefordesktop.ShipIt", os.path.expanduser("~/Library/Caches/com.anthropic.claudefordesktop.ShipIt")),
        ("应用缓存", "~/Library/Caches/com.anthropic.claudefordesktop", os.path.expanduser("~/Library/Caches/com.anthropic.claudefordesktop")),
        ("偏好设置 plist", "~/Library/Preferences/com.anthropic.claudefordesktop.plist", os.path.expanduser("~/Library/Preferences/com.anthropic.claudefordesktop.plist")),
        ("Helper 偏好 plist", "~/Library/Preferences/com.anthropic.claudefordesktop.helper.plist", os.path.expanduser("~/Library/Preferences/com.anthropic.claudefordesktop.helper.plist")),
        ("窗口状态", "~/Library/Saved Application State/com.anthropic.claudefordesktop.savedState", os.path.expanduser("~/Library/Saved Application State/com.anthropic.claudefordesktop.savedState")),
        ("HTTP 存储", "~/Library/HTTPStorages/com.anthropic.claudefordesktop", os.path.expanduser("~/Library/HTTPStorages/com.anthropic.claudefordesktop")),
        ("WebKit 缓存", "~/Library/WebKit/com.anthropic.claudefordesktop", os.path.expanduser("~/Library/WebKit/com.anthropic.claudefordesktop")),
        ("独立 Cookies", "~/Library/Cookies/com.anthropic.claudefordesktop.binarycookies", os.path.expanduser("~/Library/Cookies/com.anthropic.claudefordesktop.binarycookies")),
    ]
    existing_paths = [ep for _, _, ep in claude_sys_paths if os.path.exists(ep)]
    desktop_clean_cmd = (
        'rm -rf ~/Library/Application\\ Support/Claude ~/Library/Logs/Claude '
        '~/Library/Caches/com.anthropic.claudefordesktop* '
        '~/Library/Preferences/com.anthropic.claudefordesktop*.plist '
        '~/Library/Saved\\ Application\\ State/com.anthropic.claudefordesktop.savedState '
        '~/Library/HTTPStorages/com.anthropic.claudefordesktop '
        '~/Library/WebKit/com.anthropic.claudefordesktop '
        '~/Library/Cookies/com.anthropic.claudefordesktop.binarycookies'
    )

    ant_did_exists = os.path.isfile(os.path.join(claude_dir, "ant-did"))
    cookies_db = os.path.join(claude_dir, "Cookies")
    pref_path = os.path.join(claude_dir, "Preferences")
    local_state_path = os.path.join(claude_dir, "Local State")
    cfg_json_path = os.path.join(claude_dir, "config.json")
    mcp_cfg_path = os.path.join(claude_dir, "claude_desktop_config.json")
    nps_path = os.path.join(claude_dir, "Network Persistent State")
    log_dir = os.path.expanduser("~/Library/Logs/Claude")

    # Sub-storage dirs inside Application Support/Claude
    sub_storage_names = [
        "Trust Tokens", "DIPS", "SharedStorage", "Local Storage", "Session Storage",
        "IndexedDB", "WebStorage", "Cache", "Code Cache", "GPUCache",
        "fcache", "sentry", "blob_storage", "Service Worker", "vm_bundles",
    ]
    existing_sub_storages = [s for s in sub_storage_names if os.path.exists(os.path.join(claude_dir, s))]

    desktop_details: List[str] = []
    desktop_status = "PASS" if not existing_paths else "WARN"
    desktop_sev = "low"

    # Inventory rows for every key Claude Desktop generated artifact
    if ant_did_exists:
        st_sz = os.path.getsize(os.path.join(claude_dir, "ant-did"))
        desktop_details.append(f"存在 ant-did 设备 ID ({st_sz}B)")
        desktop_sev = "high"
        add_inv("Claude Desktop", "ant-did 设备唯一 ID", "~/Library/Application Support/Claude/ant-did", "Anthropic 跨账号关联核心设备指纹文件（绝不可复用旧文件）", f"存在 ({st_sz} B)", "FAIL")
        desktop_status = "FAIL"
    else:
        add_inv("Claude Desktop", "ant-did 设备唯一 ID", "~/Library/Application Support/Claude/ant-did", "Anthropic 跨账号关联核心设备指纹文件", "已清理 (0 残留)", "PASS")

    if os.path.isfile(cookies_db):
        tmp = tempfile.mktemp(suffix=".db")
        c_obs = "Cookies 数据库存在"
        try:
            shutil.copy2(cookies_db, tmp)
            conn = sqlite3.connect(tmp)
            rows = conn.execute("SELECT host_key, name FROM cookies").fetchall()
            conn.close()
            names = {r[1] for r in rows}
            tracked = [
                n
                for n in [
                    "anthropic-device-id", "hmt_id", "__ssid", "_fbp",
                    "sessionKey", "routingHint", "lastActiveOrg", "cf_clearance", "__cf_bm",
                ]
                if n in names
            ]
            c_obs = f"{len(rows)} 条 (追踪键: {', '.join(tracked) if tracked else '无'})"
            desktop_details.append(f"Cookies {c_obs}")
            if any(k in names for k in ("anthropic-device-id", "hmt_id", "sessionKey", "lastActiveOrg")):
                desktop_status = "FAIL"
                desktop_sev = "high"
        except Exception:
            desktop_details.append(c_obs)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
        add_inv("Claude Desktop", "Cookies 追踪数据库", "~/Library/Application Support/Claude/Cookies", "存储 anthropic-device-id、hCaptcha hmt_id、sessionKey、__ssid 等（仅查键名不读明文）", c_obs, "FAIL" if desktop_status == "FAIL" else "WARN")
    else:
        add_inv("Claude Desktop", "Cookies 追踪数据库", "~/Library/Application Support/Claude/Cookies", "存储 anthropic-device-id、hCaptcha hmt_id、sessionKey 等追踪键", "已清理 (0 残留)", "PASS")

    pref_notes: List[str] = []
    pref_st = "PASS"
    if os.path.isfile(pref_path):
        pref_st = "WARN"
        try:
            pref = json.load(open(pref_path, "r", encoding="utf-8"))
            dicts = (pref.get("spellcheck") or {}).get("dictionaries")
            if dicts:
                pref_notes.append(f"拼写字典={dicts}")
                if any("zh" in str(x).lower() for x in dicts):
                    pref_st = "FAIL"
                    desktop_status = "FAIL"
            if ((pref.get("electron") or {}).get("media") or {}).get("device_id_salt"):
                pref_notes.append("含 electron device_id_salt")
            acc_l = (pref.get("intl") or {}).get("accept_languages")
            if acc_l:
                pref_notes.append(f"accept_lang={acc_l}")
                if "zh-cn" in str(acc_l).lower():
                    pref_st = "FAIL"
                    desktop_status = "FAIL"
        except Exception:
            pref_notes.append("Preferences 存在")
    if os.path.isfile(local_state_path):
        if pref_st == "PASS":
            pref_st = "WARN"
        try:
            ls_d = json.load(open(local_state_path, "r", encoding="utf-8"))
            if ls_d.get("os_crypt"):
                pref_notes.append("Local State 含 os_crypt")
            vc = ls_d.get("variations_country")
            if vc:
                pref_notes.append(f"variations={vc}")
                if str(vc).lower() in {"cn", "hk"}:
                    pref_st = "FAIL"
                    desktop_status = "FAIL"
        except Exception:
            pref_notes.append("Local State 存在")
    if pref_notes:
        desktop_details.extend(pref_notes)
    add_inv(
        "Claude Desktop",
        "Preferences & Local State",
        "~/Library/Application Support/Claude/{Preferences, Local State}",
        "记录 electron device_id_salt 设备盐、拼写语言字典、os_crypt 加密头",
        "；".join(pref_notes) if pref_notes else "已清理 (0 残留)",
        pref_st,
    )

    cfg_notes: List[str] = []
    cfg_st = "PASS"
    if os.path.isfile(cfg_json_path):
        cfg_st = "WARN"
        try:
            cjson = json.load(open(cfg_json_path, "r", encoding="utf-8"))
            if cjson.get("locale"):
                cfg_notes.append(f"locale={cjson.get('locale')}")
            for k_u in ("lastKnownAccountUuid", "orgUuid", "userId", "oauthAccount"):
                if cjson.get(k_u):
                    cfg_notes.append(f"含 {k_u}")
                    cfg_st = "FAIL"
                    desktop_status = "FAIL"
        except Exception:
            cfg_notes.append("config.json 存在")
    if os.path.isfile(mcp_cfg_path):
        if cfg_st == "PASS":
            cfg_st = "WARN"
        try:
            cfg = json.load(open(mcp_cfg_path, "r", encoding="utf-8"))
            dev_name = str((cfg.get("preferences") or {}).get("remoteToolsDeviceName", ""))
            if dev_name:
                if has_cjk(dev_name) or "deimac" in dev_name.lower() or "demac" in dev_name.lower():
                    cfg_st = "FAIL"
                    desktop_status = "FAIL"
                    cfg_notes.append(f"remoteToolsDeviceName 含中文/拼音: {dev_name}")
                else:
                    cfg_notes.append(f"remoteToolsDeviceName={dev_name}")
            mcps = cfg.get("mcpServers")
            if isinstance(mcps, dict) and mcps:
                cfg_notes.append(f"MCP 配置 {len(mcps)} 个")
        except Exception:
            cfg_notes.append("claude_desktop_config.json 存在")
    if cfg_notes:
        desktop_details.extend(cfg_notes)
    add_inv(
        "Claude Desktop",
        "config.json & desktop_config",
        "~/Library/Application Support/Claude/{config.json, claude_desktop_config.json}",
        "保存旧账号 lastKnownAccountUuid、locale 与上报给服务端的 remoteToolsDeviceName",
        "；".join(cfg_notes) if cfg_notes else "已清理 (0 残留)",
        cfg_st,
    )

    nps_notes: List[str] = []
    if os.path.isfile(nps_path):
        try:
            nps = json.load(open(nps_path, "r", encoding="utf-8"))
            broken = ((nps.get("net") or {}).get("http_server_properties") or {}).get("broken_alternative_services") or []
            quic_fail = sum(
                int(item.get("broken_count", 0))
                for item in broken
                if isinstance(item, dict) and item.get("protocol_str") == "quic"
            )
            nps_notes.append(f"Network Persistent State 存在 (QUIC 失败 {quic_fail} 次)")
        except Exception:
            nps_notes.append("Network Persistent State 存在")
    if existing_sub_storages:
        nps_notes.append(f"子存储目录 {len(existing_sub_storages)} 个 ({', '.join(existing_sub_storages[:6])})")
    if nps_notes:
        desktop_details.extend(nps_notes)
    add_inv(
        "Claude Desktop",
        "Electron 网页存储与缓存",
        "~/Library/Application Support/Claude/{Local Storage, IndexedDB, Trust Tokens, DIPS, Cache, sentry...}",
        "Electron 沙箱本地存储、Trust Tokens、DIPS 追踪表、QUIC 记录与崩溃缓存",
        "；".join(nps_notes) if nps_notes else "已清理 (0 残留)",
        "WARN" if nps_notes else "PASS",
    )

    # Logs & ShipIt / Preferences / SavedState / HTTPStorages
    log_obs = "已清理 (0 残留)"
    log_st = "PASS"
    if os.path.isdir(log_dir):
        rb_cnt = 0
        ban_cnt = 0
        stripe_cnt = 0
        net_cnt = 0
        log_files = [fn for fn in os.listdir(log_dir) if fn.endswith(".log") and os.path.isfile(os.path.join(log_dir, fn))]
        for fn in log_files:
            try:
                txt = open(os.path.join(log_dir, fn), "r", encoding="utf-8", errors="replace").read()
                rb_cnt += txt.count("region_blocked") + txt.count("isn't available in your region")
                ban_cnt += txt.count("account_banned")
                stripe_cnt += txt.count("Failed to load Stripe.js")
                net_cnt += txt.count("ERR_NETWORK_CHANGED")
            except Exception:
                pass
        log_obs = f"{len(log_files)} 个日志 (region_blocked={rb_cnt}, account_banned={ban_cnt}, Stripe失败={stripe_cnt}, 网络变化={net_cnt})"
        if ban_cnt or rb_cnt:
            log_st = "FAIL"
            desktop_status = "FAIL"
            desktop_sev = "high"
        else:
            log_st = "WARN"
        desktop_details.append(f"日志: {log_obs}")
    add_inv(
        "Claude Desktop",
        "运行日志与封禁历史",
        "~/Library/Logs/Claude/*.log",
        "记录 region_blocked、account_banned、Stripe.js 失败与休眠断流事件",
        log_obs,
        log_st,
    )

    extra_sys_found = [label for label, _, ep in claude_sys_paths[2:] if os.path.exists(ep)]
    add_inv(
        "Claude Desktop",
        "ShipIt 缓存 / plist / HTTPStorages",
        "~/Library/{Caches, Preferences, Saved Application State, HTTPStorages, WebKit, Cookies}/com.anthropic.claudefordesktop*",
        "自动更新缓存、窗口偏好 plist、原生 HTTP Cookie 存储与 WebKit 缓存",
        f"存在 {len(extra_sys_found)} 项: {', '.join(extra_sys_found)}" if extra_sys_found else "已清理 (0 残留)",
        "WARN" if extra_sys_found else "PASS",
    )

    if not existing_paths:
        checks.append(
            make_check(
                "claude_desktop_files",
                "Claude Desktop 全套设备指纹与系统缓存",
                "PASS",
                "已清理干净 (10 类路径全部 0 残留)",
                "未发现 ant-did、Cookies、hCaptcha hmt_id、device_id_salt、lastKnownAccountUuid、日志或 ShipIt/plist 残留。",
            )
        )
    else:
        checks.append(
            make_check(
                "claude_desktop_files",
                "Claude Desktop 全套设备指纹与系统缓存",
                desktop_status,
                f"存在 {len(existing_paths)} 个本地路径",
                "；".join(desktop_details) if desktop_details else f"存在路径: {', '.join(existing_paths[:4])}",
                "换新账号前务必先完全退出 Claude Desktop，再彻底删除以上所有桌面端目录与钥匙串，避免 ant-did / Cookies / device_id_salt 跨号关联！",
                desktop_clean_cmd,
                severity=desktop_sev,
            )
        )

    # 3. Claude Code CLI (~/.claude.json, ~/.claude/*, XDG dirs)
    cc_json = os.path.expanduser("~/.claude.json")
    cc_dir = os.path.expanduser("~/.claude")
    cc_backups = [
        os.path.join(os.path.expanduser("~"), fn)
        for fn in os.listdir(os.path.expanduser("~"))
        if fn.startswith(".claude.json.backup")
    ]
    xdg_candidates = [
        os.path.expanduser("~/.anthropic"),
        os.path.expanduser("~/.config/claude"),
        os.path.expanduser("~/.config/claude-code"),
        os.path.expanduser("~/.config/anthropic"),
        os.path.expanduser("~/.cache/claude"),
        os.path.expanduser("~/.cache/claude-code"),
        os.path.expanduser("~/.cache/anthropic"),
        os.path.expanduser("~/.local/share/claude"),
        os.path.expanduser("~/.local/state/claude"),
    ]
    existing_xdg = [p for p in xdg_candidates if os.path.exists(p)]

    cc_notes: List[str] = []
    cc_status = "PASS"
    if os.path.isfile(cc_json):
        cc_status = "WARN"
        try:
            d = json.load(open(cc_json, "r", encoding="utf-8"))
            flags = [
                k
                for k in ["machineID", "userID", "oauthAccount", "anonymousId", "firstStartTime", "cachedStatsigGates", "cachedGrowthBookFeatures"]
                if k in d
            ]
            cc_notes.append(f"~/.claude.json 含 {', '.join(flags) if flags else '配置'}")
            if any(k in d for k in ("machineID", "userID", "oauthAccount", "anonymousId")):
                cc_status = "FAIL"
            projs = d.get("projects")
            if isinstance(projs, dict) and any(has_cjk(str(pk)) for pk in projs.keys()):
                cc_notes.append("projects 记录含中文路径")
        except Exception:
            cc_notes.append("~/.claude.json 存在")
    if cc_backups:
        cc_status = "WARN" if cc_status == "PASS" else cc_status
        cc_notes.append(f"含 {len(cc_backups)} 个 .claude.json.backup 备份")
    if os.path.exists(cc_dir):
        cc_status = "WARN" if cc_status == "PASS" else cc_status
        sub_cc = []
        try:
            for item in sorted(os.listdir(cc_dir)):
                if item in {"settings.json", "settings.local.json", "statsig", "projects", "debug", "telemetry", "ide", "credentials.json", ".credentials.json", "session-env", "file-history"}:
                    sub_cc.append(item)
            if ".credentials.json" in sub_cc or "credentials.json" in sub_cc:
                cc_status = "FAIL"
        except Exception:
            pass
        mac_relay_hits: List[str] = []
        for sf in ("settings.json", "settings.local.json"):
            sfp = os.path.join(cc_dir, sf)
            if os.path.isfile(sfp):
                try:
                    sd = json.load(open(sfp, "r", encoding="utf-8"))
                    s_env = sd.get("env") if isinstance(sd.get("env"), dict) else {}
                    for ek in ("ANTHROPIC_BASE_URL", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
                        if s_env.get(ek):
                            clean_ev = re.sub(r"://[^/@\s]+@", "://<REDACTED>@", str(s_env[ek]))
                            cc_notes.append(f"{sf}:{ek}={clean_ev}")
                            if ek == "ANTHROPIC_BASE_URL" and "api.anthropic.com" not in clean_ev.lower():
                                mac_relay_hits.append(f"{sf}:ANTHROPIC_BASE_URL={clean_ev}")
                    if sd.get("apiKeyHelper"):
                        cc_notes.append(f"{sf} 含 apiKeyHelper")
                        mac_relay_hits.append(f"{sf}:apiKeyHelper")
                except Exception:
                    pass
        fcnt, fbytes = _dir_stats(cc_dir, max_files=1000)
        cc_notes.append(f"~/.claude/ ({fcnt} 文件, {_fmt_bytes(fbytes)}; 含 {', '.join(sub_cc[:6]) if sub_cc else '子项'})")
    else:
        mac_relay_hits = []
    if existing_xdg:
        cc_status = "WARN" if cc_status == "PASS" else cc_status
        cc_notes.append(f"XDG/隐藏目录 {len(existing_xdg)} 个: {', '.join(os.path.basename(p) for p in existing_xdg)}")

    for h_lbl, h_path in [
        ("claude-code-router", os.path.expanduser("~/.claude-code-router")),
        ("cc-switch", os.path.expanduser("~/.cc-switch")),
        ("cc-switch(.config)", os.path.expanduser("~/.config/cc-switch")),
        ("claude-relay", os.path.expanduser("~/.claude-relay")),
    ]:
        if os.path.exists(h_path):
            mac_relay_hits.append(f"工具目录:{h_lbl}")
    env_bu = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
    if env_bu and "api.anthropic.com" not in env_bu.lower():
        safe_env_bu = re.sub(r"://[^/@\s]+@", "://<REDACTED>@", env_bu)
        mac_relay_hits.append(f"env:ANTHROPIC_BASE_URL={safe_env_bu}")
    if mac_relay_hits:
        checks.append(
            make_check(
                "claude_relay_harness",
                "第三方中转站 / 本地转发桥 / 套壳 Harness 检测 (高危封号红线)",
                "FAIL",
                f"命中 {len(mac_relay_hits)} 项: {', '.join(mac_relay_hits[:4])}",
                "检测到非官方的 ANTHROPIC_BASE_URL、本地转发桥或第三方切换/中转工具！Anthropic 明确严查在第三方套壳/中转工具中复用 Pro/Max OAuth 订阅凭据，极易直接触发 account_banned！",
                "使用官方订阅新号时，务必移除 settings.json 与环境变量中的自定义 ANTHROPIC_BASE_URL / apiKeyHelper。",
                severity="critical",
            )
        )
        add_inv("Claude Code CLI", "中转站 / 本地转发配置", "~/.claude/settings*.json · ~/.cc-switch · ~/.claude-code-router", "检测非官方 ANTHROPIC_BASE_URL 与 OAuth 套壳转发（高频封号诱因）", ", ".join(mac_relay_hits[:4]), "FAIL")
    else:
        checks.append(
            make_check(
                "claude_relay_harness",
                "第三方中转站 / 本地转发桥 / 套壳 Harness 检测 (高危封号红线)",
                "PASS",
                "未发现自定义 ANTHROPIC_BASE_URL 或第三方转发工具",
                "Claude Code 配置未指向第三方中转站或本地转发代理桥。",
            )
        )

    cli_clean_cmd = "rm -rf ~/.claude.json ~/.claude.json.backup* ~/.claude ~/.anthropic ~/.config/claude* ~/.cache/claude* ~/.local/share/claude* ~/.local/state/claude*"
    if cc_status == "PASS":
        checks.append(
            make_check(
                "claude_code_cli",
                "Claude Code CLI 全路径状态 (~/.claude* & XDG)",
                "PASS",
                "已清理干净 (0 残留)",
                "~/.claude.json、备份文件、~/.claude 目录及 ~/.config / ~/.cache / ~/.local 下均无残留。",
            )
        )
    else:
        checks.append(
            make_check(
                "claude_code_cli",
                "Claude Code CLI 全路径状态 (~/.claude* & XDG)",
                cc_status,
                "；".join(cc_notes),
                "Claude Code CLI 会在 ~/.claude.json 持久化 machineID / userID / oauthAccount，并在 ~/.claude/statsig 保存实验分组标识，换新号前需一并清理。",
                "若本机曾登录过被封账号的 Claude Code，请先清理 CLI 状态目录。",
                cli_clean_cmd,
                severity="high" if cc_status == "FAIL" else "low",
            )
        )
    add_inv(
        "Claude Code CLI",
        "~/.claude.json & ~/.claude/ & XDG",
        "~/.claude.json* · ~/.claude/ · ~/.config|cache|local/*claude*",
        "存储 CLI 的 machineID、userID、oauthAccount、statsig 标识与会话调试日志",
        "；".join(cc_notes) if cc_notes else "已清理 (0 残留)",
        cc_status,
    )

    # 4. Full Keychain Metadata Scan (Claude / Anthropic / hCaptcha / Stripe — ZERO secrets read)
    kc_found = _scan_keychain_claude()
    if kc_found:
        checks.append(
            make_check(
                "claude_keychain",
                "macOS 钥匙串全量脱敏检索 (Claude / Anthropic / Stripe)",
                "FAIL",
                f"发现 {len(kc_found)} 项: {', '.join(kc_found[:6])}",
                "钥匙串中仍存有 Claude 加密存储密钥（Claude Safe Storage）或相关凭证条目，重新安装/启动桌面端会自动复用旧加密密钥或凭据。",
                "先退出 Claude 后删除对应钥匙串条目。",
                'security delete-generic-password -s "Claude Safe Storage"; security delete-generic-password -s "Claude Code-credentials"',
                severity="high",
            )
        )
        add_inv("钥匙串与系统注册", "登录钥匙串全量扫描", "login.keychain-db (仅查服务名，不读密码)", "Electron Safe Storage 加密主密钥与 Claude Code OAuth 凭据", f"发现 {len(kc_found)} 项: {', '.join(kc_found[:4])}", "FAIL")
    else:
        checks.append(
            make_check(
                "claude_keychain",
                "macOS 钥匙串全量脱敏检索 (Claude / Anthropic / Stripe)",
                "PASS",
                "全库扫描 0 残留",
                "已遍历登录钥匙串服务名元数据（不读密码），未检测到任何 claude / anthropic / hcaptcha / stripe 凭证项。",
            )
        )
        add_inv("钥匙串与系统注册", "登录钥匙串全量扫描", "login.keychain-db (仅查服务名，不读密码)", "Electron Safe Storage 加密主密钥与 Claude Code OAuth 凭据", "全库 0 残留", "PASS")

    # 5. Broad macOS Wildcard Sweep (~/Library/*, DiagnosticReports, LaunchServices, Trash, Temp, IDE)
    lib_root = os.path.expanduser("~/Library")
    lib_subtrees = [
        "Application Support", "Caches", "Preferences", "Logs",
        "Containers", "Group Containers", "HTTPStorages",
        "Saved Application State", "WebKit", "LaunchAgents",
        "Cookies", "Application Scripts",
    ]
    known_ep_set = set(existing_paths)
    wildcard_lib_hits: List[str] = []
    for sub in lib_subtrees:
        d = os.path.join(lib_root, sub)
        if not os.path.isdir(d):
            continue
        try:
            for name in os.listdir(d):
                low = name.lower()
                if "claude" in low or "anthropic" in low:
                    full_p = os.path.join(d, name)
                    if full_p not in known_ep_set:
                        wildcard_lib_hits.append(f"~/Library/{sub}/{name}")
        except Exception:
            pass

    crash_hits: List[str] = []
    for cdir in [
        os.path.expanduser("~/Library/Logs/DiagnosticReports"),
        "/Library/Logs/DiagnosticReports",
        os.path.expanduser("~/Library/Application Support/CrashReporter"),
    ]:
        if not os.path.isdir(cdir):
            continue
        try:
            for fn in os.listdir(cdir):
                if "claude" in fn.lower() or "anthropic" in fn.lower():
                    crash_hits.append(fn)
        except Exception:
            pass

    # LaunchServices claude:// URL scheme registration
    ls_claude_registered = False
    ls_plist = os.path.expanduser("~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist")
    if os.path.isfile(ls_plist):
        try:
            with open(ls_plist, "rb") as f:
                ls_data = plistlib.load(f)
            for h in ls_data.get("LSHandlers") or []:
                if isinstance(h, dict) and (
                    str(h.get("LSHandlerURLScheme", "")).lower() == "claude"
                    or "anthropic" in str(h.get("LSHandlerRoleAll", "")).lower()
                ):
                    ls_claude_registered = True
                    break
        except Exception:
            pass

    # ~/.Trash check
    trash_hits: List[str] = []
    trash_dir = os.path.expanduser("~/.Trash")
    if os.path.isdir(trash_dir):
        try:
            trash_hits = [fn for fn in os.listdir(trash_dir) if "claude" in fn.lower() or "anthropic" in fn.lower()]
        except Exception:
            pass

    # Darwin per-user cache/temp & /tmp (distinguish official Anthropic/Claude vs unrelated 3rd-party dirs)
    official_tmp_hits: List[str] = []
    official_tmp_paths: List[str] = []
    third_party_tmp_cnt = 0
    tmp_dirs_to_scan = ["/tmp"]
    for gc_key in ("DARWIN_USER_CACHE_DIR", "DARWIN_USER_TEMP_DIR"):
        rc_g, gd, _ = run_cmd(["/usr/bin/getconf", gc_key], timeout=2)
        if rc_g == 0 and gd.strip() and os.path.isdir(gd.strip()):
            tmp_dirs_to_scan.append(gd.strip())
    for td in tmp_dirs_to_scan:
        try:
            for fn in os.listdir(td):
                low = fn.lower()
                if "anthropic" in low or low.startswith(("claude-", "claude_", "com.anthropic")):
                    full_tp = os.path.join(td, fn)
                    official_tmp_paths.append(full_tp)
                    official_tmp_hits.append(full_tp if td == "/tmp" else f"{os.path.basename(td.rstrip('/'))}/{fn}")
                elif "claude" in low:
                    third_party_tmp_cnt += 1
        except Exception:
            pass

    # IDE Extensions & Global Storage (VS Code / Cursor / Windsurf / JetBrains)
    ide_hits: List[str] = []
    for ide_label, ide_dir in [
        ("VS Code 扩展", "~/.vscode/extensions"),
        ("Cursor 扩展", "~/.cursor/extensions"),
        ("Windsurf 扩展", "~/.windsurf/extensions"),
        ("VS Code 存储", "~/Library/Application Support/Code/User/globalStorage"),
        ("Cursor 存储", "~/Library/Application Support/Cursor/User/globalStorage"),
        ("JetBrains 插件", "~/Library/Application Support/JetBrains"),
    ]:
        ep = os.path.expanduser(ide_dir)
        if not os.path.isdir(ep):
            continue
        try:
            for fn in os.listdir(ep):
                low = fn.lower()
                if "anthropic" in low or "claude" in low:
                    ide_hits.append(f"{ide_label}:{fn}")
        except Exception:
            pass

    wc_problems: List[str] = []
    if wildcard_lib_hits:
        wc_problems.append(f"~/Library 边缘路径 {len(wildcard_lib_hits)} 项 ({', '.join(wildcard_lib_hits[:3])})")
    if crash_hits:
        wc_problems.append(f"崩溃日志 {len(crash_hits)} 个 ({', '.join(crash_hits[:3])})")
    if official_tmp_hits:
        wc_problems.append(f"系统临时/缓存 {len(official_tmp_hits)} 项 ({', '.join(official_tmp_hits[:3])})")
    if trash_hits:
        wc_problems.append(f"废纸篓残留 {len(trash_hits)} 项 ({', '.join(trash_hits[:3])})")
    if ide_hits:
        wc_problems.append(f"IDE 插件/存储 {len(ide_hits)} 项 ({', '.join(ide_hits[:3])})")

    wc_info_notes: List[str] = []
    if ls_claude_registered:
        wc_info_notes.append("LaunchServices 仍保留 claude:// 协议注册（macOS 无害登记，重启或清 LaunchServices 可刷新）")
    if third_party_tmp_cnt:
        wc_info_notes.append(f"系统临时目录含 {third_party_tmp_cnt} 个第三方含 claude 字样临时目录（非官方客户端文件）")

    wc_fix_cmd = ""
    if official_tmp_paths:
        quoted = " ".join(f'"{p}"' for p in official_tmp_paths[:6])
        wc_fix_cmd = f"rm -rf {quoted}"

    checks.append(
        make_check(
            "claude_wildcard_system",
            "macOS 全盘边缘残留扫描 (Library 通配 / 崩溃日志 / 临时目录 / 废纸篓 / IDE)",
            "WARN" if wc_problems else "PASS",
            "；".join(wc_problems) if wc_problems else ("0 残留" + (f" · {'；'.join(wc_info_notes)}" if wc_info_notes else "")),
            "已遍历 ~/Library 12 个子目录、DiagnosticReports、CrashReporter、Darwin 缓存/临时目录、~/.Trash、LaunchServices 与 VS Code/Cursor/JetBrains 插件目录。"
            + (f" 附加提示: {'；'.join(wc_info_notes)}" if wc_info_notes else ""),
            "请核对并清理上述边缘残留文件，或清空废纸篓。" if wc_problems else "",
            wc_fix_cmd,
        )
    )
    add_inv("系统缓存/日志/IDE", "~/Library 12 子目录通配", "~/Library/{Containers, Group Containers, LaunchAgents, Caches...}/*claude|anthropic*", "捕获边缘插件、沙箱容器、开机自启项与隐藏缓存", f"发现 {len(wildcard_lib_hits)} 项" if wildcard_lib_hits else "全盘 0 残留", "WARN" if wildcard_lib_hits else "PASS")
    add_inv("系统缓存/日志/IDE", "崩溃日志 & 系统临时目录 & 废纸篓", "DiagnosticReports · /var/folders/.../{C,T} · /tmp · ~/.Trash", "Electron 崩溃转储 .ips、Squirrel 临时目录与未清空的废纸篓文件", ("；".join(p for p in [f"崩溃:{len(crash_hits)}" if crash_hits else "", f"官方临时:{len(official_tmp_hits)}" if official_tmp_hits else "", f"废纸篓:{len(trash_hits)}" if trash_hits else ""] if p) or f"官方文件 0 残留" + (f" (另有 {third_party_tmp_cnt} 个第三方临时项)" if third_party_tmp_cnt else "")), "WARN" if (crash_hits or official_tmp_hits or trash_hits) else "PASS")
    add_inv("钥匙串与系统注册", "LaunchServices 协议注册", "~/Library/Preferences/com.apple.LaunchServices/...secure.plist", "记录 claude:// 深链打开方式（不直接上传，但证明曾装过桌面端）", "保留 claude:// 登记 (低风险)" if ls_claude_registered else "未注册", "INFO" if ls_claude_registered else "PASS")
    add_inv("系统缓存/日志/IDE", "IDE 扩展与全局存储", "VS Code / Cursor / Windsurf / JetBrains", "检测 anthropic.claude-code 扩展及其独立缓存/认证存储", f"发现 {len(ide_hits)} 项: {', '.join(ide_hits[:3])}" if ide_hits else "0 残留 / 未安装", "WARN" if ide_hits else "PASS")

    # 6. Safari Deep Claude/Anthropic/hCaptcha/Stripe Storage Scan (WebsiteData + ITP + Salts + History)
    safari_deep = _scan_safari_claude_storage()
    wd_doms = safari_deep["website_data_domains"]
    itp_doms = safari_deep["itp_domains"]
    salt_cnt = safari_deep["salt_files"]
    hist_doms = safari_deep["history_domains"]
    fav_doms = safari_deep["favicon_domains"]

    has_active_safari_claude = bool(wd_doms or itp_doms)
    deep_parts: List[str] = []
    if wd_doms:
        deep_parts.append(f"WebsiteData 残留域名: {', '.join(wd_doms)}")
    if itp_doms:
        deep_parts.append(f"ITP 追踪库残留: {', '.join(itp_doms)}")
    if salt_cnt:
        deep_parts.append(f"DeviceIdHashSalts ({salt_cnt} 个文件)")
    if hist_doms:
        hist_summary = ", ".join(f"{k}({v})" for k, v in sorted(hist_doms.items())[:5])
        deep_parts.append(f"访问历史匹配 {sum(hist_doms.values())} 条 ({hist_summary})")
    if fav_doms:
        deep_parts.append(f"Favicon 缓存: {', '.join(sorted(fav_doms.keys()))}")

    if has_active_safari_claude:
        checks.append(
            make_check(
                "safari_claude_storage",
                "Safari 深度存储残留 (WebsiteData / ITP / DeviceIdHashSalts / 历史)",
                "FAIL",
                "；".join(deep_parts),
                "在 Safari 本地 WebKit 存储（LocalStorage / IndexedDB / ServiceWorker / ITP 统计库）中实测到 Claude / Anthropic 站点数据残留！如果不清理就直接用当前 Safari 配置文件登新号，旧设备标记、hCaptcha 令牌与缓存会直接把新旧账号关联成危险设备。",
                "强烈建议二选一：① 打开 Safari -> Settings -> Privacy -> Manage Website Data，逐一搜索并移除 claude、anthropic、hcaptcha、stripe，并清理相关历史记录；② 更彻底：在 Safari -> Settings -> Profiles 新建一个全新的独立配置文件专门用于新号（全新 Cookies、WebsiteData、DeviceIdHashSalts，且不删你原配置文件里的其他网站登录）！",
                severity="high",
            )
        )
    elif hist_doms or fav_doms:
        checks.append(
            make_check(
                "safari_claude_storage",
                "Safari 深度存储残留 (WebsiteData / ITP / DeviceIdHashSalts / 历史)",
                "WARN",
                "；".join(deep_parts),
                "WebsiteData 与 ITP 中已无 Claude/Anthropic 存储，但 Safari 历史记录或图标缓存仍保留过往访问记录。",
                "可在 Safari History 中搜索 claude / anthropic 删除对应历史，或使用全新 Safari Profile。",
            )
        )
    else:
        checks.append(
            make_check(
                "safari_claude_storage",
                "Safari 深度存储残留 (WebsiteData / ITP / DeviceIdHashSalts / 历史)",
                "PASS",
                f"WebsiteData / ITP / 历史均无 Claude/Anthropic 残留 (Salts={salt_cnt})",
                "Safari WebKit 站点存储、ITP 追踪库、历史记录与图标缓存中均未检出 claude / anthropic / hcaptcha / stripe 域名。",
            )
        )

    add_inv(
        "Safari & 浏览器",
        "Safari WebsiteData 站点存储",
        "~/Library/Containers/com.apple.Safari/.../WebKit/WebsiteData/Default",
        "保存网页版 Claude/hCaptcha/Stripe 的 LocalStorage、IndexedDB、ServiceWorker 与缓存",
        f"残留 {len(wd_doms)} 域名: {', '.join(wd_doms)}" if wd_doms else "0 残留",
        "FAIL" if wd_doms else "PASS",
    )
    add_inv(
        "Safari & 浏览器",
        "Safari ITP 追踪库 & DeviceIdHashSalts",
        "~/Library/Containers/com.apple.Safari/.../WebsiteData/{ResourceLoadStatistics, DeviceIdHashSalts}",
        "WebKit 跨站追踪统计表与按站点派生的设备 ID 哈希盐",
        (f"ITP 含 {', '.join(itp_doms)}; " if itp_doms else "ITP 0 残留; ") + f"Salts={salt_cnt} 文件",
        "FAIL" if itp_doms else "INFO",
    )
    add_inv(
        "Safari & 浏览器",
        "Safari 历史记录 & Favicon 缓存",
        "~/Library/Safari/{History.db, Favicon Cache}",
        "记录曾访问的 claude.ai / anthropic.com 域名与图标缓存（仅统计匹配域名数）",
        f"历史 {sum(hist_doms.values())} 条 ({len(hist_doms)} 域名), Favicon {len(fav_doms)} 域名" if (hist_doms or fav_doms) else "0 残留",
        "WARN" if (hist_doms or fav_doms) else "PASS",
    )

    # 7. Safari Cookies, Locale, Private Relay, Extensions & Search History (metadata/count only)
    safari_cookie = os.path.expanduser("~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies")
    safari_plist = os.path.expanduser("~/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist")
    safari_ext_dir = os.path.expanduser("~/Library/Containers/com.apple.Safari/Data/Library/Safari/WebExtensions")
    safari_notes: List[str] = []
    safari_status = "INFO"
    if os.path.isfile(safari_cookie):
        sz = os.path.getsize(safari_cookie)
        safari_notes.append(f"Cookies.binarycookies ({_fmt_bytes(sz)})")
        safari_status = "WARN"
    else:
        safari_notes.append("无 Cookies.binarycookies")

    if os.path.isdir(safari_ext_dir):
        try:
            ext_cnt = len([x for x in os.listdir(safari_ext_dir) if not x.startswith(".")])
            if ext_cnt:
                safari_notes.append(f"WebExtensions={ext_cnt} 个")
        except Exception:
            pass

    if os.path.isfile(safari_plist):
        try:
            with open(safari_plist, "rb") as f:
                sp = plistlib.load(f)
            searches = sp.get("RecentWebSearches") or []
            cjk_search_cnt = sum(
                1 for item in searches if isinstance(item, dict) and has_cjk(str(item.get("SearchString", "")))
            )
            if cjk_search_cnt:
                safari_notes.append(f"历史搜索中含 {cjk_search_cnt} 条中文记录")
                safari_status = "WARN"
            safari_loc = sp.get("WBSOfflineSearchSuggestionsModelLastUsedLocaleIdentifierKey") or ""
            if not safari_loc:
                def _find_loc(obj: Any) -> str:
                    if isinstance(obj, dict):
                        if isinstance(obj.get("Locale"), str):
                            return obj["Locale"]
                        for v in obj.values():
                            r = _find_loc(v)
                            if r:
                                return r
                    return ""
                safari_loc = _find_loc(sp)
            if safari_loc:
                safari_notes.append(f"Safari Locale={safari_loc}")
                if safari_loc.lower().startswith("zh_cn") or "zh-hans" in safari_loc.lower():
                    safari_status = "FAIL"
            relay_active = (
                sp.get("WBSPrivacyProxyAvailabilityActiveOnDefaultNetwork") == 1
                or sp.get("WBSPrivacyProxyAvailabilityServiceStatus") == 1
            )
            if relay_active:
                safari_notes.append("iCloud Private Relay=已开启(将路由至 Apple 独立出口)")
                safari_status = "FAIL"
            else:
                safari_notes.append("iCloud Private Relay=未开启")
        except Exception:
            pass

    safari_sev = "critical" if ("iCloud Private Relay=已开启" in " ".join(safari_notes) or safari_status == "FAIL") else "low"
    safari_fix = (
        "关闭系统设置 -> Apple ID -> iCloud -> Private Relay（否则 Safari 出口 IP 会与 Clash 节点分叉），并在 Safari Manage Website Data 清理 claude / anthropic / hcaptcha / stripe。"
        if safari_sev == "critical"
        else "Safari -> Settings -> Privacy -> Manage Website Data 移除 claude / anthropic / hcaptcha / stripe，或直接为新号创建全新 Safari Profile。"
    )
    checks.append(
        make_check(
            "safari_residue",
            "Safari Cookie 文件、Locale、Private Relay 与搜索痕迹",
            safari_status,
            "；".join(safari_notes),
            "出于隐私保护不解包读取 Cookies.binarycookies 明文；上方已通过 WebKit WebsiteData 与 ITP 精准定位 Claude 站点残留。若开启 iCloud Private Relay 会导致 Safari 与本机出口 IP 分叉。",
            safari_fix,
            severity=safari_sev,
        )
    )
    add_inv(
        "Safari & 浏览器",
        "Safari Cookies & Private Relay",
        "~/Library/Containers/com.apple.Safari/.../{Cookies.binarycookies, com.apple.Safari.plist}",
        "二进制 Cookie 容器、Safari 区域设置与 iCloud 专用代理状态（不读 Cookie 明文）",
        "；".join(safari_notes),
        safari_status,
    )

    # 8. Other Browsers Audit (Chromium family + Firefox / Orion / Opera / Zen)
    chromium_dirs = {
        "Chrome": os.path.expanduser("~/Library/Application Support/Google/Chrome"),
        "Chrome Canary": os.path.expanduser("~/Library/Application Support/Google/Chrome Canary"),
        "Chromium": os.path.expanduser("~/Library/Application Support/Chromium"),
        "Brave": os.path.expanduser("~/Library/Application Support/BraveSoftware/Brave-Browser"),
        "Edge": os.path.expanduser("~/Library/Application Support/Microsoft Edge"),
        "Arc": os.path.expanduser("~/Library/Application Support/Arc/User Data"),
        "Vivaldi": os.path.expanduser("~/Library/Application Support/Vivaldi"),
        "Opera": os.path.expanduser("~/Library/Application Support/com.operasoftware.Opera"),
    }
    other_non_chromium = {
        "Firefox": os.path.expanduser("~/Library/Application Support/Firefox"),
        "Orion": os.path.expanduser("~/Library/Application Support/Orion"),
        "Zen": os.path.expanduser("~/Library/Application Support/zen"),
    }
    found_browsers: List[str] = []
    browser_issues: List[str] = []
    for bname, bpath in chromium_dirs.items():
        if not os.path.isdir(bpath):
            continue
        ls_file = os.path.join(bpath, "Local State")
        b_tags: List[str] = []
        if os.path.isfile(ls_file):
            try:
                ls = json.load(open(ls_file, "r", encoding="utf-8"))
                vc = ls.get("variations_country")
                doh = (ls.get("dns_over_https") or {}).get("mode")
                if vc:
                    b_tags.append(f"variations={vc}")
                    if str(vc).lower() in {"cn", "hk"}:
                        browser_issues.append(f"{bname} variations_country={vc}")
                if doh:
                    b_tags.append(f"DoH={doh}")
            except Exception:
                pass
        # Check Default + Profile * directories
        prof_dirs = [
            os.path.join(bpath, d)
            for d in sorted(os.listdir(bpath))
            if (d == "Default" or d.startswith("Profile ")) and os.path.isdir(os.path.join(bpath, d))
        ]
        claude_cookie_hosts = set()
        for pdir in prof_dirs[:5]:
            pref_file = os.path.join(pdir, "Preferences")
            if os.path.isfile(pref_file):
                try:
                    pr = json.load(open(pref_file, "r", encoding="utf-8"))
                    acc = (pr.get("intl") or {}).get("accept_languages")
                    rtc_pol = (pr.get("webrtc") or {}).get("ip_handling_policy")
                    if acc and not any(t.startswith("lang=") for t in b_tags):
                        b_tags.append(f"lang={acc}")
                    if acc and "zh-cn" in str(acc).lower():
                        browser_issues.append(f"{bname}({os.path.basename(pdir)}) accept_languages 含 zh-CN")
                    if rtc_pol and not any(t.startswith("webrtc=") for t in b_tags):
                        b_tags.append(f"webrtc={rtc_pol}")
                except Exception:
                    pass
            ck_file = os.path.join(pdir, "Cookies")
            if os.path.isfile(ck_file):
                tmp = tempfile.mktemp(suffix=".db")
                try:
                    shutil.copy2(ck_file, tmp)
                    conn = sqlite3.connect(tmp)
                    rows = conn.execute("SELECT DISTINCT host_key FROM cookies").fetchall()
                    conn.close()
                    for (hk,) in rows:
                        if _match_claude_risk_domain(str(hk).lstrip(".")):
                            claude_cookie_hosts.add(str(hk).lstrip("."))
                except Exception:
                    pass
                finally:
                    if os.path.exists(tmp):
                        os.remove(tmp)
        if claude_cookie_hosts:
            b_tags.append(f"含Claude/风控Cookie({len(claude_cookie_hosts)}域)")
            browser_issues.append(f"{bname} Cookies 含 {', '.join(sorted(claude_cookie_hosts)[:4])}")
        found_browsers.append(f"{bname}({', '.join(b_tags) if b_tags else '已安装'})")

    for bname, bpath in other_non_chromium.items():
        if os.path.isdir(bpath):
            found_browsers.append(f"{bname}(已安装)")

    if not found_browsers:
        checks.append(
            make_check(
                "other_browsers",
                "其他浏览器残留与配置扫描 (Chrome/Arc/Brave/Edge/Firefox)",
                "PASS",
                "未安装其他浏览器 (0 残留)",
                "本机仅使用 Safari，不存在 Chrome/Arc/Brave/Edge/Firefox 残留旧 Claude Cookie 或 DoH 冲突。",
            )
        )
        add_inv("Safari & 浏览器", "其他浏览器 (Chrome/Arc/Brave/Edge/Firefox)", "~/Library/Application Support/{Google/Chrome, Arc, Brave, Edge, Firefox...}", "扫描跨浏览器语言、DoH、WebRTC 策略与 Claude/hCaptcha Cookie 域名", "未安装 (0 残留)", "PASS")
    else:
        checks.append(
            make_check(
                "other_browsers",
                "其他浏览器残留与配置扫描 (Chrome/Arc/Brave/Edge/Firefox)",
                "WARN" if browser_issues else "PASS",
                " | ".join(found_browsers),
                f"发现语言/Cookie 残留风险: {'; '.join(browser_issues)}" if browser_issues else "已安装的其他浏览器未发现中文地区配置或 Claude Cookie 残留。",
                "若在这些浏览器登录过旧 Claude 账号，请新建干净 Profile 或清理对应站点数据。" if browser_issues else "",
            )
        )
        add_inv("Safari & 浏览器", "其他浏览器 (Chrome/Arc/Brave/Edge/Firefox)", "~/Library/Application Support/{Chrome, Arc, Brave, Edge, Firefox...}", "扫描跨浏览器语言、DoH、WebRTC 策略与 Claude/hCaptcha Cookie 域名", " | ".join(found_browsers), "WARN" if browser_issues else "PASS")

    return {"title": "Claude 全路径文件与浏览器残留", "checks": checks, "inventory": inventory}


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
def run_full_scan(target_code: str) -> Dict[str, Any]:
    t0 = time.monotonic()
    target_code = target_code.upper()
    if target_code not in TARGETS:
        target_code = "SG"
    target_cfg = TARGETS[target_code]

    cf_domains = [
        "claude.ai",
        "api.anthropic.com",
        "a-api.anthropic.com",
        "console.anthropic.com",
        "platform.claude.com",
        "code.claude.com",
        "challenges.cloudflare.com",
    ]

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
            ("Anthropic Statsig", "https://statsig.anthropic.com/", "critical"),
            ("Claude Portal", "https://claude.com/", "critical"),
            ("Google OAuth", "https://accounts.google.com/Generate204", "critical"),
            ("Apple OAuth", "https://appleid.apple.com/", "critical"),
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

    cf_ok = [r for r in domain_rows if r["ok"]]
    cf_ips = {r["ip"] for r in cf_ok if r["ip"]}
    cf_locs = {r["loc"] for r in cf_ok if r["loc"]}
    if len(cf_ok) == len(domain_rows) and len(cf_ips) == 1 and cf_locs == {target_cfg["code"]}:
        leak_checks.append(
            make_check(
                "domain_consistency",
                "Anthropic / Cloudflare 全域名出口一致性",
                "PASS",
                f"{len(cf_ok)}/{len(domain_rows)} 域名统一经 {next(iter(cf_ips))} ({target_cfg['code']})",
                "claude.ai、api.anthropic.com、platform.claude.com、challenges.cloudflare.com 等全部走同一目标出口。",
            )
        )
    else:
        bad_doms = [
            f"{r['domain']}({r.get('loc') or r.get('error')})"
            for r in domain_rows
            if not r["ok"] or r.get("loc") != target_cfg["code"]
        ]
        leak_checks.append(
            make_check(
                "domain_consistency",
                "Anthropic / Cloudflare 全域名出口一致性",
                "FAIL",
                f"存在分流/失败域名: {', '.join(bad_doms) if bad_doms else f'多出口 IP {cf_ips}'}",
                "部分 Anthropic 或 Cloudflare 域名未走同一目标节点，会导致服务端与验证服务看到不同 IP/国家。",
                "确保所有 anthropic.com / claude.ai / claude.com / cloudflare.com / stripe.com / stripe.network / hcaptcha.com / statsig.anthropic.com 走同一节点。",
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
        leak_checks.append(
            make_check(
                "split_dns_divergence",
                "风控关键域名本地 DNS 污染与 Fake-IP 分叉检测",
                "WARN",
                "本地 DNS 解析全部失败 (0/7)",
                "无法通过系统 DNS 解析 claude.ai / stripe.network / statsig.anthropic.com，请检查本机 DNS 或代理状态。",
            )
        )
    else:
        mode_tag = f"全部统一 Fake-IP ({len(fakeip_doms)}/7)" if fakeip_doms else f"全部统一真实解析 ({len(realip_doms)}/7)"
        leak_checks.append(
            make_check(
                "split_dns_divergence",
                "风控关键域名本地 DNS 污染与 Fake-IP 分叉检测",
                "PASS",
                mode_tag,
                "claude.ai、api.anthropic.com、statsig.anthropic.com、m.stripe.network、api.stripe.com、api.hcaptcha.com、challenges.cloudflare.com 解析模式一致且无 DNS 劫持。",
            )
        )

    # Claude login edge gate & Third-party payment/CAPTCHA/telemetry endpoints
    if edge_res.get("blocked"):
        leak_checks.append(
            make_check(
                "claude_edge_gate",
                "Claude 登录边缘地区准入实测 (claude.ai/login)",
                "FAIL",
                f"拦截重定向: {edge_res.get('redirect_url') or edge_res.get('http_code')}",
                "访问 https://claude.ai/login 直接触发地区不可用重定向/403！",
                "更换目标支持地区的干净节点并清理本地指纹。",
                severity="critical",
            )
        )
    elif edge_res.get("cf_challenge"):
        leak_checks.append(
            make_check(
                "claude_edge_gate",
                "Claude 登录边缘地区准入实测 (claude.ai/login)",
                "WARN",
                f"HTTP 403 · cf-mitigated: challenge ({edge_res.get('latency_ms')}ms)",
                "未触发 app-unavailable-in-region 地区拦截重定向，但当前 IP 对无 Cookie 请求触发了 Cloudflare 人机盾挑战（若真实浏览器下也频繁弹盾，说明该 IP 信誉一般）。",
                severity="low",
            )
        )
    elif not edge_res.get("ok"):
        leak_checks.append(
            make_check(
                "claude_edge_gate",
                "Claude 登录边缘地区准入实测 (claude.ai/login)",
                "FAIL",
                edge_res.get("error", "请求失败"),
                "无法正常触达 https://claude.ai/login 登录入口。",
                "检查代理节点连通性。",
                severity="high",
            )
        )
    else:
        leak_checks.append(
            make_check(
                "claude_edge_gate",
                "Claude 登录边缘地区准入实测 (claude.ai/login)",
                "PASS",
                f"HTTP {edge_res.get('http_code')} ({edge_res.get('latency_ms')}ms)",
                "claude.ai/login 入口响应正常，未触发 app-unavailable-in-region 地区拦截重定向。",
            )
        )

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
                    "链路 RTT 过高（>2500ms），极易导致 Stripe.js、hCaptcha 与 TLS 握手超时，也常意味着多重中转。",
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
    tele_fail = [r for r in tp_only if not r["ok"] and r.get("category") != "critical"]
    ok_tp_cnt = sum(1 for r in tp_only if r["ok"])
    tp_summary = "；".join(f"{r['name']}:{r['http_code'] or 'ERR'}({r['latency_ms']}ms)" for r in tp_only)
    if crit_fail:
        leak_checks.append(
            make_check(
                "third_party_endpoints",
                "第三方风控 / 支付 / Statsig / 人机验证接口连通性",
                "FAIL",
                f"关键接口异常 {len(crit_fail)} 项 ({', '.join(r['name'] for r in crit_fail)})",
                f"{tp_summary}。Stripe / m.stripe.network / hCaptcha / Statsig / OAuth 加载失败会直接导致支付风控拒付或人机验证失败。",
                "检查节点链路质量或分流规则，确保 stripe.com、stripe.network、hcaptcha.com、statsig.anthropic.com、challenges.cloudflare.com 畅通。",
            )
        )
    elif tele_fail:
        leak_checks.append(
            make_check(
                "third_party_endpoints",
                "第三方风控 / 支付 / Statsig / 人机验证接口连通性",
                "WARN",
                f"遥测/客服接口异常 ({', '.join(r['name'] for r in tele_fail)})",
                tp_summary,
            )
        )
    else:
        leak_checks.append(
            make_check(
                "third_party_endpoints",
                "第三方风控 / 支付 / Statsig / 人机验证接口连通性",
                "PASS",
                f"{ok_tp_cnt}/{len(tp_only)} 第三方风控与支付域名全通",
                tp_summary,
            )
        )

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
                    f"存在物理网卡默认路由 {non_utun_defaults} 及 Scoped DNS {scutil_info.get('scoped_private_dns')}。平时走 TUN 没问题，但系统休眠唤醒或 Clash 重载瞬间，后台客户端会立刻走物理网卡直连漏出真实 IP！",
                    "休眠前先退出 Claude Desktop，或确保 Clash 开启严格的断网保护规则。",
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


def _load_pulse_history() -> None:
    global BASELINE_IP
    if not os.path.isfile(PULSE_LOG_PATH):
        return
    try:
        with open(PULSE_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        loaded: List[Dict[str, Any]] = []
        for line in lines[-200:]:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    loaded.append(obj)
            except Exception:
                pass
        with HISTORY_LOCK:
            PULSE_HISTORY.clear()
            for item in loaded:
                PULSE_HISTORY.append(item)
                if BASELINE_IP is None and item.get("ok") and item.get("ip") and item.get("ip") != "-":
                    BASELINE_IP = item["ip"]
    except Exception:
        pass


def _append_pulse_log(event: Dict[str, Any]) -> None:
    try:
        line = json.dumps(event, ensure_ascii=False)
        existing: List[str] = []
        if os.path.isfile(PULSE_LOG_PATH):
            with open(PULSE_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                existing = f.read().splitlines()
        existing.append(line)
        if len(existing) > 500:
            existing = existing[-500:]
        with open(PULSE_LOG_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(existing) + "\n")
    except Exception:
        pass


def _clear_pulse_log() -> None:
    try:
        if os.path.isfile(PULSE_LOG_PATH):
            os.remove(PULSE_LOG_PATH)
    except Exception:
        pass


def run_pulse(target_code: str, wake_detected: bool = False) -> Dict[str, Any]:
    global BASELINE_IP
    target_code = target_code.upper()
    if target_code not in TARGETS:
        target_code = "SG"

    trace = _trace_domain("claude.ai")
    utun_up, utun_ips, _, _ = _check_tun_cross_platform()

    ip = trace.get("ip", "")
    loc = trace.get("loc", "").upper()
    colo = trace.get("colo", "").upper()
    ok = bool(trace.get("ok") and ip)

    with HISTORY_LOCK:
        prev = PULSE_HISTORY[-1] if PULSE_HISTORY else None
        if BASELINE_IP is None and ok:
            BASELINE_IP = ip
        changed_ip = bool(prev and prev.get("ip") and prev["ip"] != "-" and ip and prev["ip"] != ip)
        changed_loc = bool(prev and prev.get("loc") and prev["loc"] != "-" and loc and prev["loc"] != loc)
        anomaly_reasons: List[str] = []
        if wake_detected:
            anomaly_reasons.append("检测到系统休眠唤醒跳变")
        if not ok:
            anomaly_reasons.append(f"连接失败({trace.get('error', 'err')})")
        elif loc != target_code:
            anomaly_reasons.append(f"地区不匹配({loc} != {target_code})")
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


class MonitorController:
    """Autonomous background pulse monitor surviving browser tab close & capturing wake leaks."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._running = False
        self._target = "SG"
        self._interval_sec = 30
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self, target_code: str = "SG", interval_sec: int = 30) -> Dict[str, Any]:
        target_code = target_code.upper()
        if target_code not in TARGETS:
            target_code = "SG"
        interval_sec = max(10, min(300, int(interval_sec)))

        with self._lock:
            if self._running and self._thread and self._thread.is_alive():
                self._stop_event.set()
                old_thread = self._thread
            else:
                old_thread = None

        if old_thread is not None:
            old_thread.join(timeout=2.0)

        with self._lock:
            self._target = target_code
            self._interval_sec = interval_sec
            self._stop_event = threading.Event()
            self._running = True
            self._thread = threading.Thread(target=self._loop, args=(self._stop_event,), daemon=True)
            self._thread.start()
        return self.status()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            self._running = False
            self._stop_event.set()
            th = self._thread
        if th is not None and th.is_alive():
            th.join(timeout=2.0)
        return self.status()

    def _loop(self, stop_evt: threading.Event) -> None:
        last_tick = time.time()
        first = True
        while not stop_evt.is_set():
            with self._lock:
                target = self._target
                interval = self._interval_sec
            now_wall = time.time()
            wake_detected = (not first) and ((now_wall - last_tick) > (interval + 15))
            first = False
            try:
                run_pulse(target, wake_detected=wake_detected)
                if wake_detected and not stop_evt.wait(2.0):
                    run_pulse(target, wake_detected=False)
            except Exception:
                pass
            last_tick = time.time()
            if stop_evt.wait(interval):
                break

    def status(self) -> Dict[str, Any]:
        with self._lock:
            running = self._running and (self._thread is not None and self._thread.is_alive())
            target = self._target
            interval = self._interval_sec
        with HISTORY_LOCK:
            items = list(PULSE_HISTORY)
            baseline = BASELINE_IP
        anomaly_cnt = sum(1 for e in items if e.get("anomaly"))
        jump_cnt = sum(1 for e in items if e.get("changed_ip"))
        wake_cnt = sum(1 for e in items if e.get("wake_detected"))
        return {
            "running": running,
            "target": target,
            "interval_sec": interval,
            "baseline_ip": baseline,
            "total_count": len(items),
            "anomaly_count": anomaly_cnt,
            "jump_count": jump_cnt,
            "wake_count": wake_cnt,
            "latest": items[-1] if items else None,
            "items": items,
        }


MONITOR = MonitorController()
_load_pulse_history()


# ---------------------------------------------------------------------------
# HTTP Server (Strictly Read-Only Detection & Scoring)
# ---------------------------------------------------------------------------
class RegionGuardHandler(http.server.BaseHTTPRequestHandler):
    server_version = "RegionGuard/2.0"

    def log_message(self, format: str, *args: Any) -> None:
        return

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
        if length <= 0 or length > 65536:
            return {}
        try:
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8", errors="replace"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        target = (qs.get("target") or ["SG"])[0]

        if path == "/":
            self._send_static("index.html")
        elif path.startswith("/static/"):
            rel = path[len("/static/") :]
            self._send_static(rel)
        elif path == "/api/headers":
            self._send_json(
                200,
                {
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
                self._send_json(500, {"error": str(exc)})
        elif path == "/api/pulse":
            try:
                res = run_pulse(target)
                self._send_json(200, res)
            except Exception as exc:
                self._send_json(500, {"error": str(exc)})
        elif path == "/api/history":
            with HISTORY_LOCK:
                items = list(PULSE_HISTORY)
                baseline = BASELINE_IP
            self._send_json(200, {"items": items, "baseline_ip": baseline})
        elif path == "/api/monitor/status":
            self._send_json(200, MONITOR.status())
        else:
            self.send_error(404, "Not found")

    def do_POST(self) -> None:
        global BASELINE_IP
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/api/history/clear":
            with HISTORY_LOCK:
                PULSE_HISTORY.clear()
                BASELINE_IP = None
                _clear_pulse_log()
            self._send_json(200, {"ok": True})
        elif parsed.path == "/api/monitor/start":
            body = self._read_json_body()
            target = str((qs.get("target") or [body.get("target") or "SG"])[0])
            raw_int = (qs.get("interval") or [body.get("interval") or 30])[0]
            try:
                interval_sec = int(raw_int)
            except Exception:
                interval_sec = 30
            self._send_json(200, MONITOR.start(target_code=target, interval_sec=interval_sec))
        elif parsed.path == "/api/monitor/stop":
            self._send_json(200, MONITOR.stop())
        else:
            self.send_error(404, "Not found")


class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    parser = argparse.ArgumentParser(description="Region Guard local diagnostic web server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Bind port (default 8765)")
    parser.add_argument("--open", action="store_true", help="Open dashboard in default browser after startup")
    parser.add_argument("--no-open", action="store_true", help="Do not auto-open browser (for frozen exe)")
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("Security guard: server only binds to loopback (127.0.0.1)")

    srv = ThreadingHTTPServer((args.host, args.port), RegionGuardHandler)
    url = f"http://{args.host}:{args.port}"
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
        srv.server_close()


if __name__ == "__main__":
    main()

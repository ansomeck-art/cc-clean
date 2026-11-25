#!/usr/bin/env python3
"""
Region Guard — Windows Native System, Network, Proxy & Claude Residue Audits.

Pure Python 3.9+ standard library module (zero third-party dependencies).
Strictly read-only; never reads or returns secrets, passwords, tokens,
cookie values, or proxy server credentials.
"""

import ctypes
import datetime
import glob
import json
import locale
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

if sys.platform == "win32":
    import winreg  # type: ignore
else:
    winreg = None  # type: ignore

CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0

# Microsoft GeoID (HKCU\Control Panel\International\Geo\Nation) -> ISO 3166-1 alpha-2
WIN_GEOID_MAP: Dict[str, str] = {
    "12": "AU",
    "21": "BE",
    "29": "BY",
    "32": "BR",
    "39": "CA",
    "45": "CN",
    "54": "DK",
    "56": "CU",
    "61": "FI",
    "68": "IE",
    "84": "FR",
    "94": "DE",
    "104": "HK",
    "111": "ID",
    "113": "IN",
    "116": "IR",
    "117": "IL",
    "118": "IT",
    "122": "JP",
    "131": "KP",
    "134": "KR",
    "151": "MO",
    "166": "MX",
    "167": "MY",
    "176": "NL",
    "177": "NO",
    "183": "NZ",
    "191": "PL",
    "193": "PT",
    "201": "PH",
    "203": "RU",
    "215": "SG",
    "217": "ES",
    "221": "SE",
    "222": "SY",
    "223": "CH",
    "224": "AE",
    "227": "TH",
    "235": "TR",
    "237": "TW",
    "241": "UA",
    "242": "GB",
    "244": "US",
    "251": "VN",
}

TARGET_TO_WIN_GEOID: Dict[str, str] = {
    "SG": "215",
    "US": "244",
    "JP": "122",
    "GB": "242",
    "TW": "237",
    "AU": "12",
    "CA": "39",
    "DE": "94",
}

# Windows tzutil ID -> IANA timezone name
WIN_TZ_TO_IANA: Dict[str, str] = {
    "Singapore Standard Time": "Asia/Singapore",
    "Malay Peninsula Standard Time": "Asia/Singapore",
    "China Standard Time": "Asia/Shanghai",
    "Taipei Standard Time": "Asia/Taipei",
    "Tokyo Standard Time": "Asia/Tokyo",
    "Korea Standard Time": "Asia/Seoul",
    "SE Asia Standard Time": "Asia/Bangkok",
    "Pacific Standard Time": "America/Los_Angeles",
    "Mountain Standard Time": "America/Denver",
    "US Mountain Standard Time": "America/Phoenix",
    "Central Standard Time": "America/Chicago",
    "Eastern Standard Time": "America/New_York",
    "US Eastern Standard Time": "America/Indianapolis",
    "Alaskan Standard Time": "America/Anchorage",
    "Hawaiian Standard Time": "Pacific/Honolulu",
    "GMT Standard Time": "Europe/London",
    "UTC": "Etc/UTC",
    "W. Europe Standard Time": "Europe/Berlin",
    "Central Europe Standard Time": "Europe/Budapest",
    "Central European Standard Time": "Europe/Warsaw",
    "Romance Standard Time": "Europe/Paris",
    "AUS Eastern Standard Time": "Australia/Sydney",
    "E. Australia Standard Time": "Australia/Brisbane",
    "W. Australia Standard Time": "Australia/Perth",
    "Cen. Australia Standard Time": "Australia/Adelaide",
    "Tasmania Standard Time": "Australia/Hobart",
    "New Zealand Standard Time": "Pacific/Auckland",
    "Canada Central Standard Time": "America/Regina",
    "Atlantic Standard Time": "America/Halifax",
    "Newfoundland Standard Time": "America/St_Johns",
    "Russian Standard Time": "Europe/Moscow",
    "Belarus Standard Time": "Europe/Minsk",
    "Iran Standard Time": "Asia/Tehran",
    "Syria Standard Time": "Asia/Damascus",
    "North Korea Standard Time": "Asia/Pyongyang",
    "Cuba Standard Time": "America/Havana",
}

TARGET_TO_WIN_TZ: Dict[str, str] = {
    "SG": "Singapore Standard Time",
    "US": "Pacific Standard Time",
    "JP": "Tokyo Standard Time",
    "GB": "GMT Standard Time",
    "TW": "Taipei Standard Time",
    "AU": "AUS Eastern Standard Time",
    "CA": "Eastern Standard Time",
    "DE": "W. Europe Standard Time",
}

RESTRICTED_WIN_TZS = {
    "China Standard Time",
    "Russian Standard Time",
    "Belarus Standard Time",
    "Iran Standard Time",
    "Syria Standard Time",
    "North Korea Standard Time",
    "Cuba Standard Time",
}
RESTRICTED_COUNTRIES = {"CN", "HK", "MO", "RU", "BY", "KP", "IR", "CU", "SY"}
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
    "210.2.4.8",
    "2400:3200::1",
    "2400:3200:baba::1",
    "240c::6666",
    "240c::6644",
    "2402:4e00::",
    "2402:4e00:1::",
}
CN_DOH_KEYWORDS = (
    "alidns.com",
    "doh.pub",
    "dnspod.cn",
    "doh.360.cn",
    "rubyfish.cn",
    "223.5.5.5",
    "223.6.6.6",
    "119.29.29.29",
    "114.114.114.114",
)
PROXY_EXT_KEYWORDS = (
    "switchyomega",
    "zeroomega",
    "proxy switchy",
    "smartproxy",
    "foxyproxy",
    "clash",
    "v2ray",
    "vpn",
    "hoxx",
    "browsec",
    "urban vpn",
    "hola",
)


def _has_cjk(text: str) -> bool:
    return any("\u4e00" <= ch <= "\u9fff" for ch in text)


def _has_non_ascii(text: str) -> bool:
    return any(ord(ch) > 127 for ch in text)


def _match_risk_domain(host: str) -> bool:
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


def _make_check(
    cid: str,
    title: str,
    status: str,
    observed: str,
    detail: str,
    fix_advice: str = "",
    fix_cmd: str = "",
    severity: str = "auto",
) -> Dict[str, str]:
    sev = ("high" if status == "FAIL" else "low") if severity == "auto" else severity
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


def _get_win_oem_encoding() -> str:
    if sys.platform == "win32":
        try:
            cp = ctypes.windll.kernel32.GetOEMCP()  # type: ignore[attr-defined]
            if cp:
                return f"cp{cp}"
        except Exception:
            pass
    return locale.getpreferredencoding(False) or "utf-8"


def _decode_win_bytes(raw: bytes) -> str:
    """Decode Windows console command bytes safely across UTF-8 and OEM codepages (e.g. CP936/GBK)."""
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    oem = _get_win_oem_encoding()
    for enc in (oem, locale.getpreferredencoding(False), "gb18030", "mbcs"):
        if not enc:
            continue
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


def _run_win_cmd(cmd: List[str], timeout: int = 6) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return proc.returncode, _decode_win_bytes(proc.stdout), _decode_win_bytes(proc.stderr)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:
        return 1, "", str(exc)


def _read_reg(root_name: str, subkey: str, value_name: str, default: Any = None) -> Any:
    if winreg is None:
        return default
    root = getattr(winreg, root_name, None)
    if root is None:
        return default
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as k:
            val, _ = winreg.QueryValueEx(k, value_name)
            return val
    except Exception:
        return default


def _reg_last_write_ts(root_name: str, subkey: str) -> float:
    """Return Unix timestamp of a registry key's last modification time (FILETIME -> epoch)."""
    if winreg is None:
        return 0.0
    root = getattr(winreg, root_name, None)
    if root is None:
        return 0.0
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as k:
            _, _, filetime = winreg.QueryInfoKey(k)
            if filetime and filetime > 116444736000000000:
                return (filetime - 116444736000000000) / 1e7
    except Exception:
        pass
    return 0.0


def _win_boot_timestamp() -> float:
    """Return approximate Unix epoch timestamp of last Windows boot via GetTickCount64."""
    if sys.platform != "win32":
        return 0.0
    try:
        uptime_ms = ctypes.windll.kernel32.GetTickCount64()  # type: ignore[attr-defined]
        now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
        return now_ts - (uptime_ms / 1000.0)
    except Exception:
        return 0.0


def _list_reg_values(root_name: str, subkey: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if winreg is None:
        return out
    root = getattr(winreg, root_name, None)
    if root is None:
        return out
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as k:
            idx = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, idx)
                    out[str(name)] = val
                    idx += 1
                except OSError:
                    break
    except Exception:
        pass
    return out


def _list_reg_subkeys(root_name: str, subkey: str) -> List[str]:
    out: List[str] = []
    if winreg is None:
        return out
    root = getattr(winreg, root_name, None)
    if root is None:
        return out
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as k:
            idx = 0
            while True:
                try:
                    out.append(str(winreg.EnumKey(k, idx)))
                    idx += 1
                except OSError:
                    break
    except Exception:
        pass
    return out


def _reg_key_exists(root_name: str, subkey: str) -> bool:
    if winreg is None:
        return False
    root = getattr(winreg, root_name, None)
    if root is None:
        return False
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ):
            return True
    except Exception:
        return False


def _safe_sqlite_query(db_path: str, sql: str) -> Tuple[str, List[Tuple[Any, ...]]]:
    """
    Copy SQLite DB alongside -wal and -shm into a temp directory and query read-only.
    Returns (status, rows) where status is 'ok', 'locked', or 'error'.
    """
    if not db_path or not os.path.isfile(db_path):
        return "missing", []
    with tempfile.TemporaryDirectory(prefix="rg_sql_") as tmpdir:
        base = os.path.basename(db_path)
        dst = os.path.join(tmpdir, base)
        try:
            shutil.copy2(db_path, dst)
        except PermissionError:
            return "locked", []
        except OSError as exc:
            if getattr(exc, "winerror", None) in {32, 33, 5}:
                return "locked", []
            return "error", []
        for suffix in ("-wal", "-shm"):
            src_extra = db_path + suffix
            if os.path.isfile(src_extra):
                try:
                    shutil.copy2(src_extra, dst + suffix)
                except Exception:
                    pass
        conn = None
        try:
            conn = sqlite3.connect(dst)
            rows = conn.execute(sql).fetchall()
            return "ok", rows
        except sqlite3.OperationalError:
            return "error", []
        except Exception:
            return "error", []
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass


def _parse_tasklist_csv(csv_text: str) -> List[str]:
    names: Set[str] = set()
    for line in csv_text.splitlines():
        s = line.strip()
        if not s:
            continue
        m = re.match(r'^"([^"]+)"', s)
        if m:
            names.add(m.group(1).strip())
    return sorted(names)


def _is_tun_adapter(adapter_name: str, desc: str, ip_list: List[str]) -> bool:
    tun_kw = (
        "clash", "mihomo", "wintun", "meta", "sing-box", "singbox",
        "tun", "tap-windows", "wireguard", "tailscale", "flclash",
        "nekobox", "v2ray", "hiddify", "mullvad", "warp", "cloudflare",
        "openvpn", "outline", "surge", "shadowsocks",
    )
    combo = f"{adapter_name} {desc}".lower()
    if any(k in combo for k in tun_kw):
        return True
    return any(ip.startswith(("198.18.", "172.19.")) for ip in ip_list)


def _is_virtual_local_adapter(adapter_name: str, desc: str) -> bool:
    virt_kw = ("wsl", "hyper-v", "vethernet", "vmware", "virtualbox", "docker", "loopback", "bluetooth")
    combo = f"{adapter_name} {desc}".lower()
    return any(k in combo for k in virt_kw)


def _parse_ipconfig_all(text: str) -> Dict[str, Any]:
    """Parse ipconfig /all (English or Chinese locale) per adapter for TUN, IPv6, and IPv4/IPv6 DNS."""
    adapters: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    in_dns = False

    ip4_pat = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    ip6_pat = re.compile(r"([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})")

    def _extract_dns_ips(chunk: str, target_list: List[str]) -> None:
        cleaned = chunk.split("%")[0].strip()
        found_v4 = ip4_pat.findall(cleaned)
        for m4 in found_v4:
            if m4 not in target_list:
                target_list.append(m4)
        if not found_v4 and ":" in cleaned:
            m6 = ip6_pat.search(cleaned)
            if m6:
                addr6 = m6.group(1).lower()
                if addr6 not in target_list and not addr6.startswith("fec0:0:0:ffff"):
                    target_list.append(addr6)

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            in_dns = False
            continue
        if not line[0].isspace() and line.endswith(":"):
            cur = {
                "name": line[:-1].strip(),
                "desc": "",
                "ipv4": [],
                "global_v6": [],
                "dns": [],
                "media_disconnected": False,
            }
            adapters.append(cur)
            in_dns = False
            continue

        if cur is None:
            continue

        s = line.strip()
        low = s.lower()

        if any(k in low for k in ("media disconnected", "媒体已断开")):
            cur["media_disconnected"] = True
            in_dns = False
            continue

        if any(k in low for k in ("description", "描述")):
            if ":" in s:
                cur["desc"] = s.split(":", 1)[1].strip()
            in_dns = False
            continue

        if any(k in low for k in ("dns servers", "dns 服务器")):
            in_dns = True
            after = s.split(":", 1)[1].strip() if ":" in s else ""
            _extract_dns_ips(after, cur["dns"])
            continue

        if in_dns and " . " not in s and not re.match(r"^[A-Za-z\u4e00-\u9fff][^\d:]{2,}:", s):
            _extract_dns_ips(s, cur["dns"])
            continue
        in_dns = False

        if any(k in low for k in ("ipv4 address", "ipv4 地址", "autoconfiguration ipv4", "自动配置 ipv4")):
            after = s.split(":", 1)[1] if ":" in s else s
            m4 = ip4_pat.search(after)
            if m4 and m4.group(1) not in cur["ipv4"]:
                cur["ipv4"].append(m4.group(1))
        elif any(k in low for k in ("ipv6 address", "ipv6 地址", "temporary ipv6", "临时 ipv6")):
            if "link-local" in low or "本地链接" in low:
                continue
            after = s.split(":", 1)[1] if ":" in s else s
            after = after.split("(")[0].split("%")[0].strip()
            m6 = ip6_pat.search(after)
            if m6:
                addr = m6.group(1).lower()
                if ":" in addr and not addr.startswith(("fe80:", "::1", "fc", "fd")):
                    if addr not in cur["global_v6"]:
                        cur["global_v6"].append(addr)

    tun_ips: List[str] = []
    tun_ip_set: Set[str] = set()
    global_v6: List[str] = []
    tun_dns: List[str] = []
    physical_dns: List[str] = []
    all_dns: List[str] = []

    for ad in adapters:
        if ad["media_disconnected"]:
            continue
        is_tun = _is_tun_adapter(ad["name"], ad["desc"], ad["ipv4"])
        is_virt = _is_virtual_local_adapter(ad["name"], ad["desc"])
        if is_tun:
            for ip in ad["ipv4"]:
                tun_ips.append(f"{ad['name']}: {ip}")
                tun_ip_set.add(ip)
            for d in ad["dns"]:
                if d not in tun_dns:
                    tun_dns.append(d)
                if d not in all_dns:
                    all_dns.append(d)
        else:
            if not is_virt:
                for addr6 in ad["global_v6"]:
                    global_v6.append(f"{ad['name']}: {addr6}")
                for d in ad["dns"]:
                    if d not in physical_dns:
                        physical_dns.append(d)
            for d in ad["dns"]:
                if d not in all_dns:
                    all_dns.append(d)

    return {
        "adapters": adapters,
        "tun_ips": tun_ips,
        "tun_ip_set": tun_ip_set,
        "global_v6": global_v6,
        "dns_servers": all_dns,
        "tun_dns": tun_dns,
        "physical_dns": physical_dns,
    }


def _parse_route_print_v4(text: str) -> List[Dict[str, Any]]:
    routes: List[Dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gw, iface, metric_s = parts[2], parts[3], parts[4]
            try:
                metric = int(metric_s)
            except Exception:
                metric = 9999
            routes.append(
                {
                    "family": "v4",
                    "gw": gw,
                    "iface": iface,
                    "metric": metric,
                    "text": f"0.0.0.0 -> {gw} (iface={iface}, metric={metric})",
                }
            )
    return routes


def _parse_route_print_v6(text: str) -> List[Dict[str, Any]]:
    routes: List[Dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "::/0":
            if_idx, metric_s, gw = parts[0], parts[1], parts[3]
            try:
                metric = int(metric_s)
            except Exception:
                metric = 9999
            routes.append(
                {
                    "family": "v6",
                    "gw": gw,
                    "iface": f"if#{if_idx}",
                    "metric": metric,
                    "text": f"::/0 -> {gw} (if={if_idx}, metric={metric})",
                }
            )
    return routes


def win_check_tun_details() -> Dict[str, Any]:
    """Structured Windows TUN, route metric priority, IPv6 default route, and per-adapter DNS audit."""
    _, ipcfg, _ = _run_win_cmd(["ipconfig", "/all"], timeout=5)
    _, rt4_out, _ = _run_win_cmd(["route", "print", "-4"], timeout=5)
    _, rt6_out, _ = _run_win_cmd(["route", "print", "-6"], timeout=5)

    parsed = _parse_ipconfig_all(ipcfg)
    tun_ips: List[str] = parsed["tun_ips"]
    tun_ip_set: Set[str] = parsed["tun_ip_set"]
    global_v6: List[str] = parsed["global_v6"]
    v4_routes = _parse_route_print_v4(rt4_out)
    v6_routes = _parse_route_print_v6(rt6_out)

    tun_v4_routes: List[Dict[str, Any]] = []
    non_tun_v4_routes: List[Dict[str, Any]] = []
    for r in v4_routes:
        if r["iface"] in tun_ip_set or r["iface"].startswith(("198.18.", "172.19.")) or r["gw"].startswith(("198.18.", "172.19.")):
            tun_v4_routes.append(r)
        else:
            non_tun_v4_routes.append(r)

    tun_up = bool(tun_ips) or bool(tun_v4_routes)
    min_tun_metric = min((r["metric"] for r in tun_v4_routes), default=999999)
    min_phys_metric = min((r["metric"] for r in non_tun_v4_routes), default=999999)
    tun_has_lowest_metric = bool(tun_v4_routes) and (min_tun_metric <= min_phys_metric)

    priv_pat = re.compile(r"^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)")
    physical_dns = parsed["physical_dns"]
    physical_private_dns = [d for d in physical_dns if priv_pat.match(d)]
    cn_dns = [d for d in parsed["dns_servers"] if d.lower() in CN_DNS_SERVERS]

    default_routes = [r["text"] for r in v4_routes] + [r["text"] for r in v6_routes]
    non_tun_defaults = [r["text"] for r in non_tun_v4_routes] + [r["text"] for r in v6_routes]

    return {
        "tun_up": tun_up,
        "tun_ips": tun_ips,
        "tun_ip_set": tun_ip_set,
        "default_routes": default_routes,
        "non_tun_defaults": non_tun_defaults,
        "ipv6_default_routes": [r["text"] for r in v6_routes],
        "tun_has_lowest_metric": tun_has_lowest_metric,
        "global_v6": global_v6,
        "dns_servers": parsed["dns_servers"],
        "tun_dns": parsed["tun_dns"],
        "physical_dns": physical_dns,
        "physical_private_dns": physical_private_dns,
        "cn_dns": cn_dns,
    }


def win_check_tun_status() -> Tuple[bool, List[str], List[str], List[str]]:
    """Windows equivalent of _check_utun_status: (tun_up, tun_ips, default_routes, global_v6)."""
    d = win_check_tun_details()
    return d["tun_up"], d["tun_ips"], d["default_routes"], d["global_v6"]


def win_check_dns_and_proxy(tun_details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Windows equivalent of _check_dns_and_proxy_scutil (WinINET + WinHTTP + per-adapter DNS)."""
    if tun_details is None:
        tun_details = win_check_tun_details()

    inet_key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    proxy_enable = bool(_read_reg("HKEY_CURRENT_USER", inet_key, "ProxyEnable", 0))
    proxy_server = str(_read_reg("HKEY_CURRENT_USER", inet_key, "ProxyServer", "") or "").strip()
    pac_url = str(_read_reg("HKEY_CURRENT_USER", inet_key, "AutoConfigURL", "") or "").strip()
    proxy_override = str(_read_reg("HKEY_CURRENT_USER", inet_key, "ProxyOverride", "") or "").strip()

    proxies: Dict[str, str] = {}
    if proxy_enable and proxy_server:
        proxies["ProxyEnable"] = "1"
        proxies["ProxyServer"] = re.sub(r"://[^/@\s]+@", "://<REDACTED>@", proxy_server)
    if pac_url:
        proxies["AutoConfigURL"] = re.sub(r"://[^/@\s]+@", "://<REDACTED>@", pac_url)
    if proxy_override:
        proxies["ProxyOverride"] = proxy_override[:140]

    bypass_risk: List[str] = []
    if proxy_override:
        for tok in re.split(r"[;,\s]+", proxy_override):
            tl = tok.strip().lower().lstrip("*.")
            if not tl:
                continue
            if any(k in tl for k in ("claude", "anthropic", "stripe", "hcaptcha", "cloudflare", "statsig")):
                bypass_risk.append(tok.strip())

    # WinHTTP proxy check (best-effort; some minimal Windows editions omit winhttp netsh helper)
    winhttp_proxy = ""
    rc_wh, wh_out, _ = _run_win_cmd(["netsh", "winhttp", "show", "proxy"], timeout=3)
    if rc_wh == 0 and wh_out:
        low_wh = wh_out.lower()
        if "direct access" not in low_wh and "直接访问" not in low_wh:
            for line in wh_out.splitlines():
                if ":" in line and any(k in line.lower() for k in ("proxy server", "代理服务器")):
                    val = line.split(":", 1)[1].strip()
                    if val:
                        winhttp_proxy = re.sub(r"://[^/@\s]+@", "://<REDACTED>@", val)
                        break

    return {
        "dns_servers": tun_details["dns_servers"],
        "tun_dns": tun_details["tun_dns"],
        "physical_dns": tun_details["physical_dns"],
        "scoped_private_dns": tun_details["physical_private_dns"],
        "cn_dns": tun_details["cn_dns"],
        "proxies": proxies,
        "proxy_enable": proxy_enable,
        "proxy_bypass_risk": bypass_risk,
        "winhttp_proxy": winhttp_proxy,
    }


def _discover_windows_clash_configs() -> List[Tuple[str, str]]:
    """Return (client_label, yaml_path) for existing Windows Clash/Mihomo config files."""
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    userprofile = os.environ.get("USERPROFILE", os.path.expanduser("~"))
    candidates = [
        ("Clash Verge Rev", os.path.join(appdata, "io.github.clash-verge-rev.clash-verge-rev", "clash-verge.yaml")),
        ("Clash Verge Rev", os.path.join(appdata, "io.github.clash-verge-rev.clash-verge-rev", "config.yaml")),
        ("Clash Verge", os.path.join(appdata, "clash-verge", "clash-verge.yaml")),
        ("Clash Verge", os.path.join(appdata, "clash-verge", "config.yaml")),
        ("Mihomo Party", os.path.join(appdata, "mihomo-party", "work", "config.yaml")),
        ("Mihomo Party", os.path.join(appdata, "mihomo-party", "config.yaml")),
        ("Clash Party", os.path.join(appdata, "clash-party", "work", "config.yaml")),
        ("Clash Party", os.path.join(appdata, "clash-party", "config.yaml")),
        ("FlClash", os.path.join(appdata, "com.follow.clash", "config.yaml")),
        ("FlClash", os.path.join(appdata, "FlClash", "config.yaml")),
        ("Clash Nyanpasu", os.path.join(appdata, "clash-nyanpasu", "clash-config.yaml")),
        ("Clash Nyanpasu", os.path.join(appdata, "clash-nyanpasu", "config.yaml")),
        ("Clash for Windows", os.path.join(userprofile, ".config", "clash", "config.yaml")),
        ("Mihomo", os.path.join(userprofile, ".config", "mihomo", "config.yaml")),
        ("Mihomo (Local)", os.path.join(localappdata, "mihomo", "config.yaml")),
    ]
    found: List[Tuple[str, str]] = []
    seen = set()
    for label, path in candidates:
        if path and os.path.isfile(path) and path not in seen:
            seen.add(path)
            found.append((label, path))
    return found


def win_audit_clash_proxy(
    safe_parse_yaml: Callable[[str], Dict[str, Any]],
    tun_details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Windows equivalent of audit_clash_proxy (strictly redacted)."""
    checks: List[Dict[str, str]] = []
    if tun_details is None:
        tun_details = win_check_tun_details()
    tun_up = bool(tun_details["tun_up"])

    _, tl_out, _ = _run_win_cmd(["tasklist", "/FO", "CSV", "/NH"], timeout=4)
    all_procs = _parse_tasklist_csv(tl_out)
    proxy_pat = re.compile(
        r"clash|mihomo|verge|v2ray|xray|sing-box|singbox|nekoray|nekobox|hiddify|flclash|tailscale|wireguard|openvpn|shadowsocks|trojan|mullvad|warp|nyanpasu",
        re.I,
    )
    proxy_procs = [p for p in all_procs if proxy_pat.search(p)]
    checks.append(
        _make_check(
            "proxy_process",
            "代理 / VPN 运行状态 (Windows)",
            "PASS" if proxy_procs else "WARN",
            f"运行中 {len(proxy_procs)} 个" if proxy_procs else "未检测到常见代理进程",
            f"检测到代理进程: {', '.join(proxy_procs[:10])}" if proxy_procs else "未在 tasklist 中发现常见代理内核进程，请确认代理客户端已启动。",
            "" if proxy_procs else "请确认 Clash Verge Rev / Mihomo Party / FlClash / v2rayN 等已运行并接管流量。",
        )
    )

    net_info = win_check_dns_and_proxy(tun_details)
    proxies = net_info["proxies"]
    bypass_risk = net_info["proxy_bypass_risk"]
    winhttp_proxy = net_info["winhttp_proxy"]

    if bypass_risk:
        checks.append(
            _make_check(
                "win_sys_proxy",
                "Windows 系统代理与绕过规则 (WinINET / WinHTTP)",
                "FAIL",
                f"ProxyOverride 误放行风险域名: {', '.join(bypass_risk)}",
                "Windows 系统代理绕过列表（ProxyOverride）中包含 Anthropic/Claude/Stripe/hCaptcha/Cloudflare 相关域名，会导致这些请求直连本地网络！",
                "在代理客户端或 Windows 代理设置中清理绕过列表中的相关域名。",
                severity="critical",
            )
        )
    elif proxies and not tun_up:
        p_desc = ", ".join(f"{k}={v}" for k, v in proxies.items() if k != "ProxyOverride")
        checks.append(
            _make_check(
                "win_sys_proxy",
                "Windows 系统代理与绕过规则 (WinINET / WinHTTP)",
                "WARN",
                f"{p_desc} (TUN 未开启!)" + (f" | WinHTTP={winhttp_proxy}" if winhttp_proxy else ""),
                "当前仅开启了 Windows 系统代理但未开启 TUN 虚拟网卡！Chrome/Edge 会走系统代理，但 curl、Claude Code CLI、UDP/STUN 及部分 Electron/系统后台请求不读 WinINET 代理会直接走本地直连漏 IP。",
                "强烈建议在 Clash Verge / Mihomo Party / v2rayN 中开启 TUN 虚拟网卡模式（需以管理员/服务模式安装）。",
                severity="high",
            )
        )
    elif proxies:
        p_desc = ", ".join(f"{k}={v}" for k, v in proxies.items() if k != "ProxyOverride")
        checks.append(
            _make_check(
                "win_sys_proxy",
                "Windows 系统代理与绕过规则 (WinINET / WinHTTP)",
                "INFO",
                p_desc + (f" | WinHTTP={winhttp_proxy}" if winhttp_proxy else ""),
                "Windows 系统代理与 TUN 均已启用。若浏览器与后端出口 IP 一致则正常；如出现端口冲突或规则分叉，可尝试仅保留纯 TUN 模式。",
            )
        )
    else:
        checks.append(
            _make_check(
                "win_sys_proxy",
                "Windows 系统代理与绕过规则 (WinINET / WinHTTP)",
                "PASS" if tun_up else "INFO",
                ("纯 TUN 模式 (未开系统 HTTP 代理)" if tun_up else "未开启系统 HTTP/PAC 代理")
                + (f" | WinHTTP={winhttp_proxy}" if winhttp_proxy else ""),
                "纯 TUN 虚拟网卡接管模式下所有 TCP/UDP 应用统一走代理，是最不容易分叉的方案。" if tun_up else "未开启系统代理且未检测到 TUN，请核对上方出口 IP 是否经目标节点。",
            )
        )

    configs = _discover_windows_clash_configs()
    if configs:
        client_label, cfg_path = configs[0]
        parsed = safe_parse_yaml(cfg_path)
        mode = parsed.get("mode") or "unknown"
        if mode.lower() == "global":
            checks.append(_make_check("clash_mode", f"{client_label} 代理模式", "PASS", mode, "当前为 Global 全局模式，所有流量统一走选定节点。"))
        elif mode.lower() == "rule":
            checks.append(
                _make_check(
                    "clash_mode",
                    f"{client_label} 代理模式",
                    "WARN",
                    mode,
                    "当前为 Rule 规则模式，若分流规则遗漏（如漏掉 stripe.network / statsig.anthropic.com）或 DNS 回落本地可能直连泄露。",
                    "使用 Claude 期间建议切换为 Global，或严格核对 Anthropic/Stripe/hCaptcha/Statsig 规则。",
                )
            )
        elif mode != "unknown":
            checks.append(
                _make_check(
                    "clash_mode",
                    f"{client_label} 代理模式",
                    "FAIL",
                    mode,
                    f"当前模式为 {mode}，存在直连泄露风险。",
                    "切换为 Global 或严格 Rule 模式。",
                    severity="high",
                )
            )

        ns_all = (
            (parsed.get("dns_nameserver") or [])
            + (parsed.get("dns_default_nameserver") or [])
            + (parsed.get("dns_proxy_server_nameserver") or [])
            + (parsed.get("dns_fallback") or [])
        )
        has_bad_dns = any(
            x.lower() == "system"
            or any(cn in x.lower() for cn in ("114.114", "223.5.5.5", "223.6.6.6", "119.29.29.29", "180.76.76.76", "alidns", "doh.pub"))
            for x in ns_all
        )
        dns_desc = f"enhanced-mode={parsed.get('dns_enhanced_mode') or '-'}, nameserver={parsed.get('dns_nameserver') or ['-']}"
        checks.append(
            _make_check(
                "clash_dns",
                f"{client_label} 内置 DNS 配置",
                "WARN" if has_bad_dns else "PASS",
                "包含 system 或国内上游 DNS" if has_bad_dns else dns_desc,
                f"{dns_desc}。" + ("建议将 nameserver 改为海外加密 DoH（如 https://1.1.1.1/dns-query）。" if has_bad_dns else "未引用本地 system 或国内公共 DNS。"),
                "在代理客户端 DNS 设置中改用海外 DoH/DoT。" if has_bad_dns else "",
            )
        )

        # Check TUN config & direct risk rules
        tun_en = parsed.get("tun_enable")
        strict_rt = parsed.get("tun_strict_route")
        direct_risk_rules = parsed.get("direct_risk_rules") or []
        fakeip_risk_filters = parsed.get("fakeip_risk_filters") or []
        if direct_risk_rules or fakeip_risk_filters:
            checks.append(
                _make_check(
                    "clash_direct_risk_rules",
                    f"{client_label} 规则与 Fake-IP 放行冲突",
                    "FAIL",
                    f"DIRECT 命中 {len(direct_risk_rules)} 条 | fake-ip-filter 命中 {len(fakeip_risk_filters)} 条",
                    f"检测到可能放行 Claude/风控域名的配置: {', '.join((direct_risk_rules + fakeip_risk_filters)[:5])}",
                    "从 DIRECT 规则和 fake-ip-filter 中移除 anthropic / claude / stripe / hcaptcha / statsig / cloudflare 相关条目。",
                    severity="critical",
                )
            )
        elif tun_en is not None:
            tun_note = f"tun.enable={tun_en}, stack={parsed.get('tun_stack') or '-'}, strict-route={strict_rt}"
            if tun_en and strict_rt is False:
                checks.append(
                    _make_check(
                        "clash_tun_cfg",
                        f"{client_label} TUN 严格路由配置",
                        "WARN",
                        tun_note,
                        "已启用 TUN 但 strict-route=false，部分系统连接可能绕过 TUN 直连物理网卡。",
                        "在 TUN 设置中开启 strict-route: true 与 auto-route: true。",
                    )
                )
            else:
                checks.append(_make_check("clash_tun_cfg", f"{client_label} TUN 严格路由配置", "PASS" if tun_en else "INFO", tun_note, "Clash TUN 配置已核查。"))
    else:
        checks.append(
            _make_check(
                "clash_config_missing",
                "Clash / Mihomo 配置文件探测",
                "INFO",
                "未发现常见路径下的 Clash/Mihomo 运行配置",
                "若你使用 v2rayN、sing-box 或其他客户端，此提示正常；请参考上方全域名分流、Fake-IP 与 DNS 实测结果。",
            )
        )

    return {"title": "代理与 Windows 客户端配置 (脱敏)", "checks": checks}


def win_audit_system(target_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Windows comprehensive OS fingerprint & anti-risk audit."""
    checks: List[Dict[str, str]] = []
    t_code = target_cfg["code"]

    # 1. Windows GeoID Country
    geo_key = r"Control Panel\International\Geo"
    nation_id = str(_read_reg("HKEY_CURRENT_USER", geo_key, "Nation", "") or "").strip()
    geo_name = str(_read_reg("HKEY_CURRENT_USER", geo_key, "Name", "") or "").strip().upper()
    sys_country = geo_name or WIN_GEOID_MAP.get(nation_id, "")
    target_geoid = TARGET_TO_WIN_GEOID.get(t_code, "215")
    fix_geo_cmd = f"Set-WinHomeLocation -GeoId {target_geoid}"

    if sys_country == t_code:
        checks.append(_make_check("sys_country", "Windows 国家/地区代码 (GeoID)", "PASS", f"{sys_country} (GeoID={nation_id or '-'})", f"系统区域已设置为 {t_code}。"))
    elif sys_country in RESTRICTED_COUNTRIES:
        checks.append(
            _make_check(
                "sys_country",
                "Windows 国家/地区代码 (GeoID)",
                "FAIL",
                f"{sys_country} (GeoID={nation_id or '-'})",
                f"Windows 国家或地区仍设为 {sys_country}，与目标地区 {t_code} 冲突。",
                f"在 设置 -> 时间和语言 -> 语言和区域 中将国家/地区改为 {target_cfg['name']}，或在 PowerShell 执行命令。",
                fix_geo_cmd,
                severity="high",
            )
        )
    else:
        checks.append(
            _make_check(
                "sys_country",
                "Windows 国家/地区代码 (GeoID)",
                "WARN",
                f"{sys_country or '未知'} (GeoID={nation_id or '-'})",
                f"Windows 国家/地区与目标 {t_code} 不一致。",
                f"建议统一设置为 {t_code}。",
                fix_geo_cmd,
                severity="high",
            )
        )

    # 2. Windows Locale, Preferred Languages, Display UI Language & Non-Unicode System Locale
    intl_key = r"Control Panel\International"
    locale_name = str(_read_reg("HKEY_CURRENT_USER", intl_key, "LocaleName", "") or "").strip()
    pref_langs = _read_reg("HKEY_CURRENT_USER", r"Control Panel\International\User Profile", "Languages", [])
    if not isinstance(pref_langs, list):
        pref_langs = [str(pref_langs)] if pref_langs else []
    ui_langs = _read_reg("HKEY_CURRENT_USER", r"Control Panel\Desktop", "PreferredUILanguages", [])
    if not isinstance(ui_langs, list):
        ui_langs = [str(ui_langs)] if ui_langs else []
    sys_nls_default = str(
        _read_reg("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Control\Nls\Language", "Default", "") or ""
    ).strip().lower()
    sys_nls_install = str(
        _read_reg("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Control\Nls\Language", "InstallLanguage", "") or ""
    ).strip().lower()

    is_cn_locale = (
        locale_name.lower().startswith(("zh-cn", "zh_cn", "zh-hans"))
        or any(str(x).lower().startswith(("zh-cn", "zh-hans")) for x in pref_langs[:1])
        or any(str(x).lower().startswith(("zh-cn", "zh-hans")) for x in ui_langs[:1])
    )
    is_cn_non_unicode = sys_nls_default == "0804"
    is_cn_install = sys_nls_install == "0804"
    loc_obs = (
        f"Locale={locale_name or '-'} | 显示语言={', '.join(ui_langs[:2]) or '-'} | "
        f"首选语言={', '.join(pref_langs[:3]) or '-'} | 非Unicode={sys_nls_default or '-'} | 安装SKU={sys_nls_install or '-'}"
    )
    if is_cn_locale and t_code != "TW":
        checks.append(
            _make_check(
                "user_locale",
                "Windows 区域格式、显示语言与首选语言",
                "FAIL",
                loc_obs,
                "当前 Windows 区域格式、显示语言或首选语言为简体中文，Chrome/Edge/Claude Desktop 都会直接读取并暴露在 Accept-Language / Intl / speechSynthesis 中。",
                "在 设置 -> 时间和语言 -> 语言和区域 中将 English 置顶为显示语言并修改区域格式为目标地区。",
                severity="high",
            )
        )
    elif is_cn_non_unicode or (any("zh" in str(x).lower() for x in pref_langs) and t_code != "TW"):
        checks.append(
            _make_check(
                "user_locale",
                "Windows 区域格式、显示语言与首选语言",
                "WARN",
                loc_obs,
                "首选语言列表或非 Unicode 系统区域（0804=简体中文）仍含中文痕迹"
                + ("（且系统为中文安装 SKU，可能自带中文语音/字体，可核对下方浏览器实测）" if is_cn_install else "")
                + "。",
                "在 控制面板 -> 区域 -> 管理 -> 更改系统区域设置 中核对，并确保首选语言列表为目标地区英文。",
            )
        )
    else:
        checks.append(_make_check("user_locale", "Windows 区域格式、显示语言与首选语言", "PASS", loc_obs, "Windows 区域格式、显示语言与首选语言符合目标地区。"))

    # 3. Windows Timezone (tzutil /g), Strict Restricted-TZ Reject & Reboot-After-Change Check
    rc_tz, tz_out, _ = _run_win_cmd(["tzutil", "/g"], timeout=4)
    win_tz_id = tz_out.strip() if rc_tz == 0 else ""
    iana_tz = WIN_TZ_TO_IANA.get(win_tz_id, "")
    local_dt = datetime.datetime.now().astimezone()
    offset_sec = int(local_dt.utcoffset().total_seconds()) if local_dt.utcoffset() else 0

    tz_mtime = _reg_last_write_ts("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation")
    boot_ts = _win_boot_timestamp()
    tz_changed_after_boot = bool(tz_mtime and boot_ts and tz_mtime > (boot_ts + 60.0))

    tz_is_restricted = (win_tz_id in RESTRICTED_WIN_TZS) or (iana_tz in RESTRICTED_TIMEZONES)
    if iana_tz:
        tz_ok = (iana_tz in target_cfg["timezones"]) and (not tz_is_restricted)
    elif win_tz_id:
        tz_ok = (not tz_is_restricted) and (offset_sec in target_cfg["utc_offsets_sec"])
    else:
        tz_ok = offset_sec in target_cfg["utc_offsets_sec"]

    target_win_tz = TARGET_TO_WIN_TZ.get(t_code, "Singapore Standard Time")
    if not tz_ok:
        checks.append(
            _make_check(
                "sys_timezone",
                "系统时区与重启刷新状态 (tzutil)",
                "FAIL",
                f"{win_tz_id or '未知'} -> {iana_tz or '未映射'} (UTC{offset_sec/3600:+.1f})",
                f"当前 Windows 时区为 {win_tz_id or '未知'}，与目标地区 {target_cfg['name']} 不匹配（即使同为 UTC+8，China Standard Time 也会被浏览器与 Electron 直接识别为 Asia/Shanghai）。",
                f"将系统时区改为 {target_win_tz} 并重启电脑。",
                f'tzutil /s "{target_win_tz}"',
                severity="critical" if tz_is_restricted else "high",
            )
        )
    elif tz_changed_after_boot:
        tz_ch_s = datetime.datetime.fromtimestamp(tz_mtime).strftime("%Y-%m-%d %H:%M")
        boot_s = datetime.datetime.fromtimestamp(boot_ts).strftime("%Y-%m-%d %H:%M")
        checks.append(
            _make_check(
                "sys_timezone",
                "系统时区与重启刷新状态 (tzutil)",
                "WARN",
                f"{win_tz_id}（改于 {tz_ch_s}，上次开机 {boot_s}）",
                "系统时区本身已与目标一致，但你修改时区后尚未重启 Windows；此前启动的浏览器/后台进程可能仍缓存旧时区！",
                "完成系统配置修改后完整重启一次电脑，再打开浏览器或 Claude。",
                severity="high",
            )
        )
    else:
        checks.append(
            _make_check(
                "sys_timezone",
                "系统时区与重启刷新状态 (tzutil)",
                "PASS",
                f"{win_tz_id} ({iana_tz or local_dt.strftime('%z')})",
                "Windows 系统时区与目标地区一致，且自上次重启以来未再变更。",
            )
        )

    # 4. Auto Timezone (tzautoupdate service)
    tz_auto_start = _read_reg("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\tzautoupdate", "Start", None)
    if tz_auto_start == 4:
        checks.append(_make_check("auto_timezone", "自动设置时区 (tzautoupdate)", "PASS", "已关闭 (Start=4)", "已锁定手动时区，不会被位置服务自动覆盖。"))
    elif tz_auto_start in (2, 3):
        checks.append(
            _make_check(
                "auto_timezone",
                "自动设置时区 (tzautoupdate)",
                "WARN",
                f"已启用 (Start={tz_auto_start})",
                "开启自动设置时区后，Windows 联网或唤醒时可能按物理 Wi-Fi 定位切回真实时区。",
                "在 设置 -> 时间和语言 -> 日期和时间 关闭「自动设置时区」。",
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\tzautoupdate" /v Start /t REG_DWORD /d 4 /f',
                severity="high",
            )
        )
    else:
        checks.append(_make_check("auto_timezone", "自动设置时区 (tzautoupdate)", "INFO", f"Start={tz_auto_start}", "无法确认自动时区服务状态，请在系统日期和时间设置中手动核对。"))

    # 5. Windows Location Services (ConsentStore + lfsvc + SensorOverrides)
    loc_lm = str(
        _read_reg(
            "HKEY_LOCAL_MACHINE",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
            "Value",
            "",
        )
        or ""
    ).strip()
    loc_cu = str(
        _read_reg(
            "HKEY_CURRENT_USER",
            r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
            "Value",
            "",
        )
        or ""
    ).strip()
    lfsvc_start = _read_reg("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\lfsvc", "Start", None)
    sensor_perm = _read_reg(
        "HKEY_LOCAL_MACHINE",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}",
        "SensorPermissionState",
        None,
    )
    loc_denied = (loc_lm.lower() == "deny") or (loc_cu.lower() == "deny") or (lfsvc_start == 4) or (sensor_perm == 0)
    loc_obs_str = f"HKLM={loc_lm or '-'} | HKCU={loc_cu or '-'} | lfsvc.Start={lfsvc_start if lfsvc_start is not None else '-'}"
    if loc_denied:
        checks.append(_make_check("location_services", "Windows 定位服务 (Wi-Fi 物理定位)", "PASS", loc_obs_str, "Windows 定位服务或地理位置服务已关闭。"))
    else:
        checks.append(
            _make_check(
                "location_services",
                "Windows 定位服务 (Wi-Fi 物理定位)",
                "WARN",
                loc_obs_str,
                "Windows 定位依靠周边 Wi-Fi 物理信号（BSSID）测算位置，完全绕过代理隧道。",
                "在 设置 -> 隐私和安全性 -> 位置 中关闭「位置服务」。",
                severity="high",
            )
        )

    # 6. Computer Name & User Profile Path CJK Check
    comp_name = os.environ.get("COMPUTERNAME") or socket.gethostname() or ""
    username = os.environ.get("USERNAME") or os.path.basename(os.environ.get("USERPROFILE", "")) or ""
    bad_host: List[str] = []
    if _has_cjk(comp_name) or _has_non_ascii(comp_name):
        bad_host.append(f"计算机名含非英文字符({comp_name})")
    elif any(p in comp_name.lower() for p in ("diannao", "zh-cn", "wode", "depc")):
        bad_host.append(f"计算机名含中文拼音特征({comp_name})")
    if _has_cjk(username) or _has_non_ascii(username):
        bad_host.append(f"当前 Windows 用户名含中文/非ASCII({username})，会暴露在 Claude Code 项目路径与崩溃日志中")

    if bad_host:
        checks.append(
            _make_check(
                "hostnames",
                "Windows 计算机名与用户目录名特征",
                "FAIL",
                f"Computer={comp_name} | User={username}",
                f"检测到明显中文/拼音命名特征：{'; '.join(bad_host)}。Claude Desktop 会上报为 remoteToolsDeviceName，Claude Code 会在会话和路径中带上用户目录。",
                "在 设置 -> 系统 -> 重命名这台电脑 改为纯英文名称并重启；如用户目录含中文，建议新建纯英文 Windows 本地账户运行 Claude。",
                'Rename-Computer -NewName "Workstation-PC" -Restart',
                severity="high",
            )
        )
    else:
        checks.append(_make_check("hostnames", "Windows 计算机名与用户目录名特征", "PASS", f"Computer={comp_name or '-'} | User={username or '-'}", "计算机名与当前用户名均为纯英文，无中文或拼音残留。"))

    # 7. Keyboard Layout & Modern Windows 10/11 TSF Input Methods
    preload = _list_reg_values("HKEY_CURRENT_USER", r"Keyboard Layout\Preload")
    preload_vals = [str(v).lower() for _, v in sorted(preload.items())]
    tsf_cn_hits: List[str] = []
    for sub in _list_reg_subkeys("HKEY_CURRENT_USER", r"Control Panel\International\User Profile"):
        if sub.lower().startswith(("zh-hans", "zh-cn")):
            sub_vals = _list_reg_values("HKEY_CURRENT_USER", rf"Control Panel\International\User Profile\{sub}")
            for k_tip in sub_vals:
                if k_tip.lower().startswith("0804:"):
                    tsf_cn_hits.append(f"{sub}({k_tip[:18]}...)")
    has_cn_kb = any(v.endswith("0804") for v in preload_vals) or bool(tsf_cn_hits)
    checks.append(
        _make_check(
            "input_method",
            "键盘布局与 TSF 中文输入法",
            "WARN" if has_cn_kb else "PASS",
            f"Preload={preload_vals[:4] or ['默认']}" + (f" | TSF中文IME={len(tsf_cn_hits)}个" if tsf_cn_hits else ""),
            "检测到简体中文键盘布局或微软拼音/第三方中文 TSF 输入法（0804），注册/登录 Claude 或过人机验证时请用 Win+Space 切到英文键盘 (ENG)。" if has_cn_kb else "未检测到简体中文键盘布局或中文 TSF 输入法。",
            "登录新号前切到 ENG 英文输入法，或在语言设置中移除非必要中文输入法。" if has_cn_kb else "",
        )
    )

    # 8. Wi-Fi Interface Notice (never returns personal SSID/BSSID)
    rc_w, w_out, _ = _run_win_cmd(["netsh", "wlan", "show", "interfaces"], timeout=4)
    wifi_connected = rc_w == 0 and any(k in w_out.lower() for k in ("connected", "已连接"))
    checks.append(
        _make_check(
            "wifi_cc",
            "无线网卡连接状态",
            "INFO",
            "Wi-Fi 已连接 (已隐藏 SSID/BSSID)" if wifi_connected else "未连接 Wi-Fi 或使用有线网络",
            "连接 Wi-Fi 时请确保已关闭 Windows 位置服务，防止通过周边无线路由 BSSID 反推物理位置。",
        )
    )

    # 9. Shell / User / System Env Vars (Redacted)
    env_keys = {
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy",
        "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CONFIG_DIR", "CLAUDE_SECURESTORAGE_CONFIG_DIR",
        "TZ", "LANG", "LC_ALL",
    }
    env_findings: List[str] = []
    env_risky = False
    for scope, kv in [
        ("proc", dict(os.environ)),
        ("HKCU", _list_reg_values("HKEY_CURRENT_USER", "Environment")),
        ("HKLM", _list_reg_values("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")),
    ]:
        for k, v in kv.items():
            if k not in env_keys and not k.upper().startswith(("ANTHROPIC_", "CLAUDE_")):
                continue
            sv = str(v or "").strip()
            if not sv:
                continue
            if any(sec in k.upper() for sec in ("KEY", "TOKEN", "SECRET", "PASSWORD")):
                entry = f"{scope}:{k}=<REDACTED>"
            else:
                clean_v = re.sub(r"://[^/@\s]+@", "://<REDACTED>@", sv)
                entry = f"{scope}:{k}={clean_v}"
                if "proxy" in k.lower() or k.upper() == "ANTHROPIC_BASE_URL" or any(x in sv.lower() for x in ("shanghai", "zh_cn", "zh-cn")):
                    env_risky = True
            if entry not in env_findings:
                env_findings.append(entry)
    checks.append(
        _make_check(
            "shell_proxy_env",
            "Windows 环境变量 (代理 / ANTHROPIC / CLAUDE / TZ / LANG)",
            "WARN" if env_risky else "PASS",
            ", ".join(env_findings[:6]) if env_findings else "无代理/中转站/异常区域变量",
            "发现代理、中转站或异常区域环境变量，可能使 Claude Code CLI 走不同于 TUN 的路径或指向第三方中转站。" if env_risky else "进程与系统注册表环境变量均未注入异常代理、中转站或中国区设置。",
            "检查 系统属性 -> 环境变量，清理陈旧代理或 ANTHROPIC_BASE_URL。" if env_risky else "",
            severity="high" if env_risky else "low",
        )
    )

    # 10. Windows Hosts file
    hosts_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    custom_hosts: List[str] = []
    risky_hosts: List[str] = []
    if os.path.isfile(hosts_path):
        try:
            with open(hosts_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    parts = s.split()
                    if len(parts) >= 2 and parts[1].lower() not in {"localhost"}:
                        custom_hosts.append(s[:80])
                        if any(k in s.lower() for k in ("claude", "anthropic", "stripe", "hcaptcha", "cloudflare", "statsig")):
                            risky_hosts.append(s[:80])
        except Exception:
            pass
    checks.append(
        _make_check(
            "etc_hosts",
            "Windows hosts 域名劫持检测",
            "FAIL" if risky_hosts else ("WARN" if custom_hosts else "PASS"),
            f"命中风险域名 {len(risky_hosts)} 条" if risky_hosts else (f"发现 {len(custom_hosts)} 条自定义条目" if custom_hosts else "仅默认条目"),
            f"风险条目: {'; '.join(risky_hosts[:4])}" if risky_hosts else (f"条目: {'; '.join(custom_hosts[:5])}" if custom_hosts else "hosts 文件无自定义劫持条目。"),
            "立即清理 hosts 中关于 claude / anthropic / stripe / hcaptcha / cloudflare 的手动绑定！" if risky_hosts else ("确认其中不包含 claude / anthropic / stripe / cloudflare 的陈旧绑定。" if custom_hosts else ""),
            severity="high" if risky_hosts else "low",
        )
    )

    # 11. Sleep / Modern Standby & Fast Startup Risk
    hiberboot = _read_reg("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled", None)
    rc_pc, pc_out, _ = _run_win_cmd(["powercfg", "/a"], timeout=4)
    has_s0 = rc_pc == 0 and ("s0 low power idle" in pc_out.lower() or "s0 低电量待机" in pc_out.lower())
    sleep_notes = f"ModernStandby(S0)={'支持' if has_s0 else '否'} | 快速启动(FastStartup)={hiberboot if hiberboot is not None else '未知'}"
    if has_s0 or hiberboot == 1:
        checks.append(
            _make_check(
                "power_sleep_leak",
                "休眠 / 现代待机 (S0) 与快速启动断流风险",
                "WARN",
                sleep_notes,
                "开启现代待机或快速启动时，休眠/合盖期间后台网卡唤醒容易早于 Clash TUN 恢复，从而触发 ERR_NETWORK_CHANGED 或物理网卡直连漏 IP。",
                "合盖/休眠前退出 Claude Desktop，或关闭快速启动并在电源设置中禁用待机网络连接。",
                "powercfg /h off",
                severity="high",
            )
        )
    else:
        checks.append(_make_check("power_sleep_leak", "休眠 / 现代待机与快速启动断流风险", "PASS", sleep_notes, "未检测到高风险快速启动或现代待机断流配置。"))

    # 12. Auto-Start Before Proxy/VPN Risk (Claude Startup Items)
    autostart_hits: List[str] = []
    for root_n, rk in [
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ]:
        for name, val in _list_reg_values(root_n, rk).items():
            combo = f"{name} {val}".lower()
            if "claude" in combo or "anthropic" in combo:
                autostart_hits.append(f"{root_n}\\Run:{name}")
    # Check MSIX StartupTask state (State=2 means Enabled)
    for pkg in _list_reg_subkeys("HKEY_CURRENT_USER", r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData"):
        if pkg.lower().startswith("claude_"):
            task_root = rf"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\{pkg}"
            for sub in _list_reg_subkeys("HKEY_CURRENT_USER", task_root):
                st = _read_reg("HKEY_CURRENT_USER", rf"{task_root}\{sub}", "State", None)
                if st == 2:
                    autostart_hits.append(f"MSIX StartupTask:{pkg}\\{sub}(Enabled)")
    startup_dir = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
    if startup_dir and os.path.isdir(startup_dir):
        try:
            for fn in os.listdir(startup_dir):
                if "claude" in fn.lower() or "anthropic" in fn.lower():
                    autostart_hits.append(f"Startup:{fn}")
        except Exception:
            pass
    if autostart_hits:
        checks.append(
            _make_check(
                "claude_autostart_leak",
                "Claude 开机自启抢跑代理风险 (Boot-Leak)",
                "FAIL",
                f"发现 {len(autostart_hits)} 个开机自启项: {', '.join(autostart_hits[:3])}",
                "Claude Desktop 设为开机自启时，Windows 登录后 Claude 往往比 Clash/代理 TUN 更早联网发起请求，每次开机都会向 Anthropic 暴露真实本地 IP！",
                "立即在 任务管理器 -> 启动应用 或 Claude 设置中关闭「开机自动启动」。",
                severity="high",
            )
        )
    else:
        checks.append(_make_check("claude_autostart_leak", "Claude 开机自启抢跑代理风险 (Boot-Leak)", "PASS", "未发现 Claude 开机自启项", "不存在 Claude 抢先于代理客户端联网的开机自启风险。"))

    # 13. Interface Manual CN DNS Audit (IPv4 + IPv6)
    net_info = win_check_dns_and_proxy()
    cn_dns = net_info["cn_dns"]
    if cn_dns:
        checks.append(
            _make_check(
                "network_services_proxy",
                "网卡 DNS 服务器合规检查 (IPv4 + IPv6)",
                "FAIL",
                f"发现国内公共 DNS: {', '.join(cn_dns)}",
                "网卡配置了国内公共 DNS（含 IPv4/IPv6），一旦代理断开会瞬间向国内 DNS 发起解析泄漏。",
                "在网络适配器属性中将 IPv4/IPv6 DNS 改为自动获取或 1.1.1.1 / 8.8.8.8。",
                severity="high",
            )
        )
    else:
        checks.append(
            _make_check(
                "network_services_proxy",
                "网卡 DNS 服务器合规检查 (IPv4 + IPv6)",
                "PASS",
                f"物理网卡 DNS: {', '.join(net_info['physical_dns'][:4]) or '默认'} | TUN DNS: {', '.join(net_info['tun_dns'][:3]) or '-'}",
                "网卡未配置 114 / 223.5 / 119.29 / 2400:3200::1 等国内公共 DNS。",
            )
        )

    # 14. NTP Time Server
    ntp_srv = str(_read_reg("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\W32Time\Parameters", "NtpServer", "") or "").strip()
    is_cn_ntp = any(k in ntp_srv.lower() for k in ("cn.", "aliyun", "tencent", "ntsc", "baidu", "tuna", "ustc"))
    checks.append(
        _make_check(
            "ntp_time_server",
            "Windows 时间同步服务器 (W32Time)",
            "WARN" if is_cn_ntp else "PASS",
            ntp_srv or "time.windows.com",
            "时间服务器包含国内节点。" if is_cn_ntp else "未配置国内 NTP 服务器。",
            'w32tm /config /manualpeerlist:"time.windows.com" /syncfromflags:manual /update' if is_cn_ntp else "",
        )
    )

    # 15. MITM Root CA Certificates (CurrentUser & LocalMachine Root)
    mitm_hits: List[str] = []
    mitm_kw = ("charles", "proxyman", "mitmproxy", "fiddler", "burp", "whistle", "http toolkit", "reqable")
    for args in [["certutil", "-store", "-user", "Root"], ["certutil", "-store", "Root"]]:
        rc_c, c_out, _ = _run_win_cmd(args, timeout=5)
        if rc_c == 0 and c_out:
            for line in c_out.splitlines():
                if any(k in line.lower() for k in mitm_kw):
                    s = line.strip()[:80]
                    if s not in mitm_hits:
                        mitm_hits.append(s)
    if mitm_hits:
        checks.append(
            _make_check(
                "mitm_trust_certs",
                "自定义 MITM 抓包根证书检测",
                "WARN",
                f"发现 {len(mitm_hits)} 条抓包证书记录",
                f"命中: {'; '.join(mitm_hits[:4])}。HTTPS 解密会破坏浏览器与 Electron 的 JA3/JA4 TLS 指纹。",
                "使用 Claude 时务必关闭所有抓包代理与 HTTPS 解密。",
                severity="high",
            )
        )
    else:
        checks.append(_make_check("mitm_trust_certs", "自定义 MITM 抓包根证书检测", "PASS", "未发现常见抓包工具根证书", "Windows 信任根证书库未发现 Fiddler / Charles / mitmproxy 等抓包根证书。"))

    # 16. Hardware MachineGuid, Advertising ID & WSL2 Awareness (strictly masked)
    has_guid = bool(_read_reg("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Cryptography", "MachineGuid", ""))
    adv_id_on = _read_reg("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", None)
    wsl_distros = _list_reg_subkeys("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\Lxss")
    hw_notes = [
        f"MachineGuid={'存在(已脱敏)' if has_guid else '未知'}",
        f"广告ID={'已开启' if adv_id_on == 1 else '已关闭/未设'}",
        f"WSL发行版={len(wsl_distros)}个",
    ]
    checks.append(
        _make_check(
            "hardware_device_fingerprint",
            "Windows 硬件标识、广告 ID 与 WSL2 提醒",
            "INFO",
            " | ".join(hw_notes),
            "网页版浏览器沙箱无法读取 Windows MachineGuid，但原生桌面端理论上可采集系统标识。若本机曾被封号，新号建议优先使用全新独立的 Chrome/Edge Profile 网页版。"
            + (f" 检测到 {len(wsl_distros)} 个 WSL 发行版：若曾在 WSL 中使用 Claude Code，请同步检查 WSL 内的 ~/.claude.json 及 WSL 代理路由！" if wsl_distros else ""),
            "可在 设置 -> 隐私和安全性 -> 常规 中关闭「广告 ID」。" if adv_id_on == 1 else "",
        )
    )

    return {"title": "Windows 系统环境与指纹", "checks": checks}


def _scan_chromium_profile_unlocked(pdir: str) -> Dict[str, Any]:
    """
    Read-only scan of Chromium profile files that remain readable even while the browser is running:
    - IndexedDB directory names (e.g. https_claude.ai_0.indexeddb.leveldb)
    - Network Persistent State JSON (visited server origins, zero secrets)
    - Preferences (accept_languages, webrtc policy, spellcheck, proxy extensions)
    """
    res: Dict[str, Any] = {
        "idb_hosts": set(),
        "nps_hosts": set(),
        "accept_lang": "",
        "webrtc_policy": "",
        "spell_dicts": [],
        "proxy_exts": [],
    }
    # 1. IndexedDB folder names
    idb_dir = os.path.join(pdir, "IndexedDB")
    if os.path.isdir(idb_dir):
        try:
            for fn in os.listdir(idb_dir):
                low = fn.lower()
                m = re.match(r"^https?_([^_]+)_\d+\.indexeddb", low)
                if m:
                    host = m.group(1).strip(".")
                    if _match_risk_domain(host):
                        res["idb_hosts"].add(host)
        except Exception:
            pass

    # 2. Network Persistent State (plain JSON hostnames only, never secrets)
    for rel in (os.path.join("Network", "Network Persistent State"), "Network Persistent State"):
        nps_path = os.path.join(pdir, rel)
        if not os.path.isfile(nps_path):
            continue
        try:
            with open(nps_path, "r", encoding="utf-8", errors="replace") as f:
                nps = json.load(f)
            servers = ((nps.get("net") or {}).get("http_server_properties") or {}).get("servers") or []
            for item in servers:
                if not isinstance(item, dict):
                    continue
                sv = str(item.get("server") or "")
                m = re.match(r"^https?://([^:/]+)", sv.lower())
                if m and _match_risk_domain(m.group(1)):
                    res["nps_hosts"].add(m.group(1))
        except Exception:
            pass
        break

    # 3. Preferences
    pref_file = os.path.join(pdir, "Preferences")
    if os.path.isfile(pref_file):
        try:
            with open(pref_file, "r", encoding="utf-8", errors="replace") as f:
                pr = json.load(f)
            res["accept_lang"] = str((pr.get("intl") or {}).get("accept_languages") or "")
            res["webrtc_policy"] = str((pr.get("webrtc") or {}).get("ip_handling_policy") or "")
            dicts = (pr.get("spellcheck") or {}).get("dictionaries")
            if isinstance(dicts, list):
                res["spell_dicts"] = [str(x) for x in dicts]
            ext_settings = ((pr.get("extensions") or {}).get("settings") or {})
            if isinstance(ext_settings, dict):
                for _, edata in ext_settings.items():
                    if not isinstance(edata, dict) or edata.get("state") != 1:
                        continue
                    ename = str(((edata.get("manifest") or {}).get("name")) or "").strip()
                    if ename and any(kw in ename.lower() for kw in PROXY_EXT_KEYWORDS):
                        if ename not in res["proxy_exts"]:
                            res["proxy_exts"].append(ename[:40])
        except Exception:
            pass

    return res


def win_audit_claude_browser_residue() -> Dict[str, Any]:
    """Windows comprehensive Claude Desktop (Standard + MSIX), CLI, Credential Manager, Temp, IDE & Browser audit."""
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

    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    userprofile = os.environ.get("USERPROFILE", os.path.expanduser("~"))
    temp_dir = os.environ.get("TEMP", tempfile.gettempdir())

    # Discover MSIX Claude Desktop packages (%LOCALAPPDATA%\Packages\Claude_*)
    msix_pkg_dirs: List[str] = []
    if localappdata:
        pkg_root = os.path.join(localappdata, "Packages")
        if os.path.isdir(pkg_root):
            try:
                for fn in os.listdir(pkg_root):
                    if fn.lower().startswith("claude_") or "anthropic" in fn.lower():
                        fp = os.path.join(pkg_root, fn)
                        if os.path.isdir(fp):
                            msix_pkg_dirs.append(fp)
            except Exception:
                pass

    # 1. Running processes & Installed App / CLI
    _, tl_out, _ = _run_win_cmd(["tasklist", "/FO", "CSV", "/NH"], timeout=4)
    all_procs = _parse_tasklist_csv(tl_out)
    running_claude = [
        p for p in all_procs
        if p.lower() in {"claude.exe", "claude-code.exe", "anthropicclaude.exe", "claude-desktop.exe"}
    ]
    installed_apps = [
        p
        for p in [
            os.path.join(localappdata, "AnthropicClaude", "claude.exe"),
            os.path.join(localappdata, "Programs", "claude", "Claude.exe"),
        ] + msix_pkg_dirs
        if p and os.path.exists(p)
    ]
    cli_candidates = [
        shutil.which("claude") or "",
        shutil.which("claude.cmd") or "",
        os.path.join(userprofile, ".local", "bin", "claude.exe"),
        os.path.join(appdata, "npm", "claude.cmd") if appdata else "",
    ]
    cli_bin = next((p for p in cli_candidates if p and os.path.exists(p)), "")
    proc_obs = (
        f"进程={len(running_claude)} ({', '.join(running_claude[:3])})" if running_claude else "进程=未运行"
    ) + f" | Desktop App={'已安装(' + ('MSIX' if msix_pkg_dirs else '传统') + ')' if installed_apps else '未安装'} | CLI={'已安装(' + cli_bin + ')' if cli_bin else '未安装'}"
    checks.append(
        _make_check(
            "claude_proc",
            "Claude 安装状态与后台进程 (Windows)",
            "INFO" if (running_claude or installed_apps or cli_bin) else "PASS",
            proc_obs,
            "清理本地残留或切换新号前，请先在任务管理器中彻底结束所有 Claude.exe 进程。",
        )
    )
    add_inv(
        "运行与程序",
        "Claude.exe / MSIX / CLI / 进程",
        r"%LOCALAPPDATA%\Packages\Claude_* · %LOCALAPPDATA%\AnthropicClaude · PATH\claude",
        "确认是否存在桌面端（传统/MSIX 容器）或 CLI 后台常驻进程",
        proc_obs,
        "INFO" if (running_claude or installed_apps or cli_bin) else "PASS",
    )

    # 2. Claude Desktop Files & Deep Fingerprint Inspection (BOTH %APPDATA%\Claude AND MSIX LocalCache\Roaming\Claude!)
    claude_data_roots: List[Tuple[str, str]] = []
    if appdata and os.path.isdir(os.path.join(appdata, "Claude")):
        claude_data_roots.append((r"%APPDATA%\Claude", os.path.join(appdata, "Claude")))
    for mpkg in msix_pkg_dirs:
        m_roaming = os.path.join(mpkg, "LocalCache", "Roaming", "Claude")
        if os.path.isdir(m_roaming):
            claude_data_roots.append((f"MSIX({os.path.basename(mpkg)})\\Roaming\\Claude", m_roaming))

    claude_paths = [
        p
        for p in [
            os.path.join(appdata, "Claude") if appdata else "",
            os.path.join(localappdata, "AnthropicClaude") if localappdata else "",
            os.path.join(localappdata, "claude-desktop-updater") if localappdata else "",
            os.path.join(localappdata, "Claude") if localappdata else "",
        ] + msix_pkg_dirs
        if p and os.path.exists(p)
    ]
    desktop_clean_cmd = (
        'Get-Process *claude* -ErrorAction SilentlyContinue | Stop-Process -Force; '
        'Remove-Item -Recurse -Force "$env:APPDATA\\Claude","$env:LOCALAPPDATA\\AnthropicClaude",'
        '"$env:LOCALAPPDATA\\claude-desktop-updater","$env:LOCALAPPDATA\\Claude",'
        '"$env:LOCALAPPDATA\\Claude-3p","$env:LOCALAPPDATA\\Claude-Data",'
        '"$env:LOCALAPPDATA\\Packages\\Claude_*\\LocalCache\\Roaming\\Claude",'
        '"$env:LOCALAPPDATA\\Packages\\Claude_*\\LocalCache\\Local\\*" -ErrorAction SilentlyContinue'
    )

    desktop_details: List[str] = []
    desktop_status = "PASS" if not claude_paths else "WARN"
    desktop_sev = "low"

    ant_did_hits: List[str] = []
    cookie_notes: List[str] = []
    cookie_st = "PASS"
    pref_notes: List[str] = []
    pref_st = "PASS"
    cfg_notes: List[str] = []
    cfg_st = "PASS"
    log_notes: List[str] = []
    log_st = "PASS"
    sub_hits: List[str] = []

    for r_label, cdir in claude_data_roots:
        # ant-did
        ant_did = os.path.join(cdir, "ant-did")
        if os.path.isfile(ant_did):
            sz = os.path.getsize(ant_did)
            ant_did_hits.append(f"{r_label}\\ant-did ({sz}B)")
            desktop_status = "FAIL"
            desktop_sev = "high"

        # Cookies (WAL-aware + lock-aware)
        for cand in (os.path.join(cdir, "Network", "Cookies"), os.path.join(cdir, "Cookies")):
            if not os.path.isfile(cand):
                continue
            qst, rows = _safe_sqlite_query(cand, "SELECT host_key, name FROM cookies")
            if qst == "ok":
                names = {r[1] for r in rows}
                tracked = [
                    n
                    for n in ["anthropic-device-id", "hmt_id", "__ssid", "_fbp", "sessionKey", "routingHint", "lastActiveOrg", "cf_clearance", "__cf_bm"]
                    if n in names
                ]
                c_obs = f"{r_label}: {len(rows)}条(追踪键:{','.join(tracked) if tracked else '无'})"
                cookie_notes.append(c_obs)
                if any(k in names for k in ("anthropic-device-id", "hmt_id", "sessionKey", "lastActiveOrg")):
                    cookie_st = "FAIL"
                    desktop_status = "FAIL"
                    desktop_sev = "high"
                elif cookie_st == "PASS":
                    cookie_st = "WARN"
            elif qst == "locked":
                cookie_notes.append(f"{r_label}: Cookies 被运行中的 Claude 进程锁定")
                if cookie_st == "PASS":
                    cookie_st = "WARN"
            else:
                cookie_notes.append(f"{r_label}: Cookies 数据库存在")
                if cookie_st == "PASS":
                    cookie_st = "WARN"
            break

        # Preferences & Local State
        pref_path = os.path.join(cdir, "Preferences")
        ls_path = os.path.join(cdir, "Local State")
        if os.path.isfile(pref_path):
            if pref_st == "PASS":
                pref_st = "WARN"
            try:
                with open(pref_path, "r", encoding="utf-8", errors="replace") as f:
                    pr = json.load(f)
                dicts = (pr.get("spellcheck") or {}).get("dictionaries")
                if dicts:
                    pref_notes.append(f"{r_label} 拼写字典={dicts}")
                    if any("zh" in str(x).lower() for x in dicts):
                        pref_st = "FAIL"
                        desktop_status = "FAIL"
                if ((pr.get("electron") or {}).get("media") or {}).get("device_id_salt"):
                    pref_notes.append(f"{r_label} 含 electron device_id_salt")
                acc_l = (pr.get("intl") or {}).get("accept_languages")
                if acc_l and "zh-cn" in str(acc_l).lower():
                    pref_notes.append(f"{r_label} accept_lang={acc_l}")
                    pref_st = "FAIL"
                    desktop_status = "FAIL"
            except Exception:
                pref_notes.append(f"{r_label} Preferences 存在")
        if os.path.isfile(ls_path):
            if pref_st == "PASS":
                pref_st = "WARN"
            try:
                with open(ls_path, "r", encoding="utf-8", errors="replace") as f:
                    ls_d = json.load(f)
                if ls_d.get("os_crypt"):
                    pref_notes.append(f"{r_label} Local State 含 os_crypt(DPAPI)")
                vc = ls_d.get("variations_country")
                if vc and str(vc).lower() in {"cn", "hk"}:
                    pref_notes.append(f"{r_label} variations_country={vc}")
                    pref_st = "FAIL"
                    desktop_status = "FAIL"
            except Exception:
                pref_notes.append(f"{r_label} Local State 存在")

        # config.json & claude_desktop_config.json
        cfg_json = os.path.join(cdir, "config.json")
        mcp_json = os.path.join(cdir, "claude_desktop_config.json")
        if os.path.isfile(cfg_json):
            if cfg_st == "PASS":
                cfg_st = "WARN"
            try:
                with open(cfg_json, "r", encoding="utf-8", errors="replace") as f:
                    cj = json.load(f)
                if cj.get("locale"):
                    cfg_notes.append(f"{r_label} locale={cj.get('locale')}")
                for k_u in ("lastKnownAccountUuid", "orgUuid", "userId", "oauthAccount"):
                    if cj.get(k_u):
                        cfg_notes.append(f"{r_label} 含 {k_u}")
                        cfg_st = "FAIL"
                        desktop_status = "FAIL"
            except Exception:
                cfg_notes.append(f"{r_label} config.json 存在")
        if os.path.isfile(mcp_json):
            if cfg_st == "PASS":
                cfg_st = "WARN"
            try:
                with open(mcp_json, "r", encoding="utf-8", errors="replace") as f:
                    mc = json.load(f)
                dev_name = str((mc.get("preferences") or {}).get("remoteToolsDeviceName", ""))
                if dev_name:
                    cfg_notes.append(f"{r_label} remoteToolsDeviceName={dev_name}")
                    if _has_cjk(dev_name):
                        cfg_st = "FAIL"
                        desktop_status = "FAIL"
            except Exception:
                cfg_notes.append(f"{r_label} claude_desktop_config.json 存在")

        # Logs
        log_dir = os.path.join(cdir, "logs")
        if os.path.isdir(log_dir):
            rb_cnt = ban_cnt = stripe_cnt = net_cnt = 0
            lfiles = [fn for fn in os.listdir(log_dir) if fn.endswith(".log") and os.path.isfile(os.path.join(log_dir, fn))]
            for fn in lfiles:
                try:
                    with open(os.path.join(log_dir, fn), "r", encoding="utf-8", errors="replace") as f:
                        txt = f.read()
                    rb_cnt += txt.count("region_blocked") + txt.count("isn't available in your region")
                    ban_cnt += txt.count("account_banned")
                    stripe_cnt += txt.count("Failed to load Stripe.js")
                    net_cnt += txt.count("ERR_NETWORK_CHANGED")
                except Exception:
                    pass
            l_obs = f"{r_label}: {len(lfiles)}日志(region_blocked={rb_cnt}, banned={ban_cnt}, Stripe失败={stripe_cnt}, 断流={net_cnt})"
            log_notes.append(l_obs)
            if rb_cnt or ban_cnt:
                log_st = "FAIL"
                desktop_status = "FAIL"
                desktop_sev = "high"
            elif log_st == "PASS" and lfiles:
                log_st = "WARN"

        # Sub-storages
        sub_names = [
            "Trust Tokens", os.path.join("Network", "Trust Tokens"), "DIPS", "SharedStorage",
            "Local Storage", "Session Storage", "IndexedDB", "Cache", "Code Cache",
            "GPUCache", "sentry", "Crashpad", "Service Worker", "WebStorage",
            os.path.join("Network", "Network Persistent State"),
            os.path.join("Network", "TransportSecurity"),
        ]
        exist_subs = [s for s in sub_names if os.path.exists(os.path.join(cdir, s))]
        if exist_subs:
            sub_hits.append(f"{r_label}({len(exist_subs)}项: {', '.join(exist_subs[:5])})")

    if ant_did_hits:
        desktop_details.append(f"存在 ant-did: {'; '.join(ant_did_hits)}")
    if cookie_notes:
        desktop_details.extend(cookie_notes)
    if pref_notes:
        desktop_details.extend(pref_notes)
    if cfg_notes:
        desktop_details.extend(cfg_notes)
    if log_notes:
        desktop_details.extend(log_notes)

    add_inv(
        "Claude Desktop",
        "ant-did 设备唯一 ID (含 MSIX 容器)",
        r"%APPDATA%\Claude\ant-did · %LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\ant-did",
        "Anthropic 跨账号关联核心设备指纹文件（Windows MSIX 安装会虚拟化存放在 Packages 容器内！）",
        "; ".join(ant_did_hits) if ant_did_hits else "已清理 (0 残留)",
        "FAIL" if ant_did_hits else "PASS",
    )
    add_inv(
        "Claude Desktop",
        "Cookies 追踪数据库 (含 MSIX 容器)",
        r"%APPDATA%\Claude\Network\Cookies · MSIX\...\Network\Cookies",
        "存储 anthropic-device-id、hmt_id、sessionKey 等追踪键（仅查键名不读明文）",
        "；".join(cookie_notes) if cookie_notes else "已清理 (0 残留)",
        cookie_st,
    )
    add_inv(
        "Claude Desktop",
        "Preferences & Local State",
        r"Claude\{Preferences, Local State}",
        "记录 device_id_salt、拼写语言字典与 DPAPI 加密头",
        "；".join(pref_notes) if pref_notes else "已清理 (0 残留)",
        pref_st,
    )
    add_inv(
        "Claude Desktop",
        "config.json & desktop_config",
        r"Claude\{config.json, claude_desktop_config.json}",
        "保存旧账号 UUID、locale 与上报设备名 remoteToolsDeviceName",
        "；".join(cfg_notes) if cfg_notes else "已清理 (0 残留)",
        cfg_st,
    )
    add_inv(
        "Claude Desktop",
        "运行日志与封禁历史",
        r"Claude\logs\*.log",
        "记录 region_blocked、account_banned、Stripe.js 失败与断流事件",
        "；".join(log_notes) if log_notes else "已清理 (0 残留)",
        log_st,
    )
    add_inv(
        "Claude Desktop",
        "Electron 子存储与 MSIX 沙箱缓存",
        r"Local Storage / IndexedDB / Trust Tokens / DIPS / TransportSecurity / sentry / MSIX LocalCache",
        "Electron 沙箱本地存储、Trust Tokens、DIPS、HSTS 与崩溃上报缓存",
        "；".join(sub_hits) if sub_hits else "已清理 (0 残留)",
        "WARN" if sub_hits else "PASS",
    )

    if not claude_paths:
        checks.append(_make_check("claude_desktop_files", "Claude Desktop 全套设备指纹与 MSIX 容器缓存", "PASS", "已清理干净 (0 残留)", "未发现 %APPDATA%\\Claude、%LOCALAPPDATA%\\AnthropicClaude 及 MSIX Packages\\Claude_* 残留。"))
    else:
        checks.append(
            _make_check(
                "claude_desktop_files",
                "Claude Desktop 全套设备指纹与 MSIX 容器缓存",
                desktop_status,
                f"存在 {len(claude_paths)} 个本地目录" + (f" (含 {len(msix_pkg_dirs)} 个 MSIX 容器)" if msix_pkg_dirs else ""),
                "；".join(desktop_details) if desktop_details else ", ".join(claude_paths),
                "更换新号前务必先结束所有 Claude 进程，并同时清理传统路径和 MSIX 虚拟化容器路径（Packages\\Claude_*）。",
                desktop_clean_cmd,
                severity=desktop_sev,
            )
        )

    # 3. Claude Code CLI (including CLAUDE_CONFIG_DIR override, settings.json relay check & claude-cli-nodejs)
    custom_cc_dir = os.environ.get("CLAUDE_CONFIG_DIR", "").strip()
    cc_json = os.path.join(userprofile, ".claude.json")
    cc_dir = custom_cc_dir if custom_cc_dir else os.path.join(userprofile, ".claude")
    cc_backups = [fn for fn in (os.listdir(userprofile) if os.path.isdir(userprofile) else []) if fn.startswith(".claude.json.backup")]
    xdg_hits = [
        p
        for p in [
            os.path.join(userprofile, ".anthropic"),
            os.path.join(userprofile, ".config", "claude"),
            os.path.join(userprofile, ".cache", "claude"),
            os.path.join(localappdata, "claude-cli-nodejs") if localappdata else "",
        ]
        if p and os.path.exists(p)
    ]
    cc_notes: List[str] = []
    cc_status = "PASS"
    if os.path.isfile(cc_json):
        cc_status = "WARN"
        try:
            with open(cc_json, "r", encoding="utf-8", errors="replace") as f:
                d = json.load(f)
            flags = [
                k
                for k in ["machineID", "userID", "oauthAccount", "anonymousId", "firstStartTime", "cachedStatsigGates", "cachedGrowthBookFeatures"]
                if k in d
            ]
            cc_notes.append(f".claude.json 含 {', '.join(flags) if flags else '配置'}")
            if any(k in d for k in ("machineID", "userID", "oauthAccount", "anonymousId")):
                cc_status = "FAIL"
            projs = d.get("projects")
            if isinstance(projs, dict) and any(_has_cjk(str(pk)) for pk in projs.keys()):
                cc_notes.append("projects 记录含中文路径")
        except Exception:
            cc_notes.append(".claude.json 存在")
    if cc_backups:
        cc_status = "WARN" if cc_status == "PASS" else cc_status
        cc_notes.append(f"{len(cc_backups)} 个备份")
    if os.path.exists(cc_dir):
        cc_status = "WARN" if cc_status == "PASS" else cc_status
        fcnt, fbytes = _dir_stats(cc_dir, max_files=1000)
        sub_cc: List[str] = []
        try:
            for item in sorted(os.listdir(cc_dir)):
                if item in {".credentials.json", "credentials.json", "settings.json", "settings.local.json", "statsig", "projects", "debug", "telemetry", "ide", "session-env"}:
                    sub_cc.append(item)
            if ".credentials.json" in sub_cc or "credentials.json" in sub_cc:
                cc_status = "FAIL"
        except Exception:
            pass
        # Check settings.json / settings.local.json for hidden relay/proxy env (never reads keys/tokens)
        for sf in ("settings.json", "settings.local.json"):
            sfp = os.path.join(cc_dir, sf)
            if os.path.isfile(sfp):
                try:
                    with open(sfp, "r", encoding="utf-8", errors="replace") as f:
                        sd = json.load(f)
                    s_env = sd.get("env") if isinstance(sd.get("env"), dict) else {}
                    for ek in ("ANTHROPIC_BASE_URL", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
                        if s_env.get(ek):
                            clean_ev = re.sub(r"://[^/@\s]+@", "://<REDACTED>@", str(s_env[ek]))
                            cc_notes.append(f"{sf}:{ek}={clean_ev}")
                    if sd.get("apiKeyHelper"):
                        cc_notes.append(f"{sf} 含 apiKeyHelper")
                except Exception:
                    pass
        cc_notes.append(f"{os.path.basename(cc_dir)}\\ ({fcnt} 文件, {_fmt_bytes(fbytes)}; {', '.join(sub_cc[:6]) if sub_cc else '子项'})")
    if xdg_hits:
        cc_status = "WARN" if cc_status == "PASS" else cc_status
        cc_notes.append(f"缓存/额外目录 {len(xdg_hits)} 个 ({', '.join(os.path.basename(p) for p in xdg_hits[:3])})")

    cli_clean_cmd = (
        'Remove-Item -Recurse -Force "$env:USERPROFILE\\.claude.json","$env:USERPROFILE\\.claude.json.backup*",'
        '"$env:USERPROFILE\\.claude","$env:USERPROFILE\\.anthropic","$env:LOCALAPPDATA\\claude-cli-nodejs" -ErrorAction SilentlyContinue'
    )
    checks.append(
        _make_check(
            "claude_code_cli",
            "Claude Code CLI 全路径状态 (~\\.claude* & claude-cli-nodejs)",
            cc_status,
            "；".join(cc_notes) if cc_notes else "已清理干净 (0 残留)",
            "Claude Code CLI 会在 .claude.json 持久化 machineID / userID / oauthAccount / anonymousId，并在 .claude\\.credentials.json 与 statsig 保存凭据与实验分组。" if cc_notes else "未检测到 Claude Code CLI 本地状态残留。",
            "换新号前先清理 .claude.json、.claude 目录与 %LOCALAPPDATA%\\claude-cli-nodejs。" if cc_notes else "",
            cli_clean_cmd if cc_notes else "",
            severity="high" if cc_status == "FAIL" else "low",
        )
    )
    add_inv(
        "Claude Code CLI",
        ".claude.json & .claude\\ & claude-cli-nodejs",
        r"%USERPROFILE%\.claude.json* · %USERPROFILE%\.claude · %LOCALAPPDATA%\claude-cli-nodejs",
        "存储 CLI 的 machineID、userID、oauthAccount、.credentials.json、statsig 标识与 settings.json 中转配置",
        "；".join(cc_notes) if cc_notes else "已清理 (0 残留)",
        cc_status,
    )

    # 4. Windows Credential Manager (cmdkey /list — target names ONLY, never passwords; OEM-decoded)
    rc_ck, ck_out, _ = _run_win_cmd(["cmdkey", "/list"], timeout=4)
    cred_hits: List[str] = []
    if rc_ck == 0 and ck_out:
        for line in ck_out.splitlines():
            low = line.lower()
            if any(k in low for k in ("target:", "目标:")) and any(w in low for w in ("claude", "anthropic", "hcaptcha", "stripe")):
                cred_hits.append(line.strip()[:72])
    if cred_hits:
        checks.append(
            _make_check(
                "claude_keychain",
                "Windows 凭据管理器脱敏检索 (cmdkey)",
                "FAIL",
                f"发现 {len(cred_hits)} 项: {', '.join(cred_hits[:4])}",
                "Windows 凭据管理器中保留了 Claude / Anthropic 相关凭据。",
                "打开 控制面板 -> 凭据管理器 -> Windows 凭据，移除相关条目。",
                severity="high",
            )
        )
        add_inv("凭据与注册表", "Windows 凭据管理器", "cmdkey /list (仅查目标名，不读密码)", "保存桌面端或 CLI 相关的系统凭据", f"发现 {len(cred_hits)} 项", "FAIL")
    else:
        checks.append(_make_check("claude_keychain", "Windows 凭据管理器脱敏检索 (cmdkey)", "PASS", "全库扫描 0 残留", "未在 Windows 凭据管理器中发现 claude / anthropic / hcaptcha / stripe 条目。"))
        add_inv("凭据与注册表", "Windows 凭据管理器", "cmdkey /list (仅查目标名，不读密码)", "保存桌面端或 CLI 相关的系统凭据", "0 残留", "PASS")

    # 5. Wildcard System Scan (%APPDATA%, %LOCALAPPDATA%, %TEMP%, CrashDumps, Registry URL scheme, IDE)
    known_low = {p.lower() for p in claude_paths + xdg_hits}
    wc_hits: List[str] = []
    for base_label, base_dir in [
        ("%APPDATA%", appdata),
        ("%LOCALAPPDATA%", localappdata),
        ("%TEMP%", temp_dir),
        ("CrashDumps", os.path.join(localappdata, "CrashDumps") if localappdata else ""),
    ]:
        if not base_dir or not os.path.isdir(base_dir):
            continue
        try:
            for fn in os.listdir(base_dir):
                low = fn.lower()
                fp = os.path.join(base_dir, fn)
                if fp.lower() in known_low:
                    continue
                if "anthropic" in low or low.startswith(("claude", "com.anthropic")):
                    wc_hits.append(f"{base_label}\\{fn}")
        except Exception:
            pass

    ide_hits: List[str] = []
    for ide_lbl, ide_dir in [
        ("VS Code 扩展", os.path.join(userprofile, ".vscode", "extensions")),
        ("VS Code Insiders", os.path.join(userprofile, ".vscode-insiders", "extensions")),
        ("Cursor 扩展", os.path.join(userprofile, ".cursor", "extensions")),
        ("Windsurf 扩展", os.path.join(userprofile, ".windsurf", "extensions")),
        ("Trae 扩展", os.path.join(userprofile, ".trae", "extensions")),
        ("Kiro 扩展", os.path.join(userprofile, ".kiro", "extensions")),
        ("Antigravity 扩展", os.path.join(userprofile, ".antigravity", "extensions")),
        ("VS Code 存储", os.path.join(appdata, "Code", "User", "globalStorage") if appdata else ""),
        ("Cursor 存储", os.path.join(appdata, "Cursor", "User", "globalStorage") if appdata else ""),
        ("Windsurf 存储", os.path.join(appdata, "Windsurf", "User", "globalStorage") if appdata else ""),
        ("JetBrains", os.path.join(appdata, "JetBrains") if appdata else ""),
        ("Zed", os.path.join(localappdata, "Zed") if localappdata else ""),
    ]:
        if not ide_dir or not os.path.isdir(ide_dir):
            continue
        try:
            for fn in os.listdir(ide_dir):
                if "anthropic" in fn.lower() or "claude" in fn.lower():
                    ide_hits.append(f"{ide_lbl}:{fn}")
        except Exception:
            pass

    reg_claude_url = _reg_key_exists("HKEY_CURRENT_USER", r"Software\Classes\claude")
    wc_all = wc_hits + ide_hits
    checks.append(
        _make_check(
            "claude_wildcard_system",
            "Windows 全盘边缘残留扫描 (AppData / Temp / 崩溃转储 / 注册表 / IDE)",
            "WARN" if wc_all else "PASS",
            f"发现 {len(wc_all)} 项: {', '.join(wc_all[:4])}" if wc_all else ("0 残留" + (" · 注册表保留 claude:// 登记" if reg_claude_url else "")),
            "已扫描 %APPDATA%、%LOCALAPPDATA%、%TEMP%、CrashDumps、注册表协议及 VS Code / Cursor / Windsurf / Trae / JetBrains 插件目录。",
            "请核对并清理上述边缘目录。" if wc_all else "",
        )
    )
    add_inv("系统缓存/日志/IDE", "AppData / Temp / CrashDumps 通配", r"%APPDATA% · %LOCALAPPDATA% · %TEMP% · CrashDumps", "捕获隐藏缓存、安装临时目录与崩溃转储文件", f"发现 {len(wc_hits)} 项" if wc_hits else "0 残留", "WARN" if wc_hits else "PASS")
    add_inv("凭据与注册表", "claude:// 协议注册", r"HKCU\Software\Classes\claude", "记录 claude:// 深链协议注册（低风险）", "保留登记 (低风险)" if reg_claude_url else "未注册", "INFO" if reg_claude_url else "PASS")
    add_inv("系统缓存/日志/IDE", "IDE 扩展与全局存储", "VS Code / Cursor / Windsurf / Trae / Kiro / JetBrains", "检测 anthropic.claude-code 插件与独立缓存", f"发现 {len(ide_hits)} 项" if ide_hits else "0 残留 / 未安装", "WARN" if ide_hits else "PASS")

    # 6. Windows Browsers Deep Audit (Chrome / Edge / Brave / Arc MSIX / Vivaldi / Opera / Firefox / Zen)
    arc_user_data = ""
    if localappdata:
        arc_matches = glob.glob(os.path.join(localappdata, "Packages", "TheBrowserCompany.Arc_*", "LocalCache", "Local", "Arc", "User Data"))
        if arc_matches:
            arc_user_data = arc_matches[0]

    chromium_dirs = {
        "Chrome": os.path.join(localappdata, "Google", "Chrome", "User Data") if localappdata else "",
        "Chrome Beta": os.path.join(localappdata, "Google", "Chrome Beta", "User Data") if localappdata else "",
        "Chrome Canary": os.path.join(localappdata, "Google", "Chrome SxS", "User Data") if localappdata else "",
        "Edge": os.path.join(localappdata, "Microsoft", "Edge", "User Data") if localappdata else "",
        "Edge Beta": os.path.join(localappdata, "Microsoft", "Edge Beta", "User Data") if localappdata else "",
        "Brave": os.path.join(localappdata, "BraveSoftware", "Brave-Browser", "User Data") if localappdata else "",
        "Arc": arc_user_data,
        "Vivaldi": os.path.join(localappdata, "Vivaldi", "User Data") if localappdata else "",
        "Chromium": os.path.join(localappdata, "Chromium", "User Data") if localappdata else "",
        "Opera": os.path.join(appdata, "Opera Software", "Opera Stable") if appdata else "",
        "Opera GX": os.path.join(appdata, "Opera Software", "Opera GX Stable") if appdata else "",
    }
    found_browsers: List[str] = []
    browser_issues: List[str] = []
    claude_browser_hits: List[str] = []
    locked_browsers: List[str] = []

    for bname, bpath in chromium_dirs.items():
        if not bpath or not os.path.isdir(bpath):
            continue
        ls_file = os.path.join(bpath, "Local State")
        b_tags: List[str] = []
        if os.path.isfile(ls_file):
            try:
                with open(ls_file, "r", encoding="utf-8", errors="replace") as f:
                    ls = json.load(f)
                vc = ls.get("variations_country")
                doh_cfg = ls.get("dns_over_https") or {}
                doh_mode = doh_cfg.get("mode")
                doh_tpl = str(doh_cfg.get("templates") or "")
                if vc:
                    b_tags.append(f"variations={vc}")
                    if str(vc).lower() in {"cn", "hk"}:
                        browser_issues.append(f"{bname} variations_country={vc}")
                if doh_mode:
                    b_tags.append(f"DoH={doh_mode}")
                    if doh_tpl and any(k in doh_tpl.lower() for k in CN_DOH_KEYWORDS):
                        browser_issues.append(f"{bname} 配置了国内 DoH ({doh_tpl[:40]})")
                    elif str(doh_mode).lower() == "secure":
                        browser_issues.append(f"{bname} 开启了强制独立 DoH (可能绕过 Clash Fake-IP)")
            except Exception:
                pass
        try:
            prof_dirs = [
                os.path.join(bpath, d)
                for d in sorted(os.listdir(bpath))
                if (d == "Default" or d.startswith("Profile ")) and os.path.isdir(os.path.join(bpath, d))
            ]
        except Exception:
            prof_dirs = []
        if not prof_dirs and os.path.isfile(os.path.join(bpath, "Preferences")):
            prof_dirs = [bpath]

        b_claude_hosts: Set[str] = set()
        b_storage_sources: Set[str] = set()
        b_locked = False
        b_proxy_exts: List[str] = []

        for pdir in prof_dirs[:8]:
            pname = os.path.basename(pdir)
            # Unlocked artifacts (IndexedDB, Network Persistent State, Preferences)
            unlk = _scan_chromium_profile_unlocked(pdir)
            if unlk["accept_lang"] and not any(t.startswith("lang=") for t in b_tags):
                b_tags.append(f"lang={unlk['accept_lang']}")
            if unlk["accept_lang"] and "zh-cn" in unlk["accept_lang"].lower():
                browser_issues.append(f"{bname}({pname}) accept_languages 含 zh-CN")
            if unlk["webrtc_policy"] and not any(t.startswith("webrtc=") for t in b_tags):
                b_tags.append(f"webrtc={unlk['webrtc_policy']}")
            for pe in unlk["proxy_exts"]:
                if pe not in b_proxy_exts:
                    b_proxy_exts.append(pe)
            if unlk["idb_hosts"]:
                b_claude_hosts.update(unlk["idb_hosts"])
                b_storage_sources.add("IndexedDB")
            if unlk["nps_hosts"]:
                b_claude_hosts.update(unlk["nps_hosts"])
                b_storage_sources.add("NetworkState")

            # Read-only Cookies host_key check (WAL-aware + lock-aware; NEVER reads values!)
            for ck_rel in (os.path.join("Network", "Cookies"), "Cookies"):
                ck_file = os.path.join(pdir, ck_rel)
                if not os.path.isfile(ck_file):
                    continue
                qst, rows = _safe_sqlite_query(ck_file, "SELECT DISTINCT host_key FROM cookies")
                if qst == "ok":
                    for (hk,) in rows:
                        h_clean = str(hk).lstrip(".")
                        if _match_risk_domain(h_clean):
                            b_claude_hosts.add(h_clean)
                            b_storage_sources.add("Cookies")
                elif qst == "locked":
                    b_locked = True
                break

        if b_proxy_exts:
            b_tags.append(f"代理扩展={','.join(b_proxy_exts[:2])}")
            browser_issues.append(f"{bname} 启用了代理/VPN扩展({', '.join(b_proxy_exts[:3])})，易与系统 TUN 分叉")

        if b_locked:
            locked_browsers.append(bname)
            b_tags.append("Cookies运行中锁定")

        if b_claude_hosts:
            src_str = "+".join(sorted(b_storage_sources))
            tag = f"{bname}[{src_str}]: {', '.join(sorted(b_claude_hosts)[:4])}"
            claude_browser_hits.append(tag)
            b_tags.append(f"含Claude/风控残留({len(b_claude_hosts)}域)")

        found_browsers.append(f"{bname}({', '.join(b_tags) if b_tags else '已安装'})")
        inv_st = "FAIL" if b_claude_hosts else ("WARN" if (b_locked or any(bname in x for x in browser_issues)) else "PASS")
        inv_obs = (
            f"残留域名({', '.join(sorted(b_storage_sources))}): {', '.join(sorted(b_claude_hosts))}"
            if b_claude_hosts
            else (("Cookies 文件运行中锁定(未完全核查); " if b_locked else "") + (", ".join(b_tags) or "0 残留"))
        )
        add_inv(
            "浏览器残留",
            f"{bname} 全 Profile 扫描",
            bpath,
            "检测 variations_country、DoH、代理扩展、WebRTC、IndexedDB、Network Persistent State 与 Cookie 域名（不读明文）",
            inv_obs,
            inv_st,
        )

    # Gecko family (Firefox / Zen / LibreWolf)
    gecko_dirs = {
        "Firefox": os.path.join(appdata, "Mozilla", "Firefox", "Profiles") if appdata else "",
        "Zen": os.path.join(appdata, "zen", "Profiles") if appdata else "",
        "LibreWolf": os.path.join(appdata, "librewolf", "Profiles") if appdata else "",
    }
    for gname, gprofs in gecko_dirs.items():
        if not gprofs or not os.path.isdir(gprofs):
            continue
        g_hosts: Set[str] = set()
        g_locked = False
        try:
            for pdir in os.listdir(gprofs)[:6]:
                pfull = os.path.join(gprofs, pdir)
                if not os.path.isdir(pfull):
                    continue
                # Unlocked storage/default origin folders (e.g. https+++claude.ai)
                st_def = os.path.join(pfull, "storage", "default")
                if os.path.isdir(st_def):
                    try:
                        for fn in os.listdir(st_def):
                            if "+++" in fn:
                                host = fn.split("+++", 1)[1].split("^")[0].split("+")[0]
                                if _match_risk_domain(host):
                                    g_hosts.add(host)
                    except Exception:
                        pass
                ck = os.path.join(pfull, "cookies.sqlite")
                if os.path.isfile(ck):
                    qst, rows = _safe_sqlite_query(ck, "SELECT DISTINCT host FROM moz_cookies")
                    if qst == "ok":
                        for (hk,) in rows:
                            h_clean = str(hk).lstrip(".")
                            if _match_risk_domain(h_clean):
                                g_hosts.add(h_clean)
                    elif qst == "locked":
                        g_locked = True
        except Exception:
            pass
        if g_locked:
            locked_browsers.append(gname)
        found_browsers.append(f"{gname}({'含Claude/风控残留' if g_hosts else ('锁定' if g_locked else '已安装')})")
        if g_hosts:
            claude_browser_hits.append(f"{gname}: {', '.join(sorted(g_hosts)[:4])}")
        add_inv(
            "浏览器残留",
            f"{gname} 全 Profile 扫描",
            gprofs,
            "检测 cookies.sqlite 与 storage/default 中的 Claude/hCaptcha/Stripe 域名（不读明文）",
            f"残留域名: {', '.join(sorted(g_hosts))}" if g_hosts else ("数据库运行中锁定" if g_locked else "0 残留"),
            "FAIL" if g_hosts else ("WARN" if g_locked else "PASS"),
        )

    if claude_browser_hits:
        checks.append(
            _make_check(
                "win_browser_claude_storage",
                "浏览器 Claude / Anthropic / hCaptcha / Stripe 站点残留",
                "FAIL",
                "；".join(claude_browser_hits) + (f" | 另有锁定浏览器: {', '.join(locked_browsers)}" if locked_browsers else ""),
                "检测到浏览器仍保留旧 Claude / Anthropic / hCaptcha / Stripe 站点 Cookie、IndexedDB 或 Network Persistent State 痕迹。",
                "最稳做法：在 Chrome / Edge 中为新号新建完全独立的 Profile（头像 -> 添加新配置文件），或彻底清除 claude.ai / anthropic.com / hcaptcha.com / stripe.com / stripe.network 的全部站点数据。",
                severity="high",
            )
        )
    elif locked_browsers:
        checks.append(
            _make_check(
                "win_browser_claude_storage",
                "浏览器 Claude / Anthropic / hCaptcha / Stripe 站点残留",
                "WARN",
                f"IndexedDB/NetworkState 未检出残留，但 {', '.join(locked_browsers)} 正在运行导致 Cookies 数据库被独占锁定",
                "Windows 下 Chrome/Edge 运行时会独占锁定 Cookies 文件，无法在运行时验证其中的 Cookie 键名（避免误报 PASS）。",
                "如需 100% 复核 Cookies 残留，请暂时关闭对应浏览器后点击「立即全面扫描」，或直接新建全新 Profile 使用。",
                severity="low",
            )
        )
    else:
        checks.append(
            _make_check(
                "win_browser_claude_storage",
                "浏览器 Claude / Anthropic / hCaptcha / Stripe 站点残留",
                "PASS",
                f"已扫 {len(found_browsers)} 个浏览器，未检出 Claude/风控站点残留",
                "已扫描所有可读取的 Cookies、IndexedDB 与 Network Persistent State，未发现 Claude/Anthropic/hCaptcha/Stripe 域名残留。",
            )
        )

    checks.append(
        _make_check(
            "other_browsers",
            "Windows 浏览器语言、DoH、代理扩展与 WebRTC 配置",
            "WARN" if browser_issues else ("PASS" if found_browsers else "INFO"),
            " | ".join(found_browsers) if found_browsers else "未检测到常见浏览器配置目录",
            f"发现风险配置: {'; '.join(browser_issues)}" if browser_issues else "已扫描浏览器未发现中文地区配置、国内 DoH 或代理扩展冲突。",
            "登录 Claude 前将目标浏览器的首选语言改为目标地区英文，关闭浏览器独立代理插件，并确保未开启与 Clash 冲突的强制 DoH。" if browser_issues else "",
            severity="high" if any("DoH" in x or "扩展" in x for x in browser_issues) else "low",
        )
    )

    return {"title": "Claude 全路径文件与浏览器残留 (Windows)", "checks": checks, "inventory": inventory}


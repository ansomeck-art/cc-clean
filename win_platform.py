#!/usr/bin/env python3
"""
Region Guard — Windows Native System, Network, Proxy & Claude Residue Audits.

Pure Python 3.9+ standard library module (zero third-party dependencies).
Strictly read-only; never reads or returns secrets, passwords, tokens,
cookie values, or proxy server credentials.
"""

import datetime
import json
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
    "32": "BR",
    "39": "CA",
    "45": "CN",
    "54": "DK",
    "61": "FI",
    "84": "FR",
    "94": "DE",
    "104": "HK",
    "113": "IN",
    "111": "ID",
    "68": "IE",
    "117": "IL",
    "118": "IT",
    "122": "JP",
    "134": "KR",
    "151": "MO",
    "167": "MY",
    "166": "MX",
    "176": "NL",
    "183": "NZ",
    "177": "NO",
    "201": "PH",
    "191": "PL",
    "193": "PT",
    "203": "RU",
    "215": "SG",
    "217": "ES",
    "221": "SE",
    "223": "CH",
    "237": "TW",
    "227": "TH",
    "235": "TR",
    "241": "UA",
    "224": "AE",
    "242": "GB",
    "244": "US",
    "251": "VN",
    "29": "BY",
    "131": "KP",
    "116": "IR",
    "56": "CU",
    "222": "SY",
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
    "Pacific Standard Time": "America/Los_Angeles",
    "Mountain Standard Time": "America/Denver",
    "US Mountain Standard Time": "America/Phoenix",
    "Central Standard Time": "America/Chicago",
    "Eastern Standard Time": "America/New_York",
    "Hawaiian Standard Time": "Pacific/Honolulu",
    "GMT Standard Time": "Europe/London",
    "W. Europe Standard Time": "Europe/Berlin",
    "Central Europe Standard Time": "Europe/Budapest",
    "Romance Standard Time": "Europe/Paris",
    "AUS Eastern Standard Time": "Australia/Sydney",
    "E. Australia Standard Time": "Australia/Brisbane",
    "W. Australia Standard Time": "Australia/Perth",
    "Cen. Australia Standard Time": "Australia/Adelaide",
    "Canada Central Standard Time": "America/Regina",
    "Atlantic Standard Time": "America/Halifax",
    "Russian Standard Time": "Europe/Moscow",
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

RESTRICTED_WIN_TZS = {"China Standard Time", "Russian Standard Time", "Belarus Standard Time", "Iran Standard Time", "Syria Standard Time", "North Korea Standard Time"}
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
}


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


def _run_win_cmd(cmd: List[str], timeout: int = 6) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return proc.returncode, proc.stdout, proc.stderr
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


def _parse_ipconfig_all(text: str) -> Dict[str, Any]:
    """Parse ipconfig /all (English or Chinese locale) for TUN adapters, IPv6, and DNS."""
    tun_ips: List[str] = []
    global_v6: List[str] = []
    dns_servers: List[str] = []
    cur_adapter = ""
    cur_desc = ""
    in_dns = False

    tun_kw = ("clash", "mihomo", "wintun", "meta", "sing-box", "singbox", "tun", "tap-windows", "wireguard", "tailscale", "flclash", "nekobox", "v2ray")
    ip4_pat = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    ip6_pat = re.compile(r"\b([0-9a-fA-F:]{4,})\b")

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            in_dns = False
            continue
        if not line[0].isspace() and line.endswith(":"):
            cur_adapter = line[:-1].strip()
            cur_desc = ""
            in_dns = False
            continue

        s = line.strip()
        low = s.lower()
        if any(k in low for k in ("description", "描述")):
            if ":" in s:
                cur_desc = s.split(":", 1)[1].strip()
            in_dns = False
            continue

        if any(k in low for k in ("dns servers", "dns 服务器")):
            in_dns = True
            after = s.split(":", 1)[1].strip() if ":" in s else ""
            for m4 in ip4_pat.findall(after):
                if m4 not in dns_servers:
                    dns_servers.append(m4)
            continue

        if in_dns and ":" not in s:
            for m4 in ip4_pat.findall(s):
                if m4 not in dns_servers:
                    dns_servers.append(m4)
            continue
        in_dns = False

        if any(k in low for k in ("ipv4 address", "ipv4 地址")):
            after = s.split(":", 1)[1] if ":" in s else s
            m4 = ip4_pat.search(after)
            if m4:
                ip = m4.group(1)
                combo = f"{cur_adapter} {cur_desc}".lower()
                if ip.startswith("198.18.") or any(k in combo for k in tun_kw):
                    tun_ips.append(f"{cur_adapter or 'TUN'}: {ip}")
        elif any(k in low for k in ("ipv6 address", "ipv6 地址", "temporary ipv6", "临时 ipv6")):
            if "link-local" in low or "本地链接" in low:
                continue
            after = s.split(":", 1)[1] if ":" in s else s
            after = after.split("(")[0].split("%")[0].strip()
            m6 = ip6_pat.search(after)
            if m6:
                addr = m6.group(1)
                if ":" in addr and not addr.lower().startswith(("fe80:", "::1", "fc", "fd")):
                    global_v6.append(f"{cur_adapter or 'NIC'}: {addr}")

    return {
        "tun_ips": tun_ips,
        "global_v6": global_v6,
        "dns_servers": dns_servers,
    }


def _parse_route_print(text: str) -> List[str]:
    defaults: List[str] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gw, iface, metric = parts[2], parts[3], parts[4]
            defaults.append(f"0.0.0.0 -> {gw} (iface={iface}, metric={metric})")
    return defaults


def win_check_tun_status() -> Tuple[bool, List[str], List[str], List[str]]:
    """Windows equivalent of _check_utun_status: TUN adapters, default routes, global IPv6."""
    _, ipcfg, _ = _run_win_cmd(["ipconfig", "/all"], timeout=5)
    _, rt_out, _ = _run_win_cmd(["route", "print", "-4"], timeout=5)
    parsed = _parse_ipconfig_all(ipcfg)
    tun_ips = parsed["tun_ips"]
    global_v6 = parsed["global_v6"]
    default_routes = _parse_route_print(rt_out)

    tun_up = bool(tun_ips) or any("198.18." in r for r in default_routes)
    return tun_up, tun_ips, default_routes, global_v6


def win_check_dns_and_proxy() -> Dict[str, Any]:
    """Windows equivalent of _check_dns_and_proxy_scutil."""
    _, ipcfg, _ = _run_win_cmd(["ipconfig", "/all"], timeout=5)
    parsed = _parse_ipconfig_all(ipcfg)
    dns_servers = parsed["dns_servers"]
    priv_pat = re.compile(r"^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)")
    private_dns = [d for d in dns_servers if priv_pat.match(d)]
    cn_dns = [d for d in dns_servers if d in CN_DNS_SERVERS]

    inet_key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    proxy_enable = bool(_read_reg("HKEY_CURRENT_USER", inet_key, "ProxyEnable", 0))
    proxy_server = str(_read_reg("HKEY_CURRENT_USER", inet_key, "ProxyServer", "") or "").strip()
    pac_url = str(_read_reg("HKEY_CURRENT_USER", inet_key, "AutoConfigURL", "") or "").strip()

    proxies: Dict[str, str] = {}
    if proxy_enable and proxy_server:
        proxies["ProxyEnable"] = "1"
        proxies["ProxyServer"] = re.sub(r"://[^/@\s]+@", "://<REDACTED>@", proxy_server)
    if pac_url:
        proxies["AutoConfigURL"] = re.sub(r"://[^/@\s]+@", "://<REDACTED>@", pac_url)

    return {
        "dns_servers": dns_servers,
        "scoped_private_dns": private_dns,
        "cn_dns": cn_dns,
        "proxies": proxies,
    }


def _discover_windows_clash_configs() -> List[Tuple[str, str]]:
    """Return (client_label, yaml_path) for existing Windows Clash/Mihomo config files."""
    appdata = os.environ.get("APPDATA", "")
    userprofile = os.environ.get("USERPROFILE", os.path.expanduser("~"))
    candidates = [
        ("Clash Verge Rev", os.path.join(appdata, "io.github.clash-verge-rev.clash-verge-rev", "clash-verge.yaml")),
        ("Clash Verge Rev", os.path.join(appdata, "io.github.clash-verge-rev.clash-verge-rev", "config.yaml")),
        ("Clash Verge", os.path.join(appdata, "clash-verge", "clash-verge.yaml")),
        ("Clash Verge", os.path.join(appdata, "clash-verge", "config.yaml")),
        ("Mihomo Party", os.path.join(appdata, "mihomo-party", "work", "config.yaml")),
        ("Mihomo Party", os.path.join(appdata, "mihomo-party", "config.yaml")),
        ("Clash for Windows", os.path.join(userprofile, ".config", "clash", "config.yaml")),
        ("Mihomo", os.path.join(userprofile, ".config", "mihomo", "config.yaml")),
    ]
    found: List[Tuple[str, str]] = []
    seen = set()
    for label, path in candidates:
        if path and os.path.isfile(path) and path not in seen:
            seen.add(path)
            found.append((label, path))
    return found


def win_audit_clash_proxy(safe_parse_yaml: Callable[[str], Dict[str, Any]]) -> Dict[str, Any]:
    """Windows equivalent of audit_clash_proxy (strictly redacted)."""
    checks: List[Dict[str, str]] = []
    _, tl_out, _ = _run_win_cmd(["tasklist", "/FO", "CSV", "/NH"], timeout=4)
    all_procs = _parse_tasklist_csv(tl_out)
    proxy_pat = re.compile(
        r"clash|mihomo|verge|v2ray|xray|sing-box|singbox|nekoray|nekobox|hiddify|flclash|tailscale|wireguard|openvpn|shadowsocks|trojan",
        re.I,
    )
    proxy_procs = [p for p in all_procs if proxy_pat.search(p)]
    checks.append(
        _make_check(
            "proxy_process",
            "代理 / VPN 运行状态 (Windows)",
            "PASS" if proxy_procs else "WARN",
            f"运行中 {len(proxy_procs)} 个" if proxy_procs else "未检测到常见代理进程",
            f"检测到代理进程: {', '.join(proxy_procs[:8])}" if proxy_procs else "未在 tasklist 中发现常见代理内核进程，请确认代理客户端已启动。",
            "" if proxy_procs else "请确认 Clash Verge / Mihomo Party / v2rayN 等已运行并接管流量。",
        )
    )

    net_info = win_check_dns_and_proxy()
    proxies = net_info["proxies"]
    if proxies:
        p_desc = ", ".join(f"{k}={v}" for k, v in proxies.items())
        checks.append(
            _make_check(
                "win_sys_proxy",
                "Windows 系统代理注册表 (Internet Settings)",
                "INFO",
                p_desc,
                "Windows 系统 HTTP/PAC 代理已启用；注意原生 CLI 或非系统代理应用（如 Claude Code / 部分 Electron 请求）可能不走系统代理，建议同时开启 TUN 虚拟网卡模式。",
            )
        )
    else:
        checks.append(
            _make_check(
                "win_sys_proxy",
                "Windows 系统代理注册表 (Internet Settings)",
                "INFO",
                "未开启系统 HTTP/PAC 代理 (纯 TUN 或直连)",
                "若开启了 Clash TUN 模式且下方检测全走目标节点，则纯 TUN 方式最干净；若未开 TUN 请检查代理设置。",
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
                    "当前为 Rule 规则模式，若分流规则遗漏或 DNS 回落本地可能直连泄露。",
                    "使用 Claude 期间建议切换为 Global，或严格核对 Anthropic/Stripe/hCaptcha 规则。",
                )
            )
        elif mode != "unknown":
            checks.append(_make_check("clash_mode", f"{client_label} 代理模式", "FAIL", mode, f"当前模式为 {mode}，存在直连泄露风险。", "切换为 Global 或严格 Rule 模式。"))

        ns_all = (
            (parsed.get("dns_nameserver") or [])
            + (parsed.get("dns_default_nameserver") or [])
            + (parsed.get("dns_proxy_server_nameserver") or [])
        )
        has_bad_dns = any(
            x.lower() == "system" or any(cn in x for cn in ("114.114", "223.5.5.5", "223.6.6.6", "119.29.29.29", "180.76.76.76"))
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
    else:
        checks.append(
            _make_check(
                "clash_config_missing",
                "Clash / Mihomo 配置文件探测",
                "INFO",
                "未发现常见路径下的 Clash/Mihomo 运行配置",
                "若你使用 v2rayN、sing-box 或其他客户端，此提示正常；请参考上方全域名分流与 DNS 实测结果。",
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

    # 2. Windows Locale, Preferred Languages & Non-Unicode System Locale
    intl_key = r"Control Panel\International"
    locale_name = str(_read_reg("HKEY_CURRENT_USER", intl_key, "LocaleName", "") or "").strip()
    pref_langs = _read_reg("HKEY_CURRENT_USER", r"Control Panel\International\User Profile", "Languages", [])
    if not isinstance(pref_langs, list):
        pref_langs = [str(pref_langs)] if pref_langs else []
    sys_nls_default = str(
        _read_reg("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Control\Nls\Language", "Default", "") or ""
    ).strip().lower()

    is_cn_locale = (
        locale_name.lower().startswith(("zh-cn", "zh_cn", "zh-hans"))
        or any(str(x).lower().startswith(("zh-cn", "zh-hans")) for x in pref_langs[:1])
    )
    is_cn_non_unicode = sys_nls_default == "0804"
    loc_obs = f"Locale={locale_name or '-'} | 首选语言={', '.join(pref_langs[:3]) or '-'} | 非Unicode代码页={sys_nls_default or '-'}"
    if is_cn_locale and t_code != "TW":
        checks.append(
            _make_check(
                "user_locale",
                "Windows 区域格式与首选语言",
                "FAIL",
                loc_obs,
                "当前 Windows 区域格式或首选语言为简体中文，浏览器与原生桌面端都会直接读取该区域设置。",
                "在 设置 -> 时间和语言 -> 语言和区域 中将 English 置顶并修改区域格式为目标地区。",
                severity="high",
            )
        )
    elif is_cn_non_unicode or (any("zh" in str(x).lower() for x in pref_langs) and t_code != "TW"):
        checks.append(
            _make_check(
                "user_locale",
                "Windows 区域格式与首选语言",
                "WARN",
                loc_obs,
                "首选语言列表或非 Unicode 系统区域（0804=简体中文）仍含中文痕迹。",
                "在 控制面板 -> 区域 -> 管理 -> 更改系统区域设置 中核对，并确保首选语言为目标地区英文。",
            )
        )
    else:
        checks.append(_make_check("user_locale", "Windows 区域格式与首选语言", "PASS", loc_obs, "Windows 区域格式与首选语言符合目标地区。"))

    # 3. Windows Timezone (tzutil /g) & Strict Restricted-TZ Reject
    rc_tz, tz_out, _ = _run_win_cmd(["tzutil", "/g"], timeout=4)
    win_tz_id = tz_out.strip() if rc_tz == 0 else ""
    iana_tz = WIN_TZ_TO_IANA.get(win_tz_id, "")
    local_dt = datetime.datetime.now().astimezone()
    offset_sec = int(local_dt.utcoffset().total_seconds()) if local_dt.utcoffset() else 0

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
                "系统时区 (tzutil)",
                "FAIL",
                f"{win_tz_id or '未知'} -> {iana_tz or '未映射'} (UTC{offset_sec/3600:+.1f})",
                f"当前 Windows 时区为 {win_tz_id or '未知'}，与目标地区 {target_cfg['name']} 不匹配（即使同为 UTC+8，China Standard Time 也会被浏览器与 Electron 直接识别为 Asia/Shanghai）。",
                f"将系统时区改为 {target_win_tz} 并重启电脑。",
                f'tzutil /s "{target_win_tz}"',
                severity="critical" if tz_is_restricted else "high",
            )
        )
    else:
        checks.append(
            _make_check(
                "sys_timezone",
                "系统时区 (tzutil)",
                "PASS",
                f"{win_tz_id} ({iana_tz or local_dt.strftime('%z')})",
                "Windows 系统时区与目标地区一致。若刚修改过时区，请完整重启电脑确保所有后台进程同步。",
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

    # 5. Windows Location Services
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
    if loc_lm.lower() == "deny" or loc_cu.lower() == "deny":
        checks.append(_make_check("location_services", "Windows 定位服务 (Wi-Fi 物理定位)", "PASS", f"HKLM={loc_lm or '-'} | HKCU={loc_cu or '-'}", "Windows 定位服务已关闭。"))
    else:
        checks.append(
            _make_check(
                "location_services",
                "Windows 定位服务 (Wi-Fi 物理定位)",
                "WARN",
                f"HKLM={loc_lm or 'Allow'} | HKCU={loc_cu or 'Allow'}",
                "Windows 定位依靠周边 Wi-Fi 物理信号（BSSID）测算位置，完全绕过代理隧道。",
                "在 设置 -> 隐私和安全性 -> 位置 中关闭「位置服务」。",
                severity="high",
            )
        )

    # 6. Computer Name
    comp_name = os.environ.get("COMPUTERNAME") or socket.gethostname() or ""
    bad_host: List[str] = []
    if _has_cjk(comp_name) or _has_non_ascii(comp_name):
        bad_host.append(f"含非英文字符({comp_name})")
    elif any(p in comp_name.lower() for p in ("diannao", "zh-cn", "wode", "depc")):
        bad_host.append(f"含中文拼音特征({comp_name})")
    if bad_host:
        checks.append(
            _make_check(
                "hostnames",
                "Windows 计算机名特征",
                "FAIL",
                comp_name,
                f"检测到明显中文/拼音命名特征：{'; '.join(bad_host)}。Claude Desktop 会读取并上报为 remoteToolsDeviceName。",
                "在 设置 -> 系统 -> 重命名这台电脑 改为纯英文名称并重启。",
                'Rename-Computer -NewName "Anson-PC" -Restart',
                severity="high",
            )
        )
    else:
        checks.append(_make_check("hostnames", "Windows 计算机名特征", "PASS", comp_name or "-", "计算机名为纯英文，无中文或拼音残留。"))

    # 7. Keyboard Input Method (Preload)
    preload = _list_reg_values("HKEY_CURRENT_USER", r"Keyboard Layout\Preload")
    preload_vals = [str(v).lower() for _, v in sorted(preload.items())]
    has_cn_kb = any(v.endswith("0804") for v in preload_vals)
    checks.append(
        _make_check(
            "input_method",
            "键盘布局与输入法 (Preload)",
            "WARN" if has_cn_kb else "PASS",
            f"布局列表={preload_vals[:5] or ['默认']}",
            "检测到简体中文键盘布局（0804），注册/登录 Claude 或过验证码时请用 Win+Space 切到英文键盘 (ENG)。" if has_cn_kb else "未检测到简体中文键盘布局。",
            "登录新号前切到 ENG 英文输入法。" if has_cn_kb else "",
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
            "Windows 环境变量 (代理 / ANTHROPIC / TZ / LANG)",
            "WARN" if env_risky else "PASS",
            ", ".join(env_findings[:6]) if env_findings else "无代理/中转站/异常区域变量",
            "发现代理或中转环境变量，可能使 Claude Code CLI 走不同于 TUN 的路径。" if env_risky else "进程与系统注册表环境变量均未注入异常代理或中国区设置。",
            "检查 系统属性 -> 环境变量，清理陈旧代理或 ANTHROPIC_BASE_URL。" if env_risky else "",
            severity="high" if env_risky else "low",
        )
    )

    # 10. Windows Hosts file
    hosts_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    custom_hosts: List[str] = []
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
        except Exception:
            pass
    checks.append(
        _make_check(
            "etc_hosts",
            "Windows hosts 域名劫持检测",
            "WARN" if custom_hosts else "PASS",
            f"发现 {len(custom_hosts)} 条自定义条目" if custom_hosts else "仅默认条目",
            f"条目: {'; '.join(custom_hosts[:5])}" if custom_hosts else "hosts 文件无自定义劫持条目。",
            "确认其中不包含 claude / anthropic / stripe / cloudflare 的陈旧绑定。" if custom_hosts else "",
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

    # 12. Interface Manual CN DNS Audit
    net_info = win_check_dns_and_proxy()
    cn_dns = net_info["cn_dns"]
    if cn_dns:
        checks.append(
            _make_check(
                "network_services_proxy",
                "网卡 DNS 服务器合规检查",
                "FAIL",
                f"发现国内公共 DNS: {', '.join(cn_dns)}",
                "物理网卡配置了国内公共 DNS，一旦代理断开会瞬间向国内 DNS 发起解析泄漏。",
                "在网络适配器属性中将 DNS 改为自动获取或 1.1.1.1 / 8.8.8.8。",
                severity="high",
            )
        )
    else:
        checks.append(
            _make_check(
                "network_services_proxy",
                "网卡 DNS 服务器合规检查",
                "PASS",
                f"当前 DNS: {', '.join(net_info['dns_servers'][:4]) or '默认'}",
                "物理网卡未配置 114 / 223.5 / 119.29 等国内公共 DNS。",
            )
        )

    # 13. NTP Time Server
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

    # 14. MITM Root CA Certificates (CurrentUser & LocalMachine Root)
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
                f"命中: {'; '.join(mitm_hits[:4])}。HTTPS 解密会破坏浏览器与 Electron 的 TLS 指纹。",
                "使用 Claude 时务必关闭所有抓包代理与 HTTPS 解密。",
                severity="high",
            )
        )
    else:
        checks.append(_make_check("mitm_trust_certs", "自定义 MITM 抓包根证书检测", "PASS", "未发现常见抓包工具根证书", "Windows 信任根证书库未发现 Fiddler / Charles / mitmproxy 等抓包根证书。"))

    # 15. Hardware MachineGuid Awareness (strictly masked, never outputs GUID)
    has_guid = bool(_read_reg("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Cryptography", "MachineGuid", ""))
    checks.append(
        _make_check(
            "hardware_device_fingerprint",
            "Windows 硬件与系统标识提醒 (MachineGuid)",
            "INFO",
            f"MachineGuid={'存在(已脱敏)' if has_guid else '未知'}",
            "网页版浏览器沙箱无法读取 Windows MachineGuid；原生桌面端理论上可读取系统级标识。若本机曾被封号，新号建议优先使用全新独立的 Chrome/Edge 浏览器 Profile 网页版。",
        )
    )

    return {"title": "Windows 系统环境与指纹", "checks": checks}


def win_audit_claude_browser_residue() -> Dict[str, Any]:
    """Windows comprehensive Claude Desktop, CLI, Credential Manager, Temp, IDE & Browser audit."""
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

    # 1. Running processes & Installed App / CLI
    _, tl_out, _ = _run_win_cmd(["tasklist", "/FO", "CSV", "/NH"], timeout=4)
    all_procs = _parse_tasklist_csv(tl_out)
    running_claude = [p for p in all_procs if p.lower() in {"claude.exe", "claude-code.exe", "anthropicclaude.exe"}]
    installed_apps = [
        p
        for p in [
            os.path.join(localappdata, "AnthropicClaude", "claude.exe"),
            os.path.join(localappdata, "Programs", "claude", "Claude.exe"),
        ]
        if p and os.path.exists(p)
    ]
    cli_bin = shutil.which("claude") or shutil.which("claude.cmd") or ""
    proc_obs = (
        f"进程={len(running_claude)} ({', '.join(running_claude[:3])})" if running_claude else "进程=未运行"
    ) + f" | Desktop App={'已安装' if installed_apps else '未安装'} | CLI={'已安装(' + cli_bin + ')' if cli_bin else '未安装'}"
    checks.append(
        _make_check(
            "claude_proc",
            "Claude 安装状态与后台进程 (Windows)",
            "INFO" if (running_claude or installed_apps or cli_bin) else "PASS",
            proc_obs,
            "清理本地残留或切换新号前，请先在任务管理器中彻底结束所有 Claude 进程。",
        )
    )
    add_inv("运行与程序", "Claude.exe / CLI / 进程", "%LOCALAPPDATA%\\AnthropicClaude · PATH\\claude", "确认是否存在桌面端或 CLI 后台常驻进程", proc_obs, "INFO" if (running_claude or installed_apps or cli_bin) else "PASS")

    # 2. Claude Desktop Files & Deep Fingerprint Inspection
    claude_dir = os.path.join(appdata, "Claude") if appdata else ""
    claude_paths = [
        p
        for p in [
            claude_dir,
            os.path.join(localappdata, "AnthropicClaude") if localappdata else "",
            os.path.join(localappdata, "claude-desktop-updater") if localappdata else "",
            os.path.join(localappdata, "Claude") if localappdata else "",
        ]
        if p and os.path.exists(p)
    ]
    desktop_clean_cmd = (
        'Remove-Item -Recurse -Force "$env:APPDATA\\Claude","$env:LOCALAPPDATA\\AnthropicClaude","$env:LOCALAPPDATA\\claude-desktop-updater","$env:LOCALAPPDATA\\Claude" -ErrorAction SilentlyContinue'
    )

    desktop_details: List[str] = []
    desktop_status = "PASS" if not claude_paths else "WARN"
    desktop_sev = "low"

    ant_did = os.path.join(claude_dir, "ant-did") if claude_dir else ""
    if ant_did and os.path.isfile(ant_did):
        sz = os.path.getsize(ant_did)
        desktop_details.append(f"存在 ant-did 设备 ID ({sz}B)")
        desktop_status = "FAIL"
        desktop_sev = "high"
        add_inv("Claude Desktop", "ant-did 设备唯一 ID", r"%APPDATA%\Claude\ant-did", "Anthropic 跨账号关联核心设备指纹文件", f"存在 ({sz} B)", "FAIL")
    else:
        add_inv("Claude Desktop", "ant-did 设备唯一 ID", r"%APPDATA%\Claude\ant-did", "Anthropic 跨账号关联核心设备指纹文件", "已清理 (0 残留)", "PASS")

    # Cookies (Electron stores in Network\Cookies or Cookies)
    cookies_db = ""
    for cand in [os.path.join(claude_dir, "Network", "Cookies"), os.path.join(claude_dir, "Cookies")]:
        if claude_dir and os.path.isfile(cand):
            cookies_db = cand
            break
    if cookies_db:
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
                for n in ["anthropic-device-id", "hmt_id", "__ssid", "_fbp", "sessionKey", "routingHint", "lastActiveOrg", "cf_clearance", "__cf_bm"]
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
        add_inv("Claude Desktop", "Cookies 追踪数据库", r"%APPDATA%\Claude\Network\Cookies", "存储 anthropic-device-id、hmt_id、sessionKey 等追踪键（不读明文）", c_obs, "FAIL" if desktop_status == "FAIL" else "WARN")
    else:
        add_inv("Claude Desktop", "Cookies 追踪数据库", r"%APPDATA%\Claude\Network\Cookies", "存储 anthropic-device-id、hmt_id、sessionKey 等追踪键", "已清理 (0 残留)", "PASS")

    # Preferences & Local State
    pref_notes: List[str] = []
    pref_st = "PASS"
    pref_path = os.path.join(claude_dir, "Preferences") if claude_dir else ""
    ls_path = os.path.join(claude_dir, "Local State") if claude_dir else ""
    if pref_path and os.path.isfile(pref_path):
        pref_st = "WARN"
        try:
            pr = json.load(open(pref_path, "r", encoding="utf-8"))
            dicts = (pr.get("spellcheck") or {}).get("dictionaries")
            if dicts:
                pref_notes.append(f"拼写字典={dicts}")
                if any("zh" in str(x).lower() for x in dicts):
                    pref_st = "FAIL"
                    desktop_status = "FAIL"
            if ((pr.get("electron") or {}).get("media") or {}).get("device_id_salt"):
                pref_notes.append("含 electron device_id_salt")
        except Exception:
            pref_notes.append("Preferences 存在")
    if ls_path and os.path.isfile(ls_path):
        if pref_st == "PASS":
            pref_st = "WARN"
        try:
            ls_d = json.load(open(ls_path, "r", encoding="utf-8"))
            if ls_d.get("os_crypt"):
                pref_notes.append("Local State 含 os_crypt (DPAPI 密钥)")
        except Exception:
            pref_notes.append("Local State 存在")
    if pref_notes:
        desktop_details.extend(pref_notes)
    add_inv("Claude Desktop", "Preferences & Local State", r"%APPDATA%\Claude\{Preferences, Local State}", "记录 device_id_salt、拼写语言字典与 DPAPI 加密头", "；".join(pref_notes) if pref_notes else "已清理 (0 残留)", pref_st)

    # config.json & claude_desktop_config.json
    cfg_notes: List[str] = []
    cfg_st = "PASS"
    cfg_json = os.path.join(claude_dir, "config.json") if claude_dir else ""
    mcp_json = os.path.join(claude_dir, "claude_desktop_config.json") if claude_dir else ""
    if cfg_json and os.path.isfile(cfg_json):
        cfg_st = "WARN"
        try:
            cj = json.load(open(cfg_json, "r", encoding="utf-8"))
            if cj.get("locale"):
                cfg_notes.append(f"locale={cj.get('locale')}")
            for k_u in ("lastKnownAccountUuid", "orgUuid", "userId", "oauthAccount"):
                if cj.get(k_u):
                    cfg_notes.append(f"含 {k_u}")
                    cfg_st = "FAIL"
                    desktop_status = "FAIL"
        except Exception:
            cfg_notes.append("config.json 存在")
    if mcp_json and os.path.isfile(mcp_json):
        if cfg_st == "PASS":
            cfg_st = "WARN"
        try:
            mc = json.load(open(mcp_json, "r", encoding="utf-8"))
            dev_name = str((mc.get("preferences") or {}).get("remoteToolsDeviceName", ""))
            if dev_name:
                cfg_notes.append(f"remoteToolsDeviceName={dev_name}")
                if _has_cjk(dev_name):
                    cfg_st = "FAIL"
                    desktop_status = "FAIL"
        except Exception:
            cfg_notes.append("claude_desktop_config.json 存在")
    if cfg_notes:
        desktop_details.extend(cfg_notes)
    add_inv("Claude Desktop", "config.json & desktop_config", r"%APPDATA%\Claude\{config.json, claude_desktop_config.json}", "保存旧账号 UUID、locale 与上报设备名", "；".join(cfg_notes) if cfg_notes else "已清理 (0 残留)", cfg_st)

    # Logs & Sub-storages
    log_dir = os.path.join(claude_dir, "logs") if claude_dir else ""
    log_obs = "已清理 (0 残留)"
    log_st = "PASS"
    if log_dir and os.path.isdir(log_dir):
        rb_cnt = ban_cnt = stripe_cnt = net_cnt = 0
        lfiles = [fn for fn in os.listdir(log_dir) if fn.endswith(".log") and os.path.isfile(os.path.join(log_dir, fn))]
        for fn in lfiles:
            try:
                txt = open(os.path.join(log_dir, fn), "r", encoding="utf-8", errors="replace").read()
                rb_cnt += txt.count("region_blocked") + txt.count("isn't available in your region")
                ban_cnt += txt.count("account_banned")
                stripe_cnt += txt.count("Failed to load Stripe.js")
                net_cnt += txt.count("ERR_NETWORK_CHANGED")
            except Exception:
                pass
        log_obs = f"{len(lfiles)} 日志 (region_blocked={rb_cnt}, account_banned={ban_cnt}, Stripe失败={stripe_cnt}, 网络变化={net_cnt})"
        log_st = "FAIL" if (rb_cnt or ban_cnt) else "WARN"
        if log_st == "FAIL":
            desktop_status = "FAIL"
            desktop_sev = "high"
        desktop_details.append(f"日志: {log_obs}")
    add_inv("Claude Desktop", "运行日志与封禁历史", r"%APPDATA%\Claude\logs\*.log", "记录 region_blocked、account_banned、Stripe.js 失败与断流事件", log_obs, log_st)

    sub_names = ["Trust Tokens", "DIPS", "SharedStorage", "Local Storage", "Session Storage", "IndexedDB", "Cache", "Code Cache", "GPUCache", "sentry", "Service Worker"]
    exist_subs = [s for s in sub_names if claude_dir and os.path.exists(os.path.join(claude_dir, s))]
    add_inv("Claude Desktop", "Electron 子存储与更新缓存", r"%APPDATA%\Claude\{Local Storage, Trust Tokens, Cache...} · %LOCALAPPDATA%\claude-desktop-updater", "Electron 沙箱本地存储、Trust Tokens、DIPS 与更新器缓存", f"存在 {len(exist_subs)} 个子目录" if exist_subs else "已清理 (0 残留)", "WARN" if exist_subs else "PASS")

    if not claude_paths:
        checks.append(_make_check("claude_desktop_files", "Claude Desktop 全套设备指纹与缓存", "PASS", "已清理干净 (0 残留)", "未发现 %APPDATA%\\Claude 与 %LOCALAPPDATA%\\AnthropicClaude 残留。"))
    else:
        checks.append(
            _make_check(
                "claude_desktop_files",
                "Claude Desktop 全套设备指纹与缓存",
                desktop_status,
                f"存在 {len(claude_paths)} 个本地目录",
                "；".join(desktop_details) if desktop_details else ", ".join(claude_paths),
                "更换新号前先结束所有 Claude 进程并彻底删除上述目录。",
                desktop_clean_cmd,
                severity=desktop_sev,
            )
        )

    # 3. Claude Code CLI
    cc_json = os.path.join(userprofile, ".claude.json")
    cc_dir = os.path.join(userprofile, ".claude")
    cc_backups = [fn for fn in (os.listdir(userprofile) if os.path.isdir(userprofile) else []) if fn.startswith(".claude.json.backup")]
    xdg_hits = [
        p
        for p in [
            os.path.join(userprofile, ".anthropic"),
            os.path.join(userprofile, ".config", "claude"),
            os.path.join(userprofile, ".cache", "claude"),
        ]
        if os.path.exists(p)
    ]
    cc_notes: List[str] = []
    cc_status = "PASS"
    if os.path.isfile(cc_json):
        cc_status = "WARN"
        try:
            d = json.load(open(cc_json, "r", encoding="utf-8"))
            flags = [k for k in ["machineID", "userID", "oauthAccount", "firstStartTime"] if k in d]
            cc_notes.append(f".claude.json 含 {', '.join(flags) if flags else '配置'}")
            if any(k in d for k in ("machineID", "userID", "oauthAccount")):
                cc_status = "FAIL"
        except Exception:
            cc_notes.append(".claude.json 存在")
    if cc_backups:
        cc_status = "WARN" if cc_status == "PASS" else cc_status
        cc_notes.append(f"{len(cc_backups)} 个备份")
    if os.path.exists(cc_dir):
        cc_status = "WARN" if cc_status == "PASS" else cc_status
        fcnt, fbytes = _dir_stats(cc_dir, max_files=1000)
        cc_notes.append(f".claude\\ ({fcnt} 文件, {_fmt_bytes(fbytes)})")
    if xdg_hits:
        cc_status = "WARN" if cc_status == "PASS" else cc_status
        cc_notes.append(f"额外目录 {len(xdg_hits)} 个")

    cli_clean_cmd = 'Remove-Item -Recurse -Force "$env:USERPROFILE\\.claude.json","$env:USERPROFILE\\.claude.json.backup*","$env:USERPROFILE\\.claude","$env:USERPROFILE\\.anthropic" -ErrorAction SilentlyContinue'
    checks.append(
        _make_check(
            "claude_code_cli",
            "Claude Code CLI 全路径状态 (~\\.claude*)",
            cc_status,
            "；".join(cc_notes) if cc_notes else "已清理干净 (0 残留)",
            "Claude Code CLI 会在 .claude.json 中记录 machineID / userID / oauthAccount。" if cc_notes else "未检测到 Claude Code CLI 本地状态残留。",
            "换新号前先清理 .claude.json 与 .claude 目录。" if cc_notes else "",
            cli_clean_cmd if cc_notes else "",
            severity="high" if cc_status == "FAIL" else "low",
        )
    )
    add_inv("Claude Code CLI", ".claude.json & .claude\\", r"%USERPROFILE%\.claude.json* · %USERPROFILE%\.claude", "存储 CLI 的 machineID、userID、oauthAccount 与 statsig 标识", "；".join(cc_notes) if cc_notes else "已清理 (0 残留)", cc_status)

    # 4. Windows Credential Manager (cmdkey /list — target names ONLY, never passwords)
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
    known_low = {p.lower() for p in claude_paths}
    wc_hits: List[str] = []
    for base_label, base_dir in [("%APPDATA%", appdata), ("%LOCALAPPDATA%", localappdata), ("%TEMP%", temp_dir), ("CrashDumps", os.path.join(localappdata, "CrashDumps") if localappdata else "")]:
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
        ("Cursor 扩展", os.path.join(userprofile, ".cursor", "extensions")),
        ("Windsurf 扩展", os.path.join(userprofile, ".windsurf", "extensions")),
        ("VS Code 存储", os.path.join(appdata, "Code", "User", "globalStorage") if appdata else ""),
        ("Cursor 存储", os.path.join(appdata, "Cursor", "User", "globalStorage") if appdata else ""),
        ("JetBrains", os.path.join(appdata, "JetBrains") if appdata else ""),
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
            "已扫描 %APPDATA%、%LOCALAPPDATA%、%TEMP%、CrashDumps、注册表协议及 VS Code / Cursor / JetBrains 插件目录。",
            "请核对并清理上述边缘目录。" if wc_all else "",
        )
    )
    add_inv("系统缓存/日志/IDE", "AppData / Temp / CrashDumps 通配", r"%APPDATA% · %LOCALAPPDATA% · %TEMP% · CrashDumps", "捕获隐藏缓存、安装临时目录与崩溃转储文件", f"发现 {len(wc_hits)} 项" if wc_hits else "0 残留", "WARN" if wc_hits else "PASS")
    add_inv("凭据与注册表", "claude:// 协议注册", r"HKCU\Software\Classes\claude", "记录 claude:// 深链协议注册（低风险）", "保留登记 (低风险)" if reg_claude_url else "未注册", "INFO" if reg_claude_url else "PASS")
    add_inv("系统缓存/日志/IDE", "IDE 扩展与全局存储", "VS Code / Cursor / Windsurf / JetBrains", "检测 anthropic.claude-code 插件与独立缓存", f"发现 {len(ide_hits)} 项" if ide_hits else "0 残留 / 未安装", "WARN" if ide_hits else "PASS")

    # 6. Windows Browsers Deep Audit (Edge / Chrome / Brave / Arc / Vivaldi / Opera / Firefox)
    chromium_dirs = {
        "Chrome": os.path.join(localappdata, "Google", "Chrome", "User Data"),
        "Edge": os.path.join(localappdata, "Microsoft", "Edge", "User Data"),
        "Brave": os.path.join(localappdata, "BraveSoftware", "Brave-Browser", "User Data"),
        "Arc": os.path.join(localappdata, "Packages"),  # Arc Win uses MSIX if present
        "Vivaldi": os.path.join(localappdata, "Vivaldi", "User Data"),
        "Chromium": os.path.join(localappdata, "Chromium", "User Data"),
        "Opera": os.path.join(appdata, "Opera Software", "Opera Stable"),
    }
    found_browsers: List[str] = []
    browser_issues: List[str] = []
    claude_browser_hits: List[str] = []

    for bname, bpath in chromium_dirs.items():
        if bname == "Arc" or not bpath or not os.path.isdir(bpath):
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
        for pdir in prof_dirs[:6]:
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
            # Read-only Cookies host_key check (NEVER reads value or encrypted_value!)
            for ck_rel in (os.path.join("Network", "Cookies"), "Cookies"):
                ck_file = os.path.join(pdir, ck_rel)
                if not os.path.isfile(ck_file):
                    continue
                tmp = tempfile.mktemp(suffix=".db")
                try:
                    shutil.copy2(ck_file, tmp)
                    conn = sqlite3.connect(tmp)
                    rows = conn.execute("SELECT DISTINCT host_key FROM cookies").fetchall()
                    conn.close()
                    for (hk,) in rows:
                        h_clean = str(hk).lstrip(".")
                        if _match_risk_domain(h_clean):
                            b_claude_hosts.add(h_clean)
                except Exception:
                    pass
                finally:
                    if os.path.exists(tmp):
                        os.remove(tmp)
                break
        if b_claude_hosts:
            tag = f"{bname}: {', '.join(sorted(b_claude_hosts)[:4])}"
            claude_browser_hits.append(tag)
            b_tags.append(f"含Claude/风控Cookie({len(b_claude_hosts)}域)")
        found_browsers.append(f"{bname}({', '.join(b_tags) if b_tags else '已安装'})")
        add_inv(
            "浏览器残留",
            f"{bname} 全 Profile 扫描",
            bpath,
            "检测 variations_country、DoH、语言排序、WebRTC 策略与 Claude/hCaptcha/Stripe Cookie 域名（不读明文）",
            f"残留域名: {', '.join(sorted(b_claude_hosts))}" if b_claude_hosts else (", ".join(b_tags) or "0 残留"),
            "FAIL" if b_claude_hosts else ("WARN" if any(bname in x for x in browser_issues) else "PASS"),
        )

    # Firefox profiles check (host column ONLY, zero values)
    ff_profs = os.path.join(appdata, "Mozilla", "Firefox", "Profiles") if appdata else ""
    if ff_profs and os.path.isdir(ff_profs):
        ff_hosts: Set[str] = set()
        try:
            for pdir in os.listdir(ff_profs)[:6]:
                ck = os.path.join(ff_profs, pdir, "cookies.sqlite")
                if not os.path.isfile(ck):
                    continue
                tmp = tempfile.mktemp(suffix=".db")
                try:
                    shutil.copy2(ck, tmp)
                    conn = sqlite3.connect(tmp)
                    rows = conn.execute("SELECT DISTINCT host FROM moz_cookies").fetchall()
                    conn.close()
                    for (hk,) in rows:
                        h_clean = str(hk).lstrip(".")
                        if _match_risk_domain(h_clean):
                            ff_hosts.add(h_clean)
                except Exception:
                    pass
                finally:
                    if os.path.exists(tmp):
                        os.remove(tmp)
        except Exception:
            pass
        found_browsers.append(f"Firefox({'含Claude/风控Cookie' if ff_hosts else '已安装'})")
        if ff_hosts:
            claude_browser_hits.append(f"Firefox: {', '.join(sorted(ff_hosts)[:4])}")
        add_inv("浏览器残留", "Firefox 全 Profile 扫描", ff_profs, "检测 Firefox cookies.sqlite 中的 Claude/hCaptcha/Stripe 域名（不读明文）", f"残留域名: {', '.join(sorted(ff_hosts))}" if ff_hosts else "0 残留", "FAIL" if ff_hosts else "PASS")

    if claude_browser_hits:
        checks.append(
            _make_check(
                "win_browser_claude_storage",
                "浏览器 Claude / Anthropic / hCaptcha / Stripe Cookie 残留",
                "FAIL",
                "；".join(claude_browser_hits),
                "检测到浏览器仍保留旧 Claude / Anthropic / hCaptcha / Stripe 站点 Cookie（注意：如果浏览器正在运行导致数据库被锁，部分已打开的 Profile 需关闭浏览器后再扫更准）。",
                "最稳做法：在 Chrome / Edge 中为新号新建一个完全独立的 Profile（头像 -> 添加新配置文件），或清除 claude.ai / anthropic.com / hcaptcha.com / stripe.com 的全部站点数据。",
                severity="high",
            )
        )
    else:
        checks.append(
            _make_check(
                "win_browser_claude_storage",
                "浏览器 Claude / Anthropic / hCaptcha / Stripe Cookie 残留",
                "PASS",
                f"已扫 {len(found_browsers)} 个浏览器，未检出 Claude/风控站点 Cookie 残留",
                "提示：Windows 下若 Chrome/Edge 正在运行，SQLite Cookies 文件可能被占用锁定；如需彻底复查可关闭浏览器或新建独立 Profile。",
            )
        )

    checks.append(
        _make_check(
            "other_browsers",
            "Windows 浏览器语言、DoH 与 WebRTC 配置",
            "WARN" if browser_issues else ("PASS" if found_browsers else "INFO"),
            " | ".join(found_browsers) if found_browsers else "未检测到常见浏览器配置目录",
            f"发现语言/地区风险: {'; '.join(browser_issues)}" if browser_issues else "已扫描浏览器未发现明显中文地区配置冲突。",
            "登录 Claude 前将目标浏览器的首选语言改为目标地区英文，并确保未开启与 Clash 冲突的独立 DoH。" if browser_issues else "",
        )
    )

    return {"title": "Claude 全路径文件与浏览器残留 (Windows)", "checks": checks, "inventory": inventory}

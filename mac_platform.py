"""Read-only macOS observations. External commands are dependency-injected."""
import re


def check_ipv6_disabled(run_cmd_fn):
    rc, text, _ = run_cmd_fn(["/usr/sbin/networksetup", "-listnetworkserviceorder"], timeout=5)
    services = []
    pending = None
    excluded = re.compile(r"clash|hako|vpn|wireguard|tailscale|surge|mihomo|shadowrocket|stash", re.I)
    if rc == 0:
        for line in text.splitlines():
            match = re.match(r"^\((?:\d+|\*)\)\s+(.+)$", line.strip())
            if match:
                pending = match.group(1).strip()
                continue
            hw = re.match(r"\(Hardware Port:\s*(.*?),\s*Device:\s*(.*?)\)", line.strip())
            if pending and hw:
                port, device = hw.groups()
                if device and not device.startswith("utun") and not excluded.search(pending + " " + port):
                    services.append(pending)
                pending = None
    observed, not_off, unknown = [], [], []
    for service in dict.fromkeys(services):
        rc, info, _ = run_cmd_fn(["/usr/sbin/networksetup", "-getinfo", service], timeout=5)
        match = re.search(r"^IPv6:\s*(.+)$", info, re.M) if rc == 0 else None
        state = match.group(1).strip() if match else "未知"
        observed.append(f"{service}: {state}")
        if not match:
            unknown.append(service)
        elif state.lower() != "off":
            not_off.append(service)
    status = "FAIL" if not_off else ("WARN" if unknown or not services else "PASS")
    detail = "只读核验所有物理/桥接网络服务是否明确设为 IPv6: Off；未关闭不表示已发现泄漏。"
    if unknown or not services:
        detail += " 部分服务未能确认，未知状态不计为通过。"
    def quote(value):
        return "'" + value.replace("'", "'\"'\"'") + "'"
    return dict(id="mac_ipv6_disabled", title="物理网络服务 IPv6 关闭状态", status=status,
                severity="high" if not_off else "low", observed=" | ".join(observed) or "未知：无法枚举物理网络服务",
                detail=detail, fix_advice="可在系统网络设置中自行审阅 IPv6 配置。" if not_off else "",
                fix_cmd="\n".join("networksetup -setv6off " + quote(s) for s in not_off))

import datetime
import errno
import ipaddress
import json
import os
import platform
import plistlib
import shutil
import sqlite3
import stat
import tempfile
from pathlib import Path
from urllib.parse import quote
from proxy_runtime import HakoRuntime
from audit_common import (check, cn_dns, count_log_tail, inspect_telemetry, read_json,
                          risk_root, risk_tags, safe_locale, simplified,
                          safe_parse_clash_yaml, safe_parse_surge_conf, RESTRICTED_TZS)

TCC_DETAIL = "受 macOS 隐私权限 (TCC) 限制，未读取 Safari 沙箱目录。可自行在系统设置授予完全磁盘访问权限后复测，或在 Safari 设置 → 隐私 → 管理网站数据中自查。"
RESTRICTED_COUNTRIES = {"CN", "HK", "MO", "RU", "BY", "KP", "IR", "CU", "SY"}


def _home(home=None):
    return Path(home) if home is not None else Path.home()


def _state(path):
    """Unlike exists/isdir, do not swallow EPERM/EACCES (TCC)."""
    try:
        return path.stat()
    except FileNotFoundError:
        return None


def _is_permission(exc):
    return isinstance(exc, PermissionError) or getattr(exc, "errno", None) in {errno.EACCES, errno.EPERM}


def _safe_sqlite_query(db_path, sql):
    """Snapshot DB+WAL+SHM, open only the copy in SQLite read-only mode.

    Callers project metadata columns only; no cookie values or URL paths are selected.
    Permission errors and inconsistent snapshots never become an empty-success result.
    """
    path = Path(db_path)
    try:
        if _state(path) is None:
            return "missing", []
        with tempfile.TemporaryDirectory(prefix="rg-audit-") as temp:
            dst = Path(temp) / "snapshot.db"
            sources = [path, Path(str(path) + "-wal"), Path(str(path) + "-shm")]
            stamps = []
            for source in sources:
                info = _state(source)
                stamps.append((info.st_size, info.st_mtime_ns) if info else None)
                if info:
                    shutil.copyfile(source, str(dst) + str(source)[len(str(path)):])
            for source, before in zip(sources, stamps):
                info = _state(source)
                after = (info.st_size, info.st_mtime_ns) if info else None
                if before != after:
                    return "changed", []
            conn = sqlite3.connect("file:" + quote(str(dst)) + "?mode=ro", uri=True, timeout=1)
            try:
                conn.execute("PRAGMA query_only=ON")
                cursor = conn.execute(sql)
                rows = cursor.fetchmany(10001)
                return ("limited" if len(rows) > 10000 else "ok"), rows[:10000]
            finally:
                conn.close()
    except OSError as exc:
        return ("denied" if _is_permission(exc) else "error"), []
    except sqlite3.Error:
        return "error", []


def language_check(languages, locale="en_US", target="US"):
    languages = [safe_locale(value) for value in languages] if isinstance(languages, list) else []
    primary = languages[0] if languages else ""
    if primary and simplified(primary):
        status, detail = "FAIL", "首选主语言包含简体中文/中国区域。"
    elif any(simplified(lang) for lang in languages[1:]):
        status, detail = "WARN", "虽然主界面语言已设为英文，但 macOS 备选语言列表仍含简体中文，Claude 桌面端会通过 app.getPreferredSystemLanguages() 将完整列表注入 window.desktopPreferredLanguages。"
    elif not primary or primary == "未知":
        status, detail = "INFO", "未能读取有效语言列表。"
    elif target == "US" and (primary.lower() != "en-us" or safe_locale(locale).lower() != "en-us"):
        status, detail = "WARN", "美国目标语言与区域偏好尚未统一为 en-US。"
    else:
        status, detail = "PASS", "完整语言栈未发现简体中文/中国区域。"
    return check("user_locale", "AppleLanguages 完整语言栈与 AppleLocale", status,
                 f"{safe_locale(locale)} / {', '.join(languages) or '未知'}", detail,
                 "high" if status in {"FAIL", "WARN"} else "low")


def mac_check_tun_details(run_cmd_fn):
    if_rc, iftext, _ = run_cmd_fn(["/sbin/ifconfig"], timeout=4)
    nwi_rc, nwi, _ = run_cmd_fn(["/usr/sbin/scutil", "--nwi"], timeout=4)
    route_rc, routes, _ = run_cmd_fn(["/usr/sbin/netstat", "-rn"], timeout=4)
    primaries, family = {}, ""
    for line in nwi.splitlines():
        section = re.match(r"\s*(IPv[46]) network interface information", line)
        if section:
            family = section.group(1)
        interface = re.match(r"\s*([a-z]+\d+)\s*:\s*flags", line)
        if family and interface:
            primaries.setdefault(family, interface.group(1))
    utuns, bridges, global_v6, cn_v6 = [], [], [], []
    iface, active = "", False
    for line in iftext.splitlines():
        match = re.match(r"^([a-zA-Z0-9]+):.*flags=.*<([^>]*)>", line)
        if match:
            iface = match.group(1)
            active = "UP" in match.group(2).split(",")
            if iface.startswith("utun") and active:
                utuns.append(iface)
            if (iface == "bridge100" or iface.startswith("vmnet")) and active:
                bridges.append(iface)
            continue
        match = re.search(r"\binet6\s+([0-9a-fA-F:]+)", line)
        if match and active and not iface.startswith(("utun", "lo")):
            try:
                address = ipaddress.IPv6Address(match.group(1))
                if address.is_global:
                    # Never return the host identifier (nor the unmasked network prefix).
                    first = address.exploded.split(":")[0]
                    masked = f"{iface}: {first}:xxxx:xxxx::*"
                    global_v6.append(masked)
                    if str(address).startswith(("240e:", "2408:8", "2409:8", "240c:", "2001:da8:")):
                        cn_v6.append(masked)
            except ValueError:
                pass
    defaults = []
    for line in routes.splitlines():
        cols = line.split()
        if cols and cols[0] in {"default", "::/0", "0/1", "128.0/1", "0.0.0.0/1", "128.0.0.0/1"}:
            interfaces = [c for c in cols[2:] if re.fullmatch(r"(?:en|utun|bridge|vmnet)\d+", c)]
            if interfaces:
                defaults.append(cols[0] + " -> " + interfaces[0])
    routed = any("utun" in line for line in defaults)
    physical_primary = any(not iface.startswith("utun") for iface in primaries.values())
    tun_up = bool(utuns and (routed or any(i.startswith("utun") for i in primaries.values())))
    if if_rc or nwi_rc or not primaries:
        priority_status = "WARN"
    elif utuns and physical_primary:
        priority_status = "WARN"  # scoped/split-route VPNs require corroboration, never claim a proven leak
    else:
        priority_status = "PASS" if tun_up else "FAIL"
    checks = [check("mac_nwi_priority", "内核 IPv4 / IPv6 首选接口", priority_status,
                    " | ".join(f"{f}={i}" for f, i in primaries.items()) or "未知",
                    "utun 存在不等于默认流量已接管；scutil --nwi 需与默认/分裂路由一起复核。",
                    "high" if priority_status != "PASS" else "low")]
    checks.append(check("mac_physical_ipv6", "物理网卡公网 IPv6（脱敏）", "FAIL" if cn_v6 else ("WARN" if global_v6 else ("INFO" if if_rc else "PASS")),
                        " | ".join(global_v6) or ("未知" if if_rc else "未发现"),
                        "国内运营商公网前缀表示路由器下发了原生 IPv6；TUN 未严格接管或网卡未关闭 IPv6 时，Happy Eyeballs 与唤醒重连存在泄漏风险。",
                        "critical" if cn_v6 else "low"))
    if bridges:
        checks.append(check("mac_vm_bridge", "Cowork / 虚拟机桥接接口", "INFO", " / ".join(bridges),
                            "VM 启动失败可能记录 lam_vm_startup_failed 与 vpn_active；请保留严格路由并自行审阅 VM 兼容性。"))
    return dict(tun_up=tun_up, tun_ips=utuns, default_routes=defaults, global_v6=global_v6,
                primary_interfaces=primaries, checks=checks)


def mac_sys_proxy(run_cmd_fn, utun_up=False):
    rc, text, _ = run_cmd_fn(["/usr/sbin/scutil", "--proxy"], timeout=4)
    enabled = [key for key in ("HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable")
               if re.search(r"\b" + key + r"\s*:\s*1\b", text)]
    exceptions = re.search(r"ExceptionsList\s*:\s*<array>\s*\{(.*?)\}", text, re.S)
    tags = risk_tags(exceptions.group(1)) if exceptions else []
    status = "FAIL" if tags else ("WARN" if enabled and not utun_up else ("INFO" if rc else "PASS"))
    detail = "只读取启用状态与绕过风险类型；不读取或展示代理服务器、端口、密码、PAC/订阅地址。"
    if enabled and not utun_up:
        detail += " 当前仅开启了 macOS 系统代理但未确认 TUN 接管；浏览器/Electron 可能使用系统代理，CLI、Git、SSH、UDP STUN 及不遵循系统代理的子进程可能直接走物理网卡。"
    if tags:
        detail += " ExceptionsList 包含关键服务，可能绕过系统代理。"
    return check("mac_sys_proxy", "macOS 系统代理与 ExceptionsList", status,
                 "启用=" + ("/".join(enabled) or "无/未知") + " | 绕过风险=" + ("/".join(tags) or "未发现"),
                 detail, "critical" if tags else ("high" if status == "WARN" else "low"))


def _discover_macos_proxy_configs(home=None):
    home = _home(home)
    paths = [
        ("Stash / Hako", "Library/Group Containers/group.com.hako.network/working/active/config.yaml"),
        ("Clash Verge Rev", "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml"),
        ("Clash Verge Rev", "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/config.yaml"),
        ("FlClash", "Library/Application Support/com.follow.clash/config.yaml"),
    ]
    for label, directory, files in (
        ("Mihomo Party", "mihomo-party", ("work/config.yaml", "config.yaml")),
        ("Clash Party", "clash-party", ("work/config.yaml", "config.yaml")),
        ("Clash Nyanpasu", "clash-nyanpasu", ("clash-config.yaml", "config.yaml")),
    ):
        paths.extend((label, f"Library/Application Support/{directory}/{file}") for file in files)
    paths.extend(("ClashX / Mihomo", f".config/{name}/config.yaml") for name in ("clash", "clash.meta", "mihomo"))
    paths.extend(("Sing-box", path) for path in (".config/sing-box/config.json", "Library/Application Support/sing-box/config.json"))
    found = []
    for label, relative in paths:
        path = home / relative
        try:
            info = _state(path)
            if info and stat.S_ISREG(info.st_mode):
                found.append((label, str(path), info.st_mtime))
        except OSError:
            found.append((label, str(path), 0))  # retain unknown rather than pretend absent
    try:
        directory = home / "Library/Application Support/Surge/Profiles"
        if _state(directory):
            for path in directory.glob("*.conf"):
                info = path.stat()
                found.append(("Surge", str(path), info.st_mtime))
    except OSError:
        found.append(("Surge", str(home / "Library/Application Support/Surge/Profiles"), 0))
    return [(label, path) for label, path, _ in sorted(found, key=lambda row: row[2], reverse=True)]


def mac_audit_proxy(run_cmd_fn, home=None):
    checks = []
    found = _discover_macos_proxy_configs(home)
    checks.append(check("proxy_discovery", "代理客户端配置自动发现", "INFO", f"发现 {len(found)} 份配置",
                        "按修改时间排序；文件较新不保证正在生效。逐份核验，只输出安全字段。"))
    for index, (label, path) in enumerate(found):
        prefix = f"proxy_{index}_"
        if label == "Sing-box":
            try:
                data = read_json(path)
                inbounds = data.get("inbounds") or []
                tun = [i for i in inbounds if isinstance(i, dict) and i.get("type") == "tun"]
                strict = any(i.get("strict_route") is True and i.get("auto_route") is True for i in tun)
                checks.append(check(prefix + "tun", "Sing-box 严格路由", "PASS" if strict else "WARN",
                                    f"TUN入站={len(tun)}; strict_route+auto_route={strict}", "不读取 outbounds 节点、服务器或密钥。"))
            except (OSError, ValueError, TypeError, AttributeError):
                checks.append(check(prefix + "tun", "Sing-box 严格路由", "WARN", "未能完整读取"))
            continue
        parsed = safe_parse_surge_conf(path) if label == "Surge" else safe_parse_clash_yaml(path)
        if parsed["read_state"] != "ok":
            checks.append(check(prefix + "read", label + " 配置可读性", "WARN", "未能完整读取"))
            continue
        if label != "Surge":
            checks.append(check(prefix + "mode", label + " 模式", "FAIL" if parsed["mode"] == "direct" else ("INFO" if not parsed["mode"] else "PASS"), parsed["mode"] or "未知"))
            strict = all(parsed[k] is True for k in ("tun_enable", "tun_strict_route", "tun_auto_route"))
            native = HakoRuntime(home).tun_state() if label == "Stash / Hako" else {}
            if native.get("enabled") and native.get("packet_flow") and parsed["tun_enable"] is None:
                checks.append(check("clash_tun_cfg" if index == 0 else prefix + "tun", label + " 原生 TUN 接管", "INFO",
                                    "运行时 TUN 已启用（macOS Packet Tunnel）",
                                    "该后端由 Network Extension 配置系统路由，不使用 Mihomo 的 YAML auto-route / strict-route 字段；字段缺失不代表配置错误。断隧道保护仍需单独核验。"))
            else:
                checks.append(check("clash_tun_cfg" if index == 0 else prefix + "tun", label + " TUN 严格路由", "PASS" if strict else "WARN",
                                    f"enable={parsed['tun_enable']}; strict-route={parsed['tun_strict_route']}; auto-route={parsed['tun_auto_route']}", "仅为配置意图，实际接管需对照内核路由。", "high" if not strict else "low"))
            dns = sum((parsed[k] for k in ("dns_nameserver", "dns_default_nameserver", "dns_proxy_server_nameserver", "dns_fallback")), [])
        else:
            dns = parsed["dns"]
        bad_dns = any(value == "system" or "国内" in value for value in dns)
        checks.append(check(prefix + "dns", label + " DNS", "WARN" if bad_dns else ("PASS" if dns else "INFO"), "system/国内上游" if bad_dns else ("独立上游(地址已脱敏)" if dns else "未知")))
        for key, title in (("direct_risk_rules", "DIRECT 风险"), ("process_direct_risks", "进程直连"),
                           ("reject_risk_rules", "REJECT 副作用"), ("fakeip_risk_filters", "Fake-IP 绕过"),
                           ("skip_proxy_risks", "skip-proxy 风险"), ("always_real_ip_risks", "always-real-ip 风险")):
            hits = parsed.get(key) or []
            if hits:
                checks.append(check(prefix + key, label + " " + title, "FAIL" if key != "reject_risk_rules" else "WARN",
                                    "；".join(hits[:8]), "仅报告风险类型；不执行规则修改或流量拦截。",
                                    "critical" if key in {"direct_risk_rules", "skip_proxy_risks"} else "high"))
    return dict(title="代理客户端配置（脱敏）", checks=checks)


def mac_audit_system(target_cfg, run_cmd_fn, home=None):
    home = _home(home)
    checks = []
    prefs = {}
    try:
        with open(home / "Library/Preferences/.GlobalPreferences.plist", "rb") as handle:
            prefs = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, ValueError):
        for key in ("AppleLanguages", "AppleLocale"):
            rc, value, _ = run_cmd_fn(["/usr/bin/defaults", "read", "-g", key], timeout=3)
            if rc == 0:
                prefs[key] = [s.strip(' ",()') for s in value.splitlines() if s.strip(' ",()')] if key == "AppleLanguages" else value.strip()
    checks.append(language_check(prefs.get("AppleLanguages", []), prefs.get("AppleLocale", ""), target_cfg["code"]))
    rc, country, _ = run_cmd_fn(["/usr/bin/defaults", "read", "/Library/Preferences/.GlobalPreferences", "Country"], timeout=3)
    country = country.strip().upper() if re.fullmatch(r"\s*[A-Za-z]{2}\s*", country) else "未知"
    checks.append(check("sys_country", "系统级区域", "FAIL" if country in RESTRICTED_COUNTRIES else ("PASS" if country == target_cfg["code"] else "INFO"), country))
    tz = ""
    try:
        link = os.readlink("/etc/localtime")
        tz = link.split("/zoneinfo/")[-1] if "/zoneinfo/" in link else ""
    except OSError:
        pass
    if tz not in RESTRICTED_TZS and not re.fullmatch(r"[A-Za-z_]+(?:/[A-Za-z_+-]+){1,2}", tz):
        tz = ""
    checks.append(check("sys_timezone", "系统时区", "FAIL" if tz in RESTRICTED_TZS else ("PASS" if tz in target_cfg["timezones"] else "WARN"), tz or "未知", "时区仅为环境偏好，出口国家由网络观测判断。"))
    rc, boot, _ = run_cmd_fn(["/usr/sbin/sysctl", "-n", "kern.boottime"], timeout=3)
    match = re.search(r"sec\s*=\s*(\d+)", boot)
    try:
        stale = bool(match and os.lstat("/etc/localtime").st_mtime > int(match.group(1)))
    except OSError:
        stale = False
    checks.append(check("timezone_reboot", "时区缓存刷新", "WARN" if stale else ("PASS" if match else "INFO"), "时区修改晚于本次启动" if stale else ("未发现启动后变更" if match else "未知"), "常驻客户端可能缓存旧时区；仅报告状态。"))
    for cid, title, args, pattern in (
        ("auto_timezone", "自动时区", ["/usr/bin/defaults", "read", "/Library/Preferences/com.apple.timezone.auto", "Active"], r"^(1|true|YES)$"),
        ("input_method", "当前输入法", ["/usr/bin/defaults", "read", "com.apple.HIToolbox", "AppleSelectedInputSources"], r"SCIM|Pinyin|Sogou|Rime"),
        ("location_services", "定位服务状态", ["/usr/bin/defaults", "read", "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd", "LocationServicesEnabled"], r"^1$"),
    ):
        rc, text, _ = run_cmd_fn(args, timeout=3)
        found = bool(re.search(pattern, text.strip(), re.I))
        checks.append(check(cid, title, "INFO" if rc or cid == "input_method" else ("WARN" if found else "PASS"), "未知/受权限限制" if rc else ("已启用/含相关特征" if found else "未发现相关特征"),
                            "输入法为本地偏好，不能据此认定 IP 或定位泄漏。" if cid == "input_method" else "仅报告状态，请在系统设置内自行核对。"))
    host_bad, host_known = 0, 0
    for key in ("ComputerName", "LocalHostName", "HostName"):
        rc, value, _ = run_cmd_fn(["/usr/sbin/scutil", "--get", key], timeout=3)
        if rc == 0 and value.strip():
            host_known += 1
            host_bad += bool(any(ord(c) > 127 for c in value) or re.search("deimac|demac|diannao|zh-cn", value, re.I))
    checks.append(check("hostnames", "主机名语言特征（不展示原文）", "WARN" if host_bad else ("PASS" if host_known else "INFO"), f"可读 {host_known} 项；相关特征 {host_bad} 项", "不展示设备名或个人名称。"))
    rc, wifi, _ = run_cmd_fn(["/usr/sbin/system_profiler", "SPAirPortDataType"], timeout=6)
    countries = re.findall(r"Country Code:\s*([A-Z0-9]{2})\b", wifi)
    bad_wifi = any(c in RESTRICTED_COUNTRIES for c in countries)
    checks.append(check("wifi_cc", "Wi-Fi 无线国家码", "WARN" if bad_wifi else "INFO", "/".join(sorted(set(countries))) or "未知", "802.11d 国家码仅作本地参考，不读取或输出 SSID/BSSID。"))
    flags = [key for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy") if os.environ.get(key)]
    checks.append(check("shell_proxy_env", "终端代理环境", "WARN" if flags else "INFO", f"存在 {len(flags)} 个代理环境变量；值未读取/展示", "网络探测使用移除代理变量且禁用 curlrc 的环境，以核验真实路由。"))
    try:
        tags = []
        with open("/etc/hosts", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                fields = line.split("#", 1)[0].split()
                if len(fields) > 1:
                    for domain in fields[1:]:
                        if risk_root(domain):
                            tags.extend(risk_tags(domain))
        checks.append(check("hosts_overrides", "hosts 关键域名覆盖", "WARN" if tags else "PASS", "/".join(sorted(set(tags))) or "未发现", "只读检查；不会修改 hosts 或创建拦截规则。"))
    except OSError:
        checks.append(check("hosts_overrides", "hosts 关键域名覆盖", "INFO", "未知"))
    rc, power, _ = run_cmd_fn(["/usr/bin/pmset", "-g", "custom"], timeout=3)
    power_risk = bool(re.search(r"(?:powernap|tcpkeepalive|womp)\s+1\b", power))
    checks.append(check("power_wake", "Power Nap / 网络唤醒", "INFO" if rc else ("WARN" if power_risk else "PASS"), "未知" if rc else ("网络唤醒相关功能开启" if power_risk else "未发现开启项"), "唤醒补测只观察连接变化，不修改电源策略。"))
    checks.append(check_ipv6_disabled(run_cmd_fn))
    tun = mac_check_tun_details(run_cmd_fn)
    checks.extend(tun["checks"])
    checks.append(mac_sys_proxy(run_cmd_fn, tun["tun_up"]))
    startup_count, startup_unknown = 0, False
    for directory in (home / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")):
        try:
            if _state(directory):
                startup_count += sum(1 for entry in directory.iterdir() if entry.suffix == ".plist" and any(word in entry.name.lower() for word in ("claude", "anthropic")))
        except OSError:
            startup_unknown = True
    try:
        cfg = read_json(home / "Library/Application Support/Claude/config.json")
        startup_count += cfg.get("openAtLogin") is True
    except FileNotFoundError:
        pass
    except (OSError, ValueError, AttributeError):
        startup_unknown = True
    checks.append(check("boot_leak", "Claude 自启与代理启动顺序", "WARN" if startup_count else "INFO", f"已知自启项 {startup_count} 个" + ("；部分不可读" if startup_unknown else ""), "同时核查用户/系统 LaunchAgents 与 LaunchDaemons。Ventura+ 请自行检查 System Settings → General → Login Items & Extensions；此处不写入 plist。"))
    try:
        git = home / ".gitconfig"
        # Do not load identities or credentials: existence-only, user inspects in their own UI.
        has_git = _state(git) is not None
        checks.append(check("git_identity_leak", "Git 全局身份配置", "INFO", "存在；不读取身份/凭据" if has_git else "未发现", "可自行检查 Git 身份是否符合预期。"))
    except OSError:
        checks.append(check("git_identity_leak", "Git 全局身份配置", "INFO", "未知"))
    telemetry = [key for key in ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "DISABLE_TELEMETRY", "DO_NOT_TRACK") if os.environ.get(key, "").lower() in {"1", "true", "yes"}]
    checks.append(check("claude_telemetry_privacy", "遥测偏好环境标记", "INFO", f"已启用 {len(telemetry)} 项", "仅记录状态，不拦截遥测；具体行为取决于客户端版本。"))
    checks.append(check("hardware_awareness", "硬件标识只读边界", "INFO", platform.machine(), "不查询硬件 UUID、序列号或 Secure Enclave 公钥；仅检查本地绑定状态。"))
    checks.extend(_extra_system_checks(run_cmd_fn, home))
    return dict(title="macOS 系统环境与路由", checks=checks)


def _scan_webkit(roots):
    result = dict(domains=set(), itp_domains=set(), denied=False, errors=False, limited=False, inspected=0)
    def onerror(exc):
        if _is_permission(exc):
            result["denied"] = True
        else:
            result["errors"] = True
    for root in roots:
        root = Path(root)
        try:
            if not _state(root):
                continue
            for directory, dirs, files in os.walk(root, onerror=onerror, followlinks=False):
                dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
                result["inspected"] += len(files)
                if result["inspected"] > 20000:
                    result["limited"] = True
                    break
                if "origin" in files:
                    try:
                        with open(Path(directory) / "origin", "rb") as handle:
                            data = handle.read(4096).decode("latin-1", errors="ignore")
                        # Only allowed public families leave the scan, never origin paths/IDs.
                        for candidate in re.findall(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", data):
                            family = risk_root(candidate)
                            if family:
                                result["domains"].add(family)
                    except OSError as exc:
                        onerror(exc)
                if "observations.db" in files:
                    state, rows = _safe_sqlite_query(Path(directory) / "observations.db", "SELECT DISTINCT registrableDomain FROM ObservedDomains")
                    if state == "denied":
                        result["denied"] = True
                    elif state != "ok":
                        result["errors"] = True
                    result["itp_domains"].update(risk_root(row[0]) for row in rows if row and risk_root(row[0]))
        except OSError as exc:
            onerror(exc)
    result["domains"] = sorted(result["domains"])
    result["itp_domains"] = sorted(result["itp_domains"])
    return result


def scan_safari(home=None):
    home = _home(home)
    base = home / "Library/Containers/com.apple.Safari/Data/Library/WebKit/WebsiteData"
    result = _scan_webkit([base, home / "Library/WebKit/com.apple.Safari/WebsiteData"])
    result["website_data_domains"] = result["domains"]
    result["history_domains"] = {}
    result["favicon_domains"] = {}
    for key, relative, table in (
        ("history_domains", "Library/Safari/History.db", "history_items"),
        ("favicon_domains", "Library/Safari/Favicon Cache/favicons.db", "page_url"),
    ):
        # Extract host inside SQLite: full history URLs (potential OAuth queries) never enter Python.
        sql = ("SELECT DISTINCT substr(substr(url,instr(url,'://')+3),1,"
               "instr(substr(url,instr(url,'://')+3)||'/','/')-1) FROM " + table)
        state, rows = _safe_sqlite_query(home / relative, sql)
        if state == "denied":
            result["denied"] = True
        elif state not in {"missing", "ok"}:
            result["errors"] = True
        for row in rows:
            domain = risk_root(str(row[0]).split(":")[0])
            if domain:
                result[key][domain] = result[key].get(domain, 0) + 1
    history_only = bool(result["itp_domains"] or result["history_domains"] or result["favicon_domains"])
    result["status"] = "WARN" if result["domains"] else ("INFO" if history_only or result["denied"] or result["errors"] or result["limited"] else "PASS")
    result["observed"] = TCC_DETAIL.split("。", 1)[0] if result["denied"] else f"站点残留={len(result['domains'])}; ITP={len(result['itp_domains'])}; 历史域={len(result['history_domains'])}"
    result["detail"] = TCC_DETAIL if result["denied"] else ("部分数据不可读/扫描受限，未检出不代表无残留。" if result["errors"] or result["limited"] else "覆盖 Default 与 Custom/* 全部 Profile；只查询域名元数据，不读取 Cookie 值。")
    if history_only and not result["domains"]:
        result["detail"] += " ITP/历史/图标记录不等于仍保存登录凭据，也不能据此判定账号关联。"
    return result


def _children(path):
    if _state(path) is None:
        return []
    return [child for child in path.iterdir() if child.is_dir() and not child.is_symlink()]


def _browser_result(cid, name, hits, domestic=False, proxy=0, language=False, unknown=False):
    status = "FAIL" if domestic else ("WARN" if hits or proxy or language else ("INFO" if unknown else "PASS"))
    return check(cid, name + " 浏览器配置与站点状态", status,
                 f"关键站点类型={len(hits)}; 国内DoH={domestic}; 代理扩展={proxy}; 简中偏好={language}" + ("; 部分不可读/受限" if unknown else ""),
                 "只检查主机列、站点目录、语言与扩展权限；不读取密码、Cookie 值、账户标识或浏览历史路径。" +
                 (" 代理扩展可能造成系统代理与浏览器分叉。" if proxy else ""), "high" if domestic else "low")


def scan_chromium(name, root):
    root = Path(root)
    hits, domestic, extensions, language, unknown = set(), False, 0, False, False
    try:
        data = read_json(root / "Local State")
        doh = data.get("dns_over_https") or {}
        domestic = cn_dns(doh.get("templates") or "")
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, AttributeError):
        unknown = True
    try:
        profiles = [p for p in _children(root) if p.name == "Default" or p.name.startswith("Profile ")]
        # Arc installations may store User Data and Chromium profiles under User Data.
        if not profiles and _state(root / "User Data"):
            return scan_chromium(name, root / "User Data")
        for profile in profiles:
            try:
                data = read_json(profile / "Preferences")
                language |= simplified((data.get("intl") or {}).get("accept_languages", "").split(",")[0])
            except FileNotFoundError:
                pass
            except (OSError, ValueError, AttributeError, TypeError):
                unknown = True
            for cookie in (profile / "Cookies", profile / "Network/Cookies"):
                state, rows = _safe_sqlite_query(cookie, "SELECT DISTINCT host_key FROM cookies")
                unknown |= state not in {"ok", "missing"}
                hits.update(risk_root(row[0]) for row in rows if risk_root(row[0]))
            # Chrome DIPS schema versions differ; inspect schema metadata, then project site columns only.
            dips = profile / "DIPS"
            state, tables = _safe_sqlite_query(dips, "SELECT name FROM sqlite_master WHERE type='table'")
            unknown |= state not in {"ok", "missing"}
            for (table,) in tables:
                if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", table):
                    continue
                state, columns = _safe_sqlite_query(dips, 'PRAGMA table_info("' + table + '")')
                for column in (row[1] for row in columns if row[1] in {"site", "host", "top_level_site", "registrable_domain"}):
                    state, rows = _safe_sqlite_query(dips, f'SELECT DISTINCT "{column}" FROM "{table}"')
                    unknown |= state != "ok"
                    hits.update(risk_root(row[0]) for row in rows if risk_root(row[0]))
            for entry in _children(profile / "IndexedDB"):
                # Do not expose the profile or IndexedDB directory name (may contain user IDs).
                hits.update(risk_tags(entry.name))
            for extension in _children(profile / "Extensions"):
                proxy_extension = False
                for version in _children(extension):
                    try:
                        manifest = read_json(version / "manifest.json")
                        permissions = (manifest.get("permissions") or []) + (manifest.get("optional_permissions") or [])
                        proxy_extension |= "proxy" in permissions
                    except FileNotFoundError:
                        pass
                    except (OSError, ValueError, AttributeError, TypeError):
                        unknown = True
                extensions += proxy_extension
    except OSError:
        unknown = True
    return _browser_result("browser_" + re.sub(r"\W", "_", name.lower()), name, hits, domestic, extensions, language, unknown)


def scan_firefox(name, root):
    hits, domestic, language, unknown = set(), False, False, False
    modes = set()
    try:
        profiles = _children(Path(root) / "Profiles")
        if not profiles:
            profiles = _children(Path(root))  # Zen also uses .zen/<profile>
        for profile in profiles:
            state, rows = _safe_sqlite_query(profile / "cookies.sqlite", "SELECT DISTINCT host FROM moz_cookies")
            unknown |= state not in {"ok", "missing"}
            hits.update(risk_root(row[0]) for row in rows if risk_root(row[0]))
            for entry in _children(profile / "storage/default"):
                hits.update(risk_tags(entry.name))
            try:
                with open(profile / "prefs.js", encoding="utf-8", errors="replace") as handle:
                    size = 0
                    for line in handle:
                        size += len(line)
                        if size > 4 * 1024 * 1024:
                            unknown = True
                            break
                        match = re.match(r'user_pref\("(network\.trr\.(?:mode|uri)|intl\.accept_languages)",\s*(.*?)\);', line)
                        if not match:
                            continue
                        key, value = match.groups()
                        if key == "network.trr.uri":
                            domestic |= cn_dns(value)
                        elif key == "network.trr.mode" and value in {"0", "1", "2", "3", "4", "5"}:
                            modes.add(value)
                        elif key == "intl.accept_languages":
                            language |= simplified(value.strip('"').split(",")[0])
            except FileNotFoundError:
                pass
            except OSError:
                unknown = True
    except OSError:
        unknown = True
    result = _browser_result("browser_" + name.lower(), name, hits, domestic, language=language, unknown=unknown)
    result["observed"] += "; TRR模式=" + ("/".join(sorted(modes)) or "默认/未知")
    return result


def inspect_device_registry(path):
    """Reduce bindings to counts and pk1/pku1 state; never return keys or fingerprints."""
    result = dict(exists=False, entries=0, bound=False, pending=False, readable=True)
    try:
        obj = read_json(path)
        result["exists"] = True
        def visit(item):
            if isinstance(item, dict):
                for key, value in item.items():
                    if isinstance(key, str):
                        result["bound"] |= key.startswith("pk1:")
                        result["pending"] |= key.startswith("pku1:")
                    visit(value)
            elif isinstance(item, list):
                for value in item:
                    visit(value)
            elif isinstance(item, str):
                result["bound"] |= item.startswith("pk1:")
                result["pending"] |= item.startswith("pku1:")
        visit(obj)
        accounts = obj.get("accounts", obj) if isinstance(obj, dict) else obj
        result["entries"] = len(accounts) if isinstance(accounts, (dict, list)) else 0
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, RecursionError):
        result.update(exists=True, readable=False)
    return result


def mac_audit_claude_browser_residue(run_cmd_fn, home=None, app_paths=None):
    home = _home(home)
    checks, inventory = [], []
    cdir = home / "Library/Application Support/Claude"
    def inv(name, path, purpose, observed, status="WARN", module="Claude Desktop"):
        # Paths are fixed templates only, never user profile names or discovered filenames.
        inventory.append(dict(module=module, name=name, path=path, purpose=purpose, observed=observed, status=status))
    versions, version_error = [], False
    for app in (app_paths if app_paths is not None else (Path("/Applications/Claude.app"), home / "Applications/Claude.app")):
        try:
            with open(Path(app) / "Contents/Info.plist", "rb") as handle:
                version = str(plistlib.load(handle).get("CFBundleShortVersionString", ""))
            if re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,4}", version):
                versions.append(version)
        except FileNotFoundError:
            pass
        except (OSError, ValueError, plistlib.InvalidFileException):
            version_error = True
    _, processes, _ = run_cmd_fn(["/bin/ps", "-axo", "pid,arch,comm"], timeout=4)
    # sysctl confirms physical ARM even when this Python itself runs under Rosetta.
    _, arm, _ = run_cmd_fn(["/usr/sbin/sysctl", "-n", "hw.optional.arm64"], timeout=3)
    translated = (arm.strip() == "1" or platform.machine() == "arm64") and any(
        re.search(r"\bx86_64\b", line) and re.search(r"(?:/|\s)Claude(?: Helper[^/]*)?(?:$|\.app/)", line)
        for line in processes.splitlines())
    checks.append(check("claude_version", "Claude 版本与 Rosetta", "WARN" if translated else "INFO",
                        f"版本={','.join(versions) or '未发现/未知'}; Rosetta={'检测到' if translated else '未检测到'}" + ("; 部分不可读" if version_error else ""),
                        "仅只读 Info.plist 与进程架构；running_under_translation 可能作为环境字段记录。"))
    registry = inspect_device_registry(cdir / "ant-device-registry.json")
    observed = (f"条目={registry['entries']}; 已绑定={registry['bound']}; 待确认={registry['pending']}" if registry["readable"] else "不可读；未知") if registry["exists"] else "未发现"
    status = "WARN" if registry["exists"] else "PASS"
    inv("ant-device-registry.json 硬件设备绑定缓存", "~/Library/Application Support/Claude/ant-device-registry.json", "仅统计账号条目及 pk1/pku1 状态，不输出 UUID/哈希", observed, status)
    checks.append(check("claude_device_registry", "硬件设备绑定状态", status, observed))
    for name, purpose in (("ant-did", "安装标识存在性"), ("ant-device-key-generation.json", "密钥轮换代数状态记录"),
                          ("ant-device-key-read.json", "硬件密钥读取异常记录"), ("bridge-state.json", "桥接配对状态")):
        try:
            exists = _state(cdir / name) is not None
            observed, status = ("存在；不读取标识原文", "WARN" if name == "ant-device-key-read.json" else "INFO") if exists else ("未发现", "PASS")
        except OSError:
            observed, status = "受权限限制；未知", "INFO"
        inv(name, "~/Library/Application Support/Claude/" + name, purpose, observed, status)
        checks.append(check("claude_" + name.replace(".", "_"), purpose, status, observed,
                            "正常安装/配对元数据的存在不表示网络泄漏或账号异常。" if status == "INFO" else ""))
    telemetry = inspect_telemetry(str(cdir))
    for prefix, name, file in (("sentry", "Sentry 文化状态与离线队列", "sentry"), ("fcache", "GrowthBook CLF 组织绑定缓存", "fcache")):
        status, notes = telemetry[prefix + "_status"], telemetry[prefix + "_notes"]
        observed = "；".join(notes) or "未发现"
        checks.append(check("claude_" + prefix, name, status, observed, severity="critical" if prefix == "sentry" and telemetry["sentry_critical"] else None))
        inv(name, "~/Library/Application Support/Claude/" + file, "仅统计存在性与状态类型", observed, status)
    counts = {key: 0 for key in ("region", "banned", "evicted", "telemetry", "device", "stripe", "network")}
    log_count, log_unknown = 0, False
    logdir = home / "Library/Logs/Claude"
    try:
        if _state(logdir):
            for path in logdir.glob("*.log"):
                if path.is_file() and not path.is_symlink():
                    log_count += 1
                    try:
                        values = count_log_tail(path)
                        for key in counts:
                            counts[key] += values[key]
                    except OSError:
                        log_unknown = True
    except OSError:
        log_unknown = True
    status = "FAIL" if any(counts[key] for key in ("region", "banned", "evicted")) else ("WARN" if any(counts.values()) or log_unknown else "INFO")
    observed = f"日志={log_count}; " + "; ".join(f"{key}={value}" for key, value in counts.items()) + ("; 部分不可读" if log_unknown else "")
    checks.append(check("claude_logs", "Claude v6 日志特征计数", status, observed, "每文件最多尾部 4MB；逐行互斥计数，不展示日志正文。"))
    inv("运行日志", "~/Library/Logs/Claude/*.log", "地区、遥测丢失与设备密钥异常统计", observed, status)
    # Known third-party paths: existence only, no credential databases or broad TCC enumeration.
    for name in ("Cookies", "Network/Cookies", "Local Storage", "IndexedDB", "DIPS", "Cache", "config.json", "claude_desktop_config.json"):
        try:
            present = _state(cdir / name) is not None
            observed, status = ("存在；只检查元数据", "INFO") if present else ("未发现", "PASS")
        except OSError:
            observed, status = "不可读；未知", "INFO"
        inv(name, "~/Library/Application Support/Claude/" + name, "本地状态存在性；不读取凭据/存储值", observed, status)
    wildcard_count, wildcard_unknown = 0, False
    for relative in ("Application Support", "Caches", "Preferences", "Logs", "HTTPStorages", "Saved Application State", "WebKit", "LaunchAgents"):
        directory = home / "Library" / relative
        try:
            if _state(directory):
                wildcard_count += sum(1 for entry in directory.iterdir() if re.search(r"claude|anthropic", entry.name, re.I))
        except OSError:
            wildcard_unknown = True
    checks.append(check("claude_system_paths", "Claude 系统路径与 CLI 状态", "INFO", f"可枚举目录中匹配 {wildcard_count} 项" + ("; 部分不可读" if wildcard_unknown else ""), "正常应用路径的存在不表示异常。不枚举 Containers、Group Containers 或废纸篓；不读取钥匙串、.credentials.json、.claude.json 内容。"))
    for name in (".claude", ".claude.json"):
        try:
            present = _state(home / name) is not None
            inv("Claude Code " + name, "~/" + name, "只检查路径存在性，不读取 Token 或账号", "存在" if present else "未发现", "INFO" if present else "PASS", "Claude Code")
        except OSError:
            inv("Claude Code " + name, "~/" + name, "只检查路径存在性", "未知", "INFO", "Claude Code")
    safari = scan_safari(home)
    checks.append(check("safari_residue", "Safari 全 Profile 与 ITP / 历史域名", safari["status"], safari["observed"], safari["detail"]))
    inv("Safari Default / Custom Profiles", "~/Library/Containers/com.apple.Safari/.../WebsiteData/{Default,Custom/*}", "所有配置档的 origin / ITP 域名", safari["observed"], safari["status"], "Safari & 浏览器")
    for name, relative in (
        ("Chrome", "Google/Chrome"), ("Canary", "Google/Chrome Canary"), ("Arc", "Arc"),
        ("Brave", "BraveSoftware/Brave-Browser"), ("Edge", "Microsoft Edge"),
        ("Vivaldi", "Vivaldi"), ("Chromium", "Chromium"),
    ):
        path = home / "Library/Application Support" / relative
        try:
            if _state(path):
                checks.append(scan_chromium(name, path))
        except OSError:
            checks.append(_browser_result("browser_" + name.lower(), name, set(), unknown=True))
    for name, relative in (("Firefox", "Library/Application Support/Firefox"), ("Zen", "Library/Application Support/zen"), ("Zen", ".zen")):
        try:
            path = home / relative
            if _state(path):
                checks.append(scan_firefox(name, path))
        except OSError:
            checks.append(_browser_result("browser_" + name.lower(), name, set(), unknown=True))
    orion = home / "Library/Application Support/Orion/Defaults/WebsiteData"
    try:
        if _state(orion):
            result = _scan_webkit([orion])
            checks.append(_browser_result("browser_orion", "Orion", set(result["domains"] + result["itp_domains"]), unknown=result["errors"] or result["denied"] or result["limited"]))
    except OSError:
        checks.append(_browser_result("browser_orion", "Orion", set(), unknown=True))
    return dict(title="Claude v6 与全浏览器只读审计", checks=checks, inventory=inventory)


def _extra_system_checks(run_cmd_fn, home):
    """Retain legacy environment observations, projecting only state categories."""
    checks = []
    rc, languages, _ = run_cmd_fn(['/usr/bin/defaults', 'read', '-g', 'NSLinguisticDataAssetsRequested'], timeout=3)
    has_cn = bool(re.search(r'zh[-_]?(?:Hans|CN)', languages, re.I))
    checks.append(check('linguistic_assets', '语言资源偏好', 'INFO',
                        '未知' if rc else ('存在简中语言资源偏好' if has_cn else '未发现简中特征'), '仅为本地资源偏好，不等同于网络泄漏。'))
    rc, dns, _ = run_cmd_fn(['/usr/sbin/scutil', '--dns'], timeout=4)
    domestic, private, total = 0, 0, 0
    for line in dns.splitlines():
        match = re.search(r'nameserver\[\d+\]\s*:\s*([0-9a-fA-F:.]+)', line)
        if match:
            try:
                address = ipaddress.ip_address(match.group(1))
                private += address.is_private
                domestic += cn_dns(str(address))
                total += 1
            except ValueError:
                pass
    checks.append(check('mac_dns_state', '系统解析器上游（脱敏）', 'INFO' if rc or not total else ('WARN' if domestic else 'PASS'),
                        f'解析器地址={total}; 国内公共DNS={domestic}; 私网DNS={private}', '私网解析器与物理网卡并存需结合 TUN 路由复核；不展示解析器地址。'))
    rc, trust, _ = run_cmd_fn(['/usr/bin/security', 'dump-trust-settings'], timeout=4)
    mitm = any(word in trust.lower() for word in ('charles', 'fiddler', 'mitmproxy', 'proxyman', 'burp'))
    checks.append(check('custom_root_trust', '自定义证书信任状态', 'WARN' if mitm else 'INFO',
                        '检测到调试代理证书信任特征' if mitm else ('不可读取/未配置' if rc else '未发现已知调试代理特征'),
                        '证书存在不证明当前正在解密流量；不读取私钥、不安装证书、不修改信任设置。'))
    ntp_count, domestic_ntp, ntp_unknown = 0, 0, False
    try:
        with open('/etc/ntp.conf', encoding='utf-8', errors='replace') as handle:
            for line in handle:
                fields = line.split('#', 1)[0].split()
                if len(fields) >= 2 and fields[0] in {'server', 'pool'}:
                    ntp_count += 1
                    domestic_ntp += any(word in fields[1].lower() for word in ('aliyun', 'tencent', 'ntsc.ac.cn', 'cn.pool.ntp.org'))
    except FileNotFoundError:
        pass
    except OSError:
        ntp_unknown = True
    checks.append(check('ntp_config', '系统 NTP 上游配置', 'WARN' if domestic_ntp else 'INFO',
                        f'配置项={ntp_count}; 国内上游特征={domestic_ntp}' + ('; 不可读取' if ntp_unknown else ''), '不更改时间服务或时钟。'))
    launch_bad, launch_proxies, launch_unknown = 0, 0, False
    for key in ('TZ', 'LANG', 'LC_ALL', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
        rc, text, _ = run_cmd_fn(['/bin/launchctl', 'getenv', key], timeout=2)
        if rc:
            launch_unknown = True
        elif text.strip():
            if key.endswith('PROXY'):
                launch_proxies += 1  # never use/output the address value
            else:
                launch_bad += 'zh' in text.lower() or text.strip() in RESTRICTED_TZS
    checks.append(check('launchd_environment', 'GUI 启动环境与终端分叉', 'WARN' if launch_bad or launch_proxies else 'INFO',
                        f'受限语言/时区标记={launch_bad}; 代理变量={launch_proxies}' + ('; 部分未知' if launch_unknown else ''),
                        '仅统计状态；不回显环境变量原文，也不设置 launchd 环境。'))
    installed = 0
    for app in ('AnyDesk.app', 'TeamViewer.app', 'ToDesk.app', 'SunloginClient.app'):
        try:
            installed += _state(Path('/Applications') / app) is not None
        except OSError:
            pass
    checks.append(check('remote_apps_awareness', '远程协助软件参考', 'INFO', f'已知远程协助应用路径={installed}',
                        '仅检查固定应用路径存在性，不枚举或修改应用内容。'))
    relay_markers = sum(bool(os.environ.get(key)) for key in ('ANTHROPIC_BASE_URL', 'CLAUDE_CODE_API_KEY_HELPER'))
    checks.append(check('cli_endpoint_override', 'Claude Code 自定义端点标记', 'WARN' if relay_markers else 'INFO',
                        f'覆盖标记={relay_markers}; 值不读取/展示', '不打开可能包含 API Key/OAuth Token 的 CLI 凭据文件；请自行审阅端点来源。'))
    return checks

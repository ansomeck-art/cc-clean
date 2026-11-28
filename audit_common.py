"""Small cross-platform audit primitives; results never contain raw log lines."""
import os

MAX_LOG_BYTES = 4 * 1024 * 1024
LOG_MARKERS = (
    ("region", ("region_blocked", "isn't available in your region", "app-unavailable-in-region")),
    ("banned", ("account_banned", "bad_device_id")),
    ("evicted", ("Claude-Login-Ended-By", "login_limit_reached")),
    ("telemetry", ("[EventLogging] Batch flush FAILED", "desktop_telemetry_upload_lost", "[EventLogging] POST threw")),
    ("device", ("[device-registry]",)),
    ("stripe", ("Failed to load Stripe.js",)),
    ("network", ("ERR_NETWORK_CHANGED",)),
)


def count_log_tail(path):
    """Bound I/O and count at most one category per line (including repeated markers)."""
    counts = {key: 0 for key, _ in LOG_MARKERS}
    with open(path, "rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        offset = max(0, size - MAX_LOG_BYTES)
        handle.seek(offset)
        raw = handle.read(MAX_LOG_BYTES)
    if offset:
        raw = raw.partition(b"\n")[2]  # avoid counting a partial first line
    for line in raw.decode("utf-8", errors="replace").splitlines():
        for category, markers in LOG_MARKERS:
            if any(marker in line for marker in markers):
                counts[category] += 1
                break
    return counts

# Only public domain families and executable names can leave parsers.
import json
import re
import zlib

RISK_ROOTS = ("claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com",
              "claudemcpcontent.com", "hcaptcha.com", "stripe.com", "stripe.network",
              "cloudflare.com", "statsig.com", "sentry.io", "datadoghq.com",
              "browser-intake-us5-datadoghq.com")
RISK_WORDS = ("claude", "anthropic", "stripe", "hcaptcha", "cloudflare", "statsig", "sentry", "datadog")
PROCESS_NAMES = {"anthropic", "anthropic.exe", "cowork-svc", "cowork-svc.exe", "claude", "claude.exe", "cowork", "cowork.exe", "node", "node.exe",
                 "ssh", "ssh.exe", "git", "git.exe", "curl", "curl.exe"}
CN_DNS = {"114.114.114.114", "114.114.115.115", "223.5.5.5", "223.6.6.6", "119.29.29.29",
          "182.254.116.116", "180.76.76.76", "1.2.4.8", "2400:3200::1", "240c::6666"}
CN_DOH = ("alidns.com", "doh.pub", "dns.pub", "doh.360.cn", "dns.360.cn", "dns.alidns.com")
RESTRICTED_TZS = {"Asia/Shanghai", "Asia/Chongqing", "Asia/Harbin", "Asia/Urumqi", "Asia/Kashgar",
                  "Asia/Hong_Kong", "Asia/Macau", "PRC", "Hongkong"}


def check(cid, title, status, observed, detail="", severity=None):
    return dict(id=cid, title=title, status=status, observed=observed, detail=detail,
                severity=severity or ("high" if status == "FAIL" else "low"), fix_advice="", fix_cmd="")


def risk_root(host):
    host = str(host or "").lower().strip(".* ")
    return next((root for root in RISK_ROOTS if host == root or host.endswith("." + root)), "")


def risk_tags(text):
    return [word for word in RISK_WORDS if word in str(text).lower()]


def cn_dns(text):
    value = str(text).lower()
    return any(key in value for key in CN_DOH) or any(ip in value for ip in CN_DNS)


def read_json(path, limit=4 * 1024 * 1024):
    with open(path, "rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("metadata limit")
    return json.loads(raw)


def safe_locale(value):
    value = str(value or "").split(".")[0].replace("_", "-")
    return value if re.fullmatch(r"[a-zA-Z]{2,3}(?:-[a-zA-Z0-9]{2,8}){0,3}", value) else "未知"


def simplified(value):
    value = safe_locale(value).lower()
    return value.startswith(("zh-hans", "zh-cn")) or value.endswith("-cn")


def _dns_class(value):
    low = value.lower().strip(' \"\'')
    if low == "system":
        return "system"
    if cn_dns(low):
        return "alidns/国内DNS"  # keep the Windows parser's domestic classification compatible
    return "自定义DNS(地址已脱敏)"


def _rule_metadata(value, result):
    parts = [p.strip().strip('"\'') for p in value.split(",")]
    if len(parts) < 3:
        return
    kind, subject = parts[0].upper(), parts[1]
    policy = parts[2].upper()
    if kind in {"PROCESS-NAME", "PROCESS-PATH"}:
        name = os.path.basename(subject.replace("\\", "/")).lower()
        if name in PROCESS_NAMES and policy == "DIRECT":
            result["process_direct_risks"].append("PROCESS-NAME," + name + ",DIRECT")
        return  # never fall through to substring matching for executables
    tags = risk_tags(subject)
    if tags and policy in {"DIRECT", "REJECT", "REJECT-DROP"}:
        key = "direct_risk_rules" if policy == "DIRECT" else "reject_risk_rules"
        result[key].append("/".join(tags) + "," + policy)


def safe_parse_clash_yaml(path):
    result = dict(exists=False, read_state="missing", mode="", ipv6=None, dns_enable=None,
                  dns_enhanced_mode="", dns_nameserver=[], dns_default_nameserver=[],
                  dns_proxy_server_nameserver=[], dns_fallback=[], tun_enable=None, tun_stack="",
                  tun_strict_route=None, tun_auto_route=None, tun_auto_detect_interface=None,
                  fakeip_risk_filters=[], direct_risk_rules=[], process_direct_risks=[],
                  reject_risk_rules=[], proxy_groups=[], direct_listeners=[], prepend_direct_count=0)
    section, subsection = "", ""
    dns_keys = {"nameserver": "dns_nameserver", "default-nameserver": "dns_default_nameserver",
                "proxy-server-nameserver": "dns_proxy_server_nameserver", "fallback": "dns_fallback"}
    def field(key, value):
        nonlocal subsection
        value = value.strip().strip('"\'')
        lower = value.lower()
        if section == "dns":
            subsection = key if key in {*dns_keys, "fake-ip-filter"} else ""
            if key == "enable" and lower in {"true", "false"}:
                result["dns_enable"] = lower == "true"
            elif key == "enhanced-mode" and lower in {"fake-ip", "redir-host", "normal"}:
                result["dns_enhanced_mode"] = lower
            elif subsection and value.startswith("["):
                for item in value.strip("[]").split(","):
                    dns_item(item)
        elif section == "tun":
            mapping = {"enable": "tun_enable", "strict-route": "tun_strict_route", "auto-route": "tun_auto_route",
                       "auto-detect-interface": "tun_auto_detect_interface"}
            if key in mapping and lower in {"true", "false"}:
                result[mapping[key]] = lower == "true"
            elif key == "stack" and lower in {"system", "gvisor", "mixed", "lwip"}:
                result["tun_stack"] = lower
    def dns_item(value):
        if subsection == "fake-ip-filter":
            tags = risk_tags(value)
            if tags:
                result["fakeip_risk_filters"].append("/".join(tags))
        elif subsection in dns_keys:
            result[dns_keys[subsection]].append(_dns_class(value))
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            result.update(exists=True, read_state="ok")
            consumed = 0
            for line in handle:
                consumed += len(line)
                if consumed > 4 * 1024 * 1024:
                    result["read_state"] = "limited"
                    break
                # Secret/node/provider sections are never parsed or retained.
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not line[0].isspace() and ":" in stripped and not stripped.startswith("-"):
                    key, value = stripped.split(":", 1)
                    section, subsection = key, ""
                    lower = value.strip().strip('"\'').lower()
                    if key == "mode" and lower in {"global", "rule", "direct"}:
                        result["mode"] = lower
                    elif key == "ipv6" and lower in {"true", "false"}:
                        result["ipv6"] = lower == "true"
                    elif key in {"tun", "dns"} and lower.startswith("{"):
                        for pair in lower.strip("{}").split(","):
                            if ":" in pair:
                                k, v = pair.split(":", 1)
                                field(k.strip(), v)
                    continue
                if section in {"dns", "tun"}:
                    if stripped.startswith("-") and section == "dns":
                        dns_item(stripped[1:].strip())
                    elif ":" in stripped:
                        key, value = stripped.split(":", 1)
                        field(key.strip(), value)
                elif section in {"rules", "x-clash-every-mode-rules"} and stripped.startswith("-"):
                    _rule_metadata(stripped[1:].strip().strip('"\''), result)
                elif section == "proxy-groups" and re.match(r"(?:-\s*)?name:", stripped):
                    result["proxy_groups"].append("代理组(已脱敏)")
                elif section == "listeners" and re.match(r"proxy:\s*DIRECT\b", stripped, re.I):
                    result["direct_listeners"].append({"proxy": "DIRECT"})
                elif section == "x-clash-rule-index" and stripped.startswith("- ") and ",DIRECT" in stripped.upper():
                    result["prepend_direct_count"] += 1
                    _rule_metadata(stripped[1:].strip().strip('"\''), result)
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        result["read_state"] = "unreadable"
    return result


def safe_parse_surge_conf(path):
    result = dict(exists=False, read_state="missing", dns=[], ipv6=None, skip_proxy_risks=[],
                  always_real_ip_risks=[], direct_risk_rules=[], process_direct_risks=[], reject_risk_rules=[])
    section = ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            result.update(exists=True, read_state="ok")
            size = 0
            for line in handle:
                size += len(line)
                if size > 4 * 1024 * 1024:
                    result["read_state"] = "limited"
                    break
                line = line.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                if line.startswith("["):
                    section = line.lower()
                elif section == "[general]" and "=" in line:
                    key, value = [s.strip() for s in line.split("=", 1)]
                    key = key.lower()
                    if key == "dns-server":
                        result["dns"] = [_dns_class(v) for v in value.split(",")]
                    elif key == "ipv6" and value.lower() in {"true", "false"}:
                        result["ipv6"] = value.lower() == "true"
                    elif key in {"skip-proxy", "always-real-ip"}:
                        result["skip_proxy_risks" if key == "skip-proxy" else "always_real_ip_risks"] = risk_tags(value)
                elif section == "[rule]":
                    _rule_metadata(line, result)
    except FileNotFoundError:
        pass
    except OSError:
        result["read_state"] = "unreadable"
    return result


def inspect_telemetry(cdir):
    result = dict(sentry_notes=[], sentry_status="PASS", sentry_critical=False, fcache_notes=[], fcache_status="PASS")
    try:
        obj = read_json(os.path.join(cdir, "sentry", "scope_v3.json"))
        result["sentry_status"] = "INFO"
        contexts = (obj.get("event") or {}).get("contexts") or {}
        culture = contexts.get("culture") or {}
        loc, tz = culture.get("locale", ""), culture.get("timezone", "")
        restricted = tz in RESTRICTED_TZS
        if restricted or simplified(loc):
            result.update(sentry_status="FAIL", sentry_critical=restricted)
        # No user/device IDs or free-form JSON field values leave this function.
        result["sentry_notes"].append("scope_v3.json 存在；" + ("含受限时区/简中状态" if result["sentry_status"] == "FAIL" else "普通设备绑定/文化状态(已脱敏)"))
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, AttributeError):
        result["sentry_status"] = "WARN"
        result["sentry_notes"].append("scope_v3.json 未能完整读取")
    try:
        entries = list(os.scandir(os.path.join(cdir, "sentry", "queue")))[:500]
        count = sum(e.is_file(follow_symlinks=False) for e in entries)
        if count:
            result["sentry_notes"].append(f"离线信封文件 {count} 个；不读取内容")
            if result["sentry_status"] == "PASS":
                result["sentry_status"] = "INFO"
    except FileNotFoundError:
        pass
    except OSError:
        result["sentry_status"] = "WARN"
    try:
        with open(os.path.join(cdir, "fcache"), "rb") as handle:
            raw = handle.read(2 * 1024 * 1024)
        result["fcache_status"] = "WARN"
        index = raw.find(b"\x1f\x8b\x08", 0, 32) if raw.startswith(b"CLF") else -1
        if index >= 0:
            dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
            data = dec.decompress(raw[index:], 4 * 1024 * 1024)
            if not dec.eof:
                raise ValueError("compressed metadata limit")
            obj = json.loads(data)
            bound = bool(obj.get("orgUuid"))
            result["fcache_status"] = "FAIL" if bound else "INFO"
            result["fcache_notes"].append("CLF 缓存存在；组织绑定=" + ("存在(已脱敏)" if bound else "未发现"))
        else:
            result["fcache_notes"].append("fcache 存在；格式未识别")
    except FileNotFoundError:
        pass
    except (OSError, ValueError, zlib.error, TypeError, AttributeError):
        result["fcache_status"] = "WARN"
        result["fcache_notes"].append("fcache 未能完整解析")
    return result

(() => {
  const TARGET_PROFILES = {
    SG: { code: "SG", name: "新加坡 (Singapore)", timezones: ["Asia/Singapore"], jsOffsets: [-480], langs: ["en-sg", "en-us", "en"] },
    US: { code: "US", name: "美国 (United States)", timezones: ["America/Los_Angeles", "America/New_York", "America/Chicago", "America/Denver", "America/Phoenix", "Pacific/Honolulu"], jsOffsets: [480, 420, 360, 300, 240, 600], langs: ["en-us", "en"] },
    JP: { code: "JP", name: "日本 (Japan)", timezones: ["Asia/Tokyo"], jsOffsets: [-540], langs: ["ja-jp", "ja", "en-us", "en"] },
    GB: { code: "GB", name: "英国 (United Kingdom)", timezones: ["Europe/London"], jsOffsets: [0, -60], langs: ["en-gb", "en-us", "en"] },
    TW: { code: "TW", name: "台湾 (Taiwan)", timezones: ["Asia/Taipei"], jsOffsets: [-480], langs: ["zh-tw", "zh-hant", "en-us", "en"] },
    AU: { code: "AU", name: "澳大利亚 (Australia)", timezones: ["Australia/Sydney", "Australia/Melbourne", "Australia/Brisbane", "Australia/Perth"], jsOffsets: [-600, -660, -570, -480], langs: ["en-au", "en-us", "en"] },
    CA: { code: "CA", name: "加拿大 (Canada)", timezones: ["America/Toronto", "America/Vancouver", "America/Edmonton", "America/Montreal"], jsOffsets: [480, 420, 360, 300, 240], langs: ["en-ca", "fr-ca", "en-us", "en"] },
    DE: { code: "DE", name: "德国 (Germany)", timezones: ["Europe/Berlin"], jsOffsets: [-60, -120], langs: ["de-de", "de", "en-us", "en"] },
  };

  let lastReport = null;
  let browserCategory = null;
  let currentFilter = "all";
  let monitorPollTimer = null;
  let monitorRunning = false;
  let pulseEvents = [];
  let pulseAnomalyCount = 0;
  let pulseJumpCount = 0;
  let pulseWakeCount = 0;

  async function fetchJsonWithTimeout(url, timeoutMs = 5000) {
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const r = await fetch(url, { cache: "no-store", signal: ctrl.signal });
      if (!r.ok) return null;
      return await r.json();
    } catch (_) {
      return null;
    } finally {
      clearTimeout(tid);
    }
  }

  const $ = (id) => document.getElementById(id);

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function showToast(msg) {
    const el = $("toast");
    el.textContent = msg;
    el.classList.remove("hidden");
    setTimeout(() => el.classList.add("hidden"), 1800);
  }

  function badgeHtml(status) {
    const st = String(status || "INFO").toUpperCase();
    const cls = st === "PASS" ? "pass" : st === "WARN" ? "warn" : st === "FAIL" ? "fail" : st === "ERR" ? "err" : "info";
    return `<span class="badge ${cls}">${escapeHtml(st)}</span>`;
  }

  function isPrivateLanIp(ip) {
    return (
      /^192\.168\./.test(ip) ||
      /^10\./.test(ip) ||
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
      /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)
    );
  }

  function runWebRtcProbe() {
    return new Promise((resolve) => {
      const RTCPeer = window.RTCPeerConnection || window.webkitRTCPeerConnection;
      if (!RTCPeer) {
        resolve({ supported: false, srflx: [], host: [], mdns: [], relay: [] });
        return;
      }
      let finished = false;
      const srflx = new Set();
      const host = new Set();
      const mdns = new Set();
      const relay = new Set();
      let pc = null;

      const done = () => {
        if (finished) return;
        finished = true;
        try {
          if (pc) pc.close();
        } catch (_) {}
        resolve({
          supported: true,
          srflx: Array.from(srflx),
          host: Array.from(host),
          mdns: Array.from(mdns),
          relay: Array.from(relay),
        });
      };

      try {
        pc = new RTCPeer({
          iceServers: [
            { urls: "stun:stun.l.google.com:19302" },
            { urls: "stun:stun.cloudflare.com:3478" },
          ],
        });
        pc.createDataChannel("rg-probe");
        pc.onicecandidate = (evt) => {
          if (!evt || !evt.candidate) {
            done();
            return;
          }
          const cand = evt.candidate.candidate || "";
          const parts = cand.split(/\s+/);
          const addr = parts[4] || "";
          const typIdx = parts.indexOf("typ");
          const typ = typIdx >= 0 && parts[typIdx + 1] ? parts[typIdx + 1] : "";
          if (!addr) return;
          if (addr.endsWith(".local")) {
            mdns.add(addr);
          } else if (typ === "srflx") {
            srflx.add(addr);
          } else if (typ === "relay") {
            relay.add(addr);
          } else if (typ === "host") {
            host.add(addr);
          }
        };
        pc.createOffer()
          .then((offer) => pc.setLocalDescription(offer))
          .catch(() => done());
        setTimeout(done, 3500);
      } catch (_) {
        done();
      }
    });
  }

  function applyPlatformUi(report) {
    if (!report) return;
    const plat = report.platform || "macos";
    const label = report.platform_label || (plat === "windows" ? "Windows" : "macOS");
    const pb = $("platformBadge");
    if (pb) {
      pb.className = "badge info";
      pb.textContent = label;
    }
    const invSub = $("inventorySubtitle");
    if (invSub) {
      if (plat === "windows") {
        invSub.textContent =
          "覆盖 Desktop 指纹文件（传统 %APPDATA%\\Claude 与 MSIX Packages\\Claude_* 虚拟化容器、ant-did / Cookies / device_id_salt / 日志）、Claude Code CLI、Windows 凭据管理器、AppData/Temp/IDE 与 Chrome/Edge/Brave/Arc/Firefox 站点残留（纯只读脱敏）";
      } else {
        invSub.textContent =
          "覆盖 Desktop 指纹文件（ant-did / Cookies / device_id_salt / config / 日志）、Claude Code CLI、全库钥匙串、~/Library 12 子目录、崩溃/临时/IDE 与 Safari WebsiteData / ITP / 历史（纯只读脱敏）";
      }
    }
    const chkProf = $("chkProfileText");
    const chkReb = $("chkRebootText");
    if (plat === "windows") {
      if (chkProf) {
        chkProf.textContent =
          "已清理 Chrome / Edge / Firefox 站点数据（claude / anthropic / hcaptcha / stripe / stripe.network），或已为新号新建完全独立的 Chrome/Edge Profile";
      }
      if (chkReb) {
        chkReb.textContent =
          "系统级修改（Windows 区域 GeoID / 计算机名 / 时区 / 快速启动 / 定位）完成后已完整重启电脑，并按 Win+Space 切到 ENG 英文键盘再登录";
      }
    } else {
      if (chkProf) {
        chkProf.textContent =
          "已清理 Safari Manage Website Data（claude / anthropic / hcaptcha / stripe），或已为新号新建独立的 Safari Profile（全新 Cookies / WebsiteData / DeviceIdHashSalts）";
      }
      if (chkReb) {
        chkReb.textContent =
          "系统级修改（Country / 主机名 / 时区 / Power Nap / 定位）完成后已完整重启 Mac，并切到 ABC 英文键盘再登录";
      }
    }
  }

  function probeSpeechVoices() {
    return new Promise((resolve) => {
      if (!window.speechSynthesis || typeof window.speechSynthesis.getVoices !== "function") {
        resolve([]);
        return;
      }
      const initial = window.speechSynthesis.getVoices() || [];
      if (initial.length > 0) {
        resolve(initial);
        return;
      }
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        try {
          resolve(window.speechSynthesis.getVoices() || []);
        } catch (_) {
          resolve([]);
        }
      };
      try {
        window.speechSynthesis.onvoiceschanged = finish;
      } catch (_) {}
      setTimeout(finish, 450);
    });
  }

  function probeChineseFonts() {
    const testFonts = [
      "Microsoft YaHei",
      "SimSun",
      "SimHei",
      "DengXian",
      "FangSong",
      "KaiTi",
      "PingFang SC",
      "Hiragino Sans GB",
      "Source Han Sans CN",
    ];
    const detected = [];
    try {
      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d");
      if (!ctx) return detected;
      const sample = "mmmmmmmmmmlli测试字体123";
      ctx.font = "72px monospace";
      const baseMono = ctx.measureText(sample).width;
      ctx.font = "72px sans-serif";
      const baseSans = ctx.measureText(sample).width;
      for (const f of testFonts) {
        ctx.font = `72px "${f}", monospace`;
        const wMono = ctx.measureText(sample).width;
        ctx.font = `72px "${f}", sans-serif`;
        const wSans = ctx.measureText(sample).width;
        if (Math.abs(wMono - baseMono) > 0.5 || Math.abs(wSans - baseSans) > 0.5) {
          detected.push(f);
        }
      }
    } catch (_) {}
    return detected;
  }

  function getExpectedOffsetForTz(tz) {
    try {
      const now = new Date();
      const parts = new Intl.DateTimeFormat("en-US", {
        timeZone: tz,
        timeZoneName: "shortOffset",
      }).formatToParts(now);
      const tzPart = parts.find((p) => p.type === "timeZoneName");
      if (!tzPart) return null;
      const m = /^GMT([+-])(\d{1,2})(?::?(\d{2}))?$/.exec(tzPart.value.trim());
      if (!m) return tzPart.value.trim() === "GMT" ? 0 : null;
      const sign = m[1] === "+" ? 1 : -1;
      const mins = sign * (parseInt(m[2], 10) * 60 + parseInt(m[3] || "0", 10));
      return -mins; // JS getTimezoneOffset() has inverted sign
    } catch (_) {
      return null;
    }
  }

  async function runBrowserLiveAudit(targetCode, backendReport) {
    const targetCfg = TARGET_PROFILES[targetCode] || TARGET_PROFILES.SG;
    const isWin = (backendReport && backendReport.platform) === "windows";
    const checks = [];
    const egressIp = (backendReport && backendReport.egress_summary && backendReport.egress_summary.ip) || "";
    const egressTz = (backendReport && backendReport.egress_summary && backendReport.egress_summary.timezone) || "";

    // 0. Browser Direct Egress IP & IPv6-Only Probe vs Backend curl IP Cross-Check
    const [geojsDirect, ipifyV4Direct, ipify64Direct, ipifyV6Only] = await Promise.all([
      fetchJsonWithTimeout("https://get.geojs.io/v1/ip/geo.json", 5000),
      fetchJsonWithTimeout("https://api.ipify.org?format=json", 5000),
      fetchJsonWithTimeout("https://api64.ipify.org?format=json", 5000),
      fetchJsonWithTimeout("https://api6.ipify.org?format=json", 3500),
    ]);
    const browserIp = (geojsDirect && geojsDirect.ip) || (ipifyV4Direct && ipifyV4Direct.ip) || "";
    const browserIp64 = (ipify64Direct && ipify64Direct.ip) || "";
    const browserV6Only = (ipifyV6Only && ipifyV6Only.ip && ipifyV6Only.ip.includes(":")) ? ipifyV6Only.ip : "";
    const seenBrowserIps = Array.from(new Set([browserIp, browserIp64].filter(Boolean)));
    let ipMatchStatus = "PASS";
    let ipMatchSev = "low";
    let ipMatchObs = `浏览器=${seenBrowserIps.join(" / ") || "超时"} | 后端=${egressIp || "-"}`;
    let ipMatchDetail = "浏览器直连公网出口 IP 与后端代理通道完全一致，未出现代理扩展、Private Relay 或 HTTP/3 分叉。";
    let ipMatchFix = "";
    if (!seenBrowserIps.length) {
      ipMatchStatus = "WARN";
      ipMatchSev = "low";
      ipMatchDetail = "浏览器直出 IP 探测超时，无法确认是否与后端代理分叉。";
    } else if (egressIp && seenBrowserIps.some((ip) => ip !== egressIp)) {
      ipMatchStatus = "FAIL";
      ipMatchSev = "critical";
      ipMatchDetail = isWin
        ? `致命分叉！浏览器直出 IP (${seenBrowserIps.join(", ")}) 与后端 curl IP (${egressIp}) 不一致！Windows 上常见原因为：仅开启了系统代理而未开启 TUN 虚拟网卡（导致 CLI/curl 直连），或浏览器装了独立代理插件/DoH/QUIC 分叉。`
        : `致命分叉！浏览器直出 IP (${seenBrowserIps.join(", ")}) 与后端 curl IP (${egressIp}) 不一致！通常由 iCloud Private Relay、浏览器代理扩展、单独开启 DoH 或 QUIC 直连引起。`;
      ipMatchFix = isWin
        ? "在 Clash Verge / Mihomo Party 中开启 TUN 模式接管全局，并禁用浏览器独立代理扩展。"
        : "关闭 Safari 的 iCloud Private Relay / 隐藏 IP，并禁用浏览器独立代理插件，确保全部走系统 Clash TUN。";
    }
    checks.push({
      id: "browser_ip_match",
      title: "浏览器直出 IP 与后端代理一致性 (防系统代理/扩展/Private Relay 分叉)",
      status: ipMatchStatus,
      severity: ipMatchSev,
      observed: ipMatchObs,
      detail: ipMatchDetail,
      fix_advice: ipMatchFix,
      fix_cmd: "",
    });

    // 0b. Browser IPv6-Only Direct Leak Check
    if (browserV6Only) {
      checks.push({
        id: "browser_ipv6_direct",
        title: "浏览器 IPv6 直出泄漏实测 (api6.ipify.org)",
        status: "FAIL",
        severity: "critical",
        observed: `浏览器可直连 IPv6: ${browserV6Only}`,
        detail: "浏览器通过 IPv6 协议栈直接获取到了公网 IPv6 出口（即便 IPv4 走代理，现代浏览器的 Happy Eyeballs / QUIC 也会优先尝试 IPv6 直连，直接暴露真实宽带位置！）。",
        fix_advice: isWin
          ? "在 Windows 网络适配器属性中取消勾选「Internet 协议版本 6 (TCP/IPv6)」，并在 Clash 中设 ipv6: false。"
          : "在 macOS 网络设置中关闭 IPv6，并在 Clash 中设 ipv6: false。",
        fix_cmd: "",
      });
    } else {
      checks.push({
        id: "browser_ipv6_direct",
        title: "浏览器 IPv6 直出泄漏实测 (api6.ipify.org)",
        status: "PASS",
        severity: "low",
        observed: "浏览器纯 IPv6 通道不可达 (无 IPv6 直连泄漏)",
        detail: "浏览器无法通过纯 IPv6 绕过代理直出。",
        fix_advice: "",
        fix_cmd: "",
      });
    }

    // 1. Real HTTP Accept-Language via /api/headers (+ Consistency with navigator.language)
    let hdrs = {};
    const clientBeforeMs = Date.now();
    try {
      const r = await fetch("/api/headers", { cache: "no-store" });
      hdrs = await r.json();
    } catch (_) {}
    const clientAfterMs = Date.now();

    const acceptLang = hdrs.accept_language || "";
    const alLow = acceptLang.toLowerCase();
    const navLang = navigator.language || "";
    const navLangs = Array.isArray(navigator.languages) ? navigator.languages : [];
    const alPrimary = (alLow.split(",")[0] || "").split(";")[0].trim();
    const navPrimary = navLang.toLowerCase().trim();
    const langHeaderJsMismatch = Boolean(
      alPrimary && navPrimary && alPrimary.split("-")[0] !== navPrimary.split("-")[0]
    );

    let alStatus = "PASS";
    let alSev = "low";
    let alDetail = "HTTP Accept-Language 请求头不含简体中文特征，且与 JS navigator.language 主语言一致。";
    let alFix = "";
    if (!acceptLang) {
      alStatus = "INFO";
      alDetail = "未收到 Accept-Language 请求头。";
    } else if (/^zh(-cn|-hans)?/i.test(alLow) || alLow.includes("zh-cn") || alLow.includes("zh-hans")) {
      alStatus = targetCode === "TW" ? "INFO" : "FAIL";
      alSev = alStatus === "FAIL" ? "high" : "low";
      alDetail = `当前浏览器在 HTTP 请求头里直接发送了 ${acceptLang}，服务端与 Cloudflare 每次请求都能直接看到中文偏好。`;
      alFix = "在浏览器语言设置中将 English (Singapore) / English (US) 置顶，并移除中文首选项。";
    } else if (langHeaderJsMismatch) {
      alStatus = "FAIL";
      alSev = "high";
      alDetail = `HTTP Accept-Language 主语言 (${alPrimary}) 与 JS navigator.language (${navPrimary}) 矛盾！这是典型的伪装扩展/指纹插件穿帮特征。`;
      alFix = "移除或关闭篡改语言的浏览器扩展，统一在浏览器与系统原生设置中修改语言。";
    } else if (alLow.includes("zh")) {
      alStatus = targetCode === "TW" ? "PASS" : "WARN";
      alDetail = `HTTP Accept-Language 次选语言包含中文 (${acceptLang})。`;
      alFix = "如需更纯净指纹，可从浏览器首选语言列表移除中文。";
    }
    checks.push({
      id: "browser_accept_lang",
      title: "浏览器 HTTP Accept-Language 请求头与 JS 一致性",
      status: alStatus,
      severity: alSev,
      observed: acceptLang || "<empty>",
      detail: alDetail,
      fix_advice: alFix,
      fix_cmd: "",
    });

    // 2. navigator.language & navigator.languages
    const navJoined = navLangs.join(", ");
    const navLow = navLang.toLowerCase();
    let navStatus = "PASS";
    let navSev = "low";
    let navDetail = "JS navigator.language(s) 与目标环境兼容。";
    let navFix = "";
    if (navLow.startsWith("zh-cn") || navLow === "zh") {
      navStatus = "FAIL";
      navSev = "high";
      navDetail = `JS 首选语言为 ${navLang}（完整列表: ${navJoined}），前端脚本（Stripe / hCaptcha / Claude）可直接读取。`;
      navFix = "将浏览器界面与系统首选语言改为目标地区英文，并重启浏览器。";
    } else if (navLangs.some((l) => /^zh/i.test(l)) && targetCode !== "TW") {
      navStatus = "WARN";
      navDetail = `首选语言正常 (${navLang})，但次选列表包含中文 (${navJoined})。`;
      navFix = "可在浏览器语言列表中移除中文项。";
    }
    checks.push({
      id: "browser_nav_lang",
      title: "JS navigator.language / languages",
      status: navStatus,
      severity: navSev,
      observed: `${navLang} | [${navJoined}]`,
      detail: navDetail,
      fix_advice: navFix,
      fix_cmd: "",
    });

    // 3. JS TimeZone, Localized Date String, Offset Anti-Spoof Math & Browser Clock Drift
    const RESTRICTED_TZS = new Set([
      "Asia/Shanghai", "Asia/Chongqing", "Asia/Harbin", "Asia/Urumqi",
      "Asia/Kashgar", "Asia/Hong_Kong", "Asia/Macau", "PRC", "Hongkong",
    ]);
    const resolved = Intl.DateTimeFormat().resolvedOptions();
    const jsTz = resolved.timeZone || "";
    const jsOffset = new Date().getTimezoneOffset();
    const dateStr = new Date().toString();
    const isRestrictedTz =
      RESTRICTED_TZS.has(jsTz) ||
      /China Standard Time|Hong Kong Standard Time|中国标准时间|香港标准时间|澳门标准时间|北京/i.test(dateStr);
    const expectedOffset = jsTz ? getExpectedOffsetForTz(jsTz) : null;
    const tzSpoofBroken = expectedOffset !== null && expectedOffset !== jsOffset;
    const matchTargetTz = jsTz
      ? (targetCfg.timezones.includes(jsTz) && !isRestrictedTz)
      : (targetCfg.jsOffsets.includes(jsOffset) && !isRestrictedTz);
    const matchIpTz = !egressTz || jsTz === egressTz;

    const srvUtcMs = Number(hdrs.server_utc_ms || 0);
    const clientMidMs = (clientBeforeMs + clientAfterMs) / 2;
    const browserClockDriftSec = srvUtcMs ? Math.round((clientMidMs - srvUtcMs) / 100) / 10 : 0;

    let tzStatus = "PASS";
    let tzSev = "low";
    let tzDetail = `浏览器时区 ${jsTz}（offset=${jsOffset}）与目标地区及出口 IP 时区 (${egressTz || "-"}) 一致。`;
    let tzFix = "";
    if (tzSpoofBroken) {
      tzStatus = "FAIL";
      tzSev = "critical";
      tzDetail = `时区伪装穿帮！Intl.timeZone=${jsTz} 对应理论偏移为 ${expectedOffset}，但 Date.getTimezoneOffset() 实际返回 ${jsOffset}（典型劣质改时区插件穿帮）！`;
      tzFix = "卸载改时区浏览器插件，直接修改操作系统原生时区并重启浏览器。";
    } else if (!matchTargetTz) {
      tzStatus = "FAIL";
      tzSev = isRestrictedTz ? "critical" : "high";
      tzDetail = isRestrictedTz
        ? `致命暴露！浏览器 JS 时区仍暴露受限地区 ${jsTz}（即使同为 UTC+8，Asia/Shanghai / China Standard Time / 中国标准时间 也会被前端脚本直接读取）！`
        : `不一致！当前浏览器 JS 时区为 ${jsTz} (getTimezoneOffset=${jsOffset})，与目标 ${targetCfg.name} 不符。`;
      tzFix = isWin
        ? "修改 Windows 系统时区为目标地区后务必完整重启浏览器与电脑，否则已打开的浏览器进程会继续缓存旧时区！"
        : "修改系统时区为目标地区后务必完整重启浏览器与 Mac，否则已打开的浏览器进程会继续缓存旧时区！";
    } else if (Math.abs(browserClockDriftSec) > 5) {
      tzStatus = "WARN";
      tzSev = "high";
      tzDetail = `浏览器 JS 时钟与本机后端 UTC 偏差 ${browserClockDriftSec}s（可能存在时钟劫持插件）。`;
      tzFix = "关闭可能修改浏览器 Date API 的扩展。";
    } else if (!matchIpTz) {
      tzStatus = "WARN";
      tzSev = "low";
      tzDetail = `浏览器时区 (${jsTz}) 符合目标预设，但与当前出口 IP 所在时区 (${egressTz}) 不同。`;
      tzFix = "确认节点城市与系统时区是否匹配。";
    }
    checks.push({
      id: "browser_timezone",
      title: "浏览器 JS 时区、偏移防穿帮与出口 IP 时区对齐",
      status: tzStatus,
      severity: tzSev,
      observed: `JS=${jsTz} (offset=${jsOffset}) | IP=${egressTz || "未知"} | 时钟差=${browserClockDriftSec}s`,
      detail: tzDetail,
      fix_advice: tzFix,
      fix_cmd: "",
    });

    // 4. WebRTC ICE Candidate Leak Probe
    const rtc = await runWebRtcProbe();
    let rtcStatus = "PASS";
    let rtcSev = "low";
    let rtcObs = "无公网 srflx 泄漏";
    let rtcDetail = "WebRTC 未暴露真实公网 IP。";
    let rtcFix = "";
    if (!rtc.supported) {
      rtcStatus = "INFO";
      rtcObs = "浏览器已禁用 RTCPeerConnection";
      rtcDetail = "WebRTC API 不可用，无法通过 WebRTC 泄漏 IP。";
    } else {
      const publicLeaks = rtc.srflx.filter((ip) => ip !== egressIp);
      const lanHosts = rtc.host.filter((ip) => isPrivateLanIp(ip));
      rtcObs = `srflx=[${rtc.srflx.join(", ") || "无"}] | host=[${rtc.host.join(", ") || "无"}] | mDNS=${rtc.mdns.length}`;
      if (publicLeaks.length > 0) {
        rtcStatus = "FAIL";
        rtcSev = "critical";
        rtcDetail = `WebRTC 暴露了与 TCP 出口 (${egressIp}) 不同的公网 IP: ${publicLeaks.join(", ")}！说明 WebRTC UDP 正在绕过代理泄漏真实 IP。`;
        rtcFix = "在浏览器安装 WebRTC 防泄漏设置/扩展，或将 WebRTC ICE 策略限制为 disable_non_proxied_udp。";
      } else if (lanHosts.length > 0) {
        rtcStatus = "WARN";
        rtcDetail = `未见公网 IP 泄漏，但暴露了未混淆的局域网内网 IP (${lanHosts.join(", ")})。`;
        rtcFix = "建议开启浏览器的 mDNS 本地 IP 混淆或禁用非代理 UDP。";
      } else if (rtc.srflx.length > 0 && egressIp && rtc.srflx.every((ip) => ip === egressIp)) {
        rtcStatus = "PASS";
        rtcDetail = `WebRTC srflx 出口 (${rtc.srflx.join(", ")}) 与代理 TCP 出口完全一致。`;
      } else {
        rtcStatus = "PASS";
        rtcDetail = "未发现公网 srflx 或明文内网 IP 泄漏（仅 mDNS 或 UDP 被阻断）。";
      }
    }
    checks.push({
      id: "browser_webrtc",
      title: "浏览器 WebRTC ICE 实测防泄漏",
      status: rtcStatus,
      severity: rtcSev,
      observed: rtcObs,
      detail: rtcDetail,
      fix_advice: rtcFix,
      fix_cmd: "",
    });

    // 5. Geolocation Permission State
    let geoState = "unknown";
    if (navigator.permissions && navigator.permissions.query) {
      try {
        const perm = await navigator.permissions.query({ name: "geolocation" });
        geoState = perm.state;
      } catch (_) {}
    }
    let geoStatus = "INFO";
    let geoSev = "low";
    let geoDetail = "无法查询浏览器地理位置权限状态。";
    let geoFix = "";
    if (geoState === "denied") {
      geoStatus = "PASS";
      geoDetail = "当前网页地理位置权限为 denied（已拒绝），网站无法请求 GPS/Wi-Fi 坐标。";
    } else if (geoState === "prompt") {
      geoStatus = "WARN";
      geoDetail = "地理位置权限为 prompt（默认询问），建议在浏览器设置里改为全局拒绝（Deny）。";
      geoFix = isWin
        ? "Chrome/Edge 设置 -> 隐私和安全 -> 网站设置 -> 位置信息 -> 设为「不允许网站查看您的位置信息」。"
        : "Safari -> Settings -> Websites -> Location 设为 Deny；或 Chrome Privacy -> Location 设为 Don't allow。";
    } else if (geoState === "granted") {
      geoStatus = "FAIL";
      geoSev = "critical";
      geoDetail = "地理位置权限为 granted，网页可直接读取物理位置坐标！";
      geoFix = "立即在浏览器网站权限中撤销定位授权。";
    }
    checks.push({
      id: "browser_geolocation",
      title: "浏览器 Geolocation 定位权限状态",
      status: geoStatus,
      severity: geoSev,
      observed: geoState,
      detail: geoDetail,
      fix_advice: geoFix,
      fix_cmd: "",
    });

    // 6. Deep Intl Format, Collator, RelativeTimeFormat & Calendar Consistency
    const numResolved = Intl.NumberFormat().resolvedOptions();
    const colLocale = (() => {
      try { return Intl.Collator().resolvedOptions().locale || ""; } catch (_) { return ""; }
    })();
    const rtfLocale = (() => {
      try { return new Intl.RelativeTimeFormat().resolvedOptions().locale || ""; } catch (_) { return ""; }
    })();
    const intlLocale = resolved.locale || "";
    const numLocale = numResolved.locale || "";
    const cal = resolved.calendar || "";
    const numSys = resolved.numberingSystem || "";
    const hourCycle = resolved.hourCycle || "";
    const hasCnIntl =
      /zh[-_]cn|zh[-_]hans/i.test(intlLocale) ||
      /zh[-_]cn|zh[-_]hans/i.test(numLocale) ||
      /zh[-_]cn|zh[-_]hans/i.test(colLocale) ||
      /zh[-_]cn|zh[-_]hans/i.test(rtfLocale) ||
      String(cal).toLowerCase() === "chinese";
    checks.push({
      id: "browser_intl_format",
      title: "Intl 深度区域格式 (Date / Number / Collator / Calendar)",
      status: hasCnIntl && targetCode !== "TW" ? "WARN" : "PASS",
      observed: `Date=${intlLocale} | Num=${numLocale} | Collator=${colLocale || "-"} | RTF=${rtfLocale || "-"} | Cal=${cal}`,
      detail: hasCnIntl
        ? "浏览器区域格式、排序器或历法包含中国区/农历特征（即使伪造了 navigator.language 也容易在此穿帮）。"
        : `日期、数字、排序器与历法无异常中国区特征 (NumSys=${numSys}, Hour=${hourCycle})。`,
      fix_advice: hasCnIntl ? "将系统及浏览器首选语言与地区格式设为目标地区。" : "",
      fix_cmd: "",
    });

    // 7. SpeechSynthesis Voices Hidden Chinese OS Leak Probe
    const voices = await probeSpeechVoices();
    const defaultVoice = voices.find((v) => v.default) || voices[0] || null;
    const cnVoices = voices.filter((v) => /^zh[-_]cn/i.test(v.lang || "") || /huihui|kangkang|yaoyao|tingting|xiaoxiao|yunxi/i.test(v.name || ""));
    const defaultIsCn = Boolean(
      defaultVoice &&
        (/^zh[-_]cn/i.test(defaultVoice.lang || "") || /huihui|kangkang|yaoyao|tingting/i.test(defaultVoice.name || ""))
    );
    let voiceStatus = "PASS";
    let voiceSev = "low";
    let voiceObs = defaultVoice
      ? `默认语音=${defaultVoice.name} (${defaultVoice.lang}) | 共${voices.length}语音 (zh-CN=${cnVoices.length})`
      : "未暴露系统语音列表 (0 语音)";
    let voiceDetail = "speechSynthesis 默认系统语音不含简体中文特征。";
    let voiceFix = "";
    if (defaultIsCn && targetCode !== "TW") {
      voiceStatus = "WARN";
      voiceSev = "high";
      voiceDetail =
        "隐蔽指纹泄漏！即便浏览器已改英文，speechSynthesis.getVoices() 的默认语音仍暴露为简体中文（如 Microsoft Huihui / Tingting）——hCaptcha 与 Stripe Radar 常读取此 API 识别中文操作系统！";
      voiceFix = isWin
        ? "在 Windows 设置 -> 时间和语言 -> 语音 中将默认语音改为 English (United States / Singapore)，并重启浏览器。"
        : "在 macOS System Settings -> Accessibility -> Spoken Content 中将 System Voice 改为英文语音。";
    } else if (cnVoices.length > 0 && targetCode !== "TW") {
      voiceStatus = "INFO";
      voiceDetail = `默认语音正常，但系统语音包中仍安装了 ${cnVoices.length} 个简体中文语音（${cnVoices.slice(0, 3).map((v) => v.name).join(", ")}），属于轻度 OS 特征参考信号。`;
    }
    checks.push({
      id: "browser_speech_voices",
      title: "speechSynthesis 系统语音指纹泄漏检测 (隐藏中文 OS 特征)",
      status: voiceStatus,
      severity: voiceSev,
      observed: voiceObs,
      detail: voiceDetail,
      fix_advice: voiceFix,
      fix_cmd: "",
    });

    // 8. CJK System Font Fingerprint Probe
    const cnFonts = probeChineseFonts();
    const winExclusiveCnFonts = cnFonts.filter((f) =>
      ["Microsoft YaHei", "SimSun", "SimHei", "DengXian", "FangSong", "KaiTi"].includes(f)
    );
    let fontStatus = "INFO";
    let fontDetail =
      cnFonts.length > 0
        ? isWin
          ? `检测到 Windows 中文字体 (${cnFonts.join(", ")})。说明系统安装了简体中文 SKU 或东亚字体包，属于 Canvas/DOM 字体指纹维度（通常单独存在不会封号，但与中文时区/语音叠加会放大风控分）。`
          : `检测到中文字体 (${cnFonts.join(", ")})。注：macOS 全球出厂默认自带 PingFang SC / Hiragino，属于正常系统基线。`
        : "未检测到常见简体中文系统字体。";
    checks.push({
      id: "browser_cjk_fonts",
      title: "中文字体指纹特征探测 (Canvas 文本测量)",
      status: isWin && winExclusiveCnFonts.length >= 4 && targetCode !== "TW" ? "INFO" : fontStatus,
      severity: "low",
      observed: cnFonts.length ? `命中 ${cnFonts.length} 个: ${cnFonts.join(", ")}` : "未命中常见中文字体",
      detail: fontDetail,
      fix_advice: isWin && winExclusiveCnFonts.length >= 4 ? "纯英文系统镜像最干净；如不便重装，务必保证 IP、时区、Accept-Language、语音与 Profile 全部对齐。" : "",
      fix_cmd: "",
    });

    // 9. hCaptcha-style Permissions Matrix Probe
    const permNames = ["geolocation", "notifications", "camera", "microphone", "persistent-storage", "clipboard-read"];
    const permStates = [];
    if (navigator.permissions && navigator.permissions.query) {
      for (const pname of permNames) {
        try {
          const p = await navigator.permissions.query({ name: pname });
          permStates.push(`${pname}=${p.state}`);
        } catch (_) {
          permStates.push(`${pname}=unsupported`);
        }
      }
    }
    const permObs = permStates.length ? permStates.join(" | ") : "Permissions API 不可用";
    const hasGrantedSensitive = permStates.some((s) => s.startsWith("geolocation=granted") || s.startsWith("notifications=granted"));
    checks.push({
      id: "browser_permissions_matrix",
      title: "hCaptcha 同款多权限面板探测",
      status: hasGrantedSensitive ? "WARN" : "INFO",
      observed: permObs,
      detail: "hCaptcha（newassets.hcaptcha.com）会批量查询以上浏览器权限状态作为设备信任评分维度，全部保持 prompt/denied 更安全。",
      fix_advice: hasGrantedSensitive ? "建议收回非必要的定位或通知授权。" : "",
      fix_cmd: "",
    });

    // 10. Automation Flags, Prototype Tamper, WebGL Software/VM GPU & UA-CH High-Entropy Consistency
    let webglStr = "不可用";
    try {
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (gl) {
        const dbg = gl.getExtension("WEBGL_debug_renderer_info");
        if (dbg) {
          const vendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || "";
          const renderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || "";
          webglStr = `${vendor} / ${renderer}`.trim();
        } else {
          webglStr = String(gl.getParameter(gl.RENDERER) || "WebGL enabled");
        }
      }
    } catch (_) {}

    const botArtifacts = [];
    if (navigator.webdriver) botArtifacts.push("navigator.webdriver=true");
    if (window.__playwright || window.__pw_manual) botArtifacts.push("__playwright");
    if (window.__puppeteer_evaluation_script__) botArtifacts.push("__puppeteer");
    if (window.domAutomation || window.domAutomationController) botArtifacts.push("domAutomation");
    if (window._phantom || window.callPhantom) botArtifacts.push("PhantomJS");
    try {
      const cdcKey = Object.keys(window).find((k) => /^cdc_[a-zA-Z0-9]+/.test(k));
      if (cdcKey) botArtifacts.push(`chromedriver(${cdcKey.slice(0, 12)})`);
    } catch (_) {}

    const tamperHits = [];
    try {
      const fnCanvas = Function.prototype.toString.call(HTMLCanvasElement.prototype.toDataURL);
      if (!fnCanvas.includes("[native code]")) tamperHits.push("Canvas.toDataURL被Hook");
    } catch (_) {}
    try {
      const fnIntl = Function.prototype.toString.call(Intl.DateTimeFormat.prototype.resolvedOptions);
      if (!fnIntl.includes("[native code]")) tamperHits.push("Intl.resolvedOptions被Hook");
    } catch (_) {}

    const isVmOrSoftwareGpu = /swiftshader|llvmpipe|microsoft basic render|vmware|virtualbox|parallels|qemu|mesa offscreen|subzero/i.test(webglStr);

    let uachInfo = "-";
    let uaPlatMismatch = false;
    try {
      if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {
        const he = await navigator.userAgentData.getHighEntropyValues(["platform", "platformVersion", "architecture", "bitness"]);
        uachInfo = `${he.platform || "-"} ${he.platformVersion || ""} (${he.architecture || "-"}/${he.bitness || "-"})`.trim();
        const uaLow = (navigator.userAgent || "").toLowerCase();
        const pLow = String(he.platform || "").toLowerCase();
        if (
          (pLow.includes("windows") && !uaLow.includes("windows")) ||
          (pLow.includes("mac") && !uaLow.includes("mac os"))
        ) {
          uaPlatMismatch = true;
        }
      }
    } catch (_) {}

    const secUa = hdrs.sec_ch_ua || "-";
    const secPlat = hdrs.sec_ch_ua_platform || "-";
    const hwIssues = [];
    if (botArtifacts.length) hwIssues.push(`自动化特征: ${botArtifacts.join(", ")}`);
    if (tamperHits.length) hwIssues.push(`指纹反检测Hook穿帮: ${tamperHits.join(", ")}`);
    if (uaPlatMismatch) hwIssues.push(`UA 与 Sec-CH-UA 平台冲突 (UA-CH=${uachInfo})`);
    if (isVmOrSoftwareGpu) hwIssues.push(`软件渲染/虚拟机显卡 (${webglStr})`);

    const hwStatus = botArtifacts.length || uaPlatMismatch ? "FAIL" : (tamperHits.length || isVmOrSoftwareGpu ? "WARN" : "INFO");
    const hwSev = botArtifacts.length ? "critical" : (uaPlatMismatch || tamperHits.length ? "high" : "low");
    const hwObs = `自动化=${botArtifacts.length ? botArtifacts.join(",") : "无"} | CPU=${navigator.hardwareConcurrency || "-"} | Mem=${navigator.deviceMemory || "-"}GB | Screen=${window.screen.width}x${window.screen.height} | WebGL=${webglStr}`;
    checks.push({
      id: "browser_webgl_automation",
      title: "自动化标记、Hook 反检测穿帮、WebGL 显卡与 UA-CH 硬件指纹",
      status: hwStatus,
      severity: hwSev,
      observed: hwObs,
      detail:
        (hwIssues.length ? `⚠️ ${hwIssues.join("；")}。` : "未检测到自动化框架、Hook 篡改或 UA-CH 冲突。") +
        ` UA-CH=${uachInfo} | Sec-CH-UA=${secUa} | Platform=${secPlat} | DNT=${navigator.doNotTrack || "unset"} | UA=${navigator.userAgent}`,
      fix_advice: botArtifacts.length
        ? "检测到自动化浏览器标识，极易触发 Cloudflare Turnstile / hCaptcha 封禁，请改用原生手动浏览器。"
        : (tamperHits.length || uaPlatMismatch
          ? "检测到篡改 Canvas/Intl/UA 的扩展，反而会触发 Cloudflare 与 Stripe 的异常熵风控，建议在纯净无插件 Profile 中登录 Claude。"
          : (isVmOrSoftwareGpu
            ? "当前为虚拟显卡或软件渲染（SwiftShader/VM），请开启浏览器硬件加速，或优先在宿主机原生环境登录。"
            : "")),
      fix_cmd: "",
    });

    return { title: "浏览器实时指纹实测 (当前浏览器直采)", checks };
  }

  function renderSummary(report, browserCat) {
    const allCats = Object.values(report.categories || {});
    if (browserCat) allCats.push(browserCat);

    const counts = { PASS: 0, WARN: 0, FAIL: 0, INFO: 0 };
    let criticalFail = 0;
    let highFail = 0;
    let highWarn = 0;
    let lowWarn = 0;
    const deductions = [];

    for (const cat of allCats) {
      const catTitle = cat.title || "检测模块";
      for (const chk of cat.checks || []) {
        const st = chk.status;
        const sev = chk.severity || (st === "FAIL" ? "high" : "low");
        if (counts[st] !== undefined) counts[st] += 1;
        if (st === "FAIL") {
          const pts = sev === "critical" ? 30 : 15;
          if (sev === "critical") criticalFail += 1;
          else highFail += 1;
          deductions.push({
            pts,
            level: sev === "critical" ? "致命红线" : "高危 FAIL",
            status: "FAIL",
            critical: sev === "critical",
            catTitle,
            title: chk.title || chk.id,
            observed: chk.observed || chk.detail || "",
          });
        } else if (st === "WARN") {
          const pts = sev === "high" ? 6 : 2;
          if (sev === "high") highWarn += 1;
          else lowWarn += 1;
          deductions.push({
            pts,
            level: sev === "high" ? "高风险 WARN" : "轻度 WARN",
            status: "WARN",
            critical: false,
            catTitle,
            title: chk.title || chk.id,
            observed: chk.observed || chk.detail || "",
          });
        }
      }
    }

    const penalty = criticalFail * 30 + highFail * 15 + highWarn * 6 + lowWarn * 2;
    const score = Math.max(0, Math.min(100, 100 - penalty));
    $("scoreValue").textContent = String(score);

    // Render Grade & Score Deduction Breakdown Table (Read-Only)
    const gradeBadge = $("gradeBadge");
    if (gradeBadge) {
      let gradeTxt = "S 级 · 极佳";
      let gradeCls = "badge pass";
      if (criticalFail > 0 || score < 50) {
        gradeTxt = "D 级 · 高危拦截风险";
        gradeCls = "badge fail";
      } else if (score < 70 || counts.FAIL > 0) {
        gradeTxt = "C 级 · 存在明显冲突";
        gradeCls = "badge fail";
      } else if (score < 85 || highWarn > 0) {
        gradeTxt = "B 级 · 需优化风险项";
        gradeCls = "badge warn";
      } else if (score < 95) {
        gradeTxt = "A 级 · 较安全";
        gradeCls = "badge pass";
      }
      gradeBadge.className = gradeCls;
      gradeBadge.textContent = `${gradeTxt} (${score}分)`;
    }

    const formulaEl = $("scoreFormulaText");
    if (formulaEl) {
      formulaEl.textContent =
        `扣分公式：100 - 致命红线(${criticalFail}×30) - 高危FAIL(${highFail}×15) - 高风险WARN(${highWarn}×6) - 轻度WARN(${lowWarn}×2) = ${score} 分（总扣 ${penalty} 分，最低 0 分）`;
    }

    const dedBadge = $("deductionCountBadge");
    if (dedBadge) {
      dedBadge.className = deductions.length ? (criticalFail || highFail ? "badge fail" : "badge warn") : "badge pass";
      dedBadge.textContent = deductions.length ? `共 ${deductions.length} 项扣分 (-${penalty} 分)` : "满分 0 扣分";
    }

    const dedBody = $("deductionBody");
    if (dedBody) {
      if (!deductions.length) {
        dedBody.innerHTML = `<tr><td colspan="5" class="empty-cell">🎉 当前无任何扣分项，所有已检维度全部通过！</td></tr>`;
      } else {
        deductions.sort((a, b) => b.pts - a.pts);
        dedBody.innerHTML = deductions
          .map((d) => {
            const rowCls = d.status === "FAIL" ? "row-danger" : "row-conflict";
            const ptsCls = d.status === "FAIL" ? "deduct-pts" : "deduct-pts warn";
            const lvlBadge = d.critical
              ? `<span class="badge redline">致命红线</span>`
              : badgeHtml(d.status);
            return `<tr class="${rowCls}">
              <td class="${ptsCls}">-${d.pts}</td>
              <td>${lvlBadge}</td>
              <td>${escapeHtml(d.catTitle)}</td>
              <td><strong>${escapeHtml(d.title)}</strong></td>
              <td class="mono wrap-cell">${escapeHtml(d.observed)}</td>
            </tr>`;
          })
          .join("");
      }
    }

    const circumference = 326.7;
    const offset = circumference * (1 - score / 100);
    const ring = $("scoreRingFill");
    ring.style.strokeDashoffset = String(offset);

    const redlineEl = $("redlinePill");
    if (redlineEl) {
      if (criticalFail > 0) {
        redlineEl.className = "redline-banner fail";
        redlineEl.textContent = `🚨 致命红线: ${criticalFail} 项（存在真实泄漏/受限地区暴露）`;
      } else {
        redlineEl.className = "redline-banner pass";
        redlineEl.textContent = "✅ 致命红线: 0 项";
      }
    }

    if (criticalFail > 0) {
      ring.style.stroke = "var(--fail)";
      $("verdictTitle").textContent = "触及致命暴露红线";
      $("verdictDesc").textContent = `命中 ${criticalFail} 项致命红线（真实 IP 泄漏、黑名单或受限地区），需立即处理！`;
    } else if (counts.FAIL > 0) {
      ring.style.stroke = "var(--fail)";
      $("verdictTitle").textContent = "存在地区一致性或连通故障";
      $("verdictDesc").textContent = `无真实 IP 泄漏红线，但有 ${counts.FAIL} 项 FAIL 与 ${counts.WARN} 项 WARN（如目标国家不匹配或接口不通）。`;
    } else if (score < 85 || highWarn > 0) {
      ring.style.stroke = "var(--warn)";
      $("verdictTitle").textContent = "存在潜在泄露风险";
      $("verdictDesc").textContent = `有 ${counts.WARN} 项警告建议优化（如未重启刷新时区、DNS 或断流保护）。`;
    } else {
      ring.style.stroke = "var(--pass)";
      $("verdictTitle").textContent = "环境一致性良好";
      $("verdictDesc").textContent = "未发现致命红线或高危冲突项，可留意少量低风险提示。";
    }

    $("cntPass").textContent = String(counts.PASS);
    $("cntWarn").textContent = String(counts.WARN);
    $("cntFail").textContent = String(counts.FAIL);
    $("cntInfo").textContent = String(counts.INFO);

    const eg = report.egress_summary || {};
    $("egressIp").textContent = eg.ip || "--";
    const targetCode = report.target ? report.target.code : "SG";
    const badge = $("egressBadge");
    if (eg.loc && eg.loc === targetCode) {
      badge.className = "badge pass";
      badge.textContent = `CF: ${eg.loc} / ${eg.colo || "-"}`;
    } else {
      badge.className = "badge fail";
      badge.textContent = `CF: ${eg.loc || "?"} / ${eg.colo || "-"}`;
    }
    $("egressMeta").textContent = `${eg.asn || "未知 ASN"} · 时区: ${eg.timezone || "-"} · rDNS: ${eg.rdns || "无"}`;

    $("scanTimestamp").textContent = (report.timestamp || "").replace("T", " ");
    $("scanDuration").textContent = `后端耗时 ${report.duration_ms || 0} ms · 目标: ${report.target ? report.target.name : targetCode}`;
  }

  function renderGeoipMatrix(report) {
    const eg = report.egress_summary || {};
    $("whoisSummaryBar").innerHTML =
      `<strong>WHOIS / 归属线索：</strong>注册国家=<span class="mono">${escapeHtml(eg.whois_countries || "-")}</span>` +
      ` · 机构=<span class="mono">${escapeHtml(eg.whois_orgs || "-")}</span>` +
      ` · Geofeed=<span class="mono">${escapeHtml(eg.geofeed || "无")}</span>` +
      ` · rDNS=<span class="mono">${escapeHtml(eg.rdns || "无")}</span>` +
      ` · IP类型=<span class="mono">${escapeHtml(eg.proxy_type || "-")}</span>` +
      ` · 滥用分=<span class="mono">${escapeHtml(eg.abuser_score || "-")}</span>`;

    const rows = report.geoip_matrix || [];
    if (!rows.length) {
      $("geoipBody").innerHTML = `<tr><td colspan="7" class="empty-cell">暂无数据</td></tr>`;
      return;
    }

    $("geoipBody").innerHTML = rows
      .map((r) => {
        const rowCls = r.match === "FAIL" ? "row-danger" : r.match === "WARN" ? "row-conflict" : "";
        const place = [r.region, r.city].filter(Boolean).join(" / ") || "-";
        const proxyStr = r.proxy === true ? "是 (Risk)" : r.proxy === false ? "否" : "-";
        return `<tr class="${rowCls}">
          <td>${escapeHtml(r.source)}</td>
          <td class="mono">${escapeHtml(r.country || r.error || "-")}</td>
          <td class="wrap-cell">${escapeHtml(place)}</td>
          <td class="mono">${escapeHtml(r.timezone || "-")}</td>
          <td class="wrap-cell">${escapeHtml(r.org || "-")}</td>
          <td>${escapeHtml(proxyStr)}</td>
          <td>${badgeHtml(r.match || "ERR")}</td>
        </tr>`;
      })
      .join("");
  }

  function renderDomainMatrix(report) {
    const rows = report.domain_matrix || [];
    const tpRows = report.third_party_matrix || [];
    const targetCode = report.target ? report.target.code : "SG";
    if (!rows.length && !tpRows.length) {
      $("domainBody").innerHTML = `<tr><td colspan="6" class="empty-cell">暂无数据</td></tr>`;
      return;
    }
    const domainHtml = rows
      .map((r) => {
        const isCnProbe = r.colo === "CN-test";
        let st = "ERR";
        if (r.ok) {
          if (isCnProbe) {
            st = r.ip === (report.egress_summary && report.egress_summary.ip) ? "PASS" : "INFO";
          } else {
            st = r.loc === targetCode ? "PASS" : "FAIL";
          }
        }
        const rowCls = st === "FAIL" ? "row-danger" : "";
        return `<tr class="${rowCls}">
          <td class="mono">${escapeHtml(r.domain)}</td>
          <td class="mono">${escapeHtml(r.ip || r.error || "-")}</td>
          <td>${escapeHtml(r.loc || "-")}</td>
          <td class="mono">${escapeHtml(r.colo || "-")}</td>
          <td class="mono">${escapeHtml(r.latency_ms ? `${r.latency_ms}ms` : "-")}</td>
          <td>${badgeHtml(st)}</td>
        </tr>`;
      })
      .join("");

    const tpHtml = tpRows
      .map((r) => {
        let st = r.ok ? "PASS" : (r.category === "telemetry" ? "WARN" : "FAIL");
        if (r.cf_challenge) st = "WARN";
        if (r.blocked) st = "FAIL";
        const rowCls = st === "FAIL" ? "row-danger" : (st === "WARN" ? "row-conflict" : "");
        const col2 = r.http_code ? `HTTP ${r.http_code}` : (r.error || "ERR");
        const col3 = r.redirect_url
          ? `-> ${r.redirect_url}`
          : (r.cf_challenge ? "CF 人机盾(非地区拦截)" : (r.ok ? "可达" : (r.error || "不可达")));
        const tag = r.category === "edge" ? "准入校验" : (r.category === "critical" ? "关键风控/支付" : "遥测/客服");
        return `<tr class="${rowCls}">
          <td class="mono">${escapeHtml(`${r.name} (${r.domain})`)}</td>
          <td class="mono">${escapeHtml(col2)}</td>
          <td class="wrap-cell">${escapeHtml(col3)}</td>
          <td>${escapeHtml(tag)}</td>
          <td class="mono">${escapeHtml(r.latency_ms ? `${r.latency_ms}ms` : "-")}</td>
          <td>${badgeHtml(st)}</td>
        </tr>`;
      })
      .join("");

    $("domainBody").innerHTML = domainHtml + tpHtml;
  }

  function renderClaudeInventory(report) {
    const rows = report.claude_file_inventory || [];
    const tbody = $("inventoryBody");
    const badge = $("inventoryBadge");
    if (!tbody) return;
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-cell">暂无文件清单数据</td></tr>`;
      return;
    }
    const failCnt = rows.filter((r) => r.status === "FAIL").length;
    const warnCnt = rows.filter((r) => r.status === "WARN").length;
    if (badge) {
      if (failCnt > 0) {
        badge.className = "badge fail";
        badge.textContent = `已扫 ${rows.length} 项 · ${failCnt} 项高危残留 / ${warnCnt} 项警告`;
      } else if (warnCnt > 0) {
        badge.className = "badge warn";
        badge.textContent = `已扫 ${rows.length} 项 · ${warnCnt} 项警告`;
      } else {
        badge.className = "badge pass";
        badge.textContent = `已扫 ${rows.length} 项 · 全部干净`;
      }
    }
    tbody.innerHTML = rows
      .map((r) => {
        const rowCls = r.status === "FAIL" ? "row-danger" : r.status === "WARN" ? "row-conflict" : "";
        return `<tr class="${rowCls}">
          <td>${escapeHtml(r.module)}</td>
          <td><strong>${escapeHtml(r.name)}</strong></td>
          <td class="mono wrap-cell">${escapeHtml(r.path)}</td>
          <td class="wrap-cell">${escapeHtml(r.purpose)}</td>
          <td class="wrap-cell">${escapeHtml(r.observed)}</td>
          <td>${badgeHtml(r.status)}</td>
        </tr>`;
      })
      .join("");
  }

  function renderCategories() {
    if (!lastReport) return;
    const allCats = [
      ...(browserCategory ? [["browser_live", browserCategory]] : []),
      ...Object.entries(lastReport.categories || {}),
    ];

    const html = allCats
      .map(([, cat]) => {
        const checks = (cat.checks || []).filter((c) => {
          if (currentFilter === "issues") return c.status === "FAIL" || c.status === "WARN";
          if (currentFilter === "fail") return c.status === "FAIL";
          return true;
        });
        if (!checks.length) {
          return `<div class="card cat-card">
            <div class="cat-head"><h3>${escapeHtml(cat.title)}</h3>${badgeHtml("PASS")}</div>
            <div class="check-detail">当前筛选条件下无匹配项。</div>
          </div>`;
        }
        const failCnt = checks.filter((c) => c.status === "FAIL").length;
        const warnCnt = checks.filter((c) => c.status === "WARN").length;
        const catBadge = failCnt ? "FAIL" : warnCnt ? "WARN" : "PASS";

        const itemsHtml = checks
          .map((c) => {
            const stCls = `status-${String(c.status || "info").toLowerCase()}`;
            let fixBlock = "";
            if (c.fix_advice || c.fix_cmd) {
              fixBlock = `<div class="check-fix">
                ${c.fix_advice ? `<div>💡 建议：${escapeHtml(c.fix_advice)}</div>` : ""}
                ${
                  c.fix_cmd
                    ? `<div class="cmd-row"><code>${escapeHtml(c.fix_cmd)}</code><button class="copy-btn" data-cmd="${escapeHtml(c.fix_cmd)}">复制命令</button></div>`
                    : ""
                }
              </div>`;
            }
            const redBadge = c.severity === "critical" && c.status === "FAIL" ? `<span class="badge redline">红线</span>` : "";
            return `<div class="check-item ${stCls}">
              <div class="check-top">
                <span class="check-title">${escapeHtml(c.title)}</span>
                <div class="check-badges">${redBadge}${badgeHtml(c.status)}</div>
              </div>
              <div class="check-observed">${escapeHtml(c.observed)}</div>
              <div class="check-detail">${escapeHtml(c.detail)}</div>
              ${fixBlock}
            </div>`;
          })
          .join("");

        return `<div class="card cat-card">
          <div class="cat-head">
            <h3>${escapeHtml(cat.title)}</h3>
            ${badgeHtml(catBadge)}
          </div>
          ${itemsHtml}
        </div>`;
      })
      .join("");

    $("categoriesContainer").innerHTML = html;

    document.querySelectorAll(".copy-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const cmd = btn.getAttribute("data-cmd") || "";
        try {
          await navigator.clipboard.writeText(cmd);
          showToast("修复命令已复制到剪贴板");
        } catch (_) {
          showToast("复制失败，请手动选中复制");
        }
      });
    });
  }

  async function runFullScan() {
    const btn = $("scanBtn");
    const target = $("targetSelect").value;
    btn.disabled = true;
    btn.textContent = "正在全面扫描...";
    $("alertBanner").classList.add("hidden");

    try {
      const resp = await fetch(`/api/scan?target=${encodeURIComponent(target)}`, { cache: "no-store" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const report = await resp.json();
      if (report.error) throw new Error(report.error);

      lastReport = report;
      applyPlatformUi(report);
      browserCategory = await runBrowserLiveAudit(target, report);
      renderSummary(report, browserCategory);
      renderGeoipMatrix(report);
      renderDomainMatrix(report);
      renderClaudeInventory(report);
      renderCategories();
      $("exportBtn").disabled = false;
    } catch (err) {
      $("alertBanner").textContent = `扫描失败: ${err.message || err}`;
      $("alertBanner").classList.remove("hidden");
    } finally {
      btn.disabled = false;
      btn.textContent = "立即全面扫描";
    }
  }

  function renderPulseTable() {
    $("kpiTotal").textContent = String(pulseEvents.length);
    $("kpiAnomaly").textContent = String(pulseAnomalyCount);
    $("kpiJump").textContent = String(pulseJumpCount);
    if ($("kpiWake")) $("kpiWake").textContent = String(pulseWakeCount);

    if (!pulseEvents.length) {
      $("kpiLatency").textContent = "--";
      $("kpiLatest").textContent = "--";
      $("pulseBody").innerHTML = `<tr><td colspan="7" class="empty-cell">暂无监控记录，点击「开启后台持续监控」后即使关闭本网页也会持续探测</td></tr>`;
      return;
    }

    const latest = pulseEvents[pulseEvents.length - 1];
    $("kpiLatency").textContent = `${latest.latency_ms || 0} ms`;
    $("kpiLatest").textContent = `${latest.ip} (${latest.loc}/${latest.colo})`;

    const rows = pulseEvents
      .slice()
      .reverse()
      .map((ev) => {
        const st = ev.anomaly ? "FAIL" : "PASS";
        const rowCls = ev.anomaly ? "row-danger" : "";
        const tunTxt = ev.utun_up ? "在线" : "离线";
        const reasonTxt = ev.anomaly_reasons && ev.anomaly_reasons.length ? ev.anomaly_reasons.join("；") : "正常";
        return `<tr class="${rowCls}">
          <td class="mono">${escapeHtml((ev.timestamp || "").replace("T", " "))}</td>
          <td>${badgeHtml(st)}</td>
          <td class="mono">${escapeHtml(ev.ip)}</td>
          <td class="mono">${escapeHtml(`${ev.loc} / ${ev.colo}`)}</td>
          <td>${escapeHtml(tunTxt)}</td>
          <td class="mono">${escapeHtml(`${ev.latency_ms} ms`)}</td>
          <td>${escapeHtml(reasonTxt)}</td>
        </tr>`;
      })
      .join("");
    $("pulseBody").innerHTML = rows;
  }

  function applyMonitorStatus(data) {
    if (!data) return;
    monitorRunning = Boolean(data.running);
    pulseEvents = Array.isArray(data.items) ? data.items : [];
    pulseAnomalyCount = data.anomaly_count != null ? data.anomaly_count : pulseEvents.filter((e) => e.anomaly).length;
    pulseJumpCount = data.jump_count != null ? data.jump_count : pulseEvents.filter((e) => e.changed_ip).length;
    pulseWakeCount = data.wake_count != null ? data.wake_count : pulseEvents.filter((e) => e.wake_detected).length;

    const btn = $("monitorToggleBtn");
    const badge = $("monitorStateBadge");
    if (monitorRunning) {
      btn.textContent = "停止后台监控";
      btn.classList.add("active");
      if (data.interval_sec && ["15", "30", "60"].includes(String(data.interval_sec))) {
        $("pulseInterval").value = String(data.interval_sec);
      }
      if (badge) {
        badge.className = "badge pass";
        badge.textContent = `后台守护中 (${data.target || "SG"} · 每${data.interval_sec || 30}s · 关网页继续运行)`;
      }
      if (!monitorPollTimer) {
        monitorPollTimer = setInterval(refreshMonitorStatus, 5000);
      }
    } else {
      btn.textContent = "开启后台持续监控";
      btn.classList.remove("active");
      if (badge) {
        badge.className = "badge err";
        badge.textContent = "未开启";
      }
      if (monitorPollTimer) {
        clearInterval(monitorPollTimer);
        monitorPollTimer = null;
      }
    }

    const latest = data.latest;
    if (latest && latest.anomaly && monitorRunning) {
      $("alertBanner").textContent = `⚠️ 后台守护告警 (${(latest.timestamp || "").replace("T", " ")}): ${(latest.anomaly_reasons || []).join("；")}`;
      $("alertBanner").classList.remove("hidden");
    }
    renderPulseTable();
  }

  async function refreshMonitorStatus() {
    try {
      const r = await fetch("/api/monitor/status", { cache: "no-store" });
      if (!r.ok) return;
      const d = await r.json();
      applyMonitorStatus(d);
    } catch (_) {}
  }

  async function toggleMonitor() {
    const btn = $("monitorToggleBtn");
    btn.disabled = true;
    try {
      if (monitorRunning) {
        const r = await fetch("/api/monitor/stop", { method: "POST" });
        if (r.ok) applyMonitorStatus(await r.json());
      } else {
        const target = $("targetSelect").value;
        const intervalSec = Number($("pulseInterval").value) || 30;
        const r = await fetch(
          `/api/monitor/start?target=${encodeURIComponent(target)}&interval=${encodeURIComponent(intervalSec)}`,
          { method: "POST" }
        );
        if (r.ok) applyMonitorStatus(await r.json());
      }
    } catch (_) {
    } finally {
      btn.disabled = false;
    }
  }

  async function clearHistory() {
    try {
      await fetch("/api/history/clear", { method: "POST" });
    } catch (_) {}
    pulseEvents = [];
    pulseAnomalyCount = 0;
    pulseJumpCount = 0;
    pulseWakeCount = 0;
    $("alertBanner").classList.add("hidden");
    renderPulseTable();
  }

  function exportReport() {
    if (!lastReport) return;
    const combined = {
      ...lastReport,
      browser_live: browserCategory,
      pulse_recent: pulseEvents.slice(-50),
    };
    const blob = new Blob([JSON.stringify(combined, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `region-guard-${(lastReport.target && lastReport.target.code) || "SG"}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Event bindings
  const TARGET_STORE_KEY = "region_guard_target_v1";
  try {
    const savedTarget = localStorage.getItem(TARGET_STORE_KEY);
    if (savedTarget && TARGET_PROFILES[savedTarget]) {
      $("targetSelect").value = savedTarget;
    }
  } catch (_) {}

  $("scanBtn").addEventListener("click", runFullScan);
  $("exportBtn").addEventListener("click", exportReport);
  $("monitorToggleBtn").addEventListener("click", toggleMonitor);
  $("clearHistoryBtn").addEventListener("click", clearHistory);
  $("pulseInterval").addEventListener("change", async () => {
    if (monitorRunning) {
      const target = $("targetSelect").value;
      const intervalSec = Number($("pulseInterval").value) || 30;
      const r = await fetch(
        `/api/monitor/start?target=${encodeURIComponent(target)}&interval=${encodeURIComponent(intervalSec)}`,
        { method: "POST" }
      );
      if (r.ok) applyMonitorStatus(await r.json());
    }
  });
  $("targetSelect").addEventListener("change", async () => {
    const target = $("targetSelect").value;
    try {
      localStorage.setItem(TARGET_STORE_KEY, target);
    } catch (_) {}
    if (monitorRunning) {
      const intervalSec = Number($("pulseInterval").value) || 30;
      const r = await fetch(
        `/api/monitor/start?target=${encodeURIComponent(target)}&interval=${encodeURIComponent(intervalSec)}`,
        { method: "POST" }
      );
      if (r.ok) applyMonitorStatus(await r.json());
    }
    runFullScan();
  });

  document.querySelectorAll(".tab-btn").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      currentFilter = tab.getAttribute("data-filter") || "all";
      renderCategories();
    });
  });

  function initManualChecklist() {
    const STORAGE_KEY = "region_guard_manual_checklist_v1";
    let saved = {};
    try {
      saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}") || {};
    } catch (_) {}

    const boxes = Array.from(document.querySelectorAll('#manualChecklist input[type="checkbox"]'));
    const updateCount = () => {
      const done = boxes.filter((b) => b.checked).length;
      const prog = $("checklistProgress");
      if (prog) {
        prog.textContent = `${done} / ${boxes.length} 已确认`;
        prog.className = done === boxes.length ? "badge pass" : "badge info";
      }
      boxes.forEach((b) => {
        const parent = b.closest(".checklist-item");
        if (parent) parent.classList.toggle("checked", b.checked);
      });
    };

    boxes.forEach((box) => {
      const k = box.getAttribute("data-check");
      if (k && saved[k]) box.checked = true;
      box.addEventListener("change", () => {
        if (k) saved[k] = box.checked;
        try {
          localStorage.setItem(STORAGE_KEY, JSON.stringify(saved));
        } catch (_) {}
        updateCount();
      });
    });
    updateCount();
  }

  // Boot
  initManualChecklist();
  refreshMonitorStatus();
  runFullScan();
})();

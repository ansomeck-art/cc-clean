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
  let prefsReady = Promise.resolve();
  let preferenceVersion = 0;
  let preferenceQueue = Promise.resolve();
  let preferenceSaving = false;
  let confirmedPreferences = null;
  let protectionAvailable = null;
  let failedProtectionDisable = false;
  let monitorStatusRequest = null;
  let monitorMutationVersion = 0;
  let monitorDisplayVersion = 0;
  let scanGeneration = 0;
  let activeScanError = "";
  let activeMonitorAlert = "";
  const postHeaders = { "X-Region-Guard": "1", "Content-Type": "application/json" };

  function applyPreferences(prefs) {
    if (!prefs) return;
    confirmedPreferences = { ...prefs };
    if (TARGET_PROFILES[prefs.target]) $("targetSelect").value = prefs.target;
    if ([15, 30, 60].includes(prefs.interval_sec)) $("pulseInterval").value = String(prefs.interval_sec);
    const notify = $("notifyEnabled");
    if (notify && typeof prefs.notify_enabled === "boolean") notify.checked = prefs.notify_enabled;
    const protection = $("protectionEnabled");
    if (protection && typeof prefs.protection_enabled === "boolean" && protectionAvailable !== false) {
      protection.checked = prefs.protection_enabled;
      protection.indeterminate = false;
    }
    if (failedProtectionDisable && prefs.protection_enabled === false) {
      failedProtectionDisable = false;
      if ($("prefsStatus")) $("prefsStatus").textContent = "已确认自动终止关闭";
    }
    const localInterval = $("localGuardInterval");
    if (localInterval && [50, 100, 250, 500].includes(prefs.local_interval_ms)) localInterval.value = String(prefs.local_interval_ms);
    const mode = $("runModeBadge");
    if (mode) mode.textContent = prefs.run_mode === "menubar" ? "菜单栏常驻模式" : "CLI 终端模式";
  }

  async function refreshPreferences() {
    const version = preferenceVersion;
    if (preferenceSaving) return;
    try {
      const prefs = await requestLocalJson("/api/prefs");
      if (version !== preferenceVersion || preferenceSaving) return;
      const changed = prefs.target && prefs.target !== $("targetSelect").value;
      applyPreferences(prefs);
      if (changed && lastReport) runFullScan();
    } catch (_) {}
  }

  function savePreferences(changes) {
    const version = ++preferenceVersion;
    preferenceSaving = true;
    monitorMutationVersion += 1;
    if (changes.protection_enabled === true) failedProtectionDisable = false;
    const send = async () => {
      try {
        const prefs = await requestLocalJson("/api/prefs", { method: "POST", headers: postHeaders, body: JSON.stringify(changes) });
        // FIFO means even an older successful write is the last confirmed server state;
        // remember it for rollback without overwriting a newer user's selection.
        confirmedPreferences = { ...prefs };
        if (version === preferenceVersion) {
          failedProtectionDisable = false;
          applyPreferences(prefs);
          if ($("prefsStatus")) $("prefsStatus").textContent = "偏好已同步";
        }
        return true;
      } catch (_) {
        if (version === preferenceVersion) {
          const disableUnconfirmed = changes.protection_enabled === false &&
            (!confirmedPreferences || confirmedPreferences.protection_enabled !== false);
          if (confirmedPreferences) applyPreferences(confirmedPreferences);
          if (disableUnconfirmed) {
            failedProtectionDisable = true;
            if ($("prefsStatus")) $("prefsStatus").textContent = "关闭未生效或未获确认，原保护可能仍运行；请重试";
            markMonitorUnknown("关闭保护尚未确认，原保护可能仍运行");
          } else if ($("prefsStatus")) {
            $("prefsStatus").textContent = "偏好保存失败，已恢复到最近确认值；请重试";
          }
        }
        return false;
      } finally {
        if (version === preferenceVersion) preferenceSaving = false;
      }
    };
    // Keep rapid target/interval/notification edits ordered on the server as well as in the UI.
    const pending = preferenceQueue.then(send, send);
    preferenceQueue = pending.then(() => {});
    return pending;
  }

  async function requestLocalJson(path, options = {}, timeoutMs = 2500) {
    const controller = typeof AbortController === "function" ? new AbortController() : null;
    let timer = null;
    const settings = { cache: "no-store", ...options };
    if (controller) settings.signal = controller.signal;
    const request = Promise.resolve().then(() => fetch(path, settings)).then((response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    });
    // The VM regression harness intentionally has no timers/AbortController.
    if (typeof setTimeout !== "function") return request;
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => {
        if (controller) controller.abort();
        reject(new Error("local service timeout"));
      }, timeoutMs);
    });
    try {
      return await Promise.race([request, deadline]);
    } finally {
      if (timer !== null && typeof clearTimeout === "function") clearTimeout(timer);
    }
  }

  function markMonitorUnknown(message = "无法连接后台，保护状态未知") {
    const status = $("protectionStatus");
    if (status) {
      status.className = "badge fail";
      status.textContent = "无法确认保护有效；后台连接异常";
    }
    const badge = $("monitorStateBadge");
    if (badge) {
      badge.className = "badge err";
      badge.textContent = "后台连接异常 · 保护状态未知";
    }
    const protection = $("protectionEnabled");
    if (protection && protectionAvailable !== false) protection.indeterminate = true;
    renderLocalTelemetry({ state: "unknown", tone: "warn", label: "后台连接异常，状态未知" });
    renderTrafficObservation(null, { unavailable: true, message: "后台连接异常，当前关联已撤销" });
    activeMonitorAlert = message;
    renderAlerts();
  }

  function renderAlerts() {
    const banner = $("alertBanner");
    banner.textContent = [activeScanError, activeMonitorAlert].filter(Boolean).join("\n");
    banner.classList.toggle("hidden", !banner.textContent);
  }

  function withDeadline(promise, timeoutMs, fallback = null) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(fallback), timeoutMs);
      Promise.resolve(promise).then((value) => { clearTimeout(timer); resolve(value); },
        () => { clearTimeout(timer); resolve(fallback); });
    });
  }

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
          "覆盖 Desktop 深度遥测与指纹文件（传统 %APPDATA%\\Claude 与 MSIX Roaming/Local 容器、ant-did / sentry\\scope_v3.json / fcache / Cookies / cowork-svc 进程 / 日志）、Claude Code CLI、凭据管理器、AppData/Temp/IDE 与全浏览器站点残留（纯只读脱敏）";
      } else {
        invSub.textContent =
          "覆盖 ant-device-* 设备状态、Sentry/CLF、CLI 路径存在性与 Safari 全 Profile、Chromium、Firefox/Zen/Orion 站点元数据；不读取凭据，不枚举 TCC 敏感父目录";
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
        const perm = await withDeadline(navigator.permissions.query({ name: "geolocation" }), 1200);
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
      geoStatus = "INFO";
      geoDetail = "地理位置权限为 prompt（默认询问），当前网站尚未获授权；此状态不表示正在泄漏物理位置。";
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

    const usPreferences = { targetCode, navLang, acceptLang,
      intlLocales: { Date: intlLocale, Number: numLocale, Collator: colLocale, RelativeTime: rtfLocale } };
    const usCheck = typeof RegionGuardLocaleChecks !== "undefined"
      ? RegionGuardLocaleChecks.buildUsRegionCheck(usPreferences)
      : targetCode === "US" ? {
          id: "browser_us_preferences", title: "美国语言与地区偏好（严格 en-US 核验）",
          status: [navLang, acceptLang.split(",")[0].split(";")[0].trim(), intlLocale, numLocale, colLocale, rtfLocale]
            .every((value) => String(value || "").replace(/_/g, "-").toLowerCase() === "en-us") ? "PASS" : "WARN",
          severity: "low", observed: `语言=${navLang}; 区域=${intlLocale}/${numLocale}/${colLocale}/${rtfLocale}`,
          detail: "仅比较 en-US 语言偏好；网络出口需单独核验。", fix_advice: "", fix_cmd: ""
        } : null;
    if (usCheck) checks.push(usCheck);

    // 7. SpeechSynthesis Voices Hidden Chinese OS Leak Probe
    const voices = await probeSpeechVoices();
    const defaultVoice = typeof RegionGuardLocaleChecks !== "undefined"
      ? RegionGuardLocaleChecks.selectDefaultVoice(voices) : voices.find((v) => v.default === true) || null;
    const cnVoices = voices.filter((v) => /^zh[-_]cn/i.test(v.lang || "") || /huihui|kangkang|yaoyao|tingting|xiaoxiao|yunxi/i.test(v.name || ""));
    const defaultIsCn = Boolean(
      defaultVoice &&
        (/^zh[-_]cn/i.test(defaultVoice.lang || "") || /huihui|kangkang|yaoyao|tingting/i.test(defaultVoice.name || ""))
    );
    let voiceStatus = defaultVoice ? "PASS" : "INFO";
    let voiceSev = "low";
    let voiceObs = defaultVoice
      ? `默认语音=${defaultVoice.name} (${defaultVoice.lang}) | 共${voices.length}语音 (zh-CN=${cnVoices.length})`
      : `未报告默认语音 | 共${voices.length}语音`;
    let voiceDetail = defaultVoice ? "speechSynthesis 默认系统语音不含简体中文特征。" : "浏览器未标记默认语音，无法据此判定系统默认语言。";
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
          const p = await withDeadline(navigator.permissions.query({ name: pname }), 1200);
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
        const he = await withDeadline(navigator.userAgentData.getHighEntropyValues(["platform", "platformVersion", "architecture", "bitness"]), 1200, {});
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

    // 11. Canvas 2D & AudioContext Fingerprint Stability (Detects Noisy Anti-Fingerprinting Extensions)
    const fnv1aHex = (str) => {
      let h = 0x811c9dc5;
      for (let i = 0; i < str.length; i++) {
        h ^= str.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
      }
      return (h >>> 0).toString(16).padStart(8, "0");
    };
    const renderCanvasHash = () => {
      try {
        const c = document.createElement("canvas");
        c.width = 240;
        c.height = 50;
        const ctx = c.getContext("2d");
        if (!ctx) return "";
        ctx.textBaseline = "top";
        ctx.font = "14px Arial, sans-serif";
        ctx.fillStyle = "#f60";
        ctx.fillRect(10, 8, 90, 22);
        ctx.fillStyle = "#069";
        ctx.fillText("RegionGuard-FP-2026!", 14, 14);
        ctx.strokeStyle = "rgba(102,204,0,0.7)";
        ctx.beginPath();
        ctx.arc(180, 25, 16, 0, Math.PI * 2);
        ctx.stroke();
        return fnv1aHex(c.toDataURL());
      } catch (_) {
        return "";
      }
    };
    const renderAudioHash = async () => {
      try {
        const OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!OAC) return "";
        const ctx = new OAC(1, 4410, 44100);
        const osc = ctx.createOscillator();
        const comp = ctx.createDynamicsCompressor();
        osc.type = "triangle";
        osc.frequency.value = 10000;
        comp.threshold.value = -50;
        comp.knee.value = 40;
        comp.ratio.value = 12;
        comp.attack.value = 0;
        comp.release.value = 0.25;
        osc.connect(comp);
        comp.connect(ctx.destination);
        osc.start(0);
        const buf = await withDeadline(ctx.startRendering(), 1800);
        if (!buf) return "";
        const ch = buf.getChannelData(0);
        let sum = 0;
        for (let i = 2000; i < 2500; i++) sum += Math.abs(ch[i]);
        return fnv1aHex(sum.toFixed(10));
      } catch (_) {
        return "";
      }
    };
    const canvasH1 = renderCanvasHash();
    const canvasH2 = renderCanvasHash();
    const audioH1 = await renderAudioHash();
    const audioH2 = await renderAudioHash();
    const fingerprintInput = { canvasHashes: [canvasH1, canvasH2], audioHashes: [audioH1, audioH2] };
    checks.push(typeof RegionGuardFingerprintChecks !== "undefined"
      ? RegionGuardFingerprintChecks.buildFingerprintCheck(fingerprintInput)
      : { id: "browser_canvas_audio_fp", title: "Canvas / AudioContext 采样一致性", status: "INFO", severity: "low",
          observed: `Canvas=${canvasH1 || "不可用"}/${canvasH2 || "不可用"} | Audio=${audioH1 || "不可用"}/${audioH2 || "不可用"}`,
          detail: "只记录两次采样；浏览器隐私保护可影响一致性，不能据此判断恶意篡改或 IP 泄漏。", fix_advice: "", fix_cmd: "" });

    // 12. WebGPU Adapter vs WebGL Cross-Check & Storage/Cookie Readiness
    let webgpuStr = "不支持/未启用";
    let webgpuMismatch = false;
    try {
      if (navigator.gpu && navigator.gpu.requestAdapter) {
        const adapter = await withDeadline(navigator.gpu.requestAdapter(), 1200);
        if (adapter) {
          const info = adapter.info || (adapter.requestAdapterInfo ? await withDeadline(adapter.requestAdapterInfo(), 1200, {}) : {});
          const v = info.vendor || "";
          const arch = info.architecture || "";
          const desc = info.description || info.device || "";
          webgpuStr = [v, arch, desc].filter(Boolean).join(" / ") || "WebGPU Adapter";
          const glLow = webglStr.toLowerCase();
          const gpuLow = webgpuStr.toLowerCase();
          if (
            (gpuLow.includes("nvidia") && !glLow.includes("nvidia")) ||
            (gpuLow.includes("amd") && !glLow.includes("amd") && !glLow.includes("radeon")) ||
            (gpuLow.includes("intel") && !glLow.includes("intel"))
          ) {
            webgpuMismatch = true;
          }
        }
      }
    } catch (_) {}
    let quotaMb = "";
    try {
      if (navigator.storage && navigator.storage.estimate) {
        const est = await withDeadline(navigator.storage.estimate(), 1200);
        if (est && est.quota) quotaMb = `${Math.round(est.quota / (1024 * 1024))} MB`;
      }
    } catch (_) {}
    checks.push({
      id: "browser_webgpu_storage",
      title: "WebGPU 显卡交叉核验与浏览器存储配额",
      status: webgpuMismatch ? "FAIL" : "INFO",
      severity: webgpuMismatch ? "high" : "low",
      observed: `WebGPU=${webgpuStr} | StorageQuota=${quotaMb || "-"}`,
      detail: webgpuMismatch
        ? `WebGPU 显卡 (${webgpuStr}) 与 WebGL (${webglStr}) 厂商不一致！说明存在 WebGL 伪装插件穿帮。`
        : "WebGPU 与 WebGL 硬件栈一致（提示：无痕模式配额极小且每次重启清空验证令牌，新号建议使用独立常规 Profile 保持连续可信会话）。",
      fix_advice: webgpuMismatch ? "关闭修改 WebGL 的指纹插件，保持原生显卡栈一致。" : "",
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
        } else if (r.reachable && r.trace_available === false) {
          st = "INFO";
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
        let st = r.status || (r.ok ? "PASS" : (["telemetry", "legacy"].includes(r.category) ? "WARN" : "FAIL"));
        if (r.cf_challenge) st = "INFO";
        if (r.blocked) st = "FAIL";
        if (r.route && r.route.status === "FAIL") st = "FAIL";
        const rowCls = st === "FAIL" ? "row-danger" : (st === "WARN" ? "row-conflict" : "");
        const col2 = r.http_code ? `HTTP ${r.http_code}` : (r.error || "ERR");
        const responseNote = r.note || (r.redirect_url
          ? `-> ${r.redirect_url}`
          : (r.cf_challenge ? "自动探测遇到 CF 挑战，浏览器准入待核验" : (r.ok ? "HTTP 可达" : (r.error || "不可达"))));
        const col3 = r.route ? `${responseNote} · ${r.route.label}` : responseNote;
        const tag = r.category === "edge" ? "准入校验" : (r.category === "critical" ? "关键风控/支付" : (r.category === "legacy" ? "旧版辅助" : "遥测/客服"));
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
            <div class="cat-head"><h3>${escapeHtml(cat.title)}</h3>${badgeHtml("INFO")}</div>
            <div class="check-detail">当前筛选条件下无匹配项。</div>
          </div>`;
        }
        const failCnt = checks.filter((c) => c.status === "FAIL").length;
        const warnCnt = checks.filter((c) => c.status === "WARN").length;
        const catBadge = failCnt ? "FAIL" : warnCnt ? "WARN" : checks.every((check) => check.status === "PASS") ? "PASS" : "INFO";

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
    await prefsReady;
    const generation = ++scanGeneration;
    const btn = $("scanBtn");
    const target = $("targetSelect").value;
    btn.disabled = true;
    btn.textContent = "正在全面扫描...";
    activeScanError = "";
    renderAlerts();

    try {
      const resp = await fetch(`/api/scan?target=${encodeURIComponent(target)}`, { cache: "no-store" });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const report = await resp.json();
      if (report.error) throw new Error(report.error);

      if (generation !== scanGeneration || target !== $("targetSelect").value) return;
      lastReport = report;
      browserCategory = null;
      applyPlatformUi(report);
      renderSummary(report, null);
      renderGeoipMatrix(report);
      renderDomainMatrix(report);
      renderClaudeInventory(report);
      renderCategories();
      btn.textContent = "浏览器实时检测...";
      const browserResult = await withDeadline(runBrowserLiveAudit(target, report), 40000, {
        title: "浏览器实时检测", checks: [{ id: "browser_timeout", title: "浏览器采样未完成", status: "INFO", severity: "low",
          observed: "部分 API 未在时限内返回", detail: "请保持页面前台后复测；未完成不算通过。", fix_advice: "", fix_cmd: "" }]
      });
      if (generation !== scanGeneration || target !== $("targetSelect").value) return;
      lastReport = report;
      applyPlatformUi(report);
      browserCategory = browserResult;
      renderSummary(report, browserCategory);
      renderGeoipMatrix(report);
      renderDomainMatrix(report);
      renderClaudeInventory(report);
      renderCategories();
      $("exportBtn").disabled = false;
    } catch (err) {
      if (generation !== scanGeneration) return;
      activeScanError = `扫描失败: ${err.message || err}`;
      renderAlerts();
    } finally {
      if (generation === scanGeneration) {
        btn.disabled = false;
        btn.textContent = "立即全面扫描";
      }
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

  const trafficGroupNames = { ClaudeDesktop: "Claude 主程序", ClaudeHelper: "Claude Helper" };
  const trafficIngressNames = { tun: "TUN", local_proxy: "本地代理", unknown: "未知" };
  const trafficTransportNames = { proxy: "代理", direct: "DIRECT", unknown: "未知" };
  const trafficRouteNames = { tun: "隧道路由", physical_bypass: "物理绕行", blocked: "阻断路由", local: "本地", unknown: "未知" };
  let trafficHistoryCache = null;
  let trafficCurrentDeadline = null;

  function trafficCounter(value) { return Number.isSafeInteger(value) && value >= 0; }

  function checkedTrafficHistory(raw) {
    const keys = ["observed_connection_total", "new_connection_total", "direct_connection_total", "unknown_connection_total", "physical_bypass_connection_total"];
    if (!raw || !Array.isArray(raw.groups) || raw.groups.length !== 2 ||
        typeof raw.direct_observed !== "boolean" || typeof raw.limited !== "boolean" || !trafficCounter(raw.dedupe_evictions)) return null;
    const groups = raw.groups.map((group, index) => {
      if (!group || group.id !== Object.keys(trafficGroupNames)[index] || !keys.every((key) => trafficCounter(group[key]))) return null;
      return { id: group.id, ...Object.fromEntries(keys.map((key) => [key, group[key]])) };
    });
    return groups.every(Boolean) ? { groups, direct_observed: raw.direct_observed, limited: raw.limited, dedupe_evictions: raw.dedupe_evictions } : null;
  }

  function checkedTrafficGroups(raw) {
    const keys = ["process_count", "socket_count", "matched_count", "new_connection_delta", "physical_bypass_connection_delta"];
    if (!Array.isArray(raw) || raw.length !== 2) return null;
    const groups = raw.map((group, index) => {
      if (!group || group.id !== Object.keys(trafficGroupNames)[index] || !keys.every((key) => trafficCounter(group[key])) ||
          group.matched_count > group.socket_count || group.new_connection_delta > group.socket_count ||
          !validClassCounters(group.ingress_counts, trafficIngressNames) ||
          !validClassCounters(group.transport_counts, trafficTransportNames) || !validClassCounters(group.route_counts, trafficRouteNames)) return null;
      const dimensions = [[group.ingress_counts, trafficIngressNames], [group.transport_counts, trafficTransportNames], [group.route_counts, trafficRouteNames]];
      if (dimensions.some(([counts, names]) => Object.keys(names).reduce((sum, key) => sum + counts[key], 0) !== group.socket_count) ||
          group.physical_bypass_connection_delta > group.route_counts.physical_bypass) return null;
      return { id: group.id, ...Object.fromEntries(keys.map((key) => [key, group[key]])),
        ...Object.fromEntries([["ingress_counts", trafficIngressNames], ["transport_counts", trafficTransportNames], ["route_counts", trafficRouteNames]]
          .map(([key, names]) => [key, Object.fromEntries(Object.keys(names).map((name) => [name, group[key][name]]))])) };
    });
    return groups.every(Boolean) ? groups : null;
  }

  function trafficDimension(counts, names) {
    return Object.entries(names).map(([key, name]) => `${name} ${counts[key]}`).join(" · ");
  }

  function renderTrafficObservation(data, { unavailable = false, message = "" } = {}) {
    const status = $("trafficObservationStatus");
    if (!status) return;
    const backends = { native: "原生只读接口", lsof_fallback: "进程限定 lsof 回退", injected: "隔离测试后端",
      none: data && data.state === "not_running" ? "等待 Claude 进程" : "读取后端待确认" };
    const valid = data && typeof data.running === "boolean" && ["checking", "observed", "unknown", "not_running", "stopped"].includes(data.state) &&
      trafficCounter(data.interval_ms) && data.interval_ms > 0 && data.interval_ms <= 60000 && trafficCounter(data.samples) && trafficCounter(data.event_seq) &&
      Number.isFinite(data.stale_after_ms) && data.stale_after_ms > 0 && Object.hasOwn(backends, data.backend) && data.all_traffic_covered === false;
    const history = valid ? checkedTrafficHistory(data.history) : null;
    if (history) trafficHistoryCache = history;
    const historyNow = history || trafficHistoryCache;
    const groups = valid && data.evidence && data.evidence.all_traffic_covered === false ? checkedTrafficGroups(data.evidence.groups) : null;
    const threshold = valid ? Math.min(data.stale_after_ms, Math.max(1500, data.interval_ms * 3 + 500)) : 0;
    const ageValid = valid && Number.isFinite(data.last_check_age_ms) && data.last_check_age_ms >= 0;
    const stale = valid && (!ageValid || data.last_check_age_ms > threshold);
    const current = !unavailable && monitorRunning && valid && data.running && data.backend !== "none" &&
      data.state === "observed" && !stale && Boolean(groups);
    const partial = current && groups.some((group) => group.matched_count < group.socket_count ||
      group.ingress_counts.unknown || group.transport_counts.unknown || group.route_counts.unknown);
    const bypass = current ? groups.reduce((sum, group) => sum + group.route_counts.physical_bypass, 0) : 0;
    const direct = current ? groups.reduce((sum, group) => sum + group.transport_counts.direct, 0) : 0;
    const pending = !unavailable && monitorRunning && valid && data.running && Array.isArray(data.action_reason_codes) &&
      data.action_reason_codes.includes("connection_route_bypass");
    trafficCurrentDeadline = current ? Date.now() + Math.max(0, threshold - data.last_check_age_ms) : null;
    let label = message;
    if (!label) label = !monitorRunning ? "监控已暂停，当前关联已撤销"
      : !valid ? "当前后台未提供有效连接观察，尚未确认"
        : !data.running || data.state === "stopped" ? "观察已停止，当前关联已撤销"
          : data.state === "not_running" ? "未发现已验证的 Claude 进程"
            : data.state === "checking" ? "正在取得当前连接样本"
              : stale ? "连接样本已陈旧，当前关联已撤销"
                : bypass ? "当前目的路由存在物理绕行样本"
                  : current ? partial ? "部分连接可关联，其余仍未知" : "当前样本可关联，覆盖有限"
                    : "当前连接关联未知，仅作观察提示";
    status.textContent = `后台连接观察：${label}`;
    const paused = !unavailable && (!monitorRunning || valid && (!data.running || ["stopped", "not_running"].includes(data.state)));
    status.className = `badge ${bypass ? "fail" : paused ? "info" : unavailable || !valid || stale || partial ||
      (valid && (data.state === "unknown" || data.state === "observed" && !current)) ? "warn" : "info"}`;
    const details = $("trafficObservationDetails");
    if (details) details.textContent = valid
      ? `后端周期 ${data.interval_ms}ms · ${backends[data.backend]} · 已采样 ${data.samples} 次${ageValid ? ` · 结果距今 ${Math.round(data.last_check_age_ms)}ms` : " · 结果年龄未确认"}${Number.isFinite(data.last_sample_ms) && data.last_sample_ms >= 0 ? ` · 采样耗时 ${Math.round(data.last_sample_ms)}ms` : ""} · 界面约每 1 秒刷新`
      : "当前证明已撤销；历史累计只作为历史参考，不能证明当前连接状态。";
    const body = $("trafficObservationBody");
    if (body) body.innerHTML = Object.entries(trafficGroupNames).map(([id, name]) => {
      const group = current && groups.find((item) => item.id === id);
      const total = historyNow && historyNow.groups.find((item) => item.id === id);
      const cells = [name, group ? `进程 ${group.process_count} · socket ${group.socket_count}` : "未确认 / —",
        group ? `已匹配 ${group.matched_count} · 未匹配 ${group.socket_count - group.matched_count}` : "未确认 / —",
        group ? `新连接 ${group.new_connection_delta} · 绕行 ${group.physical_bypass_connection_delta}` : "—",
        total ? `关联 ${total.observed_connection_total} · 新增 ${total.new_connection_total} · DIRECT ${total.direct_connection_total} · 未知 ${total.unknown_connection_total} · 物理绕行 ${total.physical_bypass_connection_total}` : "历史未确认",
        group ? trafficDimension(group.ingress_counts, trafficIngressNames) : "未确认 / —",
        group ? trafficDimension(group.transport_counts, trafficTransportNames) : "未确认 / —",
        group ? trafficDimension(group.route_counts, trafficRouteNames) : "未确认 / —"];
      return `<tr>${cells.map((cell) => `<td>${escapeHtml(cell)}</td>`).join("")}</tr>`;
    }).join("");
    const route = $("trafficRouteHint");
    if (route) {
      const config = current && data.evidence.route_evidence;
      const flag = (value) => value === true ? "已启用" : value === false ? "未启用" : "未确认";
      route.textContent = current ? `控制器配置：TUN ${flag(config && config.tun_enabled)} · Global ${flag(config && config.global_mode)}。当前控制器 DIRECT ${direct} 个，内核目的路由物理绕行 ${bypass} 个；两者是不同证据。DIRECT 不等同物理直连或中国出口。`
        : "当前控制器与目的路由关联未确认；历史 DIRECT 或绕行次数不作为本轮路由证据。";
      route.className = `section-sub${bypass ? " text-danger" : direct ? " text-warn" : ""}`;
    }
    const action = $("trafficActionStatus");
    if (action) action.textContent = pending ? "已观察待处理：曾记录明确目的路由绕行事件；它是锁存事件，不等同当前新鲜样本或已完成进程终止。"
      : unavailable ? "当前事件处理状态未确认；历史绕行统计不代表当前仍待处理。" : "";
    const note = $("trafficHistoryNote");
    if (note) note.textContent = `${history ? "本次监控累计" : "上次有效监控累计"}仅为历史，暂停后保留、下次启动重置。增量是最近后端样本，不是两次界面刷新之间的总数；新连接首次样本仅建基线，首样本已有明确绕行仍处理。短连接或采样间隙仍可能读不到。${historyNow && (historyNow.limited || historyNow.dedupe_evictions) ? "统计与去重范围有界，各类历史可能重叠，不相加推算总连接或请求数。" : ""}普通关联未知不自动触发强退，明确公网目的路由绕过 TUN 由既有网络保护处理。`;
  }

  function expireTrafficObservation() {
    if (trafficCurrentDeadline !== null && Date.now() > trafficCurrentDeadline) {
      renderTrafficObservation(null, { unavailable: true, message: "连接样本已陈旧，当前关联已撤销" });
    }
  }

  const fileSources = [
    { id: "sentry_scope", name: "Sentry 文化与地区", mode: "fields" },
    { id: "sentry_queue", name: "Sentry 离线队列", mode: "metadata" },
    { id: "app_config", name: "应用配置", mode: "fields" },
    { id: "electron_preferences", name: "Electron 偏好", mode: "fields" },
    { id: "desktop_config", name: "桌面 / MCP 配置", mode: "metadata" },
    { id: "cookie_store", name: "Cookie 存储", mode: "metadata" },
    { id: "installation_id", name: "安装与设备标识", mode: "metadata" },
    { id: "claude_logs", name: "Claude 日志码", mode: "log_codes" },
  ];
  const fileFieldNames = { country: "国家/地区", locale: "区域语言", timezone: "时区" };
  const fileLogNames = { region: "地区", banned: "封禁", evicted: "会话移除", telemetry: "遥测", device: "设备", stripe: "支付", network: "网络" };
  const serviceDiagnosticNames = { region_denied: "服务地区拒绝", permission_denied: "服务权限拒绝", ip_restricted: "IP 限制",
    edge_challenge: "边缘验证", account_banned: "账号封禁", network_timeout: "网络超时",
    http_forbidden_unknown: "403 原因未明", network_error: "网络错误", http_error: "其他 HTTP 错误" };
  const cnFileReasons = ["telemetry_cn_country", "telemetry_cn_locale", "telemetry_cn_timezone"];

  function validClassCounters(value, names) {
    return value && Object.keys(names).every((key) => Number.isSafeInteger(value[key]) && value[key] >= 0);
  }

  function fileSourceViews(rawSources, { paused = false, riskIds = [], intervalMs = 100 } = {}) {
    return fileSources.map((spec) => {
      const matching = Array.isArray(rawSources) ? rawSources.filter((item) => item && item.id === spec.id)
        : rawSources && Object.hasOwn(rawSources, spec.id) ? [rawSources[spec.id]] : [];
      const raw = matching.length === 1 ? matching[0] : null;
      const valid = raw && raw.id === spec.id && raw.mode === spec.mode &&
        ["safe", "risk", "unknown", "missing", "observed", "checking", "stopped"].includes(raw.state) &&
        Array.isArray(raw.field_types) && raw.field_types.every((field) => Object.hasOwn(fileFieldNames, field)) &&
        ["change_count", "file_count", "total_bytes", "files_checked"].every((key) => Number.isSafeInteger(raw[key]) && raw[key] >= 0) &&
        typeof raw.limited === "boolean" && (spec.mode !== "log_codes" ||
          validClassCounters(raw.counters, fileLogNames) || validClassCounters(raw.diagnostics, serviceDiagnosticNames));
      let state = paused ? "stopped" : valid ? raw.state : "unknown";
      const reasons = valid && Array.isArray(raw.reason_codes) ? raw.reason_codes : [];
      const explicitCn = !paused && valid && (riskIds.includes(spec.id) || reasons.some((code) => cnFileReasons.includes(code)));
      if (explicitCn) state = "risk";
      else if (state === "risk") state = "unknown";
      if (["safe", "observed"].includes(state) && (!Number.isFinite(raw.last_check_age_ms) || raw.last_check_age_ms < 0 ||
          raw.last_check_age_ms > Math.max(500, intervalMs * 3 + 250))) state = "unknown";
      if (["safe", "observed"].includes(state) && spec.mode !== "fields") state = "observed";
      const awaitingFields = state === "observed" && spec.mode === "fields" &&
        (spec.id === "sentry_scope" || !raw.field_types.length);
      const labels = { risk: "明确中国大陆字段风险", unknown: "未核验，仅作提示", missing: "未发现，待观察",
        checking: "核验中，仅作提示", stopped: "已暂停" };
      const label = labels[state] || (spec.mode === "metadata" ? "仅观察元数据，地区未核验"
        : spec.mode === "log_codes" ? "已观察日志码，仅作提示"
          : !raw.field_types.length ? "缺少地区字段，待观察" : awaitingFields ? "文化字段暂缺，待观察" : "受检字段未见指定风险");
      const tone = state === "risk" ? "fail" : awaitingFields || ["unknown", "missing", "checking"].includes(state) ? "warn" : "info";
      const modeLabel = spec.mode === "fields" ? "地区字段检查" : spec.mode === "metadata" ? "仅元数据" : "日志码（仅提示）";
      const fields = valid ? [...new Set(raw.field_types)].map((field) => fileFieldNames[field]) : [];
      let detail = spec.mode === "metadata" ? "不读取正文或标识值" : spec.mode === "fields"
        ? `字段类型：${fields.length ? fields.join("、") : "暂无可判定字段"}` : "尚无本观察周期的日志码计数";
      if (valid && spec.mode === "log_codes" && validClassCounters(raw.diagnostics, serviceDiagnosticNames)) {
        detail = Object.entries(serviceDiagnosticNames).map(([key, label]) => `${label} ${raw.diagnostics[key]}`).join(" · ");
      } else if (valid && spec.mode === "log_codes" && validClassCounters(raw.counters, fileLogNames)) {
        detail = Object.entries(fileLogNames).map(([key, label]) => `${label} ${raw.counters[key]}`).join(" · ");
      }
      const counts = !valid || paused ? "—" : `变化 ${raw.change_count} 次 · 文件 ${raw.file_count} 个 · ${raw.total_bytes} B${raw.limited ? " · 有界观察" : " · 范围内快照"}`;
      return { id: spec.id, name: spec.name, mode: spec.mode, state, tone, label, modeLabel,
        detail: paused ? "暂停期间不使用历史结果证明当前状态" : detail, counts, valid: Boolean(valid) };
    });
  }

  function localTelemetryView(guard) {
    const unknown = { state: "unknown", tone: "warn", label: "当前后台未提供文件观察，未验证" };
    if (!guard || typeof guard.supported !== "boolean") return unknown;
    if (!guard.supported) return { state: "stopped", tone: "info", label: "此平台未启用文件守护" };
    if (!monitorRunning || !guard.enabled || (!guard.running && guard.status !== "error")) {
      return { state: "stopped", tone: "info", label: "观察已暂停，不再执行终止动作" };
    }
    if (typeof guard.telemetry_backend_available !== "boolean") return unknown;
    if (!guard.telemetry_backend_available) {
      return { state: "unknown", tone: "warn", label: "文件观察不可用，尚未验证" };
    }
    const item = guard.telemetry;
    const labels = {
      checking: ["warn", "正在核验受检文件"],
      safe: ["info", "受检字段未见指定风险，覆盖有限"],
      observed: ["warn", "地区字段待观察，不据此强退"],
      risk: ["fail", "受检文件出现明确中国大陆字段"],
      unknown: ["warn", "文件未核验，仅作提示"],
      missing: ["warn", "未发现受检文件，尚未验证"],
      stopped: ["warn", "文件观察未运行，尚未验证"],
    };
    if (!item || !Object.hasOwn(labels, item.state) || !Array.isArray(item.field_types) ||
        item.field_types.some((field) => !["country", "locale", "timezone"].includes(field))) return unknown;
    const riskIds = Array.isArray(item.risk_source_ids) ? item.risk_source_ids.filter((id) => fileSources.some((source) => source.id === id)) : [];
    const sources = fileSourceViews(item.sources, { riskIds, intervalMs: Number(guard.poll_interval_ms) || 100 });
    let state = item.state;
    const codes = Array.isArray(item.reason_codes) ? item.reason_codes : [];
    const explicitCn = codes.some((code) => cnFileReasons.includes(code)) || sources.some((source) => source.state === "risk");
    if (explicitCn) state = "risk";
    else if (state === "risk") state = "unknown";
    else if (codes.includes("telemetry_file_stale")) state = "unknown";
    else if (codes.includes("telemetry_file_unknown")) state = "unknown";
    else if (codes.includes("telemetry_file_pending")) state = "checking";
    if (state === "safe" && !item.field_types.length) state = "observed";
    if (["safe", "observed"].includes(state) && (!Number.isFinite(item.last_check_age_ms) || item.last_check_age_ms < 0)) state = "unknown";
    const stale = Number.isFinite(item.last_check_age_ms) &&
      item.last_check_age_ms > Math.max(500, (Number(guard.poll_interval_ms) || 100) * 3 + 250);
    if (stale && state !== "risk") state = "unknown";
    const sourceContractComplete = Array.isArray(item.sources) && item.sources.length === fileSources.length &&
      item.sources.every((source, index) => source && source.id === fileSources[index].id);
    const unverifiedSources = !sourceContractComplete || sources.some((source) =>
      !source.valid || ["unknown", "missing", "checking", "stopped"].includes(source.state));
    if (["safe", "observed"].includes(state) && unverifiedSources) state = "unknown";
    const [tone, label] = labels[state];
    return { state, tone, label: state !== "risk" && (stale || codes.includes("telemetry_file_stale")) ? "观察结果已过期，仅提示未核验"
      : state === "unknown" && unverifiedSources ? "部分来源尚未验证，请查看覆盖列表" : label, item, sources };
  }

  function renderLocalTelemetry(view) {
    const status = $("localTelemetryStatus");
    if (status) {
      status.textContent = `本地文件：${view.label}`;
      status.className = `badge ${view.tone}`;
    }
    const sourceBody = $("fileSourcesBody");
    if (sourceBody) {
      const sources = view.sources || fileSourceViews(null, { paused: view.state === "stopped" });
      sourceBody.innerHTML = sources.map((source) => `<tr><td>${escapeHtml(source.name)}</td><td>${escapeHtml(source.modeLabel)}</td>` +
        `<td><span class="badge ${source.tone}">${escapeHtml(source.label)}</span></td><td>${escapeHtml(source.counts)}</td><td>${escapeHtml(source.detail)}</td></tr>`).join("");
    }
    const details = $("localTelemetryDetails");
    if (!details) return;
    const item = view.item;
    if (!item) {
      details.textContent = view.state === "stopped" ? "暂停期间不使用上次文件结果证明当前安全。" : "未获当前文件观察结果；上次结果不能证明当前安全。";
      return;
    }
    const fields = [...new Set(item.field_types)].map((field) => fileFieldNames[field]);
    const backendNames = { kqueue: "文件事件", "kqueue+poll": "文件事件 + 周期检查", poll: "周期检查",
      stat: "周期状态检查", "kqueue+stat": "文件事件 + 周期状态检查", none: "观察后端未就绪" };
    const metrics = [`字段类型：${fields.length ? fields.join("、") : "暂无"}`];
    if (Number.isSafeInteger(item.files_checked) && item.files_checked >= 0) metrics.push(`本轮解析 ${item.files_checked} 次`);
    if (Number.isFinite(item.last_check_age_ms) && item.last_check_age_ms >= 0) metrics.push(`结果距今 ${Math.round(item.last_check_age_ms)}ms`);
    if (Number.isFinite(item.last_scan_ms) && item.last_scan_ms >= 0) metrics.push(`文件检查 ${Math.round(item.last_scan_ms)}ms`);
    if (Object.hasOwn(backendNames, item.backend)) metrics.push(backendNames[item.backend]);
    details.textContent = metrics.join(" · ");
  }

  function renderProtection(guard) {
    const telemetry = localTelemetryView(guard);
    renderLocalTelemetry(telemetry);
    const status = $("protectionStatus");
    if (!status) return;
    const checkbox = $("protectionEnabled");
    const interval = $("localGuardInterval");
    const action = $("protectionAction");
    if (!guard || typeof guard.supported !== "boolean") {
      protectionAvailable = false;
      status.textContent = "当前后台未提供进程保护；请退出旧版后启动新版";
      status.className = "badge warn";
      if (checkbox) {
        checkbox.disabled = true;
        checkbox.checked = false;
        checkbox.indeterminate = false;
      }
      if (interval) interval.disabled = true;
      if (action) action.textContent = "";
      return;
    }
    protectionAvailable = guard.supported;
    if (checkbox) {
      checkbox.disabled = !guard.supported;
      checkbox.indeterminate = false;
      if (!guard.supported) checkbox.checked = false;
      else if (!preferenceSaving && typeof guard.enabled === "boolean") checkbox.checked = guard.enabled;
    }
    if (interval) interval.disabled = !guard.supported;
    if (!guard.supported) {
      status.textContent = "此平台保留只读监测，未启用自动终止";
      status.className = "badge info";
      if (action) action.textContent = "";
      return;
    }
    if (guard.enabled && guard.status === "error") {
      status.textContent = guard.running ? "进程保护发生错误，自动退出效果待核对" : "保护失效：线程已停止，自动退出不可用";
      status.className = "badge fail";
    } else if (!monitorRunning || !guard.running || !guard.enabled) {
      status.textContent = "自动终止已暂停";
      status.className = "badge info";
    } else {
      const blocked = guard.status === "blocked";
      const processUnconfirmed = blocked && (guard.reason_codes || []).some((code) =>
        code === "process_unknown" || code === "termination_denied");
      const condition = processUnconfirmed ? "进程处理未确认，请手动退出 Claude"
        : telemetry.state === "risk" ? "受检文件命中明确中国大陆字段"
          : blocked ? "网络或进程保护条件未满足"
            : guard.status === "safe" ? "网络已复核；文件未知仅待观察" : "网络条件校验中";
      status.className = `badge ${blocked || telemetry.state === "risk" ? "fail" : guard.status === "safe" ? "info" : "warn"}`;
      status.textContent = `本地 ${guard.poll_interval_ms}ms · ${condition} · 最近采样 ${guard.last_sample_ms || 0}ms`;
    }
    if (action) action.textContent = `${(guard.reasons || []).join("；")}${guard.terminated_total ? ` · 累计强退指令 ${guard.terminated_total} 次` : ""}`;
  }

  function applyMonitorStatus(data) {
    if (!data) return;
    monitorDisplayVersion += 1;
    monitorRunning = Boolean(data.running);
    renderProtection(data.protection);
    renderTrafficObservation(data.traffic);
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
        const guard = data.protection;
        const telemetry = localTelemetryView(guard);
        const protecting = guard && guard.supported && guard.enabled;
        badge.className = `badge ${protecting && ["blocked", "error"].includes(guard.status) || telemetry.state === "risk" ? "fail"
          : protecting && guard.running && guard.status === "safe" ? "info" : "warn"}`;
        const cadence = guard && guard.enabled && guard.running
          ? `本地 ${guard.poll_interval_ms}ms / 公网 ${data.interval_sec || 30}s` : `公网 ${data.interval_sec || 30}s`;
        badge.textContent = `后台监控中 (${data.target || "US"} · ${cadence} · 关网页继续运行)`;
      }
    } else {
      btn.textContent = "开启后台持续监控";
      btn.classList.remove("active");
      if (badge) {
        badge.className = "badge err";
        badge.textContent = "未开启";
      }
    }

    const latest = data.latest;
    activeMonitorAlert = latest && latest.anomaly && monitorRunning
      ? `⚠️ 后台守护告警 (${(latest.timestamp || "").replace("T", " ")}): ${(latest.anomaly_reasons || []).join("；")}` : "";
    if (data.monitor_error && monitorRunning) activeMonitorAlert = `后台守护告警: ${data.monitor_error}`;
    const protection = data.protection;
    if (monitorRunning && protection && protection.enabled && ["blocked", "error"].includes(protection.status)) {
      activeMonitorAlert = `Claude 进程保护: ${(protection.reasons || []).join("；")}`;
      if ((protection.reason_codes || []).some((code) => code === "process_unknown" || code === "termination_denied")) {
        activeMonitorAlert += "；进程处理未确认，请手动退出 Claude";
      }
      if (protection.last_action && protection.last_action.terminated && protection.last_action.event_seq === protection.event_seq) activeMonitorAlert += `；已对 ${protection.last_action.terminated} 个进程发送强退指令`;
    }
    renderAlerts();
    renderPulseTable();
  }

  function refreshMonitorStatus() {
    expireTrafficObservation();
    if (monitorStatusRequest) return monitorStatusRequest;
    const mutation = monitorMutationVersion;
    const displayed = monitorDisplayVersion;
    monitorStatusRequest = (async () => {
      try {
        const data = await requestLocalJson("/api/monitor/status");
        if (!data || typeof data.running !== "boolean") throw new Error("invalid monitor response");
        if (mutation === monitorMutationVersion) applyMonitorStatus(data);
      } catch (_) {
        // A preferences write is not a fresh monitor-status proof. Only a newer
        // applied status may supersede this failure (for example a confirmed stop).
        if (displayed === monitorDisplayVersion) markMonitorUnknown();
      }
    })().finally(() => { monitorStatusRequest = null; });
    return monitorStatusRequest;
  }

  async function toggleMonitor() {
    const btn = $("monitorToggleBtn");
    btn.disabled = true;
    monitorMutationVersion += 1;
    try {
      if (monitorRunning) {
        renderTrafficObservation(null, { unavailable: true, message: "暂停请求待确认，当前关联已撤销" });
        applyMonitorStatus(await requestLocalJson("/api/monitor/stop", { method: "POST", headers: postHeaders }));
      } else {
        const target = $("targetSelect").value;
        const intervalSec = Number($("pulseInterval").value) || 30;
        applyMonitorStatus(await requestLocalJson(
          `/api/monitor/start?target=${encodeURIComponent(target)}&interval=${encodeURIComponent(intervalSec)}`,
          { method: "POST", headers: postHeaders }
        ));
      }
    } catch (_) {
      markMonitorUnknown("启动或暂停请求未确认，保护状态未知");
    } finally {
      btn.disabled = false;
    }
  }

  async function clearHistory() {
    try {
      await fetch("/api/history/clear", { method: "POST", headers: postHeaders });
    } catch (_) {}
    pulseEvents = [];
    pulseAnomalyCount = 0;
    pulseJumpCount = 0;
    pulseWakeCount = 0;
    activeMonitorAlert = "";
    renderAlerts();
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

  let telemetryPoll = null;
  let telemetryPollRound = 0;
  let clientVersionCache = null;
  let clientVersionPoll = null;
  let clientVersionBusy = false;
  let clientVersionMutation = 0;
  let clientVersionDisplay = 0;
  let clientVersionFeedback = "";
  let clientVersionReviewUnconfirmed = false;
  const telemetryCounters = ["checked", "blocked", "held", "unattributed", "tls_requests"];

  function checkedClientVersion(data) {
    if (!data || !["unverified", "unknown", "missing", "changed", "observed"].includes(data.state) ||
        typeof data.review_required !== "boolean" || !Array.isArray(data.versions) || data.versions.length > 2 ||
        data.versions.some((version) => typeof version !== "string" || version.length > 48 || !/^[0-9]{1,10}(?:\.[0-9]{1,10}){1,4}$/.test(version)) ||
        data.versions.some((version, index) => index > 0 && data.versions[index - 1] >= version) ||
        data.current_version !== (data.versions[0] || "")) throw new Error("invalid client version cache");
    return { state: data.state, versions: [...data.versions], current_version: data.current_version, review_required: data.review_required };
  }

  function paintClientVersion() {
    const status = $("clientVersionStatus");
    const button = $("clientVersionReview");
    if (!status && !button) return;
    const pending = Boolean(clientVersionCache && clientVersionCache.review_required);
    const canReview = pending && clientVersionCache.versions.length > 0;
    if (status) {
      const versions = clientVersionCache && clientVersionCache.versions.join(" / ");
      const unverified = !clientVersionCache || ["unverified", "unknown", "missing"].includes(clientVersionCache.state);
      status.textContent = (pending ? `客户端版本 ${versions || "未确认"}：变化提醒待复核（仅提醒）`
        : versions && !unverified ? `客户端版本 ${versions}：当前无待复核提醒；不代表兼容性已全验证。`
          : "客户端版本尚未核验；请等待后台监控或完成一次全面扫描。") + (clientVersionFeedback ? ` ${clientVersionFeedback}` : "");
    }
    if (button) {
      button.hidden = !canReview;
      if (button.classList) button.classList.toggle("hidden", !canReview);
      button.disabled = clientVersionBusy || !canReview;
      button.textContent = clientVersionBusy ? "正在确认…" : "已复核版本变化";
    }
  }

  function renderClientVersion(data, { acknowledged = false } = {}) {
    if (!$("clientVersionStatus") && !$("clientVersionReview")) return;
    const next = checkedClientVersion(data);
    if (clientVersionReviewUnconfirmed && clientVersionCache &&
        next.versions.join("|") !== clientVersionCache.versions.join("|")) {
      clientVersionReviewUnconfirmed = false;
      clientVersionFeedback = "";
    }
    // A failed POST cannot be presented as confirmed merely because its reply
    // was lost. Retain this tuple's reminder until a successful explicit retry.
    if (!acknowledged && clientVersionReviewUnconfirmed && clientVersionCache && clientVersionCache.review_required &&
        !next.review_required && next.versions.join("|") === clientVersionCache.versions.join("|")) {
      paintClientVersion();
      return;
    }
    clientVersionCache = next;
    clientVersionDisplay += 1;
    paintClientVersion();
  }

  function refreshClientVersionStatus() {
    if ((!$("clientVersionStatus") && !$("clientVersionReview")) || clientVersionPoll) return clientVersionPoll;
    const mutation = clientVersionMutation;
    clientVersionPoll = (async () => {
      try {
        const data = await requestLocalJson("/api/client-version/status");
        if (mutation !== clientVersionMutation) return;
        if (!clientVersionReviewUnconfirmed && !clientVersionBusy) clientVersionFeedback = "";
        renderClientVersion(data);
      } catch (_) {
        if (mutation !== clientVersionMutation) return;
        clientVersionFeedback = clientVersionCache && clientVersionCache.review_required
          ? "无法读取最新版本缓存，原提醒仍保留。" : "旧后台未提供版本缓存或连接失败，尚未核验。";
        paintClientVersion();
      }
    })().finally(() => { clientVersionPoll = null; });
    return clientVersionPoll;
  }

  async function reviewClientVersion() {
    if (clientVersionBusy || !clientVersionCache || !clientVersionCache.review_required || !clientVersionCache.versions.length) return false;
    const expected = [...clientVersionCache.versions];
    const displayed = clientVersionDisplay;
    clientVersionBusy = true;
    clientVersionMutation += 1;
    clientVersionFeedback = "";
    paintClientVersion();
    try {
      const data = checkedClientVersion(await requestLocalJson("/api/client-version/review", {
        method: "POST", headers: postHeaders, body: JSON.stringify({ expected_versions: expected }),
      }));
      clientVersionMutation += 1;
      const newerTuple = displayed !== clientVersionDisplay && clientVersionCache.versions.join("|") !== expected.join("|");
      const confirmsExpected = !data.review_required && data.versions.join("|") === expected.join("|");
      clientVersionReviewUnconfirmed = false;
      if (!newerTuple && (data.review_required || confirmsExpected)) renderClientVersion(data, { acknowledged: true });
      clientVersionFeedback = newerTuple || !confirmsExpected
        ? "版本记录已变化，最新待复核提醒已保留。" : "已确认复核；仅更新 RegionGuard 自身版本基线。";
      return !newerTuple && confirmsExpected;
    } catch (_) {
      clientVersionMutation += 1;
      clientVersionReviewUnconfirmed = true;
      clientVersionFeedback = "复核提交未获确认，提醒仍保留；请重试。";
      return false;
    } finally {
      clientVersionBusy = false;
      paintClientVersion();
      if (clientVersionPoll) await clientVersionPoll;
      await refreshClientVersionStatus();
    }
  }

  function validTelemetryCounters(stats) {
    return stats && telemetryCounters.every((key) => Number.isSafeInteger(stats[key]) && stats[key] >= 0);
  }

  function renderTelemetry(data) {
    if (!data || typeof data.running !== "boolean") throw new Error("invalid retired status");
    const retired = data.running === false && (data.state === "retired" || data.retired === true);
    $("telemetryStatus").textContent = retired ? "HTTPS 正文解密已停用" : "解密入口已退役，后台待确认";
    $("telemetryStatus").className = `badge ${retired ? "info" : "warn"}`;
    const history = $("telemetryHistoryCounts");
    if (history) {
      const validCounts = validTelemetryCounters(data.stats);
      history.textContent = retired && validCounts && telemetryCounters.every((key) => data.stats[key] === 0)
        ? "退役状态仅提供兼容零计数；不作为当前覆盖或旧版历史已读取的证据。"
        : validCounts ? `旧版历史累计（不代表当前正文检查或流量覆盖）：放行 ${data.stats.checked} · 拦截 ${data.stats.blocked} · 格式待确认 ${data.stats.held} · 归属未确认 ${data.stats.unattributed} · HTTPS 请求 ${data.stats.tls_requests}`
          : "未提供旧版历史计数；不用于判断当前连接或流量覆盖。";
    }
    const message = $("telemetryMessage");
    if (message) message.textContent = data.running
      ? "当前后台仍报告旧版服务运行；请正常退出旧版 RegionGuard 后打开 3.4.0。此页面不会控制旧服务。"
      : retired ? "未检查上传正文；不安装或移除已有证书。Claude 可按正常方式打开。"
        : "当前后台未提供退役确认；此页面不提供启用、证书操作或筛选启动入口。";
  }

  async function refreshTelemetry() {
    if (telemetryPoll || !$("telemetryStatus")) return;
    telemetryPoll = (async () => {
      const versionRefresh = refreshClientVersionStatus();
      try {
        renderTelemetry(await requestLocalJson("/api/telemetry/status"));
      } catch (_) {
        $("telemetryStatus").textContent = "解密已退役，后台状态未确认";
        $("telemetryStatus").className = "badge warn";
        if ($("telemetryHistoryCounts")) $("telemetryHistoryCounts").textContent = "历史统计未获确认，不用于当前覆盖判断。";
        if ($("telemetryMessage")) $("telemetryMessage").textContent = "无法读取后台退役状态；此页面不会启动解密服务或修改证书。";
      }
      await versionRefresh;
    })().finally(() => { telemetryPoll = null; });
    return telemetryPoll;
  }

  // Event bindings
  if ($("clientVersionReview")) $("clientVersionReview").addEventListener("click", reviewClientVersion);
  $("scanBtn").addEventListener("click", runFullScan);
  $("exportBtn").addEventListener("click", exportReport);
  $("monitorToggleBtn").addEventListener("click", toggleMonitor);
  $("clearHistoryBtn").addEventListener("click", clearHistory);
  $("pulseInterval").addEventListener("change", () => {
    savePreferences({ interval_sec: Number($("pulseInterval").value) });
  });
  $("targetSelect").addEventListener("change", async () => {
    if (await savePreferences({ target: $("targetSelect").value })) runFullScan();
  });
  if ($("protectionEnabled")) $("protectionEnabled").addEventListener("change", () => {
    savePreferences({ protection_enabled: $("protectionEnabled").checked });
  });
  if ($("localGuardInterval")) $("localGuardInterval").addEventListener("change", () => {
    savePreferences({ local_interval_ms: Number($("localGuardInterval").value) });
  });
  if ($("notifyEnabled")) $("notifyEnabled").addEventListener("change", () => {
    savePreferences({ notify_enabled: $("notifyEnabled").checked });
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

  if ($("protectionEnabled")) {
    $("protectionEnabled").disabled = true;
    $("protectionEnabled").checked = false;
    $("protectionEnabled").indeterminate = true;
  }
  if ($("localGuardInterval")) $("localGuardInterval").disabled = true;
  prefsReady = refreshPreferences();
  monitorPollTimer = setInterval(() => {
    refreshPreferences();
    refreshMonitorStatus();
    telemetryPollRound = (telemetryPollRound + 1) % 5;
    if (telemetryPollRound === 0) refreshTelemetry();
  }, 1000);
  refreshTelemetry();

  // Boot
  initManualChecklist();
  refreshMonitorStatus();
  runFullScan();
})();

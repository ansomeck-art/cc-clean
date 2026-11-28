(function (root) {
  function buildUsRegionCheck({ targetCode, navLang, acceptLang, intlLocales }) {
    if (targetCode !== "US") return null;
    const primaryHeader = String(acceptLang || "").split(",")[0].split(";")[0].trim();
    const samples = [
      ["navigator.language", navLang],
      ["Accept-Language", primaryHeader],
      ...["Date", "Number", "Collator", "RelativeTime"].map((name) => [name, (intlLocales || {})[name]]),
    ];
    const mismatches = samples.filter(([, value]) =>
      String(value || "").replace(/_/g, "-").toLowerCase() !== "en-us"
    );
    return {
      id: "browser_us_preferences",
      title: "美国语言与地区偏好（严格 en-US 核验）",
      status: mismatches.length ? "WARN" : "PASS",
      severity: "low",
      observed: samples.map(([name, value]) => `${name}=${value || "未知"}`).join(" | "),
      detail: mismatches.length
        ? `以下语言字段尚未统一为美式英语 en-US：${mismatches.map(([name]) => name).join("、")}。这是语言偏好不一致，不等于发现中国地区或 IP 泄漏。`
        : "本次实际读取的浏览器语言、请求头与区域格式均为 en-US；出口国家另由网络检测核验。",
      fix_advice: mismatches.length
        ? "在系统或浏览器原生语言设置中选用 English (United States)。若当前浏览器仍缓存旧值，保存工作后正常退出并重新打开浏览器，再重新扫描。"
        : "",
      fix_cmd: "",
    };
  }

  function selectDefaultVoice(voices) {
    return voices.find((voice) => voice.default === true) || null;
  }

  const api = { buildUsRegionCheck, selectDefaultVoice };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.RegionGuardLocaleChecks = api;
})(typeof globalThis !== "undefined" ? globalThis : this);

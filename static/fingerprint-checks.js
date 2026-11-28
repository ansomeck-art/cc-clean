(function (root) {
  function sampleSummary(name, hashes) {
    const values = Array.isArray(hashes) ? hashes.slice(0, 2) : [];
    const complete = values.length === 2 && values.every((value) => typeof value === "string" && value.length > 0);
    const stable = complete ? values[0] === values[1] : null;
    const state = !complete ? "采样未完成" : stable ? "两次一致" : "两次不同";
    const display = stable ? values[0] : values.map((value) => value || "不可用").join(" / ");
    return { complete, stable, text: `${name}=${display || "不可用"}（${state}）` };
  }

  function buildFingerprintCheck({ canvasHashes, audioHashes }) {
    const canvas = sampleSummary("Canvas", canvasHashes);
    const audio = sampleSummary("Audio", audioHashes);
    const incomplete = !canvas.complete || !audio.complete;
    const different = canvas.stable === false || audio.stable === false;
    let detail = incomplete
      ? "部分 API 没有返回完整样本，无法判断其采样一致性；不可用不算稳定或检测通过。"
      : different
        ? "观察到两次采样不同。Safari 等浏览器的内置防指纹保护、实现差异或扩展都可能影响结果，单靠两次哈希不能确定原因。"
        : "本次两次采样一致，但这不能证明浏览器未受修改。";
    detail += " 本项只记录采样可复现性，不能据此认定恶意篡改、IP 泄漏、地区异常或账号封禁。";
    return {
      id: "browser_canvas_audio_fp",
      title: "Canvas / AudioContext 采样一致性（信息项）",
      status: "INFO",
      severity: "low",
      observed: `${canvas.text} | ${audio.text}`,
      detail,
      fix_advice: different ? "保留正常的浏览器隐私保护；如有具体网页功能异常，再单独排查兼容性。" : "",
      fix_cmd: "",
    };
  }

  const api = { buildFingerprintCheck };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.RegionGuardFingerprintChecks = api;
})(typeof globalThis !== "undefined" ? globalThis : this);

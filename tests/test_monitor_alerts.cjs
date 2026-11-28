const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

// Exercise the real application handlers without starting network probes.
const source = fs.readFileSync(require.resolve("../static/app.js"), "utf8");
const boot = "  // Boot\n  initManualChecklist();\n  refreshMonitorStatus();\n  runFullScan();";
assert.ok(source.includes(boot), "application boot marker must exist");
const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    const classes = new Set(id === "alertBanner" ? ["hidden"] : []);
    elements.set(id, {
      textContent: "", innerHTML: "", value: "US", disabled: false,
      addEventListener() {},
      classList: {
        add: (name) => classes.add(name),
        remove: (name) => classes.delete(name),
        contains: (name) => classes.has(name),
        toggle(name, force) {
          if (force) classes.add(name);
          else classes.delete(name);
        },
      },
    });
  }
  return elements.get(id);
}
const app = {
  document: { getElementById: element, querySelectorAll: () => [] },
  localStorage: { getItem: () => null },
  setInterval: () => 1, clearInterval() {},
  fetch: async () => ({ ok: false, status: 503 }),
};
vm.runInNewContext(source.replace(boot,
  "  globalThis.handlers = { applyMonitorStatus, runFullScan, clearHistory };"), app);

const failure = { timestamp: "2026-11-25T10:23:08-05:00", anomaly: true,
  anomaly_reasons: ["连接失败(curl: (7))"] };
const success = { ...failure, timestamp: "2026-11-25T10:24:13-05:00",
  anomaly: false, anomaly_reasons: [] };
const banner = element("alertBanner");
const apply = (latest, running = true) => app.handlers.applyMonitorStatus({
  running, target: "US", interval_sec: 30, latest,
  items: latest ? [failure, latest] : [],
});
const hidden = () => banner.classList.contains("hidden");

(async () => {
  apply(failure);
  assert.equal(hidden(), false);
  assert.match(banner.textContent, /后台守护告警.*连接失败/);
  apply(success);
  assert.equal(hidden(), true, "recovery must remove the old alert");
  assert.match(element("pulseBody").innerHTML, /连接失败/, "history must survive recovery");
  apply(failure);
  apply(failure, false);
  assert.equal(hidden(), true, "stopping must remove an active monitor alert");
  apply(failure);
  apply(null);
  assert.equal(hidden(), true, "empty history must remove the monitor alert");

  await app.handlers.runFullScan();
  assert.match(banner.textContent, /扫描失败: HTTP 503/);
  apply(failure);
  assert.match(banner.textContent, /扫描失败: HTTP 503/);
  assert.match(banner.textContent, /后台守护告警/);
  apply(success);
  assert.equal(hidden(), false, "monitor recovery must preserve a scan error");
  assert.equal(banner.textContent, "扫描失败: HTTP 503");
  apply(failure);
  await app.handlers.clearHistory();
  assert.equal(banner.textContent, "扫描失败: HTTP 503", "clearing monitor history must preserve scan errors");
  assert.equal(hidden(), false);
  console.log("Monitor alert recovery, stop, empty history, scan isolation, and history preservation passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });

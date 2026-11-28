const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const elements = new Map();
const element = (id) => {
  if (!elements.has(id)) elements.set(id, { value: 'US', checked: false, textContent: '',
    addEventListener() {}, classList: { add() {}, remove() {}, toggle() {} } });
  return elements.get(id);
};
let prefs = { target: 'US', interval_sec: 30, notify_enabled: true, auto_start_monitor: true, run_mode: 'menubar', protection_enabled: true, local_interval_ms: 100 };
const requests = [];
let fail = false;
const context = { document: { getElementById: element, querySelectorAll: () => [] },
  setInterval() {}, setTimeout, clearTimeout, fetch: async (path, options = {}) => {
    requests.push({ path, options });
    if (options.method === 'POST' && !fail) Object.assign(prefs, JSON.parse(options.body));
    return { ok: !fail, status: fail ? 503 : 200, json: async () => ({ ...prefs }) };
  } };
const source = fs.readFileSync(require.resolve('../static/app.js'), 'utf8');
const boot = '  // Boot\n  initManualChecklist();\n  refreshMonitorStatus();\n  runFullScan();';
vm.runInNewContext(source.replace(boot, '  globalThis.handlers = { applyPreferences, savePreferences, refreshPreferences, withDeadline };'), context);
(async () => {
  assert.equal(await context.handlers.withDeadline(new Promise(() => {}), 2, "incomplete"), "incomplete");
  assert.equal(await context.handlers.withDeadline(Promise.resolve("ready"), 100, "incomplete"), "ready");
  await context.handlers.refreshPreferences();
  assert.equal(element('runModeBadge').textContent, '菜单栏常驻模式');
  assert.equal(element('notifyEnabled').checked, true);
  assert.equal(element('protectionEnabled').checked, true);
  assert.equal(element('localGuardInterval').value, '100');
  assert.equal(await context.handlers.savePreferences({ target: 'JP', notify_enabled: false, interval_sec: 15, protection_enabled: false, local_interval_ms: 50 }), true);
  const last = requests.at(-1);
  assert.equal(last.path, '/api/prefs');
  assert.equal(last.options.headers['X-Region-Guard'], '1');
  assert.equal(element('targetSelect').value, 'JP');
  assert.equal(element('pulseInterval').value, '15');
  assert.equal(element('notifyEnabled').checked, false);
  assert.equal(element('protectionEnabled').checked, false);
  assert.equal(element('localGuardInterval').value, '50');
  prefs = { ...prefs, target: 'SG', run_mode: 'cli' };
  await context.handlers.refreshPreferences();
  assert.equal(element('targetSelect').value, 'SG');
  assert.equal(element('runModeBadge').textContent, 'CLI 终端模式');
  fail = true;
  assert.equal(await context.handlers.savePreferences({ target: 'DE' }), false);
  assert.match(element('prefsStatus').textContent, /保存失败/);
  console.log('Preference roundtrip, security header, external sync and failure state passed');
})().catch((error) => { console.error(error); process.exitCode = 1; });

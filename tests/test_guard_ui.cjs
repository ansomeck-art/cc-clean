const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(require.resolve('../static/app.js'), 'utf8');
const boot = '  // Boot\n  initManualChecklist();\n  refreshMonitorStatus();\n  runFullScan();';
assert.ok(source.includes(boot));

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}
function ok(value) { return { ok: true, status: 200, json: async () => ({ ...value }) }; }
function trafficFixture() {
  return { running: true, state: 'observed', interval_ms: 500, requested_interval_ms: 500,
    stale_after_ms: 2000, samples: 4, event_seq: 2, last_check_age_ms: 5, last_sample_ms: 3,
    backend: 'native', limited: true, all_traffic_covered: false, action_reason_codes: [],
    evidence: { state: 'observed', all_traffic_covered: false, reason_codes: [],
      route_evidence: { tun_enabled: true, global_mode: true }, groups: [
        { id: 'ClaudeDesktop', process_count: 1, socket_count: 2, matched_count: 2,
          new_connection_delta: 1, new_connection_count: 999, physical_bypass_connection_delta: 0,
          ingress_counts: { tun: 2, local_proxy: 0, unknown: 0 }, transport_counts: { proxy: 2, direct: 0, unknown: 0 },
          route_counts: { tun: 2, physical_bypass: 0, blocked: 0, local: 0, unknown: 0 } },
        { id: 'ClaudeHelper', process_count: 2, socket_count: 1, matched_count: 1,
          new_connection_delta: 0, new_connection_count: 999, physical_bypass_connection_delta: 0,
          ingress_counts: { tun: 1, local_proxy: 0, unknown: 0 }, transport_counts: { proxy: 1, direct: 0, unknown: 0 },
          route_counts: { tun: 1, physical_bypass: 0, blocked: 0, local: 0, unknown: 0 } },
      ] }, history: { groups: [
        { id: 'ClaudeDesktop', observed_connection_total: 10, new_connection_total: 4, direct_connection_total: 1, unknown_connection_total: 3, physical_bypass_connection_total: 1 },
        { id: 'ClaudeHelper', observed_connection_total: 5, new_connection_total: 2, direct_connection_total: 0, unknown_connection_total: 1, physical_bypass_connection_total: 0 },
      ], direct_observed: true, dedupe_evictions: 0, limited: true } };
}
function harness({ fastTimeouts = false, oldVersionUi = false, fakeClock = false } = {}) {
  const elements = new Map();
  const element = (id) => {
    if (oldVersionUi && ['clientVersionStatus', 'clientVersionReview'].includes(id)) return null;
    if (!elements.has(id)) {
      const classes = new Set(id === 'alertBanner' ? ['hidden'] : []);
      elements.set(id, {
        value: 'US', checked: id === 'protectionEnabled', disabled: false, indeterminate: false,
        textContent: '', innerHTML: '', className: '', addEventListener() {},
        classList: {
          add: (name) => classes.add(name), remove: (name) => classes.delete(name),
          contains: (name) => classes.has(name),
          toggle(name, force) { if (force) classes.add(name); else classes.delete(name); },
        },
      });
    }
    return elements.get(id);
  };
  const prefs = { target: 'US', interval_sec: 30, notify_enabled: true,
    auto_start_monitor: true, run_mode: 'menubar', protection_enabled: true, local_interval_ms: 100 };
  const sources = [
    ['sentry_scope', 'fields'], ['sentry_queue', 'metadata'], ['app_config', 'fields'],
    ['electron_preferences', 'fields'], ['desktop_config', 'metadata'], ['cookie_store', 'metadata'],
    ['installation_id', 'metadata'], ['claude_logs', 'log_codes'],
  ].map(([id, mode]) => ({ id, mode, state: 'observed', reason_codes: [],
    field_types: mode === 'fields' ? ['locale', 'timezone'] : [], change_count: 0,
    file_count: 1, total_bytes: 100, files_checked: mode === 'fields' ? 1 : 0, last_check_age_ms: 5,
    counters: { region: 0, banned: 0, evicted: 0, telemetry: 0, device: 0, stripe: 0, network: 0 }, limited: true }));
  const guard = { supported: true, enabled: true, running: true, status: 'safe',
    poll_interval_ms: 100, last_sample_ms: 2, reasons: [], reason_codes: [],
    terminated_total: 0, event_seq: 1, last_action: null, telemetry_backend_available: true,
    telemetry: { state: 'safe', reason_codes: [], field_types: ['locale', 'timezone'],
      last_check_age_ms: 5, last_scan_ms: 1, backend: 'kqueue+stat', files_checked: 1, event_seq: 1,
      risk_source_ids: [], sources } };
  const status = { running: true, target: 'US', interval_sec: 30, latest: null, items: [], protection: guard, traffic: trafficFixture() };
  const calls = [];
  let handler = async (path, options) => {
    if (path === '/api/prefs') {
      if (options.method === 'POST') Object.assign(prefs, JSON.parse(options.body));
      return ok(prefs);
    }
    if (path === '/api/monitor/status') return ok(status);
    return { ok: false, status: 503 };
  };
  const context = { document: { getElementById: element, querySelectorAll: () => [] },
    setInterval() {}, clearInterval() {}, AbortController,
    setTimeout: fastTimeouts ? (fn, ms) => setTimeout(fn, Math.min(ms, 5)) : setTimeout,
    clearTimeout,
    fetch: async (path, options = {}) => { calls.push({ path, options }); return handler(path, options); },
  };
  let clockNow = Date.now();
  if (fakeClock) context.Date = class extends Date { static now() { return clockNow; } };
  vm.runInNewContext(source.replace(boot,
    '  globalThis.handlers = { applyPreferences, renderProtection, applyMonitorStatus, refreshMonitorStatus, savePreferences, runFullScan, renderTelemetry, refreshTelemetry, renderTrafficObservation, expireTrafficObservation, renderClientVersion, refreshClientVersionStatus, reviewClientVersion, renderScanCategories: (report) => { lastReport = report; browserCategory = null; renderCategories(); } };'), context);
  return { element, prefs, guard, status, calls, handlers: context.handlers,
    advanceClock(ms) { clockNow += ms; },
    setHandler(value) { handler = value; } };
}
async function settle() { await new Promise((resolve) => setImmediate(resolve)); }

(async () => {
  // A dead/disconnected backend must never leave the last safe/green result on screen,
  // and the independent scan-error slot must survive the connection warning/recovery.
  {
    const h = harness();
    await settle();
    await h.handlers.runFullScan(); // fixture /api/scan is 503
    assert.match(h.element('alertBanner').textContent, /扫描失败: HTTP 503/);
    h.handlers.applyMonitorStatus(h.status);
    assert.match(h.element('protectionStatus').textContent, /网络已复核.*文件未知仅待观察/);
    h.setHandler(async () => ({ ok: false, status: 503 }));
    await h.handlers.refreshMonitorStatus();
    assert.match(h.element('protectionStatus').textContent, /无法确认保护有效/);
    assert.notEqual(h.element('protectionStatus').className, 'badge pass');
    assert.match(h.element('alertBanner').textContent, /扫描失败: HTTP 503/);
    assert.match(h.element('alertBanner').textContent, /保护状态未知/);
    h.setHandler(async (path) => path === '/api/monitor/status' ? ok(h.status) : ok(h.prefs));
    await h.handlers.refreshMonitorStatus();
    assert.match(h.element('protectionStatus').textContent, /网络已复核.*文件未知仅待观察/);
    assert.equal(h.element('alertBanner').textContent, '扫描失败: HTTP 503');
  }
  // A request that never resolves has a deadline. The fallback also aborts the local request.
  {
    const h = harness({ fastTimeouts: true });
    await settle();
    h.handlers.applyMonitorStatus(h.status);
    let signal;
    h.setHandler(async (path, options) => { signal = options.signal; return new Promise(() => {}); });
    await h.handlers.refreshMonitorStatus();
    assert.equal(signal.aborted, true);
    assert.match(h.element('monitorStateBadge').textContent, /保护状态未知/);
    assert.match(h.element('protectionStatus').textContent, /无法确认保护有效/);
    assert.match(h.element('trafficObservationStatus').textContent, /后台连接异常.*关联已撤销/);
    assert.doesNotMatch(h.element('trafficObservationBody').innerHTML, /已匹配 2|socket 2/);
  }
  // Preference writes cannot hide an outstanding status failure; a genuinely newer
  // applied monitor status (such as confirmed pause) must not be overwritten by it.
  {
    const h = harness();
    await settle();
    h.handlers.applyMonitorStatus(h.status);
    const reply = deferred();
    h.setHandler(async (path, options) => {
      if (path === '/api/monitor/status') return reply.promise;
      if (path === '/api/prefs') {
        Object.assign(h.prefs, JSON.parse(options.body));
        return ok(h.prefs);
      }
      return { ok: false, status: 503 };
    });
    const pending = h.handlers.refreshMonitorStatus();
    await settle();
    assert.equal(await h.handlers.savePreferences({ notify_enabled: false }), true);
    reply.resolve({ ok: false, status: 503 });
    await pending;
    assert.match(h.element('protectionStatus').textContent, /无法确认保护有效/);
    const later = deferred();
    h.setHandler(async () => later.promise);
    const oldRequest = h.handlers.refreshMonitorStatus();
    h.handlers.applyMonitorStatus({ ...h.status, running: false,
      protection: { ...h.guard, running: false, status: 'paused' } });
    later.resolve({ ok: false, status: 503 });
    await oldRequest;
    assert.equal(h.element('protectionStatus').textContent, '自动终止已暂停');
  }
  // A worker failure is unavailability, not successful protection/interception.
  {
    const h = harness();
    await settle();
    h.handlers.applyMonitorStatus({ ...h.status,
      protection: { ...h.guard, running: false, status: 'error', reasons: ['本地保护线程已停止'] } });
    assert.match(h.element('protectionStatus').textContent, /保护失效.*自动退出不可用/);
    assert.doesNotMatch(h.element('protectionStatus').textContent, /保护拦截中/);
    assert.match(h.element('alertBanner').textContent, /本地保护线程已停止/);
  }
  // Failed identity/permission handling is not a successful forced exit.
  for (const code of ['process_unknown', 'termination_denied']) {
    const h = harness();
    await settle();
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard, status: 'blocked',
      reason_codes: [code], reasons: ['进程身份或权限无法确认'] } });
    assert.match(h.element('protectionStatus').textContent, /进程处理未确认.*手动退出 Claude/);
    assert.doesNotMatch(h.element('protectionStatus').textContent, /保护拦截中/);
    assert.match(h.element('alertBanner').textContent, /进程处理未确认.*手动退出 Claude/);
  }
  // A rejected disable cannot leave an optimistic unchecked control while the backend remains armed.
  {
    const h = harness();
    await settle();
    h.handlers.applyMonitorStatus(h.status);
    h.handlers.applyPreferences(h.prefs);
    h.element('protectionEnabled').checked = false;
    h.setHandler(async () => ({ ok: false, status: 503 }));
    assert.equal(await h.handlers.savePreferences({ protection_enabled: false }), false);
    assert.equal(h.prefs.protection_enabled, true);
    assert.equal(h.element('protectionEnabled').checked, true);
    assert.match(h.element('prefsStatus').textContent, /关闭未生效.*原保护可能仍运行/);
    assert.match(h.element('protectionStatus').textContent, /无法确认保护有效/);
  }
  // Old backends without a protection capability must not retain HTML's default checkmark.
  // A later supported response must restore working controls and the actual preference state.
  {
    const h = harness();
    await settle();
    h.handlers.applyMonitorStatus({ ...h.status, protection: undefined });
    assert.match(h.element('protectionStatus').textContent, /当前后台未提供进程保护.*启动新版/);
    assert.equal(h.element('protectionEnabled').checked, false);
    assert.equal(h.element('protectionEnabled').disabled, true);
    assert.equal(h.element('localGuardInterval').disabled, true);
    h.handlers.applyPreferences(h.prefs);
    assert.equal(h.element('protectionEnabled').checked, false, 'old backend capability overrides a stray preference flag');
    h.handlers.applyMonitorStatus(h.status);
    assert.equal(h.element('protectionEnabled').disabled, false);
    assert.equal(h.element('localGuardInterval').disabled, false);
    assert.equal(h.element('protectionEnabled').checked, true);
    assert.match(h.element('protectionStatus').textContent, /网络已复核.*文件未知仅待观察/);
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard, supported: false, enabled: false } });
    assert.match(h.element('protectionStatus').textContent, /此平台保留只读监测/);
    assert.equal(h.element('protectionEnabled').checked, false);
    assert.equal(h.element('protectionEnabled').disabled, true);
  }
  // Remember an older successful FIFO write for rollback, but never paint over a newer choice.
  {
    const h = harness();
    await settle();
    h.handlers.applyMonitorStatus(h.status);
    h.handlers.applyPreferences(h.prefs);
    const first = deferred(), second = deferred();
    let posts = 0;
    h.setHandler((path, options) => {
      assert.equal(options.method, 'POST');
      posts += 1;
      return posts === 1 ? first.promise : second.promise;
    });
    h.element('targetSelect').value = 'JP';
    const one = h.handlers.savePreferences({ target: 'JP', protection_enabled: false });
    h.element('targetSelect').value = 'SG';
    h.element('protectionEnabled').checked = true;
    const two = h.handlers.savePreferences({ target: 'SG', protection_enabled: true });
    await settle();
    assert.equal(posts, 1, 'POST requests must remain FIFO');
    Object.assign(h.prefs, { target: 'JP', protection_enabled: false });
    first.resolve(ok(h.prefs));
    assert.equal(await one, true);
    assert.equal(h.element('targetSelect').value, 'SG', 'older ack cannot overwrite a newer choice');
    assert.equal(h.element('protectionEnabled').checked, true);
    await settle();
    second.resolve({ ok: false, status: 503 });
    assert.equal(await two, false);
    assert.equal(h.element('targetSelect').value, 'JP', 'latest rejected write restores last confirmed state');
    assert.equal(h.element('protectionEnabled').checked, false);
  }
  // A retained previous action is a cumulative statistic, never a claim of a new termination.
  {
    const h = harness();
    await settle();
    const blocked = { ...h.guard, status: 'blocked', reasons: ['TUN 接口离线'], reason_codes: ['tun_down'],
      event_seq: 4, terminated_total: 2, last_action: { event_seq: 2, terminated: 2 } };
    h.handlers.applyMonitorStatus({ ...h.status, protection: blocked });
    assert.doesNotMatch(h.element('alertBanner').textContent, /已对.*个进程发送/);
    assert.match(h.element('protectionAction').textContent, /累计强退指令 2 次/);
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...blocked, last_action: { event_seq: 4, terminated: 1 } } });
    assert.match(h.element('alertBanner').textContent, /已对 1 个进程发送强退指令/);
  }
  // File risk/unknown/missing must not inherit a green network-safe badge. Values and
  // paths must never reach the DOM; the file panel only accepts fixed field types.
  for (const field of ['country', 'locale', 'timezone']) {
    const h = harness();
    await settle();
    const telemetry = { ...h.guard.telemetry, state: 'risk', reason_codes: [`telemetry_cn_${field}`],
      field_types: ['country', 'locale', 'timezone'], locale: 'SECRET-LOCALE', timezone: 'SECRET-TIMEZONE',
      path: '/SECRET/Claude/sentry/scope_v3.json', coverage: 'SECRET-COVERAGE' };
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard, telemetry } });
    assert.equal(h.element('localTelemetryStatus').className, 'badge fail');
    assert.match(h.element('localTelemetryStatus').textContent, /受检文件出现明确中国大陆字段/);
    assert.match(h.element('localTelemetryDetails').textContent, /国家\/地区、区域语言、时区/);
    assert.doesNotMatch(h.element('localTelemetryDetails').textContent, /SECRET|scope_v3/);
    assert.notEqual(h.element('protectionStatus').className, 'badge pass');
    assert.notEqual(h.element('monitorStateBadge').className, 'badge pass');
  }
  for (const state of ['unknown', 'checking', 'missing', 'stopped']) {
    const h = harness();
    await settle();
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard,
      telemetry: { ...h.guard.telemetry, state, field_types: [], files_checked: 0 } } });
    assert.notEqual(h.element('localTelemetryStatus').className, 'badge pass', state);
    assert.notEqual(h.element('protectionStatus').className, 'badge pass', state);
    assert.notEqual(h.element('monitorStateBadge').className, 'badge pass', state);
    if (state === 'missing') assert.match(h.element('localTelemetryStatus').textContent, /未发现受检文件，尚未验证/);
  }
  {
    const h = harness();
    await settle();
    const apply = (changes) => h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard, ...changes } });
    apply({ telemetry_backend_available: undefined, telemetry: undefined });
    assert.match(h.element('localTelemetryStatus').textContent, /当前后台未提供.*未验证/);
    assert.equal(h.element('protectionEnabled').disabled, false, 'older file capability does not disable existing process protection');
    assert.notEqual(h.element('protectionStatus').className, 'badge pass');
    apply({ telemetry_backend_available: false });
    assert.match(h.element('localTelemetryStatus').textContent, /文件观察不可用/);
    apply({ telemetry: { ...h.guard.telemetry, field_types: ['SECRET-TYPE'] } });
    assert.doesNotMatch(h.element('localTelemetryDetails').textContent, /SECRET-TYPE/);
    assert.notEqual(h.element('localTelemetryStatus').className, 'badge pass');
    apply({ telemetry: { ...h.guard.telemetry, last_check_age_ms: 2000 } });
    assert.match(h.element('localTelemetryStatus').textContent, /已过期/);
    apply({ telemetry: { ...h.guard.telemetry, files_checked: 0 } });
    assert.notEqual(h.element('localTelemetryStatus').className, 'badge pass');
    for (const last_check_age_ms of [undefined, null, -1, Infinity]) {
      apply({ telemetry: { ...h.guard.telemetry, last_check_age_ms } });
      assert.notEqual(h.element('localTelemetryStatus').className, 'badge pass');
    }
    h.handlers.applyMonitorStatus(h.status);
    assert.equal(h.element('localTelemetryStatus').className, 'badge info', 'a fresh response restores the limited field-verification status');
    assert.match(h.element('localTelemetryDetails').textContent, /本轮解析 1 次/);
    assert.match(h.element('localTelemetryDetails').textContent, /文件事件 \+ 周期状态检查/);
    h.handlers.applyMonitorStatus({ ...h.status, running: false,
      protection: { ...h.guard, running: false, status: 'paused' } });
    assert.match(h.element('localTelemetryStatus').textContent, /观察已暂停/);
    assert.doesNotMatch(h.element('localTelemetryStatus').textContent, /未发现指定风险/);
    h.handlers.applyMonitorStatus(h.status);
    h.setHandler(async () => ({ ok: false, status: 503 }));
    await h.handlers.refreshMonitorStatus();
    assert.match(h.element('localTelemetryStatus').textContent, /连接异常，状态未知/);
    assert.notEqual(h.element('localTelemetryStatus').className, 'badge pass');
  }
  // Eight fixed sources have different contracts: metadata and log codes never
  // establish region safety, and arbitrary backend labels/values stay private.
  {
    const h = harness();
    await settle();
    h.handlers.applyMonitorStatus(h.status);
    const rows = () => h.element('fileSourcesBody').innerHTML;
    assert.equal((rows().match(/<tr>/g) || []).length, 8);
    for (const label of ['Sentry 文化与地区', 'Sentry 离线队列', '应用配置', 'Electron 偏好',
      '桌面 / MCP 配置', 'Cookie 存储', '安装与设备标识', 'Claude 日志码']) assert.ok(rows().includes(label), label);
    assert.equal((rows().match(/仅观察元数据，地区未核验/g) || []).length, 4);
    assert.match(rows(), /日志码（仅提示）/);
    assert.match(rows(), /有界观察/);
    assert.doesNotMatch(rows(), /badge pass/);
    assert.match(h.element('localTelemetryStatus').textContent, /受检字段未见指定风险，覆盖有限/);
    assert.doesNotMatch(h.element('protectionStatus').textContent, /安全条件已确认/);
    const sources = h.guard.telemetry.sources.map((source) => ({ ...source, state: 'safe',
      name: 'SECRET-SOURCE-NAME', path: '/SECRET/ACCOUNT', value: 'SECRET-VALUE',
      backend: 'SECRET-BACKEND', change_count: 88, stable1p: true,
      counters: { ...source.counters, network: 5 } }));
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard,
      telemetry: { ...h.guard.telemetry, sources } } });
    assert.equal((rows().match(/仅观察元数据，地区未核验/g) || []).length, 4);
    assert.match(rows(), /变化 88 次/);
    assert.match(rows(), /网络 5/);
    assert.doesNotMatch(rows(), /SECRET|stable1p|badge pass|已安全|全部通过/);
    assert.equal(h.element('localTelemetryStatus').className, 'badge info', 'ordinary changes and advisory log codes are not CN risk');
    h.handlers.applyMonitorStatus({ ...h.status, running: false,
      protection: { ...h.guard, running: false, status: 'paused' } });
    assert.equal((rows().match(/已暂停/g) || []).length, 8);
    assert.doesNotMatch(rows(), /受检字段未见指定风险|变化 88 次/);
  }
  // Source-specific CN and latched source IDs must identify a fixed source even
  // if its latest snapshot has already returned to ordinary observation.
  for (const id of ['sentry_scope', 'app_config', 'electron_preferences']) {
    const h = harness();
    await settle();
    const sources = h.guard.telemetry.sources.map((source) => source.id === id ?
      { ...source, reason_codes: ['telemetry_cn_locale'] } : source);
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard,
      telemetry: { ...h.guard.telemetry, sources } } });
    assert.match(h.element('fileSourcesBody').innerHTML, /badge fail.*明确中国大陆字段风险/);
    assert.equal(h.element('localTelemetryStatus').className, 'badge fail');
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard,
      telemetry: { ...h.guard.telemetry, risk_source_ids: [id] } } });
    assert.match(h.element('fileSourcesBody').innerHTML, /badge fail.*明确中国大陆字段风险/);
    assert.equal(h.element('localTelemetryStatus').className, 'badge fail');
  }
  // Legacy, missing, duplicate, stale or malformed source proof cannot silently
  // retain the complete-coverage appearance of the previous snapshot.
  for (const replacement of [undefined, [], null]) {
    const h = harness();
    await settle();
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard,
      telemetry: { ...h.guard.telemetry, sources: replacement } } });
    assert.equal((h.element('fileSourcesBody').innerHTML.match(/<tr>/g) || []).length, 8);
    assert.match(h.element('localTelemetryStatus').textContent, /部分来源尚未验证/);
    assert.equal(h.element('localTelemetryStatus').className, 'badge warn');
    assert.notEqual(h.element('monitorStateBadge').className, 'badge pass');
  }
  for (const changes of [{ state: 'missing' }, { state: 'unknown' }, { state: 'checking' },
    { last_check_age_ms: 2000 }, { mode: 'fields' }, { field_types: ['SECRET-RAW-FIELD'] }]) {
    const h = harness();
    await settle();
    const sources = h.guard.telemetry.sources.map((source) => source.id === 'cookie_store' ? { ...source, ...changes } : source);
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard,
      telemetry: { ...h.guard.telemetry, sources } } });
    assert.equal(h.element('localTelemetryStatus').className, 'badge warn');
    assert.doesNotMatch(h.element('fileSourcesBody').innerHTML, /SECRET-RAW-FIELD/);
  }
  {
    const h = harness();
    await settle();
    for (const sources of [[...h.guard.telemetry.sources, h.guard.telemetry.sources[0]],
      [...h.guard.telemetry.sources, { id: 'SECRET-EXTRA-SOURCE' }], [...h.guard.telemetry.sources].reverse(),
      h.guard.telemetry.sources.map((source) => source.id === 'claude_logs' ? { ...source, counters: {} } : source)]) {
      h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard,
        telemetry: { ...h.guard.telemetry, sources } } });
      assert.equal(h.element('localTelemetryStatus').className, 'badge warn');
      assert.doesNotMatch(h.element('fileSourcesBody').innerHTML, /SECRET-EXTRA-SOURCE/);
    }
  }
  // Missing culture/locale/timezone and uncertain file observations are advisory.
  // They must not turn a network-safe guard into a displayed file termination.
  {
    const h = harness();
    await settle();
    const sources = h.guard.telemetry.sources.map((item) => ({ ...item, field_types: [] }));
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard,
      telemetry: { ...h.guard.telemetry, state: 'observed', field_types: [], files_checked: 0, sources } } });
    assert.match(h.element('localTelemetryStatus').textContent, /待观察，不据此强退/);
    assert.equal(h.element('localTelemetryStatus').className, 'badge warn');
    assert.match(h.element('fileSourcesBody').innerHTML, /缺少地区字段，待观察/);
    assert.equal(h.element('protectionStatus').className, 'badge info');
    assert.match(h.element('protectionStatus').textContent, /网络已复核.*文件未知仅待观察/);
    assert.equal(h.element('alertBanner').textContent, '');
    for (const state of ['unknown', 'checking', 'missing']) {
      h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard,
        telemetry: { ...h.guard.telemetry, state, reason_codes: ['telemetry_file_unknown'], last_check_age_ms: 2000 } } });
      assert.notEqual(h.element('localTelemetryStatus').className, 'badge pass');
      assert.equal(h.element('protectionStatus').className, 'badge info');
      assert.equal(h.element('alertBanner').textContent, '');
    }
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard,
      telemetry: { ...h.guard.telemetry, state: 'risk', reason_codes: ['telemetry_file_unknown'],
        sources: h.guard.telemetry.sources.map((item) => item.id === 'sentry_scope'
          ? { ...item, state: 'risk', reason_codes: ['telemetry_file_unknown'] } : item) } } });
    assert.equal(h.element('localTelemetryStatus').className, 'badge warn', 'an unqualified risk enum is not explicit CN evidence');
    assert.equal(h.element('protectionStatus').className, 'badge info');
    assert.equal(h.element('alertBanner').textContent, '');
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard,
      status: 'blocked', reason_codes: ['tun_down'], reasons: ['TUN 接口离线'] } });
    assert.equal(h.element('protectionStatus').className, 'badge fail', 'independent network protection stays strict');
    assert.match(h.element('alertBanner').textContent, /TUN 接口离线/);
  }
  // Nine service-response categories remain distinct; none of these counters is
  // itself proof of a CN file field or a cause for a displayed termination.
  {
    const h = harness();
    await settle();
    const diagnostics = { region_denied: 0, permission_denied: 1, ip_restricted: 2, edge_challenge: 3,
      account_banned: 4, network_timeout: 5, http_forbidden_unknown: 6, network_error: 7, http_error: 8 };
    const sources = h.guard.telemetry.sources.map((item) => item.id === 'claude_logs'
      ? { ...item, diagnostics, raw_message: 'SECRET-LOG-ACCOUNT', hostname: 'SECRET-HOST' } : item);
    h.handlers.applyMonitorStatus({ ...h.status, protection: { ...h.guard,
      telemetry: { ...h.guard.telemetry, state: 'observed', sources } } });
    const rows = h.element('fileSourcesBody').innerHTML;
    for (const expected of ['服务地区拒绝 0', '服务权限拒绝 1', 'IP 限制 2', '边缘验证 3',
      '账号封禁 4', '网络超时 5', '403 原因未明 6', '网络错误 7', '其他 HTTP 错误 8']) assert.ok(rows.includes(expected), expected);
    assert.doesNotMatch(rows, /SECRET|badge fail|badge pass/);
    assert.equal(h.element('protectionStatus').className, 'badge info');
    assert.equal(h.element('alertBanner').textContent, '');
    h.handlers.renderScanCategories({ categories: { observations: { title: '只读观察', checks: [
      { id: 'service_response_diagnostics', title: '服务响应原因', status: 'INFO', observed: '403 原因未明', detail: '不同服务分别判断' },
      { id: 'claude_traffic_coverage', title: '只读连接来源', status: 'INFO', observed: 'PID 归属未确认', detail: 'TUN / Global 不证明全部覆盖' },
      { id: 'client_version_review', title: '客户端版本变化', status: 'INFO', observed: '版本更新待复核', detail: '轻提醒，不因版本变化强退' },
    ] } } });
    const checks = h.element('categoriesContainer').innerHTML;
    for (const title of ['服务响应原因', '只读连接来源', '客户端版本变化']) assert.ok(checks.includes(title));
    assert.doesNotMatch(checks, /badge pass|全部通过/);
  }
  // The retired HTTPS feature is read-only, even if an old backend sends a live
  // session or trusted-certificate flag. No UI action may prepare/trust/launch it.
  {
    const html = fs.readFileSync(require.resolve('../static/index.html'), 'utf8');
    assert.doesNotMatch(html, /id="telemetry(?:Start|Stop|Trust|Launch|Fingerprint|Session|Counts)"/);
    assert.doesNotMatch(source, /function changeTelemetry|api\/telemetry\/\$\{|api\/telemetry\/(?:start|stop|trust|launch)/);
    const h = harness();
    await settle();
    const totals = { checked: 99, blocked: 7, held: 5, unattributed: 3, tls_requests: 120 };
    const data = { state: 'connected', running: true, certificate_trusted: true, client_started: true,
      stats: totals, session_id: 'a'.repeat(32), session_stats: totals, traffic_confirmed: true };
    const before = h.calls.length;
    h.handlers.renderTelemetry(data);
    assert.match(h.element('telemetryStatus').textContent, /解密入口已退役，后台待确认/);
    assert.match(h.element('telemetryMessage').textContent, /仍报告旧版服务运行.*退出旧版/);
    assert.doesNotMatch(h.element('telemetryMessage').textContent, /已观察到|证书已移除|已收到/);
    assert.match(h.element('telemetryHistoryCounts').textContent, /旧版历史累计.*不代表当前.*99/);
    assert.equal(h.calls.length, before, 'rendering retired state never sends a mutation');
    h.handlers.renderTelemetry({ ...data, state: 'retired', running: false });
    assert.match(h.element('telemetryStatus').textContent, /HTTPS 正文解密已停用/);
    assert.match(h.element('telemetryMessage').textContent, /未检查上传正文；不安装或移除已有证书/);
    assert.doesNotMatch(h.element('telemetryMessage').textContent, /a{32}|已观察到|证书已移除/);
    h.handlers.renderTelemetry({ state: 'retired', retired: true, running: false,
      stats: { checked: 0, blocked: 0, held: 0, unattributed: 0, tls_requests: 0 } });
    assert.match(h.element('telemetryHistoryCounts').textContent, /兼容零计数.*不作为当前覆盖或旧版历史已读取的证据/);
    h.setHandler(async () => ({ ok: false, status: 503 }));
    await h.handlers.refreshTelemetry();
    assert.match(h.element('telemetryStatus').textContent, /退役.*状态未确认/);
    assert.match(h.element('telemetryMessage').textContent, /不会启动解密服务或修改证书/);
    assert.ok(h.calls.filter((call) => call.path.startsWith('/api/telemetry/')).every((call) => !call.options.method || call.options.method === 'GET'));
  }
  // Version review is opt-in, writes only the displayed tuple, and never starts
  // automatically during cache polling. Old pages and invalid caches stay inert.
  {
    const html = fs.readFileSync(require.resolve('../static/index.html'), 'utf8');
    assert.match(html, /id="clientVersionReview"[^>]*hidden/);
    const h = harness();
    await settle();
    const pending = { state: 'changed', current_version: '6.28899.6', versions: ['6.28899.6'], review_required: true };
    const reviewed = { ...pending, state: 'observed', review_required: false };
    let saved = false;
    h.setHandler(async (path, options) => {
      if (path === '/api/client-version/status') return ok(saved ? reviewed : pending);
      if (path === '/api/client-version/review') {
        assert.equal(options.method, 'POST');
        assert.equal(options.headers['X-Region-Guard'], '1');
        assert.deepEqual(JSON.parse(options.body), { expected_versions: ['6.28899.6'] });
        saved = true;
        return ok(reviewed);
      }
      return { ok: false, status: 503 };
    });
    await h.handlers.refreshClientVersionStatus();
    assert.equal(h.element('clientVersionReview').hidden, false);
    assert.match(h.element('clientVersionStatus').textContent, /6\.28899\.6.*待复核/);
    assert.equal(h.calls.filter((call) => call.path === '/api/client-version/review').length, 0);
    assert.equal(await h.handlers.reviewClientVersion(), true);
    assert.equal(h.element('clientVersionReview').hidden, true);
    assert.match(h.element('clientVersionStatus').textContent, /当前无待复核提醒/);
    assert.equal(h.calls.filter((call) => call.path === '/api/client-version/review').length, 1);
    const old = harness({ oldVersionUi: true });
    await settle();
    old.handlers.renderClientVersion(pending);
    await old.handlers.refreshClientVersionStatus();
    assert.equal(await old.handlers.reviewClientVersion(), false);
    assert.equal(old.calls.filter((call) => call.path.startsWith('/api/client-version/')).length, 0);
  }
  // A failed submission keeps its reminder even if the transport lost an ACK
  // after a commit. A successful explicit retry may clear that same tuple.
  {
    const h = harness();
    await settle();
    const pending = { state: 'changed', current_version: '6.28899.6', versions: ['6.28899.6'], review_required: true };
    const reviewed = { ...pending, state: 'observed', review_required: false };
    h.handlers.renderClientVersion(pending);
    h.setHandler(async (path) => path === '/api/client-version/status' ? ok(reviewed) : { ok: false, status: 503 });
    assert.equal(await h.handlers.reviewClientVersion(), false);
    assert.equal(h.element('clientVersionReview').hidden, false);
    assert.match(h.element('clientVersionStatus').textContent, /提交未获确认.*提醒仍保留/);
    await h.handlers.refreshClientVersionStatus();
    assert.equal(h.element('clientVersionReview').hidden, false);
    h.setHandler(async () => ok(reviewed));
    assert.equal(await h.handlers.reviewClientVersion(), true);
    assert.equal(h.element('clientVersionReview').hidden, true);
  }
  // A delayed confirmation for version A must never erase a newer cached B hint.
  {
    const h = harness();
    await settle();
    const old = { state: 'changed', current_version: '6.28899.6', versions: ['6.28899.6'], review_required: true };
    const next = { ...old, current_version: '6.28900.1', versions: ['6.28900.1'] };
    const reply = deferred();
    h.handlers.renderClientVersion(old);
    h.setHandler(async (path) => path === '/api/client-version/review' ? reply.promise : ok(next));
    const review = h.handlers.reviewClientVersion();
    await h.handlers.refreshClientVersionStatus();
    assert.match(h.element('clientVersionStatus').textContent, /6\.28900\.1.*待复核/);
    reply.resolve(ok({ ...old, state: 'observed', review_required: false }));
    assert.equal(await review, false);
    assert.equal(h.element('clientVersionReview').hidden, false);
    assert.match(h.element('clientVersionStatus').textContent, /6\.28900\.1.*待复核/);
  }
  {
    const h = harness();
    await settle();
    for (const versions of [[], ['SECRET-RAW-VERSION'], ['6.2', '6.2'], ['6.2', '6.1'], ['6.1', '6.2', '6.3']]) {
      h.setHandler(async () => ok({ state: 'changed', current_version: versions[0] || '', versions, review_required: true }));
      await h.handlers.refreshClientVersionStatus();
      assert.equal(h.element('clientVersionReview').hidden, true);
      assert.equal(await h.handlers.reviewClientVersion(), false);
      assert.doesNotMatch(h.element('clientVersionStatus').textContent, /SECRET-RAW-VERSION/);
    }
    assert.equal(h.calls.filter((call) => call.path === '/api/client-version/review').length, 0);
  }
  // The background observer separates two current groups, frame deltas and
  // outer history. Private correlation keys and legacy cumulative aliases stay hidden.
  {
    const h = harness();
    await settle();
    const traffic = trafficFixture();
    traffic.coverage = 'SECRET-COVERAGE';
    traffic.evidence.groups[0].path = '/SECRET/ACCOUNT/Claude';
    traffic.evidence.groups[0].address = 'SECRET-IP';
    traffic.evidence.groups[0].pid = 12345678;
    h.handlers.applyMonitorStatus({ ...h.status, traffic });
    const rows = h.element('trafficObservationBody').innerHTML;
    assert.equal((rows.match(/<tr>/g) || []).length, 2);
    assert.match(rows, /Claude 主程序/);
    assert.match(rows, /Claude Helper/);
    assert.match(rows, /socket 2/);
    assert.match(rows, /已匹配 2 · 未匹配 0/);
    assert.match(rows, /新连接 1 · 绕行 0/);
    assert.match(rows, /关联 10 · 新增 4 · DIRECT 1 · 未知 3 · 物理绕行 1/);
    assert.doesNotMatch(rows, /SECRET|12345678|999/);
    assert.match(h.element('trafficObservationStatus').textContent, /当前样本可关联，覆盖有限/);
    assert.notEqual(h.element('trafficObservationStatus').className, 'badge pass');
    assert.match(h.element('trafficRouteHint').textContent, /当前控制器 DIRECT 0 个，内核目的路由物理绕行 0 个/);
    assert.match(h.element('trafficHistoryNote').textContent, /仅为历史.*最近后端样本.*短连接/);
    assert.equal(h.calls.filter((call) => call.options.method === 'POST').length, 0);
  }
  // Partial association and ordinary unknowns are advisory. Controller DIRECT
  // is distinct from an actual kernel destination-route bypass.
  {
    const h = harness();
    await settle();
    const partial = trafficFixture();
    Object.assign(partial.evidence.groups[0], { matched_count: 1,
      ingress_counts: { tun: 1, local_proxy: 0, unknown: 1 }, transport_counts: { proxy: 1, direct: 0, unknown: 1 },
      route_counts: { tun: 1, physical_bypass: 0, blocked: 0, local: 0, unknown: 1 } });
    h.handlers.applyMonitorStatus({ ...h.status, traffic: partial });
    assert.match(h.element('trafficObservationStatus').textContent, /部分连接可关联，其余仍未知/);
    assert.equal(h.element('trafficObservationStatus').className, 'badge warn');
    assert.equal(h.element('protectionStatus').className, 'badge info');
    assert.equal(h.element('alertBanner').textContent, '');
    const direct = trafficFixture();
    direct.evidence.groups[0].transport_counts = { proxy: 1, direct: 1, unknown: 0 };
    h.handlers.applyMonitorStatus({ ...h.status, traffic: direct });
    assert.notEqual(h.element('trafficObservationStatus').className, 'badge fail');
    assert.match(h.element('trafficRouteHint').textContent, /DIRECT 1 个，内核目的路由物理绕行 0 个/);
    assert.match(h.element('trafficRouteHint').textContent, /DIRECT 不等同物理直连或中国出口/);
    assert.equal(h.element('trafficActionStatus').textContent, '');
    const bypass = trafficFixture();
    Object.assign(bypass.evidence.groups[0], { physical_bypass_connection_delta: 1,
      route_counts: { tun: 1, physical_bypass: 1, blocked: 0, local: 0, unknown: 0 } });
    bypass.action_reason_codes = ['connection_route_bypass'];
    h.handlers.applyMonitorStatus({ ...h.status, traffic: bypass });
    assert.equal(h.element('trafficObservationStatus').className, 'badge fail');
    assert.match(h.element('trafficRouteHint').textContent, /DIRECT 0 个，内核目的路由物理绕行 1 个/);
    assert.match(h.element('trafficActionStatus').textContent, /已观察待处理.*锁存事件.*不等同当前新鲜样本/);
    assert.doesNotMatch(h.element('trafficActionStatus').textContent, /中国区域已确认|已对.*发送/);
  }
  // Stopped, unknown, stale or disconnected snapshots revoke all current cells.
  // A retained action latch is explicitly past observation, while history stays history.
  {
    const h = harness();
    await settle();
    h.handlers.applyMonitorStatus(h.status);
    const stale = { ...trafficFixture(), last_check_age_ms: 2001, action_reason_codes: ['connection_route_bypass'] };
    h.handlers.applyMonitorStatus({ ...h.status, traffic: stale });
    assert.match(h.element('trafficObservationStatus').textContent, /陈旧.*关联已撤销/);
    assert.doesNotMatch(h.element('trafficObservationBody').innerHTML, /已匹配 2|socket 2|新连接 1/);
    assert.match(h.element('trafficObservationBody').innerHTML, /关联 10/);
    assert.match(h.element('trafficActionStatus').textContent, /已观察待处理/);
    for (const state of ['unknown', 'checking', 'not_running', 'stopped']) {
      h.handlers.applyMonitorStatus({ ...h.status, traffic: { ...trafficFixture(), state, running: state !== 'stopped' } });
      assert.doesNotMatch(h.element('trafficObservationBody').innerHTML, /已匹配 2|socket 2/);
    }
    h.handlers.applyMonitorStatus({ ...h.status, traffic: { ...trafficFixture(), state: 'not_running', backend: 'none' } });
    assert.match(h.element('trafficObservationDetails').textContent, /等待 Claude 进程/);
    assert.doesNotMatch(h.element('trafficObservationDetails').textContent, /后端未就绪/);
    h.handlers.applyMonitorStatus({ ...h.status, running: false, traffic: trafficFixture() });
    assert.match(h.element('trafficObservationStatus').textContent, /监控已暂停/);
    assert.equal(h.element('trafficActionStatus').textContent, '');
    h.handlers.applyMonitorStatus(h.status);
    h.setHandler(async () => ({ ok: false, status: 503 }));
    await h.handlers.refreshMonitorStatus();
    assert.match(h.element('trafficObservationStatus').textContent, /后台连接异常.*关联已撤销/);
    assert.doesNotMatch(h.element('trafficObservationBody').innerHTML, /已匹配 2|socket 2/);
    assert.match(h.element('trafficObservationBody').innerHTML, /关联 10/);
    assert.match(h.element('trafficHistoryNote').textContent, /上次有效监控累计/);
    h.handlers.applyMonitorStatus(h.status);
    assert.match(h.element('trafficObservationBody').innerHTML, /已匹配 2/);
    assert.match(h.element('trafficObservationStatus').textContent, /当前样本可关联/);
    const reset = trafficFixture();
    reset.state = 'checking';
    reset.history.groups.forEach((group) => Object.keys(group).forEach((key) => { if (key !== 'id') group[key] = 0; }));
    reset.history.direct_observed = false;
    h.handlers.applyMonitorStatus({ ...h.status, traffic: reset });
    assert.match(h.element('trafficObservationBody').innerHTML, /关联 0 · 新增 0/);
    assert.doesNotMatch(h.element('trafficObservationBody').innerHTML, /关联 10|已匹配 2/);
  }
  // Existing one-second polling also expires previously painted evidence while
  // another status request is stuck; this needs no additional browser timer.
  {
    const h = harness({ fakeClock: true });
    await settle();
    h.handlers.applyMonitorStatus(h.status);
    h.advanceClock(2500);
    h.handlers.expireTrafficObservation();
    assert.match(h.element('trafficObservationStatus').textContent, /陈旧.*关联已撤销/);
    assert.doesNotMatch(h.element('trafficObservationBody').innerHTML, /已匹配 2|socket 2/);
    assert.match(h.element('trafficObservationBody').innerHTML, /关联 10/);
    const fallback = { ...trafficFixture(), backend: 'lsof_fallback', interval_ms: 2000, stale_after_ms: 6500, last_check_age_ms: 2500 };
    h.handlers.applyMonitorStatus({ ...h.status, traffic: fallback });
    assert.match(h.element('trafficObservationStatus').textContent, /当前样本可关联/);
    assert.match(h.element('trafficObservationDetails').textContent, /后端周期 2000ms.*lsof 回退/);
    h.handlers.applyMonitorStatus({ ...h.status, traffic: undefined });
    assert.match(h.element('trafficObservationStatus').textContent, /未提供有效连接观察/);
  }
  {
    const h = harness();
    await settle();
    for (const traffic of [{ ...trafficFixture(), all_traffic_covered: true }, { ...trafficFixture(), backend: 'SECRET-BACKEND' },
      { ...trafficFixture(), evidence: { ...trafficFixture().evidence, groups: [] } }]) {
      h.handlers.applyMonitorStatus({ ...h.status, traffic });
      assert.doesNotMatch(h.element('trafficObservationBody').innerHTML, /已匹配 2|socket 2/);
      assert.doesNotMatch(h.element('trafficObservationDetails').textContent, /SECRET-BACKEND/);
    }
  }
  console.log('Guard UI: policy/privacy, retired HTTPS, explicit version review and continuous traffic proof/history/route/stale recovery passed');
})().catch((error) => { console.error(error); process.exitCode = 1; });

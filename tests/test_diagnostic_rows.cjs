const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(require.resolve('../static/app.js'), 'utf8');
const boot = '  // Boot\n  initManualChecklist();\n  refreshMonitorStatus();\n  runFullScan();';
assert.ok(source.includes(boot));
const elements = new Map();
const element = (id) => {
  if (!elements.has(id)) elements.set(id, { value: 'US', innerHTML: '', addEventListener() {} });
  return elements.get(id);
};
const context = { document: { getElementById: element, querySelectorAll: () => [] },
  setInterval() {}, clearInterval() {} };
vm.runInNewContext(source.replace(boot, '  globalThis.render = renderDomainMatrix;'), context);
const render = (row, domain = false) => {
  context.render({ target: { code: 'US' }, [domain ? 'domain_matrix' : 'third_party_matrix']: [row] });
  return element('domainBody').innerHTML;
};

assert.match(render({ domain: 'downloads.claude.ai', ok: false, reachable: true, trace_available: false }, true), /badge info/);
assert.doesNotMatch(render({ domain: 'downloads.claude.ai', ok: false, reachable: true, trace_available: false }, true), /badge pass/);
assert.match(render({ name: 'Statsig', domain: 'statsig.anthropic.com', category: 'legacy', ok: false,
  status: 'INFO', retired: true, note: '公共 DNS 返回 NXDOMAIN' }), /badge info/);
assert.match(render({ name: 'Statsig', domain: 'statsig.anthropic.com', category: 'legacy', ok: false,
  status: 'WARN', retired: false }), /badge warn/);
assert.match(render({ name: 'Stripe', domain: 'api.stripe.com', category: 'critical', ok: false }), /badge fail/);
const payment = { name: 'Stripe', domain: 'js.stripe.com', category: 'critical', ok: true,
  http_code: 200, route: { status: 'PASS', label: '实时路由：代理 VLESS' } };
assert.match(render(payment), /代理 VLESS/);
assert.match(render({ ...payment, route: { status: 'FAIL', label: '支付接口正在直连' } }), /badge fail/);
assert.match(render({ name: 'Claude', domain: 'claude.ai', ok: true, cf_challenge: true }), /badge info/);
console.log('Diagnostic rows: payment bypass, live routes, legacy DNS uncertainty and missing trace passed');

const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const zlib = require('node:zlib');
const path = require('node:path');
const crypto = require('node:crypto');
const policy = require('../telemetry_filter/policy.js');
const codec = require('../telemetry_filter/vendor/fflate-0.8.3.js');
const root = path.resolve(__dirname, '..');
const url = 'https://api.anthropic.com/api/event_logging/v2/batch';
let cases = 0;
function request(body, extra = {}) {
  return { url, method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: typeof body === 'string' || body instanceof Uint8Array ? body : JSON.stringify(body), ...extra };
}
function check(body, action, reason, extra) {
  const actual = policy.inspect(request(body, extra), codec);
  assert.equal(actual.action, action, JSON.stringify(actual));
  if (reason) assert.equal(actual.reason, reason);
  cases++;
  return actual;
}
for (const value of ['CN', 'cn', 'CHN', 'PRC', '156', 156, 'China', 'Mainland China',
  "People's Republic of China", '中国', '中国大陆', '中华人民共和国']) {
  assert.deepEqual(check({ environment: { country_code: value } }, 'block', 'cn_fields').fields, ['cn_country']);
}
for (const timezone of ['Asia/Shanghai', 'Asia/Chongqing', 'Asia/Harbin', 'Asia/Urumqi', 'Asia/Kashgar', 'PRC']) {
  assert.deepEqual(check({ contexts: { culture: { timezone } } }, 'block').fields, ['cn_timezone']);
}
for (const locale of ['zh-CN', 'zh-Hans-CN', 'en_CN.UTF-8']) check({ locale }, 'block');
for (const region of ['CN', 'CN-31', 'cn-north-1']) check({ region }, 'block');
for (const country of ['US', 'SG', 'HK', 'MO', 'TW', 'Congo', 'France']) check({ country }, 'pass', 'checked');
for (const timezone of ['Asia/Singapore', 'Asia/Taipei', 'Asia/Hong_Kong', 'Etc/GMT-8', 'UTC+08:00']) check({ timezone }, 'pass');
for (const locale of ['zh', 'zh-Hans', 'zh-TW', 'en-US']) check({ locale }, 'pass');
check({ languages: ['en-US', 'zh-Hans'], message: 'Discuss China, CN, Asia/Shanghai and 中国' }, 'pass');
check({ message: { country: 'CN' }, prompt: { timezone: 'Asia/Shanghai' },
  request: { headers: { country: 'CN' } }, content: '{"country":"CN"}' }, 'pass');
check({ region: 'US-CA', timezone_offset: -480, city: 'Shanghai', name: 'CN' }, 'pass');
check({ tags: [['country', 'CN']] }, 'block');
check({ tags: ['country:CN', 'service:claude'] }, 'block');
check({ resource: { attributes: [{ key: 'geo.country.iso_code', value: { stringValue: 'CN' } }] } }, 'block');
check({ metadata: JSON.stringify({ country_code: 'CN' }) }, 'block');
check({ attributes: [{ key: 'metadata', value: { stringValue: '{"timezone":"Asia/Shanghai"}' } }] }, 'block');
check({ event_data: '{"country":"CN"}' }, 'block');
check({ events: [{ country: 'US' }, { contexts: { culture: { timezone: 'Asia/Shanghai' } } }] }, 'block');
check({ country: 'US' }, 'block', 'cn_fields', { url: url + '?country=CN' });
check({ country: 'US' }, 'block', 'cn_fields', { headers: { 'x-country-code': 'CN' } });
check({ country: 'US' }, 'block', 'cn_fields', { headers: [{ field: 'X-Timezone', value: 'Asia/Shanghai' }] });
check('{"country":"CN","country":"US"}', 'hold', 'duplicate_json_key');
check('{"country":"US","co\\u0075ntry":"CN"}', 'hold', 'duplicate_json_key');
check('not JSON', 'hold');
check('', 'hold', 'body_unavailable');
check(new Uint8Array([123, 34, 120, 34, 58, 34, 0xc0, 0xaf, 34, 125]), 'hold', 'invalid_utf8');
check('{"value":' + '['.repeat(40) + '0' + ']'.repeat(40) + '}', 'hold', 'structure_limit');
check({ values: new Array(31000).fill(0) }, 'hold', 'structure_limit');
check('x'.repeat(policy.limits.raw + 1), 'hold', 'body_limit');
for (const compression of ['gzip', 'deflate', 'raw']) {
  const raw = Buffer.from(JSON.stringify({ contexts: { culture: { timezone: 'Asia/Shanghai' } } }));
  const body = compression === 'gzip' ? zlib.gzipSync(raw) : compression === 'deflate' ? zlib.deflateSync(raw) : zlib.deflateRawSync(raw);
  check(body, 'block', 'cn_fields', { headers: { 'Content-Encoding': compression === 'gzip' ? 'gzip' : 'deflate' } });
}
check(zlib.gzipSync(Buffer.from('{"country":"US"}')), 'pass', 'checked', { headers: { 'Content-Encoding': 'gzip' } });
check('{"country":"US"}', 'pass', 'checked', { headers: { 'Content-Encoding': 'gzip' } });
check(zlib.brotliCompressSync(Buffer.from('{"country":"CN"}')), 'hold', 'unsupported_encoding', { headers: { 'Content-Encoding': 'br' } });
check(zlib.gzipSync(Buffer.alloc(policy.limits.decoded + 100, 32)), 'hold', 'decoded_body_limit', { headers: { 'Content-Encoding': 'gzip' } });

const sentry = 'https://o1158394.ingest.us.sentry.io/api/123/envelope/';
function envelope(payload, type = 'event') {
  const bytes = Buffer.from(JSON.stringify(payload));
  return Buffer.concat([Buffer.from('{}\n' + JSON.stringify({ type, length: bytes.length }) + '\n'), bytes, Buffer.from('\n')]);
}
check(envelope({ contexts: { culture: { timezone: 'Asia/Shanghai' } } }), 'block', 'cn_fields', { url: sentry });
check(envelope({ country: 'US', message: '你好，中国' }), 'pass', 'checked', { url: sentry });
check(envelope({ country: 'US' }, 'attachment'), 'hold', 'uninspectable_envelope_item', { url: sentry });
check('{}\n{"type":"event","length":999}\n{}', 'hold', 'invalid_envelope', { url: sentry });
check('{}\n{"type":"event"}\n{"country":"CN"}', 'block', 'cn_fields', { url: sentry });
const dd = 'https://browser-intake-us5-datadoghq.com/api/v2/rum';
check({ service: 'claude-ai', country: 'CN' }, 'block', 'cn_fields', { url: dd });
check({ service: 'another-app', country: 'CN' }, 'pass', 'unattributed_shared_host', { url: dd });
check({ country: 'CN' }, 'pass', 'unattributed_shared_host', { url: dd });
check('{"service":"claude-ai","country":"US"}\n{"country":"CN"}', 'block', 'cn_fields', { url: dd });
check('bad JSON', 'hold', undefined, { url: dd + '?ddtags=service%3Aclaude-ai' });
check({ country: 'US' }, 'block', 'cn_fields', { url: dd + '?ddtags=service%3Aclaude-ai%2Ccountry%3ACN' });
for (const outside of ['https://js.stripe.com/v3/', 'https://api.stripe.com/v1/payment_intents',
  'https://claude.ai/api/organizations/123/chat_conversations', 'https://api.anthropic.com/v1/messages',
  'https://claude.ai/login', 'https://claude.ai.evil.example/api/event_logging/v2/batch',
  'https://api.anthropic.com:8443/api/event_logging/v2/batch', 'http://api.anthropic.com/api/event_logging/v2/batch']) {
  const req = { url: outside, method: 'POST', get headers() { throw new Error('headers must not be read'); },
    get body() { throw new Error('private content must not be read'); } };
  assert.equal(policy.inspect(req, codec).reason, 'out_of_scope'); cases++;
}
check({ country: 'CN' }, 'pass', 'out_of_scope', { method: 'GET' });

// Exercise the private software entry point actually used by JavaScriptCore.
const bundle = fs.readFileSync(path.join(root, 'telemetry_filter/policy-bundle.js'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'telemetry_filter/manifest.json'), 'utf8'));
assert.equal(crypto.createHash('sha256').update(bundle).digest('hex'), manifest.sha256);
assert.equal(manifest.owner, 'RegionGuard');
assert.equal(manifest.transport, 'software_loopback_proxy');
function software(req) {
  const context = { Uint8Array, ArrayBuffer };
  vm.runInNewContext(bundle, context, { timeout: 1000 });
  const fixture = { ...req, bodyBase64: Buffer.from(req.body).toString('base64') };
  delete fixture.body;
  return JSON.parse(context.RegionGuardFilter.inspectJSON(JSON.stringify(fixture)));
}
const original = request({ country: 'US', private: 'SECRET-COOKIE', message: '中国' },
  { headers: { Authorization: 'SECRET-TOKEN', Cookie: 'SECRET-COOKIE' } });
const before = JSON.stringify(original);
assert.equal(software(original).action, 'pass');
assert.equal(JSON.stringify(original), before);
const blocked = software(request({ country: 'CN', private: 'SECRET-ID' }));
assert.equal(blocked.action, 'block');
assert.doesNotMatch(JSON.stringify(blocked), /SECRET/);
assert.equal(software(request('not JSON')).action, 'hold');
assert.equal(software(request(zlib.gzipSync(Buffer.from('{"country":"CN"}')),
  { headers: { 'Content-Encoding': 'gzip' } })).action, 'block');
assert.equal(software(request(zlib.gzipSync(Buffer.from('{"country":"US"}')),
  { headers: { 'Content-Encoding': 'gzip' } })).action, 'pass');
cases += 6;
const started = performance.now();
for (let i = 0; i < 100; i++) policy.inspect(request({ events: new Array(200).fill({ country: 'US', metadata: { timezone: 'America/New_York' } }) }), codec);
assert.ok(performance.now() - started < 3000, 'bounded policy must not stall the request engine');
console.log(`${cases} telemetry filter cases passed: CN gating, unchanged normal requests, privacy, compression, envelopes and scope`);

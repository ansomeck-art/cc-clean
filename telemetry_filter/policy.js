/* RegionGuard: decide whether a buffered telemetry request may leave the device.
 * This module neither rewrites data nor reads files, credentials or account state.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.RegionGuardTelemetry = factory();
})(typeof globalThis === 'object' ? globalThis : this, function () {
  'use strict';
  var MAX_BODY = 1048576, MAX_DECODED = 2097152, MAX_NODES = 30000, MAX_DEPTH = 32;
  var COUNTRY_KEYS = new Set(['country', 'countrycode', 'countryisocode', 'countryiso2', 'countryiso3',
    'countrycodeiso2', 'countrycodeiso3', 'ipcountry', 'geocountry', 'geocountrycode',
    'geocountryisocode', 'geocountryisocode2', 'clientcountry', 'systemcountry', 'oscountry',
    'usercountry', 'countryname', 'geocountryname', 'countryofresidence']);
  var REGION_KEYS = new Set(['region', 'regioncode', 'georegion', 'clientregion', 'systemregion', 'osregion']);
  var TZ_KEYS = new Set(['timezone', 'tz', 'timezoneid', 'timezonename', 'ostimezone',
    'systemtimezone', 'clienttimezone', 'browsertimezone', 'geotimezone', 'devicetimezone']);
  var LOCALE_KEYS = new Set(['locale', 'locales', 'systemlocale', 'oslocale', 'userlocale',
    'applocale', 'browserlocale', 'devicelocale', 'preferredlocales', 'languages', 'preferredlanguages']);
  var CONTENT_KEYS = new Set(['message', 'messages', 'prompt', 'prompts', 'content', 'input', 'output',
    'request', 'response', 'headers', 'cookies', 'authorization', 'stacktrace', 'exception',
    'attachment', 'attachments', 'url', 'urlquery', 'querystring', 'description', 'feedback', 'comment']);
  var ENCODED_KEYS = new Set(['data', 'event', 'events', 'eventdata', 'eventmetadata', 'metadata',
    'properties', 'attributes', 'extra', 'contexts', 'context', 'environment', 'env']);
  var CHINA_TZ = new Set(['asia/shanghai', 'asia/chongqing', 'asia/chungking', 'asia/harbin',
    'asia/urumqi', 'asia/kashgar', 'prc']);
  var DD_HOSTS = new Set(['browser-intake-us5-datadoghq.com', 'http-intake.logs.us5.datadoghq.com']);
  var SERVICES = new Set(['claude', 'claude-ai', 'claude.ai', 'claude-desktop', 'claude-code',
    'claude-code-desktop', 'anthropic-claude']);

  function norm(key) { return String(key).toLowerCase().replace(/[^a-z0-9]/g, ''); }
  function failure(code) { var e = new Error(code); e.rgCode = code; throw e; }
  function urlParts(url) {
    var m = /^https:\/\/([a-z0-9.-]+)(?::443)?(\/[^?#]*)?(?:\?([^#]*))?$/i.exec(String(url || ''));
    return m ? { host: m[1].toLowerCase(), path: m[2] || '/', query: m[3] || '' } : null;
  }
  function endpoint(url, method) {
    var p = urlParts(url);
    if (!p || String(method).toUpperCase() !== 'POST') return null;
    if (['claude.ai', 'api.anthropic.com', 'a-api.anthropic.com'].indexOf(p.host) >= 0 &&
        /^\/api\/event_logging\/(?:v2\/)?batch\/?$/.test(p.path)) return { kind: 'anthropic', parts: p };
    if (p.host === 'a-api.anthropic.com' && /^\/v1\/b\/?$/.test(p.path)) return { kind: 'anthropic', parts: p };
    if (p.host === 'o1158394.ingest.us.sentry.io' && /^\/api\/[0-9]+\/(envelope|store)\/?$/.test(p.path))
      return { kind: /\/envelope\/?$/.test(p.path) ? 'sentry-envelope' : 'sentry', parts: p };
    if (DD_HOSTS.has(p.host) && /^\/api\/v2\/(rum|logs)\/?$/.test(p.path)) return { kind: 'datadog', parts: p };
    return null;
  }

  function utf8(text) {
    var out = [];
    for (var i = 0; i < text.length; i++) {
      var cp = text.charCodeAt(i);
      if (cp >= 0xd800 && cp <= 0xdbff) {
        var next = text.charCodeAt(++i);
        if (!(next >= 0xdc00 && next <= 0xdfff)) failure('invalid_utf8');
        cp = 0x10000 + ((cp - 0xd800) << 10) + next - 0xdc00;
      } else if (cp >= 0xdc00 && cp <= 0xdfff) failure('invalid_utf8');
      if (cp < 128) out.push(cp);
      else if (cp < 2048) out.push(192 | cp >> 6, 128 | cp & 63);
      else if (cp < 65536) out.push(224 | cp >> 12, 128 | cp >> 6 & 63, 128 | cp & 63);
      else out.push(240 | cp >> 18, 128 | cp >> 12 & 63, 128 | cp >> 6 & 63, 128 | cp & 63);
      if (out.length > MAX_DECODED) failure('body_limit');
    }
    return new Uint8Array(out);
  }
  function text(bytes) {
    var result = [], chunk = [];
    for (var i = 0; i < bytes.length;) {
      var first = bytes[i++], cp, count, min;
      if (first < 128) { cp = first; count = 0; min = 0; }
      else if (first >= 194 && first <= 223) { cp = first & 31; count = 1; min = 128; }
      else if (first >= 224 && first <= 239) { cp = first & 15; count = 2; min = 2048; }
      else if (first >= 240 && first <= 244) { cp = first & 7; count = 3; min = 65536; }
      else failure('invalid_utf8');
      for (var j = 0; j < count; j++) {
        var byte = bytes[i++];
        if (!(byte >= 128 && byte <= 191)) failure('invalid_utf8');
        cp = cp << 6 | byte & 63;
      }
      if (cp < min || cp > 0x10ffff || cp >= 0xd800 && cp <= 0xdfff) failure('invalid_utf8');
      if (cp < 65536) chunk.push(cp);
      else { cp -= 65536; chunk.push(0xd800 | cp >> 10, 0xdc00 | cp & 1023); }
      if (chunk.length >= 4096) { result.push(String.fromCharCode.apply(null, chunk)); chunk = []; }
    }
    if (chunk.length) result.push(String.fromCharCode.apply(null, chunk));
    return result.join('');
  }

  // Reject duplicate JSON keys: forwarding a body interpreted differently by two
  // parsers would defeat a before-upload decision. Object prototypes stay absent.
  function strictJSON(source, budget) {
    var at = 0;
    function ws() { while (/[\x20\x09\x0a\x0d]/.test(source.charAt(at)) && at < source.length) at++; }
    function string() {
      var start = at++;
      for (; at < source.length; at++) {
        var c = source.charAt(at);
        if (c === '\\') { at++; continue; }
        if (c === '"') { at++; return JSON.parse(source.slice(start, at)); }
      }
      failure('invalid_json');
    }
    function value(depth) {
      ws();
      if (++budget.nodes > MAX_NODES || depth > MAX_DEPTH) failure('structure_limit');
      var c = source.charAt(at), result, key;
      if (c === '"') return string();
      if (c === '{') {
        result = Object.create(null); at++; ws();
        if (source.charAt(at) === '}') { at++; return result; }
        while (at < source.length) {
          if (source.charAt(at) !== '"') failure('invalid_json');
          key = string(); ws();
          if (Object.prototype.hasOwnProperty.call(result, key)) failure('duplicate_json_key');
          if (source.charAt(at++) !== ':') failure('invalid_json');
          result[key] = value(depth + 1); ws();
          c = source.charAt(at++);
          if (c === '}') return result;
          if (c !== ',') failure('invalid_json');
          ws();
        }
      } else if (c === '[') {
        result = []; at++; ws();
        if (source.charAt(at) === ']') { at++; return result; }
        while (at < source.length) {
          result.push(value(depth + 1)); ws(); c = source.charAt(at++);
          if (c === ']') return result;
          if (c !== ',') failure('invalid_json');
        }
      } else {
        var token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(source.slice(at));
        if (token) { at += token[0].length; return JSON.parse(token[0]); }
      }
      failure('invalid_json');
    }
    var parsed = value(0); ws();
    if (at !== source.length) failure('invalid_json');
    return parsed;
  }

  function header(headers, name) {
    if (Array.isArray(headers)) {
      var items = headers.filter(function (h) { return String(h.field).toLowerCase() === name; });
      return items.map(function (h) { return String(h.value); }).join(',');
    }
    var keys = Object.keys(headers || {});
    return keys.filter(function (k) { return k.toLowerCase() === name; })
      .map(function (k) { return String(headers[k]); }).join(',');
  }
  function inflateBounded(bytes, encoding, codec) {
    if (!codec) failure('compression_unavailable');
    var Ctor = encoding === 'gzip' ? codec.Gunzip :
      ((bytes[0] & 15) === 8 && ((bytes[0] << 8) + bytes[1]) % 31 === 0 ? codec.Unzlib : codec.Inflate);
    var chunks = [], size = 0, ended = false;
    var stream = new Ctor(function (part, final) {
      size += part.length;
      if (size > MAX_DECODED) failure('decoded_body_limit');
      chunks.push(part); ended = final;
    });
    for (var i = 0; i < bytes.length; i += 256)
      stream.push(bytes.subarray(i, Math.min(i + 256, bytes.length)), i + 256 >= bytes.length);
    if (!ended) failure('invalid_compression');
    var result = new Uint8Array(size), offset = 0;
    chunks.forEach(function (part) { result.set(part, offset); offset += part.length; });
    return result;
  }
  function bodyBytes(body, headers, codec) {
    var bytes;
    if (typeof body === 'string') bytes = utf8(body);
    else if (body instanceof Uint8Array) bytes = body;
    else if (body instanceof ArrayBuffer) bytes = new Uint8Array(body);
    else if (body == null) bytes = new Uint8Array(0);
    else failure('body_unavailable');
    if (!bytes.length) failure('body_unavailable');
    if (bytes.length > MAX_BODY) failure('body_limit');
    // HTTP engines may already supply a decoded body while retaining wire headers.
    var first = 0;
    while (first < bytes.length && [9, 10, 13, 32].indexOf(bytes[first]) >= 0) first++;
    if (bytes[first] === 123 || bytes[first] === 91) return bytes;
    var enc = header(headers, 'content-encoding').trim().toLowerCase();
    if (!enc && bytes[0] === 31 && bytes[1] === 139) enc = 'gzip';
    if (enc !== 'gzip' && enc !== 'deflate') failure('unsupported_encoding');
    return inflateBounded(bytes, enc, codec);
  }

  function records(bytes, kind, budget) {
    if (kind !== 'sentry-envelope') {
      var source = text(bytes).trim();
      try { return [strictJSON(source, budget)]; }
      catch (error) {
        if (kind !== 'datadog' || source.indexOf('\n') < 0 || error.rgCode === 'duplicate_json_key') throw error;
        return source.split('\n').filter(function (line) { return line.trim(); })
          .map(function (line) { return strictJSON(line, budget); });
      }
    }
    var at = 0, parsed = [];
    function line() {
      var end = bytes.indexOf(10, at);
      if (end < 0) end = bytes.length;
      var source = text(bytes.subarray(at, end)); at = Math.min(end + 1, bytes.length);
      return strictJSON(source, budget);
    }
    var envelope = line();
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) failure('invalid_envelope');
    parsed.push(envelope);
    while (at < bytes.length) {
      var item = line(), begin = at, length = item.length;
      if (!item || typeof item !== 'object' || Array.isArray(item)) failure('invalid_envelope');
      if (['event', 'transaction', 'session', 'sessions', 'client_report', 'user_report'].indexOf(item.type) < 0)
        failure('uninspectable_envelope_item');
      if (length === undefined) {
        var end = bytes.indexOf(10, at); if (end < 0) end = bytes.length;
        length = end - at;
      }
      if (!Number.isInteger(length) || length < 0 || begin + length > bytes.length) failure('invalid_envelope');
      parsed.push(strictJSON(text(bytes.subarray(begin, begin + length)), budget));
      at += length;
      if (at < bytes.length) {
        if (bytes[at] !== 10) failure('invalid_envelope');
        at++;
      }
    }
    return parsed;
  }
  function fieldReason(key, value) {
    key = norm(key);
    if (Array.isArray(value)) {
      for (var i = 0; i < value.length; i++) { var hit = fieldReason(key, value[i]); if (hit) return hit; }
      return '';
    }
    if (value && typeof value === 'object') {
      if (Object.keys(value).length === 1) return fieldReason(key, value.stringValue === undefined ? value.value : value.stringValue);
      return '';
    }
    if (typeof value !== 'string' && typeof value !== 'number') return '';
    var v = String(value).trim(), country = v.toLowerCase().replace(/[\s.'’()_-]/g, '');
    if (COUNTRY_KEYS.has(key) && ['cn', 'chn', 'prc', '156', 'china', 'mainlandchina', 'chinamainland',
        'prchina', 'peoplesrepublicofchina', '中国', '中国大陆', '中华人民共和国'].indexOf(country) >= 0) return 'cn_country';
    if (REGION_KEYS.has(key) && (/^cn(?:[-_][a-z0-9]+)*$/i.test(v) || ['china', '中国', '中国大陆', '中华人民共和国'].indexOf(country) >= 0)) return 'cn_region';
    if (TZ_KEYS.has(key) && CHINA_TZ.has(v.toLowerCase())) return 'cn_timezone';
    if (LOCALE_KEYS.has(key) && /^[a-z]{2,3}(?:-[a-z]{4})?-cn(?:-|$)/i.test(v.replace(/_/g, '-').split('.')[0])) return 'cn_locale';
    return '';
  }
  function tagPairs(tags, visit) {
    if (typeof tags === 'string') tags.split(/[,;]/).forEach(function (tag) {
      var colon = tag.indexOf(':');
      if (colon > 0) visit(tag.slice(0, colon), tag.slice(colon + 1));
    });
    else if (Array.isArray(tags)) tags.forEach(function (tag) {
      if (Array.isArray(tag) && tag.length === 2) visit(tag[0], tag[1]);
      else if (typeof tag === 'string') tagPairs(tag, visit);
    });
  }
  function inspect(request, codec) {
    var scope = endpoint(request.url, request.method);
    if (!scope) return { action: 'pass', reason: 'out_of_scope' };
    var reasons = new Set(), claudeService = scope.kind !== 'datadog';
    function service(key, value) {
      if (norm(key) === 'service' || norm(key) === 'servicename') {
        if (typeof value === 'string' && SERVICES.has(value.toLowerCase())) claudeService = true;
        else if (value && typeof value === 'object' && SERVICES.has(String(value.stringValue || '').toLowerCase())) claudeService = true;
      }
    }
    function pair(key, value) {
      var hit = fieldReason(key, value); if (hit) reasons.add(hit);
    }
    try {
      var query = scope.parts.query.split('&').map(function (part) {
        var eq = part.indexOf('='), key = decodeURIComponent(eq < 0 ? part : part.slice(0, eq));
        var value = decodeURIComponent((eq < 0 ? '' : part.slice(eq + 1)).replace(/\+/g, ' '));
        service(key, value); if (norm(key) === 'ddtags') tagPairs(value, service);
        return [key, value];
      });
      var budget = { nodes: 0 }, visited = 0;
      var data = records(bodyBytes(request.body, request.headers, codec), scope.kind, budget);
      function walk(value, depth, visit) {
        if (++visited > MAX_NODES || depth > MAX_DEPTH) failure('structure_limit');
        if (Array.isArray(value)) { value.forEach(function (item) { walk(item, depth + 1, visit); }); return; }
        if (!value || typeof value !== 'object') return;
        if (typeof value.key === 'string' && Object.prototype.hasOwnProperty.call(value, 'value')) {
          visit(value.key, value.value);
          if (ENCODED_KEYS.has(norm(value.key)) && value.value && typeof value.value.stringValue === 'string' &&
              /^[\[{]/.test(value.value.stringValue.trim()))
            walk(strictJSON(value.value.stringValue, budget), depth + 1, visit);
        }
        if (typeof value.name === 'string' && Object.prototype.hasOwnProperty.call(value, 'value')) visit(value.name, value.value);
        Object.keys(value).forEach(function (key) {
          var normalized = norm(key), item = value[key];
          if (CONTENT_KEYS.has(normalized)) return;
          visit(key, item);
          if (normalized === 'tags' || normalized === 'ddtags') tagPairs(item, visit);
          if (ENCODED_KEYS.has(normalized) && typeof item === 'string' && /^[\[{]/.test(item.trim()))
            walk(strictJSON(item, budget), depth + 1, visit);
          else if (item && typeof item === 'object') walk(item, depth + 1, visit);
        });
      }
      if (!claudeService) data.forEach(function (record) { walk(record, 0, service); });
      if (!claudeService) return { action: 'pass', reason: 'unattributed_shared_host' };
      query.forEach(function (item) { pair(item[0], item[1]); if (norm(item[0]) === 'ddtags') tagPairs(item[1], pair); });
      ['x-country-code', 'x-client-country', 'x-ip-country', 'cf-ipcountry', 'x-timezone', 'x-client-timezone', 'x-system-locale'].forEach(function (name) {
        var value = header(request.headers, name);
        if (value) pair(name.replace(/^(x-|cf-ip)/, ''), value);
      });
      data.forEach(function (record) { walk(record, 0, pair); });
      return reasons.size ? { action: 'block', reason: 'cn_fields', fields: Array.from(reasons).sort() }
        : { action: 'pass', reason: 'checked' };
    } catch (error) {
      // Dedicated endpoints are held if a payload cannot be inspected. Shared
      // third-party intake must not silently block another application's data.
      return { action: claudeService ? 'hold' : 'pass', reason: claudeService ?
        (error.rgCode || 'uninspectable_payload') : 'unattributed_shared_host' };
    }
  }
  return { inspect: inspect, endpoint: endpoint, utf8: utf8, text: text,
    limits: { raw: MAX_BODY, decoded: MAX_DECODED, nodes: MAX_NODES, depth: MAX_DEPTH } };
});

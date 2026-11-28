"""Pure, bounded classifications for explicitly selected Claude artifact bytes.

No function opens files, starts workers, signals processes or performs networking.
Only allowlisted metadata paths are interpreted. Results contain fixed labels and
counts, never field values, log lines, paths, identifiers or exception messages.
``observed`` means no recognized CN signal in these bytes, not geographic safety.
"""
import json
import math
import re

from telemetry_watch import (
    _CHINA, _CHINA_TZ, _COUNTRY_KEYS, _LOCALE_KEYS, _REGION_KEYS, _TZ_KEYS,
    _inspect as _inspect_scope, _invalid_constant, _key, _pairs,
)

MAX_JSON_BYTES = 1024 * 1024
MAX_LOG_BYTES = 512 * 1024
MAX_DEPTH = 64
MAX_STRUCTURE_TOKENS = 60000
MAX_FIELD_VALUES = 64
MAX_FIELD_CHARACTERS = 256
_UNKNOWN = 'telemetry_file_unknown'
_APP_LOCALES = frozenset(('locale', 'language', 'preferredlanguages'))
_LOG_LOCALES = _LOCALE_KEYS | frozenset(('language',))
LOG_CATEGORIES = ('region', 'banned', 'evicted', 'telemetry', 'device', 'stripe', 'network')
_LOG_MARKERS = (
    ('region', ('region_blocked', 'region_unavailable', 'app-unavailable-in-region',
                "isn't available in your region", 'is_country_restricted',
                'signups_disabled_in_region', 'unsupported_country', 'country_not_supported')),
    ('banned', ('account_banned', 'bad_device_id')),
    ('evicted', ('claude-login-ended-by', 'login_limit_reached', 'session_evicted', 'device_evicted')),
    ('telemetry', ('[eventlogging] batch flush failed', 'desktop_telemetry_upload_lost',
                   '[eventlogging] post threw')),
    ('device', ('[device-registry]',)),
    ('stripe', ('failed to load stripe.js',)),
    ('network', ('err_network_changed',)),
)


def _result(reasons=(), fields=(), incomplete=False, counters=None):
    # Preserve positive evidence even if a different allowlisted field is broken.
    state = 'risk' if reasons else 'unknown' if incomplete else 'observed'
    result = dict(state=state, reason_codes=sorted(set(reasons)) if reasons else
                  [_UNKNOWN] if incomplete else [], field_types=sorted(set(fields)))
    if counters is not None:
        result['counters'] = dict(counters)
    return result


def _text(raw, limit):
    if type(raw) is str:
        if len(raw) > limit or len(raw.encode('utf-8')) > limit:
            raise ValueError('size limit')
        return raw
    if type(raw) not in (bytes, bytearray) or len(raw) > limit:
        raise ValueError('unsupported input or size limit')
    return bytes(raw).decode('utf-8')


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('number limit')
    return number


def _structure_budget(text):
    # Count only JSON delimiters, without traversing or interpreting user content.
    depth = tokens = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char in '{[':
            depth += 1
            tokens += 1
        elif char in '}]':
            depth -= 1
        elif char in ',:':
            tokens += 1
        if depth > MAX_DEPTH or tokens > MAX_STRUCTURE_TOKENS:
            raise ValueError('structure limit')


def _json(text):
    _structure_budget(text)
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_invalid_constant,
                      parse_float=_finite_float)


def _values(value, kind, comma_locales):
    source = value if isinstance(value, list) else [value]
    if not source:
        return [], True
    values, incomplete = [], len(source) > MAX_FIELD_VALUES
    for item in source[:MAX_FIELD_VALUES]:
        if type(item) is str:
            pieces = item.split(',', MAX_FIELD_VALUES) if comma_locales and kind == 'locale' else [item]
        elif type(item) is int and kind == 'country':
            pieces = [str(item)]
        else:
            incomplete = True
            continue
        if len(values) + len(pieces) > MAX_FIELD_VALUES:
            incomplete = True
            pieces = pieces[:MAX_FIELD_VALUES - len(values)]
        for piece in pieces:
            piece = piece.strip()
            if not piece or len(piece) > MAX_FIELD_CHARACTERS:
                incomplete = True
            else:
                values.append(piece)
    return values, incomplete


def _metadata(container, locales, *, comma_locales=True):
    reasons, fields, incomplete = set(), set(), False
    for name, value in container.items():
        normalized = _key(name)
        kind = ('country' if normalized in _COUNTRY_KEYS or normalized in _REGION_KEYS else
                'locale' if normalized in locales else 'timezone' if normalized in _TZ_KEYS else None)
        if kind is None:
            continue
        fields.add(kind)
        values, invalid = _values(value, kind, comma_locales)
        incomplete |= invalid
        for text in values:
            if kind == 'country':
                country = re.sub(r"[\s.'’()_-]", '', text.lower())
                if country in _CHINA or (normalized in _REGION_KEYS and
                                          re.fullmatch(r'cn(?:[-_][a-z0-9]+)*', text, re.I)):
                    reasons.add('telemetry_cn_country')
            elif kind == 'locale':
                locale = text.replace('_', '-').split('.')[0]
                if re.match(r'^[a-z]{2,3}(?:-[a-z]{4})?-cn(?:-|$)', locale, re.I):
                    reasons.add('telemetry_cn_locale')
            elif text.lower() in _CHINA_TZ:
                reasons.add('telemetry_cn_timezone')
    return reasons, fields, incomplete


def _preferences(obj):
    reasons, fields, incomplete = set(), set(), False
    for section, keys in (('intl', ('accept_languages', 'selected_languages')),
                          ('spellcheck', ('dictionaries',))):
        if section not in obj:
            continue
        container = obj[section]
        if not isinstance(container, dict):
            incomplete = True
            continue
        for key in keys:
            if key not in container:
                continue
            if isinstance(container[key], list) and not container[key]:
                # An unset dictionary/language list is a valid preference, not a
                # broken country value. It provides no geographic evidence.
                continue
            # These three confirmed language preferences have locale semantics.
            found, seen, invalid = _metadata({'locale': container[key]}, frozenset(('locale',)))
            reasons.update(found)
            fields.update(seen)
            incomplete |= invalid
    return _result(reasons, fields, incomplete)


def inspect_json(kind, raw):
    """Classify one complete selected JSON artifact; missing files are a caller concern.

    Missing optional scope culture is observed without a geographic conclusion.
    Other kinds inspect only named preferences/metadata; an unrelated object is
    observed. Metadata-only sources (cookies, desktop_config, ant-did) are refused
    before decoding: their contents do not belong in this policy.
    """
    if type(kind) is not str or kind not in ('sentry_scope', 'app_config', 'electron_preferences'):
        return _result(incomplete=True)
    try:
        text = _text(raw, MAX_JSON_BYTES)
        obj = _json(text)
        if not isinstance(obj, dict):
            return _result(incomplete=True)
        if kind == 'sentry_scope':
            state, reasons, fields = _inspect_scope(text.encode('utf-8'))
            result = _result(reasons if state == 'risk' else (), fields, state == 'unknown')
            if state == 'safe':
                result['state'] = 'safe'
            return result
        if kind == 'app_config':
            return _result(*_metadata(obj, _APP_LOCALES))
        return _preferences(obj)
    except (ValueError, TypeError, AttributeError, UnicodeError, RecursionError, OverflowError):
        return _result(incomplete=True)


def _log_metadata(obj):
    """Only explicit structured environmental contexts, never arbitrary message JSON."""
    containers, incomplete = [], False
    envelopes = [obj]
    envelopes.extend(obj[name] for name in ('log', 'event') if isinstance(obj.get(name), dict))
    for envelope in envelopes:
        for name in ('environment', 'env'):
            value = envelope.get(name)
            if isinstance(value, dict):
                containers.append(value)
            elif name in envelope and value is not None and not isinstance(value, str):
                incomplete = True
        if 'contexts' not in envelope:
            continue
        contexts = envelope['contexts']
        if not isinstance(contexts, dict):
            incomplete = True
            continue
        for name in ('culture', 'environment', 'geo', 'os', 'device'):
            if name not in contexts:
                continue
            if isinstance(contexts[name], dict):
                containers.append(contexts[name])
            else:
                incomplete = True
    reasons, fields = set(), set()
    for container in containers:
        found, seen, invalid = _metadata(container, _LOG_LOCALES)
        reasons.update(found)
        fields.update(seen)
        incomplete |= invalid
    return reasons, fields, incomplete


def inspect_log_chunk(raw):
    """Classify up to 512 KiB of complete UTF-8 log lines supplied by the watcher.

    Ordinary text only contributes advisory category counts (one per line in the
    established priority order). Region words/error codes never establish CN.
    Only whole JSON-object lines carry structured metadata; JSON quoted inside
    message/content fields and timestamp-prefixed prose are not reinterpreted.
    """
    counters = dict.fromkeys(LOG_CATEGORIES, 0)
    try:
        text = _text(raw, MAX_LOG_BYTES)
    except (ValueError, UnicodeError):
        return _result(incomplete=True, counters=counters)
    reasons, fields, incomplete = set(), set(), False
    # A legal JSON string can contain U+2028/U+2029. They are not log boundaries.
    for line in text.split('\n'):
        lower = line.lower()
        for category, markers in _LOG_MARKERS:
            if any(marker in lower for marker in markers):
                counters[category] += 1
                break
        stripped = line.strip()
        if not stripped.startswith('{'):
            continue
        try:
            obj = _json(stripped)
            if not isinstance(obj, dict):
                incomplete = True
                continue
            found, seen, invalid = _log_metadata(obj)
            reasons.update(found)
            fields.update(seen)
            incomplete |= invalid
        except (ValueError, TypeError, AttributeError, UnicodeError, RecursionError, OverflowError):
            incomplete = True
    return _result(reasons, fields, incomplete, counters)

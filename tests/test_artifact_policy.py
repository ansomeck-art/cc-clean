"""Synthetic artifact policy fixtures only; no user files, networking or signals."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from artifact_policy import (
    LOG_CATEGORIES, MAX_DEPTH, MAX_JSON_BYTES, MAX_LOG_BYTES, inspect_json, inspect_log_chunk,
)
from telemetry_watch import _inspect

PRIVATE = 'PRIVATE-FIXTURE-ID-TOKEN-NEVER-OUTPUT'


def encoded(value):
    return json.dumps(value, ensure_ascii=False).encode('utf-8')


def scope(locale='en-US', timezone='America/New_York', **extra):
    return {'event': {'contexts': {'culture': {'locale': locale, 'timezone': timezone}}, **extra}}


class PolicyAssertions(unittest.TestCase):
    def assert_view(self, view, state, reasons=(), fields=None, log=False):
        self.assertEqual(view['state'], state)
        self.assertEqual(view['reason_codes'], sorted(reasons))
        self.assertTrue(set(view['field_types']) <= {'country', 'locale', 'timezone'})
        if fields is not None:
            self.assertEqual(view['field_types'], sorted(fields))
        self.assertEqual(set(view), {'state', 'reason_codes', 'field_types'} | ({'counters'} if log else set()))
        self.assertNotIn(PRIVATE, json.dumps(view))
        if log:
            self.assertEqual(set(view['counters']), set(LOG_CATEGORIES))
            self.assertTrue(all(type(count) is int and count >= 0 for count in view['counters'].values()))


class ArtifactJSONTests(PolicyAssertions):
    def test_scope_preserves_optional_fields_and_positive_priority(self):
        values = [{}, scope(), scope('zh-Hans'), scope(timezone='Asia/Shanghai'),
                  {'event': {'contexts': {'culture': {'locale': 'en-US'}}}},
                  {'country': 'CN', 'event': {'contexts': {'culture': {'timezone': None}}}}]
        for value in values:
            with self.subTest(value=value):
                raw = encoded(value)
                state, reasons, fields = _inspect(raw)
                self.assert_view(inspect_json('sentry_scope', raw), state, reasons, fields)

    def test_scope_does_not_inspect_user_or_chat_content(self):
        raw = encoded(scope(user={'id': PRIVATE, 'country': 'CN'}, message={
            'country': 'CN', 'contexts': {'culture': {'locale': 'zh-CN'}}}))
        self.assert_view(inspect_json('sentry_scope', raw), 'safe', fields=['locale', 'timezone'])

    def test_existing_cn_baseline_and_identical_future_sample_are_always_risk(self):
        raw = encoded({'locale': 'zh-CN', 'deviceName': PRIVATE})
        for _ in range(2):
            self.assert_view(inspect_json('app_config', raw), 'risk', ['telemetry_cn_locale'], ['locale'])

    def test_country_and_region_values_match_the_existing_scope_vocabulary(self):
        for value in ('CN', 'cn', 'CHN', 'PRC', '156', 156, 'China', 'Mainland China',
                      "People's Republic of China", '中国', '中国大陆', '中华人民共和国'):
            with self.subTest(country=value):
                raw = encoded({'country_code': value})
                self.assert_view(inspect_json('app_config', raw), 'risk', ['telemetry_cn_country'], ['country'])
        for value in ('CN', 'cn-31', 'CN-north-1', 'cn_11'):
            with self.subTest(region=value):
                self.assert_view(inspect_json('app_config', encoded({'region': value})),
                                 'risk', ['telemetry_cn_country'], ['country'])

    def test_all_existing_country_region_and_timezone_keys_are_reused(self):
        from telemetry_watch import _COUNTRY_KEYS, _REGION_KEYS, _TZ_KEYS
        for key in _COUNTRY_KEYS | _REGION_KEYS:
            with self.subTest(key=key):
                self.assert_view(inspect_json('app_config', encoded({key: 'CN'})),
                                 'risk', ['telemetry_cn_country'], ['country'])
        for key in _TZ_KEYS:
            with self.subTest(key=key):
                self.assert_view(inspect_json('app_config', encoded({key: 'Asia/Shanghai'})),
                                 'risk', ['telemetry_cn_timezone'], ['timezone'])

    def test_only_explicit_cn_locale_segments_and_language_lists_are_risk(self):
        for key, value in (('locale', 'zh-CN'), ('language', 'en_CN.UTF-8'),
                           ('preferredLanguages', ['en-US', 'zh-Hans-CN']),
                           ('preferred_languages', 'en-US, zh-CN'),
                           ('preferredLanguages', ['en-US,zh-Hans', 'en-CN'])):
            with self.subTest(key=key, value=value):
                self.assert_view(inspect_json('app_config', encoded({key: value})),
                                 'risk', ['telemetry_cn_locale'], ['locale'])

    def test_mainland_timezones_are_explicit_and_not_utc_offset_inferences(self):
        for value in ('Asia/Shanghai', 'asia/chongqing', 'Asia/Chungking', 'Asia/Harbin',
                      'Asia/Urumqi', 'Asia/Kashgar', 'PRC'):
            with self.subTest(timezone=value):
                self.assert_view(inspect_json('app_config', encoded({'timezone': value})),
                                 'risk', ['telemetry_cn_timezone'], ['timezone'])
        for value in ('UTC+8', 'UTC+08:00', 'Etc/GMT-8', 'Asia/Singapore', 'Asia/Hong_Kong',
                      'Asia/Macau', 'Asia/Taipei'):
            with self.subTest(timezone=value):
                self.assert_view(inspect_json('app_config', encoded({'timezone': value})), 'observed')

    def test_normal_chinese_and_non_cn_regions_never_establish_cn(self):
        for locale in ('zh', 'zh-Hans', 'zh-TW', 'en-US', 'zh-HK', 'Chinese'):
            for country in ('US', 'HK', 'MO', 'TW', 'Singapore'):
                with self.subTest(locale=locale, country=country):
                    self.assert_view(inspect_json('app_config', encoded({
                        'locale': locale, 'country': country, 'deviceName': 'CN-English-Computer',
                        'comment': '中国 CN Asia/Shanghai ' + PRIVATE})), 'observed')

    def test_app_config_semantics_are_top_level_and_only_allowlisted_languages(self):
        value = {'deviceName': 'China', 'user': {'country': 'CN'}, 'metadata': {'country': 'CN'},
                 'messages': [{'role': 'user', 'content': {'locale': 'zh-CN', 'country': 'CN'}}],
                 'response': {'timezone': 'Asia/Shanghai'}, 'app': {'locale': 'zh-CN'},
                 'languages': ['zh-CN'], 'preferredLocales': ['zh-CN'], 'private': PRIVATE}
        self.assert_view(inspect_json('app_config', encoded(value)), 'observed', fields=[])

    def test_valid_objects_without_related_fields_are_observed_not_safe(self):
        for kind in ('app_config', 'electron_preferences'):
            for value in ({}, {'deviceName': PRIVATE}, {'messages': ['你好，中国！']}):
                self.assert_view(inspect_json(kind, encoded(value)), 'observed', fields=[])

    def test_bad_recognized_field_types_are_unknown_without_values(self):
        for value in ({'locale': None}, {'language': True}, {'country': 156.0}, {'country': False},
                      {'preferredLanguages': {}}, {'timezone': 156}, {'locale': []},
                      {'country': PRIVATE * 20}, {'preferredLanguages': ['en-US'] * 65}):
            with self.subTest(value=value):
                self.assert_view(inspect_json('app_config', encoded(value)),
                                 'unknown', ['telemetry_file_unknown'])

    def test_legal_cn_evidence_wins_over_other_bad_config_fields(self):
        for value, reason in (({'country': 'CN', 'locale': None}, 'telemetry_cn_country'),
                              ({'locale': 'zh-CN', 'timezone': {}}, 'telemetry_cn_locale'),
                              ({'timezone': 'Asia/Shanghai', 'country': []}, 'telemetry_cn_timezone'),
                              ({'preferredLanguages': 'en-US,,zh-CN'}, 'telemetry_cn_locale')):
            with self.subTest(value=value):
                self.assert_view(inspect_json('app_config', encoded(value)), 'risk', [reason])

    def test_bounded_list_inspection_preserves_positive_prefix_evidence(self):
        for value in (['zh-CN'] + ['en-US'] * 64, 'zh-CN,' + ','.join(['en-US'] * 1000)):
            self.assert_view(inspect_json('app_config', encoded({'preferredLanguages': value})),
                             'risk', ['telemetry_cn_locale'], ['locale'])

    def test_preferences_inspect_only_the_three_confirmed_language_paths(self):
        for section, key, value in (('intl', 'accept_languages', 'en-US, zh-CN'),
                                    ('intl', 'selected_languages', ['zh-Hans-CN', 'en-US']),
                                    ('spellcheck', 'dictionaries', ['en-US', 'en_CN.UTF-8'])):
            with self.subTest(section=section, key=key):
                self.assert_view(inspect_json('electron_preferences', encoded({section: {key: value}})),
                                 'risk', ['telemetry_cn_locale'], ['locale'])
        value = {'locale': 'zh-CN', 'profile': {'country': 'CN'},
                 'intl': {'country': 'CN', 'timezone': 'Asia/Shanghai', 'accept_languages': 'zh,zh-Hans'},
                 'spellcheck': {'dictionaries': ['zh', 'zh-Hans', 'zh-TW']},
                 'messages': [{'country': 'CN'}], 'private': PRIVATE}
        self.assert_view(inspect_json('electron_preferences', encoded(value)), 'observed', fields=['locale'])

    def test_preferences_malformed_sections_and_cn_priority(self):
        for value in ({'intl': []}, {'intl': None}, {'intl': {'selected_languages': 156}},
                      {'spellcheck': {'dictionaries': {'locale': 'zh-CN'}}}):
            with self.subTest(value=value):
                self.assert_view(inspect_json('electron_preferences', encoded(value)),
                                 'unknown', ['telemetry_file_unknown'])
        self.assert_view(inspect_json('electron_preferences', encoded({
            'intl': {'accept_languages': 'zh-CN'}, 'spellcheck': {'dictionaries': None}})),
            'risk', ['telemetry_cn_locale'], ['locale'])

    def test_empty_optional_language_lists_are_unset_not_a_file_error(self):
        for value in ({'spellcheck': {'dictionaries': []}},
                      {'intl': {'selected_languages': []}},
                      {'intl': {'accept_languages': []}}):
            with self.subTest(value=value):
                self.assert_view(inspect_json('electron_preferences', encoded(value)), 'observed', fields=[])

    def test_json_duplicates_nonfinite_invalid_utf8_and_bad_roots_are_unknown(self):
        malformed = (b'{"country":"CN","country":"US"}',
                     b'{"country":"US","co\\u0075ntry":"CN"}',
                     b'{"locale":"en-US","extra":{"a":1,"a":2}}',
                     b'{"country":NaN}', b'{"country":Infinity}', b'{"x":1e999}',
                     b'{"locale":"zh-CN"', b'\xff', b'[]', b'null', b'"CN"', b'')
        for kind in ('sentry_scope', 'app_config', 'electron_preferences'):
            for raw in malformed:
                with self.subTest(kind=kind, raw=raw):
                    self.assert_view(inspect_json(kind, raw), 'unknown', ['telemetry_file_unknown'])

    def test_raw_byte_and_structure_budgets_are_enforced(self):
        self.assert_view(inspect_json('app_config', b'{}' + b' ' * (MAX_JSON_BYTES - 2)), 'observed')
        self.assert_view(inspect_json('app_config', b'{}' + b' ' * MAX_JSON_BYTES),
                         'unknown', ['telemetry_file_unknown'])
        deep = '{"messages":' + '[' * MAX_DEPTH + '0' + ']' * MAX_DEPTH + '}'
        self.assert_view(inspect_json('app_config', deep), 'unknown', ['telemetry_file_unknown'])
        nodes = '{"messages":[' + ','.join('0' for _ in range(61000)) + ']}'
        self.assert_view(inspect_json('app_config', nodes), 'unknown', ['telemetry_file_unknown'])

    def test_metadata_only_and_unknown_kinds_do_not_decode_contents(self):
        class Unreadable:
            def __str__(self):
                raise AssertionError('metadata-only bytes must not be inspected')
            def __bytes__(self):
                raise AssertionError('metadata-only bytes must not be inspected')
        for kind in ('cookies', 'ant-did', 'desktop_config', 'queue', 'unknown'):
            self.assert_view(inspect_json(kind, Unreadable()), 'unknown', ['telemetry_file_unknown'], [])

    def test_policy_calls_never_perform_io_networking_or_signaling(self):
        forbidden = AssertionError('pure policy must not use external effects')
        with patch('builtins.open', side_effect=forbidden), patch.object(os, 'kill', side_effect=forbidden), \
             patch.object(socket, 'socket', side_effect=forbidden), \
             patch.object(subprocess, 'Popen', side_effect=forbidden):
            self.assert_view(inspect_json('sentry_scope', encoded(scope())), 'safe')
            self.assert_view(inspect_json('app_config', encoded({'locale': 'zh-CN'})),
                             'risk', ['telemetry_cn_locale'])
            self.assert_view(inspect_log_chunk(encoded({'message': PRIVATE})), 'observed', log=True)


class ArtifactLogTests(PolicyAssertions):
    def test_fixed_error_categories_are_advisory_and_count_once_per_line(self):
        lines = ['region_unavailable region_unavailable', 'account_banned bad_device_id',
                 'Claude-Login-Ended-By login_limit_reached',
                 '[EventLogging] Batch flush FAILED desktop_telemetry_upload_lost',
                 '[device-registry] ' + PRIVATE, 'Failed to load Stripe.js', 'ERR_NETWORK_CHANGED']
        result = inspect_log_chunk('\n'.join(lines))
        self.assert_view(result, 'observed', fields=[], log=True)
        self.assertEqual(result['counters'], dict.fromkeys(LOG_CATEGORIES, 1))

    def test_new_region_codes_are_not_country_evidence(self):
        for code in ('region_unavailable', 'region_blocked', 'app-unavailable-in-region',
                     'is_country_restricted', 'signups_disabled_in_region', 'unsupported_country'):
            with self.subTest(code=code):
                result = inspect_log_chunk('2026-11-27 [error] ' + code + ' ' + PRIVATE)
                self.assert_view(result, 'observed', fields=[], log=True)
                self.assertEqual(result['counters']['region'], 1)

    def test_normal_messages_and_json_chats_are_never_interpreted_as_culture(self):
        values = ['用户正在讨论中国 China CN Asia/Shanghai region_blocked ' + PRIVATE,
                  {'country': 'CN', 'locale': 'zh-CN', 'timezone': 'Asia/Shanghai', 'message': PRIVATE},
                  {'message': {'contexts': {'culture': {'locale': 'zh-CN'}}}},
                  {'message': '{"event":{"contexts":{"culture":{"locale":"zh-CN"}}}}'},
                  {'messages': [{'role': 'user', 'content': {'country': 'CN', 'locale': 'zh-CN'}}]},
                  {'content': {'environment': {'country': 'CN'}}, 'request': {'country': 'CN'}},
                  {'metadata': {'country': 'CN'}, 'user': {'country': 'CN'}}]
        for value in values:
            with self.subTest(value=value):
                raw = value if isinstance(value, str) else encoded(value)
                self.assert_view(inspect_log_chunk(raw), 'observed', fields=[], log=True)

    def test_unicode_paragraph_characters_inside_json_chat_are_not_record_boundaries(self):
        raw = encoded({'message': '你好\u2028中国\u2029CN ' + PRIVATE}) + b'\r\n'
        self.assert_view(inspect_log_chunk(raw), 'observed', fields=[], log=True)

    def test_only_explicit_structured_environment_and_culture_paths_trigger(self):
        values = [({'environment': {'country_code': 'CN'}}, 'country'),
                  ({'env': {'country': 156}}, 'country'),
                  ({'contexts': {'culture': {'locale': 'zh-CN'}}}, 'locale'),
                  ({'event': {'contexts': {'culture': {'timezone': 'Asia/Shanghai'}}}}, 'timezone'),
                  ({'log': {'contexts': {'geo': {'region': 'CN-31'}}}}, 'country'),
                  ({'event': {'environment': {'preferredLanguages': 'en-US,zh-CN'}}}, 'locale')]
        for value, field in values:
            with self.subTest(value=value):
                self.assert_view(inspect_log_chunk(encoded(value)), 'risk', ['telemetry_cn_' + field], [field], log=True)

    def test_log_environment_name_and_normal_chinese_preferences_are_observed(self):
        value = {'environment': 'production', 'event': 'clicked', 'log': '你好 ' + PRIVATE,
                 'contexts': {'culture': {'locale': 'zh-Hans', 'timezone': 'UTC+8'}}}
        self.assert_view(inspect_log_chunk(encoded(value)), 'observed', fields=['locale', 'timezone'], log=True)

    def test_positive_structured_cn_survives_other_bad_fields_or_other_bad_lines(self):
        raw = encoded({'event': {'contexts': {'culture': {'locale': 'zh-CN', 'timezone': {}}}}})
        self.assert_view(inspect_log_chunk(raw), 'risk', ['telemetry_cn_locale'], log=True)
        raw += b'\n{"message":"' + PRIVATE.encode() + b'"\n'
        self.assert_view(inspect_log_chunk(raw), 'risk', ['telemetry_cn_locale'], log=True)

    def test_malformed_structured_logs_and_limits_are_unknown_without_raw_values(self):
        values = [b'{"environment":{"country":"CN","country":"US"}}',
                  encoded({'contexts': {'culture': {'locale': None}}}),
                  encoded({'environment': {'country': PRIVATE * 20}}),
                  b'{"message":"' + PRIVATE.encode(), b'\xff', b'x' * (MAX_LOG_BYTES + 1)]
        for raw in values:
            with self.subTest(raw=raw[:100]):
                self.assert_view(inspect_log_chunk(raw), 'unknown', ['telemetry_file_unknown'], log=True)

    def test_empty_whitespace_timestamps_and_record_count_do_not_claim_safe(self):
        for raw in (b'', b' \n\t\n', b'2026-11-27T13:00:00+08:00 [info] initialized\n' * 20,
                    b'x' * MAX_LOG_BYTES):
            self.assert_view(inspect_log_chunk(raw), 'observed', fields=[], log=True)

    def test_outputs_are_fresh_copies_and_never_contain_identifiers_or_raw_values(self):
        first = inspect_log_chunk(encoded({'environment': {'country': 'CN'}, 'device_id': PRIVATE}))
        first['reason_codes'].clear()
        first['counters']['region'] = 999
        second = inspect_log_chunk(encoded({'environment': {'country': 'CN'}, 'device_id': PRIVATE}))
        self.assert_view(second, 'risk', ['telemetry_cn_country'], ['country'], log=True)
        self.assertEqual(second['counters']['region'], 0)


if __name__ == '__main__':
    unittest.main()

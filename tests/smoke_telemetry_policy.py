"""Run the shipped hook in macOS JavaScriptCore; no network, TLS trust or user data."""
import gzip
import json
from pathlib import Path
import sys

import Foundation
import objc

ROOT = Path(__file__).resolve().parents[1]


def main():
    assert sys.platform == 'darwin'
    framework = Foundation.NSBundle.bundleWithPath_('/System/Library/Frameworks/JavaScriptCore.framework')
    assert framework.load(), 'JavaScriptCore framework unavailable'
    context_class = objc.lookUpClass('JSContext')
    sys.path.insert(0, str(ROOT))
    from telemetry_worker import Policy
    policy = Policy()
    endpoint = 'https://api.anthropic.com/api/event_logging/v2/batch'
    cases = [
        (endpoint, b'{"country":"CN"}', {}, 403),
        (endpoint, b'{"country":"US","message":"China CN"}', {}, 0),
        (endpoint, gzip.compress(b'{"country":"CN"}'), {'Content-Encoding': 'gzip'}, 403),
        (endpoint, gzip.compress(b'{"country":"US"}'), {'Content-Encoding': 'gzip'}, 0),
        (endpoint, b'{"timezone":"Asia/Shanghai"}', {}, 403),
        (endpoint, '{"locale":"zh-Hans","message":"中国"}'.encode(), {}, 0),
        (endpoint, b'{"country":"CN","country":"US"}', {}, 503),
        ('https://api.stripe.com/v1/payment_intents', b'{"country":"CN"}', {}, 0),
        ('https://api.anthropic.com/v1/messages', b'{"country":"CN"}', {}, 0),
    ]
    for url, body, headers, expected in cases:
        decision = policy.inspect(url, 'POST', headers, body)
        assert {'pass': 0, 'block': 403, 'hold': 503}[decision['action']] == expected
    print(f'JavaScriptCore: {len(cases)} software-policy fixtures passed; no trust or networking changes')


if __name__ == '__main__':
    main()

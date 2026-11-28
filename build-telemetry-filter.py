#!/usr/bin/env python3
"""Build RegionGuard's private policy bundle. No VPN modules are generated."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def build():
    source = ROOT / 'telemetry_filter'
    vendor = (source / 'vendor/fflate-0.8.3.js').read_text()
    policy = (source / 'policy.js').read_text()
    entry = (source / 'software-entry.js').read_text()
    license_text = (source / 'vendor/fflate-LICENSE').read_text()
    bundle = ('/* RegionGuard software telemetry filter v2.0.0; fflate 0.8.3 (MIT).\n' +
              license_text.replace('*/', '* /') + '\n*/\n' +
              'var module = { exports: {} }, exports = module.exports;\n' + vendor +
              '\nvar rgCompression = module.exports;\nmodule = { exports: {} };\n' + policy +
              '\nvar rgPolicy = module.exports;\n' + entry + '\n')
    bundle = bundle.rstrip('\n') + '\n'
    digest = hashlib.sha256(bundle.encode()).hexdigest()
    (source / 'policy-bundle.js').write_text(bundle)
    result = {'version': '2.0.0', 'owner': 'RegionGuard', 'transport': 'software_loopback_proxy',
              'sha256': digest, 'max_body_bytes': 1048576, 'max_decoded_bytes': 2097152,
              'hosts': ['claude.ai', 'api.anthropic.com', 'a-api.anthropic.com',
                        'o1158394.ingest.us.sentry.io', 'browser-intake-us5-datadoghq.com',
                        'http-intake.logs.us5.datadoghq.com']}
    (source / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'built': True, 'owner': 'RegionGuard', 'sha256': digest}))


if __name__ == '__main__':
    build()

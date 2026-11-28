# -*- mode: python ; coding: utf-8 -*-
"""Native AppKit accessory app. Runtime files always live outside this bundle."""
import os
analysis = Analysis(
    ['tray_app.py'], pathex=['.'], binaries=[('build/native_connections/_native_connections.dylib', '.')],
    datas=[('static', 'static')],
    hiddenimports=['server', 'mac_platform', 'win_platform', 'audit_common', 'protection', 'mac_guard',
                   'proxy_runtime', 'readonly_telemetry', 'telemetry_watch', 'service_diagnostics',
                   'client_version', 'traffic_evidence', 'traffic_watch', 'native_connections', 'connection_routes',
                   'artifact_watch', 'artifact_policy', 'AppKit', 'Foundation',
                   'objc', 'PyObjCTools.AppHelper'],
    hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=['tkinter', 'pytest', 'PyObjCTest', 'pystray', 'PIL', 'mitmproxy', 'mitmproxy_rs',
              'telemetry_runtime', 'telemetry_worker', 'telemetry_certificates'], noarchive=False,
)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz, analysis.scripts, [], exclude_binaries=True,
    name='RegionGuard', debug=False, bootloader_ignore_signals=False,
    strip=False, upx=False, console=False, argv_emulation=False,
    target_arch=os.environ.get('REGIONGUARD_BUILD_ARCH') or None,
    codesign_identity=None, entitlements_file=None,
)
collection = COLLECT(exe, analysis.binaries, analysis.datas, strip=False, upx=False, name='RegionGuard')
app = BUNDLE(
    collection, name='RegionGuard.app', bundle_identifier='com.regionguard.menubar',
    info_plist={
        'CFBundleName': 'RegionGuard', 'CFBundleDisplayName': 'Region Guard',
        'CFBundleShortVersionString': '3.5.0', 'CFBundleVersion': '12',
        'LSUIElement': True, 'NSHighResolutionCapable': True,
        'NSPrincipalClass': 'NSApplication',
        'NSUserNotificationAlertStyle': 'alert',
    },
)

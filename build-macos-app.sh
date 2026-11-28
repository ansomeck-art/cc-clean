#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
DIST_DIR="${REGIONGUARD_DIST_DIR:-$DIR/dist}"
if [ "$(uname -s)" != "Darwin" ]; then
  echo "macOS .app/.dmg 构建必须在 macOS 上运行。" >&2
  exit 1
fi
command -v node >/dev/null || { echo "测试门禁需要 Node.js。" >&2; exit 1; }
PY_BUILD="${REGIONGUARD_PYTHON:-python3.12}"
"$PY_BUILD" -c 'import sys; assert sys.version_info >= (3, 12), "完整构建门禁使用 Python 3.12+"'
"$PY_BUILD" -m venv "$DIR/.venv-filter"
PY_BUILD="$DIR/.venv-filter/bin/python"
PIP_CACHE_DIR="$DIR/.venv-filter/pip-cache" "$PY_BUILD" -m pip install \
  --disable-pip-version-check --only-binary=:all: -r requirements-macos-build.txt

# Compile against the local SDK instead of copying Darwin socket_info layouts
# into Python. The helper only reads selected, revalidated user-owned PIDs.
mkdir -p "$DIR/build/native_connections"
NATIVE_FLAGS=()
case "${REGIONGUARD_BUILD_ARCH:-$(uname -m)}" in
  universal2) NATIVE_FLAGS=(-arch x86_64 -arch arm64) ;;
  x86_64|arm64) NATIVE_FLAGS=(-arch "${REGIONGUARD_BUILD_ARCH:-$(uname -m)}") ;;
  *) echo "不支持的原生构建架构" >&2; exit 1 ;;
esac
/usr/bin/xcrun clang -dynamiclib -O2 -Wall -Wextra -Werror -mmacosx-version-min=11.0 \
  "${NATIVE_FLAGS[@]}" native_connections.c -lproc -o "$DIR/build/native_connections/_native_connections.dylib"

# No packaging begins until all unit and syntax gates succeed.
"$PY_BUILD" build-telemetry-filter.py
"$PY_BUILD" -m unittest discover -s tests -p 'test_*.py' -v
for test_file in tests/test_*.cjs; do
  node "$test_file"
done
"$PY_BUILD" -m py_compile server.py mac_platform.py win_platform.py tray_app.py audit_common.py protection.py mac_guard.py proxy_runtime.py readonly_telemetry.py telemetry_watch.py artifact_watch.py artifact_policy.py service_diagnostics.py client_version.py traffic_evidence.py traffic_watch.py native_connections.py connection_routes.py
node --check static/app.js
node --check telemetry_filter/policy-bundle.js
if [ "${REGIONGUARD_SKIP_UI_SMOKE:-0}" != "1" ]; then
  "$PY_BUILD" tests/smoke_macos_ui.py
  "$PY_BUILD" tests/smoke_fast_protection.py
  "$PY_BUILD" tests/smoke_telemetry_watch.py
  "$PY_BUILD" tests/smoke_artifact_watch.py
  "$PY_BUILD" tests/smoke_native_connections.py | tee "$DIR/build/native-connections-smoke.json"
  "$PY_BUILD" tests/smoke_connection_protection.py
  # HTTPS decryption is retired and excluded from the application. Historical
  # policy/controller code remains covered by isolated unit fixtures only.
fi

PYINSTALLER_CONFIG_DIR="$DIR/.venv-macos/pyinstaller-cache" "$PY_BUILD" -m PyInstaller --clean --noconfirm --distpath "$DIST_DIR" RegionGuard-macOS.spec
/usr/bin/codesign --force --deep --sign - "$DIST_DIR/RegionGuard.app"
/usr/bin/codesign --verify --deep --strict "$DIST_DIR/RegionGuard.app"

STAGE_DIR="$(mktemp -d "$DIR/build/regionguard-dmg.XXXXXX")"
# Remove only the staging directory this script just created, never user files/caches.
trap 'if [ -d "$STAGE_DIR" ]; then /bin/rm -rf "$STAGE_DIR"; fi' EXIT
/usr/bin/ditto "$DIST_DIR/RegionGuard.app" "$STAGE_DIR/RegionGuard.app"
/bin/ln -s /Applications "$STAGE_DIR/Applications"
/usr/bin/hdiutil create -volname RegionGuard -srcfolder "$STAGE_DIR" -ov -format UDZO "$DIST_DIR/RegionGuard-macOS.dmg"
"$PY_BUILD" - "$DIST_DIR" <<'HASH_PY'
import hashlib
from pathlib import Path
import sys
image = Path(sys.argv[1]) / 'RegionGuard-macOS.dmg'
digest = hashlib.sha256(image.read_bytes()).hexdigest()
image.with_suffix('.dmg.sha256').write_text(digest + '  ' + image.name + '\n')
HASH_PY
echo "构建完成: $DIST_DIR/RegionGuard.app 与 $DIST_DIR/RegionGuard-macOS.dmg"

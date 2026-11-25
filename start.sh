#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${1:-8765}"

if command -v python3 >/dev/null 2>&1; then
  PY_BIN="$(command -v python3)"
elif [ -x /usr/bin/python3 ]; then
  PY_BIN="/usr/bin/python3"
else
  echo "Error: python3 (3.9+) not found." >&2
  exit 1
fi

echo "Starting Region Guard on http://127.0.0.1:${PORT} ..."
exec "${PY_BIN}" "${DIR}/server.py" --host 127.0.0.1 --port "${PORT}"

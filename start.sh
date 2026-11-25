#!/usr/bin/env zsh
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${1:-8765}"

echo "Starting Region Guard on http://127.0.0.1:${PORT} ..."
exec /usr/bin/python3 "${DIR}/server.py" --host 127.0.0.1 --port "${PORT}"

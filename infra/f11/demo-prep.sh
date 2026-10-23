#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV_PY="$ROOT/backend/.venv/bin/python"

if [[ -x "$VENV_PY" ]]; then
  PY="$VENV_PY"
else
  PY="python3"
fi

exec "$PY" "$ROOT/infra/f11/demo-prep.py" "$@"
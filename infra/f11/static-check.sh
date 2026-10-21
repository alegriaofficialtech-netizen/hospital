#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "== repository status =="
git status --short

echo "== python syntax (AST, no bytecode) =="
PYTHONDONTWRITEBYTECODE=1 backend/.venv/bin/python - <<'PY'
import ast
import pathlib
import sys

roots = [
    pathlib.Path("backend"),
    pathlib.Path("tests/e2e"),
    pathlib.Path("infra/local-test"),
]
files = sorted(
    path
    for root in roots
    for path in root.rglob("*.py")
    if ".venv" not in path.parts and "__pycache__" not in path.parts
)
errors = []
for path in files:
    try:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        errors.append(f"{path}:{exc.lineno}: {exc.msg}")
print(f"parsed={len(files)} errors={len(errors)}")
for error in errors:
    print(f"ERROR {error}")
sys.exit(1 if errors else 0)
PY

echo "== python dependency consistency =="
backend/.venv/bin/python -m pip check

echo "== shell syntax =="
for script in infra/f11/*.sh; do
  bash -n "$script"
done
echo "shell syntax OK"

echo "== F11 backend env JSON =="
if [[ -r infra/f11/backend.env ]]; then
  (
    set -a
    # shellcheck disable=SC1091
    . infra/f11/backend.env
    set +a
    python3 - <<'PY'
import json
import os

raw = os.environ.get("IOMT_DEVICE_KEYS_JSON")
if not raw:
    raise SystemExit("IOMT_DEVICE_KEYS_JSON is missing")
data = json.loads(raw)
if not isinstance(data, dict) or not data:
    raise SystemExit("IOMT_DEVICE_KEYS_JSON must be a non-empty object")
print(f"env JSON OK: {len(data)} device(s)")
PY
  )
else
  echo "skipped: infra/f11/backend.env not present"
fi

echo "== compose model =="
docker compose --env-file infra/f11/.env -f infra/f11/compose.yaml config --quiet
docker compose --env-file infra/f11/.env -f infra/f11/compose.yaml config --services

echo "== systemd unit syntax =="
systemd-analyze verify infra/f11/systemd/sgsi-zta-f11-backend.service

echo "== silent-check-sso references =="
if git grep -n 'silent-check-sso' -- frontend/src frontend/public; then
  echo "unexpected silent-check-sso reference" >&2
  exit 1
fi
echo "none"

echo "== whitespace =="
git diff --check
git diff --cached --check

echo "static checks passed"

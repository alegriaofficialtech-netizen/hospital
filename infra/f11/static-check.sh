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

root = pathlib.Path("backend")
files = sorted(
    path
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

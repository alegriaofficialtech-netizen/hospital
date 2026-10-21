#!/usr/bin/env bash
# Run the F11 API suite against an already running stack.
#
# This script never starts a service, never builds an image and never touches
# the Playwright path: Stage C is decoupled from it. The preflight gate
# (stage "api") must admit both the host and the running stack first.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="$ROOT/infra/f11/preflight-gate.sh"
VENV_PY="$ROOT/backend/.venv/bin/python"
SUITE_DIR="$ROOT/infra/f11/api-tests"
RUNTIME="${F11_RUNTIME_DIR:-/home/elcra/sgsi-zta-runtime/f11}"

export F11_CREDENTIALS_FILE="${F11_CREDENTIALS_FILE:-$RUNTIME/credentials.json}"

echo "== preflight (stage api) =="
if ! "$GATE" --stage api; then
  echo "error: preflight refused; the API suite did not run" >&2
  exit 1
fi

[[ -x "$VENV_PY" ]] || { echo "error: missing $VENV_PY" >&2; exit 1; }
[[ -d "$SUITE_DIR" ]] || { echo "error: missing $SUITE_DIR" >&2; exit 1; }

echo
echo "== API suite (JWT, RBAC, MFA TOTP, audit) =="
PYTHONDONTWRITEBYTECODE=1 "$VENV_PY" -m unittest discover \
  --start-directory "$SUITE_DIR" --pattern 'test_*.py' --verbose

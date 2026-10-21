#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME="${F11_RUNTIME_DIR:-/home/elcra/sgsi-zta-runtime/f11}"
CREDENTIALS="${F11_CREDENTIALS_FILE:-$RUNTIME/credentials.json}"
SECRETS="${F11_SECRETS_FILE:-$RUNTIME/e2e-secrets.json}"
API_URL="${F11_API_BASE_URL:-http://127.0.0.1:8010}"
BASE_URL="${F11_BASE_URL:-http://127.0.0.1:4200}"
AUDIENCE="${KEYCLOAK_AUDIENCE:-clinical-poc-api}"

load1="$(awk '{print $1}' /proc/loadavg)"
mem_available_kib="$(awk '/MemAvailable/ {print $2}' /proc/meminfo)"

if ! awk -v load="$load1" 'BEGIN { exit !(load < 2.0) }'; then
  echo "refusing E2E: load average $load1 is not below 2.0" >&2
  exit 1
fi
if (( mem_available_kib < 3145728 )); then
  echo "refusing E2E: MemAvailable ${mem_available_kib} KiB is below 3 GiB" >&2
  exit 1
fi

for file in "$CREDENTIALS" "$SECRETS"; do
  if [[ ! -r "$file" ]]; then
    echo "missing E2E input: $file" >&2
    exit 1
  fi
done

"$ROOT/infra/f11/health-check.sh"

echo "== Python API E2E: real Keycloak login, JWT claims, RBAC, TOTP/MFA, clinical flow =="
"$ROOT/backend/.venv/bin/python" "$ROOT/tests/e2e/test_real_stack.py" \
  --base-url "$API_URL" \
  --credentials "$CREDENTIALS" \
  --secrets "$SECRETS" \
  --audience "$AUDIENCE"

echo "== Playwright UI E2E: Angular + Keycloak login, TOTP, RBAC route guards, clinical flow =="
docker build -f "$ROOT/frontend/e2e.Dockerfile" -t sgsi-zta-f11-e2e:local "$ROOT/frontend"
docker run --rm \
  --network host \
  --ipc=host \
  --cpus 1.0 \
  --memory 1g \
  --pids-limit 256 \
  -e F11_BASE_URL="$BASE_URL" \
  -e F11_API_BASE_URL="$API_URL" \
  -e F11_CREDENTIALS_FILE=/runtime/credentials.json \
  -e F11_SECRETS_FILE=/runtime/e2e-secrets.json \
  -e F11_CHROMIUM_NO_SANDBOX=1 \
  -v "$RUNTIME:/runtime:ro" \
  sgsi-zta-f11-e2e:local

echo "E2E completed"

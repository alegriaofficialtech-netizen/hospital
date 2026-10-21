#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME="${F11_RUNTIME_DIR:-/home/elcra/sgsi-zta-runtime/f11}"
CREDENTIALS="${F11_CREDENTIALS_FILE:-$RUNTIME/credentials.json}"
SECRETS="${F11_SECRETS_FILE:-$RUNTIME/e2e-secrets.json}"
API_URL="${F11_API_BASE_URL:-http://127.0.0.1:8010}"
BASE_URL="${F11_BASE_URL:-http://127.0.0.1:4200}"
AUDIENCE="${KEYCLOAK_AUDIENCE:-clinical-poc-api}"

STATE_DIR="$RUNTIME/state"

# Admission control: CPU pressure (PSI), memory, swap, temperature, host
# stability (reboot / OOM continuity), port and stack state.
# The former `load1 < 2.0` check was removed after measurement: on this 4-thread
# host load1 never dropped below 2.29 in a 3 h window (0/181 samples), so it
# refused every run while the host still had CPU headroom. See
# infra/f11/README.md, section "Preflight gate".
"$ROOT/infra/f11/preflight-gate.sh" --stage e2e

# Mark the run active so a reboot mid-run is detected by the next gate run
# instead of being silently forgotten.
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR" 2>/dev/null || true
cat /proc/sys/kernel/random/boot_id > "$STATE_DIR/run-active"
trap 'rm -f "$STATE_DIR/run-active"' EXIT

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
# The E2E image is built by infra/f11/build-images.sh (Stage B), never here:
# build and test must not share a step, otherwise a compile failure is reported
# as a test failure and the run pollutes the measured window.
if ! docker image inspect sgsi-zta-f11-e2e:local >/dev/null 2>&1; then
  echo "missing image sgsi-zta-f11-e2e:local" >&2
  echo "run infra/f11/build-images.sh first" >&2
  exit 1
fi
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

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="$ROOT/infra/f11/backend.env"
OUT_FILE="${1:-/home/elcra/sgsi-zta-runtime/f11/e2e-secrets.json}"

if [[ ! -r "$ENV_FILE" ]]; then
  echo "missing backend env file: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

umask 077
python3 - "$OUT_FILE" <<'PY'
import json
import os
import sys
from pathlib import Path

raw = os.environ.get("IOMT_DEVICE_KEYS_JSON")
if not raw:
    raise SystemExit("IOMT_DEVICE_KEYS_JSON is missing")

try:
    devices = json.loads(raw)
except json.JSONDecodeError as exc:
    raise SystemExit(f"IOMT_DEVICE_KEYS_JSON is not valid JSON: {exc}") from exc

if not isinstance(devices, dict) or not devices:
    raise SystemExit("IOMT_DEVICE_KEYS_JSON must be a non-empty object")

device_id = next(iter(devices))
device_key = devices[device_id]
if not isinstance(device_key, str) or len(device_key) < 16:
    raise SystemExit("the selected IoMT device key must be a string of at least 16 characters")

out = Path(sys.argv[1])
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(
    json.dumps({"iomtDeviceId": device_id, "iomtDeviceKey": device_key}, indent=2) + "\n",
    encoding="utf-8",
)
out.chmod(0o600)
print(f"wrote {out} for device {device_id}")
PY

#!/usr/bin/env bash
# Stage B -- package prebuilt artifacts into images. Never compiles Angular.
#
# B1  runtime image  : copies frontend/.f11-dist/browser into Caddy. Seconds.
# B2  e2e image      : Playwright + Chromium. Heavy, cached, only built when
#                      missing (or with --rebuild-e2e).
#
# `docker build` cannot be cgroup-limited through the stable CLI. For B2 you can
# opt into a dedicated BuildKit builder whose daemon runs inside a limited
# container (memory + CPU quota). It is created under a fixed name and is NOT
# made the default builder, so other projects are unaffected.
#
# Usage:
#   build-images.sh [--rebuild-e2e] [--limited-e2e-builder]
#
# Environment:
#   F11_FRONTEND_IMAGE=sgsi-zta-f11-frontend:local
#   F11_E2E_IMAGE=sgsi-zta-f11-e2e:local
#   F11_E2E_BUILDER_MEM=3g
#   F11_E2E_BUILDER_CPU_QUOTA=200000   (100000 = 1 core)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FRONTEND="$ROOT/frontend"
GATE="$ROOT/infra/f11/preflight-gate.sh"

FRONTEND_IMAGE="${F11_FRONTEND_IMAGE:-sgsi-zta-f11-frontend:local}"
E2E_IMAGE="${F11_E2E_IMAGE:-sgsi-zta-f11-e2e:local}"
BUILDER="${F11_E2E_BUILDER:-sgsi-zta-f11-builder}"
BUILDER_MEM="${F11_E2E_BUILDER_MEM:-3g}"
BUILDER_QUOTA="${F11_E2E_BUILDER_CPU_QUOTA:-200000}"

REBUILD_E2E=0
LIMITED=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rebuild-e2e) REBUILD_E2E=1; shift ;;
    --limited-e2e-builder) LIMITED=1; shift ;;
    -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

ARTIFACTS="$FRONTEND/.f11-dist/browser"
if [[ ! -f "$ARTIFACTS/index.html" ]]; then
  echo "missing $ARTIFACTS/index.html" >&2
  echo "run infra/f11/build-artifacts.sh first (Stage A)" >&2
  exit 1
fi

"$GATE" --stage build

echo "== B1: runtime image $FRONTEND_IMAGE (no compilation) =="
docker build \
  -f "$FRONTEND/Dockerfile.prebuilt" \
  -t "$FRONTEND_IMAGE" \
  "$FRONTEND"

echo
if (( REBUILD_E2E == 0 )) && docker image inspect "$E2E_IMAGE" >/dev/null 2>&1; then
  echo "== B2: $E2E_IMAGE already present, skipped (use --rebuild-e2e to force) =="
else
  echo "== B2: e2e image $E2E_IMAGE (Playwright + Chromium; one-time, cached in layers) =="
  if (( LIMITED == 1 )); then
    echo "   limited BuildKit builder: $BUILDER (mem=${BUILDER_MEM} cpu-quota=${BUILDER_QUOTA})"
    if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
      docker buildx create \
        --name "$BUILDER" \
        --driver docker-container \
        --driver-opt "memory=${BUILDER_MEM},cpu-quota=${BUILDER_QUOTA}"
    fi
    docker buildx build \
      --builder "$BUILDER" \
      --load \
      -f "$FRONTEND/e2e.Dockerfile" \
      -t "$E2E_IMAGE" \
      "$FRONTEND"
  else
    echo "   note: plain docker build runs unconstrained on the daemon;"
    echo "         pass --limited-e2e-builder for a cgroup-limited builder."
    docker build \
      -f "$FRONTEND/e2e.Dockerfile" \
      -t "$E2E_IMAGE" \
      "$FRONTEND"
  fi
fi

echo
echo "images:"
docker images --format '  {{.Repository}}:{{.Tag}}  {{.Size}}' "$FRONTEND_IMAGE" "$E2E_IMAGE" 2>/dev/null || true
echo
echo "Stage B OK"
if (( LIMITED == 1 )); then
  echo "remove the limited builder when done: docker buildx rm $BUILDER"
fi
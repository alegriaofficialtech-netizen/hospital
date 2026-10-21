#!/usr/bin/env bash
# Stage A -- compile the Angular frontend under enforced cgroup limits.
#
# Why not `docker build`?
#   The stable Docker CLI cannot apply CPU/memory limits to a build, so the old
#   Dockerfile compiled Angular inside an unconstrained build container. On a
#   4-thread, 15 W CPU that competes with every other workload on the host.
#   Here the compiler runs in a plain container whose --cpus / --memory /
#   --pids-limit are real cgroup v2 limits, and the result is packaged
#   afterwards by build-images.sh (Stage B, no compilation).
#
# Output: frontend/.f11-dist/browser  (consumed by frontend/Dockerfile.prebuilt)
#
# Usage:
#   build-artifacts.sh [--skip-gate]
#
# Tunables (environment):
#   F11_BUILD_CPUS=2.0     CPU cores the compiler may use
#   F11_BUILD_MEM=3g       hard memory ceiling (swap disabled inside)
#   F11_BUILD_PIDS=512     process ceiling (npm spawns many workers)
#   F11_NODE_HEAP_MB=2048  Node old-space ceiling, must stay below F11_BUILD_MEM
#   F11_NODE_IMAGE=node:22-bookworm-slim
#   F11_BUILD_SOURCEMAPS=0 source maps are off for the F11 static build;
#                           set to 1 to keep them for debugging (adds ~5.7 MB
#                           of .map files to the runtime image)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FRONTEND="$ROOT/frontend"
GATE="$ROOT/infra/f11/preflight-gate.sh"

BUILD_CPUS="${F11_BUILD_CPUS:-2.0}"
BUILD_MEM="${F11_BUILD_MEM:-3g}"
BUILD_PIDS="${F11_BUILD_PIDS:-512}"
NODE_HEAP_MB="${F11_NODE_HEAP_MB:-2048}"
NODE_IMAGE="${F11_NODE_IMAGE:-node:22-bookworm-slim}"
OUT_DIR=".f11-dist"
if [[ "${F11_BUILD_SOURCEMAPS:-0}" == "1" ]]; then
  SOURCE_MAP_FLAG="--source-map=true"
else
  SOURCE_MAP_FLAG="--source-map=false"
fi

SKIP_GATE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-gate) SKIP_GATE=1; shift ;;
    -h|--help) sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -f "$FRONTEND/package-lock.json" ]] || { echo "missing frontend/package-lock.json" >&2; exit 1; }

if (( SKIP_GATE == 0 )); then
  "$GATE" --stage build
fi

echo "== Stage A: Angular build (cpus=${BUILD_CPUS} mem=${BUILD_MEM} pids=${BUILD_PIDS} heap=${NODE_HEAP_MB}M sourcemaps=${F11_BUILD_SOURCEMAPS:-0}) =="

rm -rf "${FRONTEND:?}/$OUT_DIR"

started="$(date +%s)"

docker run --rm \
  --cpus "$BUILD_CPUS" \
  --memory "$BUILD_MEM" \
  --memory-swap "$BUILD_MEM" \
  --pids-limit "$BUILD_PIDS" \
  --label com.sgsi-zta.component=f11-build \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e CI=1 \
  -e NG_CLI_ANALYTICS=false \
  -e NODE_OPTIONS="--max-old-space-size=${NODE_HEAP_MB}" \
  -e npm_config_cache=/tmp/npm-cache \
  -v "$FRONTEND:/app" \
  -w /app \
  "$NODE_IMAGE" \
  sh -c "npm ci --no-audit --no-fund && npm run build -- --configuration local-real --output-path=$OUT_DIR $SOURCE_MAP_FLAG"

elapsed=$(( $(date +%s) - started ))

if [[ "${F11_BUILD_SOURCEMAPS:-0}" != "1" ]]; then
  maps="$(find "$FRONTEND/$OUT_DIR" -name '*.map' | wc -l)"
  if [[ "$maps" -ne 0 ]]; then
    echo "build emitted $maps source maps despite --source-map=false" >&2
    exit 1
  fi
fi

INDEX="$FRONTEND/$OUT_DIR/browser/index.html"
if [[ ! -f "$INDEX" ]]; then
  echo "build finished in ${elapsed}s but produced no $INDEX" >&2
  exit 1
fi

size="$(du -sh "$FRONTEND/$OUT_DIR/browser" | cut -f1)"
echo
echo "Stage A OK in ${elapsed}s -> frontend/$OUT_DIR/browser (${size})"
echo "next: infra/f11/build-images.sh"
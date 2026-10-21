#!/usr/bin/env bash
set -euo pipefail

KEYCLOAK_URL="${F11_KEYCLOAK_URL:-http://127.0.0.1:8085}"
BACKEND_URL="${F11_API_BASE_URL:-http://127.0.0.1:8010}"
FRONTEND_URL="${F11_BASE_URL:-http://127.0.0.1:4200}"

curl -fsS --max-time 5 \
  "$KEYCLOAK_URL/realms/hospital-lab-local/.well-known/openid-configuration" >/dev/null
curl -fsS --max-time 5 "$BACKEND_URL/health" >/dev/null
curl -fsS --max-time 5 "$FRONTEND_URL/" >/dev/null

echo "health OK: keycloak + backend + frontend"

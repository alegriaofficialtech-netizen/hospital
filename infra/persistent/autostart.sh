#!/usr/bin/env bash
# SGSI-ZTA Hospital Lab: Arranque y persistencia del despliegue web HTTPS
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME="/home/elcra/sgsi-zta-runtime/f11"
CADDYFILE="$ROOT/infra/persistent/Caddyfile"
FRONTEND_DIST="$ROOT/frontend/.f11-dist/browser"

echo "=== SGSI-ZTA HOSPITAL LAB: AUTOSTART DESPLIEGUE WEB PERMANENTE ==="

# 1. Asegurar Keycloak
echo "[1/4] Verificando Keycloak (puerto 8085)..."
if ! curl -s -f -o /dev/null "http://127.0.0.1:8085/realms/hospital-lab-local/.well-known/openid-configuration" 2>/dev/null; then
  echo "      Iniciando contenedor Keycloak..."
  (cd "$ROOT/infra/f11" && docker compose --env-file .env up -d --no-deps keycloak)
fi

# 2. Asegurar backend demo aislado (puerto 8011)
echo "[2/4] Verificando backend demo (puerto 8011)..."
"$ROOT/infra/f11/demo-instance.sh" start

# 3. Asegurar gateway web Caddy (puerto 8020)
echo "[3/4] Verificando gateway Caddy (puerto 8020)..."
if ! docker ps --format '{{.Names}}' | grep -q "^sgsi-zta-web-gateway$"; then
  echo "      Iniciando contenedor sgsi-zta-web-gateway..."
  docker run -d     --name sgsi-zta-web-gateway     --restart unless-stopped     --network host     -v "$CADDYFILE:/etc/caddy/Caddyfile:ro"     -v "$FRONTEND_DIST:/usr/share/caddy:ro"     caddy:2.11-alpine
else
  echo "      Contenedor sgsi-zta-web-gateway ya activo."
fi

# 4. Asegurar Tailscale Serve (HTTPS 8443)
echo "[4/4] Verificando Tailscale Serve HTTPS (puerto 8443)..."
if ! tailscale serve status 2>/dev/null | grep -q "8443"; then
  echo "      Configurando Tailscale Serve HTTPS..."
  tailscale serve --bg --https=8443 http://127.0.0.1:8020
fi

echo "=== ESTADO DE SALUD DEL DESPLIEGUE ==="
curl -s "http://127.0.0.1:8011/health" && echo
echo "[+] URL permanente: https://servidor-1.tailb0f78a.ts.net:8443"

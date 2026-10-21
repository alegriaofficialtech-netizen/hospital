#!/usr/bin/env bash
# ==============================================================================
# identity_up.sh - Arranca SOLO el plano de identidad (Keycloak + gateway TLS).
#
# No toca el LIS ni el audit-monitor. Sirve para resolver el bloqueo "Keycloak
# detenido" antes del preflight: el issuer canónico debe existir y responder
# antes de cortar el LIS.
#
# Por defecto es SIMULACIÓN: muestra el plan y valida el material TLS.
# Con --apply escribe el compose/Caddyfile y arranca los servicios.
#
# Uso:
#   ./identity_up.sh                      # dry-run
#   ./identity_up.sh --apply              # escritura + arranque real
#   ./identity_up.sh --apply --target-dir=/tmp/copia   # ensayo aislado
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROD_DIR="/opt/sgsi-zta-hospital-lab"
TLS_DIR="${SGSI_TLS_DIR:-/etc/sgsi-zta/tls}"
CANONICAL_BASE_URL="${LIS_CANONICAL_BASE_URL:-https://servidor-1.tailb0f78a.ts.net:8443}"
CANONICAL_HOST="$(printf '%s' "$CANONICAL_BASE_URL" | sed -E 's#^https?://([^:/]+).*#\1#')"
CANONICAL_PORT="$(printf '%s' "$CANONICAL_BASE_URL" | sed -E 's#^https?://[^:/]+:?([0-9]*).*#\1#')"
CANONICAL_PORT="${CANONICAL_PORT:-443}"
CANONICAL_BIND_IP="100.78.61.51"
APPLY=0
NO_START=0
TIMEOUT=120
REALM_EXPORT_FILE="${SGSI_REALM_EXPORT_FILE:-/home/elcra/sgsi-backups/realm/hospital-lab-realm-production.json}"
SKIP_REALM_INSTALL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
ok()   { echo -e "${GREEN}[PASS]${NC} $*"; }

for arg in "$@"; do
  case "$arg" in
    --apply)           APPLY=1 ;;
    --dry-run)         APPLY=0 ;;
    --no-start)        NO_START=1 ;;
    --target-dir=*)    PROD_DIR="${arg#*=}" ;;
    --tls-dir=*)       TLS_DIR="${arg#*=}" ;;
    --timeout=*)       TIMEOUT="${arg#*=}" ;;
    --realm-export-file=*) REALM_EXPORT_FILE="${arg#*=}" ;;
    --skip-realm-install)  SKIP_REALM_INSTALL=1 ;;
    --help)            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail "Argumento desconocido: $arg" ;;
  esac
done

[ -f "${PROD_DIR}/docker-compose.yml" ] || fail "No existe ${PROD_DIR}/docker-compose.yml"

echo "=============================================================================="
echo " IDENTITY UP (solo Keycloak + gateway)"
echo " Modo    : $([ $APPLY -eq 1 ] && echo 'APLICAR' || echo 'SIMULACIÓN')"
echo " Compose : ${PROD_DIR}/docker-compose.yml"
echo " TLS     : ${TLS_DIR}"
echo " Issuer  : ${CANONICAL_BASE_URL}/realms/hospital-lab"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# 1. Material TLS (sin que el operador lea la clave)
# ------------------------------------------------------------------------------
echo "[PASO 1] Validando material TLS..."
TLS_PROBE="$(docker run --rm -e PROBE_HOST="$CANONICAL_HOST" -v "${TLS_DIR}:/certs:ro" \
  python:3.12-slim-bookworm sh -c '
set -u
C=/certs/fullchain.pem; K=/certs/privkey.pem
[ -r "$C" ] && [ -r "$K" ] || { echo MISSING; exit 0; }
echo "CHAIN=$(grep -c "BEGIN CERTIFICATE" "$C")"
if openssl x509 -in "$C" -noout -ext subjectAltName 2>/dev/null | grep -c "DNS:${PROBE_HOST}" >/dev/null; then echo SAN_OK=yes; else echo SAN_OK=no; fi
CP=$(openssl x509 -in "$C" -pubkey -noout 2>/dev/null | sha256sum | cut -d" " -f1)
KP=$(openssl pkey -in "$K" -pubout 2>/dev/null | sha256sum | cut -d" " -f1)
[ -n "$CP" ] && [ "$CP" = "$KP" ] && echo KEY_MATCH=yes || echo KEY_MATCH=no
END=$(openssl x509 -in "$C" -noout -enddate | cut -d= -f2)
echo "DAYS=$(( ( $(date -d "$END" +%s) - $(date +%s) ) / 86400 ))"
echo "KEY_MODE=$(stat -c %a "$K")"
' 2>&1)" || fail "No se pudo inspeccionar ${TLS_DIR}."

echo "$TLS_PROBE" | grep -c '^CHAIN=' >/dev/null || fail "Material TLS incompleto en ${TLS_DIR}."
echo "$TLS_PROBE" | grep -c '^SAN_OK=yes' >/dev/null || fail "El certificado no cubre ${CANONICAL_HOST}."
echo "$TLS_PROBE" | grep -c '^KEY_MATCH=yes' >/dev/null || fail "La clave no corresponde al certificado."
DAYS_LEFT="$(echo "$TLS_PROBE" | sed -n 's/^DAYS=//p')"
[ "${DAYS_LEFT:-0}" -gt 0 ] || fail "El certificado está vencido."
KEY_MODE="$(echo "$TLS_PROBE" | sed -n 's/^KEY_MODE=//p')"
case "$KEY_MODE" in *4|*6|*7) fail "Clave legible por otros (modo ${KEY_MODE})." ;; esac
ok "TLS válido: ${DAYS_LEFT} días, clave ${KEY_MODE}."

if [ "$APPLY" -eq 0 ]; then
  echo "[PLAN] 1. Actualizar ${PROD_DIR}/docker-compose.yml (gateway + KC_HOSTNAME)."
  echo "[PLAN] 2. Escribir ${PROD_DIR}/config/keycloak/identity-gateway.Caddyfile."
  echo "[PLAN] 3. Instalar el realm export válido en ${PROD_DIR}/config/keycloak/hospital-lab-realm.json (con backup)."
  echo "[PLAN] 4. docker compose --profile identidad up -d keycloak-postgres keycloak identity-gateway."
  echo "[PLAN] 5. Esperar el discovery canónico."
  ok "Dry-run completado. Use --apply para ejecutar."
  exit 0
fi

# ------------------------------------------------------------------------------
# 2. Compose: gateway + KC_HOSTNAME
# ------------------------------------------------------------------------------
echo "[PASO 2] Actualizando docker-compose.yml..."
python3 - "${PROD_DIR}/docker-compose.yml" "$CANONICAL_BASE_URL" "$CANONICAL_HOST" \
  "$CANONICAL_PORT" "$CANONICAL_BIND_IP" "$TLS_DIR" <<'PY'
import os
import sys

import yaml

path, canonical_base, canonical_host, canonical_port, bind_ip, tls_dir = sys.argv[1:7]
with open(path, "r", encoding="utf-8") as handle:
    data = yaml.safe_load(handle) or {}

keycloak = (data.get("services") or {}).get("keycloak")
if keycloak is None:
    raise SystemExit("[FAIL] servicio keycloak ausente")
env = keycloak.get("environment") or {}
if isinstance(env, list):
    env = dict(item.split("=", 1) for item in env if "=" in item)
env["KC_HOSTNAME"] = canonical_base
keycloak["environment"] = env

services = data.setdefault("services", {})
gateway = services.get("identity-gateway")
if gateway is None:
    services["identity-gateway"] = {
        "image": "${CADDY_IMAGE:-caddy:2.11-alpine}",
        "profiles": ["identidad"],
        "volumes": [
            "./config/keycloak/identity-gateway.Caddyfile:/etc/caddy/Caddyfile:ro",
            f"{tls_dir}:/certs:ro",
        ],
        "ports": [f"{bind_ip}:{canonical_port}:{canonical_port}"],
        "networks": {
            "identity-ui": {},
            "clinical": {"aliases": [canonical_host]},
        },
        "depends_on": {"keycloak": {"condition": "service_healthy"}},
        "restart": "no",
    }
else:
    volumes = [item for item in (gateway.get("volumes") or [])
               if not (isinstance(item, str) and item.endswith(":/certs:ro"))]
    volumes.append(f"{tls_dir}:/certs:ro")
    gateway["volumes"] = volumes
    gateway["ports"] = [f"{bind_ip}:{canonical_port}:{canonical_port}"]

tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    yaml.safe_dump(data, handle, sort_keys=False, allow_unicode=True)
os.chmod(tmp, 0o600)
os.replace(tmp, path)
print("[PASS] compose actualizado")
PY
ok "Compose actualizado."

# ------------------------------------------------------------------------------
# 3. Caddyfile
# ------------------------------------------------------------------------------
echo "[PASO 3] Escribiendo Caddyfile..."
mkdir -p "${PROD_DIR}/config/keycloak"
cat > "${PROD_DIR}/config/keycloak/identity-gateway.Caddyfile" <<CADDY
https://${CANONICAL_HOST}:${CANONICAL_PORT} {
    tls /certs/fullchain.pem /certs/privkey.pem
    header {
        Strict-Transport-Security "max-age=86400"
        X-Content-Type-Options "nosniff"
        -Server
    }
    @admin_block {
        path /admin /admin/* /realms/master /realms/master/*
    }
    respond @admin_block "Access to administration endpoints is prohibited." 403
    reverse_proxy keycloak:8080 {
        header_up Host {host}
        header_up X-Forwarded-Proto https
        header_up X-Forwarded-Port ${CANONICAL_PORT}
        header_up X-Forwarded-For {remote_host}
    }
}
CADDY
chmod 0644 "${PROD_DIR}/config/keycloak/identity-gateway.Caddyfile"
ok "Caddyfile escrito."

# ------------------------------------------------------------------------------
# 3b. Realm de importación válido (reemplaza el export antiguo inválido)
# ------------------------------------------------------------------------------
if [ "$SKIP_REALM_INSTALL" -eq 0 ]; then
  if [ -f "$REALM_EXPORT_FILE" ]; then
    echo "[PASO 3b] Validando e instalando el realm export..."
    python3 - "$REALM_EXPORT_FILE" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
if data.get("realm") != "hospital-lab":
    raise SystemExit(f"[FAIL] realm inesperado: {data.get('realm')!r}")
flows = data.get("authenticationFlows") or []
if not flows:
    raise SystemExit("[FAIL] el export no contiene authenticationFlows")
for flow in flows:
    if not flow.get("id"):
        raise SystemExit("[FAIL] flujo sin id")
    if flow.get("authenticationExecutions") is None:
        raise SystemExit("[FAIL] flujo sin authenticationExecutions")
print(f"flujos={len(flows)} clientes={len(data.get('clients') or [])} usuarios={len(data.get('users') or [])}")
PY
    IMPORT_TARGET="${PROD_DIR}/config/keycloak/hospital-lab-realm.json"
    if [ -f "$IMPORT_TARGET" ]; then
      cp -p "$IMPORT_TARGET" "${IMPORT_TARGET}.bak.$(date +%Y%m%d%H%M%S)"
    fi
    if [ "$(id -u)" -eq 0 ]; then
      install -m 0600 -o 1000 -g 1000 "$REALM_EXPORT_FILE" "$IMPORT_TARGET"
    else
      install -m 0600 "$REALM_EXPORT_FILE" "$IMPORT_TARGET"
    fi
    ok "Realm export instalado en el path de importación (0600)."
  else
    warn "No existe ${REALM_EXPORT_FILE}; se conserva el archivo de importación actual."
  fi
else
  warn "--skip-realm-install: no se reemplaza el archivo de importación."
fi

if [ "$NO_START" -eq 1 ]; then
  warn "--no-start: configuración aplicada, servicios no arrancados."
  exit 0
fi

# ------------------------------------------------------------------------------
# 4. Arranque y espera del issuer canónico
# ------------------------------------------------------------------------------
echo "[PASO 4] Arrancando keycloak-postgres, keycloak e identity-gateway..."
docker compose -f "${PROD_DIR}/docker-compose.yml" --profile identidad \
  up -d keycloak-postgres keycloak identity-gateway

echo "[PASO 5] Esperando el discovery canónico (máx. ${TIMEOUT}s)..."
READY=0
for _ in $(seq 1 "$TIMEOUT"); do
  if curl -sf --max-time 2 \
      "${CANONICAL_BASE_URL}/realms/hospital-lab/.well-known/openid-configuration" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
if [ "$READY" -ne 1 ]; then
  docker compose -f "${PROD_DIR}/docker-compose.yml" --profile identidad logs --tail=30 keycloak >&2 || true
  fail "El issuer canónico no respondió. Revise keycloak/identity-gateway."
fi
ok "Issuer canónico disponible: ${CANONICAL_BASE_URL}/realms/hospital-lab"
echo " Siguiente: preflight_check.py y luego cutover_deploy.sh --apply."

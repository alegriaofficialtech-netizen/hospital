#!/usr/bin/env bash
# ==============================================================================
# cutover_deploy.sh - Despliegue coordinado del LIS y audit-monitor
# SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 & NIST SP 800-207
#
# Cambios respecto de la versión anterior:
#   - Copia `clinical_domain.py` (sin él el backend no importa).
#   - Verifica MANIFEST.sha256 antes y después de copiar.
#   - Escritura atómica (temporal + mv) y respaldo de lo reemplazado.
#   - Edita docker-compose.yml como YAML real (antes usaba json.load y fallaba).
#   - Inyecta el contrato de entorno: LIS_DB_PATH, ENABLE_LEGACY_AUTH,
#     IOMT_DEVICE_KEYS_JSON, IOMT_MAX_CLOCK_SKEW_SECONDS, IOMT_NONCE_TTL_SECONDS.
#   - Garantiza el ancla de auditoría en el volumen antes del arranque.
#   - Espera /health real y ejecuta la verificación post-cutover.
#   - Si el health falla, ejecuta rollback automático.
#
# Gateway TLS:
#   - Monta /etc/sgsi-zta/tls en solo lectura; no copia ni cambia permisos de
#     la clave privada (0600 root). La validación se hace dentro de un
#     contenedor porque el operador no necesita leer la clave.
#   - Exige fullchain.pem (hoja + cadena) y privkey.pem, SAN del host canónico,
#     coincidencia cert/clave y vigencia > 0.
#
# Contrato adicional:
#   - --clinical-image=IMAGE   imagen con cryptography (se escribe en .env)
#   - --monitor-secret-file=   credenciales M2M 0600 (nunca se imprimen)
#   - --realm-export-file=     artefacto de realm importable (resiliencia)
#
# Modo por defecto: SIMULACIÓN (--dry-run). Requiere --apply.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="$(dirname "$SCRIPT_DIR")"
CANDIDATE_DIR="${SANDBOX_DIR}/candidate_release"
PROD_DIR="/opt/sgsi-zta-hospital-lab"
PORT=8086
VOLUME_NAME="clinical-data"
CANONICAL_BASE_URL="${LIS_CANONICAL_BASE_URL:-https://servidor-1.tailb0f78a.ts.net:8443}"
CANONICAL_HOST="$(printf '%s' "$CANONICAL_BASE_URL" | sed -E 's#^https?://([^:/]+).*#\1#')"
CANONICAL_PORT="$(printf '%s' "$CANONICAL_BASE_URL" | sed -E 's#^https?://[^:/]+:?([0-9]*).*#\1#')"
CANONICAL_PORT="${CANONICAL_PORT:-443}"
CANONICAL_BIND_IP="100.78.61.51"
APPLY=0
NO_RESTART=0
SKIP_PREFLIGHT=0
SKIP_POST_VERIFY=0
DEVICE_KEYS_FILE=""
AUDIT_KEY_FILE=""
MONITOR_SECRET_FILE=""
REALM_EXPORT_FILE=""
TLS_DIR="${SGSI_TLS_DIR:-/etc/sgsi-zta/tls}"
CLINICAL_IMAGE_ARG="${CLINICAL_IMAGE:-}"
HEALTH_TIMEOUT=60
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

for arg in "$@"; do
  case "$arg" in
    --apply)              APPLY=1 ;;
    --dry-run)            APPLY=0 ;;
    --no-restart)         NO_RESTART=1 ;;
    --skip-preflight)     SKIP_PREFLIGHT=1 ;;
    --skip-post-verify)   SKIP_POST_VERIFY=1 ;;
    --target-dir=*)       PROD_DIR="${arg#*=}" ;;
    --port=*)             PORT="${arg#*=}" ;;
    --volume-name=*)      VOLUME_NAME="${arg#*=}" ;;
    --device-keys-file=*) DEVICE_KEYS_FILE="${arg#*=}" ;;
    --audit-key-file=*)   AUDIT_KEY_FILE="${arg#*=}" ;;
    --monitor-secret-file=*) MONITOR_SECRET_FILE="${arg#*=}" ;;
    --realm-export-file=*)   REALM_EXPORT_FILE="${arg#*=}" ;;
    --tls-dir=*)             TLS_DIR="${arg#*=}" ;;
    --clinical-image=*)      CLINICAL_IMAGE_ARG="${arg#*=}" ;;
    --health-timeout=*)   HEALTH_TIMEOUT="${arg#*=}" ;;
    --help)
      sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "[ERROR] Argumento desconocido: $arg" >&2
      exit 1
      ;;
  esac
done

fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
ok()   { echo -e "${GREEN}[PASS]${NC} $*"; }

TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
SNAPSHOT_DIR="${PROD_DIR}/.cutover_backup_${TIMESTAMP}"

# Módulos que deben existir y copiarse, con su destino relativo.
declare -A MODULES=(
  ["server.py"]="lis-backend/server.py"
  ["database.py"]="lis-backend/database.py"
  ["jwt_validator.py"]="lis-backend/jwt_validator.py"
  ["clinical_domain.py"]="lis-backend/clinical_domain.py"
  ["audit_monitor/monitor.py"]="audit-monitor/monitor.py"
)

echo "=============================================================================="
echo " CORTE Y DESPLIEGUE COORDINADO LIS (SGSI-ZTA CUTOVER)"
echo " Modo      : $([ $APPLY -eq 1 ] && echo 'APLICACIÓN REAL (--apply)' || echo 'SIMULACIÓN SEGURA (--dry-run)')"
echo " Objetivo  : $PROD_DIR"
echo " Puerto    : $PORT"
echo " Volumen   : $VOLUME_NAME"
echo " Reinicio  : $([ $NO_RESTART -eq 1 ] && echo 'NO' || echo 'SÍ')"
echo "=============================================================================="

if [ "$PORT" -eq 8088 ]; then
  warn "El puerto 8088 colisiona con 'stream-caddy'. Se recomienda 8086."
fi

# ------------------------------------------------------------------------------
# 1. Preflight
# ------------------------------------------------------------------------------
if [ $SKIP_PREFLIGHT -eq 0 ]; then
  echo "[PASO 1] Preflight..."
  PREFLIGHT_ARGS=(--port="$PORT")
  [ -n "$DEVICE_KEYS_FILE" ] && PREFLIGHT_ARGS+=(--device-keys-file="$DEVICE_KEYS_FILE")
  [ -n "$MONITOR_SECRET_FILE" ] && PREFLIGHT_ARGS+=(--monitor-secret-file="$MONITOR_SECRET_FILE")
  [ -n "$CLINICAL_IMAGE_ARG" ] && PREFLIGHT_ARGS+=(--clinical-image="$CLINICAL_IMAGE_ARG")
  [ -n "$REALM_EXPORT_FILE" ] && PREFLIGHT_ARGS+=(--realm-export-file="$REALM_EXPORT_FILE")
  python3 "${SCRIPT_DIR}/preflight_check.py" "${PREFLIGHT_ARGS[@]}" || fail "Preflight NO-GO. Despliegue abortado."
else
  warn "Preflight omitido por --skip-preflight (no recomendado)."
fi

# ------------------------------------------------------------------------------
# 2. Integridad del candidato
# ------------------------------------------------------------------------------
echo "[PASO 2] Verificando MANIFEST.sha256 del candidato..."
( cd "$CANDIDATE_DIR" && sha256sum -c MANIFEST.sha256 --quiet ) \
  || fail "Manifiesto del candidato inválido: no se despliega código no verificado."
ok "Candidato íntegro."

for module in "${!MODULES[@]}"; do
  [ -f "${CANDIDATE_DIR}/${module}" ] || fail "Falta el módulo candidato: ${module}"
done

# ------------------------------------------------------------------------------
# 3. Contrato de entorno: claves y ancla
# ------------------------------------------------------------------------------
echo "[PASO 3] Resolviendo contrato de entorno..."

if [ -n "$DEVICE_KEYS_FILE" ]; then
  [ -f "$DEVICE_KEYS_FILE" ] || fail "Archivo de claves IoMT inexistente: $DEVICE_KEYS_FILE"
  python3 - "$DEVICE_KEYS_FILE" <<'PY' || fail "El archivo de claves IoMT no es un objeto JSON válido."
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(data, dict) or not data:
    raise SystemExit("IOMT_DEVICE_KEYS_JSON debe ser un objeto no vacío")
for device, secret in data.items():
    if not isinstance(secret, str) or len(secret) < 16:
        raise SystemExit(f"Clave demasiado corta para {device} (mínimo 16 caracteres)")
print(f"[PASS] {len(data)} claves de dispositivo válidas.")
PY
  ok "Claves IoMT listas (contenido no mostrado)."
elif [ -n "${IOMT_DEVICE_KEYS_JSON:-}" ]; then
  ok "IOMT_DEVICE_KEYS_JSON presente en el entorno del operador."
else
  fail "Sin claves IoMT: use --device-keys-file o IOMT_DEVICE_KEYS_JSON."$'\n'\
       "        Sin claves el canal IoMT queda en 503 (A-01 exige configuración explícita)."
fi

if [ -n "$AUDIT_KEY_FILE" ]; then
  [ -f "$AUDIT_KEY_FILE" ] || fail "Archivo de ancla inexistente: $AUDIT_KEY_FILE"
  ok "Ancla de auditoría provista por archivo."
elif [ -n "${AUDIT_HMAC_KEY:-}" ]; then
  ok "Ancla de auditoría provista por entorno."
else
  warn "Sin AUDIT_HMAC_KEY: se usará <db>.anchor-key del volumen (válido si el ancla ya existe)."
fi

if [ -n "$MONITOR_SECRET_FILE" ]; then
  [ -f "$MONITOR_SECRET_FILE" ] || fail "Archivo de credenciales M2M inexistente: $MONITOR_SECRET_FILE"
  MONITOR_SECRET_VALUE="$(grep -E '^AUDIT_MONITOR_CLIENT_SECRET=' "$MONITOR_SECRET_FILE" | head -n 1 | cut -d= -f2-)"
  [ -n "$MONITOR_SECRET_VALUE" ] || fail "El archivo M2M no contiene AUDIT_MONITOR_CLIENT_SECRET."
  case "$MONITOR_SECRET_VALUE" in
    change-me*) fail "El secreto M2M es un marcador de ejemplo; aprovisione el cliente real." ;;
  esac
  ok "Credenciales M2M presentes (secreto no mostrado)."
elif [ -n "${AUDIT_MONITOR_CLIENT_SECRET:-}" ]; then
  MONITOR_SECRET_VALUE="${AUDIT_MONITOR_CLIENT_SECRET}"
  ok "AUDIT_MONITOR_CLIENT_SECRET presente en el entorno del operador."
else
  fail "Sin secreto M2M: use --monitor-secret-file o AUDIT_MONITOR_CLIENT_SECRET."$'\n'\
       "        Sin él el audit-monitor no puede autenticarse contra Keycloak."
fi

if [ -z "$CLINICAL_IMAGE_ARG" ]; then
  fail "Sin imagen del LIS: use --clinical-image o defina CLINICAL_IMAGE."$'\n'\
       "        La imagen base de Python no incluye cryptography y el backend no arranca."
fi
if ! docker image inspect "$CLINICAL_IMAGE_ARG" >/dev/null 2>&1; then
  fail "La imagen '$CLINICAL_IMAGE_ARG' no existe localmente. Construya cutover_prep/lis_image primero."
fi
if ! docker run --rm --entrypoint python "$CLINICAL_IMAGE_ARG" -c 'import cryptography' >/dev/null 2>&1; then
  fail "La imagen '$CLINICAL_IMAGE_ARG' no puede importar cryptography."
fi
ok "Imagen del LIS válida: ${CLINICAL_IMAGE_ARG}"

if [ -n "$REALM_EXPORT_FILE" ]; then
  [ -f "$REALM_EXPORT_FILE" ] || fail "Artefacto de realm inexistente: $REALM_EXPORT_FILE"
  python3 - "$REALM_EXPORT_FILE" <<'PY' || fail "El artefacto de realm no es importable (flujos incompletos)."
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
flows = {flow.get("alias") for flow in data.get("authenticationFlows") or []}
if not flows:
    raise SystemExit("authenticationFlows vacío")
for key in ("browserFlow", "clientAuthenticationFlow", "directGrantFlow"):
    alias = data.get(key)
    if alias and alias not in flows:
        raise SystemExit(f"{key}={alias} sin flujo")
print(f"[PASS] realm={data.get('realm')} flujos={len(flows)}")
PY
  ok "Artefacto de realm importable presente."
else
  warn "Sin --realm-export-file: no se registrará un artefacto de recuperación del realm."
fi

# ------------------------------------------------------------------------------
# 4. Plan / snapshot del estado actual
# ------------------------------------------------------------------------------
echo "[PASO 4] Plan de sincronización:"
for module in "${!MODULES[@]}"; do
  echo "  - candidate_release/${module} -> ${PROD_DIR}/clinical-poc/${MODULES[$module]}"
done

if [ $APPLY -eq 0 ]; then
  echo "[PLAN] 5. Snapshot de lo reemplazado en ${SNAPSHOT_DIR}."
  echo "[PLAN] 6. Copia atómica y verificación de hashes post-copia."
  echo "[PLAN] 7. Actualización atómica de .env (0600) y docker-compose.yml (YAML)."
  echo "[PLAN] 8. Garantizar ancla de auditoría en el volumen '${VOLUME_NAME}'."
  echo "[PLAN] 9. docker compose --profile clinical up -d y espera de /health."
  echo "[PLAN] 10. post_cutover_verify.py --read-only; rollback automático si falla el health."
  echo "[SIMULACIÓN] Sin --apply no se modificó nada."
  exit 0
fi

[ -d "${PROD_DIR}/clinical-poc" ] || fail "No existe ${PROD_DIR}/clinical-poc"
mkdir -p "$SNAPSHOT_DIR"
chmod 700 "$SNAPSHOT_DIR"
cp -a "${PROD_DIR}/clinical-poc/." "${SNAPSHOT_DIR}/clinical-poc/"
for config in docker-compose.yml .env; do
  [ -f "${PROD_DIR}/${config}" ] && cp -a "${PROD_DIR}/${config}" "${SNAPSHOT_DIR}/${config}.bak"
done
ok "Snapshot del estado actual en ${SNAPSHOT_DIR}"

# ------------------------------------------------------------------------------
# 5. Copia atómica
# ------------------------------------------------------------------------------
echo "[PASO 5] Copiando módulos candidatos..."
for module in "${!MODULES[@]}"; do
  dest="${PROD_DIR}/clinical-poc/${MODULES[$module]}"
  mkdir -p "$(dirname "$dest")"
  cp "${CANDIDATE_DIR}/${module}" "${dest}.tmp"
  chmod 0644 "${dest}.tmp"
  mv -f "${dest}.tmp" "$dest"
done
ok "Módulos copiados de forma atómica."

echo "[PASO 5a] Verificando hashes desplegados..."
for module in "${!MODULES[@]}"; do
  dest="${PROD_DIR}/clinical-poc/${MODULES[$module]}"
  expected="$(sha256sum "${CANDIDATE_DIR}/${module}" | awk '{print $1}')"
  actual="$(sha256sum "$dest" | awk '{print $1}')"
  [ "$expected" = "$actual" ] || fail "Hash discrepante tras copiar ${module}."
done
ok "Los hashes desplegados coinciden con el manifiesto."

# ------------------------------------------------------------------------------
# 6. Contrato de entorno (.env atómico)
# ------------------------------------------------------------------------------
echo "[PASO 6] Actualizando .env (contrato de entorno)..."
DEVICE_JSON_VALUE=""
if [ -n "$DEVICE_KEYS_FILE" ]; then
  DEVICE_JSON_VALUE="$(tr -d '\n' < "$DEVICE_KEYS_FILE")"
else
  DEVICE_JSON_VALUE="${IOMT_DEVICE_KEYS_JSON:-}"
fi

AUDIT_KEY_VALUE=""
if [ -n "$AUDIT_KEY_FILE" ]; then
  AUDIT_KEY_VALUE="$(tr -d '\n' < "$AUDIT_KEY_FILE")"
else
  AUDIT_KEY_VALUE="${AUDIT_HMAC_KEY:-}"
fi

python3 - "$PROD_DIR/.env" "$PORT" "$DEVICE_JSON_VALUE" "$AUDIT_KEY_VALUE" \
  "$CLINICAL_IMAGE_ARG" "$MONITOR_SECRET_VALUE" "${AUDIT_MONITOR_CLIENT_ID:-clinical-audit-monitor-service}" <<'PY'
import os
import sys

env_path, port, device_json, audit_key, clinical_image, monitor_secret, monitor_client = sys.argv[1:8]

updates = {
    "CLINICAL_PORT": port,
    "LIS_DB_PATH": "/data/lis.db",
    "ENABLE_LEGACY_AUTH": "0",
    "IOMT_MAX_CLOCK_SKEW_SECONDS": "300",
    "IOMT_NONCE_TTL_SECONDS": "900",
    "CLINICAL_IMAGE": clinical_image,
    "AUDIT_MONITOR_CLIENT_ID": monitor_client,
    "AUDIT_MONITOR_CLIENT_SECRET": monitor_secret,
    "AUDIT_MONITOR_USE_LEGACY": "0",
}
if device_json:
    updates["IOMT_DEVICE_KEYS_JSON"] = device_json
if audit_key:
    updates["AUDIT_HMAC_KEY"] = audit_key

lines = []
seen = set()
if os.path.exists(env_path):
    with open(env_path, "r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            key = stripped.split("=", 1)[0] if "=" in stripped and not stripped.startswith("#") else None
            if key in updates:
                lines.append(f"{key}={updates[key]}\n")
                seen.add(key)
            else:
                lines.append(line if line.endswith("\n") else line + "\n")
for key, value in updates.items():
    if key not in seen:
        lines.append(f"{key}={value}\n")

tmp = env_path + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    handle.writelines(lines)
os.chmod(tmp, 0o600)
os.replace(tmp, env_path)
print("[PASS] .env actualizado de forma atómica (0600).")
PY

# ------------------------------------------------------------------------------
# 7. docker-compose.yml (YAML real)
# ------------------------------------------------------------------------------
echo "[PASO 7] Actualizando docker-compose.yml..."
python3 - "$PROD_DIR/docker-compose.yml" "$VOLUME_NAME" "$CANONICAL_BASE_URL" "$CANONICAL_HOST" "$CANONICAL_PORT" "$CANONICAL_BIND_IP" "$TLS_DIR" <<'PY'
import os
import sys

try:
    import yaml
except ImportError:
    raise SystemExit(
        "[FAIL] PyYAML no está instalado. Instale python3-yaml antes del cutover; "
        "no se edita YAML a ciegas."
    )

compose_path, volume_name = sys.argv[1], sys.argv[2]
canonical_base, canonical_host, canonical_port, canonical_bind_ip, tls_dir = sys.argv[3:8]
issuer = f"{canonical_base.rstrip('/')}/realms/hospital-lab"
with open(compose_path, "r", encoding="utf-8") as handle:
    data = yaml.safe_load(handle) or {}

data.setdefault("volumes", {})
data["volumes"][volume_name] = {"external": True}

service = (data.get("services") or {}).get("clinical-poc")
if service is None:
    raise SystemExit("[FAIL] El servicio 'clinical-poc' no existe en docker-compose.yml")

# La red 'clinical' es internal: Docker NO publica puertos en ella. Se retira
# el mapeo al host (sería inefectivo y daría una falsa sensación de exposición).
service.pop("ports", None)

environment = service.get("environment") or {}
if isinstance(environment, list):
    environment = dict(item.split("=", 1) for item in environment if "=" in item)
environment.update(
    {
        "LIS_DB_PATH": "/data/lis.db",
        "ENABLE_LEGACY_AUTH": "0",
        "IOMT_DEVICE_KEYS_JSON": "${IOMT_DEVICE_KEYS_JSON}",
        "IOMT_MAX_CLOCK_SKEW_SECONDS": "${IOMT_MAX_CLOCK_SKEW_SECONDS:-300}",
        "IOMT_NONCE_TTL_SECONDS": "${IOMT_NONCE_TTL_SECONDS:-900}",
        "KEYCLOAK_DISCOVERY_URL": f"{issuer}/.well-known/openid-configuration",
        "KEYCLOAK_AUDIENCE": "clinical-poc-api",
    }
)

keycloak = (data.get("services") or {}).get("keycloak")
if keycloak is not None:
    kc_env = keycloak.get("environment") or {}
    if isinstance(kc_env, list):
        kc_env = dict(item.split("=", 1) for item in kc_env if "=" in item)
    kc_env["KC_HOSTNAME"] = canonical_base
    keycloak["environment"] = kc_env

monitor = (data.get("services") or {}).get("clinical-audit-monitor")
if monitor is not None:
    mon_env = monitor.get("environment") or {}
    if isinstance(mon_env, list):
        mon_env = dict(item.split("=", 1) for item in mon_env if "=" in item)
    mon_env.update(
        {
            "AUDIT_MONITOR_TOKEN_URL": f"{issuer}/protocol/openid-connect/token",
            "AUDIT_MONITOR_CLIENT_ID": "${AUDIT_MONITOR_CLIENT_ID:-clinical-audit-monitor-service}",
            "AUDIT_MONITOR_CLIENT_SECRET": "${AUDIT_MONITOR_CLIENT_SECRET}",
            "AUDIT_MONITOR_USE_LEGACY": "0",
        }
    )
    monitor["environment"] = mon_env

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
        "ports": [f"{canonical_bind_ip}:{canonical_port}:{canonical_port}"],
        "networks": {
            "identity-ui": {},
            "clinical": {"aliases": [canonical_host]},
        },
        "depends_on": {"keycloak": {"condition": "service_healthy"}},
        "restart": "no",
    }
    print(f"[PASS] Servicio identity-gateway añadido (alias {canonical_host}).")
else:
    volumes = gateway.get("volumes") or []
    updated = []
    for item in volumes:
        if isinstance(item, str) and item.endswith(":/certs:ro"):
            updated.append(f"{tls_dir}:/certs:ro")
        else:
            updated.append(item)
    if not any(isinstance(item, str) and item.endswith(":/certs:ro") for item in updated):
        updated.append(f"{tls_dir}:/certs:ro")
    gateway["volumes"] = updated
    gateway["ports"] = [f"{canonical_bind_ip}:{canonical_port}:{canonical_port}"]
    print(f"[PASS] identity-gateway actualizado (TLS {tls_dir}, puerto {canonical_bind_ip}:{canonical_port}).")
if environment.get("AUDIT_HMAC_KEY") or "${AUDIT_HMAC_KEY}" in str(environment):
    pass
service["environment"] = environment

volumes = service.get("volumes") or []
if isinstance(volumes, list):
    if not any(str(item).startswith(f"{volume_name}:/data") for item in volumes):
        volumes.append(f"{volume_name}:/data:rw")
service["volumes"] = volumes

tmp = compose_path + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    yaml.safe_dump(data, handle, sort_keys=False, allow_unicode=True)
os.chmod(tmp, 0o600)
os.replace(tmp, compose_path)
print("[PASS] docker-compose.yml actualizado (YAML válido).")
PY

# ------------------------------------------------------------------------------
# 7a. Gateway de identidad canónico: material TLS y Caddyfile
# ------------------------------------------------------------------------------
echo "[PASO 7a] Verificando material TLS del gateway canónico..."
CERT_FILE="${TLS_DIR}/fullchain.pem"
KEY_FILE="${TLS_DIR}/privkey.pem"

# /etc/sgsi-zta/tls es 0700 root. El operador no debe leer la clave: la
# validación se hace dentro de un contenedor que monta el directorio en ro.
TLS_PROBE="$(docker run --rm -e PROBE_HOST="$CANONICAL_HOST" -v "${TLS_DIR}:/certs:ro" \
  python:3.12-slim-bookworm sh -c '
set -u
C=/certs/fullchain.pem
K=/certs/privkey.pem
[ -r "$C" ] || { echo "CERT_MISSING"; exit 0; }
[ -r "$K" ] || { echo "KEY_MISSING"; exit 0; }
echo "CHAIN=$(grep -c "BEGIN CERTIFICATE" "$C")"
if openssl x509 -in "$C" -noout -ext subjectAltName 2>/dev/null | grep -c "DNS:${PROBE_HOST}" >/dev/null; then
  echo "SAN_OK=yes"
else
  echo "SAN_OK=no"
fi
CP=$(openssl x509 -in "$C" -pubkey -noout 2>/dev/null | sha256sum | cut -d" " -f1)
KP=$(openssl pkey -in "$K" -pubout 2>/dev/null | sha256sum | cut -d" " -f1)
if [ -n "$CP" ] && [ "$CP" = "$KP" ]; then echo "KEY_MATCH=yes"; else echo "KEY_MATCH=no"; fi
END=$(openssl x509 -in "$C" -noout -enddate | cut -d= -f2)
echo "DAYS=$(( ( $(date -d "$END" +%s) - $(date +%s) ) / 86400 ))"
echo "KEY_MODE=$(stat -c %a "$K")"
' 2>&1)" || fail "No se pudo inspeccionar ${TLS_DIR}."

echo "$TLS_PROBE" | grep -c '^CHAIN=' >/dev/null \
  || fail "Material TLS incompleto en ${TLS_DIR}: $(echo "$TLS_PROBE" | tr '\n' ' ')"
echo "$TLS_PROBE" | grep -c '^SAN_OK=yes' >/dev/null \
  || fail "El certificado no cubre ${CANONICAL_HOST}. Emita uno para ese nombre."
echo "$TLS_PROBE" | grep -c '^KEY_MATCH=yes' >/dev/null \
  || fail "La clave privada no coincide con el certificado."
DAYS_LEFT="$(echo "$TLS_PROBE" | sed -n 's/^DAYS=//p')"
[ "${DAYS_LEFT:-0}" -gt 0 ] || fail "El certificado está vencido."
KEY_MODE="$(echo "$TLS_PROBE" | sed -n 's/^KEY_MODE=//p')"
case "$KEY_MODE" in
  *4|*6|*7) fail "La clave privada es legible por otros (modo ${KEY_MODE}). Ajústela a 0600." ;;
esac
ok "TLS válido para ${CANONICAL_HOST}: cadena $(echo "$TLS_PROBE" | sed -n 's/^CHAIN=//p'), ${DAYS_LEFT} días, clave ${KEY_MODE}."

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
ok "Caddyfile del gateway escrito (TLS /certs/fullchain.pem)."

# ------------------------------------------------------------------------------
# 8. Ancla de auditoría en el volumen
# ------------------------------------------------------------------------------
if [ $NO_RESTART -eq 1 ]; then
  warn "Arranque omitido por --no-restart: no se valida el ancla del volumen ni /health."
  echo "[INFO] Código y configuración aplicados. Snapshot para rollback: $SNAPSHOT_DIR"
  exit 0
fi

echo "[PASO 8] Garantizando ancla de auditoría en el volumen '${VOLUME_NAME}'..."
# No se pasa la clave al contenedor: quedaría visible en 'ps'. El ancla debe
# existir como archivo lateral o estar ya declarada en .env para el runtime.
VOLUME_HAS_DB=0
VOLUME_HAS_ANCHOR=0
VOLUME_PROBE="$(docker run --rm --network none -v "${VOLUME_NAME}:/data:ro" \
  python:3.12-slim-bookworm sh -c \
  'echo "DB=$(test -f /data/lis.db && echo yes || echo no)"; echo "ANCHOR=$(test -f /data/lis.db.anchor-key && echo yes || echo no)"' \
  2>/dev/null || true)"
if echo "$VOLUME_PROBE" | grep -c "DB=yes" >/dev/null; then VOLUME_HAS_DB=1; fi
if echo "$VOLUME_PROBE" | grep -c "ANCHOR=yes" >/dev/null; then VOLUME_HAS_ANCHOR=1; fi

if [ "$VOLUME_HAS_DB" -eq 1 ] && [ "$VOLUME_HAS_ANCHOR" -eq 0 ] && [ -z "$AUDIT_KEY_VALUE" ]; then
  fail "El volumen contiene lis.db sin ancla y no se proveyó AUDIT_HMAC_KEY."$'\n'\
       "        La base no arrancaría (fail-closed). Despliegue abortado antes de arrancar."
fi
if [ "$VOLUME_HAS_DB" -eq 1 ]; then
  ok "Base existente con ancla verificable (archivo lateral o AUDIT_HMAC_KEY en .env)."
else
  ok "Estado cero: el ancla se generará en el primer arranque."
fi

# ------------------------------------------------------------------------------
# 8a. Propietario del volumen para el UID del runtime (65534, rootfs read-only)
# ------------------------------------------------------------------------------
echo "[PASO 8a] Ajustando el volumen '${VOLUME_NAME}' para uid 65534..."
docker run --rm -u 0 -v "${VOLUME_NAME}:/data" python:3.12-slim-bookworm \
  sh -c 'chown 65534:65534 /data; chown -R 65534:65534 /data/* 2>/dev/null || true'
if docker run --rm -u 65534:65534 -v "${VOLUME_NAME}:/data" python:3.12-slim-bookworm \
  sh -c 'touch /data/.write-probe && rm -f /data/.write-probe' >/dev/null 2>&1; then
  ok "Volumen escribible por uid 65534."
else
  fail "El volumen ${VOLUME_NAME} no es escribible por uid 65534."$'\n'\
       "        El LIS corre con user 65534 y rootfs read-only: no podría crear lis.db."$'\n'\
       "        Corrija con: docker run --rm -u 0 -v ${VOLUME_NAME}:/data python:3.12-slim-bookworm chown -R 65534:65534 /data"
fi

# ------------------------------------------------------------------------------
# 9. Arranque y espera de health real
# ------------------------------------------------------------------------------
echo "[PASO 9] Arrancando servicios clínicos..."
(
  cd "$PROD_DIR"
  docker compose --profile clinical --profile identidad up -d \
    clinical-poc clinical-audit-monitor identity-gateway
)

echo "[PASO 9a] Esperando /health dentro de la red clínica (máx. ${HEALTH_TIMEOUT}s)..."
# La red 'clinical' es internal: Docker NO publica puertos en ella. El health
# se comprueba exec dentro del contenedor; el LIS no se expone al host.
HEALTH_OK=0
for _ in $(seq 1 "$HEALTH_TIMEOUT"); do
  if docker compose -f "${PROD_DIR}/docker-compose.yml" exec -T clinical-poc \
      python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" >/dev/null 2>&1; then
    HEALTH_OK=1
    break
  fi
  sleep 1
done

if [ $HEALTH_OK -ne 1 ]; then
  echo -e "${RED}[FAIL]${NC} /health no respondió en ${HEALTH_TIMEOUT}s. Ejecutando rollback automático..."
  "${SCRIPT_DIR}/rollback.sh" --apply --backup-dir="$SNAPSHOT_DIR" --prod-dir="$PROD_DIR" \
    || echo "[CRITICAL] El rollback automático también falló. Intervención manual requerida." >&2
  exit 1
fi
ok "Servicio saludable (verificado dentro de la red clinical)."

echo "[PASO 9b] Esperando el discovery canónico (máx. 30s)..."
CANONICAL_READY=0
for _ in $(seq 1 30); do
  if curl -sf --max-time 2 \
    "${CANONICAL_BASE_URL}/realms/hospital-lab/.well-known/openid-configuration" >/dev/null 2>&1; then
    CANONICAL_READY=1
    break
  fi
  sleep 1
done
if [ $CANONICAL_READY -ne 1 ]; then
  warn "El discovery canónico no respondió: la verificación post-cutover lo marcará como bloqueante."
else
  ok "Discovery canónico disponible en ${CANONICAL_BASE_URL}."
fi

# ------------------------------------------------------------------------------
# 10. Verificación post-cutover
# ------------------------------------------------------------------------------
if [ $SKIP_POST_VERIFY -eq 0 ]; then
  echo "[PASO 10] Verificación post-cutover (en la red clínica, solo lectura)..."
  set +e
  VERIFY_ARGS=(
    --url "http://clinical-poc:8000"
    --deployed-dir "/prod/clinical-poc/lis-backend"
    --canonical-base "${CANONICAL_BASE_URL}"
    --compose-path "/prod/docker-compose.yml"
    --read-only
  )
  VERIFY_MOUNTS=(
    -v "${SCRIPT_DIR}:/prep:ro"
    -v "${PROD_DIR}:/prod:ro"
  )
  if [ -n "$MONITOR_SECRET_FILE" ]; then
    VERIFY_MOUNTS+=(-v "${MONITOR_SECRET_FILE}:/run/secrets/monitor.env:ro")
    VERIFY_ARGS+=(--creds /run/secrets/monitor.env)
  fi
  CLINICAL_CONTAINER="$(docker compose -f "${PROD_DIR}/docker-compose.yml" ps -q clinical-poc)"
  [ -n "$CLINICAL_CONTAINER" ] || fail "No se encontró el contenedor clinical-poc para la verificación."
  CLINICAL_NETWORK="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$CLINICAL_CONTAINER")"
  [ -n "$CLINICAL_NETWORK" ] || fail "No se pudo resolver la red de clinical-poc."
  docker run --rm --network "$CLINICAL_NETWORK" \
    "${VERIFY_MOUNTS[@]}" --entrypoint python "${CLINICAL_IMAGE_ARG}" \
    /prep/post_cutover_verify.py "${VERIFY_ARGS[@]}"
  VERIFY_CODE=$?
  set -e

  case "$VERIFY_CODE" in
    0) ok "Verificación post-cutover: GO." ;;
    2) warn "Verificación post-cutover INCOMPLETA (Keycloak u otra comprobación no ejecutable). Revise el informe." ;;
    *)
      echo -e "${RED}[FAIL]${NC} Verificación post-cutover NO-GO. Ejecutando rollback..."
      "${SCRIPT_DIR}/rollback.sh" --apply --backup-dir="$SNAPSHOT_DIR" --prod-dir="$PROD_DIR" \
        || echo "[CRITICAL] Rollback automático falló. Intervención manual requerida." >&2
      exit 1
      ;;
  esac

  echo "[PASO 10a] Verificación de la base dentro del volumen (read-only)..."
  docker run --rm --network none \
    -v "${VOLUME_NAME}:/data:ro" \
    -v "${SCRIPT_DIR}:/tools:ro" \
    python:3.12-slim-bookworm \
    python3 /tools/cutover_common.py inspect --db /data/lis.db \
    || fail "La base del volumen no supera la verificación criptográfica."
fi

echo "=============================================================================="
echo " Despliegue coordinado completado."
echo " Snapshot para rollback: $SNAPSHOT_DIR"
echo "=============================================================================="

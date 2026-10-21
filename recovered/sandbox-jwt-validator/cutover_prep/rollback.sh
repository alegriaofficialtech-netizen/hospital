#!/usr/bin/env bash
# ==============================================================================
# rollback.sh - Reversión segura de código y configuración con datos preservados
# SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 & NIST SP 800-207
#
# Revierte código y configuración al estado respaldado.
#
# CAMBIO CRÍTICO: el backend endurecido migra la base a esquema v2 y firma la
# cadena con una clave de anclaje propia. El código anterior NO PUEDE ABRIR una
# base v2: falla con AuditChainCorruptedError al arrancar. Por eso este script:
#
#   - verifica la compatibilidad código/base ANTES de rearrancar;
#   - si son incompatibles, aborta con instrucciones en lugar de dejar el
#     servicio caído;
#   - con --with-database restaura también la base emparejada del respaldo
#     (pierde lo escrito desde el cutover: es una decisión explícita).
#
# Otras correcciones:
#   - snapshot del estado candidato antes de sobrescribirlo;
#   - verificación del manifiesto del respaldo;
#   - cp -a con dotfiles y limpieza de archivos exclusivos del candidato;
#   - rearranque y espera de /health (antes solo detenía los servicios);
#   - verificación criptográfica de la base tras el rollback.
#
# Modo por defecto: SIMULACIÓN (--dry-run). Requiere --apply.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROD_DIR="/opt/sgsi-zta-hospital-lab"
BACKUP_DIR=""
VOLUME_NAME="clinical-data"
PORT=8086
APPLY=0
NO_RESTART=0
WITH_DATABASE=0
DB_PATH_OVERRIDE=""
HEALTH_TIMEOUT=45
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

for arg in "$@"; do
  case "$arg" in
    --apply)            APPLY=1 ;;
    --dry-run)          APPLY=0 ;;
    --no-restart)       NO_RESTART=1 ;;
    --with-database)    WITH_DATABASE=1 ;;
    --backup-dir=*)     BACKUP_DIR="${arg#*=}" ;;
    --prod-dir=*)       PROD_DIR="${arg#*=}" ;;
    --volume-name=*)    VOLUME_NAME="${arg#*=}" ;;
    --db-path=*)        DB_PATH_OVERRIDE="${arg#*=}" ;;
    --safety-dir=*)     SAFETY_DIR="${arg#*=}" ;;
    --port=*)           PORT="${arg#*=}" ;;
    --health-timeout=*) HEALTH_TIMEOUT="${arg#*=}" ;;
    --help)
      sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
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

if [ -z "$BACKUP_DIR" ]; then
  LATEST="$(ls -td /home/elcra/sgsi-backups/pre_cutover/backup_* 2>/dev/null | head -n 1 || true)"
  [ -n "$LATEST" ] || fail "Se requiere --backup-dir=... y no se encontró respaldo automático."
  BACKUP_DIR="$LATEST"
  echo "[INFO] Respaldo más reciente detectado: $BACKUP_DIR"
fi
[ -d "$BACKUP_DIR" ] || fail "Directorio de respaldo inexistente: $BACKUP_DIR"
[ -d "${BACKUP_DIR}/clinical-poc" ] || fail "El respaldo no contiene clinical-poc/."

TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
if [ -z "${SAFETY_DIR:-}" ]; then
  SAFETY_DIR="/home/elcra/sgsi-backups/pre_rollback/rollback_${TIMESTAMP}"
fi

# ------------------------------------------------------------------------------
# 0. El directorio de snapshot debe ser escribible por el operador
# ------------------------------------------------------------------------------
SAFETY_PARENT="$(dirname "$SAFETY_DIR")"
if [ $APPLY -eq 1 ]; then
  if ! mkdir -p "$SAFETY_PARENT" 2>/dev/null; then
    fail "No se puede crear el directorio de snapshot: $SAFETY_PARENT"$'\n'\
         "        Cree la ruta con permisos del operador y reintente:"$'\n'\
         "          sudo install -d -o $(id -un) -g $(id -gn) -m 700 $SAFETY_PARENT"$'\n'\
         "        O indique otra ruta con --safety-dir=DIR."
  fi
  if [ ! -w "$SAFETY_PARENT" ]; then
    fail "El directorio de snapshot no es escribible por $(id -un): $SAFETY_PARENT"$'\n'\
         "        Use --safety-dir=DIR con una ruta escribible."
  fi
else
  PROBE_SAFETY="$SAFETY_PARENT"
  while [ ! -d "$PROBE_SAFETY" ] && [ "$PROBE_SAFETY" != "/" ]; do
    PROBE_SAFETY="$(dirname "$PROBE_SAFETY")"
  done
  if [ ! -w "$PROBE_SAFETY" ]; then
    warn "El snapshot no podría crearse en $SAFETY_PARENT (sin escritura para $(id -un))."$'\n'\
         "        En --apply fallará. Use --safety-dir=DIR o cree la ruta con sudo."
  fi
fi

echo "=============================================================================="
echo " PROCEDIMIENTO DE ROLLBACK LIS (SGSI-ZTA)"
echo " Modo      : $([ $APPLY -eq 1 ] && echo 'APLICACIÓN REAL (--apply)' || echo 'SIMULACIÓN SEGURA (--dry-run)')"
echo " Producción: $PROD_DIR"
echo " Respaldo  : $BACKUP_DIR"
echo " Volumen   : $VOLUME_NAME"
echo " Base      : $([ $WITH_DATABASE -eq 1 ] && echo 'se restaura del respaldo' || echo 'se conserva la actual')"
echo " Snapshot  : $SAFETY_DIR"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# Utilidades de inspección de base (nunca escriben)
# ------------------------------------------------------------------------------
inspect_target_db() {
  if [ -n "$DB_PATH_OVERRIDE" ]; then
    python3 "$SCRIPT_DIR/cutover_common.py" inspect --db "$DB_PATH_OVERRIDE" --json 2>/dev/null || true
  else
    docker run --rm --network none \
      -v "${VOLUME_NAME}:/data:ro" \
      -v "${SCRIPT_DIR}:/tools:ro" \
      python:3.12-slim-bookworm \
      python3 /tools/cutover_common.py inspect --db /data/lis.db --json 2>/dev/null || true
  fi
}

db_field() {
  local field="$1"
  python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    print("none"); raise SystemExit
value = data.get(sys.argv[1])
if value is None:
    print("none")
elif isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
' "$field"
}

# Capacidad del código restaurado para entender el esquema v2 / ancla nueva.
BACKUP_CODE_SUPPORTS_V2=0
if [ -f "${BACKUP_DIR}/clinical-poc/lis-backend/clinical_domain.py" ] \
   && grep -qE "AUDIT_HMAC_KEY|anchor-key|anchor_key" \
        "${BACKUP_DIR}/clinical-poc/lis-backend/database.py" 2>/dev/null; then
  BACKUP_CODE_SUPPORTS_V2=1
fi

DB_STATE="$(inspect_target_db)"
DB_SCHEMA="$(printf '%s' "$DB_STATE" | db_field schema_version)"
DB_EXISTS="$(printf '%s' "$DB_STATE" | db_field exists)"
DB_CHAIN="$(printf '%s' "$DB_STATE" | db_field chain_valid)"

echo "[INFO] Base actual: existe=${DB_EXISTS} esquema=${DB_SCHEMA} cadena=${DB_CHAIN}"
echo "[INFO] Código del respaldo soporta esquema v2: ${BACKUP_CODE_SUPPORTS_V2}"

# ------------------------------------------------------------------------------
# 1. Verificar el respaldo antes de usarlo
# ------------------------------------------------------------------------------
if [ -f "${BACKUP_DIR}/MANIFEST_BACKUP.sha256" ]; then
  echo "[PASO 1] Verificando manifiesto del respaldo..."
  ( cd "$BACKUP_DIR" && sha256sum -c MANIFEST_BACKUP.sha256 --quiet ) \
    || fail "El respaldo está alterado o incompleto. Rollback abortado."
  ok "Respaldo íntegro."
else
  warn "Sin MANIFEST_BACKUP.sha256: no se puede comprobar alteración del respaldo."
fi

# ------------------------------------------------------------------------------
# 2. Compuerta de compatibilidad ANTES de tocar nada
# ------------------------------------------------------------------------------
if [ "$DB_EXISTS" = "true" ] && [ "$DB_SCHEMA" != "none" ] && [ "$DB_SCHEMA" -ge 2 ] 2>/dev/null \
   && [ "$BACKUP_CODE_SUPPORTS_V2" -eq 0 ] && [ $WITH_DATABASE -eq 0 ]; then
  fail "El código a restaurar NO entiende la base actual (esquema v${DB_SCHEMA})."$'\n'\
       "        El backend anterior falla al arrancar con AuditChainCorruptedError."$'\n'\
       "        Opciones:"$'\n'\
       "          a) Roll-forward: no revertir el código."$'\n'\
       "          b) Restaurar base emparejada: repita con --with-database"$'\n'\
       "             (pierde los datos clínicos escritos desde el cutover)."
fi

if [ $WITH_DATABASE -eq 1 ] && [ ! -f "${BACKUP_DIR}/lis_hot_backup.db" ]; then
  fail "--with-database requiere ${BACKUP_DIR}/lis_hot_backup.db, que no existe."
fi

if [ $APPLY -eq 0 ]; then
  echo "[PLAN] 3. Snapshot del estado actual en $SAFETY_DIR."
  echo "[PLAN] 4. Detener servicios clínicos."
  echo "[PLAN] 5. Restaurar clinical-poc desde el respaldo (cp -a, incluidos dotfiles)."
  echo "[PLAN] 6. Eliminar archivos exclusivos del candidato ausentes en el respaldo."
  echo "[PLAN] 7. Restaurar .env y docker-compose.yml."
  if [ $WITH_DATABASE -eq 1 ]; then
    echo "[PLAN] 8. Restaurar base + ancla desde el respaldo y verificar la cadena."
  else
    echo "[PLAN] 8. Conservar la base actual (compatibilidad verificada)."
  fi
  echo "[PLAN] 9. Rearrancar servicios y esperar /health."
  echo "[SIMULACIÓN] Sin --apply no se modificó nada."
  exit 0
fi

# ------------------------------------------------------------------------------
# 3. Snapshot del estado candidato actual
# ------------------------------------------------------------------------------
mkdir -p "$SAFETY_DIR"
chmod 700 "$SAFETY_DIR"
if [ -d "${PROD_DIR}/clinical-poc" ]; then
  cp -a "${PROD_DIR}/clinical-poc/." "${SAFETY_DIR}/clinical-poc/"
fi
for config in docker-compose.yml .env; do
  [ -f "${PROD_DIR}/${config}" ] && cp -a "${PROD_DIR}/${config}" "${SAFETY_DIR}/${config}.bak"
done
if [ -n "$DB_PATH_OVERRIDE" ] && [ -f "$DB_PATH_OVERRIDE" ]; then
  cp -a "$DB_PATH_OVERRIDE" "${SAFETY_DIR}/lis.db"
  [ -f "${DB_PATH_OVERRIDE}.anchor-key" ] && cp -a "${DB_PATH_OVERRIDE}.anchor-key" "${SAFETY_DIR}/lis.db.anchor-key"
fi
ok "Snapshot del estado candidato en $SAFETY_DIR"

# ------------------------------------------------------------------------------
# 4. Detener servicios
# ------------------------------------------------------------------------------
echo "[PASO 4] Deteniendo servicios clínicos..."
if [ -f "${PROD_DIR}/docker-compose.yml" ]; then
  ( cd "$PROD_DIR" && docker compose --profile clinical stop clinical-poc clinical-audit-monitor ) \
    || warn "No se pudieron detener todos los servicios (puede que ya estuvieran parados)."
fi
ok "Servicios detenidos."

# ------------------------------------------------------------------------------
# 5. Restaurar código
# ------------------------------------------------------------------------------
echo "[PASO 5] Restaurando código..."
mkdir -p "${PROD_DIR}/clinical-poc"
cp -a "${BACKUP_DIR}/clinical-poc/." "${PROD_DIR}/clinical-poc/"
ok "Código restaurado (incluidos dotfiles)."

for candidate_only in "lis-backend/clinical_domain.py"; do
  if [ ! -f "${BACKUP_DIR}/clinical-poc/${candidate_only}" ] \
     && [ -f "${PROD_DIR}/clinical-poc/${candidate_only}" ]; then
    rm -f "${PROD_DIR}/clinical-poc/${candidate_only}"
    ok "Eliminado archivo exclusivo del candidato: ${candidate_only}"
  fi
done

echo "[PASO 5a] Comparando árbol restaurado con el respaldo..."
if diff -r "${BACKUP_DIR}/clinical-poc" "${PROD_DIR}/clinical-poc" >/dev/null 2>&1; then
  ok "El código en producción coincide byte a byte con el respaldo."
else
  warn "Hay diferencias entre el respaldo y producción:"
  diff -r "${BACKUP_DIR}/clinical-poc" "${PROD_DIR}/clinical-poc" | head -20 || true
fi

# ------------------------------------------------------------------------------
# 6. Restaurar configuración
# ------------------------------------------------------------------------------
echo "[PASO 6] Restaurando configuración..."
for config in docker-compose.yml .env; do
  if [ -f "${BACKUP_DIR}/${config}.bak" ]; then
    cp -a "${BACKUP_DIR}/${config}.bak" "${PROD_DIR}/${config}.tmp"
    mv -f "${PROD_DIR}/${config}.tmp" "${PROD_DIR}/${config}"
    chmod 600 "${PROD_DIR}/${config}"
    ok "${config} restaurado."
  else
    warn "El respaldo no contiene ${config}.bak; se conserva la configuración actual."
  fi
done

# ------------------------------------------------------------------------------
# 7. Base de datos: conservar o restaurar la emparejada
# ------------------------------------------------------------------------------
if [ $WITH_DATABASE -eq 1 ]; then
  echo "[PASO 7] Restaurando base emparejada del respaldo..."
  SRC_DB="${BACKUP_DIR}/lis_hot_backup.db"
  SRC_ANCHOR="${SRC_DB}.anchor-key"
  [ -f "$SRC_ANCHOR" ] || fail "El respaldo no incluye el ancla ${SRC_ANCHOR}: no se restaura."

  if [ -n "$DB_PATH_OVERRIDE" ]; then
    cp -a "$SRC_DB" "${DB_PATH_OVERRIDE}.tmp"
    mv -f "${DB_PATH_OVERRIDE}.tmp" "$DB_PATH_OVERRIDE"
    rm -f "${DB_PATH_OVERRIDE}-wal" "${DB_PATH_OVERRIDE}-shm"
    cp -a "$SRC_ANCHOR" "${DB_PATH_OVERRIDE}.anchor-key"
    chmod 600 "$DB_PATH_OVERRIDE" "${DB_PATH_OVERRIDE}.anchor-key"
  else
    docker run --rm --network none \
      -v "${VOLUME_NAME}:/data:rw" \
      -v "${BACKUP_DIR}:/src:ro" \
      python:3.12-slim-bookworm \
      sh -c '
        set -eu
        cp /src/lis_hot_backup.db /data/lis.db.tmp
        mv -f /data/lis.db.tmp /data/lis.db
        rm -f /data/lis.db-wal /data/lis.db-shm
        cp /src/lis_hot_backup.db.anchor-key /data/lis.db.anchor-key
        chmod 600 /data/lis.db /data/lis.db.anchor-key
      ' || fail "No se pudo restaurar la base emparejada."
  fi
  ok "Base y ancla restauradas desde el respaldo."

  DB_STATE="$(inspect_target_db)"
  DB_CHAIN="$(printf '%s' "$DB_STATE" | db_field chain_valid)"
  [ "$DB_CHAIN" = "true" ] || fail "La base restaurada no verifica su cadena. Rollback abortado."
  ok "Cadena de la base restaurada verificada."
else
  echo "[PASO 7] Se conserva la base actual (compatibilidad ya verificada)."
fi

# ------------------------------------------------------------------------------
# 8. Rearranque y health
# ------------------------------------------------------------------------------
if [ $NO_RESTART -eq 1 ]; then
  warn "Rearranque omitido por --no-restart. El servicio queda detenido."
else
  echo "[PASO 8] Rearrancando servicios clínicos..."
  ( cd "$PROD_DIR" && docker compose --profile clinical up -d clinical-poc clinical-audit-monitor )

  echo "[PASO 8a] Esperando /health (máx. ${HEALTH_TIMEOUT}s)..."
  HEALTH_OK=0
  for _ in $(seq 1 "$HEALTH_TIMEOUT"); do
    if python3 - "$PORT" <<'PY'
import json
import sys
import urllib.request

try:
    with urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/health", timeout=2) as response:
        body = json.loads(response.read().decode("utf-8"))
    raise SystemExit(0 if response.status == 200 and body.get("status") in ("HEALTHY", "OK") else 1)
except Exception:
    raise SystemExit(1)
PY
    then
      HEALTH_OK=1
      break
    fi
    sleep 1
  done
  if [ $HEALTH_OK -eq 1 ]; then
    ok "Servicio saludable tras el rollback."
  else
    fail "El servicio NO responde tras el rollback. Intervención manual requerida."$'\n'\
         "        Snapshot del candidato conservado en: $SAFETY_DIR"
  fi
fi

# ------------------------------------------------------------------------------
# 9. Verificación final de datos
# ------------------------------------------------------------------------------
echo "[PASO 9] Verificando la base tras el rollback..."
DB_STATE="$(inspect_target_db)"
DB_CHAIN="$(printf '%s' "$DB_STATE" | db_field chain_valid)"
DB_EXISTS="$(printf '%s' "$DB_STATE" | db_field exists)"
if [ "$DB_EXISTS" = "true" ]; then
  if [ "$DB_CHAIN" = "true" ]; then
    ok "Datos preservados: integridad y cadena verificadas."
  else
    fail "La base NO verifica tras el rollback. No reinicie servicios."$'\n'\
         "        Conserve $SAFETY_DIR y restaure desde un respaldo verificado."
  fi
else
  warn "No hay base en el destino: estado cero."
fi

echo "=============================================================================="
echo " Rollback finalizado."
echo " Re-despliegue del candidato si fue un error: snapshot en $SAFETY_DIR"
echo "=============================================================================="

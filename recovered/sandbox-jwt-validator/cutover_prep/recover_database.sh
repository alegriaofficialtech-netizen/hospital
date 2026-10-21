#!/usr/bin/env bash
# ==============================================================================
# recover_database.sh - Restauración controlada y verificada de SQLite
# SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 A.8.14 & NIST SP 800-207
#
# Restaura un respaldo SQLite junto con su clave de anclaje HMAC.
#
# Cambios respecto de la versión anterior:
#   - Restaura `<db>.anchor-key`. Sin ella la base restaurada no arranca
#     (fail-closed del backend endurecido).
#   - Toma un snapshot del estado actual ANTES de sobrescribir; si el snapshot
#     falla, no restaura. Exige --force si ya hay datos.
#   - Verifica la cadena de auditoría y el anclaje del respaldo antes de copiar,
#     y del destino después de copiar.
#   - Abre la base en mode=ro para no crear WAL durante la inspección.
#   - Permite restaurar a una ruta del host (--target-db) además del volumen,
#     para ensayos sin Docker.
#
# Modo por defecto: SIMULACIÓN (--dry-run). Requiere --apply.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_FILE=""
ANCHOR_FILE=""
VOLUME_NAME="clinical-data"
TARGET_DB=""
TARGET_ANCHOR=""
TARGET_UID="65534"
TARGET_GID="65534"
SAFETY_BASE="/home/elcra/sgsi-backups/pre_restore"
SAFETY_DIR=""
APPLY=0
FORCE=0
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

for arg in "$@"; do
  case "$arg" in
    --apply)          APPLY=1 ;;
    --dry-run)        APPLY=0 ;;
    --force)          FORCE=1 ;;
    --backup-file=*)  BACKUP_FILE="${arg#*=}" ;;
    --anchor-file=*)  ANCHOR_FILE="${arg#*=}" ;;
    --volume-name=*)  VOLUME_NAME="${arg#*=}" ;;
    --target-db=*)    TARGET_DB="${arg#*=}" ;;
    --target-anchor=*) TARGET_ANCHOR="${arg#*=}" ;;
    --safety-dir=*)   SAFETY_DIR="${arg#*=}" ;;
    --uid=*)          TARGET_UID="${arg#*=}" ;;
    --gid=*)          TARGET_GID="${arg#*=}" ;;
    --help)
      sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
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

[ -n "$BACKUP_FILE" ] || fail "Debe especificar --backup-file=RUTA_AL_RESPALDO.db"
[ -f "$BACKUP_FILE" ] || fail "Archivo de respaldo inexistente: $BACKUP_FILE"

if [ -z "$ANCHOR_FILE" ]; then
  if [ -f "${BACKUP_FILE}.anchor-key" ]; then
    ANCHOR_FILE="${BACKUP_FILE}.anchor-key"
  elif [ -f "$(dirname "$BACKUP_FILE")/lis.db.anchor-key" ]; then
    ANCHOR_FILE="$(dirname "$BACKUP_FILE")/lis.db.anchor-key"
  fi
fi

if [ -z "$SAFETY_DIR" ]; then
  SAFETY_DIR="${SAFETY_BASE}/restore_$(date +"%Y%m%d_%H%M%S")"
fi

HOST_MODE=0
if [ -n "$TARGET_DB" ]; then
  HOST_MODE=1
  [ -z "$TARGET_ANCHOR" ] && TARGET_ANCHOR="${TARGET_DB}.anchor-key"
fi

echo "=============================================================================="
echo " RESTAURACIÓN CONTROLADA DE BASE DE DATOS LIS"
echo " Modo      : $([ $APPLY -eq 1 ] && echo 'APLICACIÓN REAL (--apply)' || echo 'SIMULACIÓN SEGURA (--dry-run)')"
echo " Origen    : $BACKUP_FILE"
echo " Ancla     : ${ANCHOR_FILE:-<ninguna>}"
echo " Destino   : ${TARGET_DB:-volumen '${VOLUME_NAME}:/data/lis.db'}"
echo " Snapshot  : $SAFETY_DIR"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# 1. Verificación criptográfica del respaldo (integridad + cadena + ancla)
# ------------------------------------------------------------------------------
echo "[PASO 1] Verificando el respaldo antes de tocar el destino..."
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/lis_restore_XXXXXX")"
chmod 700 "$STAGE_DIR"
trap 'rm -rf "$STAGE_DIR"' EXIT
cp -f "$BACKUP_FILE" "$STAGE_DIR/lis.db"
chmod 600 "$STAGE_DIR/lis.db"
if [ -n "$ANCHOR_FILE" ]; then
  [ -f "$ANCHOR_FILE" ] || fail "Ancla indicada inexistente: $ANCHOR_FILE"
  cp -f "$ANCHOR_FILE" "$STAGE_DIR/lis.db.anchor-key"
  chmod 600 "$STAGE_DIR/lis.db.anchor-key"
elif [ -n "${AUDIT_HMAC_KEY:-}" ]; then
  printf '%s' "$AUDIT_HMAC_KEY" > "$STAGE_DIR/lis.db.anchor-key"
  chmod 600 "$STAGE_DIR/lis.db.anchor-key"
else
  warn "Sin ancla ni AUDIT_HMAC_KEY: solo es válido si el respaldo no tiene eventos."
fi

BACKUP_REPORT="$STAGE_DIR/backup_report.txt"
if ! python3 "${SCRIPT_DIR}/cutover_common.py" inspect --db "$STAGE_DIR/lis.db" | tee "$BACKUP_REPORT"; then
  fail "El respaldo no supera la verificación criptográfica. Restauración abortada."
fi
ok "Respaldo íntegro y verificable."

BACKUP_EVENTS="$(awk -F': *' '/^eventos/ {print $2}' "$BACKUP_REPORT" | tr -d '[:space:]')"
BACKUP_ORDERS="$(awk -F': *' '/^ordenes/ {print $2}' "$BACKUP_REPORT" | tr -d '[:space:]')"
BACKUP_EVENTS="${BACKUP_EVENTS:-0}"
BACKUP_ORDERS="${BACKUP_ORDERS:-0}"

# ------------------------------------------------------------------------------
# 2. Detectar estado del destino y exigir confirmación
# ------------------------------------------------------------------------------
echo "[PASO 2] Evaluando el destino..."
TARGET_HAS_DATA=0
if [ $HOST_MODE -eq 1 ]; then
  if [ -f "$TARGET_DB" ]; then
    TARGET_HAS_DATA=1
    echo "[INFO] Destino existente: $TARGET_DB ($(stat -c '%s bytes' "$TARGET_DB"))"
  fi
else
  PROBE="$(docker run --rm --network none -v "${VOLUME_NAME}:/data:ro" \
    python:3.12-slim-bookworm sh -c 'test -f /data/lis.db && echo PRESENT || echo EMPTY' 2>/dev/null || echo EMPTY)"
  [ "$PROBE" = "PRESENT" ] && TARGET_HAS_DATA=1
fi

if [ $TARGET_HAS_DATA -eq 1 ] && [ $FORCE -eq 0 ]; then
  fail "El destino ya contiene una base. Restaurar la sobrescribe."$'\n'\
       "        Repita con --force para confirmar (se tomará un snapshot previo)."
fi

if [ $APPLY -eq 0 ]; then
  echo "[PLAN] 3. Snapshot del destino actual en $SAFETY_DIR."
  echo "[PLAN] 4. Copiar base + ancla, eliminar -wal/-shm, aplicar 0600 y ${TARGET_UID}:${TARGET_GID}."
  echo "[PLAN] 5. Verificar cadena, ancla y recuentos (esperado: ${BACKUP_ORDERS} órdenes, ${BACKUP_EVENTS} eventos)."
  echo "[SIMULACIÓN] Sin --apply no se modificó nada."
  exit 0
fi

# ------------------------------------------------------------------------------
# 3. Snapshot del destino (obligatorio si hay datos)
# ------------------------------------------------------------------------------
if [ $TARGET_HAS_DATA -eq 1 ]; then
  echo "[PASO 3] Snapshot del destino actual..."
  if ! mkdir -p "$SAFETY_DIR" 2>/dev/null; then
    fail "No se puede crear el directorio de seguridad: $SAFETY_DIR"$'\n'\
         "        Restauración abortada sin tocar el destino. Use --safety-dir=DIR escribible."
  fi
  chmod 700 "$SAFETY_DIR"
  if [ $HOST_MODE -eq 1 ]; then
    cp -a "$TARGET_DB" "${SAFETY_DIR}/lis.db" || fail "Snapshot del destino falló. Restauración abortada."
    [ -f "$TARGET_ANCHOR" ] && cp -a "$TARGET_ANCHOR" "${SAFETY_DIR}/lis.db.anchor-key" || true
  else
    docker run --rm --network none \
      -v "${VOLUME_NAME}:/data:ro" \
      -v "${SAFETY_DIR}:/safety:rw" \
      python:3.12-slim-bookworm \
      sh -c '
        set -eu
        cp /data/lis.db /safety/lis.db
        chmod 600 /safety/lis.db
        if [ -f /data/lis.db.anchor-key ]; then
          cp /data/lis.db.anchor-key /safety/lis.db.anchor-key
          chmod 600 /safety/lis.db.anchor-key
        fi
      ' || fail "Snapshot del destino falló. Restauración abortada."
  fi
  if [ ! -f "${SAFETY_DIR}/lis.db" ]; then
    fail "No se generó el snapshot del destino. Restauración abortada por seguridad."
  fi
  ok "Snapshot de seguridad: $SAFETY_DIR"
else
  echo "[PASO 3] Destino sin datos previos: no requiere snapshot."
fi

# ------------------------------------------------------------------------------
# 4. Restauración
# ------------------------------------------------------------------------------
echo "[PASO 4] Restaurando base y ancla..."
if [ $HOST_MODE -eq 1 ]; then
  mkdir -p "$(dirname "$TARGET_DB")"
  cp -f "$BACKUP_FILE" "${TARGET_DB}.tmp"
  chmod 600 "${TARGET_DB}.tmp"
  mv -f "${TARGET_DB}.tmp" "$TARGET_DB"
  rm -f "${TARGET_DB}-wal" "${TARGET_DB}-shm"
  if [ -f "$STAGE_DIR/lis.db.anchor-key" ]; then
    cp -f "$STAGE_DIR/lis.db.anchor-key" "${TARGET_ANCHOR}.tmp"
    chmod 600 "${TARGET_ANCHOR}.tmp"
    mv -f "${TARGET_ANCHOR}.tmp" "$TARGET_ANCHOR"
    ok "Ancla restaurada en $TARGET_ANCHOR."
  else
    warn "Sin ancla restaurada: la base no arrancará si tiene eventos."
  fi
  chown "${TARGET_UID}:${TARGET_GID}" "$TARGET_DB" 2>/dev/null || true
else
  docker run --rm --network none \
    -v "${VOLUME_NAME}:/data:rw" \
    -v "$(dirname "$BACKUP_FILE"):/src:ro" \
    -v "$STAGE_DIR:/stage:ro" \
    python:3.12-slim-bookworm \
    sh -c "
      set -eu
      cp '/src/$(basename "$BACKUP_FILE")' /data/lis.db.tmp
      chmod 600 /data/lis.db.tmp
      mv -f /data/lis.db.tmp /data/lis.db
      rm -f /data/lis.db-wal /data/lis.db-shm
      if [ -f /stage/lis.db.anchor-key ]; then
        cp /stage/lis.db.anchor-key /data/lis.db.anchor-key.tmp
        chmod 600 /data/lis.db.anchor-key.tmp
        mv -f /data/lis.db.anchor-key.tmp /data/lis.db.anchor-key
      fi
      chown ${TARGET_UID}:${TARGET_GID} /data/lis.db
      chmod 600 /data/lis.db
      if [ -f /data/lis.db.anchor-key ]; then
        chown ${TARGET_UID}:${TARGET_GID} /data/lis.db.anchor-key
        chmod 600 /data/lis.db.anchor-key
      fi
    " || fail "La restauración dentro del volumen falló."
fi
ok "Base restaurada con permisos 0600."

# ------------------------------------------------------------------------------
# 5. Verificación posterior y comparación de recuentos
# ------------------------------------------------------------------------------
echo "[PASO 5] Verificando el destino restaurado..."
if [ $HOST_MODE -eq 1 ]; then
  POST_REPORT="$STAGE_DIR/post_report.txt"
  if ! python3 "${SCRIPT_DIR}/cutover_common.py" inspect --db "$TARGET_DB" | tee "$POST_REPORT"; then
    fail "La base restaurada NO verifica. Conserve el snapshot en $SAFETY_DIR y no arranque el servicio."
  fi
else
  POST_REPORT="$STAGE_DIR/post_report.txt"
  if ! docker run --rm --network none \
    -v "${VOLUME_NAME}:/data:ro" \
    -v "${SCRIPT_DIR}:/tools:ro" \
    python:3.12-slim-bookworm \
    python3 /tools/cutover_common.py inspect --db /data/lis.db | tee "$POST_REPORT"; then
    fail "La base restaurada NO verifica. Conserve el snapshot en $SAFETY_DIR y no arranque el servicio."
  fi
fi

POST_EVENTS="$(awk -F': *' '/^eventos/ {print $2}' "$POST_REPORT" | tr -d '[:space:]')"
POST_ORDERS="$(awk -F': *' '/^ordenes/ {print $2}' "$POST_REPORT" | tr -d '[:space:]')"
POST_EVENTS="${POST_EVENTS:-0}"
POST_ORDERS="${POST_ORDERS:-0}"

[ "$POST_EVENTS" = "$BACKUP_EVENTS" ] \
  || fail "Recuento de eventos distinto: respaldo=${BACKUP_EVENTS}, restaurado=${POST_EVENTS}"
[ "$POST_ORDERS" = "$BACKUP_ORDERS" ] \
  || fail "Recuento de órdenes distinto: respaldo=${BACKUP_ORDERS}, restaurado=${POST_ORDERS}"

ok "Recuentos idénticos al respaldo: ${POST_ORDERS} órdenes, ${POST_EVENTS} eventos."
ok "Cadena de auditoría y anclaje verificados tras la restauración."
echo "=============================================================================="
echo " Restauración finalizada."
echo " Rollback de esta restauración: --backup-file=${SAFETY_DIR}/lis.db --force"
echo "=============================================================================="

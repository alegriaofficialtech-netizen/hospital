#!/usr/bin/env bash
# ==============================================================================
# prepare_volume.sh - Aprovisionamiento y permisos del volumen persistente
# SGSI-ZTA Hospital Lab — ISO/IEC 27001:2022 & NIST SP 800-207
#
# Prepara el volumen Docker que aloja lis.db con el usuario mínimo (65534).
#
# Cambios respecto de la versión anterior:
#   - Detecta datos existentes y exige --allow-existing antes de tocar permisos.
#   - Nunca borra archivos: el aprovisionamiento no puede destruir datos.
#   - Aplica 0600 a lis.db y a lis.db.anchor-key (no un chmod -R indiscriminado).
#   - Verifica el esquema y la presencia del ancla tras el ajuste.
#   - Contenedores con --network none.
#
# Modo por defecto: SIMULACIÓN (--dry-run). Requiere --apply.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VOLUME_NAME="clinical-data"
TARGET_UID="65534"
TARGET_GID="65534"
EXPECTED_SCHEMA_VERSION="2"
APPLY=0
ALLOW_EXISTING=0
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

for arg in "$@"; do
  case "$arg" in
    --apply)                    APPLY=1 ;;
    --dry-run)                  APPLY=0 ;;
    --allow-existing)           ALLOW_EXISTING=1 ;;
    --volume-name=*)            VOLUME_NAME="${arg#*=}" ;;
    --uid=*)                    TARGET_UID="${arg#*=}" ;;
    --gid=*)                    TARGET_GID="${arg#*=}" ;;
    --expected-schema-version=*) EXPECTED_SCHEMA_VERSION="${arg#*=}" ;;
    --help)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
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

echo "=============================================================================="
echo " APROVISIONAMIENTO DE VOLUMEN PERSISTENTE DOCKER: $VOLUME_NAME"
echo " Modo    : $([ $APPLY -eq 1 ] && echo 'APLICACIÓN REAL (--apply)' || echo 'SIMULACIÓN SEGURA (--dry-run)')"
echo " UID/GID : $TARGET_UID:$TARGET_GID (nobody:nogroup)"
echo " Esquema : v${EXPECTED_SCHEMA_VERSION}"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# 1. Existencia del volumen
# ------------------------------------------------------------------------------
VOLUME_EXISTS=0
if docker volume ls --format '{{.Name}}' | grep -wq "^${VOLUME_NAME}$"; then
  VOLUME_EXISTS=1
  echo "[INFO] El volumen '${VOLUME_NAME}' ya existe."
else
  echo "[PLAN] Se creará el volumen '${VOLUME_NAME}'."
fi

# ------------------------------------------------------------------------------
# 2. Inventario de datos existentes (sin modificar nada)
# ------------------------------------------------------------------------------
HAS_DB=0
HAS_ANCHOR=0
VOLUME_LISTING=""
if [ $VOLUME_EXISTS -eq 1 ]; then
  VOLUME_LISTING="$(docker run --rm --network none -v "${VOLUME_NAME}:/data:ro" \
    python:3.12-slim-bookworm sh -c 'ls -la /data 2>/dev/null || true' 2>/dev/null || true)"
  echo "[INFO] Contenido actual del volumen:"
  echo "${VOLUME_LISTING:-  <vacío o inaccesible>}" | sed 's/^/  /'
  echo "$VOLUME_LISTING" | grep -qw "lis.db" && HAS_DB=1
  echo "$VOLUME_LISTING" | grep -qw "lis.db.anchor-key" && HAS_ANCHOR=1
fi

if [ $HAS_DB -eq 1 ] && [ $ALLOW_EXISTING -eq 0 ]; then
  fail "El volumen ya contiene lis.db. Este script no borra datos, pero ajustar"$'\n'\
       "        permisos sobre una base viva requiere confirmación explícita."$'\n'\
       "        Repita con --allow-existing si la base debe conservarse."
fi

if [ $HAS_DB -eq 1 ] && [ $HAS_ANCHOR -eq 0 ]; then
  warn "lis.db existe sin lis.db.anchor-key. Sin ancla la cadena no es verificable."$'\n'\
       "        El ancla debe restaurarse desde el respaldo o definirse AUDIT_HMAC_KEY."
fi

if [ $APPLY -eq 0 ]; then
  echo "[PLAN] 1. Crear el volumen si no existe."
  echo "[PLAN] 2. chown -R ${TARGET_UID}:${TARGET_GID} /data y chmod 770 /data."
  echo "[PLAN] 3. chmod 600 sobre lis.db, lis.db-wal, lis.db-shm y lis.db.anchor-key."
  echo "[PLAN] 4. Verificar escritura real como usuario ${TARGET_UID}."
  echo "[PLAN] 5. Verificar esquema >= v${EXPECTED_SCHEMA_VERSION} y presencia del ancla."
  echo "[SIMULACIÓN] Sin --apply no se modificó nada."
  exit 0
fi

# ------------------------------------------------------------------------------
# 3. Crear volumen y aplicar permisos
# ------------------------------------------------------------------------------
if [ $VOLUME_EXISTS -eq 0 ]; then
  docker volume create "${VOLUME_NAME}" >/dev/null
  ok "Volumen '${VOLUME_NAME}' creado."
fi

docker run --rm --network none \
  -v "${VOLUME_NAME}:/data:rw" \
  --user 0:0 \
  python:3.12-slim-bookworm \
  sh -c "
    set -eu
    chown -R ${TARGET_UID}:${TARGET_GID} /data
    chmod 770 /data
    for name in lis.db lis.db-wal lis.db-shm lis.db.anchor-key; do
      if [ -e \"/data/\$name\" ]; then chmod 600 \"/data/\$name\"; fi
    done
  " || fail "No se pudieron aplicar los permisos."

ok "Propiedad y permisos aplicados."

# ------------------------------------------------------------------------------
# 4. Verificación de escritura como usuario no privilegiado
# ------------------------------------------------------------------------------
TEST_RES="$(docker run --rm --network none \
  -v "${VOLUME_NAME}:/data:rw" \
  --user "${TARGET_UID}:${TARGET_GID}" \
  --read-only \
  python:3.12-slim-bookworm \
  sh -c "touch /data/.perm_test && rm -f /data/.perm_test && echo WRITE_OK" 2>&1 || true)"

if [ "$TEST_RES" = "WRITE_OK" ]; then
  ok "El usuario ${TARGET_UID}:${TARGET_GID} escribe en /data."
else
  fail "El usuario ${TARGET_UID}:${TARGET_GID} NO puede escribir en /data: ${TEST_RES}"
fi

# ------------------------------------------------------------------------------
# 5. Verificación de contenido: permisos, esquema y ancla
# ------------------------------------------------------------------------------
echo "[VERIFY] Estado final del volumen..."
docker run --rm --network none \
  -v "${VOLUME_NAME}:/data:ro" \
  -v "${SCRIPT_DIR}:/tools:ro" \
  python:3.12-slim-bookworm \
  sh -c "
    set -eu
    ls -la /data
    if [ -f /data/lis.db ]; then
      python3 /tools/cutover_common.py inspect --db /data/lis.db || exit 1
    else
      echo '[INFO] Estado cero: sin base todavía.'
      if [ ! -f /data/lis.db.anchor-key ]; then
        echo '[INFO] Sin ancla: se generará en el primer arranque del backend.'
      fi
    fi
  " || fail "La verificación del volumen falló."

ok "Volumen preparado y verificado."
echo "=============================================================================="

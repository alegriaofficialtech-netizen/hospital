#!/usr/bin/env bash
# ==============================================================================
# export_realm.sh - Exporta el realm de Keycloak SIN detener el servidor.
#
# Por qué no se ejecuta 'kc.sh export' contra la base en vivo:
#   La documentación de Keycloak exige que la instancia no esté iniciada al
#   exportar. Para no detener producción, este script:
#     1. toma un pg_dump consistente de la base de Keycloak (solo lectura);
#     2. lo restaura en un Postgres efímero y aislado;
#     3. ejecuta 'kc.sh export --users same_file' contra esa copia;
#     4. valida que el artefacto sea importable (flujos y bindings completos);
#     5. escribe el JSON en 0600 y destruye el dump intermedio.
#
# El artefacto contiene hashes de credenciales y secretos de clientes: se
# escribe 0600 y nunca se imprime su contenido.
#
# Uso:
#   ./export_realm.sh --out /home/elcra/sgsi-backups/realm/hospital-lab-realm.json
#   ./export_realm.sh --verify-import --force
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="/opt/sgsi-zta-hospital-lab/docker-compose.yml"
KC_SERVICE="keycloak"
DB_SERVICE="keycloak-postgres"
REALM="hospital-lab"
OUT="/home/elcra/sgsi-backups/realm/hospital-lab-realm.json"
FORCE=0
VERIFY=0
PG_IMAGE="postgres:16-alpine"
KC_IMAGE="quay.io/keycloak/keycloak:26.8.0"
NET="zta-realm-export-net"
PG_NAME="zta-realm-export-pg"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
ok()   { echo -e "${GREEN}[PASS]${NC} $*"; }

for arg in "$@"; do
  case "$arg" in
    --compose-file=*) COMPOSE_FILE="${arg#*=}" ;;
    --kc-service=*)   KC_SERVICE="${arg#*=}" ;;
    --db-service=*)   DB_SERVICE="${arg#*=}" ;;
    --realm=*)        REALM="${arg#*=}" ;;
    --out=*)          OUT="${arg#*=}" ;;
    --image=*)        KC_IMAGE="${arg#*=}" ;;
    --force)          FORCE=1 ;;
    --verify-import)  VERIFY=1 ;;
    --help)           sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail "Argumento desconocido: $arg" ;;
  esac
done

[ -f "$COMPOSE_FILE" ] || fail "No existe el compose: $COMPOSE_FILE"
if [ -e "$OUT" ] && [ "$FORCE" -eq 0 ]; then
  fail "$OUT ya existe; use --force para reemplazarlo."
fi

OUT_DIR="$(dirname "$OUT")"
OUT_NAME="$(basename "$OUT")"
if [ ! -d "$OUT_DIR" ]; then
  install -d -m 700 "$OUT_DIR" || fail "No se puede crear $OUT_DIR"
fi
[ -w "$OUT_DIR" ] || fail "Sin permiso de escritura en $OUT_DIR"

TMP_DIR="$(mktemp -d /tmp/zta-realm-export.XXXXXX)"
DUMP_FILE="${TMP_DIR}/keycloak.sql"
EXPORT_DIR="${TMP_DIR}/export"
mkdir -p "$EXPORT_DIR"
chmod 700 "$TMP_DIR" "$EXPORT_DIR"

cleanup() {
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  if [ -f "$DUMP_FILE" ]; then
    shred -u "$DUMP_FILE" 2>/dev/null || rm -f "$DUMP_FILE"
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "=============================================================================="
echo " EXPORTACIÓN DEL REALM ${REALM} (sin detener Keycloak)"
echo " Origen   : ${COMPOSE_FILE} (${DB_SERVICE})"
echo " Destino  : ${OUT}"
echo " Imagen   : ${KC_IMAGE}"
echo "=============================================================================="

# ------------------------------------------------------------------------------
# 1. pg_dump consistente desde el contenedor de base en ejecución
# ------------------------------------------------------------------------------
echo "[PASO 1] Copia consistente de la base de Keycloak (pg_dump)..."
DB_CONTAINER="$(docker compose -f "$COMPOSE_FILE" ps -q "$DB_SERVICE" 2>/dev/null || true)"
[ -n "$DB_CONTAINER" ] || fail "El servicio de base '$DB_SERVICE' no está creado."
[ "$(docker inspect -f '{{.State.Running}}' "$DB_CONTAINER" 2>/dev/null || echo false)" = "true" ] \
  || fail "El servicio de base '$DB_SERVICE' no está en ejecución."

umask 077
docker compose -f "$COMPOSE_FILE" exec -T "$DB_SERVICE" sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-acl --clean --if-exists' \
  > "$DUMP_FILE" || fail "pg_dump falló (¿credenciales o conexión?)"
[ -s "$DUMP_FILE" ] || fail "El dump está vacío."
chmod 600 "$DUMP_FILE"
ok "Dump obtenido ($(wc -c < "$DUMP_FILE") bytes, 0600)."

# ------------------------------------------------------------------------------
# 2. Postgres efímero y restauración
# ------------------------------------------------------------------------------
echo "[PASO 2] Restaurando el dump en un Postgres efímero..."
docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null 2>&1 || true
PG_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -d '\n/+=' | head -c 32)"
docker run -d --name "$PG_NAME" --network "$NET" \
  -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD="$PG_PASSWORD" \
  --tmpfs /var/lib/postgresql/data:rw \
  "$PG_IMAGE" >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$PG_NAME" pg_isready -U keycloak -d keycloak >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$PG_NAME" pg_isready -U keycloak -d keycloak >/dev/null 2>&1 \
  || fail "El Postgres efímero no quedó listo."

docker exec -i -e PGPASSWORD="$PG_PASSWORD" "$PG_NAME" \
  psql -U keycloak -d keycloak -v ON_ERROR_STOP=1 -q < "$DUMP_FILE" \
  || fail "La restauración del dump falló."
ok "Base restaurada en el Postgres efímero."

# ------------------------------------------------------------------------------
# 3. Exportación con kc.sh contra la copia
# ------------------------------------------------------------------------------
echo "[PASO 3] Exportando el realm con kc.sh (sobre la copia)..."
# Keycloak 26.x: al exportar a un único archivo, los usuarios deben ir en el
# mismo archivo (--users realm_file solo aplica al export a directorio).
docker run --rm --name zta-realm-export-kc --network "$NET" \
  -v "${EXPORT_DIR}:/export:rw" \
  -e KC_DB=postgres \
  -e KC_DB_URL="jdbc:postgresql://${PG_NAME}:5432/keycloak" \
  -e KC_DB_USERNAME=keycloak \
  -e KC_DB_PASSWORD="$PG_PASSWORD" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=export \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD="$PG_PASSWORD" \
  "$KC_IMAGE" export --realm "$REALM" --file "/export/${OUT_NAME}" --users same_file \
  > "${TMP_DIR}/export.log" 2>&1 \
  || { tail -20 "${TMP_DIR}/export.log" >&2; fail "kc.sh export falló."; }

[ -s "${EXPORT_DIR}/${OUT_NAME}" ] || fail "kc.sh no produjo el archivo."
chmod 600 "${EXPORT_DIR}/${OUT_NAME}"
ok "Realm exportado ($(wc -c < "${EXPORT_DIR}/${OUT_NAME}") bytes)."

# ------------------------------------------------------------------------------
# 4. Validación estructural: debe ser importable en una instancia limpia
# ------------------------------------------------------------------------------
echo "[PASO 4] Validando que el artefacto sea importable..."
python3 - "${EXPORT_DIR}/${OUT_NAME}" "$REALM" <<'PY'
import json
import sys

path, realm = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)

problems = []
if data.get("realm") != realm:
    problems.append(f"realm={data.get('realm')!r}, esperado {realm!r}")

flows = data.get("authenticationFlows") or []
aliases = {flow.get("alias") for flow in flows}
if not flows:
    problems.append("authenticationFlows vacío: --import-realm fallaría")

for key in (
    "browserFlow",
    "registrationFlow",
    "directGrantFlow",
    "resetCredentialsFlow",
    "clientAuthenticationFlow",
    "dockerAuthenticationFlow",
):
    alias = data.get(key)
    if alias and alias not in aliases:
        problems.append(f"{key}={alias!r} no existe en authenticationFlows")

clients = [client.get("clientId") for client in data.get("clients") or []]
if "clinical-poc" not in clients:
    problems.append("falta el cliente clinical-poc")
role_names = [role.get("name") for role in (data.get("roles") or {}).get("realm", [])]
if "auditor" not in role_names:
    problems.append("falta el rol de reino auditor")

if problems:
    print("[FAIL] artefacto no importable: " + "; ".join(problems), file=sys.stderr)
    raise SystemExit(1)

users = data.get("users") or []
print(f"[PASS] realm={realm} clients={len(clients)} roles={len(role_names)} "
      f"flujos={len(flows)} usuarios={len(users)}")
PY

python3 - "$OUT_DIR" "$OUT" "${EXPORT_DIR}/${OUT_NAME}" <<'PY'
import os
import sys

out_dir, out, produced = sys.argv[1:4]
os.makedirs(out_dir, mode=0o700, exist_ok=True)
tmp = os.path.join(out_dir, ".realm-export.tmp")
with open(produced, "rb") as source, open(tmp, "wb") as target:
    target.write(source.read())
os.chmod(tmp, 0o600)
os.replace(tmp, out)
print(f"[PASS] artefacto en {out} (0600)")
PY

if [ "$VERIFY" -eq 1 ]; then
  echo "[PASO 5] Verificando importación en un Keycloak limpio..."
  "${SCRIPT_DIR}/verify_realm_import.sh" --artifact="$OUT" --realm="$REALM" \
    || fail "El artefacto no importa en una instancia limpia."
fi

ok "Exportación completada: $OUT"
echo " Recuerde: el artefacto contiene hashes de credenciales y secretos de clientes (0600)."

#!/usr/bin/env bash
# ==============================================================================
# verify_realm_import.sh - Verifica que un artefacto de realm importe en limpio.
#
# Levanta un Keycloak efímero con 'start-dev --import-realm' usando el artefacto
# como único archivo de importación, comprueba discovery, cliente y rol, y
# destruye todo. No toca producción.
#
# Uso:
#   ./verify_realm_import.sh --artifact /ruta/hospital-lab-realm.json
# ==============================================================================

set -euo pipefail

ARTIFACT=""
REALM="hospital-lab"
PORT=18185
KC_IMAGE="quay.io/keycloak/keycloak:26.8.0"
PG_IMAGE="postgres:16-alpine"
PROJECT="zta-realm-verify"

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }
ok()   { echo -e "${GREEN}[PASS]${NC} $*"; }

for arg in "$@"; do
  case "$arg" in
    --artifact=*) ARTIFACT="${arg#*=}" ;;
    --realm=*)    REALM="${arg#*=}" ;;
    --port=*)     PORT="${arg#*=}" ;;
    --image=*)    KC_IMAGE="${arg#*=}" ;;
    --help)       sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail "Argumento desconocido: $arg" ;;
  esac
done

[ -f "$ARTIFACT" ] || fail "No existe el artefacto: $ARTIFACT"
[ -r "$ARTIFACT" ] || fail "El artefacto no es legible por $(id -un): $ARTIFACT"

TMP_DIR="$(mktemp -d /tmp/zta-realm-verify.XXXXXX)"
chmod 700 "$TMP_DIR"
PW="$(head -c 32 /dev/urandom | base64 | tr -d '\n/+=' | head -c 32)"

cleanup() {
  docker compose -p "$PROJECT" -f "${TMP_DIR}/compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat > "${TMP_DIR}/compose.yml" <<YAML
services:
  db:
    image: ${PG_IMAGE}
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: ${PW}
    tmpfs:
      - /var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak -d keycloak"]
      interval: 3s
      timeout: 3s
      retries: 30
  kc:
    image: ${KC_IMAGE}
    command: ["start-dev", "--import-realm"]
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://db:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: ${PW}
      KC_BOOTSTRAP_ADMIN_USERNAME: verify
      KC_BOOTSTRAP_ADMIN_PASSWORD: ${PW}
      KC_HTTP_ENABLED: "true"
      KC_HEALTH_ENABLED: "true"
    volumes:
      - ${ARTIFACT}:/opt/keycloak/data/import/realm.json:ro
    ports:
      - "127.0.0.1:${PORT}:8080"
    depends_on:
      db:
        condition: service_healthy
YAML

echo "=============================================================================="
echo " VERIFICACIÓN DE IMPORTACIÓN DEL REALM ${REALM}"
echo " Artefacto: ${ARTIFACT}"
echo " Keycloak : ${KC_IMAGE} en 127.0.0.1:${PORT}"
echo "=============================================================================="

echo "[PASO 1] Levantando Keycloak efímero con --import-realm..."
docker compose -p "$PROJECT" -f "${TMP_DIR}/compose.yml" up -d >/dev/null

READY=0
# El build inicial de Keycloak + la importación pueden superar los 2 minutos en
# hosts cargados; se espera hasta 4 minutos.
for _ in $(seq 1 240); do
  if curl -sf --max-time 2 "http://127.0.0.1:${PORT}/realms/${REALM}/.well-known/openid-configuration" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
if [ "$READY" -ne 1 ]; then
  echo "--- errores de importación (Keycloak) ---" >&2
  docker compose -p "$PROJECT" -f "${TMP_DIR}/compose.yml" logs --no-log-prefix kc 2>&1 \
    | grep -iE 'error|fail|exception|caused by|unable|cannot|invalid|import' | tail -40 >&2 || true
  echo "--- últimas 40 líneas ---" >&2
  docker compose -p "$PROJECT" -f "${TMP_DIR}/compose.yml" logs --tail=40 kc >&2 || true
  fail "El realm no quedó disponible: el artefacto no importa."
fi
ok "Realm disponible tras la importación."

echo "[PASO 2] Comprobando discovery, cliente y rol..."
python3 - "$PORT" "$REALM" "$PW" <<'PY'
import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

port, realm, password = sys.argv[1:4]
base = f"http://127.0.0.1:{port}"

def get(url, token=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=10) as response:
        return response.status, json.loads(response.read().decode("utf-8"))

status, discovery = get(f"{base}/realms/{realm}/.well-known/openid-configuration")
assert status == 200, status
assert discovery["issuer"].endswith(f"/realms/{realm}"), discovery["issuer"]

data = urllib.parse.urlencode({
    "grant_type": "password",
    "client_id": "admin-cli",
    "username": "verify",
    "password": password,
}).encode()
request = urllib.request.Request(
    f"{base}/realms/master/protocol/openid-connect/token",
    data=data,
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    method="POST",
)
with urllib.request.urlopen(request, timeout=10) as response:
    token = json.loads(response.read().decode("utf-8"))["access_token"]

status, clients = get(f"{base}/admin/realms/{realm}/clients?clientId=clinical-poc", token)
assert status == 200 and clients, "cliente clinical-poc ausente"
status, role = get(f"{base}/admin/realms/{realm}/roles/auditor", token)
assert status == 200 and role.get("name") == "auditor", "rol auditor ausente"
status, users = get(f"{base}/admin/realms/{realm}/users/count", token)
assert status == 200, "no se pudo contar usuarios"

print(f"[PASS] issuer={discovery['issuer']}")
print(f"[PASS] cliente clinical-poc presente; rol auditor presente; usuarios={users}")
PY

ok "Importación verificada en limpio."

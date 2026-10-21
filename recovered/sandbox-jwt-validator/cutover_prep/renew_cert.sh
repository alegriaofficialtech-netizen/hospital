#!/usr/bin/env bash
# ==============================================================================
# renew_cert.sh - Renueva el certificado TLS del gateway de identidad.
#
# Estrategia:
#   - El certificado es Let's Encrypt para un nombre .ts.net; solo Tailscale
#     puede completar el desafío DNS-01. La renovación se hace con
#     'tailscale cert', que requiere root (acceso al socket de tailscaled).
#   - 'tailscale cert' entrega la hoja y la clave, no siempre la cadena. Este
#     script reconstruye la cadena completa reutilizando los intermedios del
#     fullchain vigente y valida hoja+clave antes de instalar.
#   - Instalación atómica (0644 cert / 0600 clave), recarga graceful de Caddy y
#     verificación TLS de extremo a extremo. Si la verificación falla, restaura
#     el material anterior y recarga de nuevo.
#
# Se ejecuta como root desde un timer systemd (ver systemd/).
#
# Uso:
#   renew_cert.sh --check                 # solo informa estado/expiración
#   renew_cert.sh --dry-run               # emite y valida, no instala
#   renew_cert.sh                         # renueva si faltan <= 30 días
#   renew_cert.sh --force                 # renueva ahora
# ==============================================================================

set -euo pipefail

TLS_DIR="/etc/sgsi-zta/tls"
HOST="servidor-1.tailb0f78a.ts.net"
CERT_NAME="fullchain.pem"
KEY_NAME="privkey.pem"
DAYS=30
MODE="auto"          # auto | check | dry-run
FORCE=0
RELOAD=1
COMPOSE_FILE="/opt/sgsi-zta-hospital-lab/docker-compose.yml"
GATEWAY_SERVICE="identity-gateway"
BIND_IP="100.78.61.51"
PORT="8443"
TAILSCALE_BIN="tailscale"
LOCK_FILE="/run/sgsi-zta-cert-renew.lock"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
ok()   { echo -e "${GREEN}[PASS]${NC} $*"; }

for arg in "$@"; do
  case "$arg" in
    --tls-dir=*)        TLS_DIR="${arg#*=}" ;;
    --host=*)           HOST="${arg#*=}" ;;
    --cert-name=*)      CERT_NAME="${arg#*=}" ;;
    --key-name=*)       KEY_NAME="${arg#*=}" ;;
    --if-expiring-days=*) DAYS="${arg#*=}" ;;
    --check)            MODE="check" ;;
    --dry-run)          MODE="dry-run" ;;
    --force)            FORCE=1 ;;
    --no-reload)        RELOAD=0 ;;
    --compose-file=*)   COMPOSE_FILE="${arg#*=}" ;;
    --service=*)        GATEWAY_SERVICE="${arg#*=}" ;;
    --bind-ip=*)        BIND_IP="${arg#*=}" ;;
    --port=*)           PORT="${arg#*=}" ;;
    --tailscale-bin=*)  TAILSCALE_BIN="${arg#*=}" ;;
    --lock-file=*)      LOCK_FILE="${arg#*=}" ;;
    --help)             sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) fail "Argumento desconocido: $arg" ;;
  esac
done

CERT="${TLS_DIR}/${CERT_NAME}"
KEY="${TLS_DIR}/${KEY_NAME}"

exec 9>"$LOCK_FILE" 2>/dev/null && LOCK_OPEN=1 || LOCK_OPEN=0
if [ "$LOCK_OPEN" -eq 1 ] && command -v flock >/dev/null 2>&1; then
  flock -n 9 || { warn "Otra renovación está en curso; se omite esta ejecución."; exit 0; }
elif [ "$LOCK_OPEN" -eq 0 ]; then
  warn "No se pudo abrir el lock ${LOCK_FILE}; se continúa sin exclusión mutua."
fi

days_left() {
  local cert="$1"
  local end
  end="$(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)"
  local end_epoch now_epoch
  end_epoch="$(date -d "$end" +%s)"
  now_epoch="$(date +%s)"
  echo $(( (end_epoch - now_epoch) / 86400 ))
}

san_has_host() {
  local cert="$1"
  openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | grep -c "DNS:${HOST}" >/dev/null
}

key_matches_cert() {
  local cert="$1" key="$2"
  local cert_pub key_pub
  cert_pub="$(openssl x509 -in "$cert" -pubkey -noout | sha256sum | cut -d' ' -f1)"
  key_pub="$(openssl pkey -in "$key" -pubout 2>/dev/null | sha256sum | cut -d' ' -f1)"
  [ -n "$cert_pub" ] && [ "$cert_pub" = "$key_pub" ]
}

chain_count() {
  grep -c 'BEGIN CERTIFICATE' "$1" 2>/dev/null || echo 0
}

# ------------------------------------------------------------------------------
# Estado actual
# ------------------------------------------------------------------------------
if [ ! -f "$CERT" ]; then
  [ "$MODE" = "check" ] && fail "No existe $CERT"
  warn "No existe $CERT: se emitirá un certificado nuevo."
  LEFT=-1
else
  LEFT="$(days_left "$CERT")"
  echo "[INFO] Certificado: $CERT"
  echo "[INFO] Vigencia restante: ${LEFT} días"
  echo "[INFO] SAN contiene ${HOST}: $(san_has_host "$CERT" && echo si || echo NO)"
  echo "[INFO] Certificados en la cadena: $(chain_count "$CERT")"
  if [ -f "$KEY" ] && key_matches_cert "$CERT" "$KEY"; then
    echo "[INFO] Clave privada coincide con el certificado: si"
  else
    warn "La clave privada no coincide o no es legible."
  fi
fi

if [ "$MODE" = "check" ] && [ "$FORCE" -eq 0 ]; then
  if [ "$LEFT" -lt 0 ]; then fail "El certificado no existe o está vencido."; fi
  if [ "$LEFT" -le "$DAYS" ]; then
    warn "Renovación necesaria (<= ${DAYS} días). Ejecute sin --check."
    exit 0
  fi
  ok "No requiere renovación (${LEFT} > ${DAYS} días)."
  exit 0
fi

if [ "$LEFT" -gt "$DAYS" ] && [ "$FORCE" -eq 0 ]; then
  ok "No requiere renovación (${LEFT} > ${DAYS} días)."
  exit 0
fi

# ------------------------------------------------------------------------------
# Emisión
# ------------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ] && [ "$TAILSCALE_BIN" = "tailscale" ]; then
  fail "La emisión con 'tailscale cert' requiere root (socket de tailscaled)."
fi

if command -v "$TAILSCALE_BIN" >/dev/null 2>&1; then
  CERT_DOMAINS="$("$TAILSCALE_BIN" status --json 2>/dev/null \
    | python3 -c 'import json,sys; print(",".join((json.load(sys.stdin).get("Self") or {}).get("CertDomains") or []))' 2>/dev/null || true)"
  if [ -z "$CERT_DOMAINS" ]; then
    warn "CertDomains vacío: HTTPS podría estar deshabilitado en el tailnet. Se intentará igual."
  else
    echo "[INFO] CertDomains: ${CERT_DOMAINS}"
  fi
fi

TMP_DIR="$(mktemp -d /tmp/sgsi-renew.XXXXXX)"
chmod 700 "$TMP_DIR"
NEW_CERT="${TMP_DIR}/leaf.pem"
NEW_KEY="${TMP_DIR}/leaf.key"
NEW_CHAIN="${TMP_DIR}/fullchain.pem"

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

echo "[PASO 1] Emitiendo certificado con ${TAILSCALE_BIN} cert..."
"$TAILSCALE_BIN" cert --cert-file "$NEW_CERT" --key-file "$NEW_KEY" "$HOST" \
  || fail "tailscale cert falló. Habilite HTTPS Certificates en el admin console y reintente."

[ -s "$NEW_CERT" ] && [ -s "$NEW_KEY" ] || fail "tailscale cert no produjo archivos."
ok "Certificado emitido."

echo "[PASO 2] Reconstruyendo la cadena completa..."
if [ "$(chain_count "$NEW_CERT")" -gt 1 ]; then
  cp "$NEW_CERT" "$NEW_CHAIN"
else
  [ -f "$CERT" ] || fail "No hay cadena previa para reutilizar intermedios; instale un fullchain manualmente."
  # Conserva todo lo que no sea la hoja anterior (intermedios/raíces).
  awk '/BEGIN CERTIFICATE/{n++} n>=2' "$CERT" > "${TMP_DIR}/intermediates.pem"
  [ -s "${TMP_DIR}/intermediates.pem" ] \
    || fail "La cadena previa no contiene intermedios; instale un fullchain manualmente."
  cat "$NEW_CERT" "${TMP_DIR}/intermediates.pem" > "$NEW_CHAIN"
fi
ok "Cadena reconstruida: $(chain_count "$NEW_CHAIN") certificados."

echo "[PASO 3] Validando hoja, SAN, clave y vigencia..."
san_has_host "$NEW_CERT" || fail "El certificado nuevo no cubre ${HOST}."
key_matches_cert "$NEW_CERT" "$NEW_KEY" || fail "La clave nueva no coincide con la hoja."
NEW_LEFT="$(days_left "$NEW_CERT")"
[ "$NEW_LEFT" -gt 0 ] || fail "El certificado nuevo ya está vencido."
ok "Hoja válida: SAN=${HOST}, ${NEW_LEFT} días restantes."

if [ "$MODE" = "dry-run" ]; then
  ok "Dry-run: no se instala nada. Huella hoja: $(openssl x509 -in "$NEW_CERT" -noout -fingerprint -sha256 | cut -d= -f2)"
  exit 0
fi

# ------------------------------------------------------------------------------
# Instalación atómica con rollback
# ------------------------------------------------------------------------------
BACKUP_CERT="${TMP_DIR}/previous.crt"
BACKUP_KEY="${TMP_DIR}/previous.key"
HAD_PREVIOUS=0
if [ -f "$CERT" ] && [ -f "$KEY" ]; then
  cp -p "$CERT" "$BACKUP_CERT"
  cp -p "$KEY" "$BACKUP_KEY"
  HAD_PREVIOUS=1
fi

restore_previous() {
  if [ "$HAD_PREVIOUS" -eq 1 ]; then
    install -m 0644 "$BACKUP_CERT" "$CERT"
    install -m 0600 "$BACKUP_KEY" "$KEY"
    warn "Material anterior restaurado."
  fi
}

echo "[PASO 4] Instalando material (0644 cert / 0600 clave)..."
install -d -m 700 "$TLS_DIR"
install -m 0644 "$NEW_CHAIN" "${TLS_DIR}/.${CERT_NAME}.new"
install -m 0600 "$NEW_KEY" "${TLS_DIR}/.${KEY_NAME}.new"
mv -f "${TLS_DIR}/.${CERT_NAME}.new" "$CERT"
mv -f "${TLS_DIR}/.${KEY_NAME}.new" "$KEY"
ok "Material instalado."

GW_CONTAINER="$(docker compose -f "$COMPOSE_FILE" ps -q "$GATEWAY_SERVICE" 2>/dev/null || true)"
if [ "$RELOAD" -eq 1 ] && [ -n "$GW_CONTAINER" ] \
   && [ "$(docker inspect -f '{{.State.Running}}' "$GW_CONTAINER" 2>/dev/null || echo false)" = "true" ]; then
  echo "[PASO 5] Recargando Caddy..."
  docker compose -f "$COMPOSE_FILE" exec -T "$GATEWAY_SERVICE" \
    caddy reload --config /etc/caddy/Caddyfile \
    || { restore_previous; fail "caddy reload falló; se restauró el material anterior."; }
  sleep 2
  echo "[PASO 6] Verificando TLS de extremo a extremo..."
  if echo | openssl s_client -connect "${BIND_IP}:${PORT}" -servername "$HOST" \
      -verify_return_error 2>/dev/null | grep -c "Verify return code: 0" >/dev/null; then
    ok "TLS verificado contra la cadena del sistema."
  else
    restore_previous
    docker compose -f "$COMPOSE_FILE" exec -T "$GATEWAY_SERVICE" \
      caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1 || true
    fail "La cadena nueva no verifica; se restauró el material anterior."
  fi
else
  warn "Gateway no está corriendo o --no-reload: el material se usará al arrancar."
fi

ok "Renovación completada."
echo " Nueva vigencia: ${NEW_LEFT} días. Huella: $(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | cut -d= -f2)"

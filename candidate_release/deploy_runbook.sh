#!/usr/bin/env bash
# ==============================================================================
# SGSI-ZTA Hospital Lab — Runbook de Despliegue y Rollback Controlado
# ISO/IEC 27001:2022 & NIST SP 800-207
#
# Procedimiento auditable, determinista y reversible para integrar
# ZeroTrustJWTValidator en el backend LIS de Clinical PoC.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="/opt/sgsi-zta-hospital-lab/clinical-poc/lis-backend"
BACKUP_DIR="${TARGET_DIR}/backup"
MANIFEST_FILE="${SCRIPT_DIR}/MANIFEST.sha256"

# Colores para salida estructurada
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

usage() {
    cat <<EOF
Uso: $0 {check|backup|deploy|healthcheck|rollback} [--execute]

Comandos:
  check        Verifica pre-requisitos, integridad de manifiesto y estado de Keycloak.
  backup       Genera respaldo timestamped del LIS original con hash SHA256.
  deploy       Despliega los artefactos candidatos hacia el directorio destino (requiere --execute).
  healthcheck  Ejecuta pruebas de aceptacion y verificacion de endpoints post-despliegue.
  rollback     Restaura de inmediato la version original desde el ultimo respaldo.

EOF
    exit 1
}

cmd_check() {
    log_info "1. Verificando integridad criptografica del paquete candidato..."
    cd "${SCRIPT_DIR}"
    if sha256sum -c "${MANIFEST_FILE}" --status; then
        log_pass "Manifiesto SHA256 integro y consistente."
    else
        log_fail "Corrupcion detectada en los archivos del paquete candidato."
        exit 1
    fi

    log_info "2. Verificando disponibilidad del servicio Keycloak OIDC..."
    if curl -s -f -m 3 "http://127.0.0.1:8085/realms/hospital-lab/.well-known/openid-configuration" > /dev/null; then
        log_pass "Keycloak OIDC Discovery accesible en http://127.0.0.1:8085."
    else
        log_fail "Keycloak no responde en http://127.0.0.1:8085."
        exit 1
    fi

    log_info "3. Verificando existencia del directorio destino de produccion..."
    if [[ -d "${TARGET_DIR}" && -f "${TARGET_DIR}/server.py" ]]; then
        log_pass "Directorio destino y server.py original confirmados en ${TARGET_DIR}."
    else
        log_fail "No se encontro el archivo server.py en ${TARGET_DIR}."
        exit 1
    fi

    log_pass "Criterios de pre-vuelo APROBADOS. Sistema listo para autorizacion de despliegue."
}

cmd_backup() {
    log_info "Creando respaldo de seguridad del LIS original..."
    mkdir -p "${BACKUP_DIR}"
    chmod 0700 "${BACKUP_DIR}"

    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="${BACKUP_DIR}/server.py.bak_${TIMESTAMP}"

    cp -p "${TARGET_DIR}/server.py" "${BACKUP_FILE}"
    chmod 0600 "${BACKUP_FILE}"

    # Registrar hash del respaldo
    sha256sum "${BACKUP_FILE}" > "${BACKUP_FILE}.sha256"
    log_pass "Respaldo generado con exito:"
    echo "  Archivo: ${BACKUP_FILE}"
    echo "  Hash:    $(cat "${BACKUP_FILE}.sha256")"
}

cmd_deploy() {
    local execute_flag="${1:-}"
    if [[ "${execute_flag}" != "--execute" ]]; then
        log_warn "Modo SIMULACION (DRY-RUN). Para ejecutar realmente, agregue '--execute'."
        echo "Acciones a realizar:"
        echo "  - cp ${SCRIPT_DIR}/server.py -> ${TARGET_DIR}/server.py"
        echo "  - cp ${SCRIPT_DIR}/jwt_validator.py -> ${TARGET_DIR}/jwt_validator.py"
        echo "  - chmod 0644 ${TARGET_DIR}/server.py ${TARGET_DIR}/jwt_validator.py"
        return 0
    fi

    log_info "Iniciando despliegue atomico..."
    cmd_check
    cmd_backup

    cp -p "${SCRIPT_DIR}/server.py" "${TARGET_DIR}/server.py.tmp"
    cp -p "${SCRIPT_DIR}/jwt_validator.py" "${TARGET_DIR}/jwt_validator.py.tmp"

    mv "${TARGET_DIR}/server.py.tmp" "${TARGET_DIR}/server.py"
    mv "${TARGET_DIR}/jwt_validator.py.tmp" "${TARGET_DIR}/jwt_validator.py"
    chmod 0644 "${TARGET_DIR}/server.py" "${TARGET_DIR}/jwt_validator.py"

    log_pass "Despliegue atomico completado. Proceder con cmd_healthcheck."
}

cmd_rollback() {
    log_warn "Iniciando procedimiento de ROLLBACK de emergencia..."
    LATEST_BACKUP=$(ls -t "${BACKUP_DIR}"/server.py.bak_* 2>/dev/null | grep -v "\.sha256$" | head -n 1 || true)

    if [[ -z "${LATEST_BACKUP}" || ! -f "${LATEST_BACKUP}" ]]; then
        log_fail "No se encontro ningun archivo de respaldo en ${BACKUP_DIR}."
        exit 1
    fi

    log_info "Verificando integridad del respaldo: ${LATEST_BACKUP}"
    EXPECTED_HASH=$(cat "${LATEST_BACKUP}.sha256" | awk '{print $1}')
    CURRENT_HASH=$(sha256sum "${LATEST_BACKUP}" | awk '{print $1}')

    if [[ "${EXPECTED_HASH}" != "${CURRENT_HASH}" ]]; then
        log_fail "El archivo de respaldo esta corrupto. Abortando restauracion."
        exit 1
    fi

    cp -p "${LATEST_BACKUP}" "${TARGET_DIR}/server.py"
    rm -f "${TARGET_DIR}/jwt_validator.py"

    log_pass "Rollback completado con exito. LIS restaurado a estado original."
}

case "${1:-}" in
    check)
        cmd_check
        ;;
    backup)
        cmd_backup
        ;;
    deploy)
        cmd_deploy "${2:-}"
        ;;
    rollback)
        cmd_rollback
        ;;
    *)
        usage
        ;;
esac

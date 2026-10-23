#!/usr/bin/env bash
# Script de instruccion y conmutacion controlada para entorno demo limpio (F6).
# Permite alternar de forma segura entre la base operativa con historial de pruebas
# y la base de demostracion aislada sin alterar puertos ni servicios externos.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME="${F11_RUNTIME_DIR:-/home/elcra/sgsi-zta-runtime/f11}"
OPERATIONAL_DB="$RUNTIME/lis.db"
DEMO_DB="$RUNTIME/demo/lis.db"

ACTION="${1:-status}"

case "$ACTION" in
  status)
    echo "=== ESTADO DE BASE DE DATOS F11 ==="
    echo "Base operativa actual: $OPERATIONAL_DB"
    if [[ -f "$OPERATIONAL_DB" ]]; then
      echo "  - Existe (tamano: $(stat -c%s "$OPERATIONAL_DB") bytes)"
    else
      echo "  - No existe"
    fi
    echo "Base de demostracion aislada: $DEMO_DB"
    if [[ -f "$DEMO_DB" ]]; then
      echo "  - Existe (tamano: $(stat -c%s "$DEMO_DB") bytes)"
    else
      echo "  - No generada aun (ejecute: ./infra/f11/demo-prep.sh)"
    fi
    ;;
  prep)
    "$ROOT/infra/f11/demo-prep.sh"
    ;;
  *)
    echo "Uso: $0 {status|prep}"
    exit 1
    ;;
esac
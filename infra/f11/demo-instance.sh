#!/usr/bin/env bash
# Instancia independiente de demostracion para SGSI-ZTA Hospital Lab (F6).
# Ejecuta el backend sobre el puerto 8011 usando la base de datos limpia
# /home/elcra/sgsi-zta-runtime/f11/demo/lis.db SIN detener ni reemplazar
# el stack operativo de F11 (puerto 8010).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME="${F11_RUNTIME_DIR:-/home/elcra/sgsi-zta-runtime/f11}"
DEMO_DIR="$RUNTIME/demo"
BACKEND_ENV="$ROOT/infra/f11/backend.env"
VENV_PY="$ROOT/backend/.venv/bin/python"

DEMO_PORT="${DEMO_PORT:-8011}"
DEMO_DB="$DEMO_DIR/lis.db"
PIDFILE="$DEMO_DIR/backend-demo.pid"
LOGFILE="$DEMO_DIR/backend-demo.log"

wait_for_http() {
  local url="$1" timeout="${2:-30}" waited=0
  while (( waited < timeout )); do
    if curl -s -f -o /dev/null "$url" 2>/dev/null; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

demo_pid() {
  [[ -r "$PIDFILE" ]] && cat "$PIDFILE" 2>/dev/null || true
}

start_demo() {
  echo "== Iniciando instancia independiente de Demostracion (puerto $DEMO_PORT) =="
  [[ -r "$BACKEND_ENV" ]] || { echo "error: falta $BACKEND_ENV" >&2; exit 1; }
  [[ -x "$VENV_PY" ]] || { echo "error: falta $VENV_PY" >&2; exit 1; }

  mkdir -p "$DEMO_DIR"
  os_chmod_ok=true

  local pid
  pid="$(demo_pid)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "   demo backend ya esta en ejecucion (pid $pid, puerto $DEMO_PORT)"
    return 0
  fi

  # Asegurar que la base demo exista
  if [[ ! -f "$DEMO_DB" ]]; then
    echo "   [!] Base demo no encontrada. Inicializando con demo-prep.sh..."
    "$ROOT/infra/f11/demo-prep.sh" --demo-dir "$DEMO_DIR"
  fi

  # Cargar entorno base y sobreescribir puerto y base
  set -a
  # shellcheck disable=SC1090
  . "$BACKEND_ENV"
  export PORT="$DEMO_PORT"
  export LIS_DB_PATH="$DEMO_DB"
  set +a

  (
    cd "$ROOT/backend" || exit 1
    nohup nice -n 10 \
      env PYTHONDONTWRITEBYTECODE=1 "$VENV_PY" server.py \
      >>"$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
  )

  local url="http://127.0.0.1:$DEMO_PORT/health"
  if ! wait_for_http "$url" 30; then
    echo "--- ultimas lineas de $LOGFILE ---" >&2
    tail -20 "$LOGFILE" >&2 || true
    echo "error: demo backend no respondio en $url dentro de 30s" >&2
    exit 1
  fi

  echo "   [+] demo backend activo en http://127.0.0.1:$DEMO_PORT (pid $(demo_pid))"
  echo "   [+] Base aislada: $DEMO_DB"
  echo "   [+] Pila F11 operativa intacta en http://127.0.0.1:8010"
}

stop_demo() {
  echo "== Deteniendo instancia independiente de Demostracion =="
  local pid waited=0
  pid="$(demo_pid)"
  if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
    echo "   demo backend no esta en ejecucion"
    rm -f "$PIDFILE"
    return 0
  fi
  kill -TERM "$pid" 2>/dev/null || true
  while (( waited < 15 )) && kill -0 "$pid" 2>/dev/null; do
    sleep 1
    waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
    echo "   demo backend terminado forzosamente (SIGKILL)"
  else
    echo "   demo backend detenido limpiamente"
  fi
  rm -f "$PIDFILE"
}

status_demo() {
  echo "=== ESTADO DE INSTANCIA DE DEMOSTRACION AISLADA ==="
  local pid
  pid="$(demo_pid)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "   Estado: EN EJECUCION (pid $pid)"
    echo "   Puerto: $DEMO_PORT"
    echo "   Base de datos: $DEMO_DB"
    echo "   Log: $LOGFILE"
    curl -s "http://127.0.0.1:$DEMO_PORT/health" || true
    echo
  else
    echo "   Estado: DETENIDO"
    echo "   Base disponible: $DEMO_DB"
  fi
}

ACTION="${1:-status}"
case "$ACTION" in
  start)  start_demo ;;
  stop)   stop_demo ;;
  status) status_demo ;;
  *)
    echo "Uso: $0 {start|stop|status}"
    exit 2
    ;;
esac
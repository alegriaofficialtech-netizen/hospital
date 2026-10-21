#!/usr/bin/env bash
# Independent lifecycle for the F11 real-mode stack.
#
# Why the backend is not a systemd service
# ----------------------------------------
# The unit in infra/f11/systemd is deliberately NOT installed, and this
# account cannot create cgroups: `systemd-run --scope` answers "Access
# denied" and cgexec is not present. The backend therefore runs as a host
# process with the closest guards an unprivileged user can get:
#
#   taskset -c <cpu>  pins the process to one core (hard CPU bound)
#   ulimit -v <kb>    address-space guard (a runaway allocation fails fast)
#   nice -n 5         keeps the process out of the scheduler's way
#
# Those are approximations, NOT cgroup limits: the unit's MemoryMax=512M and
# CPUQuota=50% are not reproduced here. The containerised components do get
# real limits, from deploy.resources.limits in compose.yaml. The preflight
# gate stays the real admission control for the host.
#
# Usage
#   stack-ctl.sh start  keycloak|frontend|backend|all
#   stack-ctl.sh stop   keycloak|frontend|backend|all
#   stack-ctl.sh status
#
# Every start runs the preflight gate (stage "up") first: a refused gate
# means no component comes up. This script never installs a systemd unit,
# never builds an image, and never touches containers outside the F11
# compose project.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME="${F11_RUNTIME_DIR:-/home/elcra/sgsi-zta-runtime/f11}"
ENV_FILE="$ROOT/infra/f11/.env"
COMPOSE_FILE="$ROOT/infra/f11/compose.yaml"
GATE="$ROOT/infra/f11/preflight-gate.sh"
BACKEND_ENV="$ROOT/infra/f11/backend.env"
VENV_PY="$ROOT/backend/.venv/bin/python"
PIDFILE="$RUNTIME/backend.pid"
LOGFILE="$RUNTIME/backend.log"

KEYCLOAK_URL="${F11_KEYCLOAK_URL:-http://127.0.0.1:8085}"
BACKEND_URL="${F11_API_BASE_URL:-http://127.0.0.1:8010}"
FRONTEND_URL="${F11_BASE_URL:-http://127.0.0.1:4200}"

BACKEND_CPU="${F11_BACKEND_CPU:-0}"
BACKEND_VMEM_KB="${F11_BACKEND_VMEM_KB:-2097152}"
BACKEND_NICE="${F11_BACKEND_NICE:-5}"

compose() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

die() {
  echo "error: $*" >&2
  exit 1
}

require_gate() {
  local component="$1"
  echo "== preflight (stage up, component $component) =="
  if ! "$GATE" --stage up --component "$component"; then
    die "preflight refused the host; nothing was started"
  fi
}

wait_for_http() {
  local url="$1" timeout="$2" waited=0
  while (( waited < timeout )); do
    if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  return 1
}

container_running() {
  [[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)" == "true" ]]
}

backend_pid() {
  [[ -r "$PIDFILE" ]] && cat "$PIDFILE" 2>/dev/null || true
}

start_keycloak() {
  echo "== start keycloak =="
  compose up -d --no-build keycloak
  # The JVM needs ~65 s to boot on this host and the realm bootstrap adds
  # more, so the readiness wait is generous on purpose.
  if ! wait_for_http "$KEYCLOAK_URL/realms/master" 300; then
    die "keycloak did not answer on $KEYCLOAK_URL within 300s"
  fi
  echo "   keycloak is up on $KEYCLOAK_URL"
}

start_frontend() {
  echo "== start frontend =="
  # --no-build on purpose: the static image already exists and this stack
  # must never compile on the host.
  compose up -d --no-build frontend
  if ! wait_for_http "$FRONTEND_URL/" 60; then
    die "frontend did not answer on $FRONTEND_URL within 60s"
  fi
  echo "   frontend is up on $FRONTEND_URL"
}

start_backend() {
  echo "== start backend (host process) =="
  [[ -r "$BACKEND_ENV" ]] || die "missing $BACKEND_ENV"
  [[ -x "$VENV_PY" ]] || die "missing $VENV_PY"
  mkdir -p "$RUNTIME"
  local pid
  pid="$(backend_pid)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "   backend already running (pid $pid)"
    return 0
  fi
  set -a
  # shellcheck disable=SC1090
  . "$BACKEND_ENV"
  set +a
  (
    cd "$ROOT/backend" || exit 1
    ulimit -v "$BACKEND_VMEM_KB" || true
    nohup taskset -c "$BACKEND_CPU" nice -n "$BACKEND_NICE" \
      env PYTHONDONTWRITEBYTECODE=1 "$VENV_PY" server.py \
      >>"$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
  )
  if ! wait_for_http "$BACKEND_URL/health" 60; then
    echo "--- last lines of $LOGFILE ---" >&2
    tail -20 "$LOGFILE" >&2 || true
    die "backend did not answer on $BACKEND_URL/health within 60s"
  fi
  echo "   backend is up on $BACKEND_URL (pid $(backend_pid))"
}

stop_backend() {
  echo "== stop backend =="
  local pid waited=0
  pid="$(backend_pid)"
  if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
    echo "   backend is not running"
    rm -f "$PIDFILE"
    return 0
  fi
  kill -TERM "$pid" 2>/dev/null || true
  while (( waited < 30 )) && kill -0 "$pid" 2>/dev/null; do
    sleep 1
    waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
    echo "   backend was killed after 30s"
  else
    echo "   backend stopped"
  fi
  rm -f "$PIDFILE"
}

stop_container() {
  local service="$1"
  echo "== stop $service =="
  compose stop "$service"
}

host_summary() {
  local temp psi mem
  temp="$(for z in /sys/class/thermal/thermal_zone*/temp; do
            v="$(cat "$z" 2>/dev/null || echo 0)"
            case "$v" in ''|*[!0-9]*) continue ;; esac
            echo $((v / 1000))
          done | sort -n | tail -1)"
  psi="$(awk '/^some/{for(i=2;i<=NF;i++){split($i,a,"=");if(a[1]=="avg60"){print a[2]; exit}}}' /proc/pressure/cpu 2>/dev/null || echo 0)"
  mem="$(awk '/MemAvailable/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)"
  echo "   host      : ${temp:-0} C, PSI cpu ${psi:-0}%, ${mem:-0} MiB available"
}

status() {
  echo "== F11 status =="
  if container_running sgsi-zta-f11-keycloak; then
    echo "   keycloak  : running"
  else
    echo "   keycloak  : stopped"
  fi
  if container_running sgsi-zta-f11-frontend; then
    echo "   frontend  : running"
  else
    echo "   frontend  : stopped"
  fi
  local pid
  pid="$(backend_pid)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "   backend   : running (pid $pid)"
  else
    echo "   backend   : stopped"
  fi
  host_summary
}

ACTION="${1:-}"
COMPONENT="${2:-}"

case "$ACTION" in
  start|stop|status) ;;
  *)
    echo "usage: $0 start|stop|status keycloak|frontend|backend|all" >&2
    exit 2
    ;;
esac

case "$ACTION" in
  start)
    case "$COMPONENT" in
      keycloak) require_gate keycloak; start_keycloak ;;
      frontend) require_gate frontend; start_frontend ;;
      backend)  require_gate backend; start_backend ;;
      all)      require_gate all; start_keycloak; start_backend; start_frontend ;;
      *) die "unknown component '$COMPONENT'" ;;
    esac
    ;;
  stop)
    case "$COMPONENT" in
      keycloak) stop_container keycloak ;;
      frontend) stop_container frontend ;;
      backend)  stop_backend ;;
      all)      stop_backend; stop_container frontend; stop_container keycloak ;;
      *) die "unknown component '$COMPONENT'" ;;
    esac
    ;;
  status)
    status
    ;;
esac

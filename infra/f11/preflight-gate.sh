#!/usr/bin/env bash
# F11 preflight gate -- evidence-based admission control.
#
# Why this exists
# ---------------
# The previous gate refused to run whenever `load1 < 2.0`. On servidor-1
# (Intel i7-6500U, 2 physical cores / 4 threads, 15 W, ~600 tasks) load1 never
# dropped below 2.29 across a 3 h window: 0 of 181 samples were below 2.0.
# The gate therefore refused every run while the host still had measurable CPU
# headroom (47-58% busy, PSI cpu some avg60 = 20.6%, memory pressure 0.0%).
# A fixed load threshold is not portable: load counts runnable tasks and is not
# normalised by core count, so it cannot tell "busy because 600 containers have
# a heartbeat" apart from "saturated".
#
# This gate replaces it with signals that are measured, normalised and
# attributable, and it keeps every protection the old gate implied:
#   * memory               -> MemAvailable (same 3 GiB floor for e2e)
#   * host saturation      -> CPU pressure stall (PSI) + load15 / nproc
#                            (raw CPU utilisation is reported, never blocking)
#   * unexpected reboots   -> boot_id continuity against recorded state
#   * OOM events           -> oom_kill counter continuity
#   * leftover state       -> stack presence/absence per stage
#   * port conflicts       -> 8085 / 8010 / 4200 must be free before start
#   * thermal headroom     -> package temperature ceiling
#   * I/O storms           -> PSI io
#
# Stages
# ------
#   build : compile Angular. Stack must be DOWN, ports free, ~4 GiB free RAM.
#   up    : bring the stack up. Stack must be DOWN, ports free, ~3.5 GiB free.
#   e2e   : run the tests. Stack must be UP and healthy, ~3 GiB free.
#
# Usage
# -----
#   preflight-gate.sh [--stage build|up|api|e2e] [--component C] [--report] [--json] [--allow-reboot]
#
#   --component C   which component is about to start (stage "up" only):
#                   all|keycloak|backend|frontend. "backend" admits a running
#                   Keycloak, "frontend" admits a running Keycloak. The
#                   component's own port must be free and its dependencies
#                   must already be listening. Default: all.
#   --report        print the full evidence table, always exit 0
#   --json          machine readable output
#   --allow-reboot  accept a boot_id change (still refuses if a run was active)
#
# Exit codes: 0 pass (warnings allowed), 1 refuse, 2 usage error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME="${F11_RUNTIME_DIR:-/home/elcra/sgsi-zta-runtime/f11}"
STATE_DIR="$RUNTIME/state"
STATE_FILE="$STATE_DIR/preflight.env"
ACTIVE_MARKER="$STATE_DIR/run-active"

CREDENTIALS="${F11_CREDENTIALS_FILE:-$RUNTIME/credentials.json}"
SECRETS="${F11_SECRETS_FILE:-$RUNTIME/e2e-secrets.json}"

KEYCLOAK_IMAGE="${F11_KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.8.0}"
FRONTEND_IMAGE="${F11_FRONTEND_IMAGE:-sgsi-zta-f11-frontend:local}"
E2E_IMAGE="${F11_E2E_IMAGE:-sgsi-zta-f11-e2e:local}"

PORTS=(8085 8010 4200)
PROJECT_LABEL="com.sgsi-zta.project=f11"

STAGE="up"
COMPONENT="all"
MODE="enforce"
JSON=0
ALLOW_REBOOT=0

MAX_TEMP_C=0
MAX_TEMP_ZONE=""

usage() {
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage)
      [[ $# -ge 2 ]] || { echo "--stage requires a value" >&2; exit 2; }
      STAGE="$2"; shift 2 ;;
    --component)
      [[ $# -ge 2 ]] || { echo "--component requires a value" >&2; exit 2; }
      COMPONENT="$2"; shift 2 ;;
    --report)       MODE="report"; shift ;;
    --json)         JSON=1; shift ;;
    --allow-reboot) ALLOW_REBOOT=1; shift ;;
    -h|--help)      usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$STAGE" in
  build|up|api|e2e) ;;
  *) echo "invalid stage '$STAGE' (expected build|up|api|e2e)" >&2; exit 2 ;;
esac

case "$COMPONENT" in
  all|keycloak|backend|frontend) ;;
  *) echo "invalid component '$COMPONENT' (expected all|keycloak|backend|frontend)" >&2; exit 2 ;;
esac

CORES="$(nproc 2>/dev/null || echo 4)"

# ---------------------------------------------------------------------------
# thresholds (calibrated against measured servidor-1 baselines)
# ---------------------------------------------------------------------------
case "$STAGE" in
  build)
    # compiling needs headroom: ~3 GiB container + host working set
    T_CPU_WARN=75
    T_PSI_FAIL=55;   T_PSI_WARN=35
    T_PSIIO_FAIL=25; T_PSIIO_WARN=10
    T_MEM_FAIL=4096; T_MEM_WARN=5120        # MiB available
    T_TEMP_FAIL=92;  T_TEMP_WARN=84
    T_DISK_FAIL=10                          # GiB
    ;;
  up|api)
    T_CPU_WARN=70
    T_PSI_FAIL=45;   T_PSI_WARN=30
    T_PSIIO_FAIL=20; T_PSIIO_WARN=10
    T_MEM_FAIL=3584; T_MEM_WARN=4608
    T_TEMP_FAIL=88;  T_TEMP_WARN=82
    T_DISK_FAIL=8
    ;;
  e2e)
    T_CPU_WARN=70
    T_PSI_FAIL=45;   T_PSI_WARN=30
    T_PSIIO_FAIL=20; T_PSIIO_WARN=8
    T_MEM_FAIL=3072; T_MEM_WARN=4096        # same 3 GiB floor as before
    T_TEMP_FAIL=88;  T_TEMP_WARN=82
    T_DISK_FAIL=5
    ;;
esac

T_SWAP_FAIL=25    # percent of swap used
T_SWAP_WARN=10
T_SWAPOUT_FAIL=1024   # pages paged out during the 2 s sample
T_SWAPOUT_WARN=128
T_LOAD_FACTOR_FAIL=1.5   # load15 vs nproc
T_LOAD_FACTOR_WARN=1.0
T_UPTIME_FAIL=600        # seconds

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
declare -a ROWS=()
FAIL_COUNT=0
WARN_COUNT=0

record() {
  local id="$1" status="$2" value="$3" detail="$4"
  ROWS+=("${id}|${status}|${value}|${detail}")
  case "$status" in
    FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    WARN) WARN_COUNT=$((WARN_COUNT + 1)) ;;
  esac
}

gt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 > b+0)}'; }
lt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 < b+0)}'; }

meminfo_kib() {
  awk -v k="$1:" '$1==k {print $2; exit}' /proc/meminfo
}

psi_some_avg60() {
  local f="$1"
  [[ -r "$f" ]] || { echo ""; return 0; }
  awk '/^some/ {for (i=2; i<=NF; i++) {split($i, a, "="); if (a[1]=="avg60") print a[2]}}' "$f"
}

max_temp_c() {
  local z v max=0 zone=""
  for z in /sys/class/thermal/thermal_zone*/temp; do
    [[ -r "$z" ]] || continue
    v="$(cat "$z" 2>/dev/null || echo 0)"
    [[ "$v" =~ ^[0-9]+$ ]] || continue
    v=$((v / 1000))
    if (( v > max )); then
      max="$v"
      zone="$(basename "$(dirname "$z")")"
    fi
  done
  MAX_TEMP_C="$max"
  MAX_TEMP_ZONE="$zone"
}

port_busy() {
  local p="$1"
  ss -ltn 2>/dev/null | awk -v p="$p" 'NR>1 {n=split($4, a, ":"); if (a[n]==p) found=1} END {exit !found}'
}

stack_names() {
  docker ps -a --filter "label=$PROJECT_LABEL" --format '{{.Names}}' 2>/dev/null || true
}

stack_running() {
  docker ps --filter "label=$PROJECT_LABEL" --format '{{.Names}}' 2>/dev/null || true
}

unit_active() {
  systemctl is-active --quiet sgsi-zta-f11-backend 2>/dev/null
}

state_get() {
  local key="$1"
  [[ -r "$STATE_FILE" ]] || return 0
  awk -v k="$key" -F= '$1==k {print substr($0, index($0, "=") + 1); exit}' "$STATE_FILE"
}

# ---------------------------------------------------------------------------
# sample: CPU busy + swap activity over 2 s (single window for consistency)
# ---------------------------------------------------------------------------
read -r _ su1 sn1 ss1 si1 sw1 sq1 ssq1 sst1 _ < /proc/stat
tot1=$((su1 + sn1 + ss1 + si1 + sw1 + sq1 + ssq1 + sst1))
idl1=$((si1 + sw1))

swapout1="$(awk '/^pswpout/ {print $2; exit}' /proc/vmstat)"
pswpin1="$(awk '/^pswpin/ {print $2; exit}' /proc/vmstat)"

sleep 5

read -r _ su2 sn2 ss2 si2 sw2 sq2 ssq2 sst2 _ < /proc/stat
tot2=$((su2 + sn2 + ss2 + si2 + sw2 + sq2 + ssq2 + sst2))
idl2=$((si2 + sw2))

swapout2="$(awk '/^pswpout/ {print $2; exit}' /proc/vmstat)"

TOTAL_DELTA=$((tot2 - tot1))
IDLE_DELTA=$((idl2 - idl1))
if (( TOTAL_DELTA > 0 )); then
  CPU_BUSY="$(awk -v t="$TOTAL_DELTA" -v i="$IDLE_DELTA" 'BEGIN{printf "%.1f", 100*(t-i)/t}')"
else
  CPU_BUSY="0.0"
fi

SWAPOUT_DELTA=$((swapout2 - swapout1))
SWAPIN_DELTA=$(( $(awk '/^pswpin/ {print $2; exit}' /proc/vmstat) - pswpin1 ))

# ---------------------------------------------------------------------------
# 1. CPU utilisation
# ---------------------------------------------------------------------------
# Utilisation alone never blocks: a 5 s sample catches legitimate bursts and
# has no notion of whether tasks actually stalled. It is reported as evidence;
# PSI (below) and load15 normalised by cores are the blocking signals.
if gt "$CPU_BUSY" "$T_CPU_WARN"; then
  record cpu_busy WARN "${CPU_BUSY}%" "high utilisation; PSI decides admission"
else
  record cpu_busy PASS "${CPU_BUSY}%" "utilisation <= ${T_CPU_WARN}%"
fi

# ---------------------------------------------------------------------------
# 2. CPU pressure stall (PSI)
# ---------------------------------------------------------------------------
PSI_CPU="$(psi_some_avg60 /proc/pressure/cpu)"
if [[ -z "$PSI_CPU" ]]; then
  record psi_cpu SKIP "n/a" "/proc/pressure/cpu unavailable"
elif gt "$PSI_CPU" "$T_PSI_FAIL"; then
  record psi_cpu FAIL "${PSI_CPU}%" "some avg60 > ${T_PSI_FAIL}% (fail)"
elif gt "$PSI_CPU" "$T_PSI_WARN"; then
  record psi_cpu WARN "${PSI_CPU}%" "some avg60 > ${T_PSI_WARN}% (warn)"
else
  record psi_cpu PASS "${PSI_CPU}%" "some avg60 <= ${T_PSI_WARN}%"
fi

# ---------------------------------------------------------------------------
# 3. I/O pressure (stalls caused by disk)
# ---------------------------------------------------------------------------
PSI_IO="$(psi_some_avg60 /proc/pressure/io)"
if [[ -z "$PSI_IO" ]]; then
  record psi_io SKIP "n/a" "/proc/pressure/io unavailable"
elif gt "$PSI_IO" "$T_PSIIO_FAIL"; then
  record psi_io FAIL "${PSI_IO}%" "some avg60 > ${T_PSIIO_FAIL}% (fail)"
elif gt "$PSI_IO" "$T_PSIIO_WARN"; then
  record psi_io WARN "${PSI_IO}%" "some avg60 > ${T_PSIIO_WARN}% (warn)"
else
  record psi_io PASS "${PSI_IO}%" "some avg60 <= ${T_PSIIO_WARN}%"
fi

# ---------------------------------------------------------------------------
# 4. memory available
# ---------------------------------------------------------------------------
MEM_AVAIL_MIB=$(( $(meminfo_kib MemAvailable) / 1024 ))
if lt "$MEM_AVAIL_MIB" "$T_MEM_FAIL"; then
  record mem_available FAIL "${MEM_AVAIL_MIB} MiB" "< ${T_MEM_FAIL} MiB (fail)"
elif lt "$MEM_AVAIL_MIB" "$T_MEM_WARN"; then
  record mem_available WARN "${MEM_AVAIL_MIB} MiB" "< ${T_MEM_WARN} MiB (warn)"
else
  record mem_available PASS "${MEM_AVAIL_MIB} MiB" ">= ${T_MEM_WARN} MiB"
fi

# ---------------------------------------------------------------------------
# 5. swap: capacity used + active paging during the sample window
# ---------------------------------------------------------------------------
SWAP_TOTAL_KIB="$(meminfo_kib SwapTotal)"
SWAP_FREE_KIB="$(meminfo_kib SwapFree)"
if (( SWAP_TOTAL_KIB > 0 )); then
  SWAP_PCT="$(awk -v t="$SWAP_TOTAL_KIB" -v f="$SWAP_FREE_KIB" 'BEGIN{printf "%.1f", 100*(t-f)/t}')"
else
  SWAP_PCT="0.0"
fi

if gt "$SWAP_PCT" "$T_SWAP_FAIL"; then
  record swap_used FAIL "${SWAP_PCT}%" "> ${T_SWAP_FAIL}% of swap (fail)"
elif gt "$SWAP_PCT" "$T_SWAP_WARN"; then
  record swap_used WARN "${SWAP_PCT}%" "> ${T_SWAP_WARN}% of swap (warn)"
else
  record swap_used PASS "${SWAP_PCT}%" "<= ${T_SWAP_WARN}%"
fi

if gt "$SWAPOUT_DELTA" "$T_SWAPOUT_FAIL"; then
  record swap_activity FAIL "${SWAPOUT_DELTA} pg" "paging out > ${T_SWAPOUT_FAIL} pages/2s"
elif gt "$SWAPOUT_DELTA" "$T_SWAPOUT_WARN"; then
  record swap_activity WARN "${SWAPOUT_DELTA} pg" "paging out > ${T_SWAPOUT_WARN} pages/2s"
else
  record swap_activity PASS "${SWAPOUT_DELTA} pg" "paging out <= ${T_SWAPOUT_WARN} pages/2s"
fi

# ---------------------------------------------------------------------------
# 6. temperature
# ---------------------------------------------------------------------------
max_temp_c
if (( MAX_TEMP_C == 0 )); then
  record temperature SKIP "n/a" "no readable thermal zone"
elif gt "$MAX_TEMP_C" "$T_TEMP_FAIL"; then
  record temperature FAIL "${MAX_TEMP_C} C" "${MAX_TEMP_ZONE} > ${T_TEMP_FAIL} C (fail)"
elif gt "$MAX_TEMP_C" "$T_TEMP_WARN"; then
  record temperature WARN "${MAX_TEMP_C} C" "${MAX_TEMP_ZONE} > ${T_TEMP_WARN} C (warn)"
else
  record temperature PASS "${MAX_TEMP_C} C" "${MAX_TEMP_ZONE} <= ${T_TEMP_WARN} C"
fi

# ---------------------------------------------------------------------------
# 7. load, normalised by core count (not an absolute number)
# ---------------------------------------------------------------------------
read -r LOAD1 LOAD5 LOAD15 _ < /proc/loadavg
LOAD_FAIL="$(awk -v c="$CORES" -v f="$T_LOAD_FACTOR_FAIL" 'BEGIN{printf "%.2f", c*f}')"
LOAD_WARN="$(awk -v c="$CORES" -v f="$T_LOAD_FACTOR_WARN" 'BEGIN{printf "%.2f", c*f}')"

if gt "$LOAD15" "$LOAD_FAIL"; then
  record load_saturation FAIL "l15 ${LOAD15}" "load15 > ${LOAD_FAIL} (${T_LOAD_FACTOR_FAIL}x${CORES})"
elif gt "$LOAD15" "$LOAD_WARN"; then
  record load_saturation WARN "l15 ${LOAD15}" "load15 > ${LOAD_WARN} (${T_LOAD_FACTOR_WARN}x${CORES})"
else
  record load_saturation PASS "l15 ${LOAD15}" "load15 <= ${LOAD_WARN}"
fi

# rising fast: a spike, not steady state
if gt "$LOAD1" "$(awk -v l="$LOAD15" 'BEGIN{printf "%.2f", l*1.8}')" && gt "$LOAD1" "$CORES"; then
  record load_trend FAIL "l1 ${LOAD1} vs l15 ${LOAD15}" "load rising sharply"
else
  record load_trend PASS "l1 ${LOAD1} vs l15 ${LOAD15}" "no sharp rise"
fi

# ---------------------------------------------------------------------------
# 8. host stability: uptime, boot continuity, OOM, unexpected reboots
# ---------------------------------------------------------------------------
UPTIME_S="$(cut -d. -f1 /proc/uptime)"
if lt "$UPTIME_S" "$T_UPTIME_FAIL"; then
  record uptime FAIL "${UPTIME_S}s" "host booted < ${T_UPTIME_FAIL}s ago"
else
  record uptime PASS "${UPTIME_S}s" "stable since boot"
fi

CUR_BOOT="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)"
PREV_BOOT="$(state_get boot_id)"
if [[ -z "$PREV_BOOT" ]]; then
  record reboot PASS "first run" "boot_id recorded"
elif [[ "$PREV_BOOT" == "$CUR_BOOT" ]]; then
  record reboot PASS "same boot" "no reboot since last gate run"
elif [[ -f "$ACTIVE_MARKER" ]]; then
  record reboot FAIL "boot changed" "host rebooted while an F11 run was marked active"
elif (( ALLOW_REBOOT == 1 )); then
  record reboot WARN "boot changed" "accepted via --allow-reboot"
else
  record reboot FAIL "boot changed" "unexpected reboot since last run (use --allow-reboot)"
fi

# A marker left behind means a previous run died without running its trap
# (SIGKILL, OOM, session drop). Never silently reuse that state.
if [[ -f "$ACTIVE_MARKER" ]]; then
  MARK_BOOT="$(cat "$ACTIVE_MARKER" 2>/dev/null || true)"
  if [[ "$MARK_BOOT" == "$CUR_BOOT" ]]; then
    record run_marker FAIL "stale" "previous run left an active marker; inspect then remove $ACTIVE_MARKER"
  fi
fi

CUR_OOM="$(awk '/^oom_kill/ {print $2; exit}' /proc/vmstat)"
PREV_OOM="$(state_get oom_kill)"
if [[ -z "$PREV_OOM" ]]; then
  record oom_kill PASS "${CUR_OOM} total" "counter recorded"
elif (( CUR_OOM > PREV_OOM )); then
  record oom_kill FAIL "$((CUR_OOM - PREV_OOM)) new" "OOM killer fired since last run"
else
  record oom_kill PASS "${CUR_OOM} total" "no new OOM kills"
fi

# ---------------------------------------------------------------------------
# 9. ports
# ---------------------------------------------------------------------------
if [[ "$STAGE" == "e2e" || "$STAGE" == "api" ]]; then
  # The api stage exercises the backend only: the frontend is not required.
  if [[ "$STAGE" == "api" ]]; then
    NEED_PORTS=(8085 8010)
  else
    NEED_PORTS=(8085 8010 4200)
  fi
  missing=""
  for p in "${NEED_PORTS[@]}"; do
    if ! port_busy "$p"; then missing="${missing} ${p}"; fi
  done
  if [[ -n "$missing" ]]; then
    record ports FAIL "not listening:${missing}" "stack should be running but nothing listens on${missing}"
  else
    record ports PASS "listening" "${NEED_PORTS[*]} are listening"
  fi
else
  # Component-aware expectations. The component's own port must be free and
  # the ports it depends on must already be listening.
  case "$COMPONENT" in
    backend)  FREE_PORTS=(8010 4200); LISTEN_PORTS=(8085) ;;
    frontend) FREE_PORTS=(4200);     LISTEN_PORTS=(8085 8010) ;;
    *)        FREE_PORTS=(8085 8010 4200); LISTEN_PORTS=() ;;
  esac
  conflict=""
  for p in "${FREE_PORTS[@]}"; do
    if port_busy "$p"; then conflict="${conflict} ${p}"; fi
  done
  absent=""
  for p in "${LISTEN_PORTS[@]}"; do
    if ! port_busy "$p"; then absent="${absent} ${p}"; fi
  done
  if [[ -n "$conflict" ]]; then
    record ports FAIL "busy:${conflict}" "ports must be free before start"
  elif [[ -n "$absent" ]]; then
    record ports FAIL "not listening:${absent}" "dependencies must already be running"
  else
    record ports PASS "ready" "free:${FREE_PORTS[*]} listening:${LISTEN_PORTS[*]:-none}"
  fi
fi

# ---------------------------------------------------------------------------
# 10. stack state
# ---------------------------------------------------------------------------
RUNNING_NAMES="$(stack_running)"
ALL_NAMES="$(stack_names)"
BACKEND_ACTIVE=0
if unit_active; then BACKEND_ACTIVE=1; fi
# The backend may run as a host process instead of the (not installed) unit.
if (( BACKEND_ACTIVE == 0 )) && port_busy 8010; then BACKEND_ACTIVE=1; fi

if [[ "$STAGE" == "e2e" || "$STAGE" == "api" ]]; then
  missing=""
  if ! grep -q 'sgsi-zta-f11-keycloak' <<<"$RUNNING_NAMES"; then missing="${missing} keycloak"; fi
  if [[ "$STAGE" == "e2e" ]] && ! grep -q 'sgsi-zta-f11-frontend' <<<"$RUNNING_NAMES"; then missing="${missing} frontend"; fi
  if (( BACKEND_ACTIVE == 0 )); then missing="${missing} backend"; fi
  if [[ -n "$missing" ]]; then
    record stack FAIL "not up" "missing:${missing}"
  else
    if [[ "$STAGE" == "e2e" ]]; then
      record stack PASS "up" "keycloak + frontend + backend active"
    else
      record stack PASS "up" "keycloak + backend active (frontend not required)"
    fi
  fi
  # a container that restarted on its own is a failed run, not a fresh one
  restarted=""
  while IFS= read -r n; do
    [[ -n "$n" ]] || continue
    rc="$(docker inspect --format '{{.RestartCount}}' "$n" 2>/dev/null || echo 0)"
    [[ "$rc" =~ ^[0-9]+$ ]] || continue
    if (( rc > 0 )); then restarted="${restarted} ${n}(${rc})"; fi
  done <<<"$ALL_NAMES"
  if [[ -n "$restarted" ]]; then
    record restarts FAIL "restarted:${restarted}" "unexpected restarts must be investigated"
  else
    record restarts PASS "none" "no container restarts"
  fi
else
  # Component-aware: only the dependencies of the component about to start may
  # be running, and the component itself must not be running yet.
  want_keycloak=0
  want_backend=0
  case "$COMPONENT" in
    backend)  want_keycloak=1 ;;
    frontend) want_keycloak=1; want_backend=1 ;;
  esac
  unexpected=""
  # Only running containers matter: an exited container of the component
  # about to start is recreated by compose, not a conflicting state.
  for n in $RUNNING_NAMES; do
    if [[ "$n" != "sgsi-zta-f11-keycloak" ]] || (( want_keycloak == 0 )); then
      unexpected="${unexpected} ${n}"
    fi
  done
  if (( want_keycloak == 1 )) && ! grep -q 'sgsi-zta-f11-keycloak' <<<"$RUNNING_NAMES"; then
    unexpected="${unexpected} keycloak(missing)"
  fi
  if (( want_backend == 1 )); then
    if (( BACKEND_ACTIVE == 0 )); then unexpected="${unexpected} backend(missing)"; fi
  elif (( BACKEND_ACTIVE == 1 )); then
    unexpected="${unexpected} backend(active)"
  fi
  if [[ -n "$unexpected" ]]; then
    record stack FAIL "present" "unexpected state for component '$COMPONENT':${unexpected}"
  else
    record stack PASS "ready" "component '$COMPONENT' can start"
  fi
fi

# ---------------------------------------------------------------------------
# 11. disk
# ---------------------------------------------------------------------------
DISK_GIB="$(df -Pk "$ROOT" | awk 'NR==2 {printf "%d", $4/1048576}')"
if lt "$DISK_GIB" "$T_DISK_FAIL"; then
  record disk_free FAIL "${DISK_GIB} GiB" "< ${T_DISK_FAIL} GiB"
else
  record disk_free PASS "${DISK_GIB} GiB" ">= ${T_DISK_FAIL} GiB"
fi

# ---------------------------------------------------------------------------
# 12. stage-specific prerequisites
# ---------------------------------------------------------------------------
if [[ "$STAGE" == "e2e" || "$STAGE" == "api" ]]; then
  # The api stage needs the realm credentials to mint tokens. The e2e stage
  # additionally needs the IoMT device secrets and the Playwright image.
  MISSING_INPUT=""
  if [[ "$STAGE" == "e2e" ]]; then
    for f in "$CREDENTIALS" "$SECRETS"; do
      [[ -r "$f" ]] || MISSING_INPUT="${MISSING_INPUT} ${f}"
    done
  else
    [[ -r "$CREDENTIALS" ]] || MISSING_INPUT="${MISSING_INPUT} ${CREDENTIALS}"
  fi
  if [[ -n "$MISSING_INPUT" ]]; then
    record inputs FAIL "missing" "unreadable:${MISSING_INPUT}"
  else
    if python3 - "$CREDENTIALS" "$SECRETS" "$STAGE" >/dev/null 2>&1 <<'PY'
import json, sys
stage = sys.argv[3]
c = json.load(open(sys.argv[1], encoding="utf-8"))
need_c = {"issuer", "realm", "clientId", "redirectUri", "users"}
if need_c - set(c):
    raise SystemExit(1)
users = c["users"]
if stage == "api":
    required = ("recepcion.test", "laboratorio.test", "medico.test",
                "medico.sinmfa", "auditor.test")
else:
    required = ("recepcion.test", "medico.test")
for user in required:
    if user not in users:
        raise SystemExit(1)
if stage == "api":
    # the API suite computes current TOTP codes from this secret
    if not users["medico.test"].get("totp_secret"):
        raise SystemExit(1)
else:
    s = json.load(open(sys.argv[2], encoding="utf-8"))
    if {"iomtDeviceId", "iomtDeviceKey"} - set(s):
        raise SystemExit(1)
PY
    then
      record inputs PASS "schema ok" "credentials readable and shaped correctly"
    else
      record inputs FAIL "schema" "credentials.json has an unexpected shape"
    fi
  fi

  MISSING_IMG=""
  if [[ "$STAGE" == "e2e" ]]; then
    for img in "$KEYCLOAK_IMAGE" "$FRONTEND_IMAGE" "$E2E_IMAGE"; do
      docker image inspect "$img" >/dev/null 2>&1 || MISSING_IMG="${MISSING_IMG} ${img}"
    done
  else
    for img in "$KEYCLOAK_IMAGE" "$FRONTEND_IMAGE"; do
      docker image inspect "$img" >/dev/null 2>&1 || MISSING_IMG="${MISSING_IMG} ${img}"
    done
  fi
  if [[ -n "$MISSING_IMG" ]]; then
    record images FAIL "missing" "build stages first:${MISSING_IMG}"
  else
    record images PASS "present" "keycloak + frontend images present"
  fi
fi

# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------
if (( FAIL_COUNT > 0 )); then
  RESULT="FAIL"
elif (( WARN_COUNT > 0 )); then
  RESULT="PASS_WITH_WARNINGS"
else
  RESULT="PASS"
fi

if (( JSON == 1 )); then
  esc() { printf '%s' "$1" | tr -d '"\\' ; }
  printf '{"stage":"%s","cores":%s,"result":"%s","failures":%s,"warnings":%s,"checks":[' \
    "$(esc "$STAGE")" "$CORES" "$RESULT" "$FAIL_COUNT" "$WARN_COUNT"
  first=1
  for row in "${ROWS[@]}"; do
    IFS='|' read -r id status value detail <<<"$row"
    (( first )) || printf ','
    first=0
    printf '{"id":"%s","status":"%s","value":"%s","detail":"%s"}' \
      "$(esc "$id")" "$(esc "$status")" "$(esc "$value")" "$(esc "$detail")"
  done
  printf ']}\n'
else
  echo "F11 preflight gate -- stage=${STAGE} result=${RESULT}"
  echo "host: ${CORES} logical CPUs | $(uname -sr) | $(date -Is)"
  echo
  printf '%-15s %-6s %-22s %s\n' "CHECK" "STATE" "VALUE" "NOTE"
  printf '%-15s %-6s %-22s %s\n' "---------------" "------" "----------------------" "-----------------------------"
  for row in "${ROWS[@]}"; do
    IFS='|' read -r id status value detail <<<"$row"
    printf '%-15s %-6s %-22s %s\n' "$id" "$status" "$value" "$detail"
  done
  echo
  if (( FAIL_COUNT > 0 )); then
    echo "RESULT: REFUSED -- ${FAIL_COUNT} blocking check(s), ${WARN_COUNT} warning(s)"
  elif (( WARN_COUNT > 0 )); then
    echo "RESULT: ALLOWED with ${WARN_COUNT} warning(s)"
  else
    echo "RESULT: ALLOWED -- all checks passed"
  fi
fi

# ---------------------------------------------------------------------------
# persist state for reboot / OOM continuity
# ---------------------------------------------------------------------------
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR" 2>/dev/null || true
(
  umask 077
  {
    echo "boot_id=${CUR_BOOT}"
    echo "oom_kill=${CUR_OOM}"
    echo "last_run_epoch=$(date +%s)"
    echo "last_stage=${STAGE}"
    echo "last_result=${RESULT}"
  } > "$STATE_FILE"
)

if (( FAIL_COUNT > 0 )) && [[ "$MODE" == "enforce" ]]; then
  exit 1
fi
exit 0
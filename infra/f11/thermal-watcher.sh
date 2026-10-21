#!/usr/bin/env bash
# Thermal window watcher for the F11 stack.
#
# What it does
# ------------
# It watches the host for a genuinely quiet thermal window and RECORDS that it
# found one. It never builds anything, never starts or stops a service, and
# never changes a limit. It only reads /sys and /proc, and writes to its own
# log and marker file.
#
# A window is N continuous minutes where BOTH hold:
#   * the CPU package temperature is at or below --temp-max (default 76 C)
#   * the host CPU utilisation is at or below --busy-max (default 25 %)
#
# The criterion is deliberately strict. Three isolated samples are not a
# window: the streak is reset by any single sample that breaks either
# condition, so only an uninterrupted stretch counts.
#
# Exit codes
#   0  a window was detected
#   1  the run ended without a window
#   2  usage error
#
# Usage
#   thermal-watcher.sh [--minutes N] [--interval S] [--temp-max C]
#                      [--busy-max PCT] [--timeout S] [--log FILE]
#                      [--marker FILE] [--notify-cmd CMD] [--simulate FILE]
#
# The --simulate option replays a CSV of "ts,temp,busy" samples instead of
# reading the host. It exists to test the streak logic without loading the
# machine.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME="${F11_RUNTIME_DIR:-/home/elcra/sgsi-zta-runtime/f11}"

MINUTES=3
INTERVAL=10
TEMP_MAX=76
BUSY_MAX=25
TIMEOUT=0
ZONE=""
LOG="$RUNTIME/thermal-watcher.csv"
MARKER="$RUNTIME/thermal-window.marker"
NOTIFY_CMD=""
SIMULATE=""

usage() { sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --minutes)    [[ $# -ge 2 ]] || { echo "--minutes requires a value" >&2; exit 2; }; MINUTES="$2"; shift 2 ;;
    --interval)   [[ $# -ge 2 ]] || { echo "--interval requires a value" >&2; exit 2; }; INTERVAL="$2"; shift 2 ;;
    --temp-max)   [[ $# -ge 2 ]] || { echo "--temp-max requires a value" >&2; exit 2; }; TEMP_MAX="$2"; shift 2 ;;
    --busy-max)   [[ $# -ge 2 ]] || { echo "--busy-max requires a value" >&2; exit 2; }; BUSY_MAX="$2"; shift 2 ;;
    --timeout)    [[ $# -ge 2 ]] || { echo "--timeout requires a value" >&2; exit 2; }; TIMEOUT="$2"; shift 2 ;;
    --log)        [[ $# -ge 2 ]] || { echo "--log requires a value" >&2; exit 2; }; LOG="$2"; shift 2 ;;
    --marker)     [[ $# -ge 2 ]] || { echo "--marker requires a value" >&2; exit 2; }; MARKER="$2"; shift 2 ;;
    --notify-cmd) [[ $# -ge 2 ]] || { echo "--notify-cmd requires a value" >&2; exit 2; }; NOTIFY_CMD="$2"; shift 2 ;;
    --simulate)   [[ $# -ge 2 ]] || { echo "--simulate requires a value" >&2; exit 2; }; SIMULATE="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

mkdir -p "$(dirname "$LOG")" "$(dirname "$MARKER")"

find_zone() {
  local z
  for z in /sys/class/thermal/thermal_zone*; do
    [[ -e "$z/type" && -e "$z/temp" ]] || continue
    if [[ "$(cat "$z/type" 2>/dev/null)" == "x86_pkg_temp" ]]; then
      echo "$z"
      return 0
    fi
  done
  return 1
}

if [[ -z "$ZONE" ]]; then
  ZONE="$(find_zone)" || {
    echo "error: no thermal zone of type x86_pkg_temp found on this host" >&2
    exit 2
  }
fi

read_temp() {
  local raw
  raw="$(cat "$ZONE/temp" 2>/dev/null || echo 0)"
  case "$raw" in ''|*[!0-9]*) echo 0; return ;; esac
  echo $((raw / 1000))
}

read_psi60() {
  awk '/^some/{for(i=2;i<=NF;i++){split($i,a,"=");if(a[1]=="avg60"){print a[2]; exit}}}' /proc/pressure/cpu 2>/dev/null || echo 0
}

read_load1() { cut -d' ' -f1 /proc/loadavg 2>/dev/null || echo 0; }

read_mem_mib() { awk '/MemAvailable/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0; }

# CPU utilisation from /proc/stat deltas: the honest measure of work done,
# independent of the reported frequency, which is demand driven on this host.
CPU_PREV_TOTAL=0
CPU_PREV_IDLE=0
CPU_BUSY_PCT=""
# The function keeps its state in globals, so it must NOT be called inside a
# command substitution: a subshell would swallow the update and the reading
# would never progress. It publishes the result in CPU_BUSY_PCT instead.
cpu_busy() {
  local total idle dt
  read -r total idle < <(awk '/^cpu /{t=0; i=0; for(n=2;n<=NF;n++){t+=$n; if(n==5||n==6)i+=$n} print t, i; exit}' /proc/stat) || true
  if [[ -z "${total:-}" ]]; then CPU_BUSY_PCT=""; return; fi
  if (( CPU_PREV_TOTAL == 0 )); then
    CPU_PREV_TOTAL="$total"; CPU_PREV_IDLE="$idle"
    CPU_BUSY_PCT=""
    return
  fi
  # Both deltas must be taken BEFORE the globals are overwritten, otherwise the
  # idle delta is always zero and the reading collapses to 100 %.
  dt=$((total - CPU_PREV_TOTAL))
  idle_delta=$((idle - CPU_PREV_IDLE))
  CPU_PREV_TOTAL="$total"; CPU_PREV_IDLE="$idle"
  if (( dt <= 0 )); then CPU_BUSY_PCT="0.0"; return; fi
  CPU_BUSY_PCT="$(awk -v d="$dt" -v i="$idle_delta" 'BEGIN{printf "%.1f", (1 - i/d) * 100}')"
}

echo "Thermal window watcher (read only; it never builds and never touches a service)"
echo "  criterion : ${MINUTES} continuous minutes with package temp <= ${TEMP_MAX} C and cpu busy <= ${BUSY_MAX} %"
echo "  zone      : $ZONE (x86_pkg_temp)"
echo "  interval  : ${INTERVAL}s"
echo "  log       : $LOG"
echo "  marker    : $MARKER"
[[ -n "$TIMEOUT" ]] && echo "  timeout   : ${TIMEOUT}s"
[[ -n "$SIMULATE" ]] && echo "  simulate  : $SIMULATE"
echo

if [[ ! -f "$LOG" ]]; then
  echo "ts,temp_c,cpu_busy_pct,psi60,load1,mem_mib,streak_s,qualifies" > "$LOG"
fi

REQUIRED_S=$((MINUTES * 60))
SIM_ROW=0
STREAK=0
BEST_STREAK=0
DEADLINE=0
if (( TIMEOUT > 0 )); then DEADLINE=$(( $(date +%s) + TIMEOUT )); fi

while true; do
  ts="$(date +%H:%M:%S)"
  if [[ -n "$SIMULATE" ]]; then
    line="$(sed -n "$((SIM_ROW + 1))p" "$SIMULATE")"
    [[ -z "$line" ]] && break
    IFS=, read -r _sim_ts sim_temp sim_busy <<<"$line"
    ts="${_sim_ts:-$ts}"
    temp="$sim_temp"
    busy="$sim_busy"
    psi60="sim"
    load1="sim"
    mem="sim"
    SIM_ROW=$((SIM_ROW + 1))
  else
    temp="$(read_temp)"
    cpu_busy
    busy="$CPU_BUSY_PCT"
    psi60="$(read_psi60)"
    load1="$(read_load1)"
    mem="$(read_mem_mib)"
  fi

  qualifies=0
  if [[ -n "$busy" ]] && (( temp <= TEMP_MAX )) && awk -v b="$busy" -v m="$BUSY_MAX" 'BEGIN{exit !(b<=m)}'; then
    qualifies=1
  fi

  if (( qualifies == 1 )); then
    STREAK=$((STREAK + INTERVAL))
  else
    STREAK=0
  fi
  (( STREAK > BEST_STREAK )) && BEST_STREAK="$STREAK"

  echo "$ts,$temp,$busy,$psi60,$load1,$mem,$STREAK,$qualifies" >> "$LOG"

  if (( STREAK >= REQUIRED_S )); then
    {
      echo "thermal window detected"
      echo "detected_at: $(date --iso-8601=seconds 2>/dev/null || date)"
      echo "criterion: ${MINUTES} continuous minutes with package temp <= ${TEMP_MAX} C and cpu busy <= ${BUSY_MAX} %"
      echo "zone: $ZONE"
      echo "streak_seconds: $STREAK"
      echo "last_sample: ts=$ts temp_c=$temp cpu_busy_pct=$busy psi60=$psi60 load1=$load1 mem_mib=$mem"
      echo "note: this watcher does not authorise or start any build."
    } > "$MARKER"
    echo "== VENTANA TERMICA DETECTADA =="
    echo "   ${STREAK}s continuos con paquete <= ${TEMP_MAX} C y cpu busy <= ${BUSY_MAX} %"
    echo "   evidencia: $LOG"
    echo "   marcador : $MARKER"
    echo "   este watcher NO compila nada: la decision de compilar es del operador."
    if [[ -n "$NOTIFY_CMD" ]]; then
      bash -c "$NOTIFY_CMD" >/dev/null 2>&1 || true
    fi
    exit 0
  fi

  if [[ -n "$SIMULATE" ]]; then
    continue
  fi
  if (( DEADLINE > 0 && $(date +%s) >= DEADLINE )); then
    break
  fi
  sleep "$INTERVAL"
done

echo "No se detecto ninguna ventana termica en esta ejecucion."
echo "  mejor racha continua observada: ${BEST_STREAK}s (se necesitan ${REQUIRED_S}s)"
echo "  evidencia: $LOG"
exit 1

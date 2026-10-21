#!/usr/bin/env bash
# Supervised execution wrapper for F11 heavy steps.
#
# Why a file and not variables
# ----------------------------
# A monitor started with `monitor &` runs in a subshell. Any variable it
# assigns (max temperature, peak PSI, minimum memory) is local to that subshell
# and is lost when it exits, so the parent always read the initial values.
# Peaks are written to a summary file on every sample and read back by the
# parent after `wait`.
#
# Abort scope
# -----------
# On a threshold breach or on SIGINT/SIGTERM the wrapper stops, in order:
#   1. containers carrying the supervised build label
#   2. the F11 BuildKit builder named by --builder (container + buildx node)
#   3. the supervised command
#
# The builder stop is deliberately narrow. It only ever resolves
# buildx_buildkit_<name>0 for the explicit --builder value, and it refuses any
# name that does not start with --builder-prefix (default: sgsi-zta-f11). It
# never enumerates buildkit containers, never touches `default`, and never
# calls `docker buildx rm` without a name. Other builders on the host, such as
# Coolify's, are out of reach by construction.
#
# Usage
#   build-monitor.sh [options] -- <command> [args...]
#
#   --temp-fail N       abort when temperature >= N C for 3 consecutive samples (default 88)
#   --psi-fail N        abort when PSI cpu some avg60 > N % (default 75)
#   --mem-fail N        abort when MemAvailable < N MiB (default 1024)
#   --interval N        sampling period in seconds (default 5)
#   --label L           docker label used to kill an in-flight build container
#                       (default com.sgsi-zta.component=f11-build)
#   --builder NAME      F11 BuildKit builder to force-stop on abort
#   --builder-prefix P  safety allowlist for --builder (default sgsi-zta-f11)
#   --report-only       never abort, only measure
#
# Exit codes: the command's own status, 90 if a threshold aborted the run,
# 130/143 if interrupted by SIGINT/SIGTERM, 2 on usage error.
set -uo pipefail

TEMP_FAIL=88
PSI_FAIL=75
MEM_FAIL=1024
INTERVAL=5
LABEL="com.sgsi-zta.component=f11-build"
BUILDER=""
BUILDER_PREFIX="sgsi-zta-f11"
REPORT_ONLY=0
SUMMARY="${F11_MONITOR_SUMMARY:-/tmp/f11-monitor-summary.env}"
LOG="${F11_MONITOR_LOG:-/tmp/f11-monitor.log}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --temp-fail) [[ $# -ge 2 ]] || { echo "--temp-fail needs a value" >&2; exit 2; }; TEMP_FAIL="$2"; shift 2 ;;
    --psi-fail)  [[ $# -ge 2 ]] || { echo "--psi-fail needs a value" >&2; exit 2; };  PSI_FAIL="$2";  shift 2 ;;
    --mem-fail)  [[ $# -ge 2 ]] || { echo "--mem-fail needs a value" >&2; exit 2; };  MEM_FAIL="$2";  shift 2 ;;
    --interval)  [[ $# -ge 2 ]] || { echo "--interval needs a value" >&2; exit 2; };  INTERVAL="$2";  shift 2 ;;
    --label)     [[ $# -ge 2 ]] || { echo "--label needs a value" >&2; exit 2; };     LABEL="$2";     shift 2 ;;
    --builder)   [[ $# -ge 2 ]] || { echo "--builder needs a value" >&2; exit 2; };   BUILDER="$2";   shift 2 ;;
    --builder-prefix) [[ $# -ge 2 ]] || { echo "--builder-prefix needs a value" >&2; exit 2; }; BUILDER_PREFIX="$2"; shift 2 ;;
    --report-only) REPORT_ONLY=1; shift ;;
    --) shift; break ;;
    -h|--help) sed -n '2,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ $# -gt 0 ]] || { echo "no command given (use: -- <command>)" >&2; exit 2; }

if [[ -n "$BUILDER" ]]; then
  if [[ "$BUILDER" == "default" ]]; then
    echo "refusing to supervise 'default': it is not an F11 builder" >&2
    exit 2
  fi
  if [[ "$BUILDER" != "$BUILDER_PREFIX"* ]]; then
    echo "refusing builder '$BUILDER': name does not start with '$BUILDER_PREFIX'" >&2
    exit 2
  fi
fi

read_temp() {
  local z v max=0
  for z in /sys/class/thermal/thermal_zone*/temp; do
    [[ -r "$z" ]] || continue
    v="$(cat "$z" 2>/dev/null || echo 0)"
    case "$v" in ''|*[!0-9]*) continue ;; esac
    v=$((v / 1000))
    [[ "$v" -gt "$max" ]] && max="$v"
  done
  echo "$max"
}

read_psi()  { awk '/^some/{for(i=2;i<=NF;i++){split($i,a,"=");if(a[1]=="avg60"){print a[2]; exit}}}' /proc/pressure/cpu 2>/dev/null || echo 0; }
read_mem()  { awk '/MemAvailable/{printf "%d", $2/1024}' /proc/meminfo; }
read_load() { cut -d' ' -f1 /proc/loadavg; }
read_oom()  { awk '/^oom_kill/{print $2; exit}' /proc/vmstat; }

OOM_START="$(read_oom)"
: > "$LOG"
: > "$SUMMARY"
SAMPLES=0
MT=0
MP=0
MM=99999999
ML=0
BREACH=""
CHILD=""
MON=""

write_summary() {
  {
    echo "samples=$SAMPLES"
    echo "max_temp=$MT"
    echo "max_psi=$MP"
    echo "min_mem=$MM"
    echo "max_load=$ML"
    echo "oom_start=$OOM_START"
    echo "oom_end=$(read_oom)"
    echo "breach=$BREACH"
  } > "$SUMMARY.tmp" && mv "$SUMMARY.tmp" "$SUMMARY"
}

stop_builder() {
  [[ -z "$BUILDER" ]] && return 0
  # Defence in depth: never touch anything outside the F11 prefix.
  case "$BUILDER" in
    "$BUILDER_PREFIX"*) ;;
    *) echo "refusing to stop builder '$BUILDER' (outside $BUILDER_PREFIX*)" >> "$LOG"; return 0 ;;
  esac
  local ctr="buildx_buildkit_${BUILDER}0"
  if docker inspect "$ctr" >/dev/null 2>&1; then
    docker rm -f "$ctr" >> "$LOG" 2>&1 && echo "stopped builder container $ctr" >> "$LOG"
  fi
  if docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
    docker buildx rm "$BUILDER" >> "$LOG" 2>&1 && echo "removed buildx node $BUILDER" >> "$LOG"
  fi
}

stop_stack() {
  local ids
  ids="$(docker ps -q --filter "label=$LABEL" 2>/dev/null)"
  if [[ -n "$ids" ]]; then
    # shellcheck disable=SC2086
    docker kill $ids >> "$LOG" 2>&1 || true
  fi
  stop_builder
  [[ -n "$CHILD" ]] && kill -TERM "$CHILD" 2>/dev/null
}

on_signal() {
  local sig="$1"
  BREACH="interrupted_${sig}"
  write_summary
  stop_stack
  [[ -n "$MON" ]] && kill -TERM "$MON" 2>/dev/null
  echo "INTERRUPTED by SIG${sig}" >> "$LOG"
  case "$sig" in
    INT) exit 130 ;;
    *)   exit 143 ;;
  esac
}

trap 'on_signal INT' INT
trap 'on_signal TERM' TERM

monitor() {
  local hot=0 t p m l o
  while kill -0 "$CHILD" 2>/dev/null; do
    t="$(read_temp)"; p="$(read_psi)"; m="$(read_mem)"; l="$(read_load)"; o="$(read_oom)"
    SAMPLES=$((SAMPLES + 1))
    [[ "$t" -gt "$MT" ]] && MT="$t"
    awk -v a="$p" -v b="$MP" 'BEGIN{exit !(a>b)}' && MP="$p"
    [[ "$m" -lt "$MM" ]] && MM="$m"
    awk -v a="$l" -v b="$ML" 'BEGIN{exit !(a>b)}' && ML="$l"
    printf '%s temp=%sC psi60=%s%% mem=%sMiB load1=%s oom=%s\n' \
      "$(date +%H:%M:%S)" "$t" "$p" "$m" "$l" "$o" >> "$LOG"

    if [[ "$t" -ge "$TEMP_FAIL" ]]; then hot=$((hot + 1)); else hot=0; fi
    if (( hot >= 3 )); then BREACH="temp_sustained_${t}C"; fi
    if awk -v p="$p" -v lim="$PSI_FAIL" 'BEGIN{exit !(p>lim)}'; then BREACH="psi_cpu_${p}pct"; fi
    if [[ "$m" -lt "$MEM_FAIL" ]]; then BREACH="mem_low_${m}MiB"; fi
    if [[ "$o" -gt "$OOM_START" ]]; then BREACH="oom_kill"; fi

    write_summary

    if [[ -n "$BREACH" && "$REPORT_ONLY" -eq 0 ]]; then
      printf 'BREACH %s -> aborting\n' "$BREACH" >> "$LOG"
      stop_stack
      break
    fi
    sleep "$INTERVAL"
  done
  local t p m l
  t="$(read_temp)"; p="$(read_psi)"; m="$(read_mem)"; l="$(read_load)"
  [[ "$t" -gt "$MT" ]] && MT="$t"
  awk -v a="$p" -v b="$MP" 'BEGIN{exit !(a>b)}' && MP="$p"
  [[ "$m" -lt "$MM" ]] && MM="$m"
  awk -v a="$l" -v b="$ML" 'BEGIN{exit !(a>b)}' && ML="$l"
  write_summary
}

started="$(date +%s)"
"$@" &
CHILD=$!

monitor & MON=$!
wait "$CHILD"; rc=$?
wait "$MON" 2>/dev/null
elapsed=$(( $(date +%s) - started ))

# shellcheck disable=SC1090
[[ -r "$SUMMARY" ]] && . "$SUMMARY"

echo
echo "=========== SUPERVISION ==========="
printf 'command rc=%s  elapsed=%ss  samples=%s\n' "$rc" "$elapsed" "${samples:-0}"
printf 'max_temp=%sC  max_psi60=%s%%  min_mem=%sMiB  max_load1=%s\n' \
  "${max_temp:-0}" "${max_psi:-0}" "${min_mem:-0}" "${max_load:-0}"
printf 'oom start=%s end=%s  breach=%s\n' \
  "${oom_start:-0}" "${oom_end:-0}" "${breach:-none}"
[[ -n "$BUILDER" ]] && printf 'builder watched=%s\n' "$BUILDER"
echo "log: $LOG"

if [[ -n "${breach:-}" ]]; then
  exit 90
fi
exit "$rc"
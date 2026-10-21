#!/usr/bin/env bash
# Supervised execution wrapper for F11 heavy steps.
#
# Why a file and not variables
# ----------------------------
# A monitor started with `monitor &` runs in a subshell. Any variable it
# assigns (max temperature, peak PSI, minimum memory) is local to that subshell
# and is lost when it exits, so the parent always read the initial values. The
# earlier ad-hoc monitor reported max_temp=0 / max_psi=0 / min_mem=99999999
# exactly because of this. Peaks are now written to a summary file on every
# sample and read back by the parent after `wait`.
#
# Usage
#   build-monitor.sh [options] -- <command> [args...]
#
#   --temp-fail N   abort when temperature >= N C for 3 consecutive samples (default 88)
#   --psi-fail N    abort when PSI cpu some avg60 > N % (default 75)
#   --mem-fail N    abort when MemAvailable < N MiB (default 1024)
#   --interval N    sampling period in seconds (default 5)
#   --label L       docker label used to kill an in-flight build container
#                   (default com.sgsi-zta.component=f11-build)
#   --report-only   never abort, only measure
#
# Exit codes: the command's own status, 90 if a threshold aborted the run,
# 2 on usage error.
set -uo pipefail

TEMP_FAIL=88
PSI_FAIL=75
MEM_FAIL=1024
INTERVAL=5
LABEL="com.sgsi-zta.component=f11-build"
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
    --report-only) REPORT_ONLY=1; shift ;;
    --) shift; break ;;
    -h|--help) sed -n '2,31p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ $# -gt 0 ]] || { echo "no command given (use: -- <command>)" >&2; exit 2; }

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
      ids="$(docker ps -q --filter "label=$LABEL" 2>/dev/null)"
      [[ -n "$ids" ]] && docker kill $ids >> "$LOG" 2>&1
      kill -TERM "$CHILD" 2>/dev/null
      break
    fi
    sleep "$INTERVAL"
  done
  # final sample so a short run still reports something
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
echo "log: $LOG"

if [[ -n "${breach:-}" ]]; then
  exit 90
fi
exit "$rc"
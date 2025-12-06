#!/bin/bash
set -euo pipefail

OUTPUT_DIR=${1:-./fuzzer-dir/out-dir}
INTERVAL=${INTERVAL:-0}

print_status() {
    local any=0
    printf "%-12s %-6s %-8s %-10s %-10s %-10s %-10s %-10s %-10s\n" "instance" "exec/s" "stability" "paths" "favored" "pend" "density" "crashes" "hangs"
    for stats in "${OUTPUT_DIR}"/*/fuzzer_stats; do
        [[ -f "$stats" ]] || continue
        any=1
        inst=$(basename "$(dirname "$stats")")
        execs_per_sec=$(grep -m1 '^execs_per_sec' "$stats" | awk '{print $3}')
        stability=$(grep -m1 '^stability' "$stats" | awk '{print $3"%"}')
        paths_total=$(grep -m1 '^paths_total' "$stats" | awk '{print $3}')
        paths_favored=$(grep -m1 '^paths_favored' "$stats" | awk '{print $3}')
        pending_total=$(grep -m1 '^pending_total' "$stats" | awk '{print $3}')
        map_density=$(grep -m1 '^bitmap_cvg' "$stats" | awk '{print $3}')
        crashes=$(grep -m1 '^unique_crashes' "$stats" | awk '{print $3}')
        hangs=$(grep -m1 '^unique_hangs' "$stats" | awk '{print $3}')
        printf "%-12s %-6s %-8s %-10s %-10s %-10s %-10s %-10s %-10s\n" "$inst" "$execs_per_sec" "$stability" "$paths_total" "$paths_favored" "$pending_total" "$map_density" "$crashes" "$hangs"
    done
    if [[ $any -eq 0 ]]; then
        echo "[!] No fuzzer_stats found under ${OUTPUT_DIR}"
    fi
}

if [[ ${INTERVAL} -le 0 ]]; then
    print_status
else
    while true; do
        clear
        date
        print_status
        sleep "${INTERVAL}"
    done
fi

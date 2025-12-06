#!/bin/bash
set -euo pipefail

OUTPUT_DIR=${1:-./fuzzer-dir/out-dir}
HTTPD_BIN=${HTTPD_BIN:-/usr/local/apache_asan/bin/httpd}
CONF_FILE=${CONF_FILE:-./fuzzer-dir/conf/default.conf}
RESULTS_DIR=${RESULTS_DIR:-./triage-results}
TIMEOUT=${TIMEOUT:-5}

if [[ ! -x "${HTTPD_BIN}" ]]; then
    echo "[!] ASan-enabled httpd not found at ${HTTPD_BIN}. Set HTTPD_BIN to a valid binary." >&2
    exit 1
fi

mkdir -p "${RESULTS_DIR}" "${RESULTS_DIR}/logs"

declare -A seen
shopt -s nullglob
CRASH_FILES=($(find "${OUTPUT_DIR}" -type f -path "*/crashes/id:*" ! -name "*.state" 2>/dev/null))
HANG_FILES=($(find "${OUTPUT_DIR}" -type f -path "*/hangs/id:*" ! -name "*.state" 2>/dev/null))

if [[ ${#CRASH_FILES[@]} -eq 0 && ${#HANG_FILES[@]} -eq 0 ]]; then
    echo "[+] No crashes or hangs found under ${OUTPUT_DIR}"
    exit 0
fi

echo "[*] Found ${#CRASH_FILES[@]} crashes and ${#HANG_FILES[@]} hangs"

process_sample() {
    local sample="$1" type="$2"
    local base="$(basename "$sample")"
    local log_file="${RESULTS_DIR}/logs/${base}.log"

    echo "[+] Replaying ${type}: ${base}"
    set +e
    ASAN_OPTIONS=symbolize=1:abort_on_error=1:detect_leaks=0 \
        timeout "${TIMEOUT}" "${HTTPD_BIN}" -X -f "${CONF_FILE}" <"${sample}" >"${log_file}" 2>&1
    status=$?
    set -e

    signature="exit-${status}"
    if grep -m1 -E 'SUMMARY:|ERROR: AddressSanitizer' "${log_file}" >/dev/null; then
        signature=$(grep -m1 -E 'SUMMARY:|ERROR: AddressSanitizer' "${log_file}" | head -n1 | sed 's/ /_/g' | cut -c1-120)
    elif grep -m1 -E 'signal|Segmentation fault' "${log_file}" >/dev/null; then
        signature=$(grep -m1 -E 'signal|Segmentation fault' "${log_file}" | head -n1 | sed 's/ /_/g' | cut -c1-120)
    fi

    if [[ -z "${signature}" ]]; then
        signature="exit-${status}"
    fi

    if [[ -n "${seen["${signature}"]+x}" ]]; then
        echo "    [-] Duplicate signature ${signature}, skipping"
        return
    fi

    seen["${signature}"]=1
    dest_dir="${RESULTS_DIR}/${signature}"
    mkdir -p "${dest_dir}"
    cp "${sample}" "${dest_dir}/sample"
    cp "${log_file}" "${dest_dir}/asan.log"
    echo "    [+] Saved unique ${type} to ${dest_dir}"
}

for c in "${CRASH_FILES[@]}"; do
    process_sample "$c" crash
done

for h in "${HANG_FILES[@]}"; do
    process_sample "$h" hang
done

echo "[+] Triage complete. Results in ${RESULTS_DIR}"

#!/bin/bash
set -euo pipefail

# Run fuzzer
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
HTTPD_BIN=${HTTPD_BIN:-/usr/local/apache2/bin/httpd}
CONF_FILE=${CONF_FILE:-${SCRIPT_DIR}/conf/default.conf}
DICTIONARY=${DICTIONARY:-${SCRIPT_DIR}/dict/http_request_fuzzer.dict.txt}
INPUT_DIR=${INPUT_DIR:-${SCRIPT_DIR}/input-cases/}
OUTPUT_DIR=${OUTPUT_DIR:-${SCRIPT_DIR}/out-dir}

export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/apache2/lib/:${LD_LIBRARY_PATH:-}

AFL_MAP_SIZE=262144 \
AFL_SKIP_CPUFREQ=1 \
SHOW_HOOKS=1 \
ASAN_OPTIONS=detect_leaks=0,abort_on_error=1,symbolize=0,debug=true,check_initialization_order=true,detect_stack_use_after_return=true,strict_string_checks=true,detect_invalid_pointer_pairs=2 \
AFL_DISABLE_TRIM=1 \
afl-fuzz \
    -p explore \
    -t 2000 \
    -m none \
    -i "${INPUT_DIR}" \
    -o "${OUTPUT_DIR}" \
    -x "${DICTIONARY}" \
    -- "${HTTPD_BIN}" -X -f "${CONF_FILE}"

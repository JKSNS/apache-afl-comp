#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
INPUT_DIR=${INPUT_DIR:-${SCRIPT_DIR}/input-cases/}
OUTPUT_DIR=${OUTPUT_DIR:-${SCRIPT_DIR}/out-dir}
DICTIONARY=${DICTIONARY:-${SCRIPT_DIR}/dict/http_request_fuzzer.dict.txt}
CONF_FILE=${CONF_FILE:-${SCRIPT_DIR}/conf/default.conf}
USE_SCREEN=${USE_SCREEN:-0}
MODE=""
SECONDARIES=${SECONDARIES:-4}
FUZZ_ROOT=/tmp/httpd-fuzz-root

# Ensure the fuzz root exists and is writable by the daemon user
mkdir -p "${FUZZ_ROOT}/logs" "${FUZZ_ROOT}/htdocs"
if [[ ! -f "${FUZZ_ROOT}/htdocs/index.html" ]]; then
    echo "AFL httpd fuzz target" >"${FUZZ_ROOT}/htdocs/index.html"
fi
# Fix permissions so Apache (User daemon) can access this
chown -R daemon:daemon "${FUZZ_ROOT}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE=${2:-}; shift 2 ;;
        --secondaries|-s) SECONDARIES=${2:-0}; shift 2 ;;
        --screen) USE_SCREEN=1; shift ;;
        --no-screen) USE_SCREEN=0; shift ;;
        --output) OUTPUT_DIR=${2:-${OUTPUT_DIR}}; shift 2 ;;
        --input) INPUT_DIR=${2:-${INPUT_DIR}}; shift 2 ;;
        *) echo "[!] Unknown arg: $1"; exit 1 ;;
    esac
done

# Define binary paths and their specific library paths
HTTPD_ASAN=/usr/local/apache_asan/bin/httpd
LIB_ASAN="/usr/local/apache_asan/apr/lib:/usr/local/apache_asan/apr-util/lib:/usr/local/apache_asan/pcre2/lib:/usr/local/apache_asan/expat/lib"

HTTPD_CMPLOG=/usr/local/apache_cmplog/bin/httpd
LIB_CMPLOG="/usr/local/apache_cmplog/apr/lib:/usr/local/apache_cmplog/apr-util/lib:/usr/local/apache_cmplog/pcre2/lib:/usr/local/apache_cmplog/expat/lib"

HTTPD_PLAIN=/usr/local/apache_plain/bin/httpd
LIB_PLAIN="/usr/local/apache_plain/apr/lib:/usr/local/apache_plain/apr-util/lib:/usr/local/apache_plain/pcre2/lib:/usr/local/apache_plain/expat/lib"

HTTPD_COMPCOV=/usr/local/apache_compcov/bin/httpd
LIB_COMPCOV="/usr/local/apache_compcov/apr/lib:/usr/local/apache_compcov/apr-util/lib:/usr/local/apache_compcov/pcre2/lib:/usr/local/apache_compcov/expat/lib"

AVAILABLE_BUILDS=()
[[ -x "$HTTPD_ASAN" ]] && AVAILABLE_BUILDS+=("asan")
[[ -x "$HTTPD_CMPLOG" ]] && AVAILABLE_BUILDS+=("cmplog")
[[ -x "$HTTPD_PLAIN" ]] && AVAILABLE_BUILDS+=("plain")
[[ -x "$HTTPD_COMPCOV" ]] && AVAILABLE_BUILDS+=("compcov")

if [[ ${#AVAILABLE_BUILDS[@]} -eq 0 ]]; then
    echo "[!] No Apache builds found."
    exit 1
fi

if [[ -z "$MODE" ]]; then
    if [[ " ${AVAILABLE_BUILDS[*]} " =~ " plain " ]]; then MODE=plain;
    elif [[ " ${AVAILABLE_BUILDS[*]} " =~ " asan " ]]; then MODE=asan;
    else MODE=${AVAILABLE_BUILDS[0]}; fi
fi

export AFL_MAP_SIZE=262144
export AFL_SKIP_CPUFREQ=1
export AFL_DISABLE_TRIM=1
export AFL_AUTORESUME=1
# Suppress ASan warnings
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0:allocator_may_return_null=1

pkill -9 afl-fuzz 2>/dev/null || true
sleep 1

start_session() {
    local name="$1"; shift
    local cmd="$*"
    if [[ ${USE_SCREEN} -eq 1 ]]; then
        screen -dmS "${name}" bash -c "${cmd}"
    else
        nohup bash -c "${cmd}" >"${FUZZ_ROOT}/logs/${name}.log" 2>&1 &
    fi
}

build_cmd() {
    local is_master="$1"; shift
    local name="$1"; shift
    local bin="$1"; shift
    local lib_path="$1"; shift
    local strategy="$1"; shift
    local helper_bin="$2" # Optional

    local env_prefix="LD_LIBRARY_PATH=${lib_path} "
    local args="-t 2000+ -m none -i '${INPUT_DIR}' -o '${OUTPUT_DIR}'"
    
    # Master specific args
    if [[ "$is_master" == "1" ]]; then
        args="${args} -M master -x '${DICTIONARY}' AFL_FINAL_SYNC=1"
        if [[ -n "$helper_bin" ]]; then
            args="${args} -c '${helper_bin}'"
        fi
    else
        args="${args} -S ${name} -p ${strategy}"
    fi

    echo "${env_prefix} afl-fuzz ${args} -- '${bin}' -X -f '${CONF_FILE}'"
}

# Select Master
MASTER_BIN=""
MASTER_LIB=""
CMPLOG_BIN=""
case "$MODE" in
    cmplog)
        MASTER_BIN="$HTTPD_PLAIN"; MASTER_LIB="$LIB_PLAIN"; CMPLOG_BIN="$HTTPD_CMPLOG"
        [[ ! -x "$HTTPD_PLAIN" ]] && { MASTER_BIN="$HTTPD_CMPLOG"; MASTER_LIB="$LIB_CMPLOG"; }
        ;;
    plain) MASTER_BIN="$HTTPD_PLAIN"; MASTER_LIB="$LIB_PLAIN" ;;
    compcov) MASTER_BIN="$HTTPD_COMPCOV"; MASTER_LIB="$LIB_COMPCOV" ;;
    asan) MASTER_BIN="$HTTPD_ASAN"; MASTER_LIB="$LIB_ASAN" ;;
esac

echo "[*] Starting master (${MODE})..."
start_session "afl-master" "$(build_cmd 1 "master" "$MASTER_BIN" "$MASTER_LIB" "deterministic" "$CMPLOG_BIN")"

# Start Slaves
SLAVE_COUNT=0
declare -a SLAVE_TARGETS=()
[[ -x "$HTTPD_ASAN" ]] && SLAVE_TARGETS+=("asan")
[[ -x "$HTTPD_PLAIN" ]] && SLAVE_TARGETS+=("plain")
[[ -x "$HTTPD_CMPLOG" ]] && SLAVE_TARGETS+=("cmplog")
[[ -x "$HTTPD_COMPCOV" ]] && SLAVE_TARGETS+=("compcov")

if [[ ${SECONDARIES} -gt 0 && ${#SLAVE_TARGETS[@]} -gt 0 ]]; then
    for i in $(seq 1 ${SECONDARIES}); do
        target_index=$(( (i - 1) % ${#SLAVE_TARGETS[@]} ))
        target="${SLAVE_TARGETS[$target_index]}"
        SLAVE_COUNT=$((SLAVE_COUNT + 1))
        name="slave${SLAVE_COUNT}"
        
        case "$target" in
            asan)    start_session "afl-${name}" "$(build_cmd 0 "$name" "$HTTPD_ASAN" "$LIB_ASAN" "exploit")" ;;
            plain)   start_session "afl-${name}" "$(build_cmd 0 "$name" "$HTTPD_PLAIN" "$LIB_PLAIN" "fast")" ;;
            cmplog)  start_session "afl-${name}" "$(build_cmd 0 "$name" "$HTTPD_CMPLOG" "$LIB_CMPLOG" "explore")" ;;
            compcov) start_session "afl-${name}" "$(build_cmd 0 "$name" "$HTTPD_COMPCOV" "$LIB_COMPCOV" "coe")" ;;
        esac
        echo "[*] Started ${target} slave: ${name}"
        sleep 1
    done
fi

echo ""
if [[ ${USE_SCREEN} -eq 0 ]]; then
    echo "[+] Fuzzing has started. Master log is tailing below."
    echo "[+] Press Ctrl+C to stop."
    sleep 2
    # Determine which log file to tail
    tail -f "${FUZZ_ROOT}/logs/afl-master.log"
fi

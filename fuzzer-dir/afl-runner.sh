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

# Point to the specific dependency folders where the toolchain installed them
PREFIX="/usr/local/apache_plain"
export LD_LIBRARY_PATH="${PREFIX}/apr/lib:${PREFIX}/apr-util/lib:${PREFIX}/pcre2/lib:${PREFIX}/expat/lib:${LD_LIBRARY_PATH:-}"

mkdir -p "${FUZZ_ROOT}/logs" "${FUZZ_ROOT}/htdocs"
if [[ ! -f "${FUZZ_ROOT}/htdocs/index.html" ]]; then
    echo "AFL httpd fuzz target" >"${FUZZ_ROOT}/htdocs/index.html"
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            MODE=${2:-}
            shift 2
            ;;
        --secondaries|-s|--secondaires)
            SECONDARIES=${2:-0}
            shift 2
            ;;
        --screen)
            USE_SCREEN=1
            shift
            ;;
        --no-screen)
            USE_SCREEN=0
            shift
            ;;
        --output)
            OUTPUT_DIR=${2:-${OUTPUT_DIR}}
            shift 2
            ;;
        --input)
            INPUT_DIR=${2:-${INPUT_DIR}}
            shift 2
            ;;
        --conf)
            CONF_FILE=${2:-${CONF_FILE}}
            shift 2
            ;;
        --dict)
            DICTIONARY=${2:-${DICTIONARY}}
            shift 2
            ;;
        *)
            echo "[!] Unknown argument: $1"
            echo "    Supported: --mode (asan|cmplog|compcov|plain), --secondaries N, --screen, --no-screen, --output DIR, --input DIR, --conf FILE, --dict FILE"
            exit 1
            ;;
    esac
done

HTTPD_ASAN=/usr/local/apache_asan/bin/httpd
HTTPD_CMPLOG=/usr/local/apache_cmplog/bin/httpd
HTTPD_PLAIN=/usr/local/apache_plain/bin/httpd
HTTPD_COMPCOV=/usr/local/apache_compcov/bin/httpd

# Detect available binaries
AVAILABLE_BUILDS=()
[[ -x "$HTTPD_ASAN" ]] && AVAILABLE_BUILDS+=("asan")
[[ -x "$HTTPD_CMPLOG" ]] && AVAILABLE_BUILDS+=("cmplog")
[[ -x "$HTTPD_PLAIN" ]] && AVAILABLE_BUILDS+=("plain")
[[ -x "$HTTPD_COMPCOV" ]] && AVAILABLE_BUILDS+=("compcov")

if [[ ${#AVAILABLE_BUILDS[@]} -eq 0 ]]; then
    echo "[!] No Apache builds found. Run afl-toolchain.sh first."
    exit 1
fi

echo "[*] Available builds: ${AVAILABLE_BUILDS[*]}"

if [[ ${USE_SCREEN} -eq 1 ]] && ! command -v screen >/dev/null 2>&1; then
    echo "[!] screen is not installed. Re-run with USE_SCREEN=0 or install it (apt-get install screen)."
    exit 1
fi

if [[ -n "$MODE" ]]; then
    if [[ ! " ${AVAILABLE_BUILDS[*]} " =~ " ${MODE} " ]]; then
        echo "[!] Requested mode '${MODE}' is not available. Built modes: ${AVAILABLE_BUILDS[*]}"
        exit 1
    fi
else
    # Auto-select preference
    if [[ " ${AVAILABLE_BUILDS[*]} " =~ " plain " ]]; then
        MODE=plain
    elif [[ " ${AVAILABLE_BUILDS[*]} " =~ " asan " ]]; then
        MODE=asan
    else
        MODE=${AVAILABLE_BUILDS[0]}
    fi
fi

# Tunables for stability
export AFL_MAP_SIZE=262144
export AFL_SKIP_CPUFREQ=1
export AFL_DISABLE_TRIM=1
export AFL_AUTORESUME=1
# Force ASan to be less whiny during startup
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0:allocator_may_return_null=1

# Kill existing AFL instances
pkill -9 afl-fuzz 2>/dev/null || true
sleep 1

start_session() {
    local name="$1"; shift
    local cmd="$*"

    if [[ ${USE_SCREEN} -eq 1 ]]; then
        screen -dmS "${name}" bash -c "${cmd}"
        SESSIONS+=("${name}")
    else
        nohup bash -c "${cmd}" >"${FUZZ_ROOT}/logs/${name}.log" 2>&1 &
    fi
}

build_master_cmd() {
    local target_bin="$1"; shift
    local cmp_target="$1"; shift
    local env_prefix="$1"; shift

    local extra_cmp=""
    if [[ -n "$cmp_target" ]]; then
        extra_cmp="-c ${cmp_target}"
    fi

    echo "${env_prefix} AFL_FINAL_SYNC=1 afl-fuzz -M master ${extra_cmp} -t 2000+ -m none -i '${INPUT_DIR}' -o '${OUTPUT_DIR}' -x '${DICTIONARY}' -- '${target_bin}' -X -f '${CONF_FILE}'"
}

build_slave_cmd() {
    local name="$1"; shift
    local target_bin="$1"; shift
    local env_prefix="$1"; shift
    local strategy="$1"; shift

    echo "${env_prefix} afl-fuzz -S ${name} -p ${strategy} -t 2000+ -m none -i '${INPUT_DIR}' -o '${OUTPUT_DIR}' -- '${target_bin}' -X -f '${CONF_FILE}'"
}

MASTER_BIN=""
CMPLOG_HELPER=""
MASTER_ENV=""
MASTER_CMD=""

case "$MODE" in
    cmplog)
        if [[ -x "$HTTPD_PLAIN" && -x "$HTTPD_CMPLOG" ]]; then
            MASTER_BIN="$HTTPD_PLAIN"
            CMPLOG_HELPER="$HTTPD_CMPLOG"
        elif [[ -x "$HTTPD_CMPLOG" ]]; then
            MASTER_BIN="$HTTPD_CMPLOG"
        elif [[ -x "$HTTPD_PLAIN" ]]; then
            MASTER_BIN="$HTTPD_PLAIN"
        fi
        ;;
    plain)
        MASTER_BIN="$HTTPD_PLAIN"
        ;;
    compcov)
        MASTER_BIN="$HTTPD_COMPCOV"
        ;;
    asan)
        MASTER_BIN="$HTTPD_ASAN"
        ;;
esac

if [[ -z "$MASTER_BIN" || ! -x "$MASTER_BIN" ]]; then
    echo "[!] No binary available for mode '${MODE}'. Built modes: ${AVAILABLE_BUILDS[*]}"
    exit 1
fi

echo "[*] Selected mode: ${MODE}"

MASTER_CMD=$(build_master_cmd "${MASTER_BIN}" "${CMPLOG_HELPER}" "${MASTER_ENV}")

SESSIONS=()
SLAVE_COUNT=0

declare -a SLAVE_TARGETS=()
if [[ -x "$HTTPD_ASAN" ]]; then SLAVE_TARGETS+=("asan"); fi
if [[ -x "$HTTPD_PLAIN" ]]; then SLAVE_TARGETS+=("plain"); fi
if [[ -x "$HTTPD_CMPLOG" ]]; then SLAVE_TARGETS+=("cmplog"); fi
if [[ -x "$HTTPD_COMPCOV" ]]; then SLAVE_TARGETS+=("compcov"); fi

if [[ ${SECONDARIES} -gt 0 && ${#SLAVE_TARGETS[@]} -gt 0 ]]; then
    for i in $(seq 1 ${SECONDARIES}); do
        target_index=$(( (i - 1) % ${#SLAVE_TARGETS[@]} ))
        target="${SLAVE_TARGETS[$target_index]}"
        SLAVE_COUNT=$((SLAVE_COUNT + 1))
        name="slave${SLAVE_COUNT}"
        
        env_prefix=""
        strategy="fast"
        bin=""

        case "$target" in
            asan)
                strategy="exploit"
                bin="$HTTPD_ASAN"
                ;;
            plain)
                strategy="fast"
                bin="$HTTPD_PLAIN"
                ;;
            cmplog)
                strategy="explore"
                bin="$HTTPD_CMPLOG"
                ;;
            compcov)
                strategy="coe"
                bin="$HTTPD_COMPCOV"
                ;;
        esac

        if [[ ! -x "$bin" ]]; then
            continue
        fi

        echo "[*] Starting ${target} ${name}..."
        start_session "afl-${name}" "$(build_slave_cmd "${name}" "${bin}" "${env_prefix}" "${strategy}")"
        sleep 1
    done
fi

echo "[*] Starting master with $(basename "${MASTER_BIN}")${CMPLOG_HELPER:+ (+cmplog helper)}..."
if [[ ${USE_SCREEN} -eq 1 ]]; then
    start_session "afl-master" "${MASTER_CMD}"
else
    echo ""
    echo "[+] Attaching master..."
    echo ""
fi

sleep 1

echo "[+] Started $((SLAVE_COUNT + 1)) AFL instances"
echo "[+] Master: using $(basename "${MASTER_BIN}")"
echo "[+] Output: ${OUTPUT_DIR}"
echo ""
if [[ ${USE_SCREEN} -eq 1 ]]; then
    echo "Monitor with:"
    echo "  screen -r afl-master    # View master"
    echo "  screen -ls              # List all"
else
    echo "Master is running in the foreground. Use Ctrl+C to stop it."
    echo "Slave logs (if any) are under ${FUZZ_ROOT}/logs/*.log"
fi
echo "  afl-whatsup ${OUTPUT_DIR}  # Summary"
echo ""
echo "Stop all with:"
echo "  pkill -9 afl-fuzz"

echo ""
if [[ ${USE_SCREEN} -eq 0 ]]; then
    exec bash -c "${MASTER_CMD}"
fi

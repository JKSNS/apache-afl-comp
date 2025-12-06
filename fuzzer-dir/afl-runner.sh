#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
INPUT_DIR=${INPUT_DIR:-${SCRIPT_DIR}/input-cases/}
OUTPUT_DIR=${OUTPUT_DIR:-${SCRIPT_DIR}/out-dir}
DICTIONARY=${DICTIONARY:-${SCRIPT_DIR}/dict/http_request_fuzzer.dict.txt}
CONF_FILE=${CONF_FILE:-${SCRIPT_DIR}/conf/default.conf}

# Binaries
HTTPD_ASAN=/usr/local/apache_asan/bin/httpd
HTTPD_CMPLOG=/usr/local/apache_cmplog/bin/httpd
HTTPD_PLAIN=/usr/local/apache_plain/bin/httpd

# Detect available binaries
AVAILABLE_BUILDS=()
[[ -x "$HTTPD_ASAN" ]] && AVAILABLE_BUILDS+=("asan")
[[ -x "$HTTPD_CMPLOG" ]] && AVAILABLE_BUILDS+=("cmplog")
[[ -x "$HTTPD_PLAIN" ]] && AVAILABLE_BUILDS+=("plain")

if [[ ${#AVAILABLE_BUILDS[@]} -eq 0 ]]; then
    echo "[!] No Apache builds found. Run afl-toolchain.sh first:"
    echo "    BUILD_TYPE=asan ./afl-toolchain.sh"
    echo "    BUILD_TYPE=cmplog ./afl-toolchain.sh"
    echo "    BUILD_TYPE=plain ./afl-toolchain.sh"
    exit 1
fi

echo "[*] Available builds: ${AVAILABLE_BUILDS[*]}"

export AFL_MAP_SIZE=262144
export AFL_SKIP_CPUFREQ=1
export AFL_DISABLE_TRIM=1
export AFL_AUTORESUME=1

# Kill existing AFL instances
pkill -9 afl-fuzz 2>/dev/null || true
sleep 1

# Master instance
if [[ -x "$HTTPD_CMPLOG" && -x "$HTTPD_PLAIN" ]]; then
    echo "[*] Starting master with CMPLOG..."
    screen -dmS afl-master bash -c "
        AFL_FINAL_SYNC=1 \
        AFL_CMPLOG_ONLY_NEW=1 \
        afl-fuzz \
            -M master \
            -c ${HTTPD_CMPLOG} \
            -t 2000+ \
            -m none \
            -i '${INPUT_DIR}' \
            -o '${OUTPUT_DIR}' \
            -x '${DICTIONARY}' \
            -- '${HTTPD_PLAIN}' -X -f '${CONF_FILE}'
    "
    MASTER_BIN="$HTTPD_PLAIN"
elif [[ -x "$HTTPD_PLAIN" ]]; then
    echo "[*] Starting master (plain build)..."
    screen -dmS afl-master bash -c "
        AFL_FINAL_SYNC=1 \
        afl-fuzz \
            -M master \
            -t 2000+ \
            -m none \
            -i '${INPUT_DIR}' \
            -o '${OUTPUT_DIR}' \
            -x '${DICTIONARY}' \
            -- '${HTTPD_PLAIN}' -X -f '${CONF_FILE}'
    "
    MASTER_BIN="$HTTPD_PLAIN"
else
    echo "[*] Starting master (ASAN build)..."
    screen -dmS afl-master bash -c "
        ASAN_OPTIONS=detect_leaks=0,abort_on_error=1,symbolize=0 \
        AFL_FINAL_SYNC=1 \
        afl-fuzz \
            -M master \
            -t 2000+ \
            -m none \
            -i '${INPUT_DIR}' \
            -o '${OUTPUT_DIR}' \
            -x '${DICTIONARY}' \
            -- '${HTTPD_ASAN}' -X -f '${CONF_FILE}'
    "
    MASTER_BIN="$HTTPD_ASAN"
fi

sleep 2

# Launch slave instances
SLAVE_COUNT=0

# ASAN slaves (2-3 instances)
if [[ -x "$HTTPD_ASAN" ]]; then
    for i in {1..3}; do
        SLAVE_COUNT=$((SLAVE_COUNT + 1))
        echo "[*] Starting ASAN slave${SLAVE_COUNT}..."
        screen -dmS afl-slave${SLAVE_COUNT} bash -c "
            ASAN_OPTIONS=detect_leaks=0,abort_on_error=1,symbolize=0 \
            afl-fuzz \
                -S slave${SLAVE_COUNT} \
                -p exploit \
                -t 2000+ \
                -m none \
                -i '${INPUT_DIR}' \
                -o '${OUTPUT_DIR}' \
                -- '${HTTPD_ASAN}' -X -f '${CONF_FILE}'
        "
        sleep 1
    done
fi

# Plain slaves (fast exploration)
if [[ -x "$HTTPD_PLAIN" ]]; then
    for i in {1..4}; do
        SLAVE_COUNT=$((SLAVE_COUNT + 1))
        echo "[*] Starting plain slave${SLAVE_COUNT}..."
        screen -dmS afl-slave${SLAVE_COUNT} bash -c "
            afl-fuzz \
                -S slave${SLAVE_COUNT} \
                -p fast \
                -t 2000+ \
                -m none \
                -i '${INPUT_DIR}' \
                -o '${OUTPUT_DIR}' \
                -x '${DICTIONARY}' \
                -- '${HTTPD_PLAIN}' -X -f '${CONF_FILE}'
        "
        sleep 1
    done
fi

echo ""
echo "[+] Started $((SLAVE_COUNT + 1)) AFL instances"
echo "[+] Master: using $(basename $MASTER_BIN)"
echo "[+] Output: ${OUTPUT_DIR}"
echo ""
echo "Monitor with:"
echo "  screen -r afl-master    # View master"
echo "  screen -ls              # List all"
echo "  afl-whatsup ${OUTPUT_DIR}  # Summary"
echo ""
echo "Stop all with:"
echo "  pkill -9 afl-fuzz"

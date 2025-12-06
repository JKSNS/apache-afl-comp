#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
INPUT_DIR=${INPUT_DIR:-${SCRIPT_DIR}/input-cases/}
OUTPUT_DIR=${OUTPUT_DIR:-${SCRIPT_DIR}/out-dir}
DICTIONARY=${DICTIONARY:-${SCRIPT_DIR}/dict/http_request_fuzzer.dict.txt}

# Binaries
HTTPD_ASAN=/usr/local/apache_asan/bin/httpd
HTTPD_CMPLOG=/usr/local/apache_cmplog/bin/httpd
HTTPD_PLAIN=/usr/local/apache_plain/bin/httpd

CONF_FILE=${CONF_FILE:-${SCRIPT_DIR}/conf/default.conf}

export AFL_MAP_SIZE=262144
export AFL_SKIP_CPUFREQ=1
export AFL_DISABLE_TRIM=1
export AFL_AUTORESUME=1

# Master instance with CMPLOG
AFL_FINAL_SYNC=1 \
screen -dmS afl-master bash -c "
    AFL_CMPLOG_ONLY_NEW=1 \
    afl-fuzz \
        -M master \
        -c ${HTTPD_CMPLOG} \
        -t 2000 \
        -m none \
        -i '${INPUT_DIR}' \
        -o '${OUTPUT_DIR}' \
        -x '${DICTIONARY}' \
        -- '${HTTPD_PLAIN}' -X -f '${CONF_FILE}'
"

sleep 2

# Secondary instances with ASAN
for i in {1..3}; do
    screen -dmS afl-slave${i} bash -c "
        ASAN_OPTIONS=detect_leaks=0,abort_on_error=1,symbolize=0 \
        afl-fuzz \
            -S slave${i} \
            -p exploit \
            -t 2000 \
            -m none \
            -i '${INPUT_DIR}' \
            -o '${OUTPUT_DIR}' \
            -- '${HTTPD_ASAN}' -X -f '${CONF_FILE}'
    "
    sleep 1
done

# Fast secondary instances (plain build)
for i in {4..7}; do
    screen -dmS afl-slave${i} bash -c "
        afl-fuzz \
            -S slave${i} \
            -p fast \
            -t 2000 \
            -m none \
            -i '${INPUT_DIR}' \
            -o '${OUTPUT_DIR}' \
            -x '${DICTIONARY}' \
            -- '${HTTPD_PLAIN}' -X -f '${CONF_FILE}'
    "
    sleep 1
done

echo "[+] Started 8 AFL instances (1 master + 7 slaves)"
echo "[+] Master: CMPLOG for comparison tracking"
echo "[+] Slaves 1-3: ASAN for vulnerability detection"
echo "[+] Slaves 4-7: Fast exploration"
echo ""
echo "Monitor with: screen -r afl-master"
echo "List all: screen -ls"

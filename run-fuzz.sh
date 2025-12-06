#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DEFAULT_BASE="${SCRIPT_DIR}/fuzzer-dir"
INPUT_DIR=${INPUT_DIR:-${DEFAULT_BASE}/input-cases}
OUTPUT_DIR=${OUTPUT_DIR:-${DEFAULT_BASE}/out-dir}
CONF_FILE=${CONF_FILE:-${DEFAULT_BASE}/conf/default.conf}
DICTIONARY_DEFAULT="${DEFAULT_BASE}/dict/http_request_fuzzer.dict.txt"
DICTIONARY=${DICTIONARY:-${DICTIONARY_DEFAULT}}

MODE=asan
SECONDARIES=0
DETERMINISTIC=0
RELAXED_VAR=0
MASTER_NAME=m00
TIMEOUT_MS=2000
MEM_LIMIT=none
POWER=explore

usage() {
    cat <<USAGE
Usage: $0 [options]
  --mode <asan|cmplog|compcov|plain>   Build variant to run (default: asan)
  --secondaries <N>                    Number of secondary fuzzers to launch (default: 0)
  --input-dir <path>                   Seed corpus directory (default: $INPUT_DIR)
  --output-dir <path>                  AFL++ output directory (default: $OUTPUT_DIR)
  --dictionary <path>                  Optional AFL++ dictionary
  --conf <path>                        Apache config file (default: $CONF_FILE)
  --deterministic                      Enable deterministic stage (-D)
  --relaxed-variance                   Enable AFL_FAST_CAL=1 and AFL_NO_VAR_CHECK=1
  --power <explore|fast|exploit>       AFL++ power schedule (default: explore)
  --timeout-ms <ms>                    AFL++ -t timeout (default: 2000)
  --mem-limit <val>                    AFL++ -m memory limit (default: none)
  -h|--help                            Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE=$2; shift 2 ;;
        --secondaries) SECONDARIES=$2; shift 2 ;;
        --input-dir) INPUT_DIR=$2; shift 2 ;;
        --output-dir) OUTPUT_DIR=$2; shift 2 ;;
        --dictionary) DICTIONARY=$2; shift 2 ;;
        --conf) CONF_FILE=$2; shift 2 ;;
        --deterministic) DETERMINISTIC=1; shift ;;
        --relaxed-variance) RELAXED_VAR=1; shift ;;
        --power) POWER=$2; shift 2 ;;
        --timeout-ms) TIMEOUT_MS=$2; shift 2 ;;
        --mem-limit) MEM_LIMIT=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[!] Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ ! -d "${INPUT_DIR}" ]]; then
    echo "[!] Input directory not found: ${INPUT_DIR}" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}" "${DEFAULT_BASE}/logs"
LOG_DIR="${DEFAULT_BASE}/logs"
FUZZ_ROOT=/tmp/httpd-fuzz-root
mkdir -p "${FUZZ_ROOT}/logs" "${FUZZ_ROOT}/htdocs"
if [[ ! -f "${FUZZ_ROOT}/htdocs/index.html" ]]; then
    echo "AFL httpd fuzz target" >"${FUZZ_ROOT}/htdocs/index.html"
fi

HTTPD_ASAN=/usr/local/apache_asan/bin/httpd
HTTPD_CMPLOG=/usr/local/apache_cmplog/bin/httpd
HTTPD_COMPCOV=/usr/local/apache_compcov/bin/httpd
HTTPD_PLAIN=/usr/local/apache_plain/bin/httpd

get_target_for_mode() {
    case "$1" in
        asan) echo "${HTTPD_ASAN}" ;;
        cmplog) echo "${HTTPD_PLAIN}" ;;
        compcov) echo "${HTTPD_COMPCOV}" ;;
        plain) echo "${HTTPD_PLAIN}" ;;
        *) echo "" ;;
    esac
}

TARGET_BIN=$(get_target_for_mode "${MODE}")

if [[ -z "${TARGET_BIN}" || ! -x "${TARGET_BIN}" ]]; then
    echo "[!] Target binary for mode '${MODE}' not found. Build it with BUILD_TYPE=${MODE} ./afl-toolchain.sh" >&2
    exit 1
fi

if [[ "${MODE}" == "cmplog" && ! -x "${HTTPD_CMPLOG}" ]]; then
    echo "[!] CMPLOG mode requires both plain and cmplog builds. Please run BUILD_TYPE=cmplog ./afl-toolchain.sh" >&2
    exit 1
fi

if [[ ! -f "${CONF_FILE}" ]]; then
    echo "[!] Apache configuration not found: ${CONF_FILE}" >&2
    exit 1
fi

EXTRA_ENV=()
if [[ ${RELAXED_VAR} -eq 1 ]]; then
    EXTRA_ENV+=("AFL_FAST_CAL=1" "AFL_NO_VAR_CHECK=1")
fi

COMMON_ARGS=(-p "${POWER}" -t "${TIMEOUT_MS}" -m "${MEM_LIMIT}" -i "${INPUT_DIR}" -o "${OUTPUT_DIR}")
[[ -n "${DICTIONARY}" && -f "${DICTIONARY}" ]] && COMMON_ARGS+=(-x "${DICTIONARY}")
[[ ${DETERMINISTIC} -eq 1 ]] && COMMON_ARGS+=(-D)

launch_instance() {
    local name="$1"; shift
    local role="$1"; shift
    local cmd=("$@")
    echo "[*] Launching ${role} instance '${name}'"
    (cd "${DEFAULT_BASE}" && env AFL_MAP_SIZE=262144 AFL_SKIP_CPUFREQ=1 AFL_AUTORESUME=1 "${EXTRA_ENV[@]}" "${cmd[@]}" >"${LOG_DIR}/${name}.log" 2>&1 &)
}

MASTER_CMD=(afl-fuzz -M "${MASTER_NAME}" "${COMMON_ARGS[@]}")
if [[ "${MODE}" == "cmplog" ]]; then
    MASTER_CMD+=(-c "${HTTPD_CMPLOG}" -- "${TARGET_BIN}" -X -f "${CONF_FILE}")
else
    MASTER_CMD+=(-- "${TARGET_BIN}" -X -f "${CONF_FILE}")
fi

launch_instance "${MASTER_NAME}" "master" "${MASTER_CMD[@]}"

for i in $(seq -f "s%02g" 1 "${SECONDARIES}"); do
    SLAVE_CMD=(afl-fuzz -S "$i" "${COMMON_ARGS[@]}" -- "${TARGET_BIN}" -X -f "${CONF_FILE}")
    launch_instance "$i" "secondary" "${SLAVE_CMD[@]}"
done

echo "[+] Fuzzing started"
echo "    Mode        : ${MODE}"
echo "    Master      : ${MASTER_NAME} (deterministic: ${DETERMINISTIC})"
echo "    Secondaries : ${SECONDARIES}"
echo "    Input       : ${INPUT_DIR}"
echo "    Output      : ${OUTPUT_DIR}"
echo "    Config      : ${CONF_FILE}"
if [[ -n "${DICTIONARY}" && -f "${DICTIONARY}" ]]; then
    echo "    Dictionary  : ${DICTIONARY}"
fi
if [[ ${RELAXED_VAR} -eq 1 ]]; then
    echo "    Variance opts: AFL_FAST_CAL=1 AFL_NO_VAR_CHECK=1"
fi

echo "Logs: ${LOG_DIR}"
echo "Monitor: ${SCRIPT_DIR}/monitor-fuzzing.sh ${OUTPUT_DIR}"

#!/bin/bash
set -euo pipefail

OUTPUT_DIR=${1:-./out-dir}
HTTPD_BIN=${2:-/usr/local/apache_asan/bin/httpd}
CONF_FILE=${3:-./conf/default.conf}

echo "[*] Triaging crashes from: $OUTPUT_DIR"

# Collect unique crashes
afl-cmin -i "$OUTPUT_DIR/*/crashes" -o ./unique-crashes -- "$HTTPD_BIN" -X -f "$CONF_FILE"

echo "[*] Unique crashes saved to: ./unique-crashes"
echo "[*] Running with ASAN for detailed reports..."

for crash in ./unique-crashes/id:*; do
    echo ""
    echo "========================================="
    echo "Testing: $(basename "$crash")"
    echo "========================================="
    
    ASAN_OPTIONS=symbolize=1:abort_on_error=1:detect_leaks=0 \
        timeout 5 "$HTTPD_BIN" -X -f "$CONF_FILE" < "$crash" || true
done

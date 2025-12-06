#!/bin/bash

OUTPUT_DIR=${1:-./out-dir}

watch -n 5 "
echo '=== AFL Status ==='
afl-whatsup -s $OUTPUT_DIR
echo ''
echo '=== Recent Crashes ==='
find $OUTPUT_DIR -name 'crashes' -type d -exec sh -c 'echo \"\$1: \$(ls \"\$1\" 2>/dev/null | wc -l) crashes\"' _ {} \;
echo ''
echo '=== Coverage ==='
find $OUTPUT_DIR -name 'plot_data' -exec tail -1 {} \; | awk '{sum+=\$4} END {print \"Total paths:\", sum}'
"

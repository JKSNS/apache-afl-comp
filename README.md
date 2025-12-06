# apache-afl-comp

This fork extends **0xbigshaq**'s Apache fuzzing automation to newer httpd and AFL++ releases. It downloads, patches, and builds Apache httpd with AFL++ instrumentation, plus the deps it needs (APR, APR-util, Expat, PCRE2) in isolated prefixes.

## Prerequisites
- AFL++ with `afl-clang-fast` and `afl-clang-lto` on PATH

## Build httpd (copy/paste)
Default AddressSanitizer build:
```bash
./afl-toolchain.sh
```

Other instrumentation presets:
```bash
BUILD_TYPE=cmplog   ./afl-toolchain.sh   # cmpcov companion for differential stage
BUILD_TYPE=compcov  ./afl-toolchain.sh   # laf-intel/compcov build
BUILD_TYPE=asan ./afl-toolchain.sh       # asan build
BUILD_TYPE=plain    ./afl-toolchain.sh   # coverage-only baseline
```

Cleanup and recompile everything:
```bash
CLEAN_DEPS=1 ./afl-toolchain.sh
```

Artifacts install under `/usr/local/apache_<mode>/` with the patched `httpd` in `bin/`.

## Fuzzing quick start
Seeds and configs live in `fuzzer-dir/` by default.
```bash
cd fuzzer-dir/
./afl-runner.sh
```

`afl-runner.sh` is a light wrapper for a single AFL++ instance. For multi-instance runs and more tuning, use `run-fuzz.sh` from repo root:
```bash
./run-fuzz.sh --mode asan --secondaries 2
```
Key options (mix and match):
- `--mode asan|cmplog|compcov|plain` selects which build to fuzz.
- `--input-dir <dir>` / `--output-dir <dir>` override corpus/output roots.
- `--dictionary <path>` points AFL++ to an HTTP request dictionary (default lives in `fuzzer-dir/dict/`).
- `--conf <path>` points to the Apache config (default: `fuzzer-dir/conf/default.conf`).
- `--power explore|fast|exploit`, `--timeout-ms <ms>`, `--mem-limit <val>` tune AFL++ knobs.
- `--relaxed-variance` enables `AFL_FAST_CAL=1` and `AFL_NO_VAR_CHECK=1` for unstable targets.

Logs land in `fuzzer-dir/logs/`, and AFL++ status UI can be viewed with:
```bash
./monitor-fuzzing.sh fuzzer-dir/out-dir
```

## Notes
- Place pre-downloaded archives alongside the scripts to avoid network fetches.
- CMPLOG mode expects both `apache_plain` and `apache_cmplog` builds; run both commands above.

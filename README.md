# apache-afl-comp

Apache httpd fuzzing environment built around AFL++. This fork keeps the original automation from 0xbigshaq but adds hardened fuzz configs, a multi-build toolchain (ASAN / CMPLOG / COMPCOV / plain), and operational scripts for running, monitoring, and triaging fuzz campaigns.

## Repository layout
- `afl-toolchain.sh` — builds Apache httpd with the selected AFL++ instrumentation mode.
- `insert-fuzz.py` / `fuzz.patch.c` — inject the persistent-mode socket harness and determinism tweaks.
- `fuzzer-dir/` — seeds (`input-cases`), preserved full corpus (`input-cases-full`), default fuzz config, dictionary, and legacy runner.
- `run-fuzz.sh` — primary multi-instance AFL runner.
- `monitor-fuzzing.sh` — status summary for AFL instances.
- `triage-crashes.sh` — replay and deduplicate crashes/hangs with ASan traces.

## Building httpd (multi-build strategy)
Four build modes are supported:
- **asan**: `-O2 -fsanitize=address` for bug finding.
- **cmplog**: comparison-logging build for AFL++ `-c` mode (runs alongside a plain build).
- **compcov**: comparison-coverage (LAF) build for hard-to-hit branches.
- **plain**: optimized, non-sanitized build for speed; use ASan for replay.

Example commands:
```bash
# Add SKIP_APT=1 if dependencies are already installed
BUILD_TYPE=asan   bash afl-toolchain.sh
BUILD_TYPE=cmplog bash afl-toolchain.sh
BUILD_TYPE=compcov bash afl-toolchain.sh
BUILD_TYPE=plain  bash afl-toolchain.sh
```

Notes:
- Place pre-downloaded tarballs (httpd/apr/apr-util/expat/pcre2) in the repo root to skip network fetches; multiple download mirrors are attempted automatically.
- Use `CLEAN_DEPS=1` to rebuild dependencies from scratch.

## Fuzz configuration & nondeterminism hardening
- The fuzz config at `fuzzer-dir/conf/default.conf` runs on port **8080**, disables noisy logs, and forces single-process prefork with no keep-alives.
- `/tmp/httpd-fuzz-root` is created automatically with a minimal document root; logging is nulled for determinism.
- Harness (`fuzz.patch.c`) uses `__AFL_LOOP` at the per-request layer, sends one request per iteration over 127.0.0.1:8080, and retries briefly if the listener is not ready.
- Randomness in `server/core.c` is patched to a constant seed for stability.
- Optional variance relaxers: pass `--relaxed-variance` to `run-fuzz.sh` to set `AFL_FAST_CAL=1` and `AFL_NO_VAR_CHECK=1` (use only if stability remains low).

## Seed corpus curation
- Default seeds live in `fuzzer-dir/input-cases` (three small HTTP requests).
- Original, fuller corpus is preserved in `fuzzer-dir/input-cases-full`.
- To minimize a custom corpus safely:
  ```bash
  AFL_MAP_SIZE=262144 \
  afl-cmin -i <input_dir> -o <corpus_min_dir> -- /usr/local/apache_asan/bin/httpd -X -f fuzzer-dir/conf/default.conf
  ```

## Running AFL++
Use the enhanced runner for single or multi-instance fuzzing:
```bash
# Single ASAN instance with deterministic stage
./run-fuzz.sh --mode asan --deterministic

# Master + 3 secondaries on plain build for speed
./run-fuzz.sh --mode plain --secondaries 3 --power explore

# CMPLOG master paired with plain target
./run-fuzz.sh --mode cmplog --secondaries 2 --dictionary fuzzer-dir/dict/http_request_fuzzer.dict.txt
```
Key options:
- `--mode`: asan|cmplog|compcov|plain
- `--secondaries N`: launch N `-S` instances (one master `m00` always runs).
- `--deterministic`: add `-D` deterministic stage.
- `--relaxed-variance`: opt-in `AFL_FAST_CAL` and `AFL_NO_VAR_CHECK`.
- `--power`: AFL++ power schedule (explore/fast/exploit).
- `--timeout-ms` / `--mem-limit`: forwarded to AFL++ `-t` / `-m`.

Legacy runner (`fuzzer-dir/afl-runner.sh`) remains available but `run-fuzz.sh` is preferred.

## Monitoring
```bash
# One-shot status
./monitor-fuzzing.sh fuzzer-dir/out-dir

# Continuous (set INTERVAL env)
INTERVAL=10 ./monitor-fuzzing.sh fuzzer-dir/out-dir
```
The monitor prints `exec/s`, `stability`, `paths`, `pending`, `map density`, `unique crashes`, and `unique hangs` per instance.

## Crash triage
```bash
# Uses ASAN build by default; override HTTPD_BIN if needed
./triage-crashes.sh fuzzer-dir/out-dir
```
Outputs minimized, signature-deduped crashes under `./triage-results/<signature>/` with logs in `./triage-results/logs/`.

## Multi-build roles
- **ASAN**: primary for bug finding and crash triage.
- **CMPLOG**: improves mutation guidance; run master with `-c` while targeting the plain binary.
- **COMPCOV**: enables LAF transforms to uncover comparison-heavy branches.
- **Plain**: fast exploration; replay interesting findings against ASAN.

## Stability and performance expectations
- Target baseline metrics inside AFL: watch `stability`, `execs_per_sec`, `map density`, and crash counters.
- The hardened config disables hostname lookups, trims modules, removes logs, and keeps a single prefork worker to reduce nondeterminism.
- If stability still lags, use the `--relaxed-variance` flag as a last resort (may admit flaky crashes).

## Socket vs. stdin
- The harness delivers each test case over a loopback TCP connection to httpd on port 8080, matching the fuzz config.
- Run with `-X` to keep httpd single-process; stdin is unused by the harness, so AFL++ communicates through the persistent socket client.

## Validation
- Builds are expected at `/usr/local/apache_<mode>/bin/httpd` after running `afl-toolchain.sh`.
- Quick smoke test: start a short ASAN fuzzing session with the curated seeds via `./run-fuzz.sh --mode asan --timeout-ms 1000`; monitor stability with `./monitor-fuzzing.sh`.
- When offline, drop the required tarballs into the repo root to allow repeatable builds without network access.

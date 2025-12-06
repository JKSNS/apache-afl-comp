# apache-afl

This fork extends **0xbigshaq**'s Apache fuzzing automation to newer httpd and AFL++ releases. It builds, patches, and fuzzes Apache httpd with AFL++ in one place.

## Quick start
Run the toolchain (ASan build by default):
```
./afl-toolchain.sh
```
Use other modes by setting `BUILD_TYPE=asan|cmplog|compcov|plain`.

If your environment already has build dependencies, skip apt:
```
SKIP_APT=1 ./afl-toolchain.sh
```

## Fuzzing
```
cd fuzzer-dir/
./afl-runner.sh
```
`run-fuzz.sh` offers a richer multi-instance runner; see `--help` for options.

## Notes
- Place pre-downloaded tarballs next to the script to avoid network fetches.
- Builds install under `/usr/local/apache_<mode>/` with the patched `httpd` binary in `bin/`.
- More background on the original approach: https://0xbigshaq.github.io/2022/03/12/fuzzing-smarter-part2

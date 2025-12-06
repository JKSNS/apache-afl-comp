# apache-afl-comp

This fork builds on the original Apache fuzzing automation by **0xbigshaq**; full credit for the foundational project and write-up belongs to them. The goal here is simply to expand and maintain their work for newer Apache releases and AFL++ improvements.

An automated setup for compiling & fuzzing the latest Apache httpd server with AFL++.

More info about the base project/journey can be found here: https://0xbigshaq.github.io/2022/03/12/fuzzing-smarter-part2

# Usage

To start the build process against the current httpd release (2.4.66 at the time of writing), follow this workflow:

# 1. Build all variants
```
BUILD_TYPE=asan bash afl-toolchain.sh
BUILD_TYPE=cmplog bash afl-toolchain.sh
BUILD_TYPE=plain bash afl-toolchain.sh
```

# 2. Start fuzzing
```
cd fuzzer-dir
bash afl-runner-multi.sh
```

# 3. Monitor
```
bash monitor-fuzzing.sh
```

# 4. Triage findings
```
bash triage-crashes.sh
```

# Additional Considerations: 

CPU Affinity: Pin AFL instances to specific cores
tmpfs: Mount output directory on RAM for speed
Custom Mutators: Implement HTTP-aware mutations
Power Schedules: Use -p exploit for crash-heavy inputs, -p fast for exploration

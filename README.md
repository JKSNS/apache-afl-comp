# apache-afl

This fork builds on the original Apache fuzzing automation by **0xbigshaq**; full credit for the foundational project and write-up belongs to them. The goal here is simply to expand and maintain their work for newer Apache releases and AFL++ improvements.

An automated setup for compiling & fuzzing the latest Apache httpd server with AFL++.

More info about the base project/journey can be found here: https://0xbigshaq.github.io/2022/03/12/fuzzing-smarter-part2

# Usage

To start the build process against the current httpd release (2.4.66 at the time of writing), run:

```
./afl-toolchain.sh
```

To start fuzzing:
```
cd fuzzer-dir/
./afl-runner.sh
```

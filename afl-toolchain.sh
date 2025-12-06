#!/bin/bash
set -euo pipefail

BUILD_TYPE=${BUILD_TYPE:-asan}
CLEAN_DEPS=${CLEAN_DEPS:-0}
HTTPD_VER="2.4.66"
APR_VER="1.7.6"
APR_UTIL_VER="1.6.3"
EXPAT_VER="2.6.2"
PCRE2_VER="10.44"

case "$BUILD_TYPE" in
    asan)
        export CC=afl-clang-fast
        export CXX=afl-clang-fast++
        export CFLAGS="-O2 -g -fsanitize=address -fno-sanitize-recover=all -std=gnu99 -Wno-error=declaration-after-statement"
        export CXXFLAGS="-O2 -g -fsanitize=address -fno-sanitize-recover=all -Wno-error=declaration-after-statement"
        export LDFLAGS="-fsanitize=address -fno-sanitize-recover=all -lm"
        PREFIX=/usr/local/apache_asan
        ;;
    cmplog)
        export CC=afl-clang-fast
        export CXX=afl-clang-fast++
        export AFL_LLVM_CMPLOG=1
        export CFLAGS="-O2 -g -std=gnu99 -Wno-error=declaration-after-statement"
        export CXXFLAGS="-O2 -g -Wno-error=declaration-after-statement"
        export LDFLAGS="-lm"
        PREFIX=/usr/local/apache_cmplog
        ;;
    compcov)
        export CC=afl-clang-lto
        export CXX=afl-clang-lto++
        export AFL_LLVM_LAF_ALL=1
        export AR=llvm-ar
        export NM=llvm-nm
        export RANLIB=llvm-ranlib
        export CFLAGS="-O2 -g -std=gnu99 -Wno-error=declaration-after-statement"
        export CXXFLAGS="-O2 -g -Wno-error=declaration-after-statement"
        export LDFLAGS="-lm"
        PREFIX=/usr/local/apache_compcov
        ;;
    plain)
        export CC=afl-clang-fast
        export CXX=afl-clang-fast++
        export CFLAGS="-O2 -g -std=gnu99 -Wno-error=declaration-after-statement"
        export CXXFLAGS="-O2 -g -Wno-error=declaration-after-statement"
        export LDFLAGS="-lm"
        PREFIX=/usr/local/apache_plain
        ;;
    *)
        echo "[!] Unknown BUILD_TYPE: ${BUILD_TYPE}" >&2
        exit 1
        ;;
esac

DEPS_DIR="deps-dir-${BUILD_TYPE}"

# Use non-instrumented compilers for third-party dependencies to avoid AFL
# runtime symbols (e.g., __afl_area_ptr) leaking into shared objects and
# breaking relinking steps. httpd itself is still built with the AFL
# instrumented compiler chosen above. We also strip AFL instrumentation
# environment variables from dependency builds to keep them "clean".
DEP_CC=${DEP_CC:-clang}
DEP_CXX=${DEP_CXX:-clang++}

case "$BUILD_TYPE" in
    asan)
        DEP_CFLAGS="-O2 -g"
        DEP_CXXFLAGS="-O2 -g"
        DEP_LDFLAGS=""
        ;;
    *)
        DEP_CFLAGS="-O2 -g"
        DEP_CXXFLAGS="-O2 -g"
        DEP_LDFLAGS=""
        ;;
esac

DEP_CFLAGS+=" -Wno-deprecated-non-prototype"
DEP_CXXFLAGS+=" -Wno-deprecated-non-prototype"

BUILD_DEPS=(build-essential libtool-bin brotli libbrotli-dev libxml2-dev libssl-dev wget curl xz-utils)
SKIP_APT=${SKIP_APT:-0}

download_with_fallback() {
    local archive="$1"; shift
    for url in "$@"; do
        echo "    [+] Fetching ${archive} from ${url}"
        if curl -fL "${url}" -o "${archive}"; then
            return 0
        fi
    done
    return 1
}

export LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH:-}

echo "[*] Building Apache httpd with BUILD_TYPE=${BUILD_TYPE}"
echo "[*] Installation prefix: ${PREFIX}"
echo "[*] Dependency build directory: ${DEPS_DIR}"

if [[ "${SKIP_APT}" -ne 1 ]]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${BUILD_DEPS[@]}"
else
    echo "[*] SKIP_APT=1, skipping dependency installation"
fi

mkdir -p "${PREFIX}"

HTTPD_ARCHIVE="httpd-${HTTPD_VER}.tar.gz"
if [[ ! -d "httpd-${HTTPD_VER}" ]]; then
    if [[ ! -f "${HTTPD_ARCHIVE}" ]]; then
        echo "[*] Downloading Apache httpd ${HTTPD_VER}..."
        download_with_fallback "${HTTPD_ARCHIVE}" \
            "https://dlcdn.apache.org/httpd/${HTTPD_ARCHIVE}" \
            "https://archive.apache.org/dist/httpd/${HTTPD_ARCHIVE}" \
            "https://downloads.apache.org/httpd/${HTTPD_ARCHIVE}" || { echo "[!] Failed to download httpd"; exit 1; }
    fi
    echo "[*] Extracting Apache httpd..."
    tar -xzf "${HTTPD_ARCHIVE}"
else
    echo "[*] httpd-${HTTPD_VER} already extracted"
fi

cd "./httpd-${HTTPD_VER}/"

if [[ ${CLEAN_DEPS} -eq 1 ]]; then
    echo "[*] CLEAN_DEPS=1, removing previous dependency builds"
    rm -rf "${DEPS_DIR}"
fi

mkdir -p "${DEPS_DIR}"
cd "./${DEPS_DIR}"

build_dep() {
    local name="$1" archive="$2" url_list="$3" prefix="$4" configure_args="$5" extract_cmd="$6"

    local -a clean_env=(env -u AFL_LLVM_CMPLOG -u AFL_LLVM_LAF_ALL -u AFL_LLVM_DICT2FILE -u AFL_LLVM_ALLOWLIST -u AFL_LLVM_INSTRUMENT_FILE -u AFL_USE_ASAN -u AFL_USE_MSAN -u AFL_USE_UBSAN -u AFL_MAP_SIZE)

    # shellcheck disable=SC2206
    local urls=(${url_list})

    echo "[*] Building ${name}..."
    if [[ ! -d "${name}" ]]; then
        if [[ ! -f "${archive}" ]]; then
            download_with_fallback "${archive}" "${urls[@]}" || { echo "[!] Failed to download ${archive}"; exit 1; }
        fi
        echo "    [+] Extracting ${archive}"
        eval "${extract_cmd}"
        mv "${name}"-*/ "${name}"
    else
        echo "    [+] Reusing existing ${name} directory"
    fi

    cd "${name}"/
    if [[ -f Makefile ]]; then
        "${clean_env[@]}" make distclean >/dev/null 2>&1 || true
    fi

    "${clean_env[@]}" CC="${DEP_CC}" CXX="${DEP_CXX}" \
        CFLAGS="${DEP_CFLAGS}" CXXFLAGS="${DEP_CXXFLAGS}" LDFLAGS="${DEP_LDFLAGS}" \
        ./configure --prefix="${prefix}" ${configure_args}

    "${clean_env[@]}" make -j "$(nproc)" && "${clean_env[@]}" make install
    cd ..
}

build_dep "apr" "apr-${APR_VER}.tar.gz" \
    "https://dlcdn.apache.org/apr/apr-${APR_VER}.tar.gz https://archive.apache.org/dist/apr/apr-${APR_VER}.tar.gz" \
    "${PREFIX}/apr/" "" "tar -xzf apr-${APR_VER}.tar.gz"

build_dep "apr-util" "apr-util-${APR_UTIL_VER}.tar.gz" \
    "https://dlcdn.apache.org/apr/apr-util-${APR_UTIL_VER}.tar.gz https://archive.apache.org/dist/apr/apr-util-${APR_UTIL_VER}.tar.gz" \
    "${PREFIX}/apr-util/" "--with-apr=${PREFIX}/apr/" "tar -xzf apr-util-${APR_UTIL_VER}.tar.gz"

build_dep "expat" "expat-${EXPAT_VER}.tar.xz" \
    "https://github.com/libexpat/libexpat/releases/download/R_${EXPAT_VER//./_}/expat-${EXPAT_VER}.tar.xz https://sourceforge.net/projects/expat/files/expat/${EXPAT_VER}/expat-${EXPAT_VER}.tar.xz/download" \
    "${PREFIX}/expat/" "" "tar -xJf expat-${EXPAT_VER}.tar.xz"

build_dep "pcre2" "pcre2-${PCRE2_VER}.tar.gz" \
    "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VER}/pcre2-${PCRE2_VER}.tar.gz https://sourceforge.net/projects/pcre/files/pcre2/${PCRE2_VER}/pcre2-${PCRE2_VER}.tar.gz/download" \
    "${PREFIX}/pcre2/" "" "tar -xzf pcre2-${PCRE2_VER}.tar.gz"

export PATH="${PREFIX}/pcre2/bin:${PATH}"
export LD_LIBRARY_PATH="${PREFIX}/pcre2/lib:${PREFIX}/apr/lib:${PREFIX}/apr-util/lib:${PREFIX}/expat/lib:${LD_LIBRARY_PATH}"

cd ../

if [[ ${CLEAN_DEPS} -eq 1 ]]; then
    echo "[*] CLEAN_DEPS=1, cleaning httpd build directory"
    make distclean >/dev/null 2>&1 || true
fi

# Apply fuzzing patches
if [[ ! -f server/main.c ]]; then
    echo "[!] Run this script from the httpd source root." >&2
    exit 1
fi

echo "[*] Applying fuzzing patches..."
chmod +x ../insert-fuzz.py
../insert-fuzz.py

# Configure Apache
echo "[*] Configuring Apache httpd..."
make clean >/dev/null 2>&1 || true
./configure --with-apr="${PREFIX}/apr/" \
            --with-apr-util="${PREFIX}/apr-util/" \
            --with-expat="${PREFIX}/expat/" \
            --with-pcre="${PREFIX}/pcre2/bin/pcre2-config" \
            --prefix="${PREFIX}" \
            --disable-pie \
            --disable-so \
            --with-mpm=prefork \
            --enable-static-support \
            --enable-mods-static=most \
            --enable-debugger-mode \
            --with-crypto --with-openssl \
            --disable-shared

# Compile
echo "[*] Compiling Apache httpd (this may take a while)..."
make -j "$(nproc)"
make install

# Clean
rm -rf httpd-2.4.66

echo ""
echo "[+] Build complete!"
echo "[+] Type: ${BUILD_TYPE}"
echo "[+] Installed to: ${PREFIX}"
echo "[+] Binary: ${PREFIX}/bin/httpd"

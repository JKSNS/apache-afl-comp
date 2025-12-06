#!/bin/bash
set -euo pipefail

BUILD_TYPE=${BUILD_TYPE:-asan}

case "$BUILD_TYPE" in
    asan)
        export CC=afl-clang-fast
        export CXX=afl-clang-fast++
        export CFLAGS="-g -fsanitize=address -fno-sanitize-recover=all -std=gnu99 -Wno-error=declaration-after-statement"
        export CXXFLAGS="-g -fsanitize=address -fno-sanitize-recover=all"
        export LDFLAGS="-fsanitize=address -fno-sanitize-recover=all -lm"
        PREFIX=/usr/local/apache_asan
        ;;
    cmplog)
        export CC=afl-clang-fast
        export CXX=afl-clang-fast++
        export AFL_LLVM_CMPLOG=1
        export CFLAGS="-g -std=gnu99 -Wno-error=declaration-after-statement"
        export CXXFLAGS="-g"
        export LDFLAGS="-lm"
        PREFIX=/usr/local/apache_cmplog
        ;;
    compcov)
        export CC=afl-clang-lto
        export CXX=afl-clang-lto++
        export AFL_LLVM_LAF_ALL=1
        export CFLAGS="-g -std=gnu99 -Wno-error=declaration-after-statement"
        export CXXFLAGS="-g"
        export LDFLAGS="-lm"
        PREFIX=/usr/local/apache_compcov
        ;;
    plain)
        export CC=afl-clang-fast
        export CXX=afl-clang-fast++
        export CFLAGS="-g -std=gnu99 -Wno-error=declaration-after-statement"
        export CXXFLAGS="-g"
        export LDFLAGS="-lm"
        PREFIX=/usr/local/apache_plain
        ;;
esac

# Versions
HTTPD_VER="2.4.66"
APR_VER="1.7.6"
APR_UTIL_VER="1.6.3"
EXPAT_VER="2.6.2"
PCRE2_VER="10.44"

BUILD_DEPS=(build-essential libtool-bin brotli libbrotli-dev libxml2-dev libssl-dev wget curl xz-utils)
SKIP_APT=${SKIP_APT:-0}

export LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH:-}

echo "[*] Building Apache httpd with BUILD_TYPE=${BUILD_TYPE}"
echo "[*] Installation prefix: ${PREFIX}"

if [[ "${SKIP_APT}" -ne 1 ]]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${BUILD_DEPS[@]}"
else
    echo "[*] SKIP_APT=1, skipping dependency installation"
fi

mkdir -p "${PREFIX}"

# Download httpd
HTTPD_ARCHIVE="httpd-${HTTPD_VER}.tar.gz"
if [[ ! -d "httpd-${HTTPD_VER}" ]]; then
    if [[ ! -f "${HTTPD_ARCHIVE}" ]]; then
        echo "[*] Downloading Apache httpd ${HTTPD_VER}..."
        curl -fL "https://dlcdn.apache.org/httpd/${HTTPD_ARCHIVE}" -o "${HTTPD_ARCHIVE}"
    fi
    echo "[*] Extracting Apache httpd..."
    tar -xzf "${HTTPD_ARCHIVE}"
else
    echo "[*] httpd-${HTTPD_VER} already extracted"
fi

cd "./httpd-${HTTPD_VER}/"
mkdir -p deps-dir/
cd ./deps-dir

# APR
echo "[*] Building APR ${APR_VER}..."
APR_ARCHIVE="apr-${APR_VER}.tar.gz"
if [[ ! -d "apr" ]]; then
    if [[ ! -f "${APR_ARCHIVE}" ]]; then
        curl -fL "https://dlcdn.apache.org/apr/${APR_ARCHIVE}" -o "${APR_ARCHIVE}"
    fi
    tar -xzf "${APR_ARCHIVE}"
    mv "./apr-${APR_VER}" apr
fi
cd apr/
if [[ ! -f "Makefile" ]]; then
    ./configure --prefix="${PREFIX}/apr/"
fi
make -j "$(nproc)" && make install
cd ..

# APR-UTIL
echo "[*] Building APR-UTIL ${APR_UTIL_VER}..."
APR_UTIL_ARCHIVE="apr-util-${APR_UTIL_VER}.tar.gz"
if [[ ! -d "apr-util" ]]; then
    if [[ ! -f "${APR_UTIL_ARCHIVE}" ]]; then
        curl -fL "https://dlcdn.apache.org/apr/${APR_UTIL_ARCHIVE}" -o "${APR_UTIL_ARCHIVE}"
    fi
    tar -xzf "${APR_UTIL_ARCHIVE}"
    mv "./apr-util-${APR_UTIL_VER}" apr-util
fi
cd apr-util/
if [[ ! -f "Makefile" ]]; then
    ./configure --prefix="${PREFIX}/apr-util/" --with-apr="${PREFIX}/apr/"
fi
make -j "$(nproc)" && make install
cd ..

# EXPAT
echo "[*] Building EXPAT ${EXPAT_VER}..."
EXPAT_ARCHIVE="expat-${EXPAT_VER}.tar.xz"
if [[ ! -d "expat" ]]; then
    if [[ ! -f "${EXPAT_ARCHIVE}" ]]; then
        curl -fL "https://github.com/libexpat/libexpat/releases/download/R_${EXPAT_VER//./_}/${EXPAT_ARCHIVE}" -o "${EXPAT_ARCHIVE}"
    fi
    tar -xJf "${EXPAT_ARCHIVE}"
    mv "./expat-${EXPAT_VER}" expat
fi
cd expat/
if [[ ! -f "Makefile" ]]; then
    ./configure --prefix="${PREFIX}/expat/"
fi
make -j "$(nproc)" && make install
cd ..

# PCRE2
echo "[*] Building PCRE2 ${PCRE2_VER}..."
PCRE2_ARCHIVE="pcre2-${PCRE2_VER}.tar.gz"
if [[ ! -d "pcre2" ]]; then
    if [[ ! -f "${PCRE2_ARCHIVE}" ]]; then
        curl -fL "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VER}/${PCRE2_ARCHIVE}" -o "${PCRE2_ARCHIVE}"
    fi
    tar -xzf "${PCRE2_ARCHIVE}"
    mv "./pcre2-${PCRE2_VER}" pcre2
fi
cd pcre2/
if [[ ! -f "Makefile" ]]; then
    ./configure --prefix="${PREFIX}/pcre2/"
fi
make -j "$(nproc)" && make install
cd ..

export PATH="${PREFIX}/pcre2/bin:${PATH}"
export LD_LIBRARY_PATH="${PREFIX}/pcre2/lib:${PREFIX}/apr/lib:${PREFIX}/apr-util/lib:${PREFIX}/expat/lib:${LD_LIBRARY_PATH}"

cd ../

# Apply fuzzing patches
echo "[*] Applying fuzzing patches..."
chmod +x ../insert-fuzz.py
../insert-fuzz.py

# Configure Apache
echo "[*] Configuring Apache httpd..."
./configure --with-apr="${PREFIX}/apr/" \
            --with-apr-util="${PREFIX}/apr-util/" \
            --with-expat="${PREFIX}/expat/" \
            --with-pcre="${PREFIX}/pcre2/bin/pcre2-config" \
            --prefix="${PREFIX}" \
            --disable-pie \
            --disable-so \
            --with-mpm=prefork \
            --enable-static-support \
            --enable-mods-static=reallyall \
            --enable-debugger-mode \
            --with-crypto --with-openssl \
            --disable-shared

# Compile
echo "[*] Compiling Apache httpd (this may take a while)..."
make -j "$(nproc)"
make install

echo ""
echo "[+] Build complete!"
echo "[+] Type: ${BUILD_TYPE}"
echo "[+] Installed to: ${PREFIX}"
echo "[+] Binary: ${PREFIX}/bin/httpd"

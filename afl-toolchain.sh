#!/bin/bash
set -euo pipefail

# Current Versions
HTTPD_VER="2.4.66"
APR_VER="1.7.6"
APR_UTIL_VER="1.6.3"
EXPAT_VER="2.6.2"
PCRE2_VER="10.44"

PREFIX=/usr/local/apache_lab
BUILD_DEPS=(build-essential libtool-bin brotli libbrotli-dev libxml2-dev libssl-dev wget curl xz-utils)
SKIP_APT=${SKIP_APT:-0}

export LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH:-}

if [[ "${SKIP_APT}" -ne 1 ]]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${BUILD_DEPS[@]}"
else
    echo "[*] SKIP_APT=1 set, assuming build dependencies are already present."
fi

mkdir -p "${PREFIX}"

# Download Apache httpd
HTTPD_ARCHIVE="httpd-${HTTPD_VER}.tar.gz"
curl -fL "https://dlcdn.apache.org/httpd/${HTTPD_ARCHIVE}" -o "${HTTPD_ARCHIVE}"
tar -xvzf "${HTTPD_ARCHIVE}" && rm "${HTTPD_ARCHIVE}"
cd "./httpd-${HTTPD_VER}/"

# Handling dependencies
mkdir -p deps-dir/
cd ./deps-dir

# APR
APR_ARCHIVE="apr-${APR_VER}.tar.gz"
curl -fL "https://dlcdn.apache.org/apr/${APR_ARCHIVE}" -o "${APR_ARCHIVE}"
tar -xvzf "${APR_ARCHIVE}" && rm "${APR_ARCHIVE}" && mv "./apr-${APR_VER}" apr
cd apr/
./configure --prefix="${PREFIX}/apr/"
make -j "$(nproc)" && make install
cd ..

# APR-UTIL
APR_UTIL_ARCHIVE="apr-util-${APR_UTIL_VER}.tar.gz"
curl -fL "https://dlcdn.apache.org/apr/${APR_UTIL_ARCHIVE}" -o "${APR_UTIL_ARCHIVE}"
tar -xvzf "${APR_UTIL_ARCHIVE}" && rm "${APR_UTIL_ARCHIVE}" && mv "./apr-util-${APR_UTIL_VER}" apr-util
cd apr-util/
./configure --prefix="${PREFIX}/apr-util/" --with-apr="${PREFIX}/apr/"
make -j "$(nproc)" && make install
cd ..

# EXPAT
EXPAT_ARCHIVE="expat-${EXPAT_VER}.tar.xz"
curl -fL "https://github.com/libexpat/libexpat/releases/download/R_${EXPAT_VER//./_}/${EXPAT_ARCHIVE}" -o "${EXPAT_ARCHIVE}"
tar -xvJf "${EXPAT_ARCHIVE}" && rm "${EXPAT_ARCHIVE}" && mv "./expat-${EXPAT_VER}" expat
cd expat/
./configure --prefix="${PREFIX}/expat/"
make -j "$(nproc)" && make install
cd ..

# PCRE2
PCRE2_ARCHIVE="pcre2-${PCRE2_VER}.tar.gz"
curl -fL "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VER}/${PCRE2_ARCHIVE}" -o "${PCRE2_ARCHIVE}"
tar -xvzf "${PCRE2_ARCHIVE}" && rm "${PCRE2_ARCHIVE}" && mv "./pcre2-${PCRE2_VER}" pcre2
cd pcre2/
./configure --prefix="${PREFIX}/pcre2/"
make -j "$(nproc)" && make install
cd ..

# Ensure httpd can find PCRE2 
export PATH="${PREFIX}/pcre2/bin:${PATH}"
export LD_LIBRARY_PATH="${PREFIX}/pcre2/lib:${PREFIX}/apr/lib:${PREFIX}/apr-util/lib:${PREFIX}/expat/lib:${LD_LIBRARY_PATH}"

cd ../
chmod +x ../insert-fuzz.py
../insert-fuzz.py

# Configure compiler, flags and DSOs/apache modules
CC=afl-clang-fast \
CXX=afl-clang-fast++ \
CFLAGS="-g -fsanitize=address -fno-sanitize-recover=all \
        -std=gnu99 -Wno-error=declaration-after-statement" \
CXXFLAGS="-g -fsanitize=address -fno-sanitize-recover=all" \
LDFLAGS="-fsanitize=address -fno-sanitize-recover=all -lm" \
./configure --with-apr="${PREFIX}/apr/" \
            --with-apr-util="${PREFIX}/apr-util/" \
            --with-expat="${PREFIX}/expat/" \
            --with-pcre="${PREFIX}/pcre2/bin/pcre2-config" \
            --disable-pie \
            --disable-so \
            --disable-example-ipc \
            --disable-example-hooks \
            --disable-optional-hook-export \
            --disable-optional-hook-import \
            --disable-optional-fn-export \
            --disable-optional-fn-import \
            --with-mpm=prefork \
            --enable-static-support \
            --enable-mods-static=reallyall \
            --enable-debugger-mode \
            --with-crypto --with-openssl \
            --disable-shared

# Compile
make -j "$(nproc)"
make install

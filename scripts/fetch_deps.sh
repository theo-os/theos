#!/usr/bin/env bash
set -e

mkdir -p third_party
cd third_party

# zlib-ng
if [ ! -d "zlib-ng" ]; then
    echo "Fetching zlib-ng..."
    git clone --depth=1 https://github.com/zlib-ng/zlib-ng
fi

# zstd
if [ ! -d "zstd" ]; then
    echo "Fetching zstd..."
    git clone --depth=1 https://github.com/facebook/zstd
fi

if [ ! -d "lz4" ]; then
    echo "Fetching lz4..."
    git clone --depth=1 https://github.com/lz4/lz4
fi

# curl
if [ ! -d "curl" ]; then
    echo "Fetching curl..."
    git clone --depth=1 https://github.com/curl/curl
fi

# libexpat
if [ ! -d "libexpat" ]; then
    echo "Fetching libexpat..."
    git clone --depth=1 https://github.com/libexpat/libexpat
fi

# openssl
if [ ! -d "openssl" ]; then
    echo "Fetching openssl..."
    git clone --depth=1 https://github.com/openssl/openssl
fi

if [ ! -d "llvm-project" ]; then
    echo "Fetching llvm-project..."
    git clone --depth=1 https://github.com/llvm/llvm-project
fi

echo "Dependencies fetched successfully."

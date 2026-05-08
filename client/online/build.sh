#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$ROOT_DIR/src/online.cpp"
OUT_DIR="$ROOT_DIR/dist"

mkdir -p "$OUT_DIR"

i686-w64-mingw32-g++ \
  -std=c++17 \
  -O2 \
  -fno-omit-frame-pointer \
  -fno-optimize-sibling-calls \
  -s \
  -shared \
  -o "$OUT_DIR/online.asi" \
  "$SRC" \
  -lws2_32 \
  -static-libgcc \
  -static-libstdc++

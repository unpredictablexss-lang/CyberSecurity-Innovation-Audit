#!/bin/sh
set -eu
if [ "$#" -ne 2 ]; then
  echo "usage: run.sh <binary> <mode>" >&2
  exit 64
fi
binary="$1"
mode="$2"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=0}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=0}"
exec "/sandbox/out/$binary" "$mode"

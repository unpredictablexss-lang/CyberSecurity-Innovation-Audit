#!/bin/sh
# Run the two binaries built by build.sh and print one JSON object per scenario.
#
# ASAN_OPTIONS=handle_sigbus=0 leaves SIGBUS to the kernel: scenario B's whole
# point is that the caller dies when it reads past the end of the mapped file,
# and the sanitizer's own handler would report that as an exit instead.
set -eu

OUT=${OUT:-/home/audit/wtmp/parcel_harness/build}

ASAN_OPTIONS=handle_sigbus=0 "$OUT/vulnerable/harness" vulnerable \
    > "$OUT/vulnerable.jsonl" 2> "$OUT/vulnerable.stderr"
ASAN_OPTIONS=handle_sigbus=0 "$OUT/fixed/harness" fixed \
    > "$OUT/fixed.jsonl" 2> "$OUT/fixed.stderr"

cat "$OUT/vulnerable.jsonl" "$OUT/fixed.jsonl"

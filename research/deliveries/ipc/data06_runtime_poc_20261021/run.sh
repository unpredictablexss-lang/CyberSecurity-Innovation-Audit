#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-artifacts}"
mkdir -p "$OUT"
clang++ --version > "$OUT/compiler.txt"
# -O0 keeps this source-semantic harness's heap writes observable to ASan.
FLAGS=(-std=c++17 -O0 -g -fsanitize=address -fno-omit-frame-pointer -Wall -Wextra -Werror)

clang++ "${FLAGS[@]}" -DREPRO_VULNERABLE array_width_poc.cpp -o "$OUT/vulnerable"
clang++ "${FLAGS[@]}" array_width_poc.cpp -o "$OUT/fixed"

set +e
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 "$OUT/vulnerable" 4 > "$OUT/vulnerable.stdout.txt" 2> "$OUT/vulnerable.stderr.txt"
vulnerable_status=$?
set -e
if [[ $vulnerable_status -eq 0 ]] || ! grep -q 'heap-buffer-overflow' "$OUT/vulnerable.stderr.txt"; then
  echo "vulnerable positive did not produce the expected ASan heap-buffer-overflow (exit=$vulnerable_status)" >&2
  exit 1
fi
base64 -w0 "$OUT/vulnerable.stderr.txt" > "$OUT/vulnerable.stderr.raw.b64"
raw_stderr_sha256=$(sha256sum "$OUT/vulnerable.stderr.txt" | cut -d ' ' -f 1)
raw_stderr_bytes=$(wc -c < "$OUT/vulnerable.stderr.txt" | tr -d ' ')
# Keep a readable, whitespace-cleaned copy while the base64 file preserves the
# exact captured stderr bytes for lossless reconstruction.
sed -E 's/[[:blank:]]+$//' "$OUT/vulnerable.stderr.txt" > "$OUT/vulnerable.stderr.display.tmp"
mv "$OUT/vulnerable.stderr.display.tmp" "$OUT/vulnerable.stderr.txt"

ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 "$OUT/fixed" 4 > "$OUT/fixed.stdout.txt" 2> "$OUT/fixed.stderr.txt"
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 "$OUT/vulnerable" 0 > "$OUT/negative-zero.stdout.txt" 2> "$OUT/negative-zero.stderr.txt"

set +e
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 "$OUT/vulnerable" 4 2 > "$OUT/negative-short.stdout.txt" 2> "$OUT/negative-short.stderr.txt"
short_status=$?
set -e
if [[ $short_status -eq 0 ]] || grep -q 'heap-buffer-overflow' "$OUT/negative-short.stderr.txt"; then
  echo "short parcel control did not reject without an overflow (exit=$short_status)" >&2
  exit 1
fi

cat > "$OUT/result.json" <<EOF
{
  "harness": "isolated source-semantic C++ model; not the OpenHarmony component binary",
  "compiler": "$(clang++ --version | head -n 1)",
  "sanitizer": "AddressSanitizer",
  "raw_vulnerable_stderr": {"path": "vulnerable.stderr.raw.b64", "encoding": "base64", "sha256_of_decoded_bytes": "$raw_stderr_sha256", "decoded_bytes": $raw_stderr_bytes},
  "cases": {
    "vulnerable_count_4": {"expected": "heap-buffer-overflow", "exit": $vulnerable_status, "observed": "$(grep -m1 'heap-buffer-overflow' "$OUT/vulnerable.stderr.txt" | sed 's/"/\\"/g')"},
    "fixed_count_4": {"expected": "clean return", "exit": 0},
    "vulnerable_count_0": {"expected": "clean early return", "exit": 0},
    "vulnerable_count_4_remaining_2": {"expected": "read-length rejection, no overflow", "exit": $short_status}
  }
}
EOF
echo "PASS: vulnerable source model overflows; fixed and negative controls behave as expected"

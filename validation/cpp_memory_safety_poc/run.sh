#!/usr/bin/env bash
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$ROOT/validation/cpp_memory_safety_poc"
OUT="${1:-$ROOT/research/evidence/cpp/a_memory_safety_poc_20261017}"
mkdir -p "$OUT"
CXX="${CXX:-g++}"
FLAGS=(-std=c++17 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined)
{
  echo "tool=$($CXX --version | head -n 1)"
  echo "flags=${FLAGS[*]}"
  echo "root=$ROOT"
} > "$OUT/environment.txt"
for name in bounds_vulnerable bounds_fixed integer_vulnerable integer_fixed; do
  "$CXX" "${FLAGS[@]}" "$SRC/$name.cpp" -o "$OUT/$name"
  echo "compile_exit=$name=$?" >> "$OUT/environment.txt"
done
set +e
"$OUT/bounds_vulnerable" > "$OUT/bounds_vulnerable.stdout.txt" 2> "$OUT/bounds_vulnerable.stderr.txt"
echo "$?" > "$OUT/bounds_vulnerable.exit.txt"
"$OUT/bounds_fixed" > "$OUT/bounds_fixed.stdout.txt" 2> "$OUT/bounds_fixed.stderr.txt"
echo "$?" > "$OUT/bounds_fixed.exit.txt"
"$OUT/integer_vulnerable" 4294967295 > "$OUT/integer_vulnerable.stdout.txt" 2> "$OUT/integer_vulnerable.stderr.txt"
echo "$?" > "$OUT/integer_vulnerable.exit.txt"
"$OUT/integer_fixed" 4294967295 > "$OUT/integer_fixed.stdout.txt" 2> "$OUT/integer_fixed.stderr.txt"
echo "$?" > "$OUT/integer_fixed.exit.txt"
set -e
sha256sum "$SRC"/*.cpp "$OUT"/*.stdout.txt "$OUT"/*.stderr.txt "$OUT"/*.exit.txt > "$OUT/sha256sums.txt"

#!/bin/sh
set -eu
out=/sandbox/out
work=/sandbox/work
mkdir -p "$out/logs"
export TMPDIR=/tmp
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:handle_segv=0:handle_sigfpe=0:handle_sigbus=0
export UBSAN_OPTIONS=halt_on_error=0
{
  echo "argv: g++ -std=c++17 -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer $work/target_adapter.cpp -o $out/target_adapter"
  g++ -std=c++17 -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer "$work/target_adapter.cpp" -o "$out/target_adapter"
  echo "target_compile_exit=0"
  echo "argv: g++ -std=c++17 -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer -DPATCHED_TARGET=1 $work/patched_target_adapter.cpp -o $out/patched_target_adapter"
  g++ -std=c++17 -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer -DPATCHED_TARGET=1 "$work/patched_target_adapter.cpp" -o "$out/patched_target_adapter"
  echo "patched_compile_exit=0"
  g++ --version
} > "$out/logs/compile.log" 2>&1
printf 'mode	repetition	exit_code	log\n' > "$out/run_summary.tsv"
run_case() {
  mode="$1"
  binary="$2"
  repetition="$3"
  log="$out/logs/${mode}_r${repetition}.log"
  set +e
  timeout 10 "$out/$binary" "$mode" > "$log" 2>&1
  code=$?
  set -e
  printf '%s\t%s\t%s\tlogs/%s_r%s.log\n' "$mode" "$repetition" "$code" "$mode" "$repetition" >> "$out/run_summary.tsv"
}
for i in 1 2 3; do run_case attack target_adapter "$i"; done
for i in 1 2 3; do run_case safe target_adapter "$i"; done
for i in 1 2 3; do run_case fixed patched_target_adapter "$i"; done
for i in 1 2 3; do run_case fixed-safe patched_target_adapter "$i"; done
sha256sum "$out/target_adapter" "$out/patched_target_adapter" "$work/target_adapter.cpp" "$work/patched_target_adapter.cpp" "$work/target_adapter_common.hpp" > "$out/logs/artifact_hashes.txt"
echo "completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out/logs/completed_at.txt"

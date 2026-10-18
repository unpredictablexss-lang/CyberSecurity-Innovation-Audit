#!/bin/sh
set -eu
out=/sandbox/out
work=/sandbox/work
mkdir -p "$out/logs"
export TMPDIR=/tmp
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0
{
  echo "argv: g++ -std=c++17 -O0 -g -fsanitize=undefined -fno-omit-frame-pointer $work/target_adapter.cpp -o $out/target_ubsan"
  g++ -std=c++17 -O0 -g -fsanitize=undefined -fno-omit-frame-pointer "$work/target_adapter.cpp" -o "$out/target_ubsan"
  echo "target_ubsan_compile_exit=0"
  echo "argv: g++ -std=c++17 -O0 -g -fsanitize=undefined -fno-omit-frame-pointer -DPATCHED_TARGET=1 $work/patched_target_adapter.cpp -o $out/patched_ubsan"
  g++ -std=c++17 -O0 -g -fsanitize=undefined -fno-omit-frame-pointer -DPATCHED_TARGET=1 "$work/patched_target_adapter.cpp" -o "$out/patched_ubsan"
  echo "patched_ubsan_compile_exit=0"
  echo "argv: g++ -std=c++17 -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer $work/target_adapter.cpp -o $out/target_asan_ubsan"
  g++ -std=c++17 -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer "$work/target_adapter.cpp" -o "$out/target_asan_ubsan"
  echo "target_asan_ubsan_compile_exit=0"
  echo "argv: g++ -std=c++17 -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer -DPATCHED_TARGET=1 $work/patched_target_adapter.cpp -o $out/patched_asan_ubsan"
  g++ -std=c++17 -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer -DPATCHED_TARGET=1 "$work/patched_target_adapter.cpp" -o "$out/patched_asan_ubsan"
  echo "patched_asan_ubsan_compile_exit=0"
  g++ --version
} > "$out/logs/compile.log" 2>&1
printf 'mode\trepetition\texit_code\tlog\n' > "$out/run_summary.tsv"
run_case() {
  mode="$1"; binary="$2"; repetition="$3"
  log="$out/logs/${mode}_r${repetition}.log"
  set +e
  timeout 10 "$out/$binary" "$mode" > "$log" 2>&1
  code=$?
  set -e
  printf '%s\t%s\t%s\tlogs/%s_r%s.log\n' "$mode" "$repetition" "$code" "$mode" "$repetition" >> "$out/run_summary.tsv"
}
for i in 1 2 3; do run_case attack target_ubsan "$i"; done
for i in 1 2 3; do run_case safe target_ubsan "$i"; done
for i in 1 2 3; do run_case fixed patched_ubsan "$i"; done
for i in 1 2 3; do run_case fixed-safe patched_ubsan "$i"; done
set +e
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:handle_segv=0:handle_sigfpe=0:handle_sigbus=0 timeout 10 "$out/target_asan_ubsan" attack > "$out/logs/asan_ubsan_probe.log" 2>&1
asan_code=$?
set -e
printf 'asan_ubsan_probe_exit=%s\n' "$asan_code" > "$out/logs/asan_ubsan_probe_status.txt"
sha256sum "$out/target_ubsan" "$out/patched_ubsan" "$out/target_asan_ubsan" "$out/patched_asan_ubsan" "$work/target_adapter.cpp" "$work/patched_target_adapter.cpp" "$work/target_adapter_common.hpp" > "$out/logs/artifact_hashes.txt"
echo "completed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out/logs/completed_at.txt"

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p poc/results
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0
g++ --version | head -n 1 >poc/results/compiler.txt

g++ -std=c++17 -O0 -g -fsanitize=undefined -fno-omit-frame-pointer \
  source/target_adapter.cpp -o poc/results/target_ubsan \
  2>poc/results/compile_target.log
g++ -std=c++17 -O0 -g -fsanitize=undefined -fno-omit-frame-pointer \
  -DPATCHED_TARGET=1 source/patched_target_adapter.cpp \
  -o poc/results/patched_ubsan 2>poc/results/compile_patched.log

printf 'mode\trepetition\texit_code\tlog\n' >poc/results/run_summary.tsv
run_case() {
  local mode="$1" binary="$2" i code
  for i in 1 2 3; do
    set +e
    timeout 10 "poc/results/$binary" "$mode" >"poc/results/${mode}_r${i}.log" 2>&1
    code=$?
    set -e
    printf '%s\t%s\t%s\t%s_r%s.log\n' "$mode" "$i" "$code" "$mode" "$i" >>poc/results/run_summary.tsv
    if [[ "$code" -ne 0 ]]; then
      echo "${mode} run ${i} failed with exit ${code}" >&2
      return 1
    fi
  done
}

run_case attack target_ubsan
run_case safe target_ubsan
run_case fixed patched_ubsan
run_case fixed-safe patched_ubsan
sha256sum poc/results/target_ubsan poc/results/patched_ubsan \
  source/target_adapter.cpp source/patched_target_adapter.cpp \
  source/target_adapter_common.hpp source/generated/handle_contact_portrait.inc \
  >poc/results/artifact_hashes.txt
cat poc/results/run_summary.tsv

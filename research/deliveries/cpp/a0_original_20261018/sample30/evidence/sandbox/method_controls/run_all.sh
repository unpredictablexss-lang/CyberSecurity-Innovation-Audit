#!/bin/bash
set -u
export ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=0
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
export TSAN_OPTIONS=halt_on_error=1:exitcode=66:second_deadlock_stack=1
mkdir -p /sandbox/out/bin /sandbox/out/logs
: > /sandbox/out/run_summary.tsv
printf 'phase\tvariant\treplay\texit_code\texpected\tobserved\n' >> /sandbox/out/run_summary.tsv
clang++ --version > /sandbox/out/compiler_version.txt
uname -a > /sandbox/out/uname.txt
cat /etc/os-release > /sandbox/out/os-release.txt
run_cmd() {
  phase="$1"; variant="$2"; replay="$3"; expected="$4"; shift 4
  log="/sandbox/out/logs/${phase}_${variant}_r${replay}.log"
  {
    printf 'ARGV:'
    printf ' %q' "$@"
    printf '\n'
    printf 'ASAN_OPTIONS=%s\n' "$ASAN_OPTIONS"
    printf 'UBSAN_OPTIONS=%s\n' "$UBSAN_OPTIONS"
    printf 'TSAN_OPTIONS=%s\n' "$TSAN_OPTIONS"
  } > "$log"
  setarch "$(uname -m)" -R "$@" >> "$log" 2>&1
  rc=$?
  observed=unexpected
  if [ "$rc" -eq 0 ] && [ "$expected" = "clean" ] && ! grep -Eq 'ERROR: AddressSanitizer|runtime error:|WARNING: ThreadSanitizer|FATAL: ThreadSanitizer' "$log"; then observed=clean; fi
  if [ "$rc" -ne 0 ] && [ "$expected" = "sanitizer_error" ] && grep -Eq 'ERROR: AddressSanitizer|runtime error:|WARNING: ThreadSanitizer' "$log" && ! grep -q 'FATAL: ThreadSanitizer' "$log"; then observed=sanitizer_error; fi
  if grep -Eq 'FATAL: ThreadSanitizer|setarch: failed to set personality' "$log"; then observed=blocked_tool_runtime; fi
  if [ "$expected" = "valid_tsan_execution" ] && [ "$rc" -eq 66 ] && grep -q 'WARNING: ThreadSanitizer: data race' "$log"; then observed=valid_tsan_execution; fi
  if [ "$expected" = "valid_tsan_execution" ] && [ "$rc" -eq 0 ] && ! grep -q 'WARNING: ThreadSanitizer: data race' "$log"; then observed=valid_tsan_execution; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$phase" "$variant" "$replay" "$rc" "$expected" "$observed" >> /sandbox/out/run_summary.tsv
  return 0
}
compile_cmd() {
  phase="$1"; variant="$2"; shift 2
  log="/sandbox/out/logs/compile_${variant}.log"
  { printf 'ARGV:'; printf ' %q' "$@"; printf '\n'; } > "$log"
  setarch "$(uname -m)" -R "$@" >> "$log" 2>&1
  rc=$?
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$phase" "$variant" 0 "$rc" clean clean >> /sandbox/out/run_summary.tsv
}
compile_cmd compile copy_range_model clang++-14 -std=c++17 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined /sandbox/src/copy_range_model.cpp -o /sandbox/out/bin/copy_range_model
compile_cmd compile copy_range_unsafe_control clang++-14 -std=c++17 -O0 -g -fno-omit-frame-pointer -fsanitize=address,undefined /sandbox/src/copy_range_unsafe_control.cpp -o /sandbox/out/bin/copy_range_unsafe_control
compile_cmd compile copy_range_safe_control clang++-14 -std=c++17 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined /sandbox/src/copy_range_safe_control.cpp -o /sandbox/out/bin/copy_range_safe_control
compile_cmd compile shared_ptr_unsafe_control clang++-14 -std=c++17 -O1 -g -fno-omit-frame-pointer -fsanitize=thread /sandbox/src/shared_ptr_tsan_unsafe_control.cpp -o /sandbox/out/bin/shared_ptr_unsafe_control
compile_cmd compile shared_ptr_atomic_control clang++-14 -std=c++17 -O1 -g -fno-omit-frame-pointer -fsanitize=thread /sandbox/src/shared_ptr_tsan_atomic_control.cpp -o /sandbox/out/bin/shared_ptr_atomic_control
for r in 1 2 3; do
  run_cmd method_model copy_range_model "$r" clean /sandbox/out/bin/copy_range_model
  run_cmd safe_control copy_range_safe_control "$r" clean /sandbox/out/bin/copy_range_safe_control
  run_cmd positive_control copy_range_unsafe_control "$r" sanitizer_error /sandbox/out/bin/copy_range_unsafe_control 2048
  run_cmd generic_tsan_positive shared_ptr_unsafe_control "$r" valid_tsan_execution /sandbox/out/bin/shared_ptr_unsafe_control
  run_cmd generic_tsan_fixed shared_ptr_atomic_control "$r" valid_tsan_execution /sandbox/out/bin/shared_ptr_atomic_control
done
printf 'completed_at\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > /sandbox/out/completed_at.txt
exit 0

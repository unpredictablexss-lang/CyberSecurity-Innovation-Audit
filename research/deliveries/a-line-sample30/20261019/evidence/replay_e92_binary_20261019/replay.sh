#!/bin/sh
set -eu

out=/sandbox/out
input=/sandbox/input
mkdir -p "$out/logs"
cd "$input"
sha256sum target_ubsan patched_ubsan > "$out/logs/input_binary_hashes.txt"
printf 'mode\trepetition\texit_code\tlog\n' > "$out/run_summary.tsv"

run_case() {
    mode="$1"
    binary="$2"
    repetition="$3"
    log="$out/logs/${mode}_r${repetition}.log"
    set +e
    timeout 10 "$input/$binary" "$mode" > "$log" 2>&1
    code=$?
    set -e
    printf '%s\t%s\t%s\tlogs/%s_r%s.log\n' "$mode" "$repetition" "$code" "$mode" "$repetition" >> "$out/run_summary.tsv"
}

for i in 1 2 3; do run_case attack target_ubsan "$i"; done
for i in 1 2 3; do run_case safe target_ubsan "$i"; done
for i in 1 2 3; do run_case fixed patched_ubsan "$i"; done
for i in 1 2 3; do run_case fixed-safe patched_ubsan "$i"; done

date -u +%Y-%m-%dT%H:%M:%SZ > "$out/logs/completed_at_utc.txt"

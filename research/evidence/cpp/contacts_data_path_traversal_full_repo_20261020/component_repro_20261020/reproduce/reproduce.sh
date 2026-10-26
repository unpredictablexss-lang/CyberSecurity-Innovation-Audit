#!/usr/bin/env bash
# End-to-end component-level reproduction of ohscanner-contacts-path-traversal-001.
#
# Prerequisites
#   * Linux (or WSL2) with docker + python3 + git
#   * a full clone of applications_contacts_data at the pinned commit
#   * docker image with clang++ 14:  IMAGE=ohscanner-validation:c1-ruby-20261019
#     (or build one:  docker build -t ohscanner-validation:c1-ruby-20261019 harness/)
#
# Usage
#   CONTACTS_REPO=/path/to/contacts_data ./reproduce/reproduce.sh
#   VERIFY_ONLY=1 ... ./reproduce/reproduce.sh      # provenance checks only
#   ASAN_ASLR=1 ... ./reproduce/reproduce.sh        # also run the ASan/ASLR analysis
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTACTS_REPO="${CONTACTS_REPO:-/home/deepsleep/opensource/contacts_data}"
IMAGE="${IMAGE:-ohscanner-validation:c1-ruby-20261019}"
OUT="${OUT:-$HERE/results/rerun}"
VERIFY_ONLY="${VERIFY_ONLY:-0}"
ASAN_ASLR="${ASAN_ASLR:-0}"

PIN_CONTACTS="341cc3bf41b48e9a5f278dd088f40a2041d2f1c9"
PIN_TREE="2054824c04bb403eeea128a9262edfb3001efa4f"

say() { printf '\n=== %s ===\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

[ -d "$CONTACTS_REPO" ] || die "CONTACTS_REPO not found: $CONTACTS_REPO"
mkdir -p "$OUT"

say "1. provenance: pinned commit and tree"
HEAD_SHA="$(git -C "$CONTACTS_REPO" rev-parse HEAD)"
TREE_SHA="$(git -C "$CONTACTS_REPO" rev-parse 'HEAD^{tree}')"
printf 'HEAD %s\nTREE %s\n' "$HEAD_SHA" "$TREE_SHA"
[ "$HEAD_SHA" = "$PIN_CONTACTS" ] || die "contacts HEAD is $HEAD_SHA, expected $PIN_CONTACTS"
[ "$TREE_SHA" = "$PIN_TREE" ] || die "tree is $TREE_SHA, expected $PIN_TREE"

say "2. re-extract 11 functions from source and verify hashes/line numbers"
python3 "$HERE/reproduce/verify_extraction.py" \
  --repo "$CONTACTS_REPO" \
  --manifest "$HERE/harness/generated/extraction_manifest.json" \
  --inc-dir "$OUT/generated" \
  --out-json "$OUT/verify_extraction.json" --write-inc

say "3. diff regenerated snippets against the shipped .inc files"
diff -r "$OUT/generated" "$HERE/harness/generated" -x extraction_manifest.json \
  && echo "snippets identical"

if [ "$VERIFY_ONLY" = "1" ]; then
  say "VERIFY_ONLY=1: stopping before dynamic execution"
  exit 0
fi

command -v docker >/dev/null || die "docker not found (use WSL2 or install docker)"
docker image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE not found"

say "4. build and run the 12 component cases (attack/fixed/safe/fixed-safe x3)"
rm -rf "$OUT/component"; mkdir -p "$OUT/component"; chmod 777 "$OUT/component"
docker run --rm --entrypoint /bin/sh \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --cpus=2 --memory=1g --pids-limit=128 --ulimit nofile=256:256 \
  -v "$HERE/harness":/sandbox/work:ro -v "$OUT/component":/sandbox/out \
  --tmpfs /tmp --tmpfs /data:rw,size=64m \
  "$IMAGE" /sandbox/work/run_ubsan_clang.sh
cat "$OUT/component/run_summary.tsv"

say "5. build and run the write-sink probe (contactId traversal, 3+3)"
mkdir -p "$OUT/write_probe/logs"; chmod -R 777 "$OUT/write_probe"
docker run --rm --entrypoint /bin/sh \
  -v "$HERE/harness":/sandbox/work:ro -v "$OUT/write_probe":/sandbox/out \
  --tmpfs /data:rw,size=64m \
  "$IMAGE" -c 'clang++ -std=c++17 -O0 -g /sandbox/work/write_probe.cpp -o /sandbox/out/write_probe &&
               clang++ -std=c++17 -O0 -g -DPATCHED_TARGET=1 /sandbox/work/patched_write_probe.cpp -o /sandbox/out/patched_write_probe'
for i in 1 2 3; do
  docker run --rm --entrypoint /bin/sh --tmpfs /data:rw,size=64m \
    -v "$OUT/write_probe":/sandbox/out:ro "$IMAGE" -c 'cd /sandbox/out && ./write_probe attack-write'
  docker run --rm --entrypoint /bin/sh --tmpfs /data:rw,size=64m \
    -v "$OUT/write_probe":/sandbox/out:ro "$IMAGE" -c 'cd /sandbox/out && ./patched_write_probe fixed-write'
done

if [ "$ASAN_ASLR" = "1" ]; then
  say "6. ASan/ASLR analysis (needs seccomp=unconfined for setarch -R)"
  mkdir -p "$OUT/asan"; chmod 777 "$OUT/asan"
  printf 'int main() { return 0; }\n' > "$OUT/asan/t.cpp"
  docker run --rm --entrypoint /bin/sh -v "$OUT/asan":/w \
    "$IMAGE" -c 'clang++ -fsanitize=address -O0 /w/t.cpp -o /w/t_asan'
  : > "$OUT/asan/trivial_20_runs.txt"
  for i in $(seq 1 20); do
    docker run --rm --entrypoint /bin/sh -v "$OUT/asan":/w:ro "$IMAGE" -c '/w/t_asan' >/dev/null 2>&1
    printf '%s ' "$?" >> "$OUT/asan/trivial_20_runs.txt"
  done
  echo >> "$OUT/asan/trivial_20_runs.txt"
  echo "(expected: a mix of 0 and 139 without ASLR control)" >> "$OUT/asan/trivial_20_runs.txt"
fi

say "DONE - compare $OUT with the recorded results under results/"

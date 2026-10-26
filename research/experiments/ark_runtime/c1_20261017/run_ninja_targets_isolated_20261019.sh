#!/usr/bin/env bash
set -euo pipefail

SOURCE=/home/deepsleep/c-line-c1-profile-20261018/openharmony-git-archive-20261019
PREBUILTS=/home/deepsleep/c-line-c1-profile-20261018/prebuilts-stage-20261019
TOOLCHAIN=/home/deepsleep/c-line-c1-profile-20261018/toolchain-20261019
VIEW=/home/deepsleep/c-line-c1-profile-20261018/c1-object-source-view-20261019
OUTPUT=/home/deepsleep/c-line-c1-profile-20261018/out-gn-20261019-retry3/rk3568
EVIDENCE=/home/deepsleep/c-line-c1-profile-20261018/ninja_isolated_build_attempt2_20261019
NINJA="$TOOLCHAIN/ninja"
PYTHON_ROOT="$TOOLCHAIN/linux-x86/3.12.10"
EXPECTED_NINJA_SHA256=2c867ca18771ff64d2a9f72f16316760651c98b1fbce692b0542f25de49b112b

mkdir -p "$EVIDENCE"
sha256sum "$NINJA" | awk -v expected="$EXPECTED_NINJA_SHA256" '$1 != expected { exit 1 }'

unshare --user --map-root-user --mount --net --fork /bin/bash -s -- \
  "$SOURCE" "$PREBUILTS" "$TOOLCHAIN" "$VIEW" "$OUTPUT" "$EVIDENCE" "$NINJA" "$PYTHON_ROOT" <<'INNER'
set -euo pipefail
source=$1
prebuilts=$2
toolchain=$3
view=$4
output=$5
evidence=$6
ninja=$7
python_root=$8

mount --make-rprivate /
mount --bind "$source" "$source"
mount -o remount,ro,bind "$source"
mount --bind "$prebuilts" "$prebuilts"
mount -o remount,ro,bind "$prebuilts"
mount --bind "$toolchain" "$toolchain"
mount -o remount,ro,bind "$toolchain"
mount --bind "$view" "$view"
mount -o remount,ro,bind "$view"
mount --bind "$output" "$view/out/rk3568"
mount -o remount,rw,bind "$view/out/rk3568"
mount --bind "$evidence" "$evidence"
mount -o remount,rw,bind "$evidence"
mount -t tmpfs -o size=512m tmpfs /tmp
mkdir -p /tmp/bin
ln -s "$python_root/bin/python3.12" /tmp/bin/python
ln -s "$python_root/bin/python3.12" /tmp/bin/python3
ln -s "$python_root/bin/python3.12" /tmp/bin/python3.12
export PATH="/tmp/bin:/usr/bin:/bin"
export PYTHONHOME="$python_root"
export LD_LIBRARY_PATH="$python_root/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

printf 'namespace_user=%s\n' "$(readlink /proc/self/ns/user)" > "$evidence/execution_boundary.txt"
printf 'namespace_mount=%s\n' "$(readlink /proc/self/ns/mnt)" >> "$evidence/execution_boundary.txt"
printf 'namespace_network=%s\n' "$(readlink /proc/self/ns/net)" >> "$evidence/execution_boundary.txt"
printf 'root_mount=' >> "$evidence/execution_boundary.txt"
findmnt -n -o TARGET,OPTIONS / >> "$evidence/execution_boundary.txt"
printf 'source_mount=' >> "$evidence/execution_boundary.txt"
findmnt -n -T "$source" -o TARGET,OPTIONS >> "$evidence/execution_boundary.txt"
printf 'toolchain_mount=' >> "$evidence/execution_boundary.txt"
findmnt -n -T "$toolchain" -o TARGET,OPTIONS >> "$evidence/execution_boundary.txt"
printf 'prebuilts_mount=' >> "$evidence/execution_boundary.txt"
findmnt -n -T "$prebuilts" -o TARGET,OPTIONS >> "$evidence/execution_boundary.txt"
printf 'source_view_mount=' >> "$evidence/execution_boundary.txt"
findmnt -n -T "$view" -o TARGET,OPTIONS >> "$evidence/execution_boundary.txt"
printf 'output_mount=' >> "$evidence/execution_boundary.txt"
findmnt -n -T "$view/out/rk3568" -o TARGET,OPTIONS >> "$evidence/execution_boundary.txt"
printf 'evidence_mount=' >> "$evidence/execution_boundary.txt"
findmnt -n -T "$evidence" -o TARGET,OPTIONS >> "$evidence/execution_boundary.txt"
findmnt -n -T "$source" -o OPTIONS | grep -Eq '(^|,)ro(,|$)'
findmnt -n -T "$prebuilts" -o OPTIONS | grep -Eq '(^|,)ro(,|$)'
findmnt -n -T "$toolchain" -o OPTIONS | grep -Eq '(^|,)ro(,|$)'
findmnt -n -T "$view" -o OPTIONS | grep -Eq '(^|,)ro(,|$)'
findmnt -n -T "$view/out/rk3568" -o OPTIONS | grep -Eq '(^|,)rw(,|$)'
findmnt -n -T "$evidence" -o OPTIONS | grep -Eq '(^|,)rw(,|$)'
printf 'ninja_version=%s\n' "$("$ninja" --version)" >> "$evidence/execution_boundary.txt"
printf 'python_version=%s\n' "$(python --version 2>&1)" >> "$evidence/execution_boundary.txt"
printf 'python_sha256=%s\n' "$(sha256sum "$python_root/bin/python3.12" | cut -d ' ' -f 1)" >> "$evidence/execution_boundary.txt"

targets=(
  obj/arkcompiler/ets_runtime/ecmascript/compiler/builtins/libark_jsoptimizer_set/builtins_typedarray_stub_builder.o
  obj/arkcompiler/ets_runtime/ecmascript/compiler/builtins/libark_jsoptimizer_set_with_maple/builtins_typedarray_stub_builder.o
)
for i in 0 1; do
  log="$evidence/target-$((i + 1)).log"
  set +e
  "$ninja" -C "$view/out/rk3568" -j2 -w dupbuild=warn "${targets[$i]}" > "$log" 2>&1
  rc=$?
  set -e
  printf 'target=%s\nreturncode=%s\nlog=%s\n' "${targets[$i]}" "$rc" "$log" > "$evidence/target-$((i + 1)).status"
  if (( rc != 0 )); then exit "$rc"; fi
done
INNER

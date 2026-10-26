#!/usr/bin/env bash
set -euo pipefail
BASE=/home/deepsleep/c-line-c1-profile-20261018
SOURCE=$BASE/openharmony-git-archive-20261019
PREBUILTS=$BASE/prebuilts-stage-20261019
TOOLCHAIN=$BASE/toolchain-20261019
VIEW=$BASE/c1-object-source-view-20261019
OUTPUT_ROOT=$BASE/out-gn-20261019-retry3
EVIDENCE=$BASE/ninja_isolated_build_attempt4_20261019
UPPER=$EVIDENCE/source-upper
WORK=$EVIDENCE/source-work
MOUNTPOINT=$EVIDENCE/source-overlay
NINJA=$TOOLCHAIN/ninja
PYTHON_ROOT=$TOOLCHAIN/linux-x86/3.12.10
EXPECTED_NINJA_SHA256=2c867ca18771ff64d2a9f72f16316760651c98b1fbce692b0542f25de49b112b
mkdir -p "$EVIDENCE" "$UPPER" "$WORK" "$MOUNTPOINT"
sha256sum "$NINJA" | awk -v expected="$EXPECTED_NINJA_SHA256" '$1 != expected { exit 1 }'
# Bind a fresh evidence directory for this run. Keep the exact source archive as the read-only lower layer.
unshare --user --map-root-user --mount --net --fork /bin/bash -s -- \
  "$SOURCE" "$PREBUILTS" "$TOOLCHAIN" "$VIEW" "$OUTPUT_ROOT" "$EVIDENCE" "$UPPER" "$WORK" "$MOUNTPOINT" "$NINJA" "$PYTHON_ROOT" <<'INNER'
set -euo pipefail
source=$1; prebuilts=$2; toolchain=$3; view=$4; output_root=$5; evidence=$6
upper=$7; work=$8; mountpoint=$9; ninja=${10}; python_root=${11}
mount --make-rprivate /
mount --bind "$source" "$source"
mount -o remount,ro,bind "$source"
mount --bind "$prebuilts" "$prebuilts"
mount -o remount,ro,bind "$prebuilts"
mount --bind "$toolchain" "$toolchain"
mount -o remount,ro,bind "$toolchain"
# Overlay the immutable source archive, then cover its original path so all source-view symlinks resolve through COW.
mount -t overlay overlay -o "lowerdir=$source,upperdir=$upper,workdir=$work,index=off,metacopy=off" "$mountpoint"
mount --bind "$mountpoint" "$source"
mount --bind "$view" "$view"
mount -o remount,ro,bind "$view"
mount --bind "$output_root" "$view/out"
mount -o remount,rw,bind "$view/out"
mount --bind "$evidence" "$evidence"
mount -o remount,rw,bind "$evidence"
mount -t tmpfs -o size=512m tmpfs /tmp
mkdir -p /tmp/bin
ln -s "$python_root/bin/python3.12" /tmp/bin/python
ln -s "$python_root/bin/python3.12" /tmp/bin/python3
ln -s "$python_root/bin/python3.12" /tmp/bin/python3.12
export PATH="/tmp/bin:/usr/bin:/bin" PYTHONHOME="$python_root"
export LD_LIBRARY_PATH="$python_root/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
{
  printf 'namespace_user=%s\n' "$(readlink /proc/self/ns/user)"
  printf 'namespace_mount=%s\n' "$(readlink /proc/self/ns/mnt)"
  printf 'namespace_network=%s\n' "$(readlink /proc/self/ns/net)"
  printf 'root_mount='; findmnt -n -o TARGET,OPTIONS /
  printf 'source_effective_mount='; findmnt -n -T "$source/third_party/musl/COPYRIGHT" -o TARGET,FSTYPE,OPTIONS
  printf 'toolchain_mount='; findmnt -n -T "$toolchain" -o TARGET,OPTIONS
  printf 'prebuilts_mount='; findmnt -n -T "$prebuilts" -o TARGET,OPTIONS
  printf 'source_view_mount='; findmnt -n -T "$view" -o TARGET,OPTIONS
  printf 'output_root_mount='; findmnt -n -T "$view/out" -o TARGET,OPTIONS
  printf 'product_output_mount='; findmnt -n -T "$view/out/rk3568" -o TARGET,OPTIONS
  printf 'evidence_mount='; findmnt -n -T "$evidence" -o TARGET,OPTIONS
  printf 'overlay_upper=%s\noverlay_work=%s\n' "$upper" "$work"
  printf 'ninja_sha256=%s\nninja_version=%s\n' "$(sha256sum "$ninja" | cut -d ' ' -f1)" "$($ninja --version)"
  printf 'python_sha256=%s\npython_version=%s\n' "$(sha256sum "$python_root/bin/python3.12" | cut -d ' ' -f1)" "$(python --version 2>&1)"
} > "$evidence/execution_boundary.txt"
findmnt -n -T "$source/third_party/musl/COPYRIGHT" -o FSTYPE | grep -qx overlay
findmnt -n -T "$prebuilts" -o OPTIONS | grep -Eq '(^|,)ro(,|$)'
findmnt -n -T "$toolchain" -o OPTIONS | grep -Eq '(^|,)ro(,|$)'
findmnt -n -T "$view" -o OPTIONS | grep -Eq '(^|,)ro(,|$)'
findmnt -n -T "$view/out" -o OPTIONS | grep -Eq '(^|,)rw(,|$)'
findmnt -n -T "$evidence" -o OPTIONS | grep -Eq '(^|,)rw(,|$)'
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

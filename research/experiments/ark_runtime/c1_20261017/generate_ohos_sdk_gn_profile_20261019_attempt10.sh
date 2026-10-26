#!/usr/bin/env bash
set -euo pipefail
BASE=/home/deepsleep/c-line-c1-profile-20261018
SOURCE=$BASE/openharmony-git-archive-20261019
PREBUILTS=$BASE/prebuilts-stage-20261019
PREBUILTS_VIEW=$BASE/ohos_sdk_prebuilts_view_20261019
SDK_ADDON=$BASE/prebuilts-stage-sdk-addon-20261019
TOOLCHAIN=$BASE/toolchain-20261019
VIEW=$BASE/c1-object-source-view-20261019
OUTPUT_ROOT=$BASE/out-sdk-source-20261019-attempt10
EVIDENCE=$BASE/ohos_sdk_source_gn_20261019-attempt10
UPPER=$EVIDENCE/source-upper
WORK=$EVIDENCE/source-work
MOUNTPOINT=$EVIDENCE/source-overlay
PYTHON_ROOT=$TOOLCHAIN/linux-x86/3.12.10
RUBY_ROOT=$BASE/ruby-runtime-stage-20261019/root
mkdir -p "$OUTPUT_ROOT" "$EVIDENCE" "$UPPER" "$WORK" "$MOUNTPOINT"
mkdir -p "$PREBUILTS_VIEW/build-tools/linux-x86/bin"
for child in "$PREBUILTS"/*; do
  name=${child##*/}
  [[ "$name" == build-tools ]] && continue
  [[ -e "$PREBUILTS_VIEW/$name" || -L "$PREBUILTS_VIEW/$name" ]] || ln -s "$child" "$PREBUILTS_VIEW/$name"
done
for child in "$PREBUILTS/build-tools"/*; do
  name=${child##*/}
  [[ "$name" == linux-x86 ]] && continue
  [[ -e "$PREBUILTS_VIEW/build-tools/$name" || -L "$PREBUILTS_VIEW/build-tools/$name" ]] || ln -s "$child" "$PREBUILTS_VIEW/build-tools/$name"
done
for child in "$PREBUILTS/build-tools/linux-x86/bin"/*; do
  name=${child##*/}
  [[ "$name" == gn ]] && child="$TOOLCHAIN/gn"
  [[ "$name" == ninja ]] && child="$TOOLCHAIN/ninja"
  [[ -e "$PREBUILTS_VIEW/build-tools/linux-x86/bin/$name" || -L "$PREBUILTS_VIEW/build-tools/linux-x86/bin/$name" ]] || ln -s "$child" "$PREBUILTS_VIEW/build-tools/linux-x86/bin/$name"
done
ln -sfn "$TOOLCHAIN/gn" "$PREBUILTS_VIEW/build-tools/linux-x86/bin/gn"
ln -sfn "$TOOLCHAIN/ninja" "$PREBUILTS_VIEW/build-tools/linux-x86/bin/ninja"
ln -sfn "$SDK_ADDON/cmake" "$PREBUILTS_VIEW/cmake"
rm -f "$PREBUILTS_VIEW/clang"
mkdir -p "$PREBUILTS_VIEW/clang/ohos/linux-x86_64"
ln -s "$SDK_ADDON/clang/ohos/linux-x86_64/llvm" "$PREBUILTS_VIEW/clang/ohos/linux-x86_64/llvm"
unshare --user --map-root-user --mount --net --fork /bin/bash -s -- \
  "$SOURCE" "$PREBUILTS" "$PREBUILTS_VIEW" "$TOOLCHAIN" "$SDK_ADDON" "$VIEW" "$OUTPUT_ROOT" "$EVIDENCE" "$UPPER" "$WORK" "$MOUNTPOINT" "$PYTHON_ROOT" "$RUBY_ROOT" <<'INNER'
set -euo pipefail
source=$1; prebuilts=$2; prebuilts_view=$3; toolchain=$4; sdk_addon=$5; view=$6; output_root=$7; evidence=$8
upper=$9; work=${10}; mountpoint=${11}; python_root=${12}; ruby_root=${13}
mount --make-rprivate /
mount --bind "$source" "$source"
mount -o remount,ro,bind "$source"
mount --bind "$prebuilts" "$prebuilts"
mount -o remount,ro,bind "$prebuilts"
mount --bind "$toolchain" "$toolchain"
mount -o remount,ro,bind "$toolchain"
mount --bind "$sdk_addon" "$sdk_addon"
mount -o remount,ro,bind "$sdk_addon"
mount --bind "$ruby_root" "$ruby_root"
mount -o remount,ro,bind "$ruby_root"
mount -t overlay overlay -o "lowerdir=$source,upperdir=$upper,workdir=$work,index=off,metacopy=off" "$mountpoint"
mount --bind "$mountpoint" "$source"
mkdir -p /src
mount --bind "$mountpoint" /src
mkdir -p /src/out
mount --bind "$prebuilts_view" /src/prebuilts
mount -o remount,ro,bind /src/prebuilts
mount -o remount,ro,bind /src
mount --bind "$output_root" /src/out
mount -o remount,rw,bind /src/out
mount --bind "$evidence" "$evidence"
mount -o remount,rw,bind "$evidence"
mount -t tmpfs -o size=1024m tmpfs /tmp
mkdir -p /tmp/bin
ln -s "$python_root/bin/python3.12" /tmp/bin/python
ln -s "$python_root/bin/python3.12" /tmp/bin/python3
ln -s "$python_root/bin/python3.12" /tmp/bin/python3.12
ln -s "$ruby_root/usr/bin/ruby3.2" /tmp/bin/ruby
export PATH="/tmp/bin:/usr/bin:/bin" PYTHONHOME="$python_root" HOME=/tmp PYTHONPYCACHEPREFIX=/tmp/pycache
export RUBYLIB="$ruby_root/usr/lib/ruby/3.2.0:$ruby_root/usr/lib/x86_64-linux-gnu/ruby/3.2.0"
export LD_LIBRARY_PATH="$python_root/lib:$ruby_root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
mount -o remount,ro,bind /
{
  printf 'network_namespace=%s\n' "$(readlink /proc/self/ns/net)"
  printf 'root_mount='; findmnt -n -T / -o OPTIONS
  printf 'source_mount='; findmnt -n -T /src/build/hb/main.py -o TARGET,FSTYPE,OPTIONS
  printf 'output_mount='; findmnt -n -T /src/out -o TARGET,FSTYPE,OPTIONS
  printf 'prebuilts_mount='; findmnt -n -T "$prebuilts" -o TARGET,OPTIONS
  printf 'prebuilts_view_gn_target=%s\n' "$(readlink -f /src/prebuilts/build-tools/linux-x86/bin/gn)"
  printf 'sdk_addon_mount='; findmnt -n -T "$sdk_addon" -o TARGET,OPTIONS
  printf 'cmake_binary_sha256=%s\ncmake_elf_machine=%s\n' "$(sha256sum /src/prebuilts/cmake/linux-aarch64/bin/cmake | cut -d ' ' -f1)" "$(od -An -tu2 -j18 -N2 /src/prebuilts/cmake/linux-aarch64/bin/cmake | tr -d ' ')"
  printf 'clang_notice_sha256=%s\nclang_binary_sha256=%s\n' "$(sha256sum /src/prebuilts/clang/ohos/linux-x86_64/llvm/NOTICE | cut -d ' ' -f1)" "$(sha256sum /src/prebuilts/clang/ohos/linux-x86_64/llvm/bin/clang | cut -d ' ' -f1)"
  printf 'toolchain_mount='; findmnt -n -T "$toolchain" -o TARGET,OPTIONS
  printf 'python_sha256=%s\npython_version=%s\n' "$(sha256sum "$python_root/bin/python3.12" | cut -d ' ' -f1)" "$(python --version 2>&1)"
  printf 'ruby_sha256=%s\nruby_version=%s\n' "$(sha256sum "$ruby_root/usr/bin/ruby3.2" | cut -d ' ' -f1)" "$(ruby --version 2>&1)"
} > "$evidence/execution_boundary.txt"
findmnt -n -T / -o OPTIONS | grep -Eq '(^|,)ro(,|$)'
findmnt -n -T /src/build/hb/main.py -o OPTIONS | grep -Eq '(^|,)ro(,|$)'
findmnt -n -T /src/prebuilts -o OPTIONS | grep -Eq '(^|,)ro(,|$)'
findmnt -n -T /src/out -o OPTIONS | grep -Eq '(^|,)rw(,|$)'
findmnt -n -T "$prebuilts" -o OPTIONS | grep -Eq '(^|,)ro(,|$)'
findmnt -n -T "$toolchain" -o OPTIONS | grep -Eq '(^|,)ro(,|$)'
findmnt -n -T "$sdk_addon" -o OPTIONS | grep -Eq '(^|,)ro(,|$)'
set +e
cd /src
python /src/build/hb/main.py build --product-name ohos-sdk --build-only-gn true --gn-flags=--export-compile-commands --ccache false --enable-pycache false --no-prebuilt-sdk true --clean-args false > "$evidence/hb_gn.log" 2>&1
rc=$?
set -e
printf 'returncode=%s\n' "$rc" > "$evidence/status.txt"
printf 'source_overlay_upper_files=%s\n' "$(find "$upper" -type f | wc -l)" >> "$evidence/status.txt"
find "$output_root" -maxdepth 3 -type f -printf '%P\n' | sort > "$evidence/output_file_list.txt"
sha256sum "$evidence/execution_boundary.txt" "$evidence/hb_gn.log" "$evidence/status.txt" "$evidence/output_file_list.txt" > "$evidence/SHA256SUMS"
exit "$rc"
INNER



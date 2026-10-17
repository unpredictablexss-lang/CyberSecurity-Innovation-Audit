#!/bin/sh
# Materialise the pinned pasteboard sources and build one binary per revision.
#
#   PASTEBOARD_REPO  local clone containing both commits (default below)
#   CUTILS_REPO      local c_utils checkout (default below)
#   OUT              build directory outside the repository (default below)
#
# The component and c_utils sources are read from local git objects and are
# never committed; only this script and the harness live in the repository.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PASTEBOARD_REPO=${PASTEBOARD_REPO:-/home/audit/wtmp/parcel_fix/pasteboard}
CUTILS_REPO=${CUTILS_REPO:-/home/audit/openharmony-targets/commonlibrary_c_utils}
OUT=${OUT:-/home/audit/wtmp/parcel_harness/build}

VULNERABLE=3287e85450f16d3f41801040abe35701131ad6f4
FIXED=ddee7c00d97d54423c6168fac994d3ef6204f385
CUTILS_COMMIT=3bdc11e00e7bf6e577cee300ad51045ca9958efd

CXX=${CXX:-clang++}
CXXFLAGS=${CXXFLAGS:--std=c++17 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -DCROSS_PLATFORM}

materialise() {
    revision=$1
    commit=$2
    target="$OUT/$revision"
    mkdir -p "$target/api"
    git -C "$PASTEBOARD_REPO" cat-file -e "$commit^{commit}"
    git -C "$PASTEBOARD_REPO" show "$commit:framework/tlv/message_parcel_warp.cpp" \
        > "$target/message_parcel_warp.cpp"
    git -C "$PASTEBOARD_REPO" show "$commit:framework/tlv/message_parcel_warp.h" \
        > "$target/message_parcel_warp.h"
    git -C "$PASTEBOARD_REPO" show "$commit:framework/framework/include/api/visibility.h" \
        > "$target/api/visibility.h"
    git -C "$PASTEBOARD_REPO" show "$commit:utils/native/include/pasteboard_hilog.h" \
        > "$target/pasteboard_hilog.h"
    echo "== $revision $commit"
    sha256sum "$target"/message_parcel_warp.cpp "$target"/message_parcel_warp.h \
        "$target"/pasteboard_hilog.h "$target"/api/visibility.h
}

git -C "$CUTILS_REPO" cat-file -e "$CUTILS_COMMIT^{commit}"
echo "== c_utils $CUTILS_COMMIT"
for source in parcel.cpp refbase.cpp string_ex.cpp unicode_ex.cpp ashmem.cpp; do
    sha256sum "$CUTILS_REPO/base/src/$source"
done

materialise vulnerable "$VULNERABLE"
materialise fixed "$FIXED"

for revision in vulnerable fixed; do
    "$CXX" $CXXFLAGS \
        -I"$HERE/shim" \
        -I"$OUT/$revision" \
        -I"$OUT/$revision/api" \
        -I"$CUTILS_REPO/base/include" \
        -I"$CUTILS_REPO/base/src" \
        "$HERE/harness.cpp" \
        "$OUT/$revision/message_parcel_warp.cpp" \
        "$CUTILS_REPO/base/src/parcel.cpp" \
        "$CUTILS_REPO/base/src/refbase.cpp" \
        "$CUTILS_REPO/base/src/string_ex.cpp" \
        "$CUTILS_REPO/base/src/unicode_ex.cpp" \
        "$CUTILS_REPO/base/src/ashmem.cpp" \
        -o "$OUT/$revision/harness"
    echo "built $OUT/$revision/harness"
done

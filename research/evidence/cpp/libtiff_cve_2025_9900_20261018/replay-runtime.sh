#!/usr/bin/env bash
set -euo pipefail
BASE=/mnt/d/openHarmonyScanner
SCANNER="$BASE/CyberSecurity-Innovation-Audit"
MIRROR="$BASE/tmp/libtiff-cve-2025-9900-upstream"
CMAKE="$BASE/tmp/oh-cmake-py312/cmake/data/bin/cmake"
HARNESS="$SCANNER/research/evidence/cpp/libtiff_cve_2025_9900_20261018/guard_page_repro.c"
ROOT="${REPLAY_ROOT:-$BASE/tmp/libtiff-cve-2025-9900-replay-$(date +%Y%m%d-%H%M%S)-$$}"
VULN=9dff73bebc5661f2dace6f16e14cf9e857172f4e
FIXED=3e0dcf0ec651638b2bd849b2e6f3124b36890d99

for command in git tar cc timeout; do command -v "$command" >/dev/null; done
test -x "$CMAKE"
test ! -e "$ROOT"
git -C "$MIRROR" cat-file -e "$VULN^{commit}"
git -C "$MIRROR" cat-file -e "$FIXED^{commit}"
mkdir -p "$ROOT/vulnerable/src" "$ROOT/fixed/src"
git -C "$MIRROR" archive "$VULN" | tar -x -C "$ROOT/vulnerable/src"
git -C "$MIRROR" archive "$FIXED" | tar -x -C "$ROOT/fixed/src"

configure() {
    local name=$1
    "$CMAKE" -S "$ROOT/$name/src" -B "$ROOT/$name/build" \
        -Dtiff-tools=OFF -Dtiff-tests=OFF -Dtiff-contrib=OFF \
        -Dtiff-docs=OFF -Dtiff-install=OFF -DBUILD_SHARED_LIBS=OFF \
        >"$ROOT/$name/configure.log" 2>&1
    "$CMAKE" --build "$ROOT/$name/build" --parallel 2 \
        >"$ROOT/$name/build.log" 2>&1
    cc -O0 -g -I"$ROOT/$name/src/libtiff" -I"$ROOT/$name/build/libtiff" \
        "$HARNESS" "$ROOT/$name/build/libtiff/libtiff.a" -lz -lm \
        -o "$ROOT/$name/guard-repro"
}
configure vulnerable
configure fixed

ulimit -c 0
set +e
timeout 5 "$ROOT/vulnerable/guard-repro" "$ROOT/vulnerable-trigger.tif" 1 \
    >"$ROOT/runtime-vulnerable-trigger.log" 2>&1
vulnerable_trigger=$?
timeout 5 "$ROOT/fixed/guard-repro" "$ROOT/fixed-trigger.tif" 1 \
    >"$ROOT/runtime-fixed-trigger.log" 2>&1
fixed_trigger=$?
timeout 5 "$ROOT/vulnerable/guard-repro" "$ROOT/vulnerable-safe.tif" 2 \
    >"$ROOT/runtime-vulnerable-safe.log" 2>&1
vulnerable_safe=$?
timeout 5 "$ROOT/fixed/guard-repro" "$ROOT/fixed-safe.tif" 2 \
    >"$ROOT/runtime-fixed-safe.log" 2>&1
fixed_safe=$?
set -e
printf 'vulnerable_trigger=%s fixed_trigger=%s vulnerable_safe=%s fixed_safe=%s\n' \
    "$vulnerable_trigger" "$fixed_trigger" "$vulnerable_safe" "$fixed_safe"
cat "$ROOT/runtime-vulnerable-trigger.log" "$ROOT/runtime-fixed-trigger.log" \
    "$ROOT/runtime-vulnerable-safe.log" "$ROOT/runtime-fixed-safe.log"
test "$vulnerable_trigger" -eq 139
test "$fixed_trigger" -eq 0
test "$vulnerable_safe" -eq 0
test "$fixed_safe" -eq 0

#!/usr/bin/env bash
set +e
BASE=/home/deepsleep/c-line-c1-profile-20261018
BUILD="$BASE/out-gn-20261019-retry3/rk3568"
SOURCE="$BASE/openharmony-git-archive-20261019"
NINJA="$BASE/toolchain-20261019/ninja"
OUT=/mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c1_20261017/ninja_sdk_input_query_20261019.txt
WARN=/mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c1_20261017/ninja_sdk_input_query_warnings_20261019.txt
TARGETS=/mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c1_20261017/ninja_sdk_targets_in_rk3568_graph_20261019.txt
{
  echo '=== QUERY SDK FILE ==='
  "$NINJA" -C "$BUILD" -w dupbuild=warn -t query ../../prebuilts/ohos-sdk/linux/26.0.1/native/sysroot/usr/lib/arm-linux-ohos/libbundle_ndk.z.so 2> "$WARN"
  echo '=== QUERY CONSUMER OUTPUT ==='
  "$NINJA" -C "$BUILD" -w dupbuild=warn -t query web/webview/libnweb_ohos_adapter.z.so 2>> "$WARN"
  echo '=== SDK CONFIG SOURCES ==='
  ls -l "$SOURCE/build/version.gni" "$SOURCE/build/prebuilts_config.json" "$SOURCE/build/prebuilts_config.sh" "$SOURCE/build/scripts/download_sdk.py" 2>&1
  grep -nE 'sdk_version|ohos-sdk-full-linux|download_sdk|libbundle_ndk' "$SOURCE/build/version.gni" "$SOURCE/build/prebuilts_config.json" "$SOURCE/build/prebuilts_config.sh" "$SOURCE/build/scripts/download_sdk.py" 2>/dev/null | head -100
} > "$OUT" 2>&1
echo "sdk_query_sha256=$(sha256sum "$OUT" | cut -d ' ' -f1)"
sha256sum "$WARN"
"$NINJA" -C "$BUILD" -w dupbuild=warn -t targets all 2>/dev/null | grep -iE '(^|[/_.:-])(ohos.?sdk|sdk_(api|compiler|native|package)|sdk.*(zip|tar))' | head -100 > "$TARGETS"
sha256sum "$TARGETS"

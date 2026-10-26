#!/usr/bin/env bash
set -uo pipefail
OUT=/mnt/d/openHarmonyScanner/CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c1_20261017/local_sdk_artifact_search_20261019.txt
{
  echo "search_started_utc=$(date -u +%FT%TZ)"
  for root in \
    /home/deepsleep/.prebuilts_cache \
    /home/deepsleep/c-line-c1-profile-20261018/prebuilts-stage-20261019 \
    /home/deepsleep/c-line-c1-profile-20261018/out-gn-20261019-retry3 \
    /mnt/d/OpenHarmony807/prebuilts \
    /mnt/d/OpenHarmony807/out; do
    if [[ -d "$root" ]]; then
      echo "=== $root ==="
      timeout 90s find "$root" -type f \( -name libbundle_ndk.z.so -o -iname 'ohos-sdk-full-linux*.tar*' -o -iname 'ohos-sdk-full-linux*.zip' \) -print 2>&1
      echo "find_status=$?"
    else
      echo "=== absent: $root ==="
    fi
  done
  echo "search_finished_utc=$(date -u +%FT%TZ)"
} > "$OUT"
sha256sum "$OUT"

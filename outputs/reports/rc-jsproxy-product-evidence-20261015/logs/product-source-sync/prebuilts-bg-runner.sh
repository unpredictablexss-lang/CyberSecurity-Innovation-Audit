#!/bin/bash
set -o pipefail
cd /home/audit/ohos-rk3568-product || exit 125
{
  date --iso-8601=seconds
  echo "network_action=background resume OpenHarmony prebuilts download"
  echo "command=bash build/prebuilts_download.sh"
  bash build/prebuilts_download.sh
  rc=$?
  echo "exit=$rc"
  date --iso-8601=seconds
  exit "$rc"
} > /home/audit/prebuilts-bg.log 2>&1
rc=$?
printf '%s\n' "$rc" > /home/audit/prebuilts-bg.exit
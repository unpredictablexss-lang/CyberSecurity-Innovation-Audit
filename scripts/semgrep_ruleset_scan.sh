#!/usr/bin/env bash
#
# Semgrep ruleset scan for the OpenHarmony historical benchmark.
#
# Replaces the previous ad-hoc "local generic rules" file (which contained the
# pure-noise rule `deref-after-arrow`, pattern `$P->$FIELD`). The ruleset here is
# assembled from three sources:
#
#   1. vendor/raptor  - 0xdea/semgrep-rules (MIT), the only maintained public
#                       Semgrep ruleset that declares `languages: [c, cpp]`.
#   2. rules/cpp      - OpenHarmony-specific rules derived from historical fixes
#                       (oh_shared_ptr_uaf, oh_nothrow_null_deref).
#   3. p/security-audit (optional, network) - official Semgrep registry rules.
#                       The free registry only ships `c.lang.*` rules; its 154
#                       `cpp.*` rules are paywalled pro rules. Set WITH_REGISTRY=0
#                       for a fully offline run.
#
# Usage:
#   scripts/semgrep_ruleset_scan.sh FILE_OR_DIR [FILE_OR_DIR ...]
#
# Environment:
#   SEMGREP        semgrep binary                     (default: semgrep)
#   OUT_DIR        output directory for JSON          (default: outputs/reports/semgrep)
#   WITH_REGISTRY  1 to add p/security-audit, 0 to stay offline (default: 1)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEMGREP="${SEMGREP:-semgrep}"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/outputs/reports/semgrep}"
WITH_REGISTRY="${WITH_REGISTRY:-1}"

if [ "$#" -eq 0 ]; then
    echo "usage: $0 FILE_OR_DIR [FILE_OR_DIR ...]" >&2
    exit 2
fi

config_args=(
    --config "$REPO_ROOT/rules/cpp/vendor/raptor"
    --config "$REPO_ROOT/rules/cpp"
)
if [ "$WITH_REGISTRY" = "1" ]; then
    config_args+=(--config p/security-audit)
fi

mkdir -p "$OUT_DIR"
status=0

for target in "$@"; do
    if [ ! -e "$target" ]; then
        echo "skip (missing): $target" >&2
        status=1
        continue
    fi
    name="$(printf '%s' "$target" | tr '/\\:' '___' | sed 's/^_*//')"
    out="$OUT_DIR/${name}.json"
    echo "==> $target"
    "$SEMGREP" \
        "${config_args[@]}" \
        --metrics=off \
        --quiet \
        --json \
        "$target" \
        -o "$out" \
        || { echo "    semgrep failed for $target" >&2; status=1; continue; }
    "$SEMGREP" --version >/dev/null 2>&1 || true
    python3 - "$out" <<'PY' || true
import json, sys, collections
d = json.load(open(sys.argv[1]))
ids = collections.Counter(r["check_id"] for r in d["results"])
print(f"    results: {len(d['results'])}")
for cid, n in ids.most_common():
    print(f"      {n:3d}  {cid}")
PY
done

exit "$status"

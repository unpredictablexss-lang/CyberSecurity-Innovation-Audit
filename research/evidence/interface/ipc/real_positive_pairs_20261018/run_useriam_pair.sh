#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(git rev-parse --show-toplevel)"
TARGET="${1:-$HOME/oh-audit-targets/useriam_auth_executor_mgr}"
OUT="${2:-/tmp/ohscanner-useriam-auth01-pair}"
if [[ ! -d "$TARGET/.git" ]]; then
  git clone https://gitee.com/openharmony/useriam_auth_executor_mgr.git "$TARGET"
fi
git -C "$TARGET" cat-file -e 48f3ba7c220f18244f908f0452527304349e850c^{commit}
git -C "$TARGET" cat-file -e 9f35fade871d3cf15acb6191e965a8582bea201e^{commit}
mkdir -p "$OUT"
cd "$PROJECT_ROOT"
.venv-web/bin/python -m src.cli ohscan-run --repo-dir "$TARGET" --repository openharmony/useriam_auth_executor_mgr --commit 48f3ba7c220f18244f908f0452527304349e850c --detector ohscanner.interface.ipc --json-out "$OUT/useriam-auth-vuln.json" --md-out "$OUT/useriam-auth-vuln.md"
.venv-web/bin/python -m src.cli ohscan-run --repo-dir "$TARGET" --repository openharmony/useriam_auth_executor_mgr --commit 9f35fade871d3cf15acb6191e965a8582bea201e --detector ohscanner.interface.ipc --json-out "$OUT/useriam-auth-fixed.json" --md-out "$OUT/useriam-auth-fixed.md"

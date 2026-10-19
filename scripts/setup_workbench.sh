#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
VENV_PATH="${OHSCANNER_VENV:-.venv-web}"
python3 -m venv "$VENV_PATH"
"$VENV_PATH/bin/python" -m pip install -r requirements-web.txt
(
  cd web
  npm ci
  npm run build
)
echo "Ready: bash scripts/start_workbench.sh"

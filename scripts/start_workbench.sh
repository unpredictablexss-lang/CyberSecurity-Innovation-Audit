#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
VENV_PATH="${OHSCANNER_VENV:-.venv-web}"
exec "$VENV_PATH/bin/python" -m src.workbench serve "$@"

#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
# SQLite, locks and Python environments belong on WSL's Linux filesystem.
# Hash the source location so separate checkouts never share a database.
install_key=$(printf '%s' "$PWD" | sha256sum)
export OHSCANNER_DEPLOY_HOME=${OHSCANNER_DEPLOY_HOME:-"$HOME/.local/share/ohscanner/windows-${install_key:0:16}"}
echo "Runtime and data: $OHSCANNER_DEPLOY_HOME"
export OHSCANNER_SMOKE_HOLD_SECONDS=5
exec bash ./deploy-linux.sh "$@"

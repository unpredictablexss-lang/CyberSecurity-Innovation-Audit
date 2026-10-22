#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
# SQLite, locks and Python environments belong on WSL's Linux filesystem.
# Hash the source location so separate checkouts never share a database.
install_key=$(printf '%s' "$PWD" | sha256sum)
export OHSCANNER_DEPLOY_HOME=${OHSCANNER_DEPLOY_HOME:-"$HOME/.local/share/ohscanner/windows-${install_key:0:16}"}
echo "Runtime and data: $OHSCANNER_DEPLOY_HOME"
case $(uname -m) in
  x86_64) node_arch=x64 ;;
  aarch64|arm64) node_arch=arm64 ;;
  *) echo 'Unsupported Node architecture' >&2; exit 1 ;;
esac
export OHSCANNER_NODE_ARCHIVE="$PWD/.deploy/downloads/node-v22.16.0-linux-$node_arch.tar.xz"
export OHSCANNER_SMOKE_HOLD_SECONDS=5
exec bash ./deploy-linux.sh "$@"

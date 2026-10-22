#!/usr/bin/env bash
# Debian 12+/Ubuntu 22.04+, including WSL2. Run from a source checkout or ZIP.
set -Eeuo pipefail
trap 'echo "Deployment failed at line $LINENO. Fix the error above and rerun; data is preserved." >&2' ERR
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT"
PORT=8765
MODE=serve
while (($#)); do
  case "$1" in
    --port) PORT=${2:?Missing port}; shift 2 ;;
    --setup-only) MODE=setup; shift ;;
    --smoke-test) MODE=smoke; shift ;;
    --start-only) MODE=start; shift ;;
    -h|--help) echo 'Usage: bash deploy-linux.sh [--port 8765] [--setup-only|--smoke-test|--start-only]'; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$PORT" =~ ^[0-9]{4,5}$ ]] && ((10#$PORT >= 1024 && 10#$PORT <= 65535)) || { echo 'Port must be 1024..65535' >&2; exit 2; }
[[ $(uname -s) == Linux ]] || { echo 'Linux required. On Windows run deploy-windows.cmd.' >&2; exit 2; }
STATE=${OHSCANNER_DEPLOY_HOME:-"$ROOT/.deploy"}
mkdir -p "$STATE"
STATE=$(cd "$STATE" && pwd)
export OHSCANNER_VENV=${OHSCANNER_VENV:-"$STATE/venv"}
# Do not replace an operator configuration or inherit another installation's data by default.
if [[ -z ${OHSCANNER_CONFIG:-} && ! -f "$ROOT/config/workbench.local.json" ]]; then
  export OHSCANNER_DATA=${OHSCANNER_DATA:-"$STATE/data"}
  export OHSCANNER_TARGET_ROOTS=${OHSCANNER_TARGET_ROOTS:-"$STATE/targets"}
  mkdir -p "$OHSCANNER_DATA" "$STATE/targets"
fi
if [[ "$MODE" == start ]]; then
  [[ -x "$OHSCANNER_VENV/bin/python" && -f "$ROOT/web/dist/index.html" ]] || { echo 'Run deploy-linux.sh once before start-linux.sh.' >&2; exit 1; }
  exec 9>"$STATE/deploy.lock"
  flock -n 9 || { echo "Deployment already running for $STATE" >&2; exit 1; }
  exec "$OHSCANNER_VENV/bin/python" -m src.workbench serve --port "$PORT"
fi
need_packages=0
for cmd in python3 git curl xz flock; do command -v "$cmd" >/dev/null || need_packages=1; done
python3 -c 'import sys,venv,ensurepip; assert sys.version_info >= (3,10)' 2>/dev/null || need_packages=1
[[ -f /etc/ssl/certs/ca-certificates.crt ]] || need_packages=1
if ((need_packages)); then
  command -v apt-get >/dev/null || { echo 'Automatic bootstrap supports Debian/Ubuntu. Install Python 3.10+ with venv, Git, curl, xz-utils and util-linux, then rerun.' >&2; exit 1; }
  SUDO=()
  if ((EUID != 0)); then
    command -v sudo >/dev/null || { echo 'Run as root or install sudo to install OS dependencies.' >&2; exit 1; }
    SUDO=(sudo)
  fi
  "${SUDO[@]}" apt-get update
  "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv git curl ca-certificates xz-utils util-linux
fi
exec 9>"$STATE/deploy.lock"
flock -n 9 || { echo "Deployment already running for $STATE" >&2; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
# A private Node runtime avoids changing a machine's existing Node installation.
NODE_VERSION=22.16.0
case $(uname -m) in
  x86_64) NODE_ARCH=x64; NODE_SHA=f4cb75bb036f0d0eddf6b79d9596df1aaab9ddccd6a20bf489be5abe9467e84e ;;
  aarch64|arm64) NODE_ARCH=arm64; NODE_SHA=eab80cb88f8fda1e65f5e8d0420c9809bdb320b03fd34976ab7161b6e703b910 ;;
  *) echo 'Automatic Node bootstrap supports x86_64 and arm64.' >&2; exit 1 ;;
esac
NODE_DIR="$STATE/node-v$NODE_VERSION-linux-$NODE_ARCH"
if [[ ! -x "$NODE_DIR/bin/node" ]]; then
  NODE_TAR="$STATE/node-v$NODE_VERSION-linux-$NODE_ARCH.tar.xz"
  curl --fail --location --retry 3 --connect-timeout 20 "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$NODE_ARCH.tar.xz" -o "$NODE_TAR"
  echo "$NODE_SHA  $NODE_TAR" | sha256sum -c -
  tar -xJf "$NODE_TAR" -C "$STATE"
fi
export PATH="$NODE_DIR/bin:$PATH"
python3 -m venv "$OHSCANNER_VENV"
"$OHSCANNER_VENV/bin/python" -m pip install --disable-pip-version-check -r requirements-web.txt
(cd web && npm ci --no-audit --no-fund && npm run build)
if [[ "$MODE" == setup ]]; then echo 'Setup complete.'; exit 0; fi
if [[ "$MODE" == smoke ]]; then
  exec "$OHSCANNER_VENV/bin/python" scripts/deploy_smoke.py --port "$PORT" --hold-seconds "${OHSCANNER_SMOKE_HOLD_SECONDS:-0}"
fi
exec "$OHSCANNER_VENV/bin/python" -m src.workbench serve --port "$PORT"

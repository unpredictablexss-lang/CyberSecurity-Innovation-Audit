#!/usr/bin/env bash
# Local patch migration only. No push, reset, core merge or catalog modification.
set -euo pipefail
windows_source="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
destination="${1:-$HOME/projects/CyberSecurity-Innovation-Audit}"
base_sha=dcd9629f50a34545d75abc92c0a16c79723197db
core_sha=8c5c9d9b77857d9ccf41d101be6068f287453e81
patch="$windows_source/.tmp/interface-main.patch"
[[ -f "$patch" ]] || { echo "Missing prepared patch: $patch" >&2; exit 1; }
[[ ! -e "$destination" ]] || { echo "Choose a new destination; existing directory retained: $destination" >&2; exit 1; }
. /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 22.04 ]] || { echo "Requires Ubuntu 22.04" >&2; exit 1; }
command -v git >/dev/null || { echo "Install git first: sudo apt-get install git" >&2; exit 1; }
command -v python3 >/dev/null || { echo "Install python3 first" >&2; exit 1; }
mkdir -p "$(dirname "$destination")"
git clone --no-hardlinks --branch feat/oh-interface-detectors "$windows_source" "$destination"
cd "$destination"
[[ "$(git rev-parse HEAD)" == "$base_sha" ]] || { echo "Local source branch base changed; refresh migration patch" >&2; exit 1; }
git remote set-url origin https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git
git apply --check "$patch"
git apply "$patch"
python3 -m venv .venv || { echo "Install venv: sudo apt-get install python3-venv; continue in $destination" >&2; exit 1; }
.venv/bin/python -m pip install -r requirements.txt -c research/experiments/interface/parser_constraints.txt
mkdir -p outputs/logs .tmp
export TMPDIR="$destination/.tmp"
.venv/bin/python -m unittest discover -s tests -v > outputs/logs/ubuntu-full-tests.log 2>&1 || { tail -n 60 outputs/logs/ubuntu-full-tests.log; exit 1; }
tail -n 8 outputs/logs/ubuntu-full-tests.log
cache=research/experiments/interface/local_sources
if [[ -d "$windows_source/$cache" ]]; then
    mkdir -p "$(dirname "$cache")"
    cp -R "$windows_source/$cache" "$cache"
    .venv/bin/python -m research.experiments.interface.replay_ipc_inventory > outputs/logs/ubuntu-ipc-inventory.log
fi
# Test against actual core contracts without merging owner's commits into B's branch.
git fetch "$windows_source" "$core_sha"
core_test="$destination/.tmp/core-compatibility"
git worktree add --detach "$core_test" "$core_sha"
git -C "$core_test" apply --check --exclude=PROGRAM_STATUS.md --exclude=.gitignore "$patch"
git -C "$core_test" apply --exclude=PROGRAM_STATUS.md --exclude=.gitignore "$patch"
(cd "$core_test"; "$destination/.venv/bin/python" -m unittest tests.detectors.interface.test_core_adapter -v) > outputs/logs/ubuntu-core-adapter-tests.log 2>&1
cat outputs/logs/ubuntu-core-adapter-tests.log
git status --short
echo "Local migration and verification complete. No push or commit performed."

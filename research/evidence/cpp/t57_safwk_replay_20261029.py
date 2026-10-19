#!/usr/bin/env python3
"""Reproduce T57 per-file current IPC replays for A0 CR-0247–CR-0251."""
from pathlib import Path
import argparse
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from src.ohscanner.execution import run_fixed_commit_scan

COMMIT = "21c83c874a34e8d28e6a355a3b56e5167252ed27"
SCOPES = {
    "listen": ("test/services/safwk/unittest/listen_ability/src/listen_ability_stub.cpp",),
    "probe": ("test/services/safwk/unittest/multi_instance_test_probe/src/multi_instance_test_probe.cpp",),
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-repo", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args()
    for name, paths in SCOPES.items():
        run_fixed_commit_scan(args.source_repo, "openharmony/systemabilitymgr_safwk", COMMIT,
                              paths, ("ohscanner.interface.ipc",),
                              args.out_dir / f"t57_safwk_{name}_cli_20261029.json",
                              args.out_dir / f"t57_safwk_{name}_cli_20261029.md")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Replay the approved IPC detector on the exact CR-0313 source object."""
from pathlib import Path
import argparse

from src.ohscanner.execution import run_fixed_commit_scan


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--md-out", type=Path, required=True)
    args = parser.parse_args()
    run_fixed_commit_scan(
        args.source_repo,
        "openharmony/customization_enterprise_device_management",
        "e1e278bc85dc0277ab79cfdc029558a61492d3da",
        ("test/unittest/services/edm/src/system_timer_manager_test.cpp",),
        ("ohscanner.interface.ipc",),
        args.json_out,
        args.md_out,
    )


if __name__ == "__main__":
    main()

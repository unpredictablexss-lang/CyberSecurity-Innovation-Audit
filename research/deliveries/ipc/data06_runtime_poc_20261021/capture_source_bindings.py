#!/usr/bin/env python3
"""Capture byte-exact source identities for the DATA-06 candidate and fix."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def git(repo: Path, *args: str, raw: bool = False):
    result = subprocess.run(
        ["git", "-C", str(repo), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return result.stdout if raw else result.stdout.decode("utf-8").strip()


def file_binding(repo: Path, commit: str, path: str) -> dict:
    tree_row = git(repo, "ls-tree", commit, path)
    blob = tree_row.split()[2]
    content = git(repo, "show", f"{commit}:{path}", raw=True)
    return {
        "path": path,
        "blob_oid": blob,
        "source_sha256": hashlib.sha256(content).hexdigest(),
        "bytes": len(content),
    }


def commit_binding(repo: Path, commit: str, paths: tuple[str, ...]) -> dict:
    fields = git(repo, "show", "-s", "--format=%H%n%T%n%P%n%cs%n%s", commit).splitlines()
    return {
        "commit": fields[0],
        "tree": fields[1],
        "parents": fields[2].split(),
        "commit_date": fields[3],
        "subject": fields[4],
        "files": [file_binding(repo, commit, path) for path in paths],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ipc-git", type=Path, required=True)
    parser.add_argument("--scanner-git", type=Path, required=True)
    parser.add_argument("--scanner-commit", required=True)
    parser.add_argument("--scanner-closeout-commit", required=True)
    parser.add_argument("--scanner-delivery-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    ipc_paths = (
        "interfaces/innerkits/cj/src/message_sequence_impl.cpp",
        "interfaces/innerkits/cj/src/ipc_ffi.cpp",
        "interfaces/innerkits/cj/include/ipc_ffi.h",
        "interfaces/innerkits/cj/BUILD.gn",
    )
    scanner_paths = (
        "src/ohscanner/detectors/interface/detector.py",
        "src/ohscanner/detectors/interface/ffi_array_bounds.py",
        "src/ohscanner/detectors/interface/families/data06.py",
        "src/ohscanner/detectors/interface/models.py",
        "tests/test_ipc_t74_cj_array_bounds_integration_challenge.py",
        "tests/test_workbench.py",
        "web/src/pages/JobDetail.tsx",
    )
    commits = {
        "candidate_parent_of_fix": commit_binding(
            args.ipc_git, "84d681288793785e8f39f71c824f211edaed8f1e", ipc_paths
        ),
        "candidate_secondary_revision": commit_binding(
            args.ipc_git, "67cd9d3e8e08971ba614a19f99b5f6b7ec4ea039", ipc_paths
        ),
        "official_fix": commit_binding(
            args.ipc_git, "de3a68cc8b7d6f18017fd261060def0e38dce54a", ipc_paths
        ),
    }
    scanner = commit_binding(args.scanner_git, args.scanner_commit, scanner_paths)
    closeout = commit_binding(args.scanner_git, args.scanner_closeout_commit, scanner_paths)
    payload = {
        "schema_version": 1,
        "official_source_remote": git(args.ipc_git, "remote", "get-url", "origin"),
        "candidate_family": "DATA-06",
        "detector": "ohscanner.interface.ipc@0.12.13",
        "model": "oh-ipc-2026.10-v33",
        "rule": "ipc.parcel.array-allocation-width@0.1.0",
        "cwe": "CWE-131",
        "possible_consequence": "out_of_bounds_write / CWE-787",
        "scanner_mainline": scanner,
        "scanner_b_closeout": closeout,
        "scanner_delivery": commit_binding(
            args.scanner_git, args.scanner_delivery_commit, scanner_paths
        ),
        "ipc_source_objects": commits,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()

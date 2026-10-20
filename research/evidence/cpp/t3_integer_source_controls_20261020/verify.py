#!/usr/bin/env python3
"""Verify source bindings and pinned CLI metadata for T3 source-control closeout."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


SCANNER_BASE = "81dd4aea9bb51522ac912b33504ef0d2ddb79089"
SOURCE_REPO = "openharmony/arkcompiler_ets_runtime"
CONTROL_COMMIT = "aeee3fd12c03193545edea4b8e0fdfa3d9a03d11"
CONTROL_TREE = "0eea26c9eb6846f4d19926be83092c06f0d98692"
CONTROL_PATH = "ecmascript/base/array_helper.cpp"
CONTROL_BLOB = "ce74b02e5a2df9f434d982ea09440ce9f33f1dd9"
CONTROL_SHA256 = "861f37ecc33fa5a890279606e4a740ba26216c60158b802f537199b74a8d578f"
REPORT = Path(__file__).with_name("cve2025-23420-sort-indexed-properties.json")

BOUND_SOURCE = {
    "0587-vulnerable": (
        "cae11f121c030a90ba41d8e4d866f91292f25892",
        "61ff01d9a06b4186125a04e2b790e07640f57198",
        "ecmascript/base/atomic_helper.cpp",
        "7fd67717571c6d8fe7b10bf294998e952dc61e36",
        "f4890391896239c845bbcaee489d83c85eb5a64e37d563b91ed6e3908c62a541",
    ),
    "0587-fixed": (
        "5aa9c035e98911ec7ed28065a2138c2709792a42",
        "05ac3902979e37ae08efa2d1e3ed32472a69d0cc",
        "ecmascript/base/atomic_helper.cpp",
        "80d7ad14e70825ef2daf7b3f2fc956a891bf8b2c",
        "39521f4c6fa6b4b65d8b3daacd80f6e051b5a01c5aa814c9ac2ffc432529b36b",
    ),
    "23420-vulnerable": (
        CONTROL_COMMIT,
        CONTROL_TREE,
        "ecmascript/js_array.cpp",
        "2c58914ad27b6b3c5f570dbd2fe0ed02d1d9e471",
        "b7f28be2f63850ba1cb57a35d518930986855784d2081124e555f2a57d673e9b",
    ),
    "23420-control": (
        CONTROL_COMMIT,
        CONTROL_TREE,
        CONTROL_PATH,
        CONTROL_BLOB,
        CONTROL_SHA256,
    ),
}


def git(git_dir: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(git_dir), *args], text=True).strip()


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", type=Path, required=True)
    parser.add_argument("--scanner-git-dir", type=Path, required=True)
    args = parser.parse_args()

    if git(args.scanner_git_dir, "rev-parse", "HEAD") != SCANNER_BASE:
        fail("scanner checkout is not the required 81dd baseline")

    for label, (commit, tree, path, blob, sha256) in BOUND_SOURCE.items():
        actual_tree = git(args.source_git_dir, "rev-parse", f"{commit}^{{tree}}")
        actual_blob = git(args.source_git_dir, "rev-parse", f"{commit}:{path}")
        raw = subprocess.check_output(["git", "-C", str(args.source_git_dir), "cat-file", "blob", blob])
        actual_sha = hashlib.sha256(raw).hexdigest()
        if (actual_tree, actual_blob, actual_sha) != (tree, blob, sha256):
            fail(f"source identity mismatch: {label}")

    report = json.loads(REPORT.read_text(encoding="utf-8"))
    if report.get("repository") != SOURCE_REPO or report.get("commit") != CONTROL_COMMIT:
        fail("raw scan target repository/commit mismatch")
    if report.get("git_tree") != CONTROL_TREE or report.get("status") != "completed":
        fail("raw scan tree/status mismatch")
    scope = report.get("scope", {})
    if scope.get("declared_scope") != [CONTROL_PATH] or scope.get("selected_source_files") != 1:
        fail("raw scan declared/selected scope mismatch")
    run = report.get("detector_runs", [{}])[0]
    if (run.get("tool"), run.get("tool_version"), run.get("status"), run.get("diagnostic_count")) != (
        "ohscanner.cpp.bounds",
        "0.3.0",
        "completed",
        0,
    ):
        fail("raw detector metadata/result mismatch")
    parses = run.get("parsing", [])
    if len(parses) != 1 or parses[0].get("file") != CONTROL_PATH or parses[0].get("status") != "complete":
        fail("raw parse coverage is not complete for the control file")
    file_meta = report.get("audit_plan", {}).get("source", {}).get("files", [])
    if len(file_meta) != 1 or file_meta[0].get("blob_oid") != CONTROL_BLOB or file_meta[0].get("sha256") != CONTROL_SHA256:
        fail("raw report source blob/SHA mismatch")

    print("PASS_SOURCE_IDENTITY_AND_CONTROL_REPLAY_METADATA")
    print("- scanner baseline: " + SCANNER_BASE)
    print("- verified source bindings: " + ", ".join(BOUND_SOURCE))
    print("- 23420 snapshot control: complete parse, bounds 0.3.0, zero candidates")
    print("- 0587: bindings verified; no root-specific production control claimed")


if __name__ == "__main__":
    main()

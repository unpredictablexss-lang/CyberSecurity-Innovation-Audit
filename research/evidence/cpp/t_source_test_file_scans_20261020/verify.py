#!/usr/bin/env python3
"""Verify pinned source identities and scan metadata for upstream test files."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


EXPECTED = {
    "cve2025-0587-atomic-helper-test.json": {
        "commit": "cae11f121c030a90ba41d8e4d866f91292f25892",
        "path": "ecmascript/base/tests/atomic_helper_test.cpp",
        "detector": "ohscanner.cpp.integer_bounds",
        "version": "0.2.0",
        "sha256": "a15f57aa48e3d2256713fdd0db959dbe7fd79538d83b4ed4686949b219ddb630",
        "blob": "ca2806418b4189d0ccc4a7b55f7b8cc9291abb1f",
    },
    "cve2025-23420-js-array-test.json": {
        "commit": "aeee3fd12c03193545edea4b8e0fdfa3d9a03d11",
        "path": "ecmascript/tests/js_array_test.cpp",
        "detector": "ohscanner.cpp.bounds",
        "version": "0.3.0",
        "sha256": "cf4c6eb657953e5c25ac2ec3d75d89ae521e40935e7f542d65f9e4e8fce56241",
        "blob": "a9a35d082d05b8dbd5ed1b40c8154394fefa2567",
    },
}


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    errors: list[str] = []
    results = []
    for filename, expected in EXPECTED.items():
        report = json.loads((args.evidence_dir / filename).read_text(encoding="utf-8"))
        commit, path = expected["commit"], expected["path"]
        data = subprocess.check_output(["git", "-C", str(args.source_git_dir), "show", f"{commit}:{path}"])
        tree = git(args.source_git_dir, "rev-parse", f"{commit}^{{tree}}")
        blob = git(args.source_git_dir, "rev-parse", f"{commit}:{path}")
        sha256 = hashlib.sha256(data).hexdigest()
        runs = [run for run in report.get("detector_runs", []) if run.get("tool") == expected["detector"]]
        if len(runs) != 1:
            errors.append(f"{filename}: expected exactly one matching detector run")
            continue
        run = runs[0]
        parsing = run.get("parsing", [])
        actual = (
            report.get("commit"), report.get("git_tree"), report.get("scope", {}).get("declared_scope"),
            run.get("tool_version"), run.get("status"), run.get("diagnostic_count"),
            parsing[0].get("file") if len(parsing) == 1 else None,
            parsing[0].get("status") if len(parsing) == 1 else None,
        )
        wanted = (commit, tree, [path], expected["version"], "completed", 0, path, "complete")
        if actual != wanted:
            errors.append(f"{filename}: report run/scope/parse mismatch: {actual!r}")
        if blob != expected["blob"] or sha256 != expected["sha256"]:
            errors.append(f"{filename}: source blob or SHA-256 mismatch")
        results.append({"report": filename, "commit": commit, "tree": tree, "path": path,
                        "blob": blob, "sha256": sha256, "detector": expected["detector"],
                        "version": run.get("tool_version"), "parse": actual[-1],
                        "diagnostic_count": run.get("diagnostic_count"),
                        "interpretation": "source-bound test-file observation; not a safe/unrelated control"})
    print(json.dumps({"status": "PASS_SOURCE_IDENTITY_AND_SCAN_METADATA" if not errors else "FAIL",
                      "results": results, "errors": errors}, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())

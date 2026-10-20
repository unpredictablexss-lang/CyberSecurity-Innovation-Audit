#!/usr/bin/env python3
"""Verify pinned source identities and scan metadata for upstream sources."""

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

PRODUCTION_CONTROLS = {
    "cve2025-0587-dataview-adjacent.json": {
        "commit": "cae11f121c030a90ba41d8e4d866f91292f25892",
        "path": "ecmascript/builtins/builtins_dataview.cpp",
        "detector": "ohscanner.cpp.integer_bounds",
        "version": "0.2.0",
        "sha256": "e26279b7c341ded1962aad40341976c5175c2256e6c885c6eea423aa1099af06",
        "blob": "103b6f850280c39168a1f4d71d385cb2c281e650",
        "count": 0,
        "locations": [],
        "control_lines": None,
        "interpretation": "adjacent guarded DataView index-to-byte-access path; not the vulnerable TypedArray atomic API",
    },
    "cve2025-23420-js-array-root-control-review.json": {
        "commit": "aeee3fd12c03193545edea4b8e0fdfa3d9a03d11",
        "path": "ecmascript/js_array.cpp",
        "detector": "ohscanner.cpp.bounds",
        "version": "0.3.0",
        "sha256": "b7f28be2f63850ba1cb57a35d518930986855784d2081124e555f2a57d673e9b",
        "blob": "2c58914ad27b6b3c5f570dbd2fe0ed02d1d9e471",
        "count": 5,
        "locations": [("ecmascript/js_array.cpp", n, "ohcpp-memory-bounds-element-access-candidate-003") for n in (650, 653, 665, 666, 668)],
        "control_lines": [603, 636],
        "interpretation": "same-file SortElementsByInsertionSort bounded-buffer method; no candidate in its line range; findings remain in SortElementsByObject",
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
    for filename, expected in PRODUCTION_CONTROLS.items():
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
        locations = [(d.get("file"), d.get("line"), d.get("rule_id")) for d in run.get("diagnostics", [])]
        actual = (
            report.get("commit"), report.get("git_tree"), report.get("scope", {}).get("declared_scope"),
            run.get("tool_version"), run.get("status"), run.get("diagnostic_count"),
            parsing[0].get("file") if len(parsing) == 1 else None,
            parsing[0].get("status") if len(parsing) == 1 else None,
        )
        wanted = (commit, tree, [path], expected["version"], "completed", expected["count"], path, "complete")
        if actual != wanted:
            errors.append(f"{filename}: report run/scope/parse mismatch: {actual!r}")
        if blob != expected["blob"] or sha256 != expected["sha256"]:
            errors.append(f"{filename}: source blob or SHA-256 mismatch")
        if locations != expected["locations"]:
            errors.append(f"{filename}: diagnostic locations mismatch: {locations!r}")
        control_lines = expected["control_lines"]
        control_diagnostics = [line for file, line, _ in locations
                               if file == path and control_lines and control_lines[0] <= line <= control_lines[1]]
        if control_diagnostics:
            errors.append(f"{filename}: diagnostics overlap reviewed control method: {control_diagnostics!r}")
        results.append({"report": filename, "commit": commit, "tree": tree, "path": path,
                        "blob": blob, "sha256": sha256, "detector": expected["detector"],
                        "version": run.get("tool_version"), "parse": actual[-1],
                        "diagnostic_count": run.get("diagnostic_count"), "locations": locations,
                        "control_lines": control_lines,
                        "interpretation": expected["interpretation"]})
    print(json.dumps({"status": "PASS_SOURCE_IDENTITY_AND_SCAN_METADATA" if not errors else "FAIL",
                      "results": results, "errors": errors}, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())

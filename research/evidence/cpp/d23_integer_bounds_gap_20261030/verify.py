#!/usr/bin/env python3
"""Verify D23 fresh CLI reports against exact historical source identities."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


CASES = {
    "0587-vuln.json": {
        "commit": "cae11f121c030a90ba41d8e4d866f91292f25892",
        "path": "ecmascript/base/atomic_helper.cpp",
        "tree": "61ff01d9a06b4186125a04e2b790e07640f57198",
        "blob": "7fd67717571c6d8fe7b10bf294998e952dc61e36",
        "sha256": "f4890391896239c845bbcaee489d83c85eb5a64e37d563b91ed6e3908c62a541",
        "detector": "ohscanner.cpp.integer_bounds",
        "version": "0.2.0",
        "count": 1,
        "locations": [(71, "ohcpp-integer-bounds-narrow-index-candidate-003")],
    },
    "0587-fixed.json": {
        "commit": "5aa9c035e98911ec7ed28065a2138c2709792a42",
        "path": "ecmascript/base/atomic_helper.cpp",
        "tree": "05ac3902979e37ae08efa2d1e3ed32472a69d0cc",
        "blob": "80d7ad14e70825ef2daf7b3f2fc956a891bf8b2c",
        "sha256": "39521f4c6fa6b4b65d8b3daacd80f6e051b5a01c5aa814c9ac2ffc432529b36b",
        "detector": "ohscanner.cpp.integer_bounds",
        "version": "0.2.0",
        "count": 0,
        "locations": [],
    },
    "23420-vuln.json": {
        "commit": "aeee3fd12c03193545edea4b8e0fdfa3d9a03d11",
        "path": "ecmascript/js_array.cpp",
        "tree": "0eea26c9eb6846f4d19926be83092c06f0d98692",
        "blob": "2c58914ad27b6b3c5f570dbd2fe0ed02d1d9e471",
        "sha256": "b7f28be2f63850ba1cb57a35d518930986855784d2081124e555f2a57d673e9b",
        "detector": "ohscanner.cpp.bounds",
        "version": "0.3.0",
        "count": 5,
        "locations": [(line, "ohcpp-memory-bounds-element-access-candidate-003") for line in (650, 653, 665, 666, 668)],
    },
    "23420-fixed.json": {
        "commit": "1b23531531e768398682582969c2a9f17e72cafe",
        "path": "ecmascript/js_array.cpp",
        "tree": "52f27683e2f6e1ba8272aee7d5202c73059e10b4",
        "blob": "58266855967e3dc4af97721d3a2fc5417cb887b6",
        "sha256": "f6325075773451b9c9a314c6fec0c0177331786f5c9e6ce3069974eb4c79b0f6",
        "detector": "ohscanner.cpp.bounds",
        "version": "0.3.0",
        "count": 0,
        "locations": [],
    },
}


def git(source: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(source), *args])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", required=True, type=Path)
    args = parser.parse_args()
    evidence = Path(__file__).parent
    errors: list[str] = []
    for filename, expected in CASES.items():
        name = filename.removesuffix(".json")
        commit, source_path = expected["commit"], expected["path"]
        tree = git(args.source_git_dir, "rev-parse", f"{commit}^{{tree}}").decode().strip()
        entry = git(args.source_git_dir, "ls-tree", commit, "--", source_path).decode().split()
        blob = entry[2] if len(entry) >= 3 else ""
        source = git(args.source_git_dir, "show", f"{commit}:{source_path}")
        digest = hashlib.sha256(source).hexdigest()
        for field, actual in (("tree", tree), ("blob", blob), ("sha256", digest)):
            if actual != expected[field]:
                errors.append(f"{name}: {field} mismatch: {actual}")

        report = json.loads((evidence / filename).read_text(encoding="utf-8"))
        if report.get("commit") != commit:
            errors.append(f"{name}: report commit mismatch")
        if report.get("git_tree") != tree or report.get("scope", {}).get("git_tree") != tree:
            errors.append(f"{name}: report tree mismatch")
        if report.get("scope", {}).get("declared_scope") != [source_path]:
            errors.append(f"{name}: declared scope mismatch")
        if report.get("source_parsing", {}).get("parsing_status") != {"complete": 1}:
            errors.append(f"{name}: target parse is not complete")
        if report.get("diagnostic_count") != expected["count"]:
            errors.append(f"{name}: diagnostic count mismatch")
        runs = report.get("detector_runs", [])
        run = runs[0] if len(runs) == 1 else {}
        if run.get("status") != "completed":
            errors.append(f"{name}: detector run is not completed")
        locations = sorted(
            (item.get("line"), item.get("rule_id"))
            for item in run.get("diagnostics", [])
        )
        if locations != sorted(expected["locations"]):
            errors.append(f"{name}: diagnostic locations mismatch: {locations}")
    print(json.dumps({"overall": "PASS_D23_SOURCE_BOUND_REPLAY" if not errors else "FAIL", "errors": errors}, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())

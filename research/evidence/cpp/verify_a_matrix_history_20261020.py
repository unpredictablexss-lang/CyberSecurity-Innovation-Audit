#!/usr/bin/env python3
"""Verify the current-CLI source identity and differential for two historical A rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


EXPECTED = {
    "cve2025-0587-vulnerable": {
        "commit": "cae11f121c030a90ba41d8e4d866f91292f25892",
        "path": "ecmascript/base/atomic_helper.cpp",
        "detector": "ohscanner.cpp.integer_bounds",
        "version": "0.2.0",
        "count": 1,
        "locations": [("ecmascript/base/atomic_helper.cpp", 71, "ohcpp-integer-bounds-narrow-index-candidate-003")],
    },
    "cve2025-0587-fixed": {
        "commit": "5aa9c035e98911ec7ed28065a2138c2709792a42",
        "path": "ecmascript/base/atomic_helper.cpp",
        "detector": "ohscanner.cpp.integer_bounds",
        "version": "0.2.0",
        "count": 0,
        "locations": [],
    },
    "cve2025-23420-vulnerable": {
        "commit": "aeee3fd12c03193545edea4b8e0fdfa3d9a03d11",
        "path": "ecmascript/js_array.cpp",
        "detector": "ohscanner.cpp.bounds",
        "version": "0.3.0",
        "count": 5,
        "locations": [("ecmascript/js_array.cpp", n, "ohcpp-memory-bounds-element-access-candidate-003") for n in (650, 653, 665, 666, 668)],
    },
    "cve2025-23420-fixed": {
        "commit": "1b23531531e768398682582969c2a9f17e72cafe",
        "path": "ecmascript/js_array.cpp",
        "detector": "ohscanner.cpp.bounds",
        "version": "0.3.0",
        "count": 0,
        "locations": [],
    },
}


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, default=Path(__file__).parent / "a_matrix_history_20261020")
    args = parser.parse_args()
    errors: list[str] = []
    identities = {}
    by_case = {}
    for name, expected in EXPECTED.items():
        report_path = args.evidence_dir / f"{name}.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        commit, path = expected["commit"], expected["path"]
        tree = git(args.source_git_dir, "rev-parse", f"{commit}^{{tree}}")
        blob = git(args.source_git_dir, "rev-parse", f"{commit}:{path}")
        data = subprocess.check_output(["git", "-C", str(args.source_git_dir), "show", f"{commit}:{path}"])
        source_sha = hashlib.sha256(data).hexdigest()
        run = report["detector_runs"][0]
        locations = [(d["file"], d["line"], d["rule_id"]) for d in run["diagnostics"]]
        actual = (report["commit"], report["git_tree"], report["scope"]["declared_scope"], run["tool"], run["tool_version"], run["diagnostic_count"], locations)
        wanted = (commit, tree, [path], expected["detector"], expected["version"], expected["count"], expected["locations"])
        if actual != wanted:
            errors.append(f"{name}: report identity/rule/count/locations mismatch")
        if report["status"] != "completed" or report["source_parsing"]["parsing_status"].get("complete") != 1:
            errors.append(f"{name}: run or parsing is not complete")
        if any(p["status"] != "complete" for p in run["parsing"]):
            errors.append(f"{name}: per-file parse is not complete")
        diagnostic_hashes = {d["source_sha256"] for d in run["diagnostics"]}
        if diagnostic_hashes and diagnostic_hashes != {source_sha}:
            errors.append(f"{name}: diagnostic source hash mismatch")
        if report["snapshot_sha256"] == "":
            errors.append(f"{name}: snapshot hash missing")
        identity = {"commit": commit, "tree": tree, "path": path, "blob": blob, "sha256": source_sha, "bytes": len(data)}
        identities[name] = identity
        case_id = "CVE-2025-0587" if "0587" in name else "CVE-2025-23420"
        side = "vulnerable" if "vulnerable" in name else "fixed"
        by_case.setdefault(case_id, {})[side] = {"identity": identity, "report": report_path.name, "detector": run["tool"], "version": run["tool_version"], "count": run["diagnostic_count"], "locations": locations, "parse": run["parsing"][0]["status"], "profile": report["profile_id"], "snapshot_sha256": report["snapshot_sha256"]}
    payload = {"schema_version": 1, "task": "current-CLI replay for historical A matrix rows", "date": "2026-10-20", "scanner_head": git(Path.cwd(), "rev-parse", "HEAD"), "source_git_dir": str(args.source_git_dir), "cases": by_case, "errors": errors, "overall": "PASS_SOURCE_BOUND_STATIC_DIFFERENTIAL" if not errors else "FAIL"}
    out = args.evidence_dir / "matrix_history_replay_20261020.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"overall": payload["overall"], "errors": errors, "output": str(out)}, ensure_ascii=False))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())

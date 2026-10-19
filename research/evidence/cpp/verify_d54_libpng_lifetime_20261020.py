"""Verify D54's exact libpng source identities and current CLI dispositions."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp/d54_libpng_lifetime_assessment_20261020.json"


def git(git_dir: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args])


def check(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)
    print("PASS", message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--libpng-git-dir", type=Path, required=True)
    parser.add_argument("--46675-git-dir", dest="git_46675_dir", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    check(report["detector"] == "ohscanner.cpp.resource_lifetime" and report["detector_version"] == "0.4.2",
          "current detector identity is recorded")
    check(report["rule_change"] == "none", "assessment is evidence-only")
    repos = {"CVE-2026-33416": args.libpng_git_dir, "CVE-2026-46675": args.git_46675_dir}
    for case_name, case in report["cases"].items():
        repo = repos[case_name]
        expected_scope = 4 if case_name.endswith("33416") else 1
        for variant_name, variant in case["variants"].items():
            commit, tree = variant["commit"], variant["tree"]
            check(git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip() == tree,
                  f"{case_name} {variant_name} commit/tree exists in pinned source mirror")
            hashes = variant["files"]
            for path, expected_hash in hashes.items():
                blob = git(repo, "show", f"{commit}:{path}")
                check(hashlib.sha256(blob).hexdigest() == expected_hash,
                      f"{case_name} {variant_name} {path} SHA-256 matches")
            cli = json.loads((EVIDENCE.parent / variant["cli_report"]).read_text(encoding="utf-8"))
            check(cli["commit"] == commit and cli["git_tree"] == tree and cli["snapshot_sha256"] == variant["snapshot_sha256"],
                  f"{case_name} {variant_name} CLI identity matches report")
            run = next(item for item in cli["detector_runs"] if item["tool"] == report["detector"])
            coverage = cli["detector_coverage"]["detectors"][report["detector"]]["coverage_counts"]
            check(run["tool_version"] == report["detector_version"] and run["status"] == "blocked"
                  and cli["source_parsing"]["parsing_status"] == {"partial": expected_scope}
                  and coverage == {"complete": 0, "partial": expected_scope, "not_analyzed": 0, "failed": 0}
                  and cli["diagnostic_count"] == variant["findings"] == 0,
                  f"{case_name} {variant_name} stays blocked/partial with zero findings")
        check(case["decision"] == "NO_RULE_CHANGE_PARTIAL_BLOCK", f"{case_name} remains PARTIAL/BLOCK")
    print("D54 libpng lifetime assessment: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Verify T33's source-bound current M2 CLI replay and case records."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research" / "evidence" / "cpp"
UPSTREAM_COMMIT = "0c2c9dff82cc85539c8362132d7a5f6bf7d1e748"
UPSTREAM_TREE = "0d8e50cc18f9ae178e9969eed40f8a0c94fb3856"
BASELINE = "6f24b0ccae22446d76b4a993312ef37228ffd05e"
EXPECTED_FILES = {
    "cJSON.c": {
        "blob": "152b2caa479c9f448001652913c980a6dafb82e0",
        "bytes": 80529,
        "sha256": "427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb",
        "parse": "partial",
    },
    "cJSON_Utils.c": {
        "blob": "8fa24f8e9bf452cf1ba49d1325c85423ce742c74",
        "bytes": 40736,
        "sha256": "bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9",
        "parse": "complete",
    },
}
EXPECTED_FINDINGS = {
    ("cJSON.c", 3161): "ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005",
    ("cJSON_Utils.c", 932): "ohcpp-resource-exhaustion-tree-amplification-candidate-004",
    ("cJSON_Utils.c", 950): "ohcpp-resource-exhaustion-tree-amplification-candidate-004",
}


def git(source_git_dir: str, *args: str, binary: bool = False):
    completed = subprocess.run(
        ["git", "--git-dir", source_git_dir, *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout if binary else completed.stdout.decode("utf-8").strip()


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")
    print(f"PASS: {message}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-git-dir",
        default="D:/openHarmonyScanner/openharmony/.repo/project-objects/third_party_cJSON.git",
    )
    args = parser.parse_args()

    resolved_commit = git(args.source_git_dir, "rev-parse", UPSTREAM_COMMIT)
    resolved_tree = git(args.source_git_dir, "rev-parse", f"{UPSTREAM_COMMIT}^{{tree}}")
    check(resolved_commit == UPSTREAM_COMMIT and resolved_tree == UPSTREAM_TREE,
          "upstream commit and tree resolve exactly")

    for path, expected in EXPECTED_FILES.items():
        oid = git(args.source_git_dir, "rev-parse", f"{UPSTREAM_COMMIT}:{path}")
        raw = git(args.source_git_dir, "cat-file", "blob", oid, binary=True)
        check(
            oid == expected["blob"]
            and len(raw) == expected["bytes"]
            and hashlib.sha256(raw).hexdigest() == expected["sha256"],
            f"{path} blob, byte length, and SHA-256 match pinned source",
        )

    cli = json.loads((EVIDENCE / "t33_cjson_m2_cli_20261023.json").read_text(encoding="utf-8"))
    check(
        cli["repository"] == "openharmony/third_party_cJSON"
        and cli["commit"] == UPSTREAM_COMMIT
        and cli["git_tree"] == UPSTREAM_TREE
        and cli["scope"]["declared_scope"] == ["cJSON.c", "cJSON_Utils.c"],
        "production M2 CLI report binds the same two-file scope to the upstream source",
    )
    run = cli["detector_runs"][0]
    parse = {row["file"]: row["status"] for row in run["parsing"]}
    check(parse == {p: v["parse"] for p, v in EXPECTED_FILES.items()},
          "actual parser results are one partial and one complete")
    findings = {(d["file"], d["line"]): d["rule_id"] for d in run["diagnostics"]}
    check(findings == EXPECTED_FINDINGS, "both distinct rules and all three exact CLI positions reproduce")
    coverage = cli["detector_coverage"]["detectors"]["ohscanner.cpp.resource_lifetime"]
    check(run["status"] == "blocked" and coverage["status"] == "partial"
          and coverage["coverage_counts"] == {"complete": 0, "partial": 2, "not_analyzed": 0, "failed": 0},
          "aggregate blocked status and per-file detector partial coverage remain explicit")

    for cve, expected in {
        "CVE-2026-67215": {("cJSON_Utils.c", 932), ("cJSON_Utils.c", 950)},
        "CVE-2026-67216": {("cJSON.c", 3161)},
    }.items():
        stem = "t33_cjson_" + cve.lower().replace("-", "_") + "_20261023"
        record = json.loads((EVIDENCE / f"{stem}.json").read_text(encoding="utf-8"))
        positions = {(row["file"], row["line"]) for row in record["candidate_positions"]}
        check(positions == expected and record["disposition"] == "PARTIAL/BLOCK"
              and record["fixed_comparison"].startswith("BLOCK:"),
              f"{cve} per-case position, partial status, and blocked fixed comparison are preserved")

    t15 = (EVIDENCE / "t15_d18_independent_acceptance_20261020.md").read_text(encoding="utf-8")
    t16 = json.loads((EVIDENCE / "t16_d19_independent_acceptance_20261020.json").read_text(encoding="utf-8"))
    check("replay.py" in t15 and "parser and CLI coverage are not evaluated" in t16["cases"][0]["scope_note"],
          "D18/T15 and D19/T16 evidence is explicitly distinguished from whole-source CLI coverage")
    audit = json.loads((EVIDENCE / "t33_cjson_m2_audit_20261023.json").read_text(encoding="utf-8"))
    check(audit["fixed_source"] is None and audit["fixed_comparison"] == "BLOCK for both cases"
          and audit["a0_queue_modified"] is False,
          "no fixed source is invented and the frozen A0 queue remains untouched")
    queue = (EVIDENCE / "a_line_parallel_queue_20261020.md").read_text(encoding="utf-8")
    check("### T33 — cJSON CVE-2026-67215/67216 current M2 CLI replay" in queue,
          "T33 result is linked from the A-line task tree")


if __name__ == "__main__":
    main()

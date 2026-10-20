#!/usr/bin/env python3
"""Verify D32 curl source bindings, current CLI pair, and D3 family regressions."""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
EVIDENCE = pathlib.Path(__file__).resolve().parent
MANIFEST = EVIDENCE / "d32_curl92391_current_replay_20261022.json"
SOURCE_GIT = pathlib.Path(r"D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git")
EXPECTED_HEAD = "385e0266301793a45d9df84f7a18a3f1a3b07efc"


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")
    print(f"PASS: {message}")


def git(*args: str) -> str:
    proc = subprocess.run(
        ["git", "--git-dir", str(SOURCE_GIT), *args],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return proc.stdout.decode("ascii").strip()


def main() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    recorded_head = data["scanner"]["head"]
    is_ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", EXPECTED_HEAD, "HEAD"], cwd=ROOT
    ).returncode == 0
    check(recorded_head == EXPECTED_HEAD and is_ancestor, "recorded scanner base is present in current integration history")
    check(data["scanner"]["detector_version"] == "0.4.2", "current detector version is recorded")
    check(data["scanner"]["rule_id"] == "ohcpp-resource-lifetime-recursive-cleanup-candidate-003", "recursive cleanup rule identity is recorded")
    check(SOURCE_GIT.is_dir() and data["source_store"]["network_fetch_performed"] is False, "local pinned source store was used without fetch")

    reports: dict[str, dict] = {}
    for case in data["cases"]:
        commit = case["commit"]
        tree = git("rev-parse", f"{commit}^{{tree}}")
        blob = git("rev-parse", f"{commit}:{case['file']}")
        content = subprocess.run(
            ["git", "--git-dir", str(SOURCE_GIT), "cat-file", "blob", blob],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        sha256 = hashlib.sha256(content).hexdigest()
        check(tree == case["tree"] and blob == case["blob"] and sha256 == case["source_sha256"], f"{case['variant']} upstream commit/tree/blob/file SHA-256 binding")

        report_path = EVIDENCE / case["report"]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        reports[case["variant"]] = report
        check(report["commit"] == commit and report["git_tree"] == tree, f"{case['variant']} CLI report uses exact source commit/tree")
        check(report["scope"]["declared_scope"] == ["lib/mime.c"] and report["scope"]["selected_source_files"] == 1, f"{case['variant']} CLI scope is exactly lib/mime.c")
        check(report["source_parsing"]["parsing_status"].get("complete") == 1 and report["detector_coverage"]["detectors"]["ohscanner.cpp.resource_lifetime"]["coverage_counts"] == case["coverage"], f"{case['variant']} target parse and detector coverage are complete")
        run = report["detector_runs"][0]
        check(run["tool_version"] == data["scanner"]["detector_version"] and run["status"] == "completed" and run["diagnostic_count"] == case["finding_count"], f"{case['variant']} detector version/status/count matches manifest")
        check(abs(run["elapsed_seconds"] - case["elapsed_seconds"]) < 1e-12, f"{case['variant']} elapsed time matches raw report")

    vulnerable_case = data["cases"][0]
    finding = reports["vulnerable"]["detector_runs"][0]["diagnostics"][0]
    binding = finding["finding_identity"]["occurrence"]["basis"]
    check(finding["file"] == "lib/mime.c" and finding["line"] == 1118 and finding["symbol"] == "curl_mime_free", "vulnerable root-cause candidate location matches")
    check(finding["rule_id"] == data["scanner"]["rule_id"] and binding["source_blob_oid"] == vulnerable_case["blob"] and binding["source_sha256"] == vulnerable_case["source_sha256"], "candidate rule and occurrence are bound to the vulnerable source")
    check(len(reports["fixed"]["detector_runs"][0]["diagnostics"]) == 0, "exact fixed commit has no same-rule candidate")

    result = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.detectors.test_cpp_resource_lifetime_detector", "-v"],
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    print(result.stdout, end="")
    check(result.returncode == 0 and "Ran 8 tests" in result.stdout and "OK" in result.stdout, "existing resource lifetime/D3 regression controls pass (8 tests)")

    check(data["disposition"]["detector_change_made"] is False and data["disposition"]["a0_ledger_modified"] is False, "no detector edit or A0 ledger change was made")


if __name__ == "__main__":
    main()

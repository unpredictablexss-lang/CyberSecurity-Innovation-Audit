#!/usr/bin/env python3
"""Read-only T25 provenance, queue-state, and CLI-baseline verifier."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path


AUDIT = Path(__file__).with_name("a_t25_datashare_race_source_audit_20261020.json")
EXPECTED_ROWS = {
    "CR-0013": ("frameworks/native/provider/include/datashare_stub_impl.h", 35),
    "CR-0014": ("frameworks/native/provider/include/datashare_stub_impl.h", 40),
    "CR-0015": ("frameworks/native/provider/include/datashare_stub_impl.h", 42),
}


def git(git_dir: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], stderr=subprocess.PIPE)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", required=True, type=Path, help="Read-only frozen A0 queue.csv")
    parser.add_argument("--git-dir", required=True, type=Path, help="Pinned DataShare project object database")
    parser.add_argument("--cli-report", type=Path, default=AUDIT.with_name("a_t25_datashare_cr0013_0015_cli_20261020.json"))
    args = parser.parse_args()
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    cli = json.loads(args.cli_report.read_text(encoding="utf-8"))
    queue_bytes = args.queue.read_bytes()
    with args.queue.open("r", encoding="utf-8-sig", newline="") as stream:
        queue = list(csv.DictReader(stream))
    selected = {row.get("queue_id"): row for row in queue if row.get("queue_id") in EXPECTED_ROWS}

    commit = audit["source"]["commit"]
    observed_tree = git(args.git_dir, "rev-parse", f"{commit}^{{tree}}").decode().strip()
    source_checks = {}
    for item in audit["source_files"]:
        path, oid = item["path"], item["blob"]
        listed = git(args.git_dir, "ls-tree", commit, "--", path).decode().strip().split("\t", 1)
        tree_oid = listed[0].split()[2] if len(listed) == 2 else ""
        data = git(args.git_dir, "cat-file", "blob", oid)
        computed_blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        source_checks[path] = {
            "tree_blob_matches": tree_oid == oid,
            "git_blob_hash_matches": computed_blob == oid,
            "raw_sha256_matches": hashlib.sha256(data).hexdigest() == item["source_sha256"],
            "byte_count_matches": len(data) == item["bytes"],
        }

    row_checks = {}
    for row_id, (path, line) in EXPECTED_ROWS.items():
        row = selected.get(row_id)
        evidence = next((item for item in audit["rows"] if item["id"] == row_id), None)
        row_checks[row_id] = bool(
            row and evidence
            and row.get("repository") == audit["source"]["repository"]
            and row.get("repo_project_path") == audit["source"]["repo_project_path"]
            and row.get("commit") == commit and row.get("tree") == observed_tree
            and row.get("path") == path and int(row.get("line", "0")) == line
            and row.get("blob") == audit["source_files"][0]["blob"]
            and row.get("source_sha256") == audit["source_files"][0]["source_sha256"]
            and row.get("original_status") == "not_testable"
            and row.get("queue_status") == "paused_pending_evidence"
            and evidence.get("disposition") == "PARTIAL/BLOCK"
        )

    report_sha = cli.get("detector_coverage", {}).get("detectors", {}).get(
        "ohscanner.cpp.shared_ptr_race", {}).get("source_sha256", {})
    expected_reports = {item["path"]: item["source_sha256"] for item in audit["source_files"]}
    report_sources_match = all(report_sha.get(path) == sha for path, sha in expected_reports.items())
    runs = cli.get("detector_runs", [])
    diagnostics = [finding for run in runs for finding in run.get("diagnostics", [])]
    diagnostic_pairs = {(finding.get("file"), finding.get("line"), finding.get("symbol")) for finding in diagnostics}
    expected_pairs = {
        ("frameworks/native/provider/include/datashare_stub_impl.h", 35, "uvQueue_"),
        ("frameworks/native/provider/include/datashare_stub_impl.h", 42, "uvQueue_"),
    }
    cli_checks = {
        "commit_matches": cli.get("commit") == commit,
        "tree_matches": cli.get("git_tree") == observed_tree,
        "four_source_hashes_match": report_sources_match,
        "detector_id_and_version_match": len(runs) == 1 and runs[0].get("tool") == "ohscanner.cpp.shared_ptr_race" and runs[0].get("tool_version") == "0.5.1",
        "candidate_locations_match": diagnostic_pairs == expected_pairs,
        "detector_coverage_remains_partial": cli.get("detector_coverage", {}).get("detectors", {}).get("ohscanner.cpp.shared_ptr_race", {}).get("status") == "partial",
        "parser_has_one_partial_file": cli.get("source_parsing", {}).get("parsing_status") == {"complete": 3, "partial": 1},
    }
    overall = (
        len(queue) == 345 and len(selected) == 3
        and hashlib.sha256(queue_bytes).hexdigest() == audit["queue_source_sha256"]
        and observed_tree == audit["source"]["tree"]
        and all(all(check.values()) for check in source_checks.values())
        and all(row_checks.values()) and all(cli_checks.values())
        and audit["summary"]["case_disposition"] == "PARTIAL/BLOCK"
        and all(row.get("original_status") == "not_testable" for row in selected.values())
        and all(row.get("queue_status") == "paused_pending_evidence" for row in selected.values())
    )
    print(json.dumps({
        "overall_ok": overall,
        "queue_rows": len(queue),
        "queue_sha256": hashlib.sha256(queue_bytes).hexdigest(),
        "source_tree": observed_tree,
        "source_file_checks": source_checks,
        "row_identity_and_original_state_checks": row_checks,
        "cli_baseline_checks": cli_checks,
        "case_disposition": audit["summary"]["case_disposition"],
    }, indent=2))
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())

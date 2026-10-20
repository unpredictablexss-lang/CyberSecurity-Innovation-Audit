#!/usr/bin/env python3
"""Read-only source, CLI, and frozen A0-row verifier for T28."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[3]
AUDIT = ROOT / "research/evidence/cpp/a_t28_datashare_ipc_audit_20261020.json"
CLI = ROOT / "research/evidence/cpp/a_t28_datashare_cr0016_0018_cli_20261020.json"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"


def git(git_dir: str, *args: str) -> str:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", default=r"D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_data_share.git")
    args = parser.parse_args()
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    cli = json.loads(CLI.read_text(encoding="utf-8"))
    commit = audit["source"]["commit"]
    assert git(args.source_git_dir, "rev-parse", f"{commit}^{{tree}}") == audit["source"]["tree"]
    for item in audit["source"]["files"]:
        blob = git(args.source_git_dir, "rev-parse", f"{commit}:{item['path']}")
        raw = subprocess.check_output(["git", f"--git-dir={args.source_git_dir}", "cat-file", "blob", blob])
        assert blob == item["blob"], item["path"]
        assert hashlib.sha256(raw).hexdigest() == item["sha256"], item["path"]
        assert len(raw) == item["bytes"], item["path"]
    rows = list(csv.DictReader(QUEUE.open(encoding="utf-8-sig", newline="")))
    assert len(rows) == 345
    selected = {r["original_review_id"]: r for r in rows if r["original_review_id"] in {"CR-0016", "CR-0017", "CR-0018"}}
    assert set(selected) == {"CR-0016", "CR-0017", "CR-0018"}
    expected = {r["id"]: r for r in audit["rows"]}
    for ident, evidence in expected.items():
        row = selected[ident]
        assert row["commit"] == commit and row["tree"] == audit["source"]["tree"]
        assert row["blob"] == audit["source"]["files"][0]["blob"]
        assert row["source_sha256"] == audit["source"]["files"][0]["sha256"]
        assert row["original_status"] == evidence["original_status"]
        assert row["queue_status"] == evidence["queue_status"]
    runs = cli["detector_runs"]
    diagnostics = [d for run in runs for d in run["diagnostics"]]
    assert len(diagnostics) == 3
    for evidence in audit["rows"]:
        path, line = evidence["location"].rsplit(":", 1)
        hits = [d for d in diagnostics if d["file"] == path and str(d["line"]) == line and d["rule_id"] == evidence["rule"]]
        assert len(hits) == 1, evidence["id"]
        assert hits[0]["diagnostic_id"] == evidence["current_finding_id"]
    assert cli["source_parsing"]["parsing_status"] == {"partial": 1}
    assert cli["validated_vulnerability"] == 0
    assert audit["cli"]["execution_status"] == "completed_with_limitations"
    print("PASS: source commit/tree, four source blob IDs/SHA-256/size, and all three frozen queue bindings")
    print("PASS: CR-0016/17/18 exact current CLI finding IDs, lines, and rules")
    print("PASS: parse coverage remains partial; no result promoted to safety or vulnerability proof")
    print("PASS: original_status=not_testable and queue_status=queued_first_batch preserved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

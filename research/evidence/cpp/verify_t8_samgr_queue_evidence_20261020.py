from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = Path(__file__).with_name("a_t8_samgr_queue_evidence_20261020.json")
CLI = Path(__file__).with_name("a_t8_samgr_cli_20261020.json")
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"


def git(git_dir: str, *args: str) -> str:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], text=True).strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", required=True)
    args = parser.parse_args()
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    cli = json.loads(CLI.read_text(encoding="utf-8"))
    source = evidence["source"]
    assert git(args.source_git_dir, "rev-parse", f"{source['commit']}^{{tree}}") == source["tree"]
    assert git(args.source_git_dir, "rev-parse", f"{source['commit']}:{source['path']}") == source["blob"]
    blob = subprocess.check_output(["git", f"--git-dir={args.source_git_dir}", "cat-file", "blob", source["blob"]])
    assert len(blob) == source["bytes"]
    assert hashlib.sha256(blob).hexdigest() == source["sha256"]

    queue_rows = {}
    with QUEUE.open(encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream):
            if row["queue_id"] in {f"CR-{n:04d}" for n in range(219, 224)}:
                queue_rows[row["queue_id"]] = row
    diagnostics = cli["detector_runs"][0]["diagnostics"]
    hits = {(d["line"], d["rule_id"]): d["diagnostic_id"] for d in diagnostics}
    assert len(evidence["records"]) == 5
    for record in evidence["records"]:
        row = queue_rows[record["queue_id"]]
        assert row["commit"] == source["commit"]
        assert row["queue_id"] == record["queue_id"]
        assert row["original_status"] == record["original_status"]
        assert row["queue_status"] == record["queue_status"]
        key = (record["line"], "ipc.capability.export")
        assert hits[key] == record["current_cli_id"]
    assert cli["commit"] == source["commit"]
    assert cli["git_tree"] == source["tree"]
    assert cli["source_parsing"]["parsing_status"] == {"partial": 1}
    assert evidence["result"]["a0_statuses_changed"] is False
    print("PASS: pinned source identity, 5/5 queue candidates, partial coverage, and original statuses verified")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Verify D41 source identity, exact CLI replay, and unchanged A0 rows."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMMIT = "50c7dffc057a32987d5eeb7626c20e1b3717c77b"
TREE = "8b54f17921ba15ff306bcbef280078003a7b1055"
BASE = "1ebe2d809719cc7b445fe6e723c452e0634c8dd3"
IDS = {f"CR-{i:04d}" for i in range(161, 174)}
REPLAY = HERE / "d41_faultloggerd_tail_replay_20261025.json"
RAW = HERE / "d41_faultloggerd_tail_cli_20261025.json"
QUEUE_CSV = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
QUEUE_JSON = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repo", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_repo.resolve()
    assert git(source, "rev-parse", f"{COMMIT}^{{commit}}").decode().strip() == COMMIT
    assert git(source, "show", "-s", "--format=%T", COMMIT).decode().strip() == TREE

    rows = list(csv.DictReader(QUEUE_CSV.open(encoding="utf-8-sig", newline="")))
    queue_json = json.loads(QUEUE_JSON.read_text(encoding="utf-8"))["queue"]
    assert len(rows) == len(queue_json) == 345
    by_id = {row["queue_id"]: row for row in rows}
    json_by_id = {row["queue_id"]: row for row in queue_json}
    assert set(by_id) == set(json_by_id)
    selected = {qid: by_id[qid] for qid in IDS}
    assert set(selected) == IDS

    replay = json.loads(REPLAY.read_text(encoding="utf-8"))
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert replay["base_head"] == BASE
    assert replay["source"]["commit"] == COMMIT and replay["source"]["tree"] == TREE
    assert replay["queue"]["audited_ids"] == sorted(IDS)
    assert replay["queue"]["states_changed"] is False
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE
    assert raw["repository"] == "openharmony/hiviewdfx_faultloggerd"
    assert raw["source_parsing"]["parsing_status"] == {"complete": 4}
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 7
    )
    assert run["scope_files"] == 4 and run["scope_loc"] == 874
    diagnostic_map = {(item["file"], int(item["line"])): item for item in run["diagnostics"]}
    items = {item["queue_id"]: item for item in replay["items"]}
    assert set(items) == IDS and len(items) == 13

    for qid, row in selected.items():
        jrow = json_by_id[qid]
        item = items[qid]
        for key in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "original_status", "queue_status"):
            assert str(row[key]) == str(jrow[key]), (qid, key)
        assert item["queue_id"] == qid
        for key in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "original_status", "queue_status"):
            assert str(row[key]) == str(item[key]), (qid, key)
        assert row["commit"] == COMMIT and row["tree"] == TREE
        assert row["original_status"] == "not_testable"
        assert row["queue_status"] == "paused_pending_evidence"
        content = git(source, "show", f"{COMMIT}:{row['path']}")
        assert git(source, "rev-parse", f"{COMMIT}:{row['path']}").decode().strip() == row["blob"]
        assert hashlib.sha256(content).hexdigest() == row["source_sha256"]
        found = diagnostic_map.get((row["path"], int(row["line"])))
        expected = "matched_exact_line" if found else "no_current_finding_at_a0_line"
        assert item["replay"]["result"] == expected, qid
        assert row["original_status"] == jrow["original_status"]
        assert row["queue_status"] == jrow["queue_status"]

    for identity in replay["source"]["queue_bound_files"] + replay["context_files"]:
        content = git(source, "show", f"{COMMIT}:{identity['path']}")
        assert git(source, "rev-parse", f"{COMMIT}:{identity['path']}").decode().strip() == identity["blob"]
        assert hashlib.sha256(content).hexdigest() == identity["sha256"]

    matches = sum(item["replay"]["result"] == "matched_exact_line" for item in replay["items"])
    assert matches == 4
    assert replay["cli"]["finding_count"] == 7
    assert replay["queue"]["status_counts"] == {"not_testable": 13, "paused_pending_evidence": 13}

    print("D41 exact commit/tree, 13 queue rows and 4 source blobs: PASS")
    print("D41 current shared_ptr_race 0.5.1 replay, 4/4 complete, 7 diagnostics: PASS")
    print("D41 exact A0 line mapping (4 matched, 9 not matched), source/context hashes: PASS")
    print("A0 345 rows and unchanged D41 original/queue states: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


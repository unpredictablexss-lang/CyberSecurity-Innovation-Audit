#!/usr/bin/env python3
"""Verify T46 exact A0 source identities, CLI output, and lock call paths."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMMIT = "21c83c874a34e8d28e6a355a3b56e5167252ed27"
TREE = "e115202d315867371b3b7c885b4f017e10cb163f"
PATH = "interfaces/innerkits/safwk/expire_lru_cache.h"
IDS = {"CR-0241", "CR-0242", "CR-0243"}
AUDIT = HERE / "t46_safwk_expire_lru_cache_audit_20261027.json"
RAW = HERE / "t46_safwk_expire_lru_cache_cli_20261027.json"


def git(repo: Path, *args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args], input=data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument(
        "--queue-csv",
        type=Path,
        default=ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv",
    )
    parser.add_argument(
        "--queue-json",
        type=Path,
        default=ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json",
    )
    args = parser.parse_args()
    repo = args.source_repo.resolve()
    assert git(repo, "rev-parse", "HEAD").decode().strip() == COMMIT
    assert git(repo, "show", "-s", "--format=%T", COMMIT).decode().strip() == TREE

    csv_rows = list(csv.DictReader(args.queue_csv.open(encoding="utf-8-sig", newline="")))
    json_rows = json.loads(args.queue_json.read_text(encoding="utf-8"))["queue"]
    assert len(csv_rows) == len(json_rows) == 345
    csv_map = {row["queue_id"]: row for row in csv_rows}
    json_map = {row["queue_id"]: row for row in json_rows}
    assert len(csv_map) == len(json_map) == 345
    selected = {key: row for key, row in csv_map.items() if key in IDS}
    assert set(selected) == IDS

    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert audit["source"]["commit"] == COMMIT and audit["source"]["tree"] == TREE
    assert audit["source"]["path"] == PATH
    assert audit["queue"]["states_changed"] is False
    assert {row["queue_id"] for row in audit["queue"]["ids"]} == IDS
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE
    assert raw["repository"] == "openharmony/systemabilitymgr_safwk"
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 0
    )
    assert raw["validated_vulnerability"] == 0 and run["diagnostics"] == []
    assert run["scope_files"] == 1 and run["scope_loc"] == 194

    audit_rows = {row["queue_id"]: row for row in audit["queue"]["ids"]}
    for queue_id in IDS:
        row = selected[queue_id]
        assert audit_rows[queue_id] == {key: row[key] for key in audit_rows[queue_id]}
        for key in (
            "candidate_id", "repository", "commit", "tree", "path", "line", "blob",
            "source_sha256", "original_status", "queue_status",
        ):
            assert str(row[key]) == str(json_map[queue_id][key])
        assert row["repository"] == "openharmony/systemabilitymgr_safwk"
        assert row["commit"] == COMMIT and row["tree"] == TREE and row["path"] == PATH
        assert row["original_status"] == "not_testable"
        assert row["queue_status"] == "paused_pending_evidence"

    content = git(repo, "show", f"{COMMIT}:{PATH}")
    assert git(repo, "hash-object", "--stdin", data=content).decode().strip() == (
        "3e004bca071eb51d0e108845addf5ec3e25dbc65"
    )
    assert hashlib.sha256(content).hexdigest() == (
        "9eb5ce4db56c91311de4351d639949d56566733ede610f5039a39ff0148265e3"
    )
    lines = content.decode().splitlines()
    assert "data_.erase(key);" in lines[164]
    assert "data_.clear();" in lines[170]
    assert "data_.erase(iter->first);" in lines[182]

    source = content.decode()
    for public, helper in (("Remove", "DoRemove"), ("Clear", "DoClear"), ("Add", "DoAdd")):
        start = source.index(f" {public}(")
        body = source[start:source.index("\n    }", start)]
        assert "lock_guard<std::mutex>" in body and "lock_" in body and f"{helper}(" in body
    assert source.count("DoClearExpiredCache()") == 2  # definition + call inside locked DoAdd
    do_add = source[source.index("void DoAdd("):source.index("std::shared_ptr<TValue> DoGet(")]
    assert "DoClearExpiredCache()" in do_add

    print("PASS T46: exact commit/tree/blob/SHA for CR-0241–CR-0243")
    print("PASS T46: current shared_ptr_race 0.5.1 complete parse, zero findings")
    print("PASS T46: exact write lines map to public-method lock paths")
    print("PASS T46: 345 A0 records reconcile; all selected states remain unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

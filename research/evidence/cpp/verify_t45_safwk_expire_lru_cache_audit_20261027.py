#!/usr/bin/env python3
"""Verify T45 exact A0 source bindings, CLI replay, and lock/build evidence."""
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
IDS = {f"CR-{i:04d}" for i in range(231, 241)}
AUDIT = HERE / "t45_safwk_expire_lru_cache_audit_20261027.json"
RAW = HERE / "d42_safwk_expire_lru_cache_20261027.json"


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
    assert audit["queue"]["states_changed"] is False
    assert {row["queue_id"] for row in audit["queue"]["ids"]} == IDS
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE
    assert raw["repository"] == "openharmony/systemabilitymgr_safwk"
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 0
    )
    assert raw["validated_vulnerability"] == 0
    assert run["parsing"][0]["status"] == "complete"
    assert run["diagnostics"] == []

    rows_by_id = {row["queue_id"]: row for row in audit["queue"]["ids"]}
    for queue_id in IDS:
        row = selected[queue_id]
        jrow = json_map[queue_id]
        audit_row = rows_by_id[queue_id]
        for key in (
            "candidate_id", "repository", "commit", "tree", "path", "line", "blob",
            "source_sha256", "original_status", "queue_status",
        ):
            assert str(row[key]) == str(jrow[key]) == str(audit_row[key]), (queue_id, key)
        assert row["commit"] == COMMIT and row["tree"] == TREE
        assert row["repository"] == "openharmony/systemabilitymgr_safwk"
        assert row["path"] == "interfaces/innerkits/safwk/expire_lru_cache.h"
        assert row["source_sha256"] == "9eb5ce4db56c91311de4351d639949d56566733ede610f5039a39ff0148265e3"
        assert row["original_status"] == "not_testable"
        assert row["queue_status"] == "paused_pending_evidence"

    identities = {item["path"]: item for item in audit["context_files"]}
    assert len(identities) == 6
    for path, expected in identities.items():
        content = git(repo, "show", f"{COMMIT}:{path}")
        oid = git(repo, "hash-object", "--stdin", data=content).decode().strip()
        assert oid == expected["blob"], path
        assert hashlib.sha256(content).hexdigest() == expected["sha256"], path

    cache = git(repo, "show", f"{COMMIT}:interfaces/innerkits/safwk/expire_lru_cache.h").decode()
    for public in ("Add", "Get", "Remove", "Clear"):
        assert f"void {public}(" in cache or f"std::shared_ptr<TValue> {public}(" in cache
        start = cache.index(f" {public}(")
        body = cache[start:cache.index("\n    }", start)]
        assert "lock_guard<std::mutex>" in body and "lock_" in body
    for helper in ("DoAdd", "DoGet", "DoRemove", "DoClear", "DoClearExpiredCache"):
        assert cache.count(helper + "(") >= 2
    manager = git(repo, "show", f"{COMMIT}:services/safwk/src/api_cache_manager.cpp").decode()
    assert manager.count("lock_guard<std::mutex> lock(cachesMutex_)") == 7
    assert "cache->second->Get(keyVec)" in manager and "cache->second->Add(keyVec, valueVec)" in manager
    api_build = git(repo, "show", f"{COMMIT}:interfaces/innerkits/safwk/BUILD.gn").decode()
    test_build = git(repo, "show", f"{COMMIT}:test/services/safwk/unittest/BUILD.gn").decode()
    assert 'ohos_shared_library("api_cache_manager")' in api_build
    assert '"//foundation/systemabilitymgr/safwk/services/safwk/src/api_cache_manager.cpp"' in api_build
    assert 'ohos_unittest("ExpireLruCacheTest")' in test_build
    assert 'sources = [ "./expire_lru_cache_test.cpp" ]' in test_build
    test = git(repo, "show", f"{COMMIT}:test/services/safwk/unittest/expire_lru_cache_test.cpp").decode()
    assert "#define private public" in test

    print("PASS T45: exact commit/tree/blob/SHA bindings for CR-0231–CR-0240")
    print("PASS T45: current shared_ptr_race 0.5.1 CLI complete parse, zero findings")
    print("PASS T45: source-bound cache lock, API caller and GN test/library context")
    print("PASS T45: all 345 A0 rows reconcile; selected original states unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

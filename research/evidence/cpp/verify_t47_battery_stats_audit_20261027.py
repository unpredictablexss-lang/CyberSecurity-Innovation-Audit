#!/usr/bin/env python3
"""Verify T47 source identities, current CLI replay, and unchanged A0 rows."""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMMIT = "271a545acc0ececc746cfe0bb7c1501943df7c64"
TREE = "fd32c4da257effb689a86f7946f51805360fbf70"
SOURCE = "test/unittest/include/stats_test.h"
IDS = {"CR-0252", "CR-0253", "CR-0254"}
AUDIT = HERE / "t47_battery_stats_audit_20261027.json"
RAW = HERE / "t47_battery_stats_cli_20261027.json"
CONTEXT = {
    "test/BUILD.gn": ("f13c2f224dd7c8250df6d69907feddfdc4b3a4a4", "37bf2eada1e51d6f00a10f8d31e9bc17c8c3f09e48f5da2e1b5e2fa639ca9e12"),
    "test/unittest/src/servicetest/BUILD.gn": ("845f862c84b28071bd3e764d13c2e604fbb279f6", "f254d66d80bd7e1fc366edc265b9f77f7e81d1d2ec8617da918de387e7ad2662"),
    "test/unittest/src/clienttest/BUILD.gn": ("6bd83ac3e86be0841ffbac392cca86fbe4674117", "1e4f050f0b4523db6d97597fae9a3624b0ed7cfd57941fdf7a18448b03b67926"),
    "test/unittest/src/servicetest/stats_service_alarm_test.cpp": ("44c5d501f2823e1e9b7949b16db288546cdd4424", "87de8e53f95f7f27bb9aa7f3f291c33ede6680c1f68daaf91fbf6963be49b1bf"),
    "test/unittest/src/clienttest/stats_alarm_test.cpp": ("81ae1a53b3d80d7cf81828d0e0c5af62e372f0d4", "d257de1919b4ab0be12f36758b485507dc0a397c1fbdc8e2970df693b8314c54"),
}


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--queue-csv", type=Path, default=ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv")
    parser.add_argument("--queue-json", type=Path, default=ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json")
    args = parser.parse_args()
    repo = args.source_repo.resolve()
    assert git(repo, "rev-parse", "HEAD").decode().strip() == COMMIT
    assert git(repo, "show", "-s", "--format=%T", COMMIT).decode().strip() == TREE

    csv_rows = list(csv.DictReader(args.queue_csv.open(encoding="utf-8-sig", newline="")))
    json_rows = json.loads(args.queue_json.read_text(encoding="utf-8"))["queue"]
    csv_map = {row["queue_id"]: row for row in csv_rows}
    json_map = {row["queue_id"]: row for row in json_rows}
    assert len(csv_rows) == len(json_rows) == len(csv_map) == len(json_map) == 345
    assert set(csv_map) == set(json_map)
    assert Counter(row["original_status"] for row in csv_rows) == {"not_reproduced": 9, "not_testable": 336}
    assert Counter(row["queue_status"] for row in csv_rows) == {"queued_not_reproduced": 9, "queued_first_batch": 5, "paused_pending_evidence": 331}
    selected = {key: row for key, row in csv_map.items() if key in IDS}
    assert set(selected) == IDS

    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert audit["status"] == "PARTIAL/BLOCK"
    assert audit["queue"]["states_changed"] is False
    audit_rows = {row["queue_id"]: row for row in audit["queue"]["ids"]}
    assert set(audit_rows) == IDS
    for queue_id in IDS:
        row, jrow, arow = selected[queue_id], json_map[queue_id], audit_rows[queue_id]
        for key in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "original_status", "queue_status"):
            assert str(row[key]) == str(jrow[key]) == str(arow[key]), (queue_id, key)
        assert row["repository"] == "openharmony/powermgr_battery_statistics"
        assert row["commit"] == COMMIT and row["tree"] == TREE
        assert row["path"] == SOURCE
        assert row["original_status"] == "not_testable"
        assert row["queue_status"] == "paused_pending_evidence"
        assert int(row["line"]) == int(queue_id[-3:]) - 211
        assert row["blob"] == "adaadee18b512e92c3f4afd1d9a566a1fc90f4a6"
        assert row["source_sha256"] == "c1113bea553ef18ffe9450df4b13865075bb2e54b42b44188f424e9cfb127c91"

    source = git(repo, "show", f"{COMMIT}:{SOURCE}")
    assert git(repo, "rev-parse", f"{COMMIT}:{SOURCE}").decode().strip() == "adaadee18b512e92c3f4afd1d9a566a1fc90f4a6"
    assert hashlib.sha256(source).hexdigest() == "c1113bea553ef18ffe9450df4b13865075bb2e54b42b44188f424e9cfb127c91"
    source_text = source.decode()
    for needle in ("static std::shared_ptr<BatteryStatsParser> g_statsParser;", "if (g_statsParser == nullptr)", "g_statsParser = std::make_shared<BatteryStatsParser>();", "if (!g_statsParser->Init())"):
        assert needle in source_text
    assert "lock_guard" not in source_text and "atomic<" not in source_text

    for path, (blob, sha256) in CONTEXT.items():
        content = git(repo, "show", f"{COMMIT}:{path}")
        assert git(repo, "rev-parse", f"{COMMIT}:{path}").decode().strip() == blob, path
        assert hashlib.sha256(content).hexdigest() == sha256, path
    test_build = git(repo, "show", f"{COMMIT}:test/BUILD.gn").decode()
    service_build = git(repo, "show", f"{COMMIT}:test/unittest/src/servicetest/BUILD.gn").decode()
    client_build = git(repo, "show", f"{COMMIT}:test/unittest/src/clienttest/BUILD.gn").decode()
    assert 'group("unittest")' in test_build and "testonly = true" in test_build
    assert 'ohos_unittest("stats_service_alarm_test")' in service_build
    assert 'ohos_unittest("stats_service_test")' in client_build

    assert raw["repository"] == "openharmony/powermgr_battery_statistics"
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE
    assert raw["status"] == "completed" and raw["validated_vulnerability"] == 0
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == ("ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 3)
    assert run["parsing"][0]["status"] == "complete"
    findings = run["diagnostics"]
    assert {item["line"] for item in findings} == {41, 42, 43}
    assert all(item["rule_id"] == "ohcpp-shared-ptr-race-candidate-001" for item in findings)
    assert all(item["candidate_cwe"] == "CWE-362" for item in findings)

    print("PASS T47: exact A0 commit/tree/blob/SHA binding for CR-0252–CR-0254")
    print("PASS T47: current shared_ptr_race 0.5.1 CLI complete parse; three line-matched candidates")
    print("PASS T47: testonly GN context and exact caller/build file identities verified")
    print("PASS T47: 345 A0 queue rows reconcile; selected original states unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Verify D35 A0 identity, full-file replay locations, and preserved queue state."""
from __future__ import annotations

import collections
import csv
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
QUEUE_JSON = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
QUEUE_CSV = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
RAW = HERE / "d35_preferences_fuzz_20261024.json"
REPORT = HERE / "d35_preferences_source_replay_20261024.json"
OBJECTS = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git")
COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE = "7761d9e273ae7007046ae115797f255e554523ae"
SOURCE = "test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp"
BUILD = "test/native/fuzztest/dbpreferences_fuzzer/BUILD.gn"
IDS = [f"CR-{n:04d}" for n in range(22, 41)]


def git(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={OBJECTS}", *args], input=data)


def blob_and_sha(path: str) -> tuple[str, str]:
    content = git("show", f"{COMMIT}:{path}")
    return (git("hash-object", "--stdin", data=content).decode().strip(), hashlib.sha256(content).hexdigest())


def main() -> int:
    with QUEUE_CSV.open(encoding="utf-8-sig", newline="") as handle:
        csv_rows = list(csv.DictReader(handle))
    json_rows = json.loads(QUEUE_JSON.read_text(encoding="utf-8"))["queue"]
    cmap, jmap = ({x["queue_id"]: x for x in rows} for rows in (csv_rows, json_rows))
    assert len(csv_rows) == len(json_rows) == len(cmap) == len(jmap) == 345
    assert set(cmap) == set(jmap)
    for qid in cmap:
        for key in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "original_status", "queue_status"):
            assert str(cmap[qid][key]) == str(jmap[qid][key]), (qid, key)
    assert git("rev-parse", f"{COMMIT}^{{commit}}").decode().strip() == COMMIT
    assert git("show", "-s", "--format=%T", COMMIT).decode().strip() == TREE
    source_blob, source_sha = blob_and_sha(SOURCE)
    build_blob, build_sha = blob_and_sha(BUILD)
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    run = raw["detector_runs"][0]
    assert raw["repository"] == "openharmony/distributeddatamgr_preferences"
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE and raw["status"] == "completed"
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == ("ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 19)
    source_diags = {d["line"]: d for d in run["diagnostics"] if d["file"] == SOURCE}
    assert len(source_diags) == 19
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert report["task"] == "D35" and report["queue_states_changed"] is False
    assert report["source"]["tree"] == TREE
    assert report["source"]["file"]["blob"] == source_blob and report["source"]["file"]["sha256"] == source_sha
    assert report["build_target"]["file"]["blob"] == build_blob and report["build_target"]["file"]["sha256"] == build_sha
    assert report["build_target"]["target"] == "ohos_fuzztest(DBPreferencesFuzzTest)"
    assert report["build_target"]["test_group"] == "group(fuzztest) [testonly = true]"
    assert report["build_target"]["harness_entry"] == "LLVMFuzzerTestOneInput"
    assert report["cli"]["parse"] == {"complete": 1} and report["cli"]["findings"] == 19
    assert [x["queue_id"] for x in report["items"]] == IDS
    for item in report["items"]:
        qid = item["queue_id"]
        qrow = cmap[qid]
        line = int(qrow["line"])
        diag = source_diags[line]
        assert item["source"]["commit"] == COMMIT and item["source"]["tree"] == TREE
        assert item["source"]["blob"] == source_blob and item["source"]["sha256"] == source_sha
        assert item["source"]["line"] == line == item["replay"]["finding_line"]
        assert item["replay"]["diagnostic_id"] == diag["diagnostic_id"]
        assert item["replay"]["rule_id"] == diag["rule_id"] and item["replay"]["parse_status"] == "complete"
        assert item["replay"]["stable_identity_status"] == "unknown"
        assert item["replay"]["occurrence_identity_status"] == "unknown"
        assert item["disposition"] == "PARTIAL" and item["queue_preserved"]
        assert (qrow["original_status"], qrow["queue_status"]) == ("not_testable", "paused_pending_evidence")
    assert set(int(cmap[q]["line"]) for q in IDS) == set(source_diags)
    counts = {key: dict(collections.Counter(x[key] for x in csv_rows)) for key in ("original_status", "queue_status")}
    assert counts["original_status"] == {"not_testable": 336, "not_reproduced": 9}
    assert counts["queue_status"] == {"paused_pending_evidence": 331, "queued_not_reproduced": 9, "queued_first_batch": 5}
    print("Preferences commit/tree and source + BUILD.gn blob/SHA: PASS")
    print("A0 CSV/JSON parity, 345 IDs and status counts: PASS")
    print("CR-0022–0040 all bind to exact source lines and replay identities: PASS")
    print("Current shared_ptr_race full-file run: 19/19, complete parse: PASS")
    print("ohos_fuzztest test-harness classification; no production conclusion: PASS")
    print("PARTIAL dispositions and original A0 states preserved: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

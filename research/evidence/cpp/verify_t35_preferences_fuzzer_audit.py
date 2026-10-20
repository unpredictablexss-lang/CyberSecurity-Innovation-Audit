#!/usr/bin/env python3
"""Read-only verifier for T35 Preferences fuzz-family audit."""
from __future__ import annotations
import collections, csv, hashlib, json, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
OBJECTS = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git")
QUEUE = Path(r"D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\a-line-triage\20261018\queue.csv")
COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE = "7761d9e273ae7007046ae115797f255e554523ae"
SOURCE = "test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp"
BUILD = "test/native/fuzztest/dbpreferences_fuzzer/BUILD.gn"

def git(*args, data=None):
    return subprocess.check_output(["git", f"--git-dir={OBJECTS}", *args], input=data)

def main():
    audit = json.loads((HERE / "t35_preferences_fuzzer_source_audit_20261020.json").read_text(encoding="utf-8"))
    raw = json.loads((HERE / audit["cli"]["raw"]).read_text(encoding="utf-8"))
    with QUEUE.open(encoding="utf-8-sig", newline="") as f:
        all_rows = list(csv.DictReader(f))
    rows = {r["queue_id"]: r for r in all_rows}
    assert len(rows) == 345
    queue_json = json.loads(QUEUE.with_name("queue.json").read_text(encoding="utf-8"))["queue"]
    jrows = {r["queue_id"]: r for r in queue_json}
    assert len(jrows) == 345 and set(rows) == set(jrows)
    for qid in rows:
        for key in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "original_status", "queue_status", "family_key"):
            assert str(rows[qid][key]) == str(jrows[qid][key]), (qid, key)
    assert git("rev-parse", f"{COMMIT}^{{commit}}").decode().strip() == COMMIT
    assert git("show", "-s", "--format=%T", COMMIT).decode().strip() == TREE
    source = git("show", f"{COMMIT}:{SOURCE}")
    build = git("show", f"{COMMIT}:{BUILD}")
    assert hashlib.sha256(source).hexdigest() == audit["source"]["sha256"]
    assert git("hash-object", "--stdin", data=source).decode().strip() == audit["source"]["blob"]
    assert hashlib.sha256(build).hexdigest() == audit["build"]["sha256"]
    assert git("hash-object", "--stdin", data=build).decode().strip() == audit["build"]["blob"]
    assert b'ohos_fuzztest("DBPreferencesFuzzTest")' in build
    assert b'group("fuzztest")' in build and b"testonly = true" in build
    assert b"LLVMFuzzerTestOneInput" in source
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE
    run = raw["detector_runs"][0]
    assert raw["status"] == "completed" and raw["source_parsing"]["parsing_status"] == {"complete": 1}
    assert run["tool"] == "ohscanner.cpp.shared_ptr_race" and run["tool_version"] == "0.5.1"
    assert raw["scope"]["declared_scope"] == [SOURCE]
    diagnostics = {(d["line"], d["symbol"]): d["diagnostic_id"] for d in run["diagnostics"]}
    assert len(diagnostics) == 19
    assert len(audit["queue"]["target_rows"]) == 16
    for item in audit["queue"]["target_rows"]:
        qid = item["queue_id"]
        row = rows[qid]
        assert (row["candidate_id"], row["commit"], row["tree"], row["path"], int(row["line"]), row["blob"], row["source_sha256"], row["original_status"], row["queue_status"]) == (
            item["candidate_id"], COMMIT, TREE, SOURCE, item["line"], audit["source"]["blob"], audit["source"]["sha256"], "not_testable", "paused_pending_evidence")
        assert (item["line"], item["symbol"]) in diagnostics
        assert item["cli_diagnostic_id"] == diagnostics[(item["line"], item["symbol"])]
        assert item["disposition"] == "PARTIAL" and item["queue_preserved"] is True
    counts = collections.Counter(r["queue_status"] for r in all_rows)
    assert counts == {"paused_pending_evidence": 331, "queued_not_reproduced": 9, "queued_first_batch": 5}
    print("T35 source and fuzz BUILD blob/SHA provenance: PASS")
    print("Original A0 345-row queue and CR-0025–0040 source keys/states: PASS")
    print("Production M2 CLI exact source scope and 16 mapped findings: PASS")
    print("Fuzz-only target boundary assertions and PARTIAL dispositions: PASS")
    print("A0 queue state counts unchanged: PASS")

if __name__ == "__main__":
    main()

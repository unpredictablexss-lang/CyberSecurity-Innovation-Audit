from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REPORT = ROOT / "research/evidence/cpp/t38_preferences_vector_replay_20261024.json"
RAW = ROOT / "research/evidence/cpp/t38_preferences_vector_cli_20261024.json"
QUEUE = Path(r"D:\openHarmonyScanner\tmp\a0_triage_t22_verify_20261020\queue.csv")
OBJECTS = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\distributeddatamgr_preferences.git")
COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
SRC = "test/native/fuzztest/dbpreferencesvector_fuzzer/dbpreferencesvector_fuzzer.cpp"
BUILD = "test/native/fuzztest/dbpreferencesvector_fuzzer/BUILD.gn"


def git(*args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={OBJECTS}", *args], input=data)


def main() -> None:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    rows = list(csv.DictReader(QUEUE.open(encoding="utf-8-sig", newline="")))
    assert len(rows) == 345 and len({r["queue_id"] for r in rows}) == 345
    qmap = {r["queue_id"]: r for r in rows}
    assert report["a0"]["rows"] == 345 and report["a0"]["queue_state_unchanged"] is True
    assert report["source"]["commit"] == COMMIT
    assert report["source"]["tree"] == git("show", "-s", "--format=%T", COMMIT).decode().strip()
    assert report["source"]["file"]["path"] == SRC
    for path, actual in ((SRC, report["source"]["file"]), (BUILD, report["build_target"]["file"])):
        blob = git("show", f"{COMMIT}:{path}")
        assert actual["blob"] == git("hash-object", "--stdin", data=blob).decode().strip()
        assert actual["sha256"] == hashlib.sha256(blob).hexdigest()
    run = raw["detector_runs"][0]
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    assert run["tool"] == "ohscanner.cpp.shared_ptr_race" and run["tool_version"] == "0.5.1"
    diagnostics = {d["line"]: d for d in run["diagnostics"] if d["file"] == SRC}
    assert len(diagnostics) == 6 and len(report["items"]) == 6
    for item in report["items"]:
        row = qmap[item["queue_id"]]
        assert row["path"] == SRC and row["commit"] == COMMIT
        assert row["line"] == str(item["source_line"])
        assert row["blob"] == item["source"]["blob"]
        assert row["source_sha256"].lower() == item["source"]["sha256"]
        assert row["original_status"] == "not_testable" and row["queue_status"] == "paused_pending_evidence"
        assert diagnostics[item["source_line"]]["diagnostic_id"] == item["replay"]["diagnostic_id"]
    assert report["overall_disposition"] == "PARTIAL"
    print("PASS T38 verifier: source/build bindings, six per-ID findings, and unchanged 345-row A0 state")


if __name__ == "__main__":
    main()

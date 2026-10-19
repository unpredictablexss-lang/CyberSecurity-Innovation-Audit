from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp"
REPORT = EVIDENCE / "t39_preferences_fuzzer_audit_20261024.json"
RAW = EVIDENCE / "t39_preferences_fuzzer_cli_20261024.json"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
SOURCE_REPO = Path(r"D:\openHarmonyScanner\tmp\t39-preferences-source-20261024")
COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE = "7761d9e273ae7007046ae115797f255e554523ae"
SOURCE_PATH = "test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp"
BUILD_PATH = "test/native/fuzztest/preferences_fuzzer/BUILD.gn"
EXPECTED_IDS = [f"CR-{number:04d}" for number in range(97, 116)]


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(SOURCE_REPO), *args], text=True).strip()


def object_identity(path: str) -> tuple[str, str, int]:
    data = subprocess.check_output(["git", "-C", str(SOURCE_REPO), "show", f"{COMMIT}:{path}"])
    blob = git("rev-parse", f"{COMMIT}:{path}")
    return blob, hashlib.sha256(data).hexdigest(), len(data)


def main() -> None:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    with QUEUE.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 345 and len({row["queue_id"] for row in rows}) == 345
    qmap = {row["queue_id"]: row for row in rows}
    assert report["a0"]["rows"] == 345
    assert hashlib.sha256(QUEUE.read_bytes()).hexdigest() == report["a0"]["queue_csv_sha256"]
    assert report["a0"]["queue_state_unchanged"] is True
    assert git("rev-parse", "HEAD") == COMMIT
    assert git("rev-parse", "HEAD^{tree}") == TREE
    assert report["source"]["commit"] == COMMIT and report["source"]["tree"] == TREE
    for path, recorded in ((SOURCE_PATH, report["source"]["file"]),
                           (BUILD_PATH, report["build_target"]["file"])):
        blob, sha256, size = object_identity(path)
        assert recorded == {"path": path, "blob": blob, "sha256": sha256, "bytes": size}
    assert (raw["repository"], raw["commit"], raw["git_tree"]) == (
        "openharmony/distributeddatamgr_preferences", COMMIT, TREE
    )
    assert raw["scope"]["declared_scope"] == [SOURCE_PATH]
    assert raw["source_parsing"]["parsing_status"] == {"complete": 1}
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 19
    )
    diagnostics = {item["line"]: item for item in run["diagnostics"] if item["file"] == SOURCE_PATH}
    assert len(diagnostics) == 19
    assert [item["queue_id"] for item in report["items"]] == EXPECTED_IDS
    for item in report["items"]:
        qrow = qmap[item["queue_id"]]
        line = int(qrow["line"])
        finding = diagnostics[line]
        assert item["source_line"] == line
        assert qrow["path"] == SOURCE_PATH and qrow["commit"] == COMMIT and qrow["tree"] == TREE
        assert qrow["blob"] == report["source"]["file"]["blob"]
        assert qrow["source_sha256"].lower() == report["source"]["file"]["sha256"]
        assert (qrow["original_status"], qrow["queue_status"]) == (
            "not_testable", "paused_pending_evidence"
        )
        assert item["original_a0"] == {
            "original_status": qrow["original_status"], "queue_status": qrow["queue_status"]
        }
        assert item["replay"]["diagnostic_id"] == finding["diagnostic_id"]
        assert item["replay"]["source_sha256"] == report["source"]["file"]["sha256"]
    assert report["build_target"]["target"] == 'ohos_fuzztest("PreferencesFuzzTest")'
    assert report["build_target"]["group_testonly"] is True
    assert report["overall_disposition"] == "PARTIAL"
    assert report["queue_states_changed"] is False and report["detector_or_test_changes"] is False
    print("PASS T39 verifier: exact source/BUILD identity, 19 per-ID candidates, and unchanged A0 queue")


if __name__ == "__main__":
    main()

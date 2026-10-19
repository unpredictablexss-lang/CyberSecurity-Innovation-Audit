from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
RAW = EVIDENCE / "t41_faultloggerd_tail_cli_20261024.json"
AUDIT = EVIDENCE / "t41_faultloggerd_tail_audit_20261024.json"
SOURCE_ROOT = Path(r"D:\openHarmonyScanner\tmp\t40-faultloggerd-source-20261024")
COMMIT = "50c7dffc057a32987d5eeb7626c20e1b3717c77b"
TREE = "8b54f17921ba15ff306bcbef280078003a7b1055"
IDS = [f"CR-{n:04d}" for n in range(161, 174)]


def git(*args: str) -> str | bytes:
    result = subprocess.check_output(["git", "-C", str(SOURCE_ROOT), *args])
    return result.decode("utf-8").strip() if isinstance(result, bytes) else result


def check_identity(item: dict) -> None:
    path = item["path"]
    assert git("rev-parse", f"{COMMIT}:{path}") == item["blob"]
    data = subprocess.check_output(["git", "-C", str(SOURCE_ROOT), "show", f"{COMMIT}:{path}"])
    assert hashlib.sha256(data).hexdigest() == item["sha256"]
    assert len(data) == item["bytes"]


def main() -> None:
    assert git("rev-parse", "HEAD") == COMMIT
    assert git("rev-parse", f"{COMMIT}^{{tree}}") == TREE
    rows = list(csv.DictReader(QUEUE.open(encoding="utf-8-sig", newline="")))
    assert len(rows) == 345 and len({r["queue_id"] for r in rows}) == 345
    by_id = {r["queue_id"]: r for r in rows}
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    assert (raw["repository"], raw["commit"], raw["git_tree"]) == (
        "openharmony/hiviewdfx_faultloggerd", COMMIT, TREE)
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 7)
    parse = {x["file"]: x["status"] for x in run["parsing"]}
    assert len(parse) == 4 and set(parse.values()) == {"complete"}
    diagnostics = {(d["file"], int(d["line"])): d for d in run["diagnostics"]}
    assert audit["task"] == "T41" and audit["overall_disposition"] == "PARTIAL"
    assert len(audit["a0_rows"]) == 13
    exact = 0
    for item, queue_id in zip(audit["a0_rows"], IDS, strict=True):
        row = by_id[queue_id]
        assert item["queue_id"] == queue_id
        assert (row["repository"], row["commit"], row["tree"]) == (
            "openharmony/hiviewdfx_faultloggerd", COMMIT, TREE)
        assert row["original_status"] == "not_testable"
        assert row["queue_status"] == "paused_pending_evidence"
        assert item["candidate_id"] == row["candidate_id"]
        assert (item["path"], item["line"]) == (row["path"], int(row["line"]))
        assert item["parse_status"] == parse[row["path"]] == "complete"
        assert item["a0_source_sha256"] == row["source_sha256"].lower()
        assert item["source"]["blob"] == row["blob"]
        src = subprocess.check_output(["git", "-C", str(SOURCE_ROOT), "show", f"{COMMIT}:{row['path']}"])
        assert hashlib.sha256(src).hexdigest() == row["source_sha256"].lower()
        assert item["line_text"] == src.decode("utf-8").splitlines()[int(row["line"]) - 1].strip()
        diag = diagnostics.get((row["path"], int(row["line"])))
        assert item["current_cli"]["exact_line_finding"] is (diag is not None)
        if diag:
            exact += 1
            assert item["current_cli"]["diagnostic_id"] == diag["diagnostic_id"]
        assert item["assessment"] == "PARTIAL"
    assert exact == audit["exact_line_findings"] == 4
    assert audit["scanner"]["parse_status"] == {"complete": 4}
    assert audit["a0_unchanged"] == {
        "queue_rows": 345, "group_rows": 13,
        "group_original_status_counts": {"not_testable": 13},
        "group_queue_status_counts": {"paused_pending_evidence": 13}, "modified": False}
    for group in ("source_file_identities", "build_file_identities", "reviewed_context_file_identities"):
        for item in audit[group]:
            check_identity(item)
    assert any(x["path"] == "tools/process_dump/dfx_process.h" and x["line"] == 74
               for x in audit["a0_rows"])
    assert any(x["file"] == "tools/process_dump/dfx_process.h" and x["line"] == 74
               for x in run["diagnostics"])
    print("PASS T41: 13 exact A0 rows; 4/13 exact findings; 4 complete CLI files; source/tree/blob/SHA and BUILD/context identities verified; all A0 states preserved")


if __name__ == "__main__":
    main()

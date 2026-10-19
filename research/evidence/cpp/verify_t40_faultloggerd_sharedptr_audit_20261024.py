from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
RAW = ROOT / "research/evidence/cpp/t40_faultloggerd_sharedptr_cli_20261024.json"
AUDIT = ROOT / "research/evidence/cpp/t40_faultloggerd_sharedptr_audit_20261024.json"
SOURCE_ROOT = Path(r"D:\openHarmonyScanner\tmp\t40-faultloggerd-source-20261024")
COMMIT = "50c7dffc057a32987d5eeb7626c20e1b3717c77b"
TREE = "8b54f17921ba15ff306bcbef280078003a7b1055"
IDS = [f"CR-{number:04d}" for number in range(119, 161)]


def git(*args: str) -> str | bytes:
    return subprocess.check_output(["git", "-C", str(SOURCE_ROOT), *args])


def main() -> None:
    assert git("rev-parse", "HEAD").decode().strip() == COMMIT
    assert git("rev-parse", "HEAD^{tree}").decode().strip() == TREE
    with QUEUE.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 345 and len({row["queue_id"] for row in rows}) == 345
    by_id = {row["queue_id"]: row for row in rows}
    assert all(queue_id in by_id for queue_id in IDS)
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    run = raw["detector_runs"][0]
    assert (raw["commit"], raw["git_tree"], raw["repository"]) == (
        COMMIT, TREE, "openharmony/hiviewdfx_faultloggerd"
    )
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 11
    )
    assert raw["source_parsing"]["parsing_status"] == {"complete": 11}
    assert audit["task"] == "T40" and audit["overall_disposition"] == "PARTIAL"
    assert audit["a0_unchanged"]["queue_rows"] == 345
    assert audit["a0_unchanged"]["group_rows"] == 42
    assert audit["a0_unchanged"]["group_original_status_counts"] == {"not_testable": 42}
    assert audit["a0_unchanged"]["group_queue_status_counts"] == {
        "paused_pending_evidence": 42
    }
    assert not audit["a0_unchanged"]["modified"]
    assert len(audit["a0_rows"]) == 42
    exact_findings = 0
    diagnostics = {(item["file"], int(item["line"])): item for item in run["diagnostics"]}
    for item, queue_id in zip(audit["a0_rows"], IDS, strict=True):
        row = by_id[queue_id]
        assert item["queue_id"] == queue_id
        assert (row["repository"], row["commit"], row["tree"]) == (
            "openharmony/hiviewdfx_faultloggerd", COMMIT, TREE
        )
        assert row["original_status"] == "not_testable"
        assert row["queue_status"] == "paused_pending_evidence"
        assert item["a0_candidate_id"] == row["candidate_id"]
        source_file = item["source"]
        assert source_file["path"] == row["path"]
        assert source_file["blob"] == row["blob"]
        source = git("show", f"{COMMIT}:{row['path']}")
        assert hashlib.sha256(source).hexdigest() == row["source_sha256"].lower()
        assert source_file["sha256"] == row["source_sha256"].lower()
        assert item["candidate_line"] == int(row["line"])
        line_text = source.decode("utf-8").splitlines()[int(row["line"]) - 1].strip()
        assert item["candidate_line_text"] == line_text
        finding = diagnostics.get((row["path"], int(row["line"])))
        assert item["current_cli"]["exact_line_finding"] is (finding is not None)
        if finding:
            exact_findings += 1
            assert item["current_cli"]["diagnostic_id"] == finding["diagnostic_id"]
            assert finding["source_sha256"] == row["source_sha256"].lower()
        assert item["disposition"] == "PARTIAL"
    assert exact_findings == 10
    assert audit["scanner"]["diagnostic_count"] == 11
    # The extra finding is retained and explicitly shown to be outside this A0 ID group.
    assert any(
        item["file"] == "tools/process_dump/dfx_process.h" and item["line"] == 74
        for item in run["diagnostics"]
    )
    for build_file in audit["build_file_identities"]:
        content = git("show", f"{COMMIT}:{build_file['path']}")
        assert hashlib.sha256(content).hexdigest() == build_file["sha256"]
        assert git("rev-parse", f"{COMMIT}:{build_file['path']}").decode().strip() == build_file["blob"]
    for context_file in audit["reviewed_context_file_identities"]:
        content = git("show", f"{COMMIT}:{context_file['path']}")
        assert hashlib.sha256(content).hexdigest() == context_file["sha256"]
        assert git("rev-parse", f"{COMMIT}:{context_file['path']}").decode().strip() == context_file["blob"]
    print("PASS T40: 42 exact A0 rows; 10/42 exact current findings; 11 complete CLI files; source/tree/blob/SHA and BUILD identities verified; A0 states preserved")


if __name__ == "__main__":
    main()

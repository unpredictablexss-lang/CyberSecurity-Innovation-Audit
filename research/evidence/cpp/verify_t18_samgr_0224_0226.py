#!/usr/bin/env python3
"""Verify T18 Samgr source binding and unchanged A0 queue states."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp/a_t18_samgr_0224_0226_20261020.json"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
MIRROR = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\systemabilitymgr_samgr.git")
EXPECTED = {"CR-0224": ("ohscanner.interface.ipc:1ab7b873ef0e71d2", 1692), "CR-0225": ("ohscanner.interface.ipc:79b120286d7e2168", 1735), "CR-0226": ("ohscanner.interface.ipc:c85193fe8d815688", 1784)}

def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(MIRROR), *args])

def main() -> None:
    ev = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    src = ev["source"]
    assert git("cat-file", "-t", src["commit"]).decode().strip() == "commit"
    assert git("rev-parse", src["commit"] + "^{tree}").decode().strip() == src["tree"]
    tree_line = git("ls-tree", src["commit"], src["path"]).decode().strip().split()
    assert tree_line[2] == src["blob"], tree_line
    blob = git("cat-file", "blob", src["blob"])
    assert len(blob) == src["bytes"]
    assert hashlib.sha256(blob).hexdigest() == src["sha256"]
    rows = {x["queue_id"]: x for x in ev["cases"]}
    assert set(rows) == set(EXPECTED)
    queue = json.loads(QUEUE.read_text(encoding="utf-8"))["queue"]
    qrows = {x["queue_id"]: x for x in queue if x.get("queue_id") in EXPECTED}
    assert set(qrows) == set(EXPECTED)
    for qid, (candidate, line) in EXPECTED.items():
        row, original = rows[qid], qrows[qid]
        assert row["candidate_id"] == candidate and row["reported_line"] == line
        assert original["candidate_id"] == candidate and original["line"] == line
        assert original["commit"] == src["commit"] and original["tree"] == src["tree"]
        assert original["blob"] == src["blob"] and original["source_sha256"] == src["sha256"]
        assert original["original_status"] == "not_reproduced"
        assert original["queue_status"] == "queued_not_reproduced"
        assert original["source_file_analysis_status"] == "partial"
    assert ev["family_scope"]["queue_state"] == "all rows preserve original_status=not_reproduced and queue_status=queued_not_reproduced"
    print(json.dumps({"overall_ok": True, "ids": sorted(EXPECTED), "source_commit": src["commit"], "tree": src["tree"], "blob": src["blob"], "sha256": src["sha256"], "queue_states_unchanged": True}, indent=2))

if __name__ == "__main__":
    main()

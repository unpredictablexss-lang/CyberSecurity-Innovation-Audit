#!/usr/bin/env python3
"""Verify T44 source bindings, current IPC CLI mapping, and unchanged A0 rows."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp/a_t44_samgr_callback_audit_20261027.json"
CLI = ROOT / "research/evidence/cpp/a_t44_samgr_callback_cli_20261027.json"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
MIRROR = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\systemabilitymgr_samgr.git")


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(MIRROR), *args])


def main() -> None:
    ev = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    cli = json.loads(CLI.read_text(encoding="utf-8"))
    queue = json.loads(QUEUE.read_text(encoding="utf-8"))["queue"]
    src = ev["source"]
    assert git("cat-file", "-t", src["commit"]).decode().strip() == "commit"
    assert git("rev-parse", src["commit"] + "^{tree}").decode().strip() == src["tree"]
    for item in src["files"]:
        assert git("ls-tree", src["commit"], item["path"]).decode().split()[2] == item["blob"]
        blob = git("cat-file", "blob", item["blob"])
        assert len(blob) == item["bytes"]
        assert hashlib.sha256(blob).hexdigest() == item["sha256"]
    assert cli["git_tree"] == src["tree"]
    assert cli["scope"]["declared_scope"] == [item["path"] for item in src["files"]]
    assert cli["scope"]["selected_source_files"] == 4
    assert cli["scope"]["selected_source_bytes"] == ev["cli"]["scope_bytes"]
    assert cli["source_parsing"]["parsing_status"] == ev["cli"]["parse_counts"]
    cov = cli["detector_coverage"]["detectors"]["ohscanner.interface.ipc"]
    assert cov["coverage_counts"] == ev["cli"]["coverage_counts"]
    diags = {(d["file"], d["line"]): d for d in cli["detector_runs"][0]["diagnostics"]}
    qrows = {r["queue_id"]: r for r in queue if r.get("queue_id") in {f"CR-{i:04d}" for i in range(214, 219)}}
    assert len(qrows) == len(ev["cases"]) == 5
    for case in ev["cases"]:
        row = qrows[case["queue_id"]]
        assert row["candidate_id"] == case["candidate_id"]
        assert row["path"] == case["path"] and row["line"] == case["line"]
        assert row["blob"] == case["blob"] and row["source_sha256"] == case["source_sha256"]
        assert row["commit"] == src["commit"] and row["tree"] == src["tree"]
        assert row["original_status"] == case["original_status"] == "not_testable"
        assert row["queue_status"] == case["queue_status"] == "paused_pending_evidence"
        d = diags[(case["path"], case["line"])]
        assert d["diagnostic_id"] == case["finding_id"]
        assert d["rule_id"] == case["rule_id"] == "ipc.relay.descriptor-boundary"
        assert d["source_sha256"] == case["source_sha256"]
    assert len(cli["detector_runs"][0]["diagnostics"]) == ev["cli"]["findings"] == 13
    assert ev["disposition"] == "PARTIAL/BLOCK"
    assert ev["queue_preservation"]["status_changed"] is False
    print(json.dumps({"overall_ok": True, "ids": sorted(qrows), "source_commit": src["commit"], "tree": src["tree"], "mapped_candidates": len(ev["cases"]), "parse_counts": ev["cli"]["parse_counts"], "queue_states_unchanged": True}, indent=2))


if __name__ == "__main__":
    main()

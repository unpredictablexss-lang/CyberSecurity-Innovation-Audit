#!/usr/bin/env python3
"""Verify T30 Samgr source binding, current IPC replay, and frozen A0 states."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp/a_t30_samgr_ipc_audit_20261020.json"
CLI = ROOT / "research/evidence/cpp/a_t30_samgr_cli_20261020.json"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
MIRROR = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\systemabilitymgr_samgr.git")
PATH = "services/samgr/native/source/system_ability_manager_stub.cpp"


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(MIRROR), *args])


def main() -> None:
    ev = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    cli = json.loads(CLI.read_text(encoding="utf-8"))
    q = json.loads(QUEUE.read_text(encoding="utf-8"))["queue"]
    src = ev["source"]
    assert git("cat-file", "-t", src["commit"]).decode().strip() == "commit"
    assert git("rev-parse", src["commit"] + "^{tree}").decode().strip() == src["tree"]
    assert git("ls-tree", src["commit"], PATH).decode().split()[2] == src["blob"]
    blob = git("cat-file", "blob", src["blob"])
    assert len(blob) == src["bytes"] and hashlib.sha256(blob).hexdigest() == src["sha256"]
    assert cli["git_tree"] == src["tree"]
    assert cli["scope"]["declared_scope"] == [PATH]
    assert cli["scope"]["selected_source_files"] == 1
    assert cli["scope"]["selected_source_bytes"] == src["bytes"]
    cov = cli["detector_coverage"]["detectors"]["ohscanner.interface.ipc"]
    assert cov["source_sha256"][PATH] == src["sha256"]
    assert cov["coverage_counts"] == ev["cli"]["coverage"]
    assert cli["source_parsing"]["parsing_status"] == {"partial": 1}
    diags = cli["detector_runs"][0]["diagnostics"]
    assert len(diags) == ev["cli"]["total_diagnostics"] == 10
    by_line = {d["line"]: d for d in diags}
    rows = {r["queue_id"]: r for r in q if r.get("queue_id", "") in {f"CR-{i:04d}" for i in range(219, 227)}}
    cases = ev["cases"]
    assert len(rows) == len(cases) == 8
    for case in cases:
        original = rows[case["queue_id"]]
        assert original["candidate_id"] == case["candidate_id"]
        assert original["line"] == case["line"]
        assert original["repository"] == src["repository"]
        assert original["commit"] == src["commit"] and original["tree"] == src["tree"]
        assert original["path"] == PATH and original["blob"] == src["blob"]
        assert original["source_sha256"] == src["sha256"]
        assert original["original_status"] == case["original_status"] == "not_reproduced"
        assert original["queue_status"] == case["queue_status"] == "queued_not_reproduced"
        assert original["source_file_analysis_status"] == "partial"
        d = by_line[case["line"]]
        assert d["diagnostic_id"] == case["diagnostic_id"]
        assert d["rule_id"] == case["rule_id"] == "ipc.capability.export"
        assert d["source_sha256"] == src["sha256"]
    assert ev["queue_preservation"]["status_changed"] is False
    print(json.dumps({"overall_ok": True, "ids": sorted(rows), "source_commit": src["commit"], "tree": src["tree"], "blob": src["blob"], "sha256": src["sha256"], "current_cli_candidates": 8, "parse_status": "partial", "queue_states_unchanged": True}, indent=2))


if __name__ == "__main__":
    main()

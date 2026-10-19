#!/usr/bin/env python3
"""Verify T45 exact source binding, CLI locations, and unchanged A0 states."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp/a_t45_safwk_ipc_audit_20261027.json"
CLI = ROOT / "research/evidence/cpp/a_t45_safwk_cli_20261027.json"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
MIRROR = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\systemabilitymgr_safwk.git")


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(MIRROR), *args])


def main() -> None:
    ev = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    cli = json.loads(CLI.read_text(encoding="utf-8"))
    queue = json.loads(QUEUE.read_text(encoding="utf-8"))["queue"]
    source = ev["source"]
    assert git("cat-file", "-t", source["commit"]).decode().strip() == "commit"
    assert git("rev-parse", source["commit"] + "^{tree}").decode().strip() == source["tree"]
    assert git("ls-tree", source["commit"], source["path"]).decode().split()[2] == source["blob"]
    blob = git("cat-file", "blob", source["blob"])
    assert len(blob) == source["bytes"]
    assert hashlib.sha256(blob).hexdigest() == source["sha256"]
    assert cli["git_tree"] == source["tree"]
    assert cli["scope"]["declared_scope"] == [source["path"]]
    assert cli["scope"]["selected_source_files"] == 1
    assert cli["scope"]["selected_source_bytes"] == ev["cli"]["scope_bytes"]
    assert cli["source_parsing"]["parsing_status"] == ev["cli"]["parse_counts"]
    coverage = cli["detector_coverage"]["detectors"]["ohscanner.interface.ipc"]["coverage_counts"]
    assert coverage == ev["cli"]["coverage_counts"]
    diagnostics = {d["line"]: d for d in cli["detector_runs"][0]["diagnostics"]}
    rows = {r["queue_id"]: r for r in queue if r.get("queue_id") in {"CR-0244", "CR-0245", "CR-0246"}}
    assert len(rows) == len(ev["cases"]) == 3
    for case in ev["cases"]:
        row = rows[case["queue_id"]]
        assert row["candidate_id"] == case["candidate_id"] == case["a0_finding_id"]
        assert row["commit"] == source["commit"] and row["tree"] == source["tree"]
        assert row["path"] == case["path"] == source["path"]
        assert row["line"] == case["line"]
        assert row["blob"] == source["blob"] and row["source_sha256"] == case["source_sha256"] == source["sha256"]
        assert row["original_status"] == case["original_status"] == "not_testable"
        assert row["queue_status"] == case["queue_status"] == "paused_pending_evidence"
        diagnostic = diagnostics[case["line"]]
        assert diagnostic["diagnostic_id"] == case["finding_id"]
        assert diagnostic["rule_id"] == case["rule_id"] == case["a0_rule"]
        assert diagnostic["source_sha256"] == source["sha256"]
    assert len(diagnostics) == ev["cli"]["findings"] == 3
    assert ev["disposition"] == "PARTIAL/BLOCK"
    assert ev["queue_preservation"]["status_changed"] is False
    print(json.dumps({"overall_ok": True, "ids": sorted(rows), "source_commit": source["commit"], "tree": source["tree"], "mapped_candidates": 3, "parse_counts": ev["cli"]["parse_counts"], "queue_states_unchanged": True}, indent=2))


if __name__ == "__main__":
    main()

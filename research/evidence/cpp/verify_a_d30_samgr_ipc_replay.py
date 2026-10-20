"""Verify D30's exact-source replay and unchanged A0 queue states."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
EXPECTED = {
    "CR-0219": (464, "CheckRemtSystemAbilityInner"),
    "CR-0220": (551, "CheckSystemAbilityImmeInner"),
    "CR-0221": (668, "GetSystemAbilityInner"),
    "CR-0222": (706, "CheckSystemAbilityInner"),
    "CR-0223": (1485, "GetExtensionRunningSaListInner"),
    "CR-0224": (1692, "GetSystemAbilityWithUserIdInner"),
    "CR-0225": (1735, "CheckSystemAbilityWithUserIdInner"),
    "CR-0226": (1784, "CheckSystemAbilityByUserIdInner"),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", type=Path, default=QUEUE)
    args = parser.parse_args()
    replay = json.loads((EVIDENCE / "a_d30_samgr_ipc_replay_20261021.json").read_text(encoding="utf-8"))
    cli = json.loads((EVIDENCE / "a_d30_samgr_ipc_cli_20261021.json").read_text(encoding="utf-8"))
    assert replay["integration_baseline"] == "3aa6acc13ab7f39b0ebaee092a3e3e5b9b83bfa2"
    assert replay["source"]["commit_tree_blob_sha_verified"] is True
    assert replay["source"]["commit"] == "08e2a552b839ea7727251cb9b749a5c1dd9cfeff"
    assert replay["source"]["tree"] == "b7a89e95be788f2f2372258e341f7be842c7826d"
    assert replay["source"]["blob"] == "ae84d998c4d90c8c08d692b9020404593b58a0cc"
    assert replay["source"]["sha256"] == "e82aa966b6c70278c64683b3bc4c0b236cf7550da3e65aeafc12acfa5f718433"
    assert replay["cli"]["detector_version"] == "0.12.12"
    assert replay["cli"]["source_parse_status"] == "partial"
    assert replay["cli"]["rule_version"] is None
    assert cli["commit"] == replay["source"]["commit"]
    assert cli["git_tree"] == replay["source"]["tree"]
    findings = {}
    for run in cli["detector_runs"]:
        assert run["tool"] == "ohscanner.interface.ipc"
        assert run["tool_version"] == "0.12.12"
        for finding in run["diagnostics"]:
            if finding.get("rule_id") == "ipc.capability.export":
                findings[finding["line"]] = finding
    assert len(replay["cases"]) == len(EXPECTED)
    with args.queue.open(encoding="utf-8-sig", newline="") as handle:
        rows = {row["queue_id"]: row for row in csv.DictReader(handle)}
    for case in replay["cases"]:
        queue_id = case["queue_id"]
        line, method = EXPECTED[queue_id]
        assert case["line"] == line and case["method"] == method
        assert line in findings
        finding = findings[line]
        assert finding["symbol"].endswith(method)
        assert finding["source_sha256"] == replay["source"]["sha256"]
        row = rows[queue_id]
        assert row["original_status"] == "not_reproduced"
        assert row["queue_status"] == "queued_not_reproduced"
        assert case["original_status"] == row["original_status"]
        assert case["queue_status"] == row["queue_status"]
    print("PASS: source commit/tree/blob/SHA and current CLI identity verified")
    print("PASS: CR-0219–CR-0226 each map to current ipc.capability.export line/method findings")
    print("PASS: parser partial and unavailable rule-version limit remain explicit")
    print("PASS: all eight original A0 queue states preserved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

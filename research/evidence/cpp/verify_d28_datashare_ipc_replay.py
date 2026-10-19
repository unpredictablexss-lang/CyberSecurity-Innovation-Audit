#!/usr/bin/env python3
"""Verify D28's CR-0016/17/18 source binding, CLI replay and queue preservation."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path


COMMIT = "560c5cdadf08b4beeb691e93d70ff32cc2dca8bd"
TREE = "f731230c116c94d7619f5514c828b33ffac69924"
PATH = "frameworks/native/provider/src/datashare_stub.cpp"
BLOB = "cb62502d82c0534a6b9466f7a5d0a9e122d85693"
SHA256 = "cc742b1811c6c6ce2c351e27619a74ec1e5f472502a7a712c50d49fbaeed667a"
EXPECTED = {
    "CR-0016": (204, "ohscanner.interface.ipc", "0.5.0", "ipc.auth.missing"),
    "CR-0017": (221, "ohscanner.interface.ipc", "0.5.0", "ipc.capability.export"),
    "CR-0018": (243, "ohscanner.interface.ipc", "0.5.0", "ipc.capability.export"),
}


def git(git_dir: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], stderr=subprocess.PIPE)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, default=Path("research/deliveries/cpp/a0_triage_20261019/queue.csv"))
    parser.add_argument("--git-dir", type=Path, required=True)
    parser.add_argument("--cli", type=Path, default=Path("research/evidence/cpp/d28_cr0016_18_cli_20261020.json"))
    parser.add_argument("--audit", type=Path, default=Path("research/evidence/cpp/d28_cr0016_18_source_audit_20261020.json"))
    args = parser.parse_args()

    with args.queue.open("r", encoding="utf-8-sig", newline="") as stream:
        queue = list(csv.DictReader(stream))
    rows = {row["queue_id"]: row for row in queue if row.get("queue_id") in EXPECTED}
    assert len(queue) == 345 and set(rows) == set(EXPECTED)
    for queue_id, (line, detector, version, rule) in EXPECTED.items():
        row = rows[queue_id]
        assert row["repository"] == "openharmony/distributeddatamgr_data_share"
        assert row["commit"] == COMMIT and row["tree"] == TREE
        assert row["path"] == PATH and int(row["line"]) == line
        assert row["blob"] == BLOB and row["source_sha256"] == SHA256
        assert row["detector"] == detector and row["detector_version"] == version and row["rule"] == rule
        assert row["original_status"] == "not_testable"
        assert row["queue_status"] == "queued_first_batch"

    assert git(args.git_dir, "rev-parse", f"{COMMIT}^{{tree}}").decode().strip() == TREE
    data = git(args.git_dir, "show", f"{COMMIT}:{PATH}")
    assert hashlib.sha256(data).hexdigest() == SHA256
    assert git(args.git_dir, "rev-parse", f"{COMMIT}:{PATH}").decode().strip() == BLOB
    lines = data.decode("utf-8").splitlines()
    assert "fd = OpenFile(uri, mode);" in lines[203]
    assert "if (!reply.WriteFileDescriptor(fd)) {" in lines[220]
    assert "if (!reply.WriteFileDescriptor(fd)) {" in lines[242]

    cli = json.loads(args.cli.read_text(encoding="utf-8"))
    run = cli["detector_runs"][0]
    observed = {(d["line"], d["rule_id"]) for d in run["diagnostics"]}
    assert cli["commit"] == COMMIT and cli["git_tree"] == TREE
    assert cli["validated_vulnerability"] == 0
    assert run["tool"] == "ohscanner.interface.ipc" and run["tool_version"] == "0.12.12"
    assert observed == {(line, rule) for line, _, _, rule in EXPECTED.values()}
    assert cli["detector_coverage"]["detectors"]["ohscanner.interface.ipc"]["status"] == "partial"
    assert cli["source_parsing"]["parsing_status"] == {"partial": 1}
    audit = json.loads(args.audit.read_text(encoding="utf-8"))
    assert audit["analysis"]["rule_gap_reproduced"] is False
    assert audit["analysis"]["disposition"] == "PARTIAL/BLOCK"
    print(json.dumps({
        "overall_ok": True,
        "queue_rows": len(queue),
        "queue_ids": sorted(rows),
        "source": {"commit": COMMIT, "tree": TREE, "blob": BLOB, "sha256": SHA256},
        "cli_candidates": sorted([list(item) for item in observed]),
        "parse_status": cli["source_parsing"]["parsing_status"],
        "disposition": audit["analysis"]["disposition"],
        "original_queue_state": "not_testable / queued_first_batch",
        "queue_states_preserved": True,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

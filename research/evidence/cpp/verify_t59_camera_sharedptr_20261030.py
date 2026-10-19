#!/usr/bin/env python3
"""Verify independent T59 replay and immutable A0 bindings for camera rows."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = ROOT / "research/evidence/cpp"
REPORT = HERE / "t59_camera_sharedptr_audit_20261030.json"
CLI = HERE / "t59_camera_sharedptr_cli_20261030.json"
QUEUE_CSV = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
QUEUE_JSON = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
COMMIT = "35445b57d739a41cb916330935e61f1e83d982ca"
TREE = "2907d1748b46897c49c8f8c253c49384294a6a7a"
REPO = "openharmony/multimedia_camera_framework"
IDS = {f"CR-{n:04d}" for n in range(261, 291)}


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "--git-dir", str(repo), *args])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-repo", type=Path, required=True,
                    help="Pinned multimedia_camera_framework Git object store")
    args = ap.parse_args()
    source = args.source_repo.resolve()
    assert git(source, "rev-parse", f"{COMMIT}^{{commit}}").decode().strip() == COMMIT
    assert git(source, "rev-parse", f"{COMMIT}^{{tree}}").decode().strip() == TREE

    with QUEUE_CSV.open(encoding="utf-8-sig", newline="") as f:
        csv_rows = {r["queue_id"]: r for r in csv.DictReader(f)}
    qjson = json.loads(QUEUE_JSON.read_text(encoding="utf-8"))
    json_rows = {r["queue_id"]: r for r in qjson["queue"]}
    assert len(csv_rows) == len(json_rows) == 345
    assert len(IDS) == 30 and IDS <= csv_rows.keys() and IDS <= json_rows.keys()

    cli = json.loads(CLI.read_text(encoding="utf-8"))
    assert cli["repository"] == REPO
    assert cli["commit"] == COMMIT and cli["git_tree"] == TREE
    run = next(r for r in cli["detector_runs"] if r.get("tool") == "ohscanner.cpp.shared_ptr_race")
    assert run["tool_version"] == "0.5.1" and run["status"] == "blocked"
    assert run["diagnostic_count"] == len(run["diagnostics"]) == 13
    assert cli["source_parsing"]["parsing_status"] == {"complete": 13}
    assert cli["scope"]["selected_source_files"] == 13
    assert cli["scope"]["git_tree"] == TREE
    by_key = {(d["file"], int(d["line"]), int(d["column"]), d.get("symbol")): d
              for d in run["diagnostics"]}

    records = []
    for qid in sorted(IDS):
        row, nested = csv_rows[qid], json_rows[qid]
        original = nested["original_record"]
        assert (row["repository"], row["commit"], row["tree"]) == (REPO, COMMIT, TREE)
        assert (original["repository"], original["commit"], original["git_tree"]) == (REPO, COMMIT, TREE)
        assert row["path"] == original["file"]
        assert int(row["line"]) == int(original["line"])
        content = git(source, "show", f"{COMMIT}:{row['path']}")
        blob = git(source, "rev-parse", f"{COMMIT}:{row['path']}").decode().strip()
        sha = hashlib.sha256(content).hexdigest()
        assert blob == row["blob"] == original["source_binding"]["git_blob_oid"]
        assert sha == row["source_sha256"] == original["source_binding"]["actual_source_sha256"]
        assert row["original_status"] == original["final_status"]
        assert row["queue_status"] == "paused_pending_evidence"
        assert nested["queue_status"] == row["queue_status"]

        key = (row["path"], int(row["line"]), int(original["column"]), original["symbol"])
        finding = by_key.get(key)
        line = content.decode("utf-8").splitlines()[int(row["line"]) - 1]
        records.append({
            "queue_id": qid,
            "repository": REPO,
            "commit": COMMIT,
            "tree": TREE,
            "source": {"path": row["path"], "line": int(row["line"]),
                       "column": int(original["column"]), "symbol": original["symbol"],
                       "blob": blob, "sha256": sha, "line_text": line.strip()},
            "original_status": row["original_status"],
            "queue_status": row["queue_status"],
            "current_cli": ({"matched": True, "diagnostic_id": finding["diagnostic_id"],
                             "line": finding["line"], "column": finding["column"],
                             "symbol": finding.get("symbol"), "rule_id": finding["rule_id"]}
                            if finding else {"matched": False}),
            "parse_status": "complete",
            "build_context": "GN product inclusion, enabled feature profile, and testonly status not established for this individual header/row",
            "safety_or_vulnerability_verdict": "unknown",
        })

    matched = sum(bool(r["current_cli"]["matched"]) for r in records)
    assert matched == 10
    assert all(r["original_status"] == "not_testable" and
               r["queue_status"] == "paused_pending_evidence" for r in records)
    audit = {
        "schema_version": 1,
        "task": "T59 independent camera framework shared_ptr_race acceptance",
        "result": "PARTIAL/BLOCK",
        "source": {"repository": REPO, "commit": COMMIT, "tree": TREE,
                   "git_object_source": "local pinned project object database"},
        "replay": {"command": "python -m src.cli.main ohscan-run --repo-dir <pinned-checkout> --repository openharmony/multimedia_camera_framework --commit 35445b57d739a41cb916330935e61f1e83d982ca --include <13 A0 paths> --detector ohscanner.cpp.shared_ptr_race",
                   "detector": "ohscanner.cpp.shared_ptr_race", "version": "0.5.1",
                   "parse": {"complete": 13}, "selected_files": 13,
                   "diagnostics": 13, "run_status": "blocked",
                   "a0_exact_line_column_symbol_hits": matched,
                   "a0_exact_line_column_symbol_misses": len(records) - matched,
                   "scope": "13 files uniquely referenced by CR-0261–CR-0290"},
        "a0_queue": {"csv_rows": len(csv_rows), "json_rows": len(json_rows),
                     "target_rows": len(records), "ids_unchanged": True,
                     "original_and_queue_states_unchanged": True},
        "limitations": [
            "All 30 rows remain not_testable / paused_pending_evidence; line-level findings are syntax candidates, not confirmed races or vulnerabilities.",
            "Complete syntax parsing does not establish full detector semantic coverage, cross-function ownership/aliasing, lock dominance, actual thread overlap, attacker control, product inclusion, or security impact.",
            "GN product/testonly status is not established per row/header; enabled product profile and test target dependencies need owner build evidence.",
            "No trusted fixed-source pair or target-derived runtime/TSan harness was provided for these A0 rows.",
        ],
        "minimum_followup": [
            "For each candidate member, enumerate all reads/writes, object aliases, lock identity/guard dominance, and callback/executor lifecycle in callers.",
            "Resolve exact GN production target and feature/macro profile, and distinguish testonly harnesses from product-linked targets.",
            "For remaining concrete conflicting accesses, provide target-derived reproducer/TSan evidence and a trustworthy fixed revision; otherwise retain PARTIAL/BLOCK.",
        ],
        "rows": records,
    }
    REPORT.write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("PASS source commit/tree and 30 exact row blob/SHA bindings")
    print(f"PASS 345 A0 IDs; 30 row identities/statuses unchanged; exact current CLI match {matched}/30")
    print("PASS current CLI replay: 13 files, 13 complete parses, 13 diagnostics; PARTIAL/BLOCK preserved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

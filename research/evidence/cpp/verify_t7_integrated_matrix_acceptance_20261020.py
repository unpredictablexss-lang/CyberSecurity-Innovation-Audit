#!/usr/bin/env python3
"""Verify T7's integrated 13-row A-line matrix accounting and evidence references."""

from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RECORD = Path(__file__).with_name("t7_integrated_matrix_acceptance_20261020.json")
EXPECTED_HEAD = "790e353846b6c0d7926ee46290dcbc2873c8cad0"
SCANNER_FREEZE = "81dd4aea9bb51522ac912b33504ef0d2ddb79089"
EXPECTED_QUEUE_SHA = "a174c0a74986e8410c53f173b84bb446c59000c3867add612a14e8aab4396d27"
EXPECTED_QUEUE_COUNTS = Counter({"not_testable": 336, "not_reproduced": 9})
EXPECTED_QUEUE_STATES = Counter({
    "paused_pending_evidence": 331,
    "queued_first_batch": 5,
    "queued_not_reproduced": 9,
})


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main() -> int:
    data = json.loads(RECORD.read_text(encoding="utf-8"))
    errors: list[str] = []
    is_descendant = subprocess.run(
        ["git", "merge-base", "--is-ancestor", EXPECTED_HEAD, "HEAD"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    if not is_descendant:
        errors.append("HEAD does not descend from the recorded 790e353 integration base")
    src_diff = subprocess.run(
        ["git", "diff", "--quiet", SCANNER_FREEZE, "HEAD", "--", "src"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode
    if src_diff != 0:
        errors.append("scanner src differs from frozen scanner commit")

    matrix_path = ROOT / "research/evidence/cpp/a_static_baseline_20261019/matrix.json"
    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    rows = data.get("cases", [])
    original_ids = [item["case_id"] for item in matrix["cases"]]
    if len(original_ids) != 13 or [row.get("case_id") for row in rows] != original_ids:
        errors.append("T7 rows do not exactly cover the original 13-row matrix in order")
    prior = Counter(row.get("prior_t12") for row in rows)
    statuses = Counter(row.get("bounded_static_regression") for row in rows)
    product_statuses = Counter(row.get("case_product_disposition") for row in rows)
    if prior != Counter({"PASS": 3, "PARTIAL": 8, "N/A": 2}):
        errors.append(f"prior T12 counts mismatch: {dict(prior)}")
    if statuses != Counter({"PASS": 2, "PARTIAL": 9, "N/A": 2}):
        errors.append(f"T7 bounded static regression counts mismatch: {dict(statuses)}")
    if product_statuses != Counter({"PARTIAL/BLOCK": 11, "N/A": 2}):
        errors.append(f"T7 case/product disposition counts mismatch: {dict(product_statuses)}")
    if data.get("counts", {}).get("t7_bounded_static_regression") != dict(statuses):
        errors.append("machine bounded-static summary does not match its rows")
    expected_product_counts = {"PASS": 0, "PARTIAL/BLOCK": 11, "N/A": 2}
    if data.get("counts", {}).get("t7_case_product_disposition") != expected_product_counts:
        errors.append("machine case/product summary does not match its rows")

    for row in rows:
        if row.get("bounded_static_regression") == "PASS":
            cli = row.get("cli", {})
            if not (cli.get("vulnerable_findings", 0) > 0 and cli.get("fixed_findings") == 0
                    and cli.get("parse") == "complete on both sides"
                    and cli.get("coverage") == "complete"):
                errors.append(f"PASS row lacks complete vulnerable/fixed CLI evidence: {row['case_id']}")
            if row.get("safe_unrelated_control", "").startswith("BLOCK"):
                errors.append(f"PASS row has a blocked safe/unrelated control: {row['case_id']}")
        for evidence in row.get("evidence", []):
            if not (ROOT / evidence).is_file():
                errors.append(f"missing evidence reference: {evidence}")

    queue = data.get("a0_invariant", {})
    queue_path = ROOT / queue.get("queue_path", "")
    queue_bytes = queue_path.read_bytes()
    queue_sha = hashlib.sha256(queue_bytes).hexdigest()
    if queue_sha != EXPECTED_QUEUE_SHA or queue_sha != queue.get("csv_sha256"):
        errors.append(f"A0 queue SHA changed: {queue_sha}")
    base_bytes = subprocess.check_output(
        ["git", "show", f"{EXPECTED_HEAD}:{queue['queue_path']}"], cwd=ROOT
    )
    if base_bytes != queue_bytes:
        errors.append("A0 queue differs from the integrated base commit")
    parsed = list(csv.DictReader(queue_path.open(encoding="utf-8-sig", newline="")))
    ids = [row["candidate_id"] for row in parsed]
    original_counts = Counter(row["original_status"] for row in parsed)
    queue_states = Counter(row["queue_status"] for row in parsed)
    if len(parsed) != 345 or len(set(ids)) != 345:
        errors.append("A0 queue does not contain 345 unique candidate IDs")
    if original_counts != EXPECTED_QUEUE_COUNTS:
        errors.append(f"A0 original status counts changed: {dict(original_counts)}")
    if queue_states != EXPECTED_QUEUE_STATES:
        errors.append(f"A0 queue status counts changed: {dict(queue_states)}")

    for record in data.get("verifiers", []):
        if not (ROOT / record["path"]).is_file():
            errors.append(f"missing verifier reference: {record['path']}")

    print(json.dumps({
        "result": "PASS_T7_INTEGRATED_MATRIX_ACCOUNTING" if not errors else "FAIL",
        "integrated_head": run("git", "rev-parse", "HEAD"),
        "scanner_src_unchanged_from_freeze": src_diff == 0,
        "original_matrix_rows": len(rows),
        "prior_t12_counts": dict(prior),
        "t7_bounded_static_regression_counts": dict(statuses),
        "t7_case_product_disposition_counts": dict(product_statuses),
        "a0_rows": len(parsed),
        "a0_unique_ids": len(set(ids)),
        "a0_csv_sha256": queue_sha,
        "errors": errors,
    }, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())

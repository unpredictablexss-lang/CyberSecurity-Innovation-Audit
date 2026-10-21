#!/usr/bin/env python3
"""Verify the copied A0 evidence package without modifying historical files."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
SAMPLE = HERE.parents[3] / "research" / "deliveries" / "cpp" / "a0_original_20261018" / "sample30"
TRIAGE = HERE.parents[3] / "research" / "deliveries" / "cpp" / "a0_original_20261018" / "triage"


def main() -> int:
    manifest = json.loads((SAMPLE / "evidence" / "hashes.json").read_text(encoding="utf-8"))
    reviews = json.loads((SAMPLE / "evidence" / "candidate_reviews.json").read_text(encoding="utf-8"))
    samples = json.loads((SAMPLE / "evidence" / "sample_manifest.json").read_text(encoding="utf-8"))
    queue = json.loads((TRIAGE / "queue.json").read_text(encoding="utf-8"))
    with (TRIAGE / "queue.csv").open(encoding="utf-8-sig", newline="") as stream:
        csv_rows = list(csv.DictReader(stream))

    missing: list[str] = []
    mismatched: list[str] = []
    total_bytes = 0
    for item in manifest["files"]:
        path = SAMPLE / item["path"]
        if not path.is_file():
            missing.append(item["path"])
            continue
        content = path.read_bytes()
        total_bytes += len(content)
        if len(content) != item["size_bytes"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
            mismatched.append(item["path"])

    source_by_id = {item["diagnostic_id"]: item for item in reviews["records"]}
    queue_by_id = {item["candidate_id"]: item for item in queue["queue"]}
    csv_by_id = {item["candidate_id"]: item for item in csv_rows}
    sample_by_order = {item["sample_order"]: item for item in samples["records"]}
    key_mismatches: list[str] = []
    for candidate_id, source in source_by_id.items():
        item = queue_by_id.get(candidate_id)
        if item is None:
            key_mismatches.append(candidate_id)
            continue
        source_values = [
            source.get("review_id"), source.get("repository"), source.get("commit"),
            source.get("git_tree"), source.get("file"), source.get("scanner_provider"),
            source.get("detector_version"), source.get("rule_id"), source.get("final_status"),
            source.get("source_binding", {}).get("git_blob_oid"),
            source.get("source_binding", {}).get("actual_source_sha256"),
            sample_by_order.get(source["sample_order"], {}).get("profile_id"),
        ]
        queue_values = [
            item.get("original_review_id"), item.get("repository"), item.get("commit"),
            item.get("tree"), item.get("path"), item.get("detector"),
            item.get("detector_version"), item.get("rule"), item.get("original_status"),
            item.get("blob"), item.get("source_sha256"), item.get("profile"),
        ]
        if source_values != queue_values:
            key_mismatches.append(candidate_id)

    statuses = Counter(item["original_status"] for item in queue["queue"])
    queue_states = Counter(item["queue_status"] for item in queue["queue"])
    source_ids = set(source_by_id)
    queue_ids = set(queue_by_id)
    checks = {
        "all_manifest_files_present_and_hash_bound": not missing and not mismatched,
        "source_record_keys_match_queue": not key_mismatches,
        "all_345_unique_ids_preserved": len(source_ids) == len(queue["queue"]) == len(csv_rows) == 345
        and source_ids == queue_ids == set(csv_by_id),
        "original_status_counts_preserved": statuses == {"not_testable": 336, "not_reproduced": 9},
        "queue_state_counts_preserved": queue_states == {
            "paused_pending_evidence": 331,
            "queued_first_batch": 5,
            "queued_not_reproduced": 9,
        },
    }
    result = {
        "manifest_entries": len(manifest["files"]),
        "manifest_bytes_verified": total_bytes,
        "missing": missing,
        "hash_mismatches": mismatched,
        "source_records": len(source_ids),
        "queue_rows": len(queue["queue"]),
        "csv_rows": len(csv_rows),
        "unique_ids": len(queue_ids),
        "source_key_mismatches": key_mismatches,
        "original_status_counts": dict(sorted(statuses.items())),
        "queue_state_counts": dict(sorted(queue_states.items())),
        "checks": checks,
        "overall_ok": all(checks.values()),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["overall_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Read-only reconciliation for the 2026-10-19 A0 candidate triage refresh."""
from __future__ import annotations

import collections
import csv
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = pathlib.Path(
    r"D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\a-line-sample30\20261018"
)
TRIAGE_SOURCE = pathlib.Path(
    r"D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\a-line-triage\20261018"
)


def load(path: pathlib.Path):
    return json.loads(path.read_text(encoding="utf-8"))


hash_manifest = load(SOURCE / "evidence/hashes.json")
reviews = load(SOURCE / "evidence/candidate_reviews.json")
samples = load(SOURCE / "evidence/sample_manifest.json")
reconciliation = load(SOURCE / "evidence/reconciliation.json")
queue_doc = load(HERE / "queue.json")
reference_queue = load(TRIAGE_SOURCE / "queue.json")
with (HERE / "queue.csv").open(encoding="utf-8-sig", newline="") as stream:
    csv_rows = list(csv.DictReader(stream))

missing: list[str] = []
mismatched: list[str] = []
for entry in hash_manifest["files"]:
    path = SOURCE / entry["path"]
    if not path.is_file():
        missing.append(entry["path"])
        continue
    data = path.read_bytes()
    if len(data) != entry["size_bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        mismatched.append(entry["path"])

source_by_id = {item["diagnostic_id"]: item for item in reviews["records"]}
queue_by_id = {item["candidate_id"]: item for item in queue_doc["queue"]}
csv_by_id = {item["candidate_id"]: item for item in csv_rows}
key_mismatches: list[str] = []
duplicate_ids = len(queue_doc["queue"]) - len(queue_by_id)
sample_by_order = {item["sample_order"]: item for item in samples["records"]}
fields = (
    ("review_id", "original_review_id"),
    ("repository", "repository"),
    ("commit", "commit"),
    ("git_tree", "tree"),
    ("file", "path"),
    ("scanner_provider", "detector"),
    ("detector_version", "detector_version"),
    ("rule_id", "rule"),
    ("final_status", "original_status"),
)
for candidate_id, source in source_by_id.items():
    item = queue_by_id.get(candidate_id)
    if item is None:
        key_mismatches.append(candidate_id)
        continue
    expected_values = [source.get(a) for a, _ in fields]
    actual_values = [item.get(b) for _, b in fields]
    expected_values += [
        source.get("source_binding", {}).get("git_blob_oid"),
        source.get("source_binding", {}).get("actual_source_sha256"),
        sample_by_order.get(source["sample_order"], {}).get("profile_id"),
    ]
    actual_values += [item.get("blob"), item.get("source_sha256"), item.get("profile")]
    if expected_values != actual_values:
        key_mismatches.append(candidate_id)

statuses = collections.Counter(item["original_status"] for item in queue_doc["queue"])
reference_ids = {item["candidate_id"] for item in reference_queue["queue"]}
source_ids = set(source_by_id)
queue_ids = set(queue_by_id)
priority_counts = collections.Counter(item["queue_status"] for item in queue_doc["queue"])
unknown_leakage = sum(
    "unknown" in (item.get("family_leakage") or "").lower() for item in queue_doc["queue"]
)
required_fields = (
    "potential_impact_score",
    "boundary_sensitivity_score",
    "evidence_completeness_score",
    "evidence_cost_score",
    "replayability_score",
    "blocker_category",
    "minimum_next_evidence_action",
    "priority_reason",
    "owner",
    "dependency",
    "queue_status",
    "family_key",
    "family_leakage",
)
incomplete_actions = [
    item["candidate_id"]
    for item in queue_doc["queue"]
    if any(item.get(field) in (None, "") for field in required_fields)
]
checks = {
    "source_hash_manifest_files_present_and_matching": not missing and not mismatched,
    "source_keys_match_A0": not key_mismatches,
    "all_A0_candidate_ids_retained": source_ids == queue_ids == reference_ids,
    "csv_and_json_ids_match": queue_ids == set(csv_by_id) and len(csv_rows) == len(csv_by_id),
    "no_duplicate_queue_ids": duplicate_ids == 0,
    "source_candidate_count_is_345": len(source_ids) == 345,
    "queue_count_is_345": len(queue_doc["queue"]) == 345,
    "original_status_counts_preserved": statuses == {"not_reproduced": 9, "not_testable": 336},
    "not_reproduced_rows_remain_queued": priority_counts["queued_not_reproduced"] == 9,
    "first_batch_is_actionable_not_testable": priority_counts["queued_first_batch"] == 5,
    "remaining_not_testable_rows_remain_queued": priority_counts["paused_pending_evidence"] == 331,
    "unknown_family_leakage_is_explicit": unknown_leakage == 345,
    "all_rows_have_action_and_ranking_fields": not incomplete_actions,
    "A0_reconciliation_candidate_count_is_345": reconciliation["canonical_counts"]["scan_candidates"] == 345
    and reconciliation["observed_counts"]["json"]["scan_candidates"] == 345,
}
result = {
    "verification_date": "2026-10-19",
    "source_root": str(SOURCE),
    "source_hash_manifest_entries": len(hash_manifest["files"]),
    "source_hash_manifest_bytes": sum(x["size_bytes"] for x in hash_manifest["files"]),
    "missing_source_materials": missing,
    "hash_mismatches": mismatched,
    "source_candidates": len(source_ids),
    "queue_rows": len(queue_doc["queue"]),
    "csv_rows": len(csv_rows),
    "unique_queue_ids": len(queue_ids),
    "duplicate_queue_ids": duplicate_ids,
    "duplicate_csv_ids": len(csv_rows) - len(csv_by_id),
    "source_key_mismatches": key_mismatches,
    "original_status_counts": dict(sorted(statuses.items())),
    "queue_status_counts": dict(sorted(priority_counts.items())),
    "unknown_family_leakage_rows": unknown_leakage,
    "rows_missing_action_or_ranking_fields": incomplete_actions,
    "checks": checks,
    "overall_ok": all(checks.values()),
}
(HERE / "reconciliation_20261019.json").write_bytes(
    (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
)
artifact_names = (
    "README.md",
    "family_audit.json",
    "input_identity_20261019.json",
    "queue.csv",
    "queue.json",
    "reconciliation_20261019.json",
    "verify_triage.py",
)
artifact_hashes = {
    name: {
        "size_bytes": (HERE / name).stat().st_size,
        "sha256": hashlib.sha256((HERE / name).read_bytes()).hexdigest(),
    }
    for name in artifact_names
}
(HERE / "artifact_hashes.json").write_bytes(
    (json.dumps(artifact_hashes, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
)
print(json.dumps(result, ensure_ascii=False, indent=2))
sys.exit(0 if result["overall_ok"] else 1)

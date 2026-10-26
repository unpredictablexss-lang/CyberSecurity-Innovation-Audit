from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable


DISPOSITIONS = {
    "confirmed",
    "not_reproduced",
    "not_testable",
    "safe_or_fixed",
    "known_false_positive",
    "unknown",
}
CONFIDENCES = {"high", "medium", "low"}
IMMUTABLE_REVIEW_FIELDS = (
    "review_sample_id",
    "repository",
    "commit",
    "file",
    "line",
    "source_sha256",
    "source_binding_status",
    "source_context",
)
REVIEW_FIELDS = (
    "reviewer_disposition",
    "reviewer_rationale",
    "evidence_reference",
    "confidence",
    "reviewer_id",
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames:
            raise ValueError(f"CSV has no header: {path}")
        return list(reader.fieldnames), list(reader)


def index_unique(rows: Iterable[dict[str, str]], label: str) -> dict[str, dict[str, str]]:
    result = {}
    for row in rows:
        sample_id = row.get("review_sample_id", "")
        if not sample_id or sample_id in result:
            raise ValueError(f"missing or duplicate review_sample_id in {label}: {sample_id!r}")
        result[sample_id] = row
    return result


def _load_sampling_manifest(canonical_queue: Path) -> dict:
    manifest_path = canonical_queue.parent.parent / "sampling_manifest.json"
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def merge_locked_labels(
    canonical_queue: Path,
    submitted_queue: Path,
    coordinator_key: Path,
    locked_sha256: str,
) -> tuple[list[dict[str, str]], dict]:
    actual_hash = file_sha256(submitted_queue)
    if actual_hash.lower() != locked_sha256.lower():
        raise ValueError("submitted review queue hash does not match the frozen label lock")

    expected_headers, expected_rows = read_csv(canonical_queue)
    submitted_headers, submitted_rows = read_csv(submitted_queue)
    key_headers, key_rows = read_csv(coordinator_key)
    expected = index_unique(expected_rows, "canonical queue")
    submitted = index_unique(submitted_rows, "submitted queue")
    key = index_unique(key_rows, "coordinator key")
    if set(submitted) != set(expected):
        missing = sorted(set(expected) - set(submitted))
        extra = sorted(set(submitted) - set(expected))
        raise ValueError(f"sample ID set changed; missing={missing[:5]}, extra={extra[:5]}")
    if set(key) != set(expected):
        raise ValueError("coordinator key sample IDs do not exactly match the blind queue")
    if submitted_headers != expected_headers:
        raise ValueError("submitted queue schema changed; preserve the original header and column order")
    for sample_id, row in submitted.items():
        canonical = expected[sample_id]
        for field in IMMUTABLE_REVIEW_FIELDS:
            if row.get(field) != canonical.get(field):
                raise ValueError(f"immutable source/evidence field changed for {sample_id}: {field}")
        for field in REVIEW_FIELDS:
            if field not in submitted_headers or not row.get(field, "").strip():
                raise ValueError(f"review label is incomplete for {sample_id}: {field}")
        if row["reviewer_disposition"] not in DISPOSITIONS:
            raise ValueError(f"invalid disposition for {sample_id}: {row['reviewer_disposition']!r}")
        if row["confidence"] not in CONFIDENCES:
            raise ValueError(f"invalid confidence for {sample_id}: {row['confidence']!r}")

    private_headers = [field for field in key_headers if field != "review_sample_id"]
    merged = []
    weighted_counts: defaultdict[str, float] = defaultdict(float)
    label_counts: Counter[str] = Counter()
    reviewers: set[str] = set()
    for sample_id in sorted(expected):
        row = dict(submitted[sample_id])
        row.update({field: key[sample_id][field] for field in private_headers})
        merged.append(row)
        label = submitted[sample_id]["reviewer_disposition"]
        probability = float(key[sample_id]["inclusion_probability"])
        if not 0 < probability <= 1:
            raise ValueError(f"invalid inclusion probability for {sample_id}: {probability}")
        label_counts[label] += 1
        weighted_counts[label] += 1.0 / probability
        reviewers.add(submitted[sample_id]["reviewer_id"])

    sampling = _load_sampling_manifest(canonical_queue)
    dimensions = sampling["report_count_dimensions"]
    summary = {
        "schema_version": "ohscanner.a-unsafe-memory-blind-review-results-v1",
        "frozen_review_queue_sha256": actual_hash,
        "sample_size": len(merged),
        "reviewer_ids": sorted(reviewers),
        "report_count_dimensions": {
            "raw_observation_rows": dimensions["raw_observation_rows"],
            "within_repository_root_cause_clusters": dimensions["within_repository_root_cause_clusters"],
            "cross_repository_identical_source_clusters": dimensions["cross_repository_identical_source_clusters"],
            "human_review_outcomes": {
                "reviewed": len(merged),
                "pending": 0,
                "disposition_counts_in_sample": dict(sorted(label_counts.items())),
                "estimated_population_by_disposition_ht": {
                    label: round(value, 3) for label, value in sorted(weighted_counts.items())
                },
                "estimator": "Horvitz-Thompson sum of 1/inclusion_probability within the frozen stratified sample; provisional for the 9,323-row frame, not the unresolved 8,994 target.",
                "status": "labels_frozen_independent_review_claim_unverified",
            },
        },
        "limitations": [
            "This tool validates label completeness and mapping integrity; it does not independently verify reviewer identity or label correctness.",
            "Population estimates apply only to the pinned provisional sample frame and must not be presented as precision/recall.",
            "Root-cause clusters remain unknown unless reviewers provide a separately validated root-cause identity.",
        ],
    }
    return merged, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and privately merge a frozen blind-review queue.")
    parser.add_argument("--canonical-queue", type=Path, required=True)
    parser.add_argument("--submitted-queue", type=Path, required=True)
    parser.add_argument("--coordinator-key", type=Path, required=True)
    parser.add_argument("--locked-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    coordinator_dir = args.coordinator_key.resolve().parent
    if not output_dir.is_relative_to(coordinator_dir):
        raise SystemExit("private merged outputs must stay under the coordinator directory")
    merged, summary = merge_locked_labels(
        args.canonical_queue.resolve(),
        args.submitted_queue.resolve(),
        args.coordinator_key.resolve(),
        args.locked_sha256,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    merged_path = output_dir / "merged_review_labels.csv"
    summary_path = output_dir / "review_summary.json"
    fields = list(merged[0]) if merged else []
    with merged_path.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        writer.writerows(merged)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"sample_size": len(merged), "queue_sha256": summary["frozen_review_queue_sha256"], "summary": str(summary_path)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate and privately merge a frozen A-NULL blind-review queue."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Iterable


DISPOSITIONS = {
    "confirmed",
    "safe_or_fixed",
    "known_false_positive",
    "not_reproduced",
    "not_testable",
    "unknown",
}
CONFIDENCES = {"high", "medium", "low"}
IMMUTABLE_FIELDS = (
    "review_sample_id",
    "repository",
    "commit",
    "file",
    "line",
    "source_sha256",
    "source_binding_status",
    "source_context",
)
LABEL_FIELDS = (
    "reviewer_disposition",
    "reviewer_rationale",
    "evidence_reference",
    "confidence",
    "reviewer_id",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames:
            raise ValueError(f"CSV has no header: {path}")
        return reader.fieldnames, list(reader)


def index_unique(rows: Iterable[dict[str, str]], label: str) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        sample_id = row.get("review_sample_id", "")
        if not sample_id or sample_id in indexed:
            raise ValueError(f"missing or duplicate review_sample_id in {label}: {sample_id!r}")
        indexed[sample_id] = row
    return indexed


def merge_labels(
    canonical_queue: Path,
    submitted_queue: Path,
    coordinator_key: Path,
    locked_sha256: str,
) -> tuple[list[str], list[dict[str, str]], dict]:
    actual_hash = sha256(submitted_queue)
    if actual_hash.lower() != locked_sha256.lower():
        raise ValueError("submitted queue SHA-256 does not match frozen label lock")

    canonical_headers, canonical_rows = read_csv(canonical_queue)
    submitted_headers, submitted_rows = read_csv(submitted_queue)
    _key_headers, key_rows = read_csv(coordinator_key)
    canonical = index_unique(canonical_rows, "canonical queue")
    submitted = index_unique(submitted_rows, "submitted queue")
    key = index_unique(key_rows, "coordinator key")
    if submitted_headers != canonical_headers:
        raise ValueError("submitted queue schema/order changed; preserve canonical header")
    if set(submitted) != set(canonical):
        raise ValueError("submitted sample IDs do not exactly match canonical queue")
    if set(key) != set(canonical):
        raise ValueError("coordinator key sample IDs do not exactly match canonical queue")

    for sample_id, row in submitted.items():
        original = canonical[sample_id]
        for field in IMMUTABLE_FIELDS:
            if row.get(field) != original.get(field):
                raise ValueError(f"immutable evidence changed for {sample_id}: {field}")
        for field in LABEL_FIELDS:
            if not row.get(field, "").strip():
                raise ValueError(f"review label is incomplete for {sample_id}: {field}")
        if row["reviewer_disposition"] not in DISPOSITIONS:
            raise ValueError(f"invalid disposition for {sample_id}: {row['reviewer_disposition']!r}")
        if row["confidence"] not in CONFIDENCES:
            raise ValueError(f"invalid confidence for {sample_id}: {row['confidence']!r}")

    key_headers = _key_headers
    private_fields = [field for field in key_headers if field != "review_sample_id"]
    merged: list[dict[str, str]] = []
    counts: Counter[str] = Counter()
    reviewers: set[str] = set()
    for sample_id in sorted(canonical):
        row = dict(submitted[sample_id])
        row.update({field: key[sample_id].get(field, "") for field in private_fields})
        merged.append(row)
        counts[row["reviewer_disposition"]] += 1
        reviewers.add(row["reviewer_id"])

    manifest_path = canonical_queue.parent.parent / "sampling_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_sample_size = manifest.get("sample_size")
    if expected_sample_size != len(merged):
        raise ValueError("merged label count disagrees with sampling manifest")
    summary = {
        "schema_version": "ohscanner.a-null-blind-review-results-v1",
        "frozen_review_queue_sha256": actual_hash,
        "pilot_run_identity": manifest.get("run_identity"),
        "observed_raw_population": manifest.get("observed_raw_population"),
        "unbound_expected_population_claim": manifest.get("expected_population_claim"),
        "sample_size": len(merged),
        "reviewer_ids": sorted(reviewers),
        "disposition_counts_in_sample": dict(sorted(counts.items())),
        "human_review_outcomes": {
            "reviewed": len(merged),
            "pending": 0,
            "status": "labels_frozen_independent_review_claim_unverified",
        },
        "limitations": [
            "This validates completeness and key mapping only; reviewer identity and label correctness are not independently verified.",
            "The pilot is for the pinned observed frame and is not representative of the unbound expected population claim.",
            "Do not report precision/recall from this pilot without a separately justified sampling and ground-truth protocol.",
        ],
    }
    return canonical_headers + private_fields, merged, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
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
    if output_dir.exists():
        raise SystemExit(f"refusing to overwrite existing output directory: {output_dir}")
    headers, rows, summary = merge_labels(
        args.canonical_queue.resolve(),
        args.submitted_queue.resolve(),
        args.coordinator_key.resolve(),
        args.locked_sha256,
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    with (output_dir / "merged_review_labels.csv").open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    (output_dir / "review_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"sample_size": len(rows), "queue_sha256": summary["frozen_review_queue_sha256"], "summary": str(output_dir / "review_summary.json")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Audit NULL candidate counts and identity for a pinned full-scan artifact.

The reported 546,559 count is an external task claim, not an input artifact.
This script verifies the locally available run and reports the mismatch without
assuming the two counts refer to the same population.
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any


NULL_DETECTOR = "ohscanner.cpp.null_dereference"
DEFAULT_SCAN_ROOT = Path(r"D:\openHarmonyScanner\openharmony-abcd-full-scan-20261018-final")
DEFAULT_REPORT_ROOT = Path(r"D:\openHarmonyScanner\openharmony-scan-reports-20261018")
DEFAULT_REPORTED_COUNT = 546_559
MESSAGE_DIMENSIONS = {
    key: re.compile(r"\b" + key + r"=([^;]+)")
    for key in ("null_source", "sink", "guard_relation", "error_path")
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-root", type=Path, default=DEFAULT_SCAN_ROOT)
    parser.add_argument("--report-root", type=Path, default=DEFAULT_REPORT_ROOT)
    parser.add_argument("--reported-count", type=int, default=DEFAULT_REPORTED_COUNT)
    parser.add_argument("--output", type=Path, help="write the JSON result directly as UTF-8")
    args = parser.parse_args()

    config = read_json(args.scan_root / "run_config.json")
    summary = read_json(args.report_root / "compact-summary.json")
    checksums = read_json(args.report_root / "checksums.json")
    csv_path = args.scan_root / "candidate_results.csv"
    detector_rows = 0
    all_rows = 0
    ids: collections.Counter[str] = collections.Counter()
    rule_counts: collections.Counter[str] = collections.Counter()
    shape_counts: dict[str, collections.Counter[str]] = {
        key: collections.Counter() for key in (*MESSAGE_DIMENSIONS, "analysis_status")
    }
    repository_counts: collections.Counter[str] = collections.Counter()

    with csv_path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            all_rows += 1
            if row.get("detector") != NULL_DETECTOR:
                continue
            detector_rows += 1
            rule_counts[row.get("rule_id", "")] += 1
            ids[row.get("diagnostic_id", "")] += 1
            repository_counts[row.get("repository", "<missing>")] += 1
            shape_counts["analysis_status"][row.get("analysis_status") or "missing"] += 1
            message = row.get("message", "")
            for key, pattern in MESSAGE_DIMENSIONS.items():
                match = pattern.search(message)
                shape_counts[key][match.group(1) if match else "missing"] += 1

    nonempty_ids = {diagnostic_id: count for diagnostic_id, count in ids.items() if diagnostic_id}
    unique_ids = len(nonempty_ids)
    duplicate_rows = sum(nonempty_ids.values()) - unique_ids
    duplicate_ids = {diagnostic_id for diagnostic_id, count in nonempty_ids.items() if count > 1}
    duplicate_details: dict[str, list[dict[str, str]]] = collections.defaultdict(list)
    if duplicate_ids:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as source:
            for row in csv.DictReader(source):
                if row.get("detector") == NULL_DETECTOR and row.get("diagnostic_id") in duplicate_ids:
                    duplicate_details[row["diagnostic_id"]].append(
                        {key: row.get(key, "") for key in (
                            "repository", "manifest_commit", "rule_id", "file", "line", "analysis_status", "result_path"
                        )}
                    )
    duplicate_result_diagnostic_counts: dict[str, dict[str, int]] = {}
    for diagnostic_id, rows in duplicate_details.items():
        result_counts = {}
        for result_path in {row["result_path"] for row in rows}:
            normalized = result_path.replace("\\", "/")
            path_parts = normalized.split("/")
            try:
                projects_index = path_parts.index("projects")
                result_json_path = args.scan_root / "projects" / path_parts[projects_index + 1] / "result.json"
            except (ValueError, IndexError) as exc:
                raise ValueError(f"cannot resolve duplicate row result_path: {result_path}") from exc
            result_data = read_json(result_json_path)
            count = sum(
                diagnostic.get("diagnostic_id") == diagnostic_id
                for run in result_data.get("detector_runs", [])
                for diagnostic in run.get("diagnostics", [])
            )
            result_counts[result_path] = count
        duplicate_result_diagnostic_counts[diagnostic_id] = result_counts
    actual_compact_sha = sha256(args.report_root / "compact-summary.json")
    detector_summary_path = args.report_root / "检测器能力.csv"
    actual_detector_summary_sha = sha256(detector_summary_path)
    detector_summary_rows = {}
    with detector_summary_path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            if row.get("detector") == NULL_DETECTOR:
                detector_summary_rows[row["detector"]] = row
    detector_summary_candidate_count = int(detector_summary_rows[NULL_DETECTOR]["candidate_count"])
    expected_identity = {
        "run_signature": config.get("run_signature"),
        "scanner_commit": config.get("scanner_commit"),
        "manifest_sha256": config.get("manifest_sha256"),
    }
    report_identity = summary.get("scanner", {})
    checks = {
        "null_detector_enabled_in_run_config": NULL_DETECTOR in config.get("detectors", []),
        "scan_and_report_identity_match": expected_identity == {
            "run_signature": report_identity.get("run_signature"),
            "scanner_commit": report_identity.get("commit"),
            "manifest_sha256": report_identity.get("manifest_sha256"),
        },
        "compact_summary_checksum_matches": checksums.get("compact-summary.json") == actual_compact_sha,
        "detector_summary_checksum_matches": checksums.get("检测器能力.csv") == actual_detector_summary_sha,
        "csv_rows_match_summary": all_rows == summary.get("results", {}).get("candidate_count"),
        "null_raw_rows_match_cwe_summary": detector_rows
        == summary.get("candidate_counts_by_cwe", {}).get("ohcpp-null-dereference-candidate-001"),
        "null_raw_rows_match_detector_summary": detector_rows
        == summary.get("candidate_counts_by_detector", {}).get(NULL_DETECTOR),
        "detector_summary_count_matches_unique_ids": detector_summary_candidate_count == unique_ids,
        "duplicate_csv_ids_have_single_result_diagnostic": all(
            count == 1
            for per_path_counts in duplicate_result_diagnostic_counts.values()
            for count in per_path_counts.values()
        ),
        "diagnostic_ids_nonempty": len(nonempty_ids) == len(ids),
        "each_shape_dimension_reconciles_to_raw_rows": all(
            sum(counts.values()) == detector_rows for counts in shape_counts.values()
        ),
    }
    report = {
        "audit_status": "PASS" if all(checks.values()) else "FAIL",
        "reported_count": args.reported_count,
        "reported_count_source_status": "unbound_task_claim",
        "audited_run": expected_identity,
        "scan_scope": summary.get("scope"),
        "candidate_csv_sha256": sha256(csv_path),
        "candidate_csv_rows": all_rows,
        "null_detector": NULL_DETECTOR,
        "null_raw_observation_rows": detector_rows,
        "null_rows_by_rule_id": dict(sorted(rule_counts.items())),
        "null_unique_diagnostic_ids": unique_ids,
        "null_duplicate_id_rows": duplicate_rows,
        "null_duplicate_diagnostic_ids": sorted(duplicate_ids),
        "duplicate_id_rows": dict(duplicate_details),
        "duplicate_id_result_diagnostic_counts": duplicate_result_diagnostic_counts,
        "detector_summary_candidate_count": detector_summary_candidate_count,
        "unique_candidate_repositories": len(repository_counts),
        "top_repositories_by_raw_rows": [
            {"repository": repository, "rows": count}
            for repository, count in repository_counts.most_common(10)
        ],
        "candidate_output_shape_counts": {
            dimension: {
                value: {"rows": count, "fraction": round(count / detector_rows, 6)}
                for value, count in sorted(counts.items())
            }
            for dimension, counts in sorted(shape_counts.items())
        },
        "reported_minus_audited_raw_rows": args.reported_count - detector_rows,
        "compact_summary_sha256": actual_compact_sha,
        "detector_summary_sha256": actual_detector_summary_sha,
        "checks": checks,
        "interpretation": (
            "This audit verifies only the pinned local run. The reported count has no bound run/config, "
            "so the arithmetic difference is not an explained population delta."
        ),
        "limitations": [
            "Candidate rows are not vulnerability ground truth.",
            "This CSV count does not attest the source tree or reproduce the detector execution environment.",
            "The 546,559 count remains unbound to a run signature, scanner commit, manifest, or input CSV.",
        ],
    }
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if report["audit_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

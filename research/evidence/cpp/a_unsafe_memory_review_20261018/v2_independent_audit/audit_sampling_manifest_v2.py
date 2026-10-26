#!/usr/bin/env python3
"""Independently audit the A-UNSAFE v2 sampling counts.

This script does not import or call the sample builder. It filters the pinned
candidate CSV, joins target rows to their referenced result JSON diagnostics,
and recomputes observation identities and exact-source cross-repository
clusters. It prints a JSON audit result and does not write output files.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import re
import sys
from pathlib import Path
from typing import Any


TARGET_RULES = {
    "ohcpp-format-string-candidate-002",
    "ohcpp-unsafe-memory-call-candidate-001",
}
EXPECTED_POPULATION = 8994
EXPECTED_OBSERVED = 9323
EXPECTED_SAMPLE_SIZE = 160
CLUSTER_KEY = "rule_id + exact source_sha256 + at least two repositories"


def result_json_for_row(row: dict[str, str], projects_dir: Path) -> Path:
    """Map the absolute result_path in the CSV to this input tree's result JSON."""
    normalized = row["result_path"].replace("\\", "/")
    match = re.search(r"(?:^|/)projects/([^/]+)/result\.json$", normalized)
    if not match:
        raise ValueError(f"unrecognized result_path for {row['diagnostic_id']}")
    project_dir = (projects_dir / match.group(1)).resolve()
    if not project_dir.is_relative_to(projects_dir.resolve()):
        raise ValueError(f"result_path escaped projects root for {row['diagnostic_id']}")
    return project_dir / "result.json"


def read_diagnostics(path: Path) -> tuple[str, dict[str, list[dict[str, Any]]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    repository = data.get("repository")
    if not isinstance(repository, str) or not repository:
        raise ValueError(f"result JSON has no repository: {path}")
    by_id: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for run in data.get("detector_runs", []):
        for diagnostic in run.get("diagnostics", []):
            diagnostic_id = diagnostic.get("diagnostic_id")
            if diagnostic_id:
                by_id[diagnostic_id].append(diagnostic)
    return repository, by_id


def validate_schema(manifest: dict[str, Any], schema_path: Path) -> str | None:
    try:
        import jsonschema
    except ImportError:
        return "jsonschema is unavailable; install jsonschema to verify the schema"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(manifest, schema)
    except Exception as exc:  # report validation errors in the audit output
        return f"{type(exc).__name__}: {exc}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidate-root",
        type=Path,
        default=Path(r"D:\openHarmonyScanner\openharmony-abcd-full-scan-20261018-final"),
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().with_name("sampling_manifest_v2.json"),
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path(__file__).resolve().parents[5] / "research/schemas/a_unsafe_memory_review_manifest_v2.schema.json",
    )
    args = parser.parse_args()

    root = args.candidate_root.resolve()
    csv_path = root / "candidate_results.csv"
    projects_dir = root / "projects"
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))

    target_rows: list[dict[str, str]] = []
    total_csv_rows = 0
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            total_csv_rows += 1
            if row.get("rule_id") in TARGET_RULES:
                target_rows.append(row)

    result_cache: dict[Path, tuple[str, dict[str, list[dict[str, Any]]]]] = {}
    joined: list[dict[str, str]] = []
    errors: list[str] = []
    referenced_result_files: set[Path] = set()

    for row in target_rows:
        try:
            result_path = result_json_for_row(row, projects_dir)
            referenced_result_files.add(result_path)
            if result_path not in result_cache:
                result_cache[result_path] = read_diagnostics(result_path)
            repository, diagnostics_by_id = result_cache[result_path]
            matches = diagnostics_by_id.get(row.get("diagnostic_id", ""), [])
            if len(matches) != 1:
                errors.append(
                    f"{row.get('diagnostic_id')}: expected one result diagnostic, found {len(matches)}"
                )
                continue
            diagnostic = matches[0]
            source_hash = diagnostic.get("source_sha256")
            rule_id = diagnostic.get("rule_id")
            csv_repository = row.get("repository")
            if rule_id != row.get("rule_id"):
                errors.append(f"{row.get('diagnostic_id')}: CSV/result rule_id mismatch")
            if repository != csv_repository:
                errors.append(f"{row.get('diagnostic_id')}: CSV/result repository mismatch")
            if not isinstance(source_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", source_hash):
                errors.append(f"{row.get('diagnostic_id')}: invalid or missing exact source_sha256")
                continue
            joined.append(
                {
                    "diagnostic_id": row["diagnostic_id"],
                    "repository": repository,
                    "rule_id": rule_id,
                    "source_sha256": source_hash,
                }
            )
        except Exception as exc:
            errors.append(f"{row.get('diagnostic_id', '<missing-id>')}: {type(exc).__name__}: {exc}")

    diagnostic_ids = [row["diagnostic_id"] for row in joined]
    unique_diagnostic_ids = len(set(diagnostic_ids))
    duplicate_diagnostic_id_rows = len(diagnostic_ids) - unique_diagnostic_ids

    groups: dict[tuple[str, str], list[dict[str, str]]] = collections.defaultdict(list)
    for row in joined:
        groups[(row["rule_id"], row["source_sha256"])].append(row)
    cross_repository_clusters = []
    for (rule_id, source_hash), rows in groups.items():
        repositories = sorted({row["repository"] for row in rows})
        if len(repositories) >= 2:
            cross_repository_clusters.append(
                {
                    "rule_id": rule_id,
                    "source_sha256": source_hash,
                    "repositories": repositories,
                    "raw_observation_rows": len(rows),
                }
            )
    cross_repository_clusters.sort(key=lambda item: (item["rule_id"], item["source_sha256"]))
    cross_cluster_rows = sum(item["raw_observation_rows"] for item in cross_repository_clusters)

    identity = manifest.get("observation_identity_audit", {})
    dimensions = manifest.get("report_count_dimensions", {})
    raw_dimension = dimensions.get("raw_observation_rows", {})
    within_dimension = dimensions.get("within_repository_root_cause_clusters", {})
    cross_dimension = dimensions.get("cross_repository_identical_source_clusters", {})
    review_dimension = dimensions.get("human_review_outcomes", {})
    schema_error = validate_schema(manifest, args.schema)

    checks = {
        "schema_valid": schema_error is None,
        "target_rule_counts": dict(sorted(collections.Counter(row["rule_id"] for row in target_rows).items()))
        == manifest.get("population_by_rule"),
        "row_count_matches": len(target_rows) == EXPECTED_OBSERVED == manifest.get("raw_observation_rows") == manifest.get("observed_population"),
        "manifest_expected_population": manifest.get("expected_population") == EXPECTED_POPULATION,
        "mismatch_is_explicit_and_provisional": manifest.get("population_mismatch") is True
        and manifest.get("provisional_frame") is True,
        "all_rows_source_bound": len(joined) == len(target_rows) and not errors,
        "diagnostic_id_audit": identity.get("rows") == len(joined)
        and identity.get("unique_diagnostic_ids") == unique_diagnostic_ids
        and identity.get("duplicate_diagnostic_id_rows") == duplicate_diagnostic_id_rows == 0,
        "raw_dimension": raw_dimension.get("count") == len(target_rows)
        and raw_dimension.get("status") == "counted",
        "within_repo_dimension_not_established": within_dimension.get("count") is None
        and within_dimension.get("status") == "not_established"
        and bool(within_dimension.get("reason")),
        "cross_repo_dimension": cross_dimension.get("count") == len(cross_repository_clusters)
        and cross_dimension.get("rows_in_those_clusters") == cross_cluster_rows
        and cross_dimension.get("key") == CLUSTER_KEY
        and cross_dimension.get("status") == "counted_from_source_bound_diagnostics"
        and cross_dimension.get("clusters") == cross_repository_clusters,
        "review_dimension": review_dimension.get("reviewed") == 0
        and review_dimension.get("pending") == EXPECTED_SAMPLE_SIZE
        and review_dimension.get("status") == "pending_independent_review",
        "sample_size": manifest.get("sample_size") == EXPECTED_SAMPLE_SIZE,
    }

    output = {
        "audit_status": "PASS" if all(checks.values()) else "FAIL",
        "population_assessment": "PARTIAL" if manifest.get("population_mismatch") else "MATCHED",
        "candidate_csv_total_rows": total_csv_rows,
        "target_rows": len(target_rows),
        "target_rows_by_rule": dict(sorted(collections.Counter(row["rule_id"] for row in target_rows).items())),
        "referenced_result_json_files": len(referenced_result_files),
        "joined_source_bound_rows": len(joined),
        "unique_diagnostic_ids": unique_diagnostic_ids,
        "duplicate_diagnostic_id_rows": duplicate_diagnostic_id_rows,
        "cross_repository_exact_source_clusters": cross_repository_clusters,
        "cross_repository_cluster_count": len(cross_repository_clusters),
        "raw_rows_in_cross_repository_clusters": cross_cluster_rows,
        "expected_population": manifest.get("expected_population"),
        "observed_population": manifest.get("observed_population"),
        "population_delta_observed_minus_expected": manifest.get("observed_population", 0)
        - manifest.get("expected_population", 0),
        "sample_size": manifest.get("sample_size"),
        "human_reviewed": review_dimension.get("reviewed"),
        "human_review_pending": review_dimension.get("pending"),
        "schema_error": schema_error,
        "checks": checks,
        "errors": errors,
        "limitations": [
            "The expected population differs from the observed candidate frame; sampling remains provisional.",
            "Within-repository root-cause clusters are not established from these raw records.",
            "The 160 observations are pending independent human review; candidates are not vulnerability ground truth.",
        ],
    }
    print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if output["audit_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

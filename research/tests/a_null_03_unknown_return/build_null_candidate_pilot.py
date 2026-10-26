#!/usr/bin/env python3
"""Build a blinded, stratified pilot queue for a pinned NULL-candidate run.

The queue is a pilot for the locally verifiable run, not a representative
sample of the unbound 546,559-row task claim. Raw CSV rows remain sampling
units, including duplicate diagnostic rows.
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import math
import re
from pathlib import Path, PurePosixPath
from typing import Any


DETECTOR_ID = "ohscanner.cpp.null_dereference"
CLAIMED_POPULATION = 546_559
SEED = "20261019-null-real-candidate-pilot-v1"
DIMENSION_PATTERNS = {
    key: re.compile(r"\b" + key + r"=([^;]+)")
    for key in ("null_source", "sink", "guard_relation", "error_path")
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def get_message_value(message: str, pattern: re.Pattern[str]) -> str:
    match = pattern.search(message)
    return match.group(1) if match else "missing"


def allocate(n_by_stratum: dict[tuple[str, ...], int], sample_size: int) -> dict[tuple[str, ...], int]:
    if sample_size < len(n_by_stratum) or sample_size > sum(n_by_stratum.values()):
        raise ValueError(
            f"sample size must be between the number of nonempty strata ({len(n_by_stratum)}) "
            f"and the population ({sum(n_by_stratum.values())})"
        )
    allocation = {key: 1 for key in n_by_stratum}
    remaining = sample_size - len(allocation)
    remaining_population = sum(size - 1 for size in n_by_stratum.values())
    fractional = []
    for key, size in n_by_stratum.items():
        exact = remaining * (size - 1) / remaining_population if remaining_population else 0
        floor = min(size - 1, math.floor(exact))
        allocation[key] += floor
        fractional.append((exact - floor, key))
    remainder = sample_size - sum(allocation.values())
    for _fraction, key in sorted(fractional, key=lambda item: (-item[0], item[1])):
        if not remainder:
            break
        if allocation[key] < n_by_stratum[key]:
            allocation[key] += 1
            remainder -= 1
    for key in sorted(n_by_stratum):
        if not remainder:
            break
        additional = min(remainder, n_by_stratum[key] - allocation[key])
        allocation[key] += additional
        remainder -= additional
    if remainder:
        raise AssertionError("stratified allocation left unallocated sample slots")
    return allocation


def result_file_from_csv(value: str, scan_root: Path) -> Path:
    prefix = "/mnt/d/openHarmonyScanner/"
    if not value.startswith(prefix):
        raise ValueError("candidate result path is outside the pinned scan artifact root")
    relative = PurePosixPath(value[len(prefix):])
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError("candidate result path is not canonical")
    parts = relative.parts
    try:
        project_index = parts.index("projects")
    except ValueError as exc:
        raise ValueError("candidate result path has no projects segment") from exc
    return scan_root / "projects" / parts[project_index + 1] / "result.json"


def result_diagnostic(
    row: dict[str, str],
    scan_root: Path,
    cache: dict[Path, tuple[dict[str, Any], list[dict[str, Any]]]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    path = result_file_from_csv(row["result_path"], scan_root)
    cached = cache.get(path)
    if cached is None:
        report = json.loads(path.read_text(encoding="utf-8"))
        diagnostics = [
            diagnostic
            for run in report.get("detector_runs", [])
            if run.get("tool") == DETECTOR_ID
            for diagnostic in run.get("diagnostics", [])
        ]
        cached = (report, diagnostics)
        cache[path] = cached
    report, diagnostics = cached
    matches = [item for item in diagnostics if item.get("diagnostic_id") == row["diagnostic_id"]]
    if len(matches) != 1:
        raise ValueError(f"{row['diagnostic_id']}: expected exactly one result diagnostic, found {len(matches)}")
    return report, matches[0]


def source_context(
    row: dict[str, str],
    project: dict[str, str],
    diagnostic: dict[str, Any],
    source_root: Path,
) -> tuple[str, str, str]:
    project_path = PurePosixPath(project["project_path"])
    source_relative = PurePosixPath(row["file"])
    if any(part in ("", ".", "..") for part in (*project_path.parts, *source_relative.parts)):
        raise ValueError("source path contains unsafe components")
    root = source_root.resolve()
    source = root.joinpath(*project_path.parts, *source_relative.parts).resolve()
    if not source.is_relative_to(root):
        raise ValueError("candidate source escapes source root")
    expected = diagnostic.get("source_sha256")
    if not source.is_file():
        return str(expected or ""), "source_unavailable", ""
    actual = sha256(source)
    if actual != expected:
        return str(expected or ""), "source_hash_mismatch", ""
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    line = int(row["line"])
    if line < 1 or line > len(lines):
        return actual, "source_hash_matched_line_out_of_range", ""
    start, end = max(1, line - 4), min(len(lines), line + 4)
    snippet = "\n".join(f"{number}: {lines[number - 1]}" for number in range(start, end + 1))
    return actual, "source_hash_matched", snippet


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError(f"refusing to write empty CSV: {path}")
    with path.open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-root", type=Path, required=True)
    parser.add_argument("--report-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--sample-size", type=int, default=160)
    parser.add_argument("--claimed-population", type=int, default=CLAIMED_POPULATION)
    args = parser.parse_args()

    output_root = args.output_root.resolve()
    if output_root.exists():
        raise SystemExit(f"output already exists; refusing to overwrite: {output_root}")

    config = json.loads((args.scan_root / "run_config.json").read_text(encoding="utf-8"))
    summary = json.loads((args.report_root / "compact-summary.json").read_text(encoding="utf-8"))
    checksums = json.loads((args.report_root / "checksums.json").read_text(encoding="utf-8"))
    detector_summary_path = args.report_root / "检测器能力.csv"
    detector_summary_sha = sha256(detector_summary_path)
    with detector_summary_path.open("r", encoding="utf-8-sig", newline="") as source:
        detector_summary = {
            row["detector"]: row for row in csv.DictReader(source)
        }.get(DETECTOR_ID)
    if detector_summary is None:
        raise ValueError("NULL detector is missing from the corroborating detector summary")

    identity = {
        "run_signature": config.get("run_signature"),
        "scanner_commit": config.get("scanner_commit"),
        "manifest_sha256": config.get("manifest_sha256"),
    }
    report_scanner = summary.get("scanner", {})
    report_identity = {
        "run_signature": report_scanner.get("run_signature"),
        "scanner_commit": report_scanner.get("commit"),
        "manifest_sha256": report_scanner.get("manifest_sha256"),
    }
    if identity != report_identity:
        raise ValueError("scan config and corroborating report run identities differ")
    if DETECTOR_ID not in config.get("detectors", []):
        raise ValueError("NULL detector is absent from the pinned run config")

    projects: dict[str, dict[str, str]] = {}
    with (args.scan_root / "project_summary.csv").open(encoding="utf-8-sig", newline="") as source:
        for project in csv.DictReader(source):
            projects[project["repository"]] = project
    selected_source_counts = sorted(int(project["selected_source_files"]) for project in projects.values())
    quartile_bounds = [selected_source_counts[len(selected_source_counts) * i // 4] for i in (1, 2, 3)]

    def repository_scale(repository: str) -> str:
        count = int(projects[repository]["selected_source_files"])
        return "Q" + str(1 + sum(count > bound for bound in quartile_bounds))

    population: list[dict[str, str]] = []
    duplicate_ids: collections.Counter[str] = collections.Counter()
    csv_path = args.scan_root / "candidate_results.csv"
    with csv_path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        for csv_row_number, row in enumerate(reader, start=2):
            if row.get("detector") != DETECTOR_ID:
                continue
            repository = row.get("repository", "")
            if repository not in projects:
                raise ValueError("candidate repository is absent from project summary")
            row["csv_row_number"] = str(csv_row_number)
            row["null_source"] = get_message_value(row.get("message", ""), DIMENSION_PATTERNS["null_source"])
            row["sink_shape"] = get_message_value(row.get("message", ""), DIMENSION_PATTERNS["sink"])
            row["guard_relation"] = get_message_value(row.get("message", ""), DIMENSION_PATTERNS["guard_relation"])
            row["error_path"] = get_message_value(row.get("message", ""), DIMENSION_PATTERNS["error_path"])
            row["repository_scale"] = repository_scale(repository)
            row["stratum"] = "|".join((row["null_source"], row["sink_shape"], row["repository_scale"]))
            row["review_sample_id"] = hashlib.sha256(
                f"{SEED}|{repository}|{row['diagnostic_id']}|{csv_row_number}".encode("utf-8")
            ).hexdigest()[:16]
            duplicate_ids[row["diagnostic_id"]] += 1
            population.append(row)

    if len(population) != summary.get("candidate_counts_by_detector", {}).get(DETECTOR_ID):
        raise ValueError("NULL raw CSV count disagrees with compact summary")
    if len(population) != summary.get("candidate_counts_by_cwe", {}).get("ohcpp-null-dereference-candidate-001"):
        raise ValueError("NULL raw CSV count disagrees with CWE summary")
    unique_ids = len(duplicate_ids)
    duplicate_row_count = len(population) - unique_ids
    if unique_ids != int(detector_summary["candidate_count"]):
        raise ValueError("unique diagnostic IDs disagree with the detector summary candidate count")

    strata: dict[tuple[str, ...], list[dict[str, str]]] = collections.defaultdict(list)
    for row in population:
        strata[tuple(row["stratum"].split("|"))].append(row)
    allocation = allocate({key: len(rows) for key, rows in strata.items()}, args.sample_size)
    selected: list[tuple[dict[str, str], int, int]] = []
    for key in sorted(strata):
        ranked = sorted(
            strata[key],
            key=lambda row: hashlib.sha256(f"{SEED}|{row['review_sample_id']}".encode("utf-8")).hexdigest(),
        )
        selected.extend((row, len(strata[key]), allocation[key]) for row in ranked[:allocation[key]])

    result_cache: dict[Path, tuple[dict[str, Any], list[dict[str, Any]]]] = {}
    reviewer_rows: list[dict[str, Any]] = []
    key_rows: list[dict[str, Any]] = []
    source_status_counts: collections.Counter[str] = collections.Counter()
    commit_metadata_matches = 0
    for row, stratum_population, stratum_sample in selected:
        result_report, diagnostic = result_diagnostic(row, args.scan_root, result_cache)
        metadata_match = (
            result_report.get("repository") == row["repository"]
            and result_report.get("commit") == row["manifest_commit"]
            and diagnostic.get("rule_id") == row["rule_id"]
            and diagnostic.get("file") == row["file"]
            and str(diagnostic.get("line")) == row["line"]
            and diagnostic.get("source_sha256") is not None
        )
        commit_metadata_matches += int(metadata_match)
        source_hash, source_status, snippet = source_context(
            row, projects[row["repository"]], diagnostic, args.source_root
        )
        source_status_counts[source_status] += 1
        probability = stratum_sample / stratum_population
        reviewer_rows.append({
            "review_sample_id": row["review_sample_id"],
            "repository": row["repository"],
            "commit": row["manifest_commit"],
            "file": row["file"],
            "line": row["line"],
            "source_sha256": source_hash,
            "source_binding_status": source_status,
            "source_context": snippet,
            "reviewer_disposition": "",
            "reviewer_rationale": "",
            "evidence_reference": "",
            "confidence": "",
            "reviewer_id": "",
        })
        key_rows.append({
            "review_sample_id": row["review_sample_id"],
            "csv_row_number": row["csv_row_number"],
            "diagnostic_id": row["diagnostic_id"],
            "source_role": row["null_source"],
            "sink_shape": row["sink_shape"],
            "guard_relation": row["guard_relation"],
            "error_path": row["error_path"],
            "analysis_status": row["analysis_status"],
            "stratum": row["stratum"],
            "stratum_population": stratum_population,
            "stratum_sample": stratum_sample,
            "inclusion_probability": probability,
            "source_binding_status": source_status,
            "csv_result_metadata_match": str(metadata_match).lower(),
            "raw_duplicate_diagnostic_id": str(duplicate_ids[row["diagnostic_id"]] > 1).lower(),
        })

    output_root.mkdir(parents=True, exist_ok=False)
    reviewer_dir = output_root / "reviewer"
    coordinator_dir = output_root / "coordinator"
    reviewer_dir.mkdir()
    coordinator_dir.mkdir()
    reviewer_queue_path = reviewer_dir / "blind_review_queue.csv"
    coordinator_key_path = coordinator_dir / "review_key.csv"
    write_csv(reviewer_queue_path, reviewer_rows)
    write_csv(coordinator_key_path, key_rows)

    dimension_counts = {
        dimension: dict(sorted(collections.Counter(row[dimension] for row in population).items()))
        for dimension in ("null_source", "sink_shape", "guard_relation", "error_path", "analysis_status")
    }
    manifest = {
        "schema_version": "ohscanner.a-null-real-candidate-pilot-v1",
        "seed": SEED,
        "detector_id": DETECTOR_ID,
        "expected_population_claim": args.claimed_population,
        "observed_raw_population": len(population),
        "population_delta_observed_minus_claim": len(population) - args.claimed_population,
        "population_claim_status": "unbound_task_claim",
        "provisional_frame": len(population) != args.claimed_population,
        "run_identity": identity,
        "candidate_csv_sha256": sha256(csv_path),
        "project_summary_sha256": sha256(args.scan_root / "project_summary.csv"),
        "report_identity_status": "matched_run_signature_commit_manifest_and_checksums",
        "report_compact_summary_sha256": sha256(args.report_root / "compact-summary.json"),
        "report_detector_summary_sha256": detector_summary_sha,
        "raw_observation_rows": len(population),
        "unique_diagnostic_ids": unique_ids,
        "duplicate_diagnostic_id_rows": duplicate_row_count,
        "duplicate_diagnostic_ids": sorted(
            diagnostic_id for diagnostic_id, count in duplicate_ids.items() if count > 1
        ),
        "population_shape_counts": dimension_counts,
        "stratification_fields": ["null_source", "sink_shape", "repository_selected_source_files_quartile"],
        "repository_scale_quartile_upper_bounds": quartile_bounds,
        "strata_count": len(strata),
        "sample_size": len(selected),
        "sampled_by_source_binding": dict(sorted(source_status_counts.items())),
        "csv_result_commit_rule_metadata_matches": commit_metadata_matches,
        "inclusion_probabilities": {
            "method": "proportional allocation after a minimum one observation in every nonempty stratum",
            "strata": [
                {
                    "source_role": key[0],
                    "sink_shape": key[1],
                    "repository_scale": key[2],
                    "population": len(strata[key]),
                    "sample": allocation[key],
                    "probability": allocation[key] / len(strata[key]),
                }
                for key in sorted(strata)
            ],
        },
        "human_review_outcomes": {"reviewed": 0, "pending": len(selected), "status": "pending_independent_review"},
        "blind_queue_sha256": sha256(reviewer_queue_path),
        "coordinator_key_sha256": sha256(coordinator_key_path),
        "checksums": checksums,
        "limitations": [
            "This is a pilot for the pinned 403,360-row run; it is not representative of the unbound 546,559 claim.",
            "Source role, sink, guard and status counts describe detector output only, not true/false positives.",
            "Commit fields are cross-checked between CSV and result JSON; selected source bytes are independently hash-matched to result diagnostics.",
            "Do not share coordinator/review_key.csv with the blind reviewer before labels are frozen.",
            "A source_hash_mismatch or source_unavailable row remains in the sample and is eligible for not_testable; do not resample it away.",
        ],
    }
    manifest_path = output_root / "sampling_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "manifest": str(manifest_path),
        "raw_population": len(population),
        "unique_ids": unique_ids,
        "duplicate_rows": duplicate_row_count,
        "strata": len(strata),
        "sample_size": len(selected),
        "source_binding": dict(source_status_counts),
        "csv_result_metadata_matches": commit_metadata_matches,
        "expected_claim_bound": False,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from pathlib import PurePosixPath
import re

try:
    from .validate_review_manifest import validate_manifest
except ImportError:  # Allow direct execution as a research CLI.
    from validate_review_manifest import validate_manifest


SEED = "20261018"
DETECTOR_ID = "ohscanner.cpp.unsafe_memory_call"
EXPECTED_POPULATION = 8994


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def crosscheck_report(report_root: Path, run_config: dict, observed_population: int) -> dict:
    summary_path = report_root / "compact-summary.json"
    detector_summary_path = report_root / "检测器能力.csv"
    checksums_path = report_root / "checksums.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    checksums = json.loads(checksums_path.read_text(encoding="utf-8"))
    scanner = summary.get("scanner", {})
    for key, config_key in (("run_signature", "run_signature"), ("commit", "scanner_commit"), ("manifest_sha256", "manifest_sha256")):
        if scanner.get(key) != run_config.get(config_key):
            raise ValueError(f"report cross-check scanner identity mismatch: {key}")
    rows = {}
    with detector_summary_path.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            rows[row["detector"]] = row
    detector_row = rows.get(DETECTOR_ID)
    if detector_row is None or int(detector_row["candidate_count"]) != observed_population:
        raise ValueError("report cross-check unsafe-memory count mismatch")
    if int(summary.get("candidate_counts_by_detector", {}).get(DETECTOR_ID, -1)) != observed_population:
        raise ValueError("compact report unsafe-memory count mismatch")
    for name, path in (("compact-summary.json", summary_path), ("检测器能力.csv", detector_summary_path)):
        if checksums.get(name) != sha256(path):
            raise ValueError(f"report cross-check checksum mismatch: {name}")
    return {
        "path": str(report_root.resolve()),
        "run_signature": scanner["run_signature"],
        "scanner_commit": scanner["commit"],
        "manifest_sha256": scanner["manifest_sha256"],
        "unsafe_memory_candidate_count": observed_population,
        "compact_summary_sha256": sha256(summary_path),
        "detector_summary_sha256": sha256(detector_summary_path),
        "status": "matched_same_run_signature_and_count",
    }


def callee_shape(row: dict[str, str]) -> str:
    match = re.search(r"`([^`]+)` receives", row.get("message", ""))
    return match.group(1) if match else "unknown-callee-shape"


def allocate(n_by_stratum: dict[tuple, int], sample_size: int) -> dict[tuple, int]:
    if sample_size < len(n_by_stratum) or sample_size > sum(n_by_stratum.values()):
        raise ValueError("sample size must cover each nonempty stratum and not exceed population")
    remaining = sample_size - len(n_by_stratum)
    remaining_total = sum(n_by_stratum.values()) - len(n_by_stratum)
    allocation = {key: 1 for key in n_by_stratum}
    fractional = []
    for key, population in n_by_stratum.items():
        exact = remaining * (population - 1) / remaining_total if remaining_total else 0
        floor = min(population - 1, math.floor(exact))
        allocation[key] += floor
        fractional.append((exact - floor, key))
    remainder = sample_size - sum(allocation.values())
    for _fraction, key in sorted(fractional, key=lambda item: (-item[0], item[1])):
        if remainder == 0:
            break
        if allocation[key] < n_by_stratum[key]:
            allocation[key] += 1
            remainder -= 1
    if remainder:
        for key in sorted(n_by_stratum):
            add = min(remainder, n_by_stratum[key] - allocation[key])
            allocation[key] += add
            remainder -= add
            if remainder == 0:
                break
    return allocation


def result_path(value: str) -> Path:
    prefix = "/mnt/d/openHarmonyScanner/"
    if not value.startswith(prefix):
        raise ValueError("candidate result path is outside the pinned scan artifact root")
    relative = PurePosixPath(value[len(prefix):])
    if relative.is_absolute() or not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError("candidate result path is not a canonical relative path")
    return Path("D:/openHarmonyScanner").joinpath(*relative.parts)


def diagnostic_index(result_file: Path, result_cache: dict[Path, dict[str, dict]]) -> dict[str, dict]:
    result = result_cache.get(result_file)
    if result is None:
        report = json.loads(result_file.read_text(encoding="utf-8"))
        result = {
            item["diagnostic_id"]: item
            for run in report["detector_runs"]
            if run.get("tool") == DETECTOR_ID
            for item in run.get("diagnostics", [])
        }
        result_cache[result_file] = result
    return result


def load_source_binding(row: dict[str, str], project_path: str, source_root: Path, result_cache: dict[Path, dict[str, dict]]):
    result_file = result_path(row["result_path"])
    diagnostic = diagnostic_index(result_file, result_cache)[row["diagnostic_id"]]
    project = PurePosixPath(project_path)
    source_relative = PurePosixPath(row["file"])
    if any(part in ("", ".", "..") for part in (*project.parts, *source_relative.parts)):
        raise ValueError("source record contains an unsafe relative path")
    resolved_source_root = source_root.resolve()
    source = resolved_source_root.joinpath(*project.parts, *source_relative.parts).resolve()
    if not source.is_relative_to(resolved_source_root):
        raise ValueError("candidate source escaped the pinned source root")
    source_hash = diagnostic.get("source_sha256", "")
    if not source.is_file():
        return source_hash, "source_unavailable", ""
    actual_hash = sha256(source)
    if actual_hash != source_hash:
        return source_hash, "source_hash_mismatch", ""
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    line = int(row["line"])
    start, end = max(1, line - 4), min(len(lines), line + 4)
    snippet = "\n".join(f"{number}: {lines[number - 1]}" for number in range(start, end + 1))
    return source_hash, "source_bound", snippet


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-root", type=Path, required=True)
    parser.add_argument("--report-root", type=Path)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--sample-size", type=int, default=160)
    parser.add_argument("--expected-population", type=int, default=EXPECTED_POPULATION)
    parser.add_argument("--allow-population-mismatch", action="store_true")
    parser.add_argument("--function-shape-audit", type=Path,
                        help="optional source-hash-bound function-shape census used for function-aware strata")
    args = parser.parse_args()

    if args.output_root.exists():
        raise SystemExit(f"output root already exists; refusing to overwrite: {args.output_root.resolve()}")

    run_config_path = args.scan_root / "run_config.json"
    result_csv = args.scan_root / "candidate_results.csv"
    project_csv = args.scan_root / "project_summary.csv"
    run_config = json.loads(run_config_path.read_text(encoding="utf-8"))
    projects = {}
    with project_csv.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            projects[row["repository"]] = row
    source_counts = sorted(int(row["selected_source_files"]) for row in projects.values())
    quartile_points = [source_counts[len(source_counts) * index // 4] for index in (1, 2, 3)]

    def repo_scale(repository: str) -> str:
        count = int(projects[repository]["selected_source_files"])
        return "Q" + str(1 + sum(count > point for point in quartile_points))

    function_shape_audit = None
    function_shape_by_id: dict[str, dict[str, str]] = {}
    if args.function_shape_audit:
        function_shape_audit = json.loads(args.function_shape_audit.read_text(encoding="utf-8"))
        expected_identity = {
            "run_signature": run_config.get("run_signature"),
            "scanner_commit": run_config.get("scanner_commit"),
            "manifest_sha256": run_config.get("manifest_sha256"),
        }
        if function_shape_audit.get("run_identity") != expected_identity:
            raise ValueError("function-shape audit run identity does not match scan config")
        if function_shape_audit.get("candidate_csv_sha256") != sha256(result_csv):
            raise ValueError("function-shape audit candidate CSV hash does not match")
        if function_shape_audit.get("audit_status") != "PASS":
            raise ValueError("function-shape audit is not a fully source-hash-matched census")
        for item in function_shape_audit.get("candidate_rows", []):
            sample_id = item.get("diagnostic_id", "")
            if not sample_id or sample_id in function_shape_by_id:
                raise ValueError("function-shape audit has a missing or duplicate diagnostic ID")
            function_shape_by_id[sample_id] = item

    population = []
    population_statuses: Counter[str] = Counter()
    diagnostic_ids: Counter[str] = Counter()
    with result_csv.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            if row.get("detector") != DETECTOR_ID:
                continue
            if row.get("repository") not in projects:
                raise ValueError("candidate repository is absent from project summary")
            if row["result_path"].startswith("/mnt/d/openHarmonyScanner/") is False:
                raise ValueError("candidate path is not bound to the expected full-scan root")
            row["callee_shape"] = callee_shape(row)
            row["repo_scale"] = repo_scale(row["repository"])
            if function_shape_audit is not None:
                shape = function_shape_by_id.get(row["diagnostic_id"])
                if shape is None or shape.get("rule_id") != row["rule_id"] or shape.get("repository_scale") != row["repo_scale"]:
                    raise ValueError(f"function-shape audit row mismatch: {row['diagnostic_id']}")
                row["function_shape"] = shape["function_shape"]
                row["stratum"] = "|".join((row["rule_id"], row["function_shape"], row["repo_scale"]))
            else:
                row["stratum"] = "|".join((row["rule_id"], row["callee_shape"], row["repo_scale"]))
            row["review_sample_id"] = hashlib.sha256(
                (SEED + "|" + row["repository"] + "|" + row["diagnostic_id"]).encode()
            ).hexdigest()[:16]
            population_statuses[row.get("analysis_status", "unknown")] += 1
            diagnostic_ids[row["diagnostic_id"]] += 1
            population.append(row)
    if function_shape_audit is not None and set(function_shape_by_id) != {row["diagnostic_id"] for row in population}:
        raise ValueError("function-shape audit diagnostic ID set differs from candidate population")
    if len(population) != args.expected_population and not args.allow_population_mismatch:
        raise SystemExit(
            f"Expected {args.expected_population} observations but pinned artifact contains {len(population)}; "
            "reconcile the source run before sampling or use --allow-population-mismatch for a provisional frame."
        )
    if len({row["review_sample_id"] for row in population}) != len(population):
        raise ValueError("sample identifier collision or duplicated observation key")

    strata: dict[tuple, list[dict[str, str]]] = defaultdict(list)
    for row in population:
        middle_dimension = row["function_shape"] if function_shape_audit is not None else row["callee_shape"]
        key = (row["rule_id"], middle_dimension, row["repo_scale"])
        strata[key].append(row)
    allocation = allocate({key: len(rows) for key, rows in strata.items()}, args.sample_size)
    selected = []
    for key in sorted(strata):
        ranked = sorted(
            strata[key],
            key=lambda row: hashlib.sha256((SEED + "|" + row["review_sample_id"]).encode()).hexdigest(),
        )
        selected.extend((row, len(strata[key]), allocation[key]) for row in ranked[:allocation[key]])

    shape_field = "function_shape" if function_shape_audit is not None else "callee_shape"
    shape_field_name = "function_shape" if function_shape_audit is not None else "callee_shape"
    population_shape_counts = Counter((row["rule_id"], row[shape_field]) for row in population)
    sample_shape_counts = Counter((row["rule_id"], row[shape_field]) for row, _n, _sample in selected)
    source_shape_summary = [
        {
            "rule_id": rule_id,
            shape_field_name: callee,
            "population": population_count,
            "sample": sample_shape_counts[(rule_id, callee)],
            "population_share": round(population_count / len(population), 6),
        }
        for (rule_id, callee), population_count in sorted(
            population_shape_counts.items(), key=lambda item: (-item[1], item[0])
        )
    ]

    result_cache: dict[Path, dict[str, dict]] = {}
    source_clusters: dict[tuple[str, str], dict[str, object]] = {}
    for row in population:
        diagnostic = diagnostic_index(result_path(row["result_path"]), result_cache)[row["diagnostic_id"]]
        source_hash = diagnostic.get("source_sha256", "")
        if not source_hash:
            continue
        key = (row["rule_id"], source_hash)
        cluster = source_clusters.setdefault(key, {"repositories": set(), "rows": 0})
        cluster["repositories"].add(row["repository"])
        cluster["rows"] += 1
    cross_repo_clusters = [
        {
            "rule_id": rule_id,
            "source_sha256": source_sha256,
            "repositories": sorted(item["repositories"]),
            "raw_observation_rows": item["rows"],
        }
        for (rule_id, source_sha256), item in sorted(source_clusters.items())
        if len(item["repositories"]) > 1
    ]
    report_crosscheck = (
        crosscheck_report(args.report_root, run_config, len(population))
        if args.report_root else None
    )
    blind_rows, key_rows = [], []
    source_statuses = Counter()
    for row, stratum_size, stratum_sample_size in selected:
        project = projects[row["repository"]]
        source_hash, source_status, snippet = load_source_binding(
            row, project["project_path"], args.source_root, result_cache
        )
        source_statuses[source_status] += 1
        blind_rows.append({
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
            "csv_index": row["index"],
            "diagnostic_id": row["diagnostic_id"],
            "rule_id": row["rule_id"],
            "callee_shape": row["callee_shape"],
            "function_shape": row.get("function_shape", "not_used_for_stratification"),
            "repo_scale": row["repo_scale"],
            "stratum_population": stratum_size,
            "stratum_sample": stratum_sample_size,
            "inclusion_probability": stratum_sample_size / stratum_size,
            "analysis_status": row["analysis_status"],
            "scanner_message": row["message"],
        })

    output_queue = args.output_root / "reviewer" / "blind_review_queue.csv"
    output_key = args.output_root / "coordinator" / "review_key.csv"
    output_queue.parent.mkdir(parents=True, exist_ok=True)
    output_key.parent.mkdir(parents=True, exist_ok=True)
    review_protocol = Path(__file__).resolve().parents[2] / "evidence" / "cpp" / "a_unsafe_memory_review_20261018" / "reviewer" / "review_protocol.md"
    if review_protocol.is_file():
        shutil.copyfile(review_protocol, output_queue.parent / "review_protocol.md")
    with output_queue.open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=list(blind_rows[0]))
        writer.writeheader()
        writer.writerows(blind_rows)
    with output_key.open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=list(key_rows[0]))
        writer.writeheader()
        writer.writerows(key_rows)

    manifest = {
        "schema_version": "ohscanner.a-unsafe-memory-stratified-review-v2",
        "source_run_signature": run_config["run_signature"],
        "scanner_commit": run_config["scanner_commit"],
        "corroborating_report_artifact": report_crosscheck,
        "manifest_sha256": run_config["manifest_sha256"],
        "candidate_results_sha256": sha256(result_csv),
        "project_summary_sha256": sha256(project_csv),
        "expected_population": args.expected_population,
        "observed_population": len(population),
        "population_mismatch": len(population) != args.expected_population,
        "provisional_frame": len(population) != args.expected_population,
        "raw_observation_rows": len(population),
        "unique_observation_ids": len({row["diagnostic_id"] for row in population}),
        "sample_size": len(selected),
        "seed": SEED,
        "stratification_fields": [
            "rule_id",
            "function_shape_from_source" if function_shape_audit is not None else "callee_shape_from_message",
            "repository_selected_source_files_quartile",
        ],
        "function_shape_audit_sha256": sha256(args.function_shape_audit) if args.function_shape_audit else None,
        "repository_scale_quartile_upper_bounds": quartile_points,
        "population_by_rule": dict(sorted(Counter(row["rule_id"] for row in population).items())),
        "source_shape_counts": source_shape_summary,
        "observation_identity_audit": {
            "rows": len(population),
            "unique_diagnostic_ids": len(diagnostic_ids),
            "duplicate_diagnostic_id_rows": sum(count - 1 for count in diagnostic_ids.values() if count > 1),
            "by_analysis_status": dict(sorted(population_statuses.items())),
            "interpretation": "Diagnostic ID deduplication does not explain the requested population difference when duplicate_diagnostic_id_rows is zero.",
        },
        "sampled_by_rule": dict(sorted(Counter(row["rule_id"] for row, _, _ in selected).items())),
        "strata": [
            {"rule_id": key[0], shape_field_name: key[1], "repository_scale": key[2],
             "population": len(strata[key]), "sample": allocation[key],
             "inclusion_probability": allocation[key] / len(strata[key])}
            for key in sorted(strata)
        ],
        "sample_source_binding_status": dict(sorted(source_statuses.items())),
        "report_count_dimensions": {
            "raw_observation_rows": {"count": len(population), "status": "counted"},
            "within_repository_root_cause_clusters": {
                "count": None,
                "status": "not_established",
                "reason": "Raw scan records lack a validated root-cause identity; do not substitute same file/line or text shape as root cause.",
            },
            "cross_repository_identical_source_clusters": {
                "count": len(cross_repo_clusters),
                "rows_in_those_clusters": sum(item["raw_observation_rows"] for item in cross_repo_clusters),
                "key": "rule_id + exact source_sha256 + at least two repositories",
                "status": "counted_from_source_bound_diagnostics",
                "clusters": cross_repo_clusters,
            },
            "human_review_outcomes": {
                "reviewed": 0,
                "pending": len(selected),
                "disposition_counts": {},
                "status": "pending_independent_review",
            },
        },
        "blind_queue_sha256": sha256(output_queue),
        "coordinator_key_sha256": sha256(output_key),
        "source_root": str(args.source_root.resolve()),
        "review_status": "not_reviewed",
        "limitations": [
            "The requested population was 8,994; the pinned final full-scan artifact currently contains a different raw count.",
            "This is a provisional sample frame until that population discrepancy is reconciled.",
            "The sample is stratified by rule, the configured function/callee shape dimension and repository size; it is not a complete review of all observations.",
            "Reviewer queue omits scanner rule, status and message. Keep coordinator key separate until labels are locked.",
            "No candidate row or source location is deleted by this sampling procedure.",
        ],
    }
    validate_manifest(manifest)
    manifest_path = args.output_root / "sampling_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"manifest": str(manifest_path), "observed_population": len(population),
                      "sample_size": len(selected), "population_mismatch": manifest["population_mismatch"],
                      "sample_source_binding_status": dict(source_statuses)}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Audit function-context shapes for a pinned unsafe-memory candidate frame.

This is a descriptive source census, not a vulnerability classifier. Every
shape is derived only after matching source bytes to the diagnostic SHA-256.
Rows with unavailable or mismatched source remain in explicit unknown buckets.
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from src.ohscanner.detectors.cpp.shared_ptr_race_detector import (
    _class_spans,
    _function_spans,
    _mask_comments_and_literals,
    _namespace_spans,
)


DETECTOR_ID = "ohscanner.cpp.unsafe_memory_call"
RESULT_PREFIX = "/mnt/d/openHarmonyScanner/"


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


def result_file_from_row(value: str, scan_root: Path) -> Path:
    if not value.startswith(RESULT_PREFIX):
        raise ValueError("candidate result path is outside the pinned scan artifact root")
    relative = PurePosixPath(value[len(RESULT_PREFIX):])
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError("candidate result path is not canonical")
    try:
        project_index = relative.parts.index("projects")
    except ValueError as error:
        raise ValueError("candidate result path has no projects segment") from error
    if project_index + 1 >= len(relative.parts):
        raise ValueError("candidate result path has no project ID")
    return scan_root / "projects" / relative.parts[project_index + 1] / "result.json"


def diagnostic_for_row(
    row: dict[str, str], scan_root: Path,
    cache: dict[Path, tuple[dict[str, Any], dict[str, dict[str, Any]]]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    path = result_file_from_row(row["result_path"], scan_root)
    if path not in cache:
        report = read_json(path)
        diagnostics = {
            diagnostic["diagnostic_id"]: diagnostic
            for run in report.get("detector_runs", [])
            if run.get("tool") == DETECTOR_ID
            for diagnostic in run.get("diagnostics", [])
            if diagnostic.get("diagnostic_id")
        }
        cache[path] = (report, diagnostics)
    report, diagnostics = cache[path]
    diagnostic = diagnostics.get(row.get("diagnostic_id", ""))
    if diagnostic is None:
        raise ValueError(f"diagnostic missing from referenced result: {row.get('diagnostic_id')}")
    if (
        report.get("repository") != row.get("repository")
        or report.get("commit") != row.get("manifest_commit")
        or diagnostic.get("rule_id") != row.get("rule_id")
        or diagnostic.get("file") != row.get("file")
        or str(diagnostic.get("line")) != row.get("line")
        or not diagnostic.get("source_sha256")
    ):
        raise ValueError(f"candidate/result identity mismatch: {row.get('diagnostic_id')}")
    return report, diagnostic


def function_shapes_by_line(source_text: str, target_lines: set[int]) -> dict[int, str]:
    """Classify the innermost lexical named-function span at each 1-based line."""
    masked = _mask_comments_and_literals(source_text)
    namespaces = _namespace_spans(masked)
    classes = _class_spans(masked, namespaces)
    functions = _function_spans(masked, namespaces, classes)

    line_offsets: dict[int, int] = {}
    offset = 0
    macro_lines: set[int] = set()
    in_macro = False
    for line_number, line in enumerate(source_text.splitlines(keepends=True), start=1):
        line_offsets[line_number] = offset
        stripped = line.lstrip()
        is_define = stripped.startswith("#define")
        if is_define or in_macro:
            macro_lines.add(line_number)
        in_macro = (is_define or in_macro) and line.rstrip("\r\n").rstrip().endswith("\\")
        offset += len(line)

    shapes: dict[int, str] = {}
    for line_number in target_lines:
        if line_number not in line_offsets:
            shapes[line_number] = "line_out_of_range"
            continue
        if line_number in macro_lines:
            shapes[line_number] = "macro_definition_body"
            continue
        position = line_offsets[line_number]
        containing = [
            function for function in functions
            if function.span.start <= position < function.span.end
        ]
        if not containing:
            shapes[line_number] = "outside_named_function"
            continue
        function = min(containing, key=lambda item: item.span.end - item.span.start)
        shapes[line_number] = "member_method" if function.owner_class else "free_function"
    return shapes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-root", type=Path, required=True)
    parser.add_argument("--report-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--progress", action="store_true", help="print each source file before parsing it")
    args = parser.parse_args()

    output_path = args.output.resolve()
    if output_path.exists():
        raise SystemExit(f"output already exists; refusing to overwrite: {output_path}")

    config = read_json(args.scan_root / "run_config.json")
    summary = read_json(args.report_root / "compact-summary.json")
    checksums = read_json(args.report_root / "checksums.json")
    detector_summary_path = args.report_root / "检测器能力.csv"
    if checksums.get("compact-summary.json") != sha256(args.report_root / "compact-summary.json"):
        raise ValueError("compact summary checksum mismatch")
    if checksums.get("检测器能力.csv") != sha256(detector_summary_path):
        raise ValueError("detector summary checksum mismatch")
    report_identity = summary.get("scanner", {})
    identity = {
        "run_signature": config.get("run_signature"),
        "scanner_commit": config.get("scanner_commit"),
        "manifest_sha256": config.get("manifest_sha256"),
    }
    if identity != {
        "run_signature": report_identity.get("run_signature"),
        "scanner_commit": report_identity.get("commit"),
        "manifest_sha256": report_identity.get("manifest_sha256"),
    }:
        raise ValueError("scan config and report run identities differ")
    if DETECTOR_ID not in config.get("detectors", []):
        raise ValueError("unsafe-memory detector absent from pinned run config")

    with detector_summary_path.open(encoding="utf-8-sig", newline="") as source:
        detector_summary = {
            row["detector"]: row for row in csv.DictReader(source)
        }.get(DETECTOR_ID)
    if detector_summary is None:
        raise ValueError("unsafe-memory detector absent from report detector summary")

    projects: dict[str, dict[str, str]] = {}
    with (args.scan_root / "project_summary.csv").open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            projects[row["repository"]] = row
    source_file_counts = sorted(int(item["selected_source_files"]) for item in projects.values())
    quartile_bounds = [source_file_counts[len(source_file_counts) * index // 4] for index in (1, 2, 3)]

    def repository_scale(repository: str) -> str:
        count = int(projects[repository]["selected_source_files"])
        return "Q" + str(1 + sum(count > bound for bound in quartile_bounds))

    result_cache: dict[Path, tuple[dict[str, Any], dict[str, dict[str, Any]]]] = {}
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = collections.defaultdict(list)
    rule_counts: collections.Counter[str] = collections.Counter()
    raw_rows = 0
    unique_ids: set[str] = set()
    candidate_csv = args.scan_root / "candidate_results.csv"
    with candidate_csv.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            if row.get("detector") != DETECTOR_ID:
                continue
            raw_rows += 1
            if row.get("repository") not in projects:
                raise ValueError("candidate repository missing from project summary")
            if row["manifest_commit"] != projects[row["repository"]]["manifest_commit"]:
                raise ValueError(f"candidate/project manifest commit mismatch: {row['diagnostic_id']}")
            _report, diagnostic = diagnostic_for_row(row, args.scan_root, result_cache)
            unique_ids.add(row["diagnostic_id"])
            rule_counts[row["rule_id"]] += 1
            source_rel = PurePosixPath(projects[row["repository"]]["project_path"]) / PurePosixPath(row["file"])
            if any(part in ("", ".", "..") for part in source_rel.parts):
                raise ValueError("candidate source path contains unsafe components")
            source_file = args.source_root.joinpath(*source_rel.parts).resolve()
            source_root = args.source_root.resolve()
            if not source_file.is_relative_to(source_root):
                raise ValueError("candidate source path escapes source root")
            expected_sha = diagnostic["source_sha256"]
            key = (row["repository"], row["manifest_commit"], row["file"], expected_sha)
            grouped[key].append({
                "diagnostic_id": row["diagnostic_id"],
                "repository": row["repository"],
                "file": row["file"],
                "line": int(row["line"]),
                "rule_id": row["rule_id"],
                "repository_scale": repository_scale(row["repository"]),
                "source_file": source_file,
                "expected_sha256": expected_sha,
            })

    if raw_rows != int(summary.get("candidate_counts_by_detector", {}).get(DETECTOR_ID, -1)):
        raise ValueError("candidate CSV raw count disagrees with compact summary")
    if raw_rows != int(detector_summary["candidate_count"]):
        raise ValueError("candidate CSV raw count disagrees with detector summary")
    if len(unique_ids) != raw_rows:
        raise ValueError("duplicate diagnostic IDs found; reconcile before function census")

    source_binding_counts: collections.Counter[str] = collections.Counter()
    shape_counts: collections.Counter[tuple[str, str, str]] = collections.Counter()
    row_shape_records: list[dict[str, str]] = []
    for group_index, ((repository, _commit, file_name, expected_sha), rows) in enumerate(grouped.items(), start=1):
        source_file = rows[0]["source_file"]
        if args.progress:
            print(f"source {group_index}/{len(grouped)} {repository}:{file_name}", flush=True)
        if not source_file.is_file():
            source_status = "source_unavailable"
            shape = source_status
        else:
            source_bytes = source_file.read_bytes()
            actual_sha = hashlib.sha256(source_bytes).hexdigest()
            if actual_sha != expected_sha:
                source_status = "source_hash_mismatch"
                shape = source_status
            else:
                source_status = "source_hash_matched"
                source_text = source_bytes.decode("utf-8", errors="replace")
                shape_by_line = function_shapes_by_line(source_text, {row["line"] for row in rows})
                for row in rows:
                    stratum = (row["rule_id"], shape_by_line[row["line"]], row["repository_scale"])
                    shape_counts[stratum] += 1
                    row_shape_records.append({
                        "diagnostic_id": row["diagnostic_id"],
                        "rule_id": row["rule_id"],
                        "function_shape": shape_by_line[row["line"]],
                        "repository_scale": row["repository_scale"],
                    })
                source_binding_counts[source_status] += len(rows)
                continue
        source_binding_counts[source_status] += len(rows)
        for row in rows:
            stratum = (row["rule_id"], shape, row["repository_scale"])
            shape_counts[stratum] += 1
            row_shape_records.append({
                "diagnostic_id": row["diagnostic_id"],
                "rule_id": row["rule_id"],
                "function_shape": shape,
                "repository_scale": row["repository_scale"],
            })

    counts_by_function_shape: collections.Counter[tuple[str, str]] = collections.Counter()
    for (rule_id, function_shape, _repo_scale), count in shape_counts.items():
        counts_by_function_shape[(rule_id, function_shape)] += count
    shape_distribution = [
        {
            "rule_id": rule_id,
            "function_shape": shape,
            "population": count,
            "population_share_of_frame": round(count / raw_rows, 6),
        }
        for (rule_id, shape), count in sorted(counts_by_function_shape.items())
    ]
    strata = [
        {
            "rule_id": rule_id,
            "function_shape": function_shape,
            "repository_scale": repo_scale,
            "population": count,
        }
        for (rule_id, function_shape, repo_scale), count in sorted(shape_counts.items())
    ]
    result = {
        "schema_version": "ohscanner.a-unsafe-function-shape-audit-v1",
        "audit_status": "PASS" if source_binding_counts["source_hash_matched"] == raw_rows else "PARTIAL",
        "frame_status": "provisional_population_mismatch",
        "expected_population_claim": 8994,
        "observed_raw_population": raw_rows,
        "observed_unique_diagnostic_ids": len(unique_ids),
        "population_delta_observed_minus_claim": raw_rows - 8994,
        "run_identity": identity,
        "candidate_csv_sha256": sha256(candidate_csv),
        "project_summary_sha256": sha256(args.scan_root / "project_summary.csv"),
        "compact_summary_sha256": sha256(args.report_root / "compact-summary.json"),
        "detector_summary_sha256": sha256(detector_summary_path),
        "source_root": str(args.source_root.resolve()),
        "repository_scale_quartile_upper_bounds_selected_source_files": quartile_bounds,
        "population_by_rule": dict(sorted(rule_counts.items())),
        "source_hash_status_by_raw_rows": dict(sorted(source_binding_counts.items())),
        "function_shape_population": shape_distribution,
        "function_shape_strata": strata,
        "function_shape_strata_count": len(strata),
        "candidate_rows": sorted(row_shape_records, key=lambda item: item["diagnostic_id"]),
        "parser": {
            "library": "bounded lexical function-span extraction",
            "implementation": "src.ohscanner.detectors.cpp.shared_ptr_race_detector",
            "classification": "innermost named enclosing function category only; not a vulnerability/flow judgment",
        },
        "limitations": [
            "The observed 9,323-row frame is not the unbound 8,994 target population.",
            "Function shape comes from the scanner's bounded lexical span helper over exact source-hash-matched files; it does not resolve lambdas, compile flags, overloads, macros, aliasing, CFG, reachability, or vulnerability truth.",
            "Source-unavailable and hash-mismatch rows remain in explicit strata and are not dropped or resampled.",
            "Function-shape and repository-size distributions describe the detector output only; human review is still required before changing rules.",
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(output_path),
        "audit_status": result["audit_status"],
        "raw_rows": raw_rows,
        "source_hash_status": result["source_hash_status_by_raw_rows"],
        "function_shape_strata": len(strata),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

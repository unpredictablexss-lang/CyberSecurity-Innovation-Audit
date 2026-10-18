#!/usr/bin/env python3
"""Batch OpenHarmony scan with reviewed A/B and research-only C/D detectors.

The product catalog and C/D admission records are intentionally unchanged.
C/D outputs are research candidates only and cannot become validated
vulnerabilities through this runner.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

SCHEMA_VERSION = "openharmony-abcd-full-scan-v1"
LANE_BY_DETECTOR = {
    "ohscanner.cpp.bounds": "A",
    "ohscanner.cpp.integer_bounds": "A",
    "ohscanner.cpp.lifetime": "A",
    "ohscanner.cpp.null_dereference": "A",
    "ohscanner.cpp.resource_lifetime": "A",
    "ohscanner.cpp.shared_ptr_race": "A",
    "ohscanner.cpp.unsafe_memory_call": "A",
    "ohscanner.interface.ipc": "B",
    "ohscanner.oh.arkts_js": "B",
    "ohscanner.ark.runtime.type_safety": "C",
    "ohscanner.data.sensitive_exposure": "D",
}
PRODUCTION_IDS = tuple(sorted(k for k, v in LANE_BY_DETECTOR.items() if v in {"A", "B"}))
RESEARCH_IDS = tuple(sorted(k for k, v in LANE_BY_DETECTOR.items() if v in {"C", "D"}))
DETECTORS = tuple(sorted(LANE_BY_DETECTOR))
C_BRANCH = "origin/codex/teammate-c-ark-runtime-type-safety"
D_BRANCH = "origin/feat/teammate-d-sensitive-exposure-20261017"
PROJECT_COLUMNS = [
    "index", "name", "project_path", "repository", "manifest_commit", "git_tree",
    "execution_state", "classification", "scanner_status", "failure_reason",
    "duration_seconds", "selected_source_files", "tracked_entries", "oversize",
    "binary_or_non_utf8", "symlinks", "submodules", "parse_complete", "parse_partial",
    "parse_failed", "parse_not_run", "production_coverage", "research_c_status",
    "research_d_status", "candidate_count", "validated_vulnerability", "result_path",
]
CANDIDATE_COLUMNS = [
    "index", "name", "repository", "manifest_commit", "lane", "admission",
    "detector", "detector_version", "diagnostic_id", "rule_id", "file", "line",
    "candidate_cwe", "symbol", "analysis_status", "message", "evidence_obligations",
    "result_path",
]
DETECTOR_COLUMNS = [
    "detector", "lane", "admission", "projects_with_run", "completed", "partial",
    "blocked", "failed", "not_applicable", "applicable_files", "analyzed_files",
    "partially_inspected_files", "not_analyzed_files", "failed_files",
    "candidate_count", "elapsed_seconds",
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def atomic_json(path: Path, value) -> None:
    atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def atomic_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in columns})
    os.replace(tmp, path)


def safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")
    return cleaned or "project"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_value(repo_dir: Path, expression: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-parse", expression],
        text=True, encoding="utf-8", errors="replace",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
    )
    if proc.returncode:
        raise RuntimeError(f"git rev-parse {expression} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def load_projects(manifest: Path) -> list[dict]:
    root = ET.parse(manifest).getroot()
    projects = []
    for index, node in enumerate(root.findall(".//project"), start=1):
        name = node.attrib.get("name", "")
        revision = node.attrib.get("revision", "").lower()
        project_path = node.attrib.get("path") or name
        if not name or not re.fullmatch(r"[0-9a-f]{40}", revision):
            continue
        projects.append({
            "index": index,
            "name": name,
            "project_path": project_path,
            "repository": f"openharmony/{name}",
            "manifest_commit": revision,
        })
    return projects


def result_is_valid(path: Path) -> tuple[bool, dict, str]:
    if not path.is_file() or path.stat().st_size == 0:
        return False, {}, "missing_or_empty_result_json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, {}, f"invalid_result_json:{type(exc).__name__}:{exc}"
    required = {
        "schema_version", "status", "repository", "commit", "git_tree",
        "snapshot_sha256", "scope", "detector_runs", "diagnostic_count",
        "validated_vulnerability", "detector_coverage",
    }
    missing = sorted(required - set(value))
    if missing:
        return False, value, "missing_result_fields:" + ",".join(missing)
    return True, value, ""


def build_registry():
    from src.ohscanner.detectors.catalog import build_registry as build_product_registry
    from research.full_scan_20261018.lanes.c.detector import ArkRuntimeTypeSafetyDetector
    from research.full_scan_20261018.lanes.d.models import DEFAULT_SOURCE
    from research.full_scan_20261018.lanes.d.sensitive_exposure import SensitiveExposureDetector

    registry = build_product_registry(PRODUCTION_IDS)
    registry.register(ArkRuntimeTypeSafetyDetector())
    registry.register(SensitiveExposureDetector(DEFAULT_SOURCE))
    if tuple(sorted(item.detector_id for item in registry.detectors())) != DETECTORS:
        raise RuntimeError("detector registry does not match frozen detector set")
    return registry


def compact_detector_metrics(report: dict) -> list[dict]:
    sidecar = report.get("detector_coverage", {}).get("detectors", {})
    rows = []
    for run in report.get("detector_runs", []):
        detector = run.get("tool", "")
        coverage = sidecar.get(detector, {})
        counts = coverage.get("coverage_counts", {})
        rows.append({
            "detector": detector,
            "lane": LANE_BY_DETECTOR.get(detector, "unknown"),
            "admission": "research_unadmitted" if detector in RESEARCH_IDS else "production_research_candidate",
            "run_status": run.get("status"),
            "coverage_status": coverage.get("status"),
            "applicable_files": coverage.get("applicable_files", 0),
            "analyzed_files": len(coverage.get("analyzed_files", [])),
            "partially_inspected_files": len(coverage.get("partially_inspected_files", [])),
            "not_analyzed_files": len(coverage.get("not_analyzed_files", [])),
            "failed_files": counts.get("failed", 0),
            "candidate_count": run.get("diagnostic_count", 0),
            "elapsed_seconds": run.get("elapsed_seconds", 0.0),
        })
    return rows


def classify(report: dict, detector_metrics: list[dict]) -> tuple[str, str, str]:
    production = [row for row in detector_metrics if row["lane"] in {"A", "B"}]
    c_status = next((row["coverage_status"] for row in detector_metrics if row["lane"] == "C"), "missing")
    d_status = next((row["coverage_status"] for row in detector_metrics if row["lane"] == "D"), "missing")
    if not production:
        return "unknown", c_status, d_status
    if any(row["run_status"] == "failed" or row["coverage_status"] == "failed" for row in production):
        return "failed", c_status, d_status
    applicable = [row for row in production if row["applicable_files"]]
    if not applicable:
        return "not_applicable", c_status, d_status
    if all(row["coverage_status"] == "complete" for row in applicable):
        classification = "completed"
    elif any(row["analyzed_files"] or row["partially_inspected_files"] for row in applicable):
        classification = "partial"
    else:
        classification = "unknown"
    scope = report.get("scope", {})
    if any(int(scope.get(key, 0) or 0) for key in ("oversize", "binary_or_non_utf8", "symlinks", "submodules")):
        classification = "partial" if classification == "completed" else classification
    return classification, c_status, d_status


def candidate_rows(project: dict, result: dict, result_path: Path) -> list[dict]:
    parsing_by_file = {}
    for run in result.get("detector_runs", []):
        for item in run.get("parsing", []):
            parsing_by_file[(run.get("tool"), item.get("file"))] = item.get("analysis_status", "unknown")
    rows = []
    for run in result.get("detector_runs", []):
        detector = run.get("tool", "")
        admission = "research_unadmitted" if detector in RESEARCH_IDS else "production_research_candidate"
        for diagnostic in run.get("diagnostics", []):
            obligations = diagnostic.get("evidence_obligations", [])
            rows.append({
                **project,
                "lane": LANE_BY_DETECTOR.get(detector, "unknown"),
                "admission": admission,
                "detector": detector,
                "detector_version": run.get("tool_version", ""),
                "diagnostic_id": diagnostic.get("diagnostic_id", ""),
                "rule_id": diagnostic.get("rule_id", ""),
                "file": diagnostic.get("file", ""),
                "line": diagnostic.get("line", ""),
                "candidate_cwe": diagnostic.get("candidate_cwe", ""),
                "symbol": diagnostic.get("symbol", ""),
                "analysis_status": parsing_by_file.get((detector, diagnostic.get("file")), "unknown"),
                "message": diagnostic.get("message", ""),
                "evidence_obligations": len(obligations) if isinstance(obligations, list) else "",
                "result_path": str(result_path),
            })
    return rows


def project_row(project: dict, meta: dict, result: dict, project_dir: Path) -> dict:
    scope = result.get("scope", {})
    parsing = result.get("source_parsing", {}).get("parsing_status", {})
    metrics = meta.get("detector_metrics", [])
    production = [row for row in metrics if row["lane"] in {"A", "B"}]
    if production and all(row["coverage_status"] == "complete" for row in production if row["applicable_files"]):
        production_coverage = "complete" if any(row["applicable_files"] for row in production) else "not_applicable"
    elif any(row["analyzed_files"] or row["partially_inspected_files"] for row in production):
        production_coverage = "partial"
    else:
        production_coverage = "unknown"
    return {
        **project,
        "git_tree": meta.get("git_tree", ""),
        "execution_state": meta.get("execution_state", "failed"),
        "classification": meta.get("classification", "failed"),
        "scanner_status": meta.get("scanner_status", ""),
        "failure_reason": meta.get("failure_reason", ""),
        "duration_seconds": meta.get("duration_seconds", ""),
        "selected_source_files": scope.get("selected_source_files", 0),
        "tracked_entries": scope.get("tracked_entries", 0),
        "oversize": scope.get("oversize", 0),
        "binary_or_non_utf8": scope.get("binary_or_non_utf8", 0),
        "symlinks": scope.get("symlinks", 0),
        "submodules": scope.get("submodules", 0),
        "parse_complete": parsing.get("complete", 0),
        "parse_partial": parsing.get("partial", 0),
        "parse_failed": parsing.get("failed", 0),
        "parse_not_run": parsing.get("not_run", 0),
        "production_coverage": production_coverage,
        "research_c_status": meta.get("research_c_status", "missing"),
        "research_d_status": meta.get("research_d_status", "missing"),
        "candidate_count": meta.get("candidate_count", 0),
        "validated_vulnerability": meta.get("validated_vulnerability", 0),
        "result_path": str(project_dir / "result.json"),
    }


def write_worker_result(result_path: Path, report: dict) -> None:
    report["research_mode"] = {
        "combination": "A/B/C/D research full scan",
        "production_admitted_ids": list(PRODUCTION_IDS),
        "research_unadmitted_ids": list(RESEARCH_IDS),
        "c_admission": "blocked; execution_enabled=false in product admission metadata",
        "d_admission": "blocked; execution_enabled=false in product admission metadata",
        "warning": "C/D are research-only. Their candidates cannot be promoted or counted as validated vulnerabilities.",
    }
    report["limitations"] = report.get("limitations", []) + [
        "C/D were instantiated in a research-only runner without changing the production catalog or admission gate.",
        "All diagnostics remain unassessed candidates; validated_vulnerability is fixed at zero by this runner.",
    ]
    from src.ohscanner.execution import write_report_json
    write_report_json(report, result_path)
    with result_path.with_name("report.md").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write("\n## Research admission\n\n")
        handle.write("- C/D are blocked and not production enabled in the product admission metadata.\n")
        handle.write("- This run records research candidates only and cannot validate a vulnerability.\n")


def run_worker(args) -> int:
    started = time.monotonic()
    result_path = Path(args.result_json)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    registry = build_registry()
    from src.ohscanner.execution import run_reviewed_detectors
    report = run_reviewed_detectors(
        repo_dir=Path(args.repo_dir),
        repository=args.repository,
        commit=args.commit,
        includes=(".",),
        registry=registry,
    )
    write_worker_result(result_path, report)
    metrics = compact_detector_metrics(report)
    classification, c_status, d_status = classify(report, metrics)
    summary = {
        "worker_schema_version": SCHEMA_VERSION,
        "scanner_status": report.get("status"),
        "classification": classification,
        "research_c_status": c_status,
        "research_d_status": d_status,
        "git_tree": report.get("git_tree"),
        "snapshot_sha256": report.get("snapshot_sha256"),
        "candidate_count": report.get("diagnostic_count", 0),
        "validated_vulnerability": report.get("validated_vulnerability", 0),
        "duration_seconds": round(time.monotonic() - started, 3),
        "detector_metrics": metrics,
    }
    atomic_json(result_path.with_name("worker_summary.json"), summary)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


def aggregate_detector_rows(project_rows: list[dict], output: Path) -> list[dict]:
    raw = []
    for project in project_rows:
        meta_path = Path(project["result_path"]).with_name("run_meta.json")
        if not meta_path.is_file():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        raw.extend(meta.get("detector_metrics", []))
    grouped = {}
    for row in raw:
        detector = row.get("detector", "")
        item = grouped.setdefault(detector, {
            "detector": detector,
            "lane": LANE_BY_DETECTOR.get(detector, "unknown"),
            "admission": "research_unadmitted" if detector in RESEARCH_IDS else "production_research_candidate",
            "projects_with_run": 0, "completed": 0, "partial": 0, "blocked": 0,
            "failed": 0, "not_applicable": 0, "applicable_files": 0,
            "analyzed_files": 0, "partially_inspected_files": 0,
            "not_analyzed_files": 0, "failed_files": 0, "candidate_count": 0,
            "elapsed_seconds": 0.0,
        })
        item["projects_with_run"] += 1
        status = row.get("coverage_status") or row.get("run_status") or "unknown"
        if status in {"completed", "partial", "blocked", "failed", "not_applicable"}:
            item[status] += 1
        for key in ("applicable_files", "analyzed_files", "partially_inspected_files",
                    "not_analyzed_files", "failed_files", "candidate_count"):
            item[key] += int(row.get(key, 0) or 0)
        item["elapsed_seconds"] += float(row.get("elapsed_seconds", 0.0) or 0.0)
    for item in grouped.values():
        item["elapsed_seconds"] = round(item["elapsed_seconds"], 3)
    rows = [grouped[key] for key in sorted(grouped)]
    atomic_csv(output / "detector_summary.csv", DETECTOR_COLUMNS, rows)
    return rows


def write_summary(output: Path, projects: list[dict], project_rows: list[dict],
                  candidates: list[dict], started_at: str, manifest: Path,
                  scanner_sha: str, signature: str, batch_size: int) -> dict:
    counts = {}
    for row in project_rows:
        key = row.get("classification") or "unknown"
        counts[key] = counts.get(key, 0) + 1
    candidate_by_lane = {}
    candidate_by_cwe = {}
    for row in candidates:
        lane = row.get("lane", "unknown")
        candidate_by_lane[lane] = candidate_by_lane.get(lane, 0) + 1
        cwe = row.get("candidate_cwe") or "未标注"
        candidate_by_cwe[cwe] = candidate_by_cwe.get(cwe, 0) + 1
    detector_rows = aggregate_detector_rows(project_rows, output)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "started_at": started_at,
        "updated_at": utc_now(),
        "manifest": str(manifest),
        "manifest_sha256": sha256_file(manifest),
        "scanner_commit": scanner_sha,
        "run_signature": signature,
        "project_count": len(projects),
        "processed_count": len(project_rows),
        "classification_counts": counts,
        "candidate_count": len(candidates),
        "validated_vulnerability_count": 0,
        "candidate_counts_by_lane": dict(sorted(candidate_by_lane.items())),
        "candidate_counts_by_cwe": dict(sorted(candidate_by_cwe.items(), key=lambda item: (-item[1], item[0]))),
        "remaining_disk_bytes": shutil.disk_usage(output).free,
        "batch_size": batch_size,
        "detector_summary": detector_rows,
    }
    atomic_json(output / "summary.json", summary)
    atomic_json(output / "progress.json", {
        "schema_version": SCHEMA_VERSION,
        "updated_at": summary["updated_at"],
        "processed_count": len(project_rows),
        "project_count": len(projects),
        "classification_counts": counts,
        "candidate_count": len(candidates),
        "remaining_disk_bytes": summary["remaining_disk_bytes"],
    })
    atomic_csv(output / "project_summary.csv", PROJECT_COLUMNS, project_rows)
    atomic_csv(output / "candidate_results.csv", CANDIDATE_COLUMNS, candidates)
    return summary


def load_existing_rows(output: Path, filename: str) -> dict[str, dict]:
    path = output / filename
    rows = {}
    if not path.is_file():
        return rows
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                key = row.get("result_path") or row.get("diagnostic_id") or json.dumps(row, sort_keys=True)
                rows[key] = row
    except Exception:
        return {}
    return rows


def meta_valid(meta_path: Path, result_path: Path, signature: str) -> tuple[bool, dict, dict]:
    valid, result, _ = result_is_valid(result_path)
    if not valid or not meta_path.is_file():
        return False, {}, {}
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return False, {}, {}
    if meta.get("run_signature") != signature or meta.get("execution_state") != "completed":
        return False, meta, result
    return True, meta, result


def project_dir_for(output: Path, project: dict) -> Path:
    digest = hashlib.sha1(project["project_path"].encode("utf-8")).hexdigest()[:10]
    return output / "projects" / f"{project['index']:04d}-{safe_name(project['name'])}-{digest}"


def run_parent(args) -> int:
    manifest = Path(args.manifest).resolve()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    projects = load_projects(manifest)
    if args.only:
        wanted = set(args.only)
        projects = [item for item in projects if item["name"] in wanted]
        missing = wanted - {item["name"] for item in projects}
        if missing:
            raise SystemExit("unknown project names: " + ", ".join(sorted(missing)))
    if args.start > 1:
        projects = projects[args.start - 1:]
    if args.limit is not None:
        projects = projects[:args.limit]
    scanner_root = Path(__file__).resolve().parents[1]
    scanner_sha = git_value(scanner_root, "HEAD")
    c_sha = git_value(scanner_root, C_BRANCH)
    d_sha = git_value(scanner_root, D_BRANCH)
    config = {
        "schema_version": SCHEMA_VERSION,
        "manifest": str(manifest),
        "manifest_sha256": sha256_file(manifest),
        "scanner_commit": scanner_sha,
        "c_source_branch": C_BRANCH,
        "c_source_commit": c_sha,
        "d_source_branch": D_BRANCH,
        "d_source_commit": d_sha,
        "detectors": list(DETECTORS),
        "production_detectors": list(PRODUCTION_IDS),
        "research_unadmitted_detectors": list(RESEARCH_IDS),
        "timeout_seconds": args.timeout,
        "batch_size": args.batch_size,
    }
    signature = hashlib.sha256(json.dumps(config, sort_keys=True).encode("utf-8")).hexdigest()
    config["run_signature"] = signature
    atomic_json(output / "run_config.json", config)

    project_rows = load_existing_rows(output, "project_summary.csv")
    candidates = load_existing_rows(output, "candidate_results.csv")
    started_at = utc_now()
    total = len(projects)
    print(f"runner_start projects={total} output={output} signature={signature}", flush=True)

    for offset, project in enumerate(projects, start=1):
        project_dir = project_dir_for(output, project)
        result_path = project_dir / "result.json"
        meta_path = project_dir / "run_meta.json"
        valid, meta, result = meta_valid(meta_path, result_path, signature)
        if not valid:
            project_dir.mkdir(parents=True, exist_ok=True)
            repo_dir = Path(args.repo_root) / project["project_path"]
            started_project = utc_now()
            clock = time.monotonic()
            command = [
                sys.executable, str(Path(__file__).resolve()), "--worker",
                "--repo-dir", str(repo_dir),
                "--repository", project["repository"],
                "--commit", project["manifest_commit"],
                "--result-json", str(result_path),
                "--report-md", str(project_dir / "report.md"),
            ]
            request = {**project, "command": command, "timeout_seconds": args.timeout,
                       "run_signature": signature, "started_at": started_project}
            atomic_json(project_dir / "request.json", request)
            failure = ""
            exit_code = None
            timed_out = False
            stdout = ""
            stderr = ""
            try:
                proc = subprocess.run(
                    command, cwd=str(scanner_root), text=True, encoding="utf-8",
                    errors="replace", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=args.timeout, env={**os.environ, "PYTHONUNBUFFERED": "1"},
                )
                exit_code = proc.returncode
                stdout = proc.stdout or ""
                stderr = proc.stderr or ""
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                failure = f"timeout_after_{args.timeout}_seconds"
                stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
                stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
            except Exception as exc:
                failure = f"runner_exception:{type(exc).__name__}:{exc}"
            (project_dir / "stdout.log").write_text(stdout, encoding="utf-8", newline="\n")
            (project_dir / "stderr.log").write_text(stderr, encoding="utf-8", newline="\n")
            valid, result, validation_error = result_is_valid(result_path)
            worker_summary = {}
            worker_summary_path = project_dir / "worker_summary.json"
            if worker_summary_path.is_file():
                try:
                    worker_summary = json.loads(worker_summary_path.read_text(encoding="utf-8"))
                except Exception:
                    worker_summary = {}
            if not failure and exit_code != 0:
                failure = f"nonzero_exit:{exit_code}"
            if not failure and not valid:
                failure = validation_error
            actual_commit = ""
            git_tree = ""
            if repo_dir.is_dir():
                try:
                    actual_commit = git_value(repo_dir, project["manifest_commit"] + "^{commit}")
                    git_tree = git_value(repo_dir, project["manifest_commit"] + "^{tree}")
                except Exception as exc:
                    failure = failure or f"git_provenance_failed:{type(exc).__name__}:{exc}"
            if not failure and actual_commit != project["manifest_commit"]:
                failure = "manifest_commit_not_available_in_local_git_objects"
            execution_state = "completed" if not failure and not timed_out else "failed"
            metrics = worker_summary.get("detector_metrics", [])
            if not metrics and valid:
                metrics = compact_detector_metrics(result)
            classification = worker_summary.get("classification", "failed")
            if execution_state == "failed":
                classification = "failed"
            meta = {
                "schema_version": SCHEMA_VERSION,
                "run_signature": signature,
                **project,
                "repo_dir": str(repo_dir),
                "started_at": started_project,
                "finished_at": utc_now(),
                "duration_seconds": round(time.monotonic() - clock, 3),
                "timeout_seconds": args.timeout,
                "timed_out": timed_out,
                "exit_code": exit_code,
                "execution_state": execution_state,
                "failure_reason": failure,
                "actual_commit": actual_commit,
                "git_tree": git_tree,
                "result_json_valid": valid,
                "result_validation_error": "" if valid else validation_error,
                "scanner_status": worker_summary.get("scanner_status") or result.get("status", ""),
                "classification": classification,
                "research_c_status": worker_summary.get("research_c_status", "missing"),
                "research_d_status": worker_summary.get("research_d_status", "missing"),
                "candidate_count": worker_summary.get("candidate_count", result.get("diagnostic_count", 0) if valid else 0),
                "validated_vulnerability": 0,
                "detector_metrics": metrics,
                "command": command,
                "remaining_disk_bytes": shutil.disk_usage(output).free,
            }
            atomic_json(meta_path, meta)
        row = project_row(project, meta, result if valid else {}, project_dir)
        project_rows[str(result_path)] = row
        for candidate in candidate_rows(project, result if valid else {}, result_path):
            candidates[candidate["diagnostic_id"] or json.dumps(candidate, sort_keys=True)] = candidate
        summary = write_summary(
            output, projects, list(project_rows.values()), list(candidates.values()),
            started_at, manifest, scanner_sha, signature, args.batch_size,
        )
        print(
            f"[{offset:03d}/{total:03d}] {project['repository']} "
            f"state={meta.get('execution_state')} class={row['classification']} "
            f"status={row['scanner_status']} candidates={row['candidate_count']} "
            f"duration={row['duration_seconds']}s"
            + (f" failure={row['failure_reason']}" if row["failure_reason"] else ""),
            flush=True,
        )
        if offset % args.batch_size == 0 or offset == total:
            atomic_json(output / "batch_checkpoint.json", {
                "schema_version": SCHEMA_VERSION,
                "updated_at": utc_now(),
                "processed_count": len(project_rows),
                "project_count": total,
                "classification_counts": summary["classification_counts"],
                "candidate_count": summary["candidate_count"],
                "validated_vulnerability_count": 0,
                "note": "Research checkpoint. C/D remain unadmitted and candidates remain unassessed.",
            })
    print(
        "runner_finish "
        f"processed={len(project_rows)} "
        f"classifications={json.dumps(summary['classification_counts'], sort_keys=True)} "
        f"candidates={summary['candidate_count']} "
        f"validated=0 "
        f"remaining_disk_bytes={summary['remaining_disk_bytes']}",
        flush=True,
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--repo-dir")
    parser.add_argument("--repository")
    parser.add_argument("--commit")
    parser.add_argument("--result-json")
    parser.add_argument("--report-md")
    parser.add_argument("--manifest")
    parser.add_argument("--repo-root")
    parser.add_argument("--output-dir")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--batch-size", type=int, default=25)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--only", action="append", default=[])
    args = parser.parse_args()
    if args.worker:
        required = ("repo_dir", "repository", "commit", "result_json", "report_md")
        if any(not getattr(args, name) for name in required):
            parser.error("worker requires --repo-dir, --repository, --commit, --result-json and --report-md")
        return run_worker(args)
    required = ("manifest", "repo_root", "output_dir")
    if any(not getattr(args, name) for name in required):
        parser.error("run requires --manifest, --repo-root and --output-dir")
    return run_parent(args)


if __name__ == "__main__":
    raise SystemExit(main())

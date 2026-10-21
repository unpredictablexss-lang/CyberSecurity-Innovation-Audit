"""M2: run reviewed first-party detectors on pinned local Git sources.

Emits reproducible source scope and per-detector coverage/evidence obligations.
A zero-diagnostic result cannot imply safety. No external analyzer invocation.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
from time import perf_counter, process_time

from .detectors.catalog import build_registry, default_detector_ids
from .git_source import load_git_sources
from .indexing import child_cpu_seconds, environment_fingerprint, prepare_git_context
from .runner import run_all_with_coverage



MAX_REPORT_BYTES = 64 * 1024 * 1024


def write_report_json(report, path):
    performance = report.setdefault("performance", {})
    performance["report_json_serialization_seconds"] = None
    # Fixed-width JSON number allows the measured publication duration to be
    # patched without serializing or rewriting the full report a second time.
    performance["report_file_write_seconds"] = 0.000000000e+000
    performance["report_write_seconds"] = None
    performance["report_write_status"] = "temporary write and atomic replace; timing-field patch excluded"
    started = perf_counter()
    data = (json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    elapsed = perf_counter() - started
    needle = b'"report_json_serialization_seconds":null'
    replacement = f'"report_json_serialization_seconds":{elapsed:.9f}'.encode("ascii")
    data = data.replace(needle, replacement, 1)
    data = data.replace(
        b'"report_file_write_seconds":0.0',
        b'"report_file_write_seconds":0.000000000e+000', 1,
    )
    data = data.replace(
        b'"report_write_seconds":null',
        b'"report_write_seconds":0.000000000e+000', 1,
    )
    placeholder = b'"report_file_write_seconds":0.000000000e+000'
    write_offset = data.find(placeholder)
    alias_placeholder = b'"report_write_seconds":0.000000000e+000'
    alias_offset = data.find(alias_placeholder)
    if write_offset < 0 or alias_offset < 0:
        raise ValueError("Report file-write timing placeholder is missing")
    # Keep the in-memory result identical to the precision written to JSON.
    performance["report_json_serialization_seconds"] = float(f"{elapsed:.9f}")
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("Report exceeds 64 MiB publication budget; narrow the scope or select fewer rules. No complete result was published; analysis remains unknown.")
    temporary = path.with_suffix(path.suffix + ".tmp")
    write_started = perf_counter()
    temporary.write_bytes(data)
    temporary.replace(path)
    write_elapsed = perf_counter() - write_started
    performance["report_file_write_seconds"] = float(f"{write_elapsed:.9e}")
    performance["report_write_seconds"] = performance["report_file_write_seconds"]
    mantissa, exponent = f"{write_elapsed:.9e}".split("e")
    sign = "+" if int(exponent) >= 0 else "-"
    measured = f'"report_file_write_seconds":{mantissa}e{sign}{abs(int(exponent)):03d}'.encode("ascii")
    alias_measured = f'"report_write_seconds":{mantissa}e{sign}{abs(int(exponent)):03d}'.encode("ascii")
    if len(measured) != len(placeholder):
        raise ValueError("Unexpected report file-write timing format")
    with path.open("r+b") as stream:
        stream.seek(write_offset)
        stream.write(measured)
        stream.seek(alias_offset)
        stream.write(alias_measured)


def run_reviewed_detectors(
    repo_dir: Path,
    repository: str,
    commit: str,
    includes: tuple[str, ...],
    registry,
    *, planning_selection=False, expected_plan=None, ast_cache_dir=None,
    ast_cache_max_bytes=512 * 1024 * 1024, clear_ast_cache=False,
    base_commit=None, detector_result_cache_dir=None,
    detector_checkpoint_dir=None, detector_checkpoint_engine_sha256=None,
):
    """Programmatic extension point: callers supply an explicitly reviewed registry.

    Actual detector plugins may be integrated only after code review. Does not
    support untrusted arbitrary imports or invoke subprocess scanners.
    """
    if not registry.detectors():
        raise ValueError("at least one reviewed detector is required")
    wall_started, cpu_started = perf_counter(), process_time()
    phase_metrics = {}
    ast_cache = None
    cache_setup_started, cache_setup_cpu_started = perf_counter(), process_time()
    if ast_cache_dir is not None:
        from .ast_cache import AstSummaryCache
        ast_cache = AstSummaryCache(Path(ast_cache_dir), max_bytes=ast_cache_max_bytes)
        if clear_ast_cache:
            ast_cache.clear()
    phase_metrics["ast_cache_setup_seconds"] = perf_counter() - cache_setup_started
    phase_metrics["ast_cache_setup_cpu_seconds"] = process_time() - cache_setup_cpu_started
    requested_facts = tuple(sorted({
        fact for detector in registry.detectors()
        for fact in detector.required_facts
    }))
    context, tree, inventory, parsing, sources = prepare_git_context(
        repo_dir, repository, commit, includes, ast_cache=ast_cache,
        phase_metrics=phase_metrics, requested_facts=requested_facts,
    )
    incremental_plan = None
    if base_commit is not None:
        from .incremental import plan_fixed_commit_diff
        incremental_plan = plan_fixed_commit_diff(
            repo_dir, base_commit, context.request.commit, includes,
            head_sources=sources, head_inventory=inventory,
            head_ast=context.shared_facts.get("ast", {}), ast_cache=ast_cache)
    plan = None
    if planning_selection is not False:
        from .planning import plan_context
        execution_budget = expected_plan.get("execution_budget") if expected_plan is not None else None
        plan = plan_context(
            context, tree, inventory, sources, planning_selection,
            execution_budget=execution_budget,
        )
        if expected_plan is not None and plan != expected_plan:
            raise ValueError("Frozen audit plan drifted; no scan result published")
        if planning_selection is None:
            if not plan["suggested_detector_ids"]:
                raise ValueError("No applicable approved detector; analysis remains unknown")
            registry = build_registry(tuple(plan["suggested_detector_ids"]))
    detector_stage_started = perf_counter()
    detector_stage_cpu_started = process_time()
    result_cache = None
    result_cache_setup_error = None
    if detector_result_cache_dir is not None:
        try:
            from .incremental_cache import PerFileDetectorResultCache
            result_cache = PerFileDetectorResultCache(Path(detector_result_cache_dir))
        except OSError as error:
            result_cache_setup_error = type(error).__name__ + ": " + str(error)[:300]
    detector_checkpoints = None
    if detector_checkpoint_dir is not None and detector_checkpoint_engine_sha256:
        from .detector_checkpoints import DetectorCheckpointStore
        detector_checkpoints = DetectorCheckpointStore(
            detector_checkpoint_dir, detector_checkpoint_engine_sha256
        )
    reports, sidecar = run_all_with_coverage(
        context, registry, per_file_result_cache=result_cache,
        detector_checkpoints=detector_checkpoints)
    if detector_checkpoints is not None:
        phase_metrics["detector_checkpoints"] = dict(detector_checkpoints.stats)
    if result_cache is not None:
        phase_metrics["detector_result_cache"] = dict(result_cache.stats)
    elif detector_result_cache_dir is not None:
        phase_metrics["detector_result_cache"] = {
            "hits": 0, "misses": 0, "bypassed": 0, "invalid": 0,
            "writes": 0, "write_skipped": 0, "read_errors": 0,
            "status": "disabled_after_setup_error", "error": result_cache_setup_error,
        }
    phase_metrics["detector_stage_wall_seconds"] = perf_counter() - detector_stage_started
    phase_metrics["detector_stage_cpu_seconds"] = process_time() - detector_stage_cpu_started

    # Independently re-read the same immutable objects. Do not claim the scan
    # succeeded when the local object store changes during execution.
    verify_started = perf_counter()
    verify_cpu_started = process_time()
    verify_child_cpu_before = child_cpu_seconds()
    commit2, tree2, sources2, inventory2 = load_git_sources(repo_dir, commit, includes)
    phase_metrics["source_read_seconds"] += perf_counter() - verify_started
    phase_metrics["source_read_cpu_seconds"] += process_time() - verify_cpu_started
    verify_child_cpu_after = child_cpu_seconds()
    if phase_metrics.get("source_read_child_cpu_seconds") is not None and verify_child_cpu_before is not None and verify_child_cpu_after is not None:
        phase_metrics["source_read_child_cpu_seconds"] += verify_child_cpu_after - verify_child_cpu_before
    else:
        phase_metrics["source_read_child_cpu_seconds"] = None
    def immutable_sources(items):
        return tuple((item.path, item.language, item.oid, item.data) for item in items)

    if (
        commit2 != context.request.commit
        or tree2 != tree
        or inventory2 != inventory
        or immutable_sources(sources) != immutable_sources(sources2)
    ):
        raise ValueError("pinned Git source inventory changed during detector execution")

    raw_diagnostics = sum(result.diagnostic_count for result in reports)
    coverage_has_gaps = (
        bool(inventory["oversize"] or inventory["binary_or_non_utf8"]
             or inventory["symlinks"] or inventory["submodules"]
             or any(item.get("skipped") or item.get("limitations")
                    or item.get("status") != "indexed"
                    for item in inventory.get("source_archives", [])))
        or any(data["status"] != "complete"
               for data in sidecar["detectors"].values())
    )
    plugin_count = len(reports)
    report_build_started = perf_counter()
    report_build_cpu_started = process_time()
    report = {
        "schema_version": 1,
        "experiment_kind": "first_party_detector_execution",
        "status": "completed_with_limitations" if coverage_has_gaps else "completed",
        "repository": context.request.repository,
        "target_id": context.request.target_id,
        "commit": context.request.commit,
        "git_tree": tree,
        "snapshot_sha256": context.request.snapshot_sha256,
        "provenance": "local_git_objects",
        "profile_id": context.request.profile_id,
        "environment": environment_fingerprint(),
        "scope": inventory,
        "source_parsing": parsing,
        "detector_count": plugin_count,
        "diagnostic_count": raw_diagnostics,
        "validated_vulnerability": 0,
        "detector_runs": [result.to_dict() for result in reports],
        "detector_coverage": sidecar,
        "analysis_fact_providers": phase_metrics.get("fact_providers", []),
        "files_in_scope_without_a_claiming_detector": sorted(
            unit.path for unit in context.units
            if not any(unit.language in detector.supported_languages
                       for detector in registry.detectors())
        ),
        "limitations": [
            "Diagnostics are candidates/evidence only, not proof of security impact.",
            "Zero diagnostics does NOT mean the component is free of vulnerabilities.",
            "Git origin name is user declared; source is pinned local objects, not an OH product build.",
            "No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.",
        ],
    }
    if plan is not None:
        report["audit_plan"] = plan
        report["plan_execution"] = {
            "plan_sha256": plan["plan_sha256"],
            "detectors": [{"id": result.tool, "version": result.tool_version,
                           "status": result.status} for result in reports],
        }
    for archive in inventory.get("source_archives", []):
        if archive.get("status") != "indexed" or archive.get("skipped"):
            report["limitations"].append(
                f"Source archive {archive['archive']} has partial/unsupported member coverage; inspect scope.source_archives."
            )
    if report["files_in_scope_without_a_claiming_detector"]:
        report["status"] = "completed_with_limitations"
        report["limitations"].append(
            "Some indexed source files have no claiming detector; their security analysis is unknown."
        )
    phase_metrics["detector_execution_seconds"] = sum(
        float(result.elapsed_seconds or 0.0) for result in reports
    )
    phase_metrics["report_build_seconds"] = perf_counter() - report_build_started
    phase_metrics["report_build_cpu_seconds"] = process_time() - report_build_cpu_started
    phase_metrics["process_cpu_seconds"] = process_time() - cpu_started
    phase_metrics["analysis_wall_seconds"] = perf_counter() - wall_started
    phase_metrics["peak_rss_bytes"] = None
    phase_metrics["peak_rss_status"] = "unknown; measured externally by perf_scale_scan.py when available"
    report["performance"] = phase_metrics
    if incremental_plan is not None:
        cache_stats = phase_metrics.get("detector_result_cache", {})
        cache_hits = int(cache_stats.get("hits", 0))
        incremental_plan["detector_result_cache"] = cache_stats
        incremental_plan["execution"] = (
            "full_source_index_with_verified_per_file_result_reuse" if cache_hits
            else "full_scan_required"
        )
        if cache_hits:
            incremental_plan["fallback_reason"] = "cross_file_dependency_reuse_unproven; declared_source_blob_results_reused"
        incremental_plan["reused_files"] = len(cache_stats.get("hit_paths", ()))
        incremental_plan["reused_detector_results"] = cache_hits
        incremental_plan["recomputed_detector_results"] = int(cache_stats.get("misses", 0)) + int(
            cache_stats.get("bypassed", 0))
        report["incremental"] = incremental_plan
        report["limitations"].append(
            "Incremental mode preserves full source indexing. Only explicitly opted-in single-Blob detector results may be reused; cross-file dependency reuse remains disabled."
        )
    return report


def run_fixed_commit_scan(
    repo_dir: Path,
    repository: str,
    commit: str,
    includes: tuple[str, ...],
    detector_ids: tuple[str, ...],
    json_out: Path,
    md_out: Path,
    *,
    allow_examples=False,
    expected_plan=None,
    ast_cache_dir=None,
    ast_cache_max_bytes=512 * 1024 * 1024,
    clear_ast_cache=False,
    base_commit=None,
    detector_result_cache_dir=None,
    detector_checkpoint_dir=None,
    detector_checkpoint_engine_sha256=None,
):
    if json_out.resolve() == md_out.resolve():
        raise ValueError("JSON and Markdown output paths must differ")
    registry = build_registry(default_detector_ids() if detector_ids is None else detector_ids,
                              allow_examples=allow_examples)
    selection = expected_plan["requested_detector_ids"] if expected_plan is not None else (
        None if detector_ids is None else tuple(detector_ids))
    report = run_reviewed_detectors(
        repo_dir, repository, commit, includes, registry,
        planning_selection=False if allow_examples else selection, expected_plan=expected_plan,
        ast_cache_dir=ast_cache_dir, ast_cache_max_bytes=ast_cache_max_bytes,
        clear_ast_cache=clear_ast_cache, base_commit=base_commit,
        detector_result_cache_dir=detector_result_cache_dir,
        detector_checkpoint_dir=detector_checkpoint_dir,
        detector_checkpoint_engine_sha256=detector_checkpoint_engine_sha256)

    render_started = perf_counter()
    render_cpu_started = process_time()
    lines = [
        "# OHScanner M2 reviewed-detector execution",
        "",
        "> Detection candidates and coverage limitations, NOT validated vulnerabilities.",
        "",
        f"- Source repository (declared): `{report['repository']}`",
        f"- Pinned commit: `{report['commit']}`",
        f"- Git tree: `{report['git_tree']}`",
        f"- Snapshot SHA-256: `{report['snapshot_sha256']}`",
        f"- Source files indexed: {report['scope']['selected_source_files']}",
        f"- Parsing coverage: `{json.dumps(report['source_parsing']['parsing_status'], sort_keys=True)}`",
        f"- Detector runs: {report['detector_count']}",
        f"- Total unverified diagnostics: {report['diagnostic_count']}",
        f"- Validated vulnerabilities: **0** (no runtime verification performed)",
        "",
        "## Per-detector results",
        "",
        "| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for result in report["detector_runs"]:
        coverage = report["detector_coverage"]["detectors"][result["tool"]]
        lines.append(
            f"| `{result['tool']}` | {result['status']} | "
            f"{result['scope_files']} | {len(coverage['analyzed_files'])} | "
            f"{len(coverage['partially_inspected_files'])} | {len(coverage['not_analyzed_files'])} | "
            f"{result['diagnostic_count']} | "
            f"{coverage['status']} |"
        )
    lines.extend([
        "", "## Candidate evidence and missing proof",
        "", "| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |",
        "|---|---|---|---|---|",
    ])
    for result in report["detector_runs"]:
        proof = {
            item["diagnostic_id"]: item["obligations"]
            for item in report["detector_coverage"]["detectors"][result["tool"]]["evidence_obligations"]
        }
        for diag in result["diagnostics"]:
            obligations = proof.get(diag["diagnostic_id"], ())
            detail = "; ".join(o["kind"] + "=" + o["status"] for o in obligations) or "not recorded"
            lines.append(
                f"| `{result['tool']}` | `{diag['diagnostic_id']}` | "
                f"`{diag['file']}:{diag['line']}` | `{diag['rule_id']}` | {detail} |"
            )
    if not report["diagnostic_count"]:
        lines.append("| — | — | — | — | No reported candidate; NOT proof of safety |")
    lines.extend(["", "## Coverage gaps", ""])
    lines.append("Scope counts source inspection, not complete semantic coverage; partial remains unknown.")
    lines.append(
        "Files without a claiming detector: "
        + str(len(report["files_in_scope_without_a_claiming_detector"]))
    )
    lines.extend("- `" + path + "`" for path in report["files_in_scope_without_a_claiming_detector"])
    for detector, info in report["detector_coverage"]["detectors"].items():
        lines.append(
            f"- `{detector}`: {info['status']}, "
            f"{len(info['analyzed_files'])}/{info['applicable_files']} applicable files examined;"
            f" unexamined={len(info['unexamined'])}"
        )
    lines.extend(["", "## Limitations", ""])
    if report.get("incremental"):
        incremental = report["incremental"]
        lines.extend([
            "## Incremental planning",
            "",
            f"- Base commit: `{incremental['base_commit']}`; changed paths: {incremental['changed_path_count']}",
            f"- Execution: `{incremental['execution']}`; fallback reason: `{incremental['fallback_reason']}`",
            f"- Reused source files: {incremental.get('reused_files', 0)}; reused detector results: {incremental.get('reused_detector_results', 0)}; cache-eligible recomputations/bypasses: {incremental.get('recomputed_detector_results', 0)}. Full head source inventory and uncacheable detectors still ran.",
            "",
        ])
    lines.extend(["- " + item for item in report["limitations"]])
    for result in report["detector_runs"]:
        for limitation in result["limitations"]:
            lines.append(f"- `{result['tool']}`: {limitation}")
    lines.append("")
    report["performance"]["report_render_seconds"] = perf_counter() - render_started
    report["performance"]["report_render_cpu_seconds"] = process_time() - render_cpu_started

    if "audit_plan" in report:
        plan = report["audit_plan"]
        lines.extend(["## Frozen execution plan", "",
                      f"- Planner: {plan['planner_version']}; mode: {plan['selection_mode']}",
                      f"- Plan SHA-256: `{plan['plan_sha256']}`",
                      "- Language matching plans attempts; actual coverage remains in the results above.", ""])
    # Source data and scanner output are only written after successful
    # re-verification of the fixed commit's Git blob inventory.
    json_out.parent.mkdir(parents=True, exist_ok=True)
    md_out.parent.mkdir(parents=True, exist_ok=True)
    write_report_json(report, json_out)
    md_out.write_text("\n".join(lines), encoding="utf-8")
    return report

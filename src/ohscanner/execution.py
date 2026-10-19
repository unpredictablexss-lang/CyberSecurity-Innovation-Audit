"""M2: run reviewed first-party detectors on pinned local Git sources.

Emits reproducible source scope and per-detector coverage/evidence obligations.
A zero-diagnostic result cannot imply safety. No external analyzer invocation.
"""
from datetime import datetime, timezone
import json
from pathlib import Path

from .detectors.catalog import build_registry, default_detector_ids
from .git_source import load_git_sources
from .indexing import environment_fingerprint, prepare_git_context
from .runner import run_all_with_coverage



MAX_REPORT_BYTES = 64 * 1024 * 1024


def write_report_json(report, path):
    data = (json.dumps(report, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("Report exceeds 64 MiB publication budget; narrow the scope or select fewer rules. No complete result was published; analysis remains unknown.")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def run_reviewed_detectors(
    repo_dir: Path,
    repository: str,
    commit: str,
    includes: tuple[str, ...],
    registry,
    *, planning_selection=False, expected_plan=None,
):
    """Programmatic extension point: callers supply an explicitly reviewed registry.

    Actual detector plugins may be integrated only after code review. Does not
    support untrusted arbitrary imports or invoke subprocess scanners.
    """
    if not registry.detectors():
        raise ValueError("at least one reviewed detector is required")
    context, tree, inventory, parsing, sources = prepare_git_context(
        repo_dir, repository, commit, includes
    )
    plan = None
    if planning_selection is not False:
        from .planning import plan_context
        plan = plan_context(context, tree, inventory, sources, planning_selection)
        if expected_plan is not None and plan != expected_plan:
            raise ValueError("Frozen audit plan drifted; no scan result published")
        if planning_selection is None:
            if not plan["suggested_detector_ids"]:
                raise ValueError("No applicable approved detector; analysis remains unknown")
            registry = build_registry(tuple(plan["suggested_detector_ids"]))
    reports, sidecar = run_all_with_coverage(context, registry)

    # Independently re-read the same immutable objects. Do not claim the scan
    # succeeded when the local object store changes during execution.
    commit2, tree2, sources2, inventory2 = load_git_sources(repo_dir, commit, includes)
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
):
    if json_out.resolve() == md_out.resolve():
        raise ValueError("JSON and Markdown output paths must differ")
    registry = build_registry(default_detector_ids() if detector_ids is None else detector_ids,
                              allow_examples=allow_examples)
    selection = expected_plan["requested_detector_ids"] if expected_plan is not None else (
        None if detector_ids is None else tuple(detector_ids))
    report = run_reviewed_detectors(
        repo_dir, repository, commit, includes, registry,
        planning_selection=False if allow_examples else selection, expected_plan=expected_plan)

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
    lines.extend(["- " + item for item in report["limitations"]])
    for result in report["detector_runs"]:
        for limitation in result["limitations"]:
            lines.append(f"- `{result['tool']}`: {limitation}")
    lines.append("")

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

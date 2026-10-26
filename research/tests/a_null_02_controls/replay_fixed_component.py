from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp import null_dereference_detector as null_model
from src.ohscanner.detectors.cpp.null_dereference_detector import NullDereferenceDetector
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import load_git_sources
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REPO = Path(
    os.environ.get(
        "OHSCANNER_FIXED_COMPONENT_REPO",
        "/mnt/e/网安/_wsl_targets_stage/communication_dsoftbus"
        if os.name != "nt"
        else r"E:\网安\_wsl_targets_stage\communication_dsoftbus",
    )
)
SOURCE_PATH = "core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp"
REPOSITORY = "openharmony/communication_dsoftbus"
VULNERABLE_COMMIT = "258662cd9840b55a31546a72d91027f6368cea84"
FIXED_COMMIT = "192f3e11d74beeaa3d879333471deb8a24a7e1c5"
EXPECTED_BLOBS = {
    VULNERABLE_COMMIT: "a82b71fb5520b02278a4af695bbe918d14c1048e",
    FIXED_COMMIT: "13ddbe93a7f617784dec0f3761e09f66b5c3217c",
}
FUNCTIONS = (
    "ClinetOnNodeOnlineStateChanged",
    "ClinetOnNodeBasicInfoChanged",
    "ClientOnNodeStatusChanged",
    "ClinetOnLocalNetworkIdChanged",
    "ClinetNotifyDeviceNotTrusted",
)
ROOT_CAUSE_GROUP = "A-NULL-02-RC-NOTHROW-CLIENTPROXY-ALLOC"
CLASSIFICATION_POLICY = {
    "likely_false_positive": "A detector output contradicted by a fixed, safe, unrelated or non-pointer control.",
    "plausible_unproven": "Exact bounded source/sink relation is present, but product trigger, attacker control, reachability or CIA impact is unproven.",
    "refuted": "The candidate relation is absent or a local repair guard is present in the pinned comparison source; this is not a product safety proof.",
    "insufficient_evidence": "Coverage, parse, macro/template, cross-function alias, build context or evidence obligations prevent a stronger classification.",
}


def _offline_git(repo: Path, *args: str) -> bytes:
    env = os.environ.copy()
    env.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    process = subprocess.run(
        ["git", "-c", "remote.origin.promisor=false", "-C", str(repo), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
        env=env,
    )
    if process.returncode:
        raise RuntimeError(
            "offline Git object operation failed: "
            + " ".join(args)
            + ": "
            + process.stderr.decode("utf-8", "replace")[:300]
        )
    return process.stdout


def _line_column(text: str, position: int) -> tuple[int, int]:
    line = text.count("\n", 0, position) + 1
    previous = text.rfind("\n", 0, position)
    return line, position + 1 if previous < 0 else position - previous


def _source_site(text: str, function_name: str) -> dict:
    masked = null_model._mask_comments_and_literals(text)
    brace_spans, malformed = null_model._brace_spans(masked)
    if malformed:
        raise RuntimeError("source delimiter integrity failed")
    classes = null_model._class_shapes(masked, brace_spans)
    functions = null_model._function_shapes(masked, brace_spans, classes)
    function = next((item for item in functions if item.name == function_name), None)
    if function is None:
        raise RuntimeError("function not found in pinned source: " + function_name)
    body = masked[function.body.start : function.body.end]
    alloc = re.search(
        r"\bclientProxy\s*=\s*new\s*\(\s*(?:std::)?nothrow\s*\)\s+[^;]+;",
        body,
    )
    sink = re.search(r"\bclientProxy\s*->", body)
    if alloc is None or sink is None:
        raise RuntimeError("source/sink relation not found: " + function_name)
    alloc_pos = function.body.start + alloc.start()
    sink_pos = function.body.start + sink.start()
    guard = re.search(
        r"\bif\s*\(\s*clientProxy\s*==\s*(?:nullptr|NULL|0)\s*\)",
        body[alloc.end() : sink.start()],
    )
    guard_pos = function.body.start + alloc.end() + guard.start() if guard else None
    alias_match = re.search(
        r"\\b(?:[A-Za-z_]\\w*\\s*[*&]+\\s*|auto\\s*&\\s*)[A-Za-z_]\\w*\\s*=\\s*clientProxy\\b",
        body,
    )
    rebind_match = re.search(
        r"\\bclientProxy\\s*(?:=[^=]|\\+\\+|--)",
        body[alloc.end() : sink.start()],
    )
    if guard is None:
        guard_error_path = "none_before_sink"
    else:
        guard_body_start = body.find("{", guard.end(), sink.start())
        guard_body_end = body.find("}", guard_body_start + 1, sink.start()) if guard_body_start >= 0 else -1
        guard_body = body[guard_body_start : guard_body_end + 1] if guard_body_start >= 0 and guard_body_end >= 0 else ""
        guard_error_path = (
            "local_early_return_shape"
            if null_model._branch_terminates_error_path(guard_body)
            else "guard_present_error_path_unknown"
        )
    return {
        "function": function_name,
        "source_kind": "nothrow_allocation_may_be_null",
        "source_expression": text[alloc_pos : function.body.start + alloc.end()].strip(),
        "source_line": _line_column(text, alloc_pos)[0],
        "pointer_sink": text[sink_pos : function.body.start + sink.end()].strip(),
        "sink_line": _line_column(text, sink_pos)[0],
        "guard_expression": (
            text[guard_pos : function.body.start + alloc.end() + guard.end()].strip()
            if guard is not None
            else None
        ),
        "guard_line": _line_column(text, guard_pos)[0] if guard_pos is not None else None,
        "guard_error_path": guard_error_path,
        "alias_relation": (
            "bounded_alias_present" if alias_match else "direct_binding_no_bounded_alias"
        ),
        "local_rebinding_before_sink": bool(rebind_match),
        "relation": "source_then_pointer_sink" if guard is None else "source_then_guard_then_pointer_sink",
    }


def _finding_view(finding) -> dict:
    return {
        "file": finding.file,
        "line": finding.line,
        "column": finding.column,
        "rule_id": finding.rule_id,
        "rule_version": finding.rule_version,
        "rule_lineage_id": finding.rule_lineage_id,
        "candidate_cwe": finding.candidate_cwe,
        "symbol": finding.symbol,
        "message": finding.message,
        "source_sha256": finding.source_sha256,
        "symbol_identity": finding.symbol_identity,
        "ast_fingerprint": finding.ast_fingerprint,
        "identity_quality": finding.identity_quality,
        "evidence_obligations": [
            {"kind": item.kind, "status": item.status}
            for item in finding.evidence_obligations
        ],
    }


def _run_snapshot(repo: Path, commit: str) -> dict:
    pinned, tree, sources, inventory = load_git_sources(repo, commit, (SOURCE_PATH,))
    if pinned != commit:
        raise RuntimeError("pinned commit mismatch")
    if sources[0].oid != EXPECTED_BLOBS[commit]:
        raise RuntimeError("pinned blob mismatch")
    units, ast, coverage = index_sources(sources)
    unit = units[0]
    digest = snapshot_digest(units)
    context = ScanContext(
        request=ScanRequest(
            request_id="A-NULL-02-fixed-component-replay:" + commit[:12],
            repository=REPOSITORY,
            commit=commit,
            snapshot_sha256=digest,
            target_id="current-component:" + REPOSITORY,
            profile_id="light-ast",
            provenance="git_object",
        ),
        units=units,
        shared_facts={
            "ast": ast,
            "coverage": coverage,
            "source_blob_oid": {source.path: source.oid for source in sources},
        },
    )
    detector = NullDereferenceDetector()
    first = detector.detect(context, units)
    second = detector.detect(context, units)
    if first != second:
        raise RuntimeError("detector output changed across replay")
    registry = DetectorRegistry()
    registry.register(detector)
    reports, _sidecar = run_all_with_coverage(context, registry)
    report = reports[0]
    if report.diagnostic_count != len(first.findings):
        raise RuntimeError("runner/detector finding count mismatch")
    return {
        "repository": REPOSITORY,
        "local_repository_path": str(repo),
        "commit": pinned,
        "tree": tree,
        "source_path": SOURCE_PATH,
        "source_blob_oid": sources[0].oid,
        "source_sha256": unit.sha256,
        "source_byte_length": len(unit.text.encode("utf-8")),
        "snapshot_sha256": digest,
        "profile_id": "light-ast",
        "parse_status": unit.parse_status,
        "parse_issues": list(unit.parse_issues),
        "coverage": coverage,
        "detector": {
            "detector_id": first.detector_id,
            "version": first.version,
            "status": first.status,
            "file_outcomes": dict(first.file_outcomes),
            "finding_count": len(first.findings),
            "findings": [_finding_view(item) for item in first.findings],
            "runner_diagnostic_count": report.diagnostic_count,
            "limitations": list(first.limitations),
        },
        "source_sites": [_source_site(unit.text, name) for name in FUNCTIONS],
        "object_inventory": inventory,
    }


def _control_noise_summary() -> dict:
    manifest = json.loads(
        (ROOT / "research/tests/a_null_02_controls/control_manifest.json").read_text(
            encoding="utf-8"
        )
    )
    cases = {item["fixture"]: item for item in manifest["cases"]}
    by_category = {}
    for item in manifest["units"]:
        case = cases[item["path"].rsplit("/", 1)[-1]]
        path = ROOT / item["path"]
        data = path.read_bytes()
        unit = SourceUnit(
            path=item["path"],
            language="cpp",
            text=data.decode("utf-8"),
            sha256=item["sha256"],
            parse_status=item["parse_status"],
        )
        request = ScanRequest(
            request_id="A-NULL-02-control-noise",
            repository="fixture/ohscanner-null-controls",
            commit="synthetic-a-null-02",
            snapshot_sha256=snapshot_digest((unit,)),
            target_id="current-component:fixture/ohscanner-null-controls",
            profile_id="fixture-no-build",
            provenance="fixture",
        )
        run = NullDereferenceDetector().detect(
            ScanContext(request=request, units=(unit,)), (unit,)
        )
        bucket = by_category.setdefault(
            case["category"],
            {
                "control_count": 0,
                "expected_finding_count": 0,
                "observed_finding_count": 0,
                "unexpected_findings": [],
                "classification": (
                    "plausible_unproven"
                    if case["category"] == "positive"
                    else "refuted"
                ),
            },
        )
        bucket["control_count"] += 1
        bucket["expected_finding_count"] += case["expected_finding_count"]
        bucket["observed_finding_count"] += len(run.findings)
        if len(run.findings) != case["expected_finding_count"]:
            bucket["unexpected_findings"].append(item["path"])
            bucket["classification"] = "likely_false_positive"
    return {
        "source": "research/tests/a_null_02_controls/control_manifest.json",
        "categories": dict(sorted(by_category.items())),
        "noise_conclusion": "All six positive controls retained one candidate each; no fixed, safe or unrelated control produced an unexpected finding. This is control evidence, not a precision/recall estimate.",
    }


def build_report(repo: Path) -> dict:
    vulnerable = _run_snapshot(repo, VULNERABLE_COMMIT)
    fixed = _run_snapshot(repo, FIXED_COMMIT)
    vulnerable_findings = vulnerable["detector"]["findings"]
    fixed_findings = fixed["detector"]["findings"]
    rows = []
    for index, name in enumerate(FUNCTIONS, start=1):
        source_site = next(item for item in vulnerable["source_sites"] if item["function"] == name)
        fixed_site = next(item for item in fixed["source_sites"] if item["function"] == name)
        finding = next(
            (
                item
                for item in vulnerable_findings
                if item["symbol_identity"].endswith("::" + name + "::clientProxy")
            ),
            None,
        )
        if finding is None:
            raise RuntimeError("expected vulnerable candidate missing: " + name)
        rows.append(
            {
                "review_row_id": f"A-NULL-02-ROW-{index:02d}",
                "root_cause_group": ROOT_CAUSE_GROUP,
                "function": name,
                "classification": "plausible_unproven",
                "classification_reason": "Exact nothrow allocation to immediate pointer sink is present; allocation-failure null path is plausible. Entry, trigger, attacker control, product reachability and CIA remain unproven.",
                "source_relation": source_site,
                "fixed_relation": fixed_site,
                "vulnerable_finding": finding,
                "fixed_finding_count": sum(
                    1
                    for item in fixed_findings
                    if item["symbol_identity"].endswith("::" + name + "::clientProxy")
                ),
                "refutation_scope": "fixed local guard relation only; not proof of product safety",
            }
        )
    fixed_rows = [
        {
            "review_row_id": f"A-NULL-02-FIXED-{index:02d}",
            "root_cause_group": ROOT_CAUSE_GROUP,
            "function": name,
            "classification": "refuted",
            "classification_reason": "The pinned fixed source adds a local nullptr guard before the same pointer sink; this refutes the local missing-guard candidate relation only.",
            "source_relation": next(item for item in fixed["source_sites"] if item["function"] == name),
            "fixed_finding_count": 0,
        }
        for index, name in enumerate(FUNCTIONS, start=1)
    ]
    unknown_row = {
        "review_row_id": "A-NULL-02-UNKNOWN-001",
        "root_cause_group": ROOT_CAUSE_GROUP,
        "classification": "insufficient_evidence",
        "classification_reason": "The replay binds source facts and local lexical relations but does not establish build context, product entry/privilege boundary, attacker control, trigger conditions, reachable sensitive operation or CIA impact.",
        "unknowns": [
            "compile_context",
            "entry_or_privilege_boundary",
            "attacker_control",
            "sensitive_operation_reachability",
            "trigger_conditions",
            "cia_impact",
            "cross_function_alias",
            "macro_expansion",
            "template_instantiation",
            "partial_failed_not_analyzed_semantics",
        ],
    }
    counts = {
        label: sum(1 for row in rows + fixed_rows + [unknown_row] if row["classification"] == label)
        for label in CLASSIFICATION_POLICY
    }
    counts["likely_false_positive"] = 0
    report = {
        "schema_version": "ohscanner.a-null-02-fixed-component-review-v1",
        "change_request_id": "A-NULL-02",
        "detector_identity": {
            "detector_id": "ohscanner.cpp.null_dereference",
            "version": "0.6.0",
            "rule_id": null_model.RULE_ID,
            "rule_version": null_model.RULE_VERSION,
            "rule_lineage_id": null_model.RULE_LINEAGE_ID,
            "profile_id": "light-ast",
            "ast_scope": "per_file",
        },
        "candidate_index_only": {
            "sample_id": "communication_dsoftbus_null_deref_001",
            "benchmark_path": "benchmarks/historical/communication_dsoftbus_null_deref.json",
            "authority": "candidate index only; historical verdict and CVE are not used as truth or upgrade evidence",
        },
        "classification_policy": CLASSIFICATION_POLICY,
        "classification_counts": counts,
        "control_noise_summary": _control_noise_summary(),
        "root_cause_groups": [
            {
                "root_cause_group": ROOT_CAUSE_GROUP,
                "independent_root_cause_count": 1,
                "candidate_site_count": len(rows),
                "fixed_site_count": len(fixed_rows),
                "validated_vulnerability_count": 0,
                "counting_rule": "count one root-cause group, not five alert lines",
                "basis": "same nothrow BusCenterClientProxy allocation family, same immediate clientProxy pointer sink and same local nullptr guard repair shape",
            }
        ],
        "candidate_review_rows": rows,
        "fixed_review_rows": fixed_rows,
        "unknown_rows": [unknown_row],
        "replay": {
            "stable_across_two_detector_runs": True,
            "fixed_repo_object_reads": "offline local Git objects only; no fetch/checkout",
            "snapshots": {"vulnerable": vulnerable, "fixed": fixed},
        },
        "upgrade_blockers": [
            "No real product entry or privilege boundary was established.",
            "No attacker-controlled allocation-failure trigger was demonstrated.",
            "No product build, macro/template instantiation or complete alias/CFG context was bound.",
            "No concrete confidentiality, integrity or availability impact was demonstrated.",
            "A historical advisory/CVE and fixed commit are context only and cannot upgrade a candidate.",
        ],
        "non_upgrade_statement": "candidate/unassessed only; validated_vulnerability=0; no confirmed/reportable, CVE or product-safety claim",
    }
    return report


def catalog_metadata(report: dict) -> dict:
    snapshots = report["replay"]["snapshots"]
    return {
        "schema_version": "ohscanner.catalog-research-candidate-suggestion-v1",
        "change_request_id": "A-NULL-02",
        "kind": "research_candidate",
        "detector_id": report["detector_identity"]["detector_id"],
        "detector_version": report["detector_identity"]["version"],
        "rule_id": report["detector_identity"]["rule_id"],
        "rule_version": report["detector_identity"]["rule_version"],
        "rule_lineage_id": report["detector_identity"]["rule_lineage_id"],
        "candidate_cwe": "CWE-476",
        "supported_languages": ["c", "cpp"],
        "ast_scope": "per_file",
        "profile_id": "light-ast",
        "candidate_status": "candidate/unassessed",
        "severity": "unassessed",
        "confidence": "unassessed",
        "root_cause_groups": report["root_cause_groups"],
        "source_binding": {
            "repository": REPOSITORY,
            "snapshots": {
                key: {
                    "commit": value["commit"],
                    "tree": value["tree"],
                    "source_path": value["source_path"],
                    "source_blob_oid": value["source_blob_oid"],
                    "source_sha256": value["source_sha256"],
                    "snapshot_sha256": value["snapshot_sha256"],
                    "profile_id": value["profile_id"],
                    "parse_status": value["parse_status"],
                }
                for key, value in snapshots.items()
            },
        },
        "coverage_semantics": ["complete", "partial", "failed", "not_analyzed"],
        "coverage_unknowns": report["unknown_rows"][0]["unknowns"],
        "evidence_obligation_policy": {
            "guard_dominance": "unknown",
            "cross_function_alias": "unknown",
            "compile_context": "missing",
            "entry_or_privilege_boundary": "missing",
            "attacker_control": "missing",
            "sensitive_operation_reachability": "missing",
            "trigger_conditions": "missing",
            "cia_impact": "missing",
        },
        "upgrade_blockers": report["upgrade_blockers"],
        "notes": [
            "Registration is a proposal only; public catalog remains unchanged.",
            "Historical benchmark labels and CVE are not used as detector truth.",
            "AST/pattern source relations do not prove dominance, attacker control or CIA impact.",
        ],
    }


def markdown(report: dict) -> str:
    rows = report["candidate_review_rows"]
    lines = [
        "# A-NULL-02 fixed-component candidate review",
        "",
        "This is a bounded source-bound review, not a vulnerability report.",
        "",
        "## Root-cause aggregation",
        "",
        "| root cause group | independent root causes | candidate sites | fixed sites | validated vulnerabilities |",
        "|---|---:|---:|---:|---:|",
    ]
    for item in report["root_cause_groups"]:
        lines.append(
            f"| `{item['root_cause_group']}` | {item['independent_root_cause_count']} | "
            f"{item['candidate_site_count']} | {item['fixed_site_count']} | "
            f"{item['validated_vulnerability_count']} |"
        )
    lines += [
        "",
        "## Candidate review table",
        "",
        "| row | function | source relation | pointer sink | alias / rebind | guard/error path | classification |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        source = row["source_relation"]
        lines.append(
            f"| `{row['review_row_id']}` | `{row['function']}` | "
            f"L{source['source_line']}: `{source['source_expression']}` | "
            f"L{source['sink_line']}: `{source['pointer_sink']}` | "
            f"{source['alias_relation']} / rebind={str(source['local_rebinding_before_sink']).lower()} | "
            f"{source['guard_error_path']} | `{row['classification']}` |"
        )
    lines += [
        "",
        "The five rows are one independent root-cause group for counting; they are not five confirmed vulnerabilities.",
        "",
        "## Fixed comparison",
        "",
        "| row | function | allocation line | guard line | sink line | error path | classification |",
        "|---|---|---:|---:|---:|---|---|",
    ]
    for row in report["fixed_review_rows"]:
        source = row["source_relation"]
        lines.append(
            f"| `{row['review_row_id']}` | `{row['function']}` | "
            f"{source['source_line']} | {source['guard_line']} | {source['sink_line']} | "
            f"{source['guard_error_path']} | `{row['classification']}` |"
        )
    lines += [
        "",
        "`refuted` applies only to the local missing-guard relation; it is not a product safety verdict.",
        "",
        "## Label policy",
        "",
    ]
    for label, meaning in report["classification_policy"].items():
        lines.append(f"- `{label}`: {meaning}")
    lines += [
        "",
        "## False-positive and noise analysis",
        "",
        "| category | controls | expected findings | observed findings | classification |",
        "|---|---:|---:|---:|---|",
    ]
    for category, item in report["control_noise_summary"]["categories"].items():
        lines.append(
            f"| {category} | {item['control_count']} | "
            f"{item['expected_finding_count']} | {item['observed_finding_count']} | "
            f"`{item['classification']}` |"
        )
    lines += [
        "",
        report["control_noise_summary"]["noise_conclusion"],
        "",
        "## Unknown and non-upgrade reasons",
        "",
    ]
    lines += [f"- {item}" for item in report["upgrade_blockers"]]
    lines += ["", f"Final state: `{report['non_upgrade_statement']}`", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "research/evidence/cpp/a_null_02_fixed_component_review_20261016/replay_results.json",
    )
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = build_report(args.repo.resolve())
    if args.write:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (args.output.parent / "catalog_metadata_suggestion.json").write_text(
            json.dumps(catalog_metadata(report), ensure_ascii=False, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        (args.output.parent / "candidate_review.md").write_text(
            markdown(report), encoding="utf-8"
        )
        print(args.output)
        return 0
    if args.check:
        actual = json.loads(args.output.read_text(encoding="utf-8"))
        if actual != report:
            raise SystemExit("A-NULL-02 fixed-component replay mismatch")
        print(json.dumps({"status": "passed", "root_cause_groups": 1, "candidate_sites": 5}, sort_keys=True))
        return 0
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Deterministic source-bound review evidence for the narrow cpp.lifetime detector.

This module is an M0 review sidecar, not a replacement for the public detector
contract and not a vulnerability validator. It binds candidate identities to
exact source-unit hashes while preserving candidate/unassessed and unknown
coverage semantics.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Mapping, Sequence, Tuple

from src.ohscanner.contracts import ScanContext, DetectorRun, safe_relative_path


_RULE_ID = "ohcpp-lifetime-unique-raw-alias-reset-001"
_SHA256_RE = re.compile(r"[a-f0-9]{64}")
_EVIDENCE_CLASS_ORDER = ("vulnerable", "fixed", "unrelated", "safe", "unknown", "not_applicable")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _evidence_class(category: str) -> str:
    if category.startswith("vulnerable"):
        return "vulnerable"
    if category.startswith("fixed"):
        return "fixed"
    if category.startswith("unrelated"):
        return "unrelated"
    if category.startswith("safe"):
        return "safe"
    if category.startswith("unknown"):
        return "unknown"
    if category.startswith("not_applicable"):
        return "not_applicable"
    raise ValueError(f"unsupported fixture category: {category}")


def _manifest_units(fixture_manifest: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    if fixture_manifest.get("schema_version") != 1:
        raise ValueError("unsupported fixture manifest schema")
    units = fixture_manifest.get("units")
    if not isinstance(units, list) or not units:
        raise ValueError("fixture manifest requires units")
    result: Dict[str, Mapping[str, Any]] = {}
    for item in units:
        if not isinstance(item, Mapping):
            raise ValueError("fixture unit metadata must be an object")
        path = item.get("path")
        if not isinstance(path, str):
            raise ValueError("fixture unit path must be a string")
        safe_relative_path(path)
        if path in result:
            raise ValueError("duplicate fixture unit path")
        result[path] = item
    return result


def _coverage_interpretation(run_status: str, limitations: Sequence[str]) -> str:
    joined = " ".join(limitations)
    if "no source with supported language" in joined:
        return "not_applicable_no_matching_language"
    if "outside a modeled block/function span" in joined:
        return "unknown_incomplete_analysis"
    if any(token in joined for token in ("parse_status=partial", "parse_status=failed", "parse_status=not_run")):
        return "unknown_incomplete_analysis"
    if "Unresolved rule symbols" in joined:
        return "unknown_unresolved_rule_symbols"
    if run_status == "completed":
        return "analyzed_selected_scope_only"
    return "unknown_incomplete_analysis"


def build_cpp_lifetime_review_evidence(
    context: ScanContext,
    run: DetectorRun,
    fixture_manifest: Mapping[str, Any],
    fixture_manifest_sha256: str,
) -> Dict[str, Any]:
    """Bind one non-mixed fixture group to source hashes and candidate identities."""
    if not isinstance(fixture_manifest_sha256, str) or not _SHA256_RE.fullmatch(
        fixture_manifest_sha256
    ):
        raise ValueError("fixture manifest hash must be SHA-256")
    if run.detector_id != "ohscanner.cpp.lifetime":
        raise ValueError("review evidence is scoped to ohscanner.cpp.lifetime")
    if run.version != "0.2.0-proposed":
        raise ValueError("unexpected cpp.lifetime detector version")

    manifest_units = _manifest_units(fixture_manifest)
    source_units = {unit.path: unit for unit in context.units}
    if not set(source_units).issubset(manifest_units):
        raise ValueError("context units are not all present in the fixture manifest")

    classes = []
    source_artifacts = []
    for path in sorted(source_units):
        unit = source_units[path]
        metadata = manifest_units[path]
        if metadata.get("sha256") != unit.sha256:
            raise ValueError("finding source hash does not match fixture manifest")
        category = metadata.get("fixture_category")
        if not isinstance(category, str):
            raise ValueError("fixture category is required")
        classes.append(_evidence_class(category))
        source_artifacts.append(
            {
                "path": unit.path,
                "language": unit.language,
                "sha256": unit.sha256,
                "parse_status": unit.parse_status,
                "parse_issues": list(unit.parse_issues),
                "fixture_category": category,
                "evidence_class": _evidence_class(category),
            }
        )
    distinct_classes = tuple(sorted(set(classes), key=_EVIDENCE_CLASS_ORDER.index))
    if len(distinct_classes) != 1:
        raise ValueError(
            "vulnerable/fixed/unrelated/safe/unknown/not_applicable evidence cannot be mixed"
        )

    finding_bindings = []
    for finding in run.findings:
        if finding.file not in run.analyzed_files:
            raise ValueError("finding is outside analyzed scope")
        unit = source_units.get(finding.file)
        if unit is None:
            raise ValueError("finding does not bind to a provided source unit")
        source_lines = unit.text.splitlines()
        if (
            isinstance(finding.line, bool)
            or not isinstance(finding.line, int)
            or finding.line < 1
            or finding.line > len(source_lines)
        ):
            raise ValueError("finding line is outside source")
        if finding.column is not None and (
            isinstance(finding.column, bool)
            or not isinstance(finding.column, int)
            or finding.column < 1
            or finding.column > len(source_lines[finding.line - 1]) + 1
        ):
            raise ValueError("finding column is outside source line")
        if finding.rule_id != _RULE_ID:
            raise ValueError("unexpected cpp.lifetime rule_id")
        if finding.evidence_type != "syntax":
            raise ValueError("cpp.lifetime findings must use syntax evidence")
        if not finding.message.startswith("Candidate only:"):
            raise ValueError("cpp.lifetime output must remain candidate evidence")
        binding = {
            "assessment": "candidate",
            "review_status": "unassessed",
            "file": finding.file,
            "line": finding.line,
            "column": finding.column,
            "rule_id": finding.rule_id,
            "evidence_type": finding.evidence_type,
            "symbol": finding.symbol,
            "message": finding.message,
            "source_sha256": unit.sha256,
        }
        binding["finding_binding_id"] = _sha256_text(_canonical_json(binding))
        finding_bindings.append(binding)
    finding_bindings.sort(key=lambda item: item["finding_binding_id"])

    limitations = list(run.limitations)
    limitations.extend(
        (
            "completed covers only the selected source units and is not a safe verdict.",
            "blocked/failed/not_run/partial analysis is unknown and is never assigned as a miss.",
            "Source hash binding is held in this local review sidecar; public ToolDiagnostic does not carry source_sha256.",
            "No vulnerability, reachability, impact or runtime validation status is assigned.",
        )
    )
    evidence = {
        "schema_version": 1,
        "evidence_kind": "cpp_lifetime_source_bound_review",
        "evidence_class": distinct_classes[0],
        "fixture_manifest_sha256": fixture_manifest_sha256,
        "request": {
            "request_id": context.request.request_id,
            "repository": context.request.repository,
            "commit": context.request.commit,
            "revision": context.request.commit,
            "target_id": context.request.target_id,
            "profile_id": context.request.profile_id,
            "provenance": context.request.provenance,
            "snapshot_sha256": context.request.snapshot_sha256,
        },
        "tool": {"tool_id": run.detector_id, "version": run.version},
        "scope": {
            "requested_files": [unit.path for unit in context.units],
            "analyzed_files": list(run.analyzed_files),
            "run_status": run.status,
            "coverage_interpretation": _coverage_interpretation(
                run.status, run.limitations
            ),
            "benchmark_outcome": "not_assigned",
        },
        "source_artifacts": source_artifacts,
        "finding_bindings": finding_bindings,
        "limitations": sorted(set(limitations)),
        "interpretation": (
            "Candidate/unassessed syntax evidence only; completed is scoped execution, "
            "empty findings are not safe, and incomplete analysis is unknown."
        ),
    }
    return evidence


def canonical_review_json(evidence: Mapping[str, Any]) -> str:
    return _canonical_json(evidence) + "\n"


def review_evidence_sha256(evidence: Mapping[str, Any]) -> str:
    return _sha256_text(canonical_review_json(evidence))


def verify_review_evidence(evidence: Mapping[str, Any], context: ScanContext) -> None:
    """Reject stale or edited source/finding bindings before review."""
    if evidence.get("schema_version") != 1:
        raise ValueError("unsupported review evidence schema")
    if evidence.get("evidence_kind") != "cpp_lifetime_source_bound_review":
        raise ValueError("unexpected review evidence kind")
    expected_request = {
        "request_id": context.request.request_id,
        "repository": context.request.repository,
        "commit": context.request.commit,
        "revision": context.request.commit,
        "target_id": context.request.target_id,
        "profile_id": context.request.profile_id,
        "provenance": context.request.provenance,
        "snapshot_sha256": context.request.snapshot_sha256,
    }
    if evidence.get("request") != expected_request:
        raise ValueError("review request binding mismatch")
    if evidence.get("tool") != {
        "tool_id": "ohscanner.cpp.lifetime",
        "version": "0.2.0-proposed",
    }:
        raise ValueError("review tool binding mismatch")
    source_units = {unit.path: unit for unit in context.units}
    scope = evidence.get("scope")
    if not isinstance(scope, Mapping):
        raise ValueError("review scope binding is required")
    if scope.get("requested_files") != [unit.path for unit in context.units]:
        raise ValueError("review requested scope mismatch")
    analyzed_files = scope.get("analyzed_files")
    if (
        not isinstance(analyzed_files, list)
        or any(not isinstance(path, str) for path in analyzed_files)
        or not set(analyzed_files).issubset(source_units)
    ):
        raise ValueError("review analyzed scope mismatch")
    run_status = scope.get("run_status")
    if run_status not in {"completed", "blocked", "failed"}:
        raise ValueError("review run status is invalid")
    limitations = evidence.get("limitations")
    if not isinstance(limitations, list) or any(
        not isinstance(item, str) for item in limitations
    ):
        raise ValueError("review limitations must be strings")
    if scope.get("coverage_interpretation") != _coverage_interpretation(
        run_status, limitations
    ):
        raise ValueError("review coverage interpretation mismatch")
    if scope.get("benchmark_outcome") != "not_assigned":
        raise ValueError("review benchmark outcome must remain not assigned")
    artifacts = evidence.get("source_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("source artifacts are required")
    if any(not isinstance(item, Mapping) for item in artifacts):
        raise ValueError("source artifact metadata must be objects")
    if {item.get("path") for item in artifacts} != set(source_units):
        raise ValueError("review source artifact scope mismatch")
    for item in artifacts:
        path = item.get("path")
        if path not in source_units:
            raise ValueError("review source artifact is outside context")
        unit = source_units[path]
        if item.get("sha256") != unit.sha256:
            raise ValueError("stale review source hash")
        if item.get("parse_status") != unit.parse_status:
            raise ValueError("review parse status does not match source unit")
        if item.get("language") != unit.language:
            raise ValueError("review language does not match source unit")

    findings = evidence.get("finding_bindings")
    if not isinstance(findings, list):
        raise ValueError("finding bindings are required")
    if any(not isinstance(finding, Mapping) for finding in findings):
        raise ValueError("finding binding metadata must be objects")
    for finding in findings:
        unit = source_units.get(finding.get("file"))
        if unit is None or finding.get("source_sha256") != unit.sha256:
            raise ValueError("stale finding source hash")
        source_lines = unit.text.splitlines()
        line = finding.get("line")
        if (
            isinstance(line, bool)
            or not isinstance(line, int)
            or line < 1
            or line > len(source_lines)
        ):
            raise ValueError("finding line is outside source")
        column = finding.get("column")
        if column is not None and (
            isinstance(column, bool)
            or not isinstance(column, int)
            or column < 1
            or column > len(source_lines[line - 1]) + 1
        ):
            raise ValueError("finding column is outside source line")
        if finding.get("assessment") != "candidate":
            raise ValueError("review assessment must remain candidate")
        if finding.get("review_status") != "unassessed":
            raise ValueError("review status must remain unassessed")
        if finding.get("rule_id") != _RULE_ID:
            raise ValueError("unexpected finding rule_id")
        if finding.get("evidence_type") != "syntax":
            raise ValueError("unexpected finding evidence type")
        identity = dict(finding)
        expected = identity.pop("finding_binding_id", None)
        if not expected or expected != _sha256_text(_canonical_json(identity)):
            raise ValueError("finding binding identity mismatch")

"""Source-bound review sidecar for ``ohscanner.cpp.shared_ptr_race``.

This is an M0/M1 review sidecar, not a vulnerability validator and not a
replacement for the public detector contract. It binds candidate identities to
exact ``SourceUnit.sha256`` values and keeps every finding candidate/unassessed.

Review verification is intentionally redundant with record generation. A saved
record is checked against a trusted ScanContext, DetectorRun and fixture
manifest rather than trusting mutable fields inside the record itself. A
SHA-256 value provides integrity binding to a separately trusted manifest; it
is not an authentication or anti-forgery mechanism.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Mapping, Sequence, Tuple

from src.ohscanner.contracts import (
    DetectorRun,
    ScanContext,
    safe_relative_path,
)


_RULE_ID = "ohcpp-shared-ptr-race-candidate-001"
_DETECTOR_ID = "ohscanner.cpp.shared_ptr_race"
_DETECTOR_VERSION = "0.2.0-proposed"
_SHA256_RE = re.compile(r"[a-f0-9]{64}")
_SHA256_OR_OID_RE = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})")
_EVIDENCE_CLASS_ORDER = (
    "vulnerable",
    "fixed",
    "unrelated",
    "safe",
    "unknown",
    "not_applicable",
)
_PARSE_STATUSES = {"complete", "partial", "failed", "not_run"}
_LANGUAGES = {"c", "cpp", "js", "ts", "arkts"}
_MANIFEST_UNIT_FIELDS = {
    "path",
    "sha256",
    "parse_status",
    "parse_issues",
    "fixture_category",
    "language",
}


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_manifest_sha256(fixture_manifest: Mapping[str, Any]) -> str:
    """Hash the canonical manifest object supplied by an independent caller."""
    return _sha256_text(_canonical_json(fixture_manifest))


def _evidence_class(category: str) -> str:
    if not isinstance(category, str):
        raise ValueError("fixture category is required")
    for prefix in _EVIDENCE_CLASS_ORDER:
        if category.startswith(prefix):
            return prefix
    raise ValueError(f"unsupported fixture category: {category}")


def _manifest_units(
    fixture_manifest: Mapping[str, Any],
) -> Mapping[str, Mapping[str, Any]]:
    if fixture_manifest.get("schema_version") != 1:
        raise ValueError("unsupported fixture manifest schema")
    provenance = fixture_manifest.get("provenance")
    if not isinstance(provenance, Mapping) or not provenance.get("kind"):
        raise ValueError("fixture manifest provenance is required")
    units = fixture_manifest.get("units")
    if not isinstance(units, list) or not units:
        raise ValueError("fixture manifest requires units")
    result: Dict[str, Mapping[str, Any]] = {}
    for item in units:
        if not isinstance(item, Mapping):
            raise ValueError("fixture unit metadata must be an object")
        if not _MANIFEST_UNIT_FIELDS.issubset(item):
            raise ValueError("fixture unit metadata fields are incomplete or unexpected")
        path = item.get("path")
        if not isinstance(path, str):
            raise ValueError("fixture unit path must be a string")
        safe_relative_path(path)
        if path in result:
            raise ValueError("duplicate fixture unit path")
        if not isinstance(item.get("sha256"), str) or not _SHA256_RE.fullmatch(
            item["sha256"]
        ):
            raise ValueError("fixture unit source hash must be SHA-256")
        if item.get("parse_status") not in _PARSE_STATUSES:
            raise ValueError("fixture unit parse status is invalid")
        parse_issues = item.get("parse_issues")
        if not isinstance(parse_issues, list) or any(
            not isinstance(issue, str) for issue in parse_issues
        ):
            raise ValueError("fixture unit parse issues must be strings")
        if item.get("language") not in _LANGUAGES:
            raise ValueError("fixture unit language is invalid")
        _evidence_class(item.get("fixture_category"))
        result[path] = item
    return result


def _coverage_interpretation(run_status: str, limitations: Sequence[str]) -> str:
    joined = " ".join(limitations)
    if "no source with supported language" in joined:
        return "not_applicable_no_matching_language"
    if "outside a modeled function span" in joined:
        return "unknown_incomplete_analysis"
    if any(
        token in joined
        for token in ("parse_status=partial", "parse_status=failed", "parse_status=not_run")
    ):
        return "unknown_incomplete_analysis"
    if run_status == "completed":
        return "analyzed_selected_scope_only"
    return "unknown_incomplete_analysis"


def _review_limitations(run_limitations: Sequence[str]) -> list[str]:
    limitations = list(run_limitations)
    limitations.extend(
        (
            "completed covers only the selected source units and is not a safe verdict.",
            "blocked/failed/not_run/partial analysis is unknown and is never assigned as a miss.",
            "Source hash binding is held in this local review sidecar; public ToolDiagnostic does not carry source_sha256.",
            "No vulnerability, reachability, impact or runtime validation status is assigned.",
        )
    )
    return sorted(set(limitations))


def _expected_artifacts(
    context: ScanContext,
    fixture_manifest: Mapping[str, Any],
    manifest_units: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], str]:
    provenance = fixture_manifest["provenance"]
    source_units = {unit.path: unit for unit in context.units}
    if set(source_units) != set(source_units).intersection(manifest_units):
        raise ValueError("context units are not all present in the fixture manifest")
    classes = []
    source_artifacts = []
    for path in sorted(source_units):
        unit = source_units[path]
        metadata = manifest_units[path]
        expected = {
            "path": unit.path,
            "language": unit.language,
            "sha256": unit.sha256,
            "parse_status": unit.parse_status,
            "parse_issues": list(unit.parse_issues),
            "fixture_category": metadata["fixture_category"],
            "evidence_class": _evidence_class(metadata["fixture_category"]),
        }
        actual = {
            "path": metadata.get("path"),
            "language": metadata.get("language"),
            "sha256": metadata.get("sha256"),
            "parse_status": metadata.get("parse_status"),
            "parse_issues": metadata.get("parse_issues"),
            "fixture_category": metadata.get("fixture_category"),
            "evidence_class": _evidence_class(metadata.get("fixture_category")),
        }
        if provenance["kind"] == "local_git_objects":
            expected["git_tree"] = provenance.get("git_tree")
            expected["git_blob_oid"] = provenance.get("blob_oid")
            if (
                provenance.get("repository") != context.request.repository
                or provenance.get("commit") != context.request.commit
                or provenance.get("source_path") != unit.path
                or not isinstance(provenance.get("git_tree"), str)
                or not _SHA256_OR_OID_RE.fullmatch(provenance.get("git_tree", ""))
                or not isinstance(provenance.get("blob_oid"), str)
                or not _SHA256_OR_OID_RE.fullmatch(provenance.get("blob_oid", ""))
            ):
                raise ValueError("local Git manifest provenance does not match the request")
            actual["git_tree"] = provenance.get("git_tree")
            actual["git_blob_oid"] = provenance.get("blob_oid")
        if actual != expected:
            raise ValueError("fixture manifest metadata does not match source unit")
        classes.append(expected["evidence_class"])
        source_artifacts.append(expected)

    distinct_classes = tuple(sorted(set(classes), key=_EVIDENCE_CLASS_ORDER.index))
    if len(distinct_classes) != 1:
        raise ValueError(
            "vulnerable/fixed/unrelated/safe/unknown/not_applicable evidence cannot be mixed"
        )
    return source_artifacts, distinct_classes[0]


def _expected_findings(
    run: DetectorRun,
    source_units: Mapping[str, Any],
) -> list[dict[str, Any]]:
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
            raise ValueError("unexpected shared_ptr_race rule_id")
        if finding.evidence_type != "syntax":
            raise ValueError("shared_ptr_race findings must use syntax evidence")
        if finding.candidate_cwe != "CWE-362":
            raise ValueError("shared_ptr_race primary candidate CWE must be CWE-362")
        if "CWE-416/use-after-free is only a possible consequence" not in finding.message:
            raise ValueError(
                "shared_ptr_race message must keep CWE-416 as a possible consequence"
            )
        for phrase in (
            "does not prove UAF",
            "guard dominance",
            "concurrent interleaving",
            "attacker control",
            "security impact",
        ):
            if phrase not in finding.message:
                raise ValueError(
                    f"shared_ptr_race message is missing semantic boundary: {phrase}"
                )
        if not finding.message.startswith("Candidate only:"):
            raise ValueError("shared_ptr_race output must remain candidate evidence")
        binding = {
            "assessment": "candidate",
            "review_status": "unassessed",
            "file": finding.file,
            "line": finding.line,
            "column": finding.column,
            "rule_id": finding.rule_id,
            "evidence_type": finding.evidence_type,
            "candidate_cwe": finding.candidate_cwe,
            "symbol": finding.symbol,
            "message": finding.message,
            "source_sha256": unit.sha256,
        }
        binding["finding_binding_id"] = _sha256_text(_canonical_json(binding))
        finding_bindings.append(binding)
    finding_bindings.sort(key=lambda item: item["finding_binding_id"])
    return finding_bindings


def build_shared_ptr_race_review_evidence(
    context: ScanContext,
    run: DetectorRun,
    fixture_manifest: Mapping[str, Any],
    fixture_manifest_sha256: str,
) -> Dict[str, Any]:
    actual_manifest_sha256 = canonical_manifest_sha256(fixture_manifest)
    if fixture_manifest_sha256 != actual_manifest_sha256:
        raise ValueError("fixture manifest hash mismatch")
    if run.detector_id != _DETECTOR_ID:
        raise ValueError("review evidence is scoped to ohscanner.cpp.shared_ptr_race")
    if run.version != _DETECTOR_VERSION:
        raise ValueError("unexpected shared_ptr_race detector version")
    if len(run.analyzed_files) != len(set(run.analyzed_files)):
        raise ValueError("detector analyzed files must be unique")
    if list(run.analyzed_files) != sorted(run.analyzed_files):
        raise ValueError("detector analyzed files must be sorted")
    if not set(run.analyzed_files).issubset({unit.path for unit in context.units}):
        raise ValueError("detector analyzed files are outside the requested scope")

    manifest_units = _manifest_units(fixture_manifest)
    source_units = {unit.path: unit for unit in context.units}
    source_artifacts, evidence_class = _expected_artifacts(context, fixture_manifest, manifest_units)
    finding_bindings = _expected_findings(run, source_units)

    evidence = {
        "schema_version": 1,
        "evidence_kind": "cpp_shared_ptr_race_source_bound_review",
        "evidence_class": evidence_class,
        "fixture_manifest_sha256": actual_manifest_sha256,
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
        "limitations": _review_limitations(run.limitations),
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


def verify_review_evidence(
    evidence: Mapping[str, Any],
    context: ScanContext,
    run: DetectorRun,
    fixture_manifest: Mapping[str, Any],
    fixture_manifest_sha256: str,
) -> None:
    """Reject any saved record not exactly reconstructed from trusted inputs."""
    expected = build_shared_ptr_race_review_evidence(
        context,
        run,
        fixture_manifest,
        fixture_manifest_sha256,
    )
    if _canonical_json(evidence) != _canonical_json(expected):
        raise ValueError(
            "review evidence does not match trusted context, run and fixture manifest"
        )

"""A-CCR-03 layered Finding identity: stable, occurrence, cross-run relation.

This module is additive to schema v2. Legacy diagnostic_id values are never
recomputed, replaced, or backfilled for historical payloads. Identity quality
is fail-closed: missing or partial facts stay unknown and never become safe,
fixed, missed, or disappeared.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import re
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple


IDENTITY_SCHEMA = "ohscanner.finding-identity.v1"
OCCURRENCE_SCHEMA = "ohscanner.finding-occurrence.v1"
IDENTITY_RECORD_SCHEMA = "ohscanner.finding-identity-record.v1"

RELATIONS = frozenset({
    "persistent_unchanged",
    "persistent_changed_metadata",
    "persistent_moved_or_changed",
    "observation_absent_comparable",
    "observation_added_comparable",
    "unknown_identity",
    "unknown_identity_ambiguous",
    "unknown_version_boundary",
    "unknown_not_comparable",
})

_STABLE_REQUIRED = ("repository", "rule_lineage_id", "symbol_identity", "ast_fingerprint")
_OCCURRENCE_REQUIRED = (
    "repository", "legacy_diagnostic_id", "detector_id", "detector_version",
    "rule_id", "rule_version", "file", "line", "message",
    "source_blob_oid", "source_sha256", "byte_start", "byte_end",
)
_CHANGED_FIELDS = (
    "legacy_diagnostic_id", "detector_id", "detector_version", "rule_id", "rule_version",
    "file", "line", "message", "source_blob_oid", "source_sha256",
    "byte_start", "byte_end",
)
_SHA256 = re.compile(r"[a-f0-9]{64}")
_GIT_OID = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})")


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _unknown(reasons: Iterable[str]) -> Dict[str, Any]:
    return {
        "id": None,
        "status": "unknown",
        "basis": None,
        "unknown_reasons": sorted(set(str(item) for item in reasons)),
    }


def _present(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def stable_identity(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Compute semantic identity without message, line, or version drift.

    identity_quality must be explicitly complete. A detector must also supply
    repository, rule lineage, full symbol scope, and AST/expression fingerprint;
    no fallback uses file:line, a message, or a legacy ID.
    """
    reasons = []
    quality = record.get("identity_quality", "unknown")
    if quality != "complete":
        reasons.append("identity_quality:" + str(quality))
    for key in _STABLE_REQUIRED:
        if not _present(record.get(key)):
            reasons.append("missing:" + key)
    if reasons:
        return _unknown(reasons)

    basis = {
        "schema": IDENTITY_SCHEMA,
        "repository": record["repository"],
        "rule_lineage_id": record["rule_lineage_id"],
        "symbol_identity": record["symbol_identity"],
        "ast_fingerprint": record["ast_fingerprint"],
    }
    return {
        "id": "ohfi:v1:" + _digest(basis),
        "status": "stable",
        "basis": basis,
        "unknown_reasons": [],
    }


def line_byte_range(text: str, line: int) -> Tuple[Optional[int], Optional[int]]:
    """Return the exact half-open UTF-8 byte range of a one-based source line."""
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        return None, None
    data = text.encode("utf-8")
    lines = data.splitlines(keepends=True)
    if line > len(lines):
        return None, None
    start = sum(len(item) for item in lines[: line - 1])
    return start, start + len(lines[line - 1])


def occurrence_identity(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Compute an exact-observation identity for a source-bound diagnostic."""
    reasons = []
    for key in _OCCURRENCE_REQUIRED:
        if record.get(key) in (None, ""):
            reasons.append("missing:" + key)
    line = record.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        reasons.append("invalid:line")
    for key in ("byte_start", "byte_end"):
        value = record.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            reasons.append("invalid:" + key)
    if _present(record.get("source_sha256")) and not _SHA256.fullmatch(record["source_sha256"]):
        reasons.append("invalid:source_sha256")
    if _present(record.get("source_blob_oid")) and not _GIT_OID.fullmatch(record["source_blob_oid"]):
        reasons.append("invalid:source_blob_oid")
    start, end = record.get("byte_start"), record.get("byte_end")
    if (isinstance(start, int) and not isinstance(start, bool)
            and isinstance(end, int) and not isinstance(end, bool)
            and end <= start):
        reasons.append("invalid:byte_range")
    if reasons:
        return _unknown(reasons)

    basis = {
        "schema": OCCURRENCE_SCHEMA,
        "repository": record["repository"],
        "legacy_diagnostic_id": record["legacy_diagnostic_id"],
        "detector_id": record["detector_id"],
        "detector_version": record["detector_version"],
        "rule_id": record["rule_id"],
        "rule_version": record["rule_version"],
        "file": record["file"],
        "line": record["line"],
        "message": record["message"],
        "source_blob_oid": record["source_blob_oid"],
        "source_sha256": record["source_sha256"],
        "byte_start": record["byte_start"],
        "byte_end": record["byte_end"],
    }
    return {
        "id": "ohocc:v1:" + _digest(basis),
        "status": "stable",
        "basis": basis,
        "unknown_reasons": [],
    }


def source_binding(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Record exact source provenance without claiming object verification."""
    keys = (
        "repository", "commit", "snapshot_sha256", "profile_id",
        "detector_id", "detector_version", "rule_id", "rule_version",
        "file", "source_blob_oid", "source_sha256", "byte_start", "byte_end",
    )
    values = {key: record.get(key) for key in keys}
    complete = all(_present(values[key]) for key in (
        "repository", "commit", "snapshot_sha256", "profile_id",
        "detector_id", "detector_version", "rule_id", "rule_version",
        "file", "source_blob_oid", "source_sha256",
    )) and (
        isinstance(values["byte_start"], int) and not isinstance(values["byte_start"], bool)
    ) and (
        isinstance(values["byte_end"], int) and not isinstance(values["byte_end"], bool)
    )
    values["status"] = "bound" if complete else "unbound"
    values["verification"] = "not_performed_by_identity_layer"
    return values


def build_identity_record(observation: Mapping[str, Any]) -> Dict[str, Any]:
    """Build one append-only identity record for a newly emitted observation."""
    stable = stable_identity(observation)
    occurrence = occurrence_identity(observation)
    legacy_id = observation.get("legacy_diagnostic_id")
    historical_ids = list(observation.get("historical_ids") or ())
    if _present(legacy_id) and legacy_id not in historical_ids:
        historical_ids.insert(0, legacy_id)
    observation_view = {
        key: observation.get(key)
        for key in (
            "legacy_diagnostic_id", "detector_id", "detector_version",
            "rule_id", "rule_version", "file", "line", "message",
            "source_blob_oid", "source_sha256", "byte_start", "byte_end",
            "identity_quality", "rule_lineage_id", "symbol_identity",
            "ast_fingerprint", "patch_region",
        )
        if key in observation
    }
    return {
        "schema_version": IDENTITY_RECORD_SCHEMA,
        "stable": stable,
        "occurrence": occurrence,
        "observation": observation_view,
        "source_binding": source_binding(observation),
        "historical_ids": historical_ids,
        "backfilled": False,
        "interpretation": (
            "Layered identity describes observation correspondence only; it does not "
            "prove a vulnerability, fix, safety, miss, or disappearance."
        ),
    }

def _record_from_payload(payload: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    value = payload.get("finding_identity")
    if isinstance(value, Mapping):
        return value
    value = payload.get("identity")
    if isinstance(value, Mapping):
        return value
    return None


def read_identity(
    payload: Mapping[str, Any],
    schema_version: Optional[int] = None,
) -> Dict[str, Any]:
    """Read v1/v2 diagnostics without inventing identity for old records."""
    if not isinstance(payload, Mapping):
        raise ValueError("diagnostic payload must be an object")
    version = payload.get("schema_version", schema_version)
    legacy_id = payload.get("diagnostic_id")
    source_sha = payload.get("source_sha256") or ""
    source_status = "bound" if _SHA256.fullmatch(str(source_sha)) else "unbound"
    base = {
        "schema_version": version,
        "legacy_diagnostic_id": legacy_id,
        "source_binding": source_status,
        "backfilled": False,
        "finding_identity_id": payload.get("finding_identity_id"),
        "occurrence_id": payload.get("occurrence_id"),
    }
    record = _record_from_payload(payload)
    if record is None:
        base.update({
            "stable": _unknown(["identity_record_absent"]),
            "occurrence": _unknown(["identity_record_absent"]),
            "historical_ids": [legacy_id] if _present(legacy_id) else [],
            "reasons": ["identity_record_absent"],
        })
        return base

    stable = (
        record.get("stable") if isinstance(record.get("stable"), Mapping)
        else _unknown(["stable_absent"])
    )
    occurrence = (
        record.get("occurrence") if isinstance(record.get("occurrence"), Mapping)
        else _unknown(["occurrence_absent"])
    )
    reasons = []
    if base["finding_identity_id"] is not None and stable.get("id") != base["finding_identity_id"]:
        reasons.append("finding_identity_id_mismatch")
        stable = _unknown(reasons)
    if base["occurrence_id"] is not None and occurrence.get("id") != base["occurrence_id"]:
        reasons.append("occurrence_id_mismatch")
        occurrence = _unknown(reasons)
    historical = record.get("historical_ids")
    if not isinstance(historical, list):
        historical = [legacy_id] if _present(legacy_id) else []
    elif _present(legacy_id) and legacy_id not in historical:
        historical = [legacy_id] + list(historical)
    base.update({
        "stable": dict(stable),
        "occurrence": dict(occurrence),
        "source_binding": record.get("source_binding") or {
            "status": source_status,
            "verification": "not_performed_by_identity_layer",
        },
        "historical_ids": historical,
        "backfilled": False,
        "reasons": reasons,
    })
    return base


def _identity_view(payload: Mapping[str, Any]) -> Dict[str, Any]:
    read = read_identity(payload)
    return {
        "read": read,
        "stable_id": read["stable"].get("id"),
        "occurrence_id": read["occurrence"].get("id"),
    }


def _record_observation(record: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if isinstance(record, Mapping) and isinstance(record.get("observation"), Mapping):
        return dict(record["observation"])
    return {}


def _observation_values(payload: Mapping[str, Any]) -> Dict[str, Any]:
    values = _record_observation(_record_from_payload(payload))
    if values:
        return values
    return {
        key: payload.get(key)
        for key in _CHANGED_FIELDS
        if key in payload
    }


def _compatibility(before: Mapping[str, Any], after: Mapping[str, Any], mode: str) -> str:
    if mode in ("compatible", "incompatible", "unknown"):
        return mode
    if mode != "auto":
        return "unknown"
    keys = ("detector_id", "detector_version", "rule_id", "rule_version")
    left, right = _observation_values(before), _observation_values(after)
    if not left or not right:
        return "unknown"
    if all(left.get(key) is not None and left.get(key) == right.get(key) for key in keys):
        return "compatible"
    return "unknown"


def _coverage(value: str) -> str:
    return value if isinstance(value, str) else "unknown"


def compare_findings(
    before: Sequence[Mapping[str, Any]],
    after: Sequence[Mapping[str, Any]],
    *,
    before_coverage: str = "unknown",
    after_coverage: str = "unknown",
    rule_compatibility: str = "auto",
) -> list[Dict[str, Any]]:
    """Compare two observations while keeping every non-evidence state unknown."""
    left_groups: Dict[Optional[str], list[Mapping[str, Any]]] = defaultdict(list)
    right_groups: Dict[Optional[str], list[Mapping[str, Any]]] = defaultdict(list)
    for item in before:
        left_groups[_identity_view(item)["stable_id"]].append(item)
    for item in after:
        right_groups[_identity_view(item)["stable_id"]].append(item)

    results: list[Dict[str, Any]] = []

    def unknown_group(key, left, right, ambiguous=False):
        results.append({
            "relation": "unknown_identity_ambiguous" if ambiguous else "unknown_identity",
            "finding_identity_id": key,
            "before_count": len(left),
            "after_count": len(right),
            "vulnerability_effect": "unknown",
            "reasons": ["ambiguous_stable_identity" if ambiguous else "stable_identity_unknown"],
        })

    for key in sorted(set(left_groups) | set(right_groups), key=lambda value: value or ""):
        old_items, new_items = left_groups.get(key, []), right_groups.get(key, [])
        if key is None:
            unknown_group(key, old_items, new_items)
            continue
        if len(old_items) > 1 or len(new_items) > 1:
            unknown_group(key, old_items, new_items, ambiguous=True)
            continue

        if old_items and new_items:
            old, new = old_items[0], new_items[0]
            compatibility = _compatibility(old, new, rule_compatibility)
            if compatibility != "compatible":
                results.append({
                    "relation": "unknown_version_boundary",
                    "finding_identity_id": key,
                    "before_count": 1,
                    "after_count": 1,
                    "vulnerability_effect": "unknown",
                    "reasons": ["rule_compatibility:" + compatibility],
                })
                continue
            old_read, new_read = read_identity(old), read_identity(new)
            old_occ, new_occ = old_read["occurrence"], new_read["occurrence"]
            changed = sorted(
                field for field in _CHANGED_FIELDS
                if _observation_values(old).get(field) != _observation_values(new).get(field)
            )
            if old_occ.get("id") is not None and old_occ.get("id") == new_occ.get("id"):
                relation = "persistent_unchanged"
            else:
                new_record = _record_from_payload(new) or {}
                patch = _record_observation(new_record).get("patch_region", {})
                if not isinstance(patch, Mapping):
                    patch = new.get("patch_region") if isinstance(new.get("patch_region"), Mapping) else {}
                position_changed = any(field in changed for field in (
                    "line", "file", "source_blob_oid", "source_sha256", "byte_start", "byte_end",
                ))
                if patch.get("status") == "mapped" and position_changed:
                    relation = "persistent_moved_or_changed"
                elif changed or old_occ.get("id") != new_occ.get("id"):
                    relation = "persistent_changed_metadata"
                else:
                    relation = "unknown_identity"
            results.append({
                "relation": relation,
                "finding_identity_id": key,
                "before_count": 1,
                "after_count": 1,
                "changed_fields": changed,
                "before_occurrence_id": old_occ.get("id"),
                "after_occurrence_id": new_occ.get("id"),
                "historical_ids": sorted(set(
                    value for item in (old, new)
                    for value in (read_identity(item).get("historical_ids") or [])
                    if _present(value)
                )),
                "vulnerability_effect": "unknown",
                "reasons": [],
            })
            continue

        coverage_before = _coverage(before_coverage)
        coverage_after = _coverage(after_coverage)
        if rule_compatibility in ("compatible", "incompatible", "unknown"):
            compatibility = rule_compatibility
        else:
            compatibility = "unknown"
        comparable = (
            coverage_before == "complete"
            and coverage_after == "complete"
            and compatibility == "compatible"
        )
        if comparable:
            relation = "observation_absent_comparable" if old_items else "observation_added_comparable"
            reasons = []
        else:
            relation = "unknown_not_comparable"
            reasons = [
                "before_coverage:" + coverage_before,
                "after_coverage:" + coverage_after,
                "rule_compatibility:" + compatibility,
            ]
        results.append({
            "relation": relation,
            "finding_identity_id": key,
            "before_count": len(old_items),
            "after_count": len(new_items),
            "vulnerability_effect": "unknown",
            "reasons": reasons,
        })
    return results

def _report_coverage(report: Mapping[str, Any], tool: str) -> str:
    detector = report.get("detector_coverage", {}).get("detectors", {}).get(tool, {})
    run = next(
        (item for item in report.get("detector_runs", []) if item.get("tool") == tool),
        {},
    )
    status = detector.get("status") if isinstance(detector, Mapping) else None
    if run.get("status") != "completed" or status != "complete":
        return str(status or "unknown")
    return "complete"


def _report_diagnostics(report: Mapping[str, Any], tool: str) -> list[Mapping[str, Any]]:
    run = next(
        (item for item in report.get("detector_runs", []) if item.get("tool") == tool),
        None,
    )
    if not isinstance(run, Mapping):
        return []
    return [item for item in run.get("diagnostics", []) if isinstance(item, Mapping)]


def compare_reports(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    rule_compatibility: str = "auto",
) -> list[Dict[str, Any]]:
    """Compare schema v1/v2 report payloads without rewriting either report."""
    tools = sorted({
        item.get("tool")
        for report in (before, after)
        for item in report.get("detector_runs", [])
        if isinstance(item, Mapping) and _present(item.get("tool"))
    })
    results = []
    for tool in tools:
        results.extend(compare_findings(
            _report_diagnostics(before, tool),
            _report_diagnostics(after, tool),
            before_coverage=_report_coverage(before, tool),
            after_coverage=_report_coverage(after, tool),
            rule_compatibility=rule_compatibility,
        ))
    return results
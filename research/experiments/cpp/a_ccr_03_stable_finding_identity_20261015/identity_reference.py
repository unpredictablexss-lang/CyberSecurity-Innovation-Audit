"""Experimental reference model for A-CCR-03.

This is deliberately outside src/ohscanner. It is not a production contract,
runner, catalog, or detector implementation. It models the proposed layered
identity contract so the compatibility tests and experiment can exercise the
proposal without changing public code.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence


IDENTITY_SCHEMA = "ohscanner.finding-identity.v1"
OCCURRENCE_SCHEMA = "ohscanner.finding-occurrence.v1"


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def make_observation(**overrides: Any) -> dict[str, Any]:
    """Return a raw finding observation used only by the draft tests."""
    record: dict[str, Any] = {
        "repository": "fixture/repo",
        "legacy_schema_version": 2,
        "legacy_diagnostic_id": "fixture-diagnostic",
        "detector_id": "ohscanner.test.identity",
        "detector_version": "0.4.0",
        "rule_id": "test.rule",
        "rule_version": "1",
        "rule_lineage_id": "test.rule.lineage",
        "rule_compatibility": "compatible",
        "file": "src/a.cpp",
        "line": 2,
        "column": 3,
        "message": "candidate message",
        "symbol_identity": "ns::A::f",
        "ast_fingerprint": "expr:shared_ptr-read",
        "source_blob_oid": "blob-a",
        "source_sha256": "a" * 64,
        "byte_start": 10,
        "byte_end": 20,
        "identity_quality": "complete",
        "patch_region": {"status": "same", "method": "exact"},
        "historical_ids": [],
    }
    record.update(overrides)
    return record


def _unknown(reason: str) -> dict[str, Any]:
    return {"id": None, "status": "unknown", "unknown_reasons": [reason]}


def stable_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    """Compute a semantic finding identity without using line/message.

    Missing or partially parsed fields stay unknown. The caller must not fall
    back to file:line or a historical diagnostic ID to manufacture identity.
    """
    reasons: list[str] = []
    quality = record.get("identity_quality", "unknown")
    if quality != "complete":
        reasons.append(f"identity_quality:{quality}")
    required = ("repository", "rule_lineage_id", "symbol_identity", "ast_fingerprint")
    for key in required:
        value = record.get(key)
        if not isinstance(value, str) or not value.strip():
            reasons.append(f"missing:{key}")
    if reasons:
        return {"id": None, "status": "unknown", "unknown_reasons": reasons}

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


def occurrence_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    """Compute an exact occurrence identity for an emitted observation."""
    reasons: list[str] = []
    required = (
        "repository", "legacy_diagnostic_id", "detector_id", "detector_version",
        "rule_id", "rule_version", "file", "line", "message", "source_blob_oid",
        "source_sha256", "byte_start", "byte_end",
    )
    for key in required:
        if record.get(key) in (None, ""):
            reasons.append(f"missing:{key}")
    for key in ("byte_start", "byte_end"):
        value = record.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            reasons.append(f"invalid:{key}")
    if not reasons and record["byte_end"] < record["byte_start"]:
        reasons.append("invalid:byte_range")
    if reasons:
        return {"id": None, "status": "unknown", "unknown_reasons": reasons}

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


def prepare(record: Mapping[str, Any]) -> dict[str, Any]:
    """Attach the proposed identity layers while retaining historical IDs."""
    legacy_id = record.get("legacy_diagnostic_id")
    source_hash = record.get("source_sha256") or ""
    aliases = list(record.get("historical_ids", []))
    if legacy_id and legacy_id not in aliases:
        aliases.append(legacy_id)
    legacy_schema = record.get("legacy_schema_version", 2 if source_hash else 1)
    return {
        "finding_identity": stable_identity(record),
        "occurrence_identity": occurrence_identity(record),
        "legacy_identity": {
            "schema_version": legacy_schema,
            "diagnostic_id": legacy_id,
            "retained": True,
            "source_binding": "bound" if source_hash else "unbound",
            "aliases": aliases,
        },
        "record": dict(record),
    }


def _index(items: Sequence[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        prepared = prepare(item)
        identity = prepared["finding_identity"]
        key = identity["id"] if identity["status"] == "stable" else "__unknown__"
        grouped.setdefault(key, []).append(prepared)
    return grouped


def _changed_fields(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    fields = (
        "legacy_diagnostic_id", "detector_version", "rule_id", "rule_version",
        "file", "line", "column", "message", "source_blob_oid", "source_sha256",
        "byte_start", "byte_end",
    )
    changed = []
    if before.get("legacy_diagnostic_id") != after.get("legacy_diagnostic_id"):
        changed.append("diagnostic_id")
    changed.extend(field for field in fields if field != "legacy_diagnostic_id" and before.get(field) != after.get(field))
    return changed


def compare(
    before: Sequence[Mapping[str, Any]],
    after: Sequence[Mapping[str, Any]],
    *,
    before_coverage: str = "complete",
    after_coverage: str = "complete",
    rule_compatibility: str = "compatible",
) -> list[dict[str, Any]]:
    """Compare observations without inferring vulnerability status."""
    left = _index(before)
    right = _index(after)
    results: list[dict[str, Any]] = []

    for key in sorted(set(left) & set(right)):
        old_items = left.get(key, [])
        new_items = right.get(key, [])
        if key == "__unknown__":
            results.append({
                "relation": "unknown_identity",
                "identity_id": None,
                "before_count": len(old_items),
                "after_count": len(new_items),
                "vulnerability_effect": "unknown",
                "reasons": ["missing_stable_identity"],
            })
            continue
        if len(old_items) != 1 or len(new_items) != 1:
            results.append({
                "relation": "unknown_identity_ambiguous",
                "identity_id": key,
                "before_count": len(old_items),
                "after_count": len(new_items),
                "vulnerability_effect": "unknown",
                "reasons": ["ambiguous_stable_identity"],
            })
            continue

        old = old_items[0]["record"]
        new = new_items[0]["record"]
        if rule_compatibility not in ("compatible",):
            results.append({
                "relation": "unknown_version_boundary",
                "identity_id": key,
                "changed_fields": _changed_fields(old, new),
                "vulnerability_effect": "unknown",
                "reasons": [f"rule_compatibility:{rule_compatibility}"],
            })
            continue

        changed = _changed_fields(old, new)
        old_occ = old_items[0]["occurrence_identity"]
        new_occ = new_items[0]["occurrence_identity"]
        patch = new.get("patch_region", {})
        if old_occ.get("id") == new_occ.get("id"):
            relation = "persistent_unchanged"
        elif patch.get("status") == "mapped" and any(
            field in changed for field in ("line", "column", "byte_start", "byte_end", "source_blob_oid")
        ):
            relation = "persistent_moved_or_changed"
        elif changed:
            relation = "persistent_changed_metadata"
        else:
            relation = "persistent_changed"
        results.append({
            "relation": relation,
            "identity_id": key,
            "changed_fields": changed,
            "old_occurrence_id": old_occ.get("id"),
            "new_occurrence_id": new_occ.get("id"),
            "historical_ids": old_items[0]["legacy_identity"]["aliases"],
            "vulnerability_effect": "unknown",
        })

    for key in sorted(set(left) - set(right)):
        if key == "__unknown__":
            results.append({
                "relation": "unknown_identity",
                "identity_id": None,
                "before_count": len(left[key]),
                "after_count": 0,
                "vulnerability_effect": "unknown",
                "reasons": ["missing_stable_identity"],
            })
            continue
        if len(left[key]) != 1:
            continue
        comparable = rule_compatibility == "compatible" and after_coverage == "complete"
        results.append({
            "relation": "observation_absent_comparable" if comparable else "unknown_not_comparable",
            "identity_id": key,
            "before_count": 1,
            "after_count": 0,
            "vulnerability_effect": "unknown",
            "reasons": [] if comparable else [
                f"rule_compatibility:{rule_compatibility}",
                f"after_coverage:{after_coverage}",
            ],
        })
    for key in sorted(set(right) - set(left)):
        if key == "__unknown__":
            results.append({
                "relation": "unknown_identity",
                "identity_id": None,
                "before_count": 0,
                "after_count": len(right[key]),
                "vulnerability_effect": "unknown",
                "reasons": ["missing_stable_identity"],
            })
            continue
        if len(right[key]) != 1:
            continue
        comparable = rule_compatibility == "compatible" and before_coverage == "complete"
        results.append({
            "relation": "observation_added_comparable" if comparable else "unknown_not_comparable",
            "identity_id": key,
            "before_count": 0,
            "after_count": 1,
            "vulnerability_effect": "unknown",
            "reasons": [] if comparable else [
                f"rule_compatibility:{rule_compatibility}",
                f"before_coverage:{before_coverage}",
            ],
        })
    return results

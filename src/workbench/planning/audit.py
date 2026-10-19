"""Choose detector attempts from caller-supplied approved metadata.

Language applicability is not execution coverage. This module never invokes a
factory/detector, imports a user module, runs Git, writes a DB, or calls a model.
"""
from collections import Counter
from collections.abc import Mapping
import json

from src.workbench.sources.manifest import SourceManifest, canonical_sha256

PLANNER_VERSION = "0.1.1"


def _strings(value, *, nonempty=False):
    return (isinstance(value, (list, tuple)) and (bool(value) or not nonempty)
            and all(isinstance(x, str) and bool(x.strip()) for x in value)
            and len(value) == len(set(value)))


def metadata_from_detectors(rows, detectors):
    """Enrich supplied catalog rows from already-approved detector instances.

    Does NOT build/register instances or call detect. Reject mismatched IDs,
    versions or language claims instead of silently merging stale metadata.
    Caller retains responsibility for approved catalog provenance.
    """
    instances = list(detectors)
    by_id = {d.detector_id: d for d in instances}
    if len(by_id) != len(instances):
        raise ValueError("duplicate detector instance")
    result = []
    seen = set()
    for row in rows:
        if (not isinstance(row, Mapping) or not isinstance(row.get("id"), str)
                or not row["id"].startswith("ohscanner.") or row["id"] in seen):
            raise ValueError("invalid or duplicate catalog row")
        ident = row.get("id")
        detector = by_id.get(ident)
        if detector is None or row.get("version") != detector.version:
            raise ValueError("catalog/detector identity mismatch")
        languages = row.get("supported_languages")
        if not _strings(languages, nonempty=True) or set(languages) != set(detector.supported_languages):
            raise ValueError("catalog/detector languages mismatch")
        if not _strings(detector.required_facts):
            raise ValueError("invalid detector required facts")
        if "required_facts" in row and (not _strings(row["required_facts"]) or set(row["required_facts"]) != set(detector.required_facts)):
            raise ValueError("catalog/detector facts mismatch")
        result.append({**row, "required_facts": sorted(detector.required_facts)})
        seen.add(ident)
    if seen != set(by_id):
        raise ValueError("extra detector instance outside supplied catalog")
    return sorted(result, key=lambda r: r["id"])


def plan_audit(source: SourceManifest, metadata, *, selected_detector_ids=None, execution_budget=None):
    """Return a JSON-serializable plan. None selects automatically, [] selects none.

    No scan is enqueued. suggested_detector_ids are attempts for the existing
    Runner; their actual per-file outcomes must be recorded after execution.
    """
    if not isinstance(source, SourceManifest):
        raise ValueError("validated SourceManifest required")
    if selected_detector_ids is not None and not _strings(selected_detector_ids):
        raise ValueError("selection must contain distinct nonempty IDs")
    # Defensive JSON copy prevents mutation of input and rejects non-JSON data.
    rows = json.loads(json.dumps(list(metadata), allow_nan=False))
    decisions, review, known_ids = [], [], set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"].strip():
            review.append({"reason": "missing_detector_id"})
            continue
        ident = row["id"]
        if ident in known_ids:
            raise ValueError("duplicate detector metadata ID")
        known_ids.add(ident)
    files = sorted(source.files, key=lambda f: f.path)
    chosen = None if selected_detector_ids is None else set(selected_detector_ids)
    normalized = []
    valid_rows = [r for r in rows if isinstance(r, dict) and isinstance(r.get("id"), str) and r["id"].strip()]
    invalid_rows = sorted((r for r in rows if not (isinstance(r, dict) and isinstance(r.get("id"), str) and r["id"].strip())), key=lambda r: json.dumps(r, sort_keys=True))
    for row in sorted(valid_rows, key=lambda r: r["id"]):
        row = dict(row)
        reasons = []
        if not isinstance(row.get("version"), str) or not row["version"].strip():
            reasons.append("missing_detector_version")
        if not row["id"].startswith("ohscanner."):
            reasons.append("invalid_detector_namespace")
        if not _strings(row.get("supported_languages"), nonempty=True):
            reasons.append("missing_or_invalid_supported_languages")
        else:
            row["supported_languages"] = sorted(row["supported_languages"])
        if row.get("kind") == "admission_pending":
            reasons.append("admission_not_approved")
        elif row.get("kind") != "research_candidate":
            reasons.append("example_or_unrecognized_detector_kind")
        if "required_facts" in row:
            if not _strings(row["required_facts"]):
                reasons.append("invalid_required_facts")
            else:
                row["required_facts"] = sorted(row["required_facts"])
        if "default_enabled" in row and not isinstance(row["default_enabled"], bool):
            reasons.append("invalid_default_admission")
        normalized.append(row)
        valid_languages = row.get("supported_languages", []) if not reasons or reasons == ["admission_not_approved"] else []
        matched = [f.path for f in files if f.language in valid_languages]
        missing_facts = sorted(set(row.get("required_facts", [])) - set(source.available_facts)) if _strings(row.get("required_facts")) else []
        prerequisite = "unknown" if not _strings(row.get("required_facts")) else "missing" if missing_facts else "satisfied"
        if reasons:
            decision = "blocked"
        elif chosen is not None and row["id"] not in chosen:
            decision, reasons = "skipped", ["not_selected"]
        elif chosen is None and row.get("default_enabled", True) is False:
            decision, reasons = "skipped", ["explicit_selection_required"]
        elif not matched:
            decision, reasons = "skipped", ["no_matching_language"]
        elif missing_facts:
            decision, reasons = "blocked", ["required_facts_unavailable"]
        else:
            decision, reasons = "planned", ["language_match_attempt"]
            if prerequisite == "unknown":
                review.append({"detector_id": row["id"], "reason": "missing_prerequisite_metadata"})
        if decision == "blocked":
            review.append({"detector_id": row["id"], "reason": reasons[0]})
        decisions.append({"id": row["id"], "version": row.get("version"), "decision": decision,
                          "reason_codes": reasons, "matched_files": matched,
                          "prerequisite_status": prerequisite, "missing_facts": missing_facts,
                          "execution_status": "not_run",
                          **({"admission": {k: row[k] for k in (
                              "lane", "admission_status", "execution_enabled", "summary",
                              "accepted_evidence", "missing_evidence", "confirmation_evidence")}}
                             if row.get("kind") == "admission_pending" else {})})
    for ident in sorted((chosen or set()) - known_ids):
        review.append({"detector_id": ident, "reason": "unknown_selected_detector"})
    if chosen == set():
        review.append({"reason": "explicit_empty_selection"})
    suggested = [d["id"] for d in decisions if d["decision"] == "planned"]
    attempted_paths = {p for d in decisions if d["decision"] == "planned" for p in d["matched_files"]}
    uncovered = [{"file": f.path, "language": f.language, "reason": "no_planned_detector"} for f in files if f.path not in attempted_paths]
    uncertain_parse = [{"file": f.path, "parse_status": f.parse_status, "reason": "parser_not_complete"} for f in files if f.parse_status != "complete"]
    if uncovered:
        review.append({"reason": "files_without_planned_detector", "count": len(uncovered)})
    if uncertain_parse:
        review.append({"reason": "incomplete_parse", "count": len(uncertain_parse)})
    if source.unclassified_entries:
        review.append({"reason": "unclassified_or_non_source_entries", "count": source.unclassified_entries})
    if source.skipped_entries:
        review.append({"reason": "skipped_source_inventory_entries", "count": source.skipped_entries})
    if not rows:
        review.append({"reason": "empty_detector_catalog"})
    missing_blobs = sum(f.blob_oid is None for f in files)
    if missing_blobs:
        review.append({"reason": "missing_blob_identities", "count": missing_blobs})
    if source.provenance == "caller_supplied":
        review.append({"reason": "source_binding_not_independently_verified"})
    empty = not files and not source.unclassified_entries and not source.skipped_entries
    status = "empty_scope" if empty else "ready_with_limitations" if suggested and review else "ready" if suggested else "blocked"
    if execution_budget is not None:
        if (not isinstance(execution_budget, dict)
                or set(execution_budget) != {"timeout_seconds", "memory_mb"}):
            raise ValueError("invalid execution budget in audit plan")
        timeout_seconds = execution_budget["timeout_seconds"]
        memory_mb = execution_budget["memory_mb"]
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int)
                or not 1 <= timeout_seconds <= 3600
                or isinstance(memory_mb, bool) or not isinstance(memory_mb, int)
                or not 256 <= memory_mb <= 8192):
            raise ValueError("execution budget is outside allowed limits")
    plan = {
        "plan_schema_version": 1, "planner_version": PLANNER_VERSION,
        "status": status, "selection_mode": "automatic" if chosen is None else "explicit",
        "requested_detector_ids": None if chosen is None else sorted(chosen),
        "source": source.to_dict(), "metadata_sha256": canonical_sha256(sorted(normalized + invalid_rows, key=lambda r: json.dumps(r, sort_keys=True))),
        "detector_metadata": normalized, "invalid_metadata": invalid_rows,
        "suggested_detector_ids": suggested,
        "detectors": decisions, "files_without_planned_detector": uncovered,
        "parse_limitations": uncertain_parse,
        "languages": dict(sorted(Counter(f.language for f in files).items())),
        "needs_review": sorted(review, key=lambda item: json.dumps(item, sort_keys=True)),
        "execution_status": "not_run", "security_assessment": "unknown",
        "limitations": [
            "Planning only; no detector, model, build, network or task execution occurred.",
            "Language match is not analyzed coverage; Runner and adapters decide actual eligibility.",
            "Rules are known only at detector granularity; no invented rule IDs or CVE claims.",
            "Global fact availability does not prove per-file semantic facts or guard dominance.",
            "Repository name is declared; object bindings do not authenticate official ownership.",
            "Current non_source counts include unrecognized suffixes and non-code; no universal language discovery is claimed.",
            "Plan digest is not an execution cache key or a vulnerability verdict.",
        ],
    }
    if execution_budget is not None:
        plan["execution_budget"] = {
            "timeout_seconds": execution_budget["timeout_seconds"],
            "memory_mb": execution_budget["memory_mb"],
        }
    plan["plan_sha256"] = canonical_sha256(plan)
    return plan

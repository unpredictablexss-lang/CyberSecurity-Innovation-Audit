"""Deterministic local-evidence ranking with a family-diversity first pass."""

from __future__ import annotations

from collections import defaultdict
import re
from typing import Any, Iterable

from .contracts import RANKING_VERSION, GIT_COMMIT_RE, SHA256_RE


_SEVERITY_POINTS = {"critical": 12, "severe": 12, "high": 9, "medium": 5, "low": 2}


def _family_bucket(group: dict[str, Any]) -> str:
    explicit = group.get("family_bucket")
    if isinstance(explicit, str) and explicit.strip() and len(explicit) <= 80:
        return explicit.strip()
    members = group.get("members") or group.get("candidates") or []
    detector = " ".join(
        str(item.get("detector_id") or item.get("tool") or "")
        for item in members if isinstance(item, dict)
    ).lower()
    if any(token in detector for token in ("ipc", "permission", "auth")):
        return "ipc_authorization"
    if any(token in detector for token in ("cpp", "cxx", "memory", "bounds", "use-after")):
        return "cpp_memory_safety"
    if any(token in detector for token in ("arkts", "javascript", "typescript", "js.")):
        return "script_api"
    if any(token in detector for token in ("sensitive", "privacy", "logging", "data-leak")):
        return "sensitive_data"
    if any(token in detector for token in ("known-cve", "disclosed", "cve")):
        return "disclosed_vulnerability"
    if detector:
        token = re.sub(r"[^a-z0-9_.-]+", "_", detector.split()[0])[:60]
        return "detector:" + token
    return "unknown_family"


def _members(group: dict[str, Any]) -> list[dict[str, Any]]:
    values = group.get("members")
    if values is None:
        values = group.get("candidates")
    return [item for item in values or [] if isinstance(item, dict)]


def _member_is_bound(member: dict[str, Any], scope: dict[str, Any]) -> bool:
    repository = member.get("repository") or member.get("repository_id") or scope.get("repository")
    commit = member.get("commit") or scope.get("commit")
    snapshot = (member.get("snapshot_sha256") or member.get("report_sha256")
                or scope.get("snapshot_sha256") or scope.get("report_sha256"))
    source_hash = member.get("source_sha256")
    file = member.get("file")
    return bool(
        member.get("source_binding_verified") is True
        and isinstance(repository, str) and repository
        and isinstance(commit, str) and GIT_COMMIT_RE.fullmatch(commit)
        and isinstance(snapshot, str) and SHA256_RE.fullmatch(snapshot)
        and isinstance(source_hash, str) and SHA256_RE.fullmatch(source_hash)
        and isinstance(file, str) and file and not file.startswith(("/", "\\"))
        and ".." not in file.replace("\\", "/").split("/")
    )


def _member_unknown(member: dict[str, Any]) -> bool:
    status = str(member.get("parse_status") or member.get("coverage_status") or "").lower()
    return status in {"partial", "blocked", "not_analyzed", "failed", "unknown"}


def _facts(member: dict[str, Any]) -> set[str]:
    evidence = member.get("evidence")
    if not isinstance(evidence, dict):
        evidence = {}
    signals = member.get("evidence_signals")
    found = set()
    if isinstance(signals, dict):
        found.update(key for key, enabled in signals.items() if enabled is True and key in {
            "entry", "source", "guard", "sink", "effect", "dataflow", "authorization_boundary",
        })
    for key in ("entry", "source", "guard", "sink", "effect", "dataflow", "authorization_boundary"):
        if evidence.get(key):
            found.add(key)
    return found


def _obligations(member: dict[str, Any]) -> set[str]:
    values = member.get("evidence_obligations")
    if values is None and isinstance(member.get("evidence"), dict):
        values = member["evidence"].get("obligations")
    if not isinstance(values, list):
        return set()
    result = set()
    for value in values:
        if isinstance(value, str) and value.strip():
            result.add(value.strip())
        elif isinstance(value, dict):
            identifier = value.get("id") or value.get("obligation") or value.get("name")
            status = str(value.get("status") or "unresolved").lower()
            if isinstance(identifier, str) and status not in {"complete", "resolved", "satisfied"}:
                result.add(identifier)
    return result


def _score(group: dict[str, Any]) -> tuple[int, dict[str, int], list[str], bool, str]:
    members = _members(group)
    scope = group.get("source_scope") if isinstance(group.get("source_scope"), dict) else {}
    bound = bool(members) and all(_member_is_bound(item, scope) for item in members)
    unknown = bool(group.get("coverage_unknown")) or any(_member_unknown(item) for item in members)
    facts = set().union(*(_facts(item) for item in members)) if members else set()
    obligations = set().union(*(_obligations(item) for item in members)) if members else set()
    severities = []
    for item in members:
        # Model-authored risk_assessment is explanatory output, not priority truth.
        severities.append(str(item.get("severity") or "").lower())
    risk_points = max((_SEVERITY_POINTS.get(value, 0) for value in severities), default=0)
    changes = any(str(item.get("change_status") or item.get("diff_status") or "").lower()
                  in {"new", "added", "changed", "modified"} for item in members)
    components = {
        "source_binding": 30 if bound and not unknown else 0,
        "local_security_facts": min(5, len(facts)) * 6,
        "unresolved_evidence_obligations": min(5, len(obligations)) * 4,
        "potential_impact": risk_points,
        "version_change": 8 if changes else 0,
        "root_cause_signal": 3 if group.get("group_kind") == "root_cause_candidate" else 0,
    }
    reasons = []
    if not bound:
        reasons.append("source_binding_incomplete")
    if unknown:
        reasons.append("coverage_unknown")
    if obligations:
        reasons.append("unresolved_evidence_obligations")
    if facts:
        reasons.append("source_bound_security_facts")
    if changes:
        reasons.append("version_change_observed")
    family = _family_bucket(group)
    return sum(components.values()), components, reasons, (not bound or unknown), family


def rank_groups(groups: Iterable[dict[str, Any]], limit: int, *,
                family_quotas: bool = True) -> dict[str, Any]:
    """Rank groups for optional model spend; never remove or clear any candidate.

    This is a local selection decision only. Non-selected/unknown findings remain
    available and are not marked safe, false positive, or validated.
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or not 0 <= limit <= 10_000:
        raise ValueError("limit must be an integer between 0 and 10000")
    if not isinstance(family_quotas, bool):
        raise ValueError("family_quotas must be boolean")
    groups = list(groups)
    prepared = []
    seen_ids = set()
    for group in groups:
        if not isinstance(group, dict):
            raise ValueError("every group must be an object")
        group_id = group.get("group_id")
        if not isinstance(group_id, str) or not group_id or group_id in seen_ids:
            raise ValueError("group_id must be unique and non-empty")
        seen_ids.add(group_id)
        score, components, reasons, blocked, family = _score(group)
        prepared.append({
            "group_id": group_id,
            "score": score,
            "components": components,
            "evidence_gaps": sorted(set().union(*(_obligations(item) for item in _members(group)))),
            "family_bucket": family,
            "coverage_unknown": blocked,
            "reason_codes": reasons,
            "selected": False,
        })
    ordered = sorted(prepared, key=lambda item: (-item["score"], item["group_id"]))
    eligible = [item for item in ordered if not item["coverage_unknown"]]
    selected_ids = set()
    family_selected = set()
    if family_quotas and limit:
        family_best = {}
        for item in eligible:
            family_best.setdefault(item["family_bucket"], item)
        for family, item in sorted(
            family_best.items(), key=lambda pair: (-pair[1]["score"], pair[0], pair[1]["group_id"])
        ):
            if len(selected_ids) >= limit:
                break
            selected_ids.add(item["group_id"])
            family_selected.add(family)
            item["reason_codes"].append("family_quota_coverage")
    for item in eligible:
        if len(selected_ids) >= limit:
            break
        if item["group_id"] not in selected_ids:
            selected_ids.add(item["group_id"])
            item["reason_codes"].append("within_model_selection_budget")
    rank_by_id = {item["group_id"]: index + 1 for index, item in enumerate(ordered)}
    for item in prepared:
        item["rank"] = rank_by_id[item["group_id"]]
        item["selected"] = item["group_id"] in selected_ids
        if item["coverage_unknown"]:
            item["reason_codes"].append("retained_for_manual_review_not_auto_selected")
        elif not item["selected"]:
            item["reason_codes"].append("model_selection_budget_exhausted")
        item["reason_codes"] = sorted(set(item["reason_codes"]))
    decisions = sorted(prepared, key=lambda item: (item["rank"], item["group_id"]))
    return {
        "ranking_version": RANKING_VERSION,
        "selection_limit": limit,
        "family_quotas": family_quotas,
        "group_count": len(decisions),
        "selected_group_count": len(selected_ids),
        "retained_candidate_count": sum(len(_members(group)) for group in groups),
        "decisions": decisions,
    }

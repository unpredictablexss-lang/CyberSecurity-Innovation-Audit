"""Conservative, deterministic candidate grouping without model calls."""

from __future__ import annotations

from collections import OrderedDict
from copy import deepcopy
import re
from typing import Any, Iterable

from .contracts import GROUPING_VERSION, GIT_COMMIT_RE, SHA256_RE, content_sha256


_ROOT_CAUSE_FIELDS = frozenset({
    "entry_id", "sink_id", "mechanism_id", "relation_id", "source_fact_ids",
    "provenance",
})


def _text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip() and len(value) <= 512:
        return value.strip()
    return None


def _scope(candidate: dict[str, Any], default_scope: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for key in ("repository", "commit", "tree_sha256", "snapshot_sha256", "report_sha256"):
        value = candidate.get(key, default_scope.get(key))
        if isinstance(value, str):
            result[key] = value
    return result


def _scope_is_fixed(scope: dict[str, Any]) -> bool:
    repository = _text(scope.get("repository"))
    commit = _text(scope.get("commit"))
    snapshot = scope.get("snapshot_sha256") or scope.get("report_sha256")
    return bool(repository and commit and GIT_COMMIT_RE.fullmatch(commit)
                and isinstance(snapshot, str) and SHA256_RE.fullmatch(snapshot))


def _source_hash(candidate: dict[str, Any]) -> str | None:
    value = candidate.get("source_sha256")
    return value if isinstance(value, str) and SHA256_RE.fullmatch(value) else None


def _candidate_id(candidate: dict[str, Any]) -> str | None:
    return _text(candidate.get("candidate_id") or candidate.get("id"))


def _location_key(candidate: dict[str, Any]) -> tuple[Any, ...] | None:
    detector = _text(candidate.get("detector_id"))
    version = _text(candidate.get("detector_version"))
    rule = _text(candidate.get("rule_id"))
    file = _text(candidate.get("file"))
    line = candidate.get("line")
    column = candidate.get("column")
    symbol = _text(candidate.get("symbol")) or ""
    if (not detector or not version or not rule or not file
            or not isinstance(line, int) or isinstance(line, bool) or line < 1
            or (column is not None and (not isinstance(column, int) or isinstance(column, bool) or column < 1))):
        return None
    if file.startswith(("/", "\\")) or ".." in file.replace("\\", "/").split("/"):
        return None
    return detector, version, rule, file, line, column or 0, symbol


def _root_cause_key(candidate: dict[str, Any], scope: dict[str, Any]) -> tuple[Any, ...] | None:
    identity = candidate.get("root_cause_identity")
    if (candidate.get("source_binding_verified") is not True
            or not _scope_is_fixed(scope) or not _source_hash(candidate)
            or not isinstance(identity, dict)):
        return None
    if set(identity) != _ROOT_CAUSE_FIELDS or identity.get("provenance") != "deterministic_source_analysis":
        return None
    if not all(_text(identity.get(name)) for name in ("entry_id", "sink_id", "mechanism_id", "relation_id")):
        return None
    fact_ids = identity.get("source_fact_ids")
    if (not isinstance(fact_ids, list) or not fact_ids
            or any(not _text(item) for item in fact_ids)):
        return None
    scope_key = (
        scope.get("repository"), scope.get("commit"),
        scope.get("snapshot_sha256") or scope.get("report_sha256"),
    )
    return (*scope_key, identity["entry_id"], identity["sink_id"],
            identity["mechanism_id"], identity["relation_id"], tuple(sorted(set(fact_ids))))


def group_candidates(candidates: Iterable[dict[str, Any]], *,
                     source_scope: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a reversible group manifest; uncertain relationships stay separate.

    Strong duplicate identity requires fixed source binding and source hash. Semantic
    root-cause grouping additionally requires structured, deterministic source facts;
    matching CWE, path, line, symbol, message, or model prose is never sufficient.
    """
    source_scope = dict(source_scope or {})
    observations = []
    for index, item in enumerate(candidates):
        if not isinstance(item, dict):
            raise ValueError("every candidate must be an object")
        candidate = deepcopy(item)
        scope = _scope(candidate, source_scope)
        candidate_id = _candidate_id(candidate)
        location = _location_key(candidate)
        fixed = (candidate.get("source_binding_verified") is True
                 and _scope_is_fixed(scope) and _source_hash(candidate) is not None
                 and location is not None)
        observations.append({
            "index": index,
            "candidate": candidate,
            "candidate_id": candidate_id,
            "scope": scope,
            "fixed": fixed,
            "location": location,
            "duplicate_key": (
                scope.get("repository"), scope.get("commit"),
                scope.get("snapshot_sha256") or scope.get("report_sha256"),
                _source_hash(candidate), location, candidate_id,
            ) if fixed and candidate_id else None,
            "root_key": _root_cause_key(candidate, scope),
        })

    buckets: OrderedDict[tuple[Any, ...], dict[str, Any]] = OrderedDict()
    for item in observations:
        # Categorical evidence labels avoid presenting an uncalibrated probability.
        if item["root_key"] is not None:
            key = ("root_cause_candidate", *item["root_key"])
            kind = "root_cause_candidate"
            basis = "same fixed source scope and deterministic entry/sink/mechanism/source-fact identity"
            confidence = "same_deterministic_source_facts"
        elif item["duplicate_key"] is not None:
            key = ("exact_duplicate", *item["duplicate_key"])
            kind = "duplicate_observation"
            basis = "same fixed report, candidate identity, source hash, rule, and location"
            confidence = "exact_fixed_source_observation"
        else:
            # Even identical paths or CWE labels remain separate without strong evidence.
            identity = item["candidate_id"] or content_sha256(item["candidate"])
            key = ("independent", item["index"], identity)
            kind = "independent_candidate"
            basis = "insufficient source-bound identity; kept separate"
            confidence = "not_merged"
        group = buckets.setdefault(key, {
            "group_kind": kind,
            "grouping_basis": basis,
            "grouping_confidence": confidence,
            "root_cause_conclusion": "not_inferred",
            "source_scope": item["scope"],
            "_members": [],
        })
        group["_members"].append(item)

    groups = []
    flattened_member_ids = []
    for key, value in buckets.items():
        members = value.pop("_members")
        member_ids = [item["candidate_id"] for item in members]
        flattened_member_ids.extend(member_ids)
        public_members = [item["candidate"] for item in members]
        exact_duplicate_counts = {}
        for item in members:
            duplicate_key = item["duplicate_key"]
            if duplicate_key is not None:
                exact_duplicate_counts[duplicate_key] = exact_duplicate_counts.get(duplicate_key, 0) + 1
        duplicate_observation_count = sum(count - 1 for count in exact_duplicate_counts.values())
        group_kind = value["group_kind"]
        grouping_basis = value["grouping_basis"]
        grouping_confidence = value["grouping_confidence"]
        # When a semantic root-cause group contains only one exact observation
        # identity, report it as an exact duplicate group. The full member list
        # still records every source observation in either case.
        if group_kind == "root_cause_candidate" and len(exact_duplicate_counts) == 1:
            group_kind = "duplicate_observation"
            grouping_basis = "same fixed report, candidate identity, source hash, rule, and location"
            grouping_confidence = "exact_fixed_source_observation"
        group_identity = [GROUPING_VERSION, list(key), [item["index"] for item in members]]
        groups.append({
            "group_id": "ptg-" + content_sha256(group_identity)[:24],
            **{**value, "group_kind": group_kind,
               "grouping_basis": grouping_basis,
               "grouping_confidence": grouping_confidence},
            "member_candidate_ids": member_ids,
            "members": public_members,
            "observation_count": len(public_members),
            "exact_duplicate_group_count": len(exact_duplicate_counts),
            "duplicate_observation_count": duplicate_observation_count,
            "coverage_unknown": any(not item["fixed"] for item in members),
        })
    groups.sort(key=lambda group: group["group_id"])
    manifest = {
        "schema_version": 1,
        "grouping_version": GROUPING_VERSION,
        "source_scope": source_scope,
        "input_observation_count": len(observations),
        "group_count": len(groups),
        "member_candidate_ids": flattened_member_ids,
        "groups": groups,
    }
    manifest["manifest_sha256"] = content_sha256(manifest)
    return manifest

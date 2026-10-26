"""Progressive triage planning adapters used by completed audit operations.

This adapter currently connects fixed multi-endpoint reports to local L0/L1
grouping and ranking. It does not make Provider calls or change finding state.
"""
from __future__ import annotations

from typing import Any

from .grouping import group_candidates
from .policy import validate_policy
from .ranking import rank_groups
from .contracts import content_sha256


SUPPORTED_OPERATION_KINDS = {
    "snapshot", "revision_range", "recent_window_comparison", "branch_comparison", "version_matrix",
}


def build_operation_plan(settings, store, task: dict[str, Any], *,
                         read_report=None, findings=None,
                         source_binding_valid=None) -> dict[str, Any]:
    """Build an immutable, endpoint-aware L0/L1 plan after all scans complete."""
    if task.get("kind") not in SUPPORTED_OPERATION_KINDS:
        raise ValueError("operation kind is not supported by progressive planning")
    spec = task.get("spec") if isinstance(task.get("spec"), dict) else {}
    envelope = spec.get("progressive_triage_policy")
    if not isinstance(envelope, dict):
        raise ValueError("operation has no frozen progressive policy")
    policy = validate_policy(envelope.get("policy"))
    if envelope.get("policy_sha256") != content_sha256(policy):
        raise ValueError("frozen progressive policy digest mismatch")

    if read_report is None or findings is None or source_binding_valid is None:
        from .. import service, smart_audit
        read_report = read_report or service.read_report
        findings = findings or service.findings
        source_binding_valid = source_binding_valid or smart_audit._source_binding_valid

    observations = []
    endpoint_states = []
    for scan_id in spec.get("scan_ids", []):
        try:
            job = store.job(scan_id)
            report = read_report(settings, job)
        except Exception as error:
            endpoint_states.append({"scan_id": scan_id, "state": "unknown",
                                    "reason": type(error).__name__})
            continue
        if job.get("status") not in {"completed", "completed_with_limitations"}:
            endpoint_states.append({"scan_id": scan_id, "state": "unknown",
                                    "reason": "scan_not_complete"})
            continue
        endpoint_state = job.get("status")
        endpoint_states.append({"scan_id": scan_id, "state": endpoint_state,
                                "repository": report.get("repository"),
                                "commit": report.get("commit"),
                                "report_sha256": job.get("report_sha256")})
        for original in findings(report):
            candidate = dict(original)
            candidate.update({
                "candidate_id": candidate.get("id"),
                "repository": report.get("repository"),
                "commit": report.get("commit"),
                "snapshot_sha256": report.get("snapshot_sha256"),
                "report_sha256": job.get("report_sha256"),
                "source_binding_verified": source_binding_valid(report, original),
                "coverage_status": ("partial" if endpoint_state == "completed_with_limitations"
                                    else report.get("status")),
            })
            observations.append(candidate)

    grouped = group_candidates(observations)
    decision = rank_groups(
        grouped["groups"],
        policy["limits"]["quick_screen_groups_per_audit"],
        family_quotas=policy["family_quotas"],
    )
    by_group = {row["group_id"]: row for row in decision["decisions"]}
    all_endpoints_complete = (
        len(endpoint_states) == len(spec.get("scan_ids", []))
        and all(row.get("state") == "completed" for row in endpoint_states)
    )
    static_only = spec.get("audit_mode") == "static_only"
    groups = []
    for group in grouped["groups"]:
        item = dict(group)
        item["ranking"] = by_group[item["group_id"]]
        item["state"] = "selected_for_quick_screen" if item["ranking"]["selected"] else "retained_candidate"
        item["quick_screen_state"] = "not_scheduled"
        item["deep_agent_state"] = "not_scheduled"
        groups.append(item)
    return {
        "schema_version": 1,
        "planner_version": "progressive-operation-plan-v1",
        "policy_revision": envelope["revision"],
        "policy_sha256": envelope["policy_sha256"],
        "policy_profile": policy["profile"],
        "state": (("ranked_static_only" if static_only else "ranked_waiting_for_authorized_quick_screen")
                  if all_endpoints_complete else "partial_unknown"),
        "endpoint_states": endpoint_states,
        "grouping": {key: value for key, value in grouped.items() if key != "groups"},
        "ranking": decision,
        "groups": groups,
        "original_observation_count": len(observations),
        "candidate_disposition_changed": False,
        "validated_vulnerability": 0,
        "limitations": [
            "L0 grouping and L1 ranking are deterministic local planning only.",
            "L2 quick screen and L3 Agent dispatch require a separate task-level consent and are not scheduled by this operation.",
            *(["This snapshot was authorized as static-only; no model request is permitted from this audit."]
              if static_only else []),
            "Unselected and unknown observations remain candidates; ranking is not a safety or validity verdict.",
            *([] if all_endpoints_complete else [
                "One or more fixed endpoints did not produce a completed report; missing endpoint observations remain unknown and are not counted in this ranking."
            ]),
        ],
    }

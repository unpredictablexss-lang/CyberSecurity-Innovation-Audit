"""Task-level read model for progressive triage stages and shared budget."""
from __future__ import annotations

from pathlib import Path
from typing import Any


AUDIT_KINDS = {"revision_range", "recent_window_comparison", "branch_comparison", "version_matrix"}


def build_progressive_status(settings, ops, audit_id: str, *, store=None) -> dict[str, Any]:
    """Summarize one audit's immutable L0/L1 plan, L2/L3 work, and budget ledger.

    This is a read-only projection. It never creates a ledger or schedules Provider work.
    """
    try:
        audit = ops.get(audit_id)
    except KeyError:
        if store is None:
            raise
        job = store.job(audit_id)
        audit = {"id": audit_id, "kind": "snapshot", "status": job.get("status"),
                 "spec": job.get("spec", {}), "report_sha256": job.get("report_sha256")}
    is_snapshot = audit.get("kind") == "snapshot"
    if audit.get("kind") not in AUDIT_KINDS and not is_snapshot:
        raise ValueError("operation is not a supported multi-endpoint audit")
    spec = audit.get("spec") if isinstance(audit.get("spec"), dict) else {}
    policy_snapshot = spec.get("progressive_triage_policy")
    if not isinstance(policy_snapshot, dict):
        raise ValueError("audit has no frozen progressive policy")

    result = None
    if is_snapshot and store is not None and audit.get("status") in {"completed", "completed_with_limitations"}:
        from .runtime import build_operation_plan
        result = {"progressive_triage": build_operation_plan(settings, store, {
            "id": audit_id, "kind": "snapshot",
            "spec": {"progressive_triage_policy": policy_snapshot,
                     "scan_ids": [audit_id],
                     "audit_mode": spec.get("audit_mode", "static_only")},
        })}
    elif audit.get("result_sha256"):
        result = ops.result(audit_id)
    plan = result.get("progressive_triage") if isinstance(result, dict) else None
    plan = plan if isinstance(plan, dict) else None
    groups = plan.get("groups", []) if plan else []
    groups = [row for row in groups if isinstance(row, dict)]

    children = ops.progressive_operations_for_audit(audit_id)
    latest_by_group: dict[str, dict[str, dict[str, Any]]] = {}
    for child in children:
        child_spec = child.get("spec") if isinstance(child.get("spec"), dict) else {}
        if child.get("kind") == "progressive_quick_screen_batch":
            child_result = None
            if child.get("result_sha256"):
                try:
                    child_result = ops.result(child["id"])
                except (KeyError, OSError, ValueError):
                    child_result = None
            results_by_group = {
                row.get("group_id"): row for row in child_result.get("groups", [])
                if isinstance(row, dict) and isinstance(row.get("group_id"), str)
            } if isinstance(child_result, dict) else {}
            for entry in child_spec.get("items", []):
                item_spec = entry.get("spec") if isinstance(entry, dict) else None
                group = item_spec.get("group") if isinstance(item_spec, dict) else None
                group_id = group.get("group_id") if isinstance(group, dict) else None
                if not isinstance(group_id, str):
                    continue
                result_row = results_by_group.get(group_id)
                batch_active = child.get("status") in {"queued", "running"}
                synthetic = {"id": child["id"], "created_at": child.get("created_at", ""),
                             "status": ("running" if batch_active and child.get("status") == "running"
                                        else "queued" if batch_active
                                        else "completed" if result_row and result_row.get("state") == "completed"
                                        else "completed_with_limitations" if result_row
                                        else "not_started_candidate"),
                             "result": result_row.get("result") if result_row else None}
                latest_by_group.setdefault(group_id, {})["quick_screen"] = synthetic
            continue
        if child.get("kind") == "progressive_deep_agent_batch":
            child_result = None
            if child.get("result_sha256"):
                try:
                    child_result = ops.result(child["id"])
                except (KeyError, OSError, ValueError):
                    child_result = None
            results_by_group = {
                row.get("group_id"): row for row in child_result.get("groups", [])
                if isinstance(row, dict) and isinstance(row.get("group_id"), str)
            } if isinstance(child_result, dict) else {}
            for entry in child_spec.get("items", []):
                item_spec = entry.get("spec") if isinstance(entry, dict) else None
                group_id = item_spec.get("progressive_group_id") if isinstance(item_spec, dict) else None
                if not isinstance(group_id, str):
                    continue
                result_row = results_by_group.get(group_id)
                batch_active = child.get("status") in {"queued", "running"}
                synthetic = {"id": child["id"], "kind": "agent_investigation",
                             "created_at": child.get("created_at", ""), "spec": item_spec,
                             "status": ("running" if batch_active and child.get("status") == "running"
                                        else "queued" if batch_active
                                        else "completed" if result_row and result_row.get("state") == "completed"
                                        else "completed_with_limitations" if result_row
                                        else "not_started_candidate"),
                             "result": result_row.get("result") if result_row else None}
                latest_by_group.setdefault(group_id, {})["deep_agent"] = synthetic
            continue
        group = child_spec.get("group") if isinstance(child_spec.get("group"), dict) else {}
        group_id = (group.get("group_id") if child.get("kind") == "progressive_quick_screen"
                    else child_spec.get("progressive_group_id"))
        stage = "quick_screen" if child.get("kind") == "progressive_quick_screen" else "deep_agent"
        if not isinstance(group_id, str):
            continue
        if child.get("result_sha256"):
            try:
                child["result"] = ops.result(child["id"])
            except (KeyError, OSError, ValueError):
                child["result"] = None
        prior = latest_by_group.setdefault(group_id, {})
        existing = prior.get(stage)
        if existing is None or child.get("created_at", "") > existing.get("created_at", ""):
            prior[stage] = child

    selected_ids = {row.get("group_id") for row in (plan or {}).get("ranking", {}).get("decisions", [])
                    if isinstance(row, dict) and row.get("selected") is True}
    for group in groups:
        group_id = group.get("group_id")
        statuses = latest_by_group.get(group_id, {})
        quick = statuses.get("quick_screen")
        deep = statuses.get("deep_agent")
        group["quick_screen_state"] = _operation_state(quick)
        group["deep_agent_state"] = _operation_state(deep)
        group["quick_screen_operation_id"] = quick.get("id") if quick else None
        group["deep_agent_operation_id"] = deep.get("id") if deep else None

    selected_groups = [row for row in groups if row.get("group_id") in selected_ids]
    quick_done = sum(row["quick_screen_state"] == "completed" for row in selected_groups)
    quick_active = sum(row["quick_screen_state"] in {"queued", "running"} for row in selected_groups)
    deep_eligible = sum(
        (latest_by_group.get(row.get("group_id"), {}).get("quick_screen", {}).get("result") or {})
        .get("quick_screen", {}).get("quick_assessment") == "investigate"
        for row in selected_groups
    )
    deep_done = sum(row["deep_agent_state"] == "completed" for row in selected_groups)
    deep_active = sum(row["deep_agent_state"] in {"queued", "running"} for row in selected_groups)

    budget = None
    ledger_path = Path(settings.data_dir) / "progressive-triage-budget.sqlite3"
    if ledger_path.is_file():
        try:
            from .ledger import BudgetLedger
            budget = BudgetLedger(ledger_path).get(audit_id)
        except (OSError, ValueError):
            budget = {"state": "unknown", "reason": "budget_ledger_unavailable"}

    if not plan:
        phase = "static_in_progress" if audit.get("status") in {"queued", "running"} else "static_incomplete"
    elif plan.get("state") == "partial_unknown":
        phase = "partial_unknown"
    elif not selected_groups:
        phase = "deterministic_ranked"
    elif quick_active:
        phase = "quick_screening"
    elif quick_done < len(selected_groups):
        phase = "awaiting_quick_screen_authorization"
    elif deep_active:
        phase = "deep_investigating"
    elif deep_done < deep_eligible:
        phase = "awaiting_deep_agent_authorization"
    else:
        phase = "evidence_judged"

    candidate_count = sum(len(row.get("members", [])) for row in groups)
    unresolved_members = sum(
        len(row.get("members", [])) for row in groups
        if row.get("quick_screen_state") != "completed"
    )
    return {
        "audit_operation_id": audit_id,
        "policy_revision": policy_snapshot.get("revision"),
        "policy_sha256": policy_snapshot.get("policy_sha256"),
        "phase": phase,
        "phase_counts": {
            "candidate_count": candidate_count,
            "raw_candidate_observations": (plan or {}).get("original_observation_count", 0),
            "candidate_groups": len(groups),
            "selected_for_quick_screen": len(selected_groups),
            "quick_screen_completed": quick_done,
            "deep_agent_eligible": deep_eligible,
            "deep_agent_completed": deep_done,
            "unassessed_group_members": unresolved_members,
        },
        "budget": budget,
        "cost_enforcement": (budget or {}).get("cost", {}).get("enforcement", "not_started"),
        "stop_reason": (budget or {}).get("stop_reason"),
        "groups": groups,
        "candidate_disposition_changed": False,
        "validated_vulnerability": 0,
        "limitations": [
            "Quick-screen and deep-Agent opinions do not change candidate or confirmation status.",
            "L2/L3 operations appear only after their separate source disclosure and authorization.",
            "USD is advisory unless the configured Provider supplies a verified hard cap.",
        ],
    }


def _operation_state(operation: dict[str, Any] | None) -> str:
    if operation is None:
        return "not_scheduled"
    state = operation.get("status")
    if state == "not_started_candidate":
        return state
    if state in {"queued", "running"}:
        return state
    if state == "completed":
        return "completed"
    if state == "completed_with_limitations":
        return "partial"
    return "unknown"

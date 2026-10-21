"""Task-consented, sequential L2 scheduling over a frozen L0/L1 selection."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any

from .contracts import content_sha256
from .policy import policy_envelope, validate_policy

AUDIT_KINDS = {"revision_range", "recent_window_comparison", "branch_comparison", "version_matrix"}
MAX_BATCH_ITEMS = 1_000
MAX_BATCH_SPEC_BYTES = 12 * 1024 * 1024


def _load_audit(settings, store, ops, audit_id: str):
    try:
        audit = ops.get(audit_id)
    except KeyError:
        job = store.job(audit_id)
        if job.get("status") not in {"completed", "completed_with_limitations"}:
            raise ValueError("snapshot static report is not complete")
        spec = job.get("spec") if isinstance(job.get("spec"), dict) else {}
        if spec.get("audit_mode") == "static_only":
            raise ValueError("static-only audit cannot schedule AI quick screens")
        policy_snapshot = spec.get("progressive_triage_policy")
        if not isinstance(policy_snapshot, dict):
            raise ValueError("snapshot has no frozen progressive policy")
        from .runtime import build_operation_plan
        plan = build_operation_plan(settings, store, {
            "id": audit_id, "kind": "snapshot",
            "spec": {"progressive_triage_policy": policy_snapshot,
                     "audit_mode": spec.get("audit_mode", "standard_review"),
                     "scan_ids": [audit_id]},
        })
        return None, job, policy_snapshot, plan

    if audit.get("kind") not in AUDIT_KINDS:
        raise ValueError("operation is not a supported multi-endpoint audit")
    if audit.get("status") not in {"completed", "completed_with_limitations"}:
        raise ValueError("all fixed endpoint scans must finish before L2 batch consent")
    spec = audit.get("spec") if isinstance(audit.get("spec"), dict) else {}
    if spec.get("audit_mode") == "static_only":
        raise ValueError("static-only audit cannot schedule AI quick screens")
    policy_snapshot = spec.get("progressive_triage_policy")
    if not isinstance(policy_snapshot, dict):
        raise ValueError("audit has no frozen progressive policy")
    result = ops.result(audit_id) if audit.get("result_sha256") else None
    plan = result.get("progressive_triage") if isinstance(result, dict) else None
    if not isinstance(plan, dict):
        raise ValueError("audit has no completed L0/L1 plan")
    return audit, None, policy_snapshot, plan


def prepare_quick_screen_batch(settings, store, ops, audit_id: str, provider,
                               consent_nonce: str,
                               consent_expires_at: str | None = None) -> dict[str, Any]:
    """Prepare a complete, bounded disclosure for all selected, unscheduled L2 groups."""
    from .quick_screen_operation import prepare_quick_screen

    audit, snapshot_job, policy_snapshot, plan = _load_audit(settings, store, ops, audit_id)
    policy = validate_policy(policy_snapshot.get("policy"))
    policy_sha = policy_envelope(policy)["policy_sha256"]
    if (policy_snapshot.get("policy_sha256") != policy_sha
            or not isinstance(policy_snapshot.get("revision"), int)):
        raise ValueError("frozen progressive policy snapshot is invalid")
    expiry = consent_expires_at or (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()

    audit_parent = audit
    parent_plan = plan if audit else None
    selected = [row for row in plan.get("ranking", {}).get("decisions", [])
                if isinstance(row, dict) and row.get("selected") is True]
    selected.sort(key=lambda row: (row.get("rank", 10**9), row.get("group_id", "")))
    selected_by_id = {row.get("group_id"): row for row in selected}
    groups_by_id = {row.get("group_id"): row for row in plan.get("groups", [])
                    if isinstance(row, dict)}

    completed_or_active: set[str] = set()
    for operation in ops.progressive_operations_for_audit(audit_id):
        spec = operation.get("spec") if isinstance(operation.get("spec"), dict) else {}
        if operation.get("kind") == "progressive_quick_screen":
            group = spec.get("group") if isinstance(spec.get("group"), dict) else {}
            if isinstance(group.get("group_id"), str):
                completed_or_active.add(group["group_id"])
        elif operation.get("kind") == "progressive_quick_screen_batch":
            for item in spec.get("items", []):
                child_spec = item.get("spec") if isinstance(item, dict) else None
                group = child_spec.get("group") if isinstance(child_spec, dict) else None
                if isinstance(group, dict) and isinstance(group.get("group_id"), str):
                    completed_or_active.add(group["group_id"])

    scan_ids = [audit_id] if snapshot_job else (audit.get("spec", {}).get("scan_ids", []))
    jobs_by_report = {}
    for scan_id in scan_ids:
        job = store.job(scan_id)
        if job.get("report_sha256"):
            jobs_by_report[job["report_sha256"]] = job

    existing = set(completed_or_active)
    items = []
    skipped = []
    for decision in selected:
        group_id = decision.get("group_id")
        group = groups_by_id.get(group_id)
        if not isinstance(group, dict):
            skipped.append({"group_id": group_id, "reason": "selected_group_missing_from_plan"})
            continue
        if group_id in existing:
            skipped.append({"group_id": group_id, "reason": "already_scheduled_or_completed"})
            continue
        members = group.get("members") if isinstance(group.get("members"), list) else []
        representative = next((member for member in members
                               if isinstance(member, dict)
                               and member.get("source_binding_verified") is True
                               and isinstance(member.get("candidate_id"), str)
                               and member.get("report_sha256") in jobs_by_report), None)
        if representative is None:
            skipped.append({"group_id": group_id, "reason": "no_fixed_source_bound_representative"})
            continue
        job = jobs_by_report[representative["report_sha256"]]
        preview = prepare_quick_screen(
            settings, store, job["id"], representative["candidate_id"], provider,
            consent_nonce, expiry, audit_parent=audit_parent,
            audit_parent_plan=parent_plan,
        )
        if preview.get("eligible") is not True:
            skipped.append({"group_id": group_id, "reason": preview.get("reason", "not_eligible")})
            continue
        child_spec = {
            "source_submission_approved": True,
            "job_id": job["id"],
            "audit_operation_id": preview["audit_operation_id"],
            "candidate_id": representative["candidate_id"],
            "progressive_policy": preview["progressive_policy"],
            "ranking": preview["ranking"],
            "consent_nonce": consent_nonce,
            "consent_sha256": preview["consent_sha256"],
            "consent_expires_at": expiry,
            "consent_manifest": preview["consent_manifest"],
            "group": preview["group"],
            "evidence": preview["evidence"],
            "authorization": preview["authorization"],
            "provider_fingerprint": provider.fingerprint,
            "provider_model": provider.model,
        }
        items.append({"group_id": group_id, "spec": child_spec,
                      "disclosure": preview["disclosure"]})
        existing.add(group_id)
        if len(items) > min(MAX_BATCH_ITEMS, policy["limits"]["quick_screen_groups_per_audit"]):
            raise ValueError("selected L2 batch exceeds the bounded consent preview capacity; lower the task policy limit")

    if not items:
        raise ValueError("there are no selected, unscheduled, source-bound groups to quick-screen")
    if len(json.dumps(items, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_BATCH_SPEC_BYTES:
        raise ValueError("task-level L2 disclosure exceeds the 12 MiB bounded preview capacity; lower the group limit")
    batch_manifest = {
        "schema_version": 1,
        "audit_operation_id": audit_id,
        "policy_revision": policy_snapshot["revision"],
        "policy_sha256": policy_sha,
        "plan_sha256": content_sha256(plan),
        "consent_nonce": consent_nonce,
        "consent_expires_at": expiry,
        "provider_fingerprint": provider.fingerprint,
        "model": provider.model,
        "selected_group_count": len(selected),
        "scheduled_group_count": len(items),
        "skipped": skipped,
        "items": [{
            "group_id": item["group_id"],
            "job_id": item["spec"]["job_id"],
            "candidate_id": item["spec"]["candidate_id"],
            "consent_sha256": item["spec"]["consent_sha256"],
            "report_sha256": item["spec"]["authorization"]["report_sha256"],
            "commit": item["spec"]["authorization"]["commit"],
        } for item in items],
    }
    consent_sha = content_sha256(batch_manifest)
    for item in items:
        item.pop("disclosure", None)
    disclosures = [{
        "group_id": item["group_id"],
        "candidate_id": item["spec"]["candidate_id"],
        "repository": item["spec"]["authorization"]["repository"],
        "commit": item["spec"]["authorization"]["commit"],
        "report_sha256": item["spec"]["authorization"]["report_sha256"],
        "file": item["spec"]["evidence"][0]["file"],
        "line_start": item["spec"]["evidence"][0]["line_start"],
        "line_end": item["spec"]["evidence"][0]["line_end"],
        "source_sha256": item["spec"]["evidence"][0]["source_sha256"],
        "excerpt": item["spec"]["evidence"][0]["text"],
        "redactions": item["spec"]["evidence"][0].get("sensitive_redactions", []),
        "request_output_tokens": item["spec"]["consent_manifest"].get("request_output_tokens", 512),
        "consent_sha256": item["spec"]["consent_sha256"],
    } for item in items]
    return {
        "eligible": True,
        "audit_operation_id": audit_id,
        "consent_nonce": consent_nonce,
        "consent_expires_at": expiry,
        "consent_sha256": consent_sha,
        "batch_manifest": batch_manifest,
        "items": items,
        "disclosures": disclosures,
        "provider": provider.public,
        "progressive_policy": policy_snapshot,
        "plan_sha256": batch_manifest["plan_sha256"],
        "selected_group_count": len(selected),
        "scheduled_group_count": len(items),
        "skipped": skipped,
        "vulnerability_state_after_review": "candidate",
        "budget_limits": {
            "quick_screen_groups_per_audit": policy["limits"]["quick_screen_groups_per_audit"],
            "deep_groups_per_audit": policy["limits"]["deep_groups_per_audit"],
            "max_model_concurrency": policy["limits"]["max_model_concurrency"],
            "max_cost_usd": policy["limits"]["max_cost_usd"],
            "max_model_calls_per_audit": None,
            "max_input_tokens_per_audit": None,
            "max_output_tokens_per_audit": None,
            "max_ai_wall_seconds": None,
            "cumulative_usage_limits_enforced": False,
        },
        "limitations": [
            "Each selected group receives one no-tools L2 request under this preview and consent. There is no local cumulative token, call-count, or time ceiling.",
            "L3 deep Agent still requires its own fixed-source preview and explicit approval.",
            "Unselected, skipped, failed, and not-yet-scheduled observations remain candidates.",
        ],
    }


def batch_manifest_sha(spec: dict[str, Any]) -> str:
    manifest = spec.get("consent_manifest")
    if not isinstance(manifest, dict):
        raise ValueError("progressive batch consent manifest is missing")
    return content_sha256(manifest)


def execute_quick_screen_batch(settings, store, ops, task):
    """Sequentially run frozen L2 items; stop on cancellation or budget gate."""
    from ..agent import ProviderConfig
    from .quick_screen_operation import execute_quick_screen

    spec = task.get("spec") if isinstance(task.get("spec"), dict) else {}
    manifest = spec.get("consent_manifest")
    if (spec.get("source_submission_approved") is not True
            or batch_manifest_sha(spec) != spec.get("consent_sha256")
            or not isinstance(manifest, dict)
            or manifest.get("audit_operation_id") != spec.get("audit_operation_id")
            or manifest.get("items") != [{
                "group_id": item["group_id"],
                "job_id": item["spec"]["job_id"],
                "candidate_id": item["spec"]["candidate_id"],
                "consent_sha256": item["spec"]["consent_sha256"],
                "report_sha256": item["spec"]["authorization"]["report_sha256"],
                "commit": item["spec"]["authorization"]["commit"],
            } for item in spec.get("items", [])]):
        raise ValueError("task-level L2 consent binding is invalid")
    try:
        expires_at = datetime.fromisoformat(spec["consent_expires_at"].replace("Z", "+00:00"))
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ValueError("task-level L2 consent expiry is invalid") from None
    if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
        raise ValueError("task-level L2 consent expired before Worker execution")
    provider = ProviderConfig.from_env(settings.data_dir)
    if (not provider.configured or provider.fingerprint != manifest.get("provider_fingerprint")
            or provider.model != manifest.get("model")):
        raise ValueError("Provider changed after task-level L2 consent")
    audit_id = spec["audit_operation_id"]
    parent = None
    try:
        parent = ops.get(audit_id)
        parent_spec = parent.get("spec") if isinstance(parent.get("spec"), dict) else {}
        if (parent.get("kind") not in AUDIT_KINDS
                or parent.get("status") not in {"completed", "completed_with_limitations"}
                or parent_spec.get("audit_mode") == "static_only"
                or parent_spec.get("progressive_triage_policy") != spec.get("progressive_policy")
                or parent.get("cancel_requested") is True
                or parent.get("status") in {"cancelled", "failed", "timed_out", "interrupted"}):
            raise ValueError("parent audit changed, was cancelled, or no longer owns this batch")
        plan = ops.result(audit_id).get("progressive_triage")
    except KeyError:
        job = store.job(audit_id)
        job_spec = job.get("spec") if isinstance(job.get("spec"), dict) else {}
        if (job.get("status") not in {"completed", "completed_with_limitations"}
                or job_spec.get("progressive_triage_policy") != spec.get("progressive_policy")
                or job_spec.get("audit_mode") == "static_only"):
            raise ValueError("snapshot policy changed or static-only audit does not authorize L2")
        from .runtime import build_operation_plan
        plan = build_operation_plan(settings, store, {
            "id": audit_id, "kind": "snapshot",
            "spec": {"progressive_triage_policy": spec["progressive_policy"],
                     "audit_mode": job.get("spec", {}).get("audit_mode", "static_only"),
                     "scan_ids": [audit_id]},
        })
    if not isinstance(plan, dict) or content_sha256(plan) != manifest.get("plan_sha256"):
        raise ValueError("L0/L1 plan changed after task-level L2 consent")
    policy = validate_policy(spec["progressive_policy"]["policy"])
    policy_sha = policy_envelope(policy)["policy_sha256"]
    if manifest.get("policy_sha256") != policy_sha:
        raise ValueError("progressive policy changed after task-level L2 consent")

    results = []
    stop_reason = None
    for item in spec.get("items", []):
        if ops.get(task["id"]).get("cancel_requested") is True:
            stop_reason = "cancelled"
            break
        group_id = item["group_id"]
        child_spec = item["spec"]
        child = {"id": task["id"] + ":" + group_id,
                 "kind": "progressive_quick_screen", "spec": child_spec}
        result = execute_quick_screen(settings, child, provider=provider, ops=ops)
        quick = result.get("quick_screen") if isinstance(result, dict) else None
        results.append({"group_id": group_id, "candidate_id": child_spec["candidate_id"],
                        "job_id": child_spec["job_id"], "state": result.get("state", "quick_unknown"),
                        "quick_assessment": quick.get("quick_assessment") if isinstance(quick, dict) else None,
                        "reason_code": quick.get("reason_code") if isinstance(quick, dict) else result.get("reason_code"),
                        "result": result})
        reason = results[-1]["reason_code"]
        if isinstance(reason, str) and (reason.startswith("budget_gate:")
                                        or reason == "provider_quota_exhausted"
                                        or reason in {"authorization_binding_changed", "parent_plan_binding_changed"}):
            stop_reason = ("provider_quota_exhausted" if reason == "provider_quota_exhausted"
                           else "budget_exhausted" if reason.startswith("budget_gate:")
                           else "authorization_revoked")
            break

    finished_ids = {row["group_id"] for row in results}
    remaining = [{"group_id": item["group_id"], "state": "not_started_candidate"}
                 for item in spec.get("items", []) if item["group_id"] not in finished_ids]
    if stop_reason is None and len(results) == len(spec.get("items", [])):
        stop_reason = "all_selected_groups_processed"
    ledger_budget = None
    ledger_path = settings.data_dir / "progressive-triage-budget.sqlite3"
    if ledger_path.is_file():
        try:
            from .ledger import BudgetLedger
            ledger_budget = BudgetLedger(ledger_path).get(audit_id)
        except (OSError, ValueError):
            ledger_budget = None
    complete = len(results) == len(spec.get("items", [])) and all(row["state"] == "completed" for row in results)
    return {
        "status": "completed" if complete else "completed_with_limitations",
        "stage": "L2_quick_screen_batch",
        "audit_operation_id": audit_id,
        "consent_sha256": spec["consent_sha256"],
        "policy_sha256": policy_sha,
        "selected_group_count": manifest.get("selected_group_count"),
        "processed_group_count": len(results),
        "completed_group_count": sum(row["state"] == "completed" for row in results),
        "stop_reason": stop_reason,
        "groups": results,
        "not_started": remaining,
        "budget": ledger_budget,
        "candidate_disposition_changed": False,
        "validated_vulnerability": 0,
        "limitations": [
            "Quick-screen opinions never confirm, dismiss, or mark a finding safe.",
            "Unselected, skipped, failed, unknown, and not-started observations remain candidates.",
            "L3 requires a separate fixed-source consent; USD remains advisory without a Provider hard cap.",
        ],
    }

"""Task-consented sequential L3 dispatch over source-bound L2 results."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .contracts import content_sha256
from .policy import policy_envelope, validate_policy

MAX_BATCH_ITEMS = 100


def deep_batch_manifest_sha(spec: dict[str, Any]) -> str:
    manifest = spec.get("consent_manifest")
    if not isinstance(manifest, dict):
        raise ValueError("progressive deep batch consent manifest is missing")
    return content_sha256(manifest)


class _BatchOperationProxy:
    """Map Agent events and cancellation checks onto the durable batch operation."""
    def __init__(self, ops, batch_task_id: str, child_task_id: str, group_id: str):
        self.ops = ops
        self.batch_task_id = batch_task_id
        self.child_task_id = child_task_id
        self.group_id = group_id

    def get(self, key):
        if key in {self.batch_task_id, self.child_task_id}:
            return self.ops.get(self.batch_task_id)
        return self.ops.get(key)

    def event(self, key, stage, message):
        if key == self.child_task_id:
            return self.ops.event(self.batch_task_id, "L3:" + self.group_id + ":" + str(stage), message)
        return self.ops.event(key, stage, message)

    def __getattr__(self, name):
        return getattr(self.ops, name)


def execute_progressive_deep_agent_batch(settings, store, ops, task):
    """Run reviewed L3 scopes sequentially, reusing the existing Agent and ledger gates."""
    from .deep_agent_operation import execute_progressive_deep_agent
    from ..agent import ProviderConfig

    spec = task.get("spec") if isinstance(task.get("spec"), dict) else {}
    manifest = spec.get("consent_manifest")
    items = spec.get("items")
    if (spec.get("source_submission_approved") is not True
            or not isinstance(manifest, dict)
            or deep_batch_manifest_sha(spec) != spec.get("consent_sha256")
            or not isinstance(items, list) or not 1 <= len(items) <= MAX_BATCH_ITEMS
            or manifest.get("items") != [{
                "group_id": row.get("group_id"),
                "progressive_consent_sha256": row.get("spec", {}).get("progressive_consent_sha256"),
                "source_consent_sha256": row.get("spec", {}).get("source_consent_sha256"),
                "job_id": row.get("spec", {}).get("job_id"),
                "candidate_id": row.get("spec", {}).get("candidate_id"),
                "report_sha256": row.get("spec", {}).get("report_sha256"),
                "source_commit": row.get("spec", {}).get("source_commit"),
            } for row in items]):
        raise ValueError("task-level L3 consent binding is invalid")
    try:
        expiry = datetime.fromisoformat(spec["consent_expires_at"].replace("Z", "+00:00"))
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ValueError("task-level L3 consent expiry is invalid") from None
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise ValueError("task-level L3 consent expired before Worker execution")

    provider = ProviderConfig.from_env(settings.data_dir)
    if (not provider.configured or provider.fingerprint != manifest.get("provider_fingerprint")
            or provider.model != manifest.get("model")):
        raise ValueError("Provider changed after task-level L3 consent")

    audit_id = spec.get("audit_operation_id")
    l2_id = spec.get("l2_batch_operation_id")
    l2 = ops.get(l2_id)
    if (l2.get("kind") != "progressive_quick_screen_batch"
            or l2.get("status") not in {"completed", "completed_with_limitations"}
            or l2.get("result_sha256") != spec.get("l2_batch_result_sha256")
            or l2.get("spec", {}).get("audit_operation_id") != audit_id):
        raise ValueError("L2 batch changed or no longer authorizes these L3 members")
    audit = ops.get(audit_id) if audit_id != items[0].get("spec", {}).get("job_id") else None
    policy_snapshot = spec.get("progressive_policy")
    if not isinstance(policy_snapshot, dict):
        raise ValueError("frozen L3 batch policy is missing")
    policy = validate_policy(policy_snapshot.get("policy"))
    policy_sha = policy_envelope(policy)["policy_sha256"]
    if (policy_sha != manifest.get("policy_sha256")
            or policy_snapshot.get("policy_sha256") != policy_sha
            or (audit and (audit.get("cancel_requested") is True
                           or audit.get("spec", {}).get("audit_mode") == "static_only"
                           or audit.get("spec", {}).get("progressive_triage_policy") != policy_snapshot))):
        raise ValueError("parent audit changed, was revoked, or no longer owns this L3 batch")

    l2_result = ops.result(l2_id)
    l2_rows = {row.get("group_id"): row for row in l2_result.get("groups", [])
               if isinstance(row, dict)}
    l2_items = {row.get("group_id"): row for row in l2.get("spec", {}).get("items", [])
                if isinstance(row, dict)}
    results = []
    stop_reason = None
    for entry in items:
        if ops.get(task["id"]).get("cancel_requested") is True:
            stop_reason = "cancelled"
            break
        group_id = entry["group_id"]
        child_spec = entry["spec"]
        l2_row = l2_rows.get(group_id)
        l2_item = l2_items.get(group_id)
        if (not isinstance(l2_row, dict) or l2_row.get("state") != "completed"
                or l2_row.get("quick_assessment") != "investigate"
                or not isinstance(l2_item, dict)
                or l2_item.get("spec", {}).get("candidate_id") != child_spec.get("candidate_id")):
            stop_reason = "authorization_revoked"
            break
        synthetic_id = task["id"] + ":" + group_id
        proxy = _BatchOperationProxy(ops, task["id"], synthetic_id, group_id)
        child_task = {"id": synthetic_id, "kind": "agent_investigation", "spec": child_spec}
        try:
            result = execute_progressive_deep_agent(settings, store, proxy, child_task)
            results.append({"group_id": group_id, "candidate_id": child_spec["candidate_id"],
                            "state": "completed" if isinstance(result, dict) and result.get("status") == "completed"
                            else "completed_with_limitations", "result": result})
        except Exception as error:
            message = str(error)
            lowered = message.lower()
            state = "unknown"
            results.append({"group_id": group_id, "candidate_id": child_spec["candidate_id"],
                            "state": state, "reason": type(error).__name__ + ": " + message[:500]})
            if any(value in lowered for value in ("budget", "quota", "cancel", "authorization", "consent",
                                                   "provider changed", "source-bound", "parent audit changed")):
                stop_reason = ("provider_quota_exhausted" if "quota" in lowered
                               else "budget_exhausted" if "budget" in lowered
                               else "authorization_revoked")
                break

    finished = {row["group_id"] for row in results}
    not_started = [{"group_id": row["group_id"], "state": "not_started_candidate"}
                   for row in items if row["group_id"] not in finished]
    if stop_reason is None:
        stop_reason = "all_eligible_groups_processed"
    ledger = None
    ledger_path = settings.data_dir / "progressive-triage-budget.sqlite3"
    if ledger_path.is_file():
        from .ledger import BudgetLedger
        try:
            ledger = BudgetLedger(ledger_path).get(audit_id)
        except (OSError, ValueError):
            ledger = None
    all_completed = len(results) == len(items) and all(row["state"] == "completed" for row in results)
    return {
        "status": "completed" if all_completed else "completed_with_limitations",
        "stage": "L3_deep_agent_batch", "audit_operation_id": audit_id,
        "l2_batch_operation_id": l2_id, "consent_sha256": spec["consent_sha256"],
        "processed_group_count": len(results), "eligible_group_count": len(items),
        "completed_group_count": sum(row["state"] == "completed" for row in results),
        "stop_reason": stop_reason, "groups": results, "not_started": not_started,
        "budget": ledger, "candidate_disposition_changed": False,
        "validated_vulnerability": 0,
        "limitations": ["Deep Agent, Skeptic and draft reporting share the frozen task token, request-count, concurrency and elapsed-time limits.",
                        "Unknown, failed and not-started findings remain candidates; no result confirms a product vulnerability.",
                        "USD remains advisory without a verified Provider-side hard cap."],
    }

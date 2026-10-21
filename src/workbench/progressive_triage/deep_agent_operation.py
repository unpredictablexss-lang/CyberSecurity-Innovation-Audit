"""Budget and evidence gates around the existing bounded read-only Agent."""
from __future__ import annotations

import json
from typing import Any

from .ledger import BudgetError, BudgetLedger
from .policy import validate_policy, policy_envelope


def progressive_gate(settings, ops, task: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Recheck the L2 result, fixed report, parent policy, and cancellation state."""
    spec = task.get("spec") if isinstance(task.get("spec"), dict) else {}
    required = ("progressive_quick_screen_operation_id", "progressive_quick_screen_result_sha256",
                "progressive_audit_operation_id", "progressive_group_id", "progressive_policy_sha256")
    if any(not isinstance(spec.get(key), str) or not spec[key] for key in required):
        raise ValueError("progressive deep Agent is missing its L2/task binding")
    quick_id = spec["progressive_quick_screen_operation_id"]
    quick_task = ops.get(quick_id)
    if (quick_task.get("kind") != "progressive_quick_screen"
            or quick_task.get("result_sha256") != spec["progressive_quick_screen_result_sha256"]
            or quick_task.get("status") not in {"completed", "completed_with_limitations"}):
        raise ValueError("the source-bound L2 result is missing, changed, or incomplete")
    quick_result = ops.result(quick_id)
    assessment = quick_result.get("quick_screen") if isinstance(quick_result, dict) else None
    if (not isinstance(assessment, dict) or assessment.get("state") != "completed"
            or assessment.get("quick_assessment") != "investigate"):
        raise ValueError("deep Agent requires a completed L2 investigate assessment")
    source_binding = quick_result.get("source_binding") if isinstance(quick_result, dict) else None
    if not isinstance(source_binding, dict):
        raise ValueError("L2 result has no fixed source binding")
    quick_spec = quick_task.get("spec") if isinstance(quick_task.get("spec"), dict) else {}
    quick_group = quick_spec.get("group") if isinstance(quick_spec.get("group"), dict) else {}
    ranking = quick_spec.get("ranking") if isinstance(quick_spec.get("ranking"), dict) else {}
    decisions = ranking.get("decisions") if isinstance(ranking.get("decisions"), list) else []
    selected = any(isinstance(item, dict)
                   and item.get("group_id") == quick_group.get("group_id")
                   and item.get("selected") is True for item in decisions)
    if (quick_spec.get("job_id") != spec.get("job_id")
            or quick_spec.get("candidate_id") != spec.get("candidate_id")
            or quick_group.get("group_id") != spec.get("progressive_group_id")
            or not selected
            or source_binding.get("report_sha256") != spec.get("report_sha256")
            or source_binding.get("commit") != spec.get("source_commit")):
        raise ValueError("L2 result is unselected or belongs to another candidate, group, report, or fixed commit")
    audit_id = spec["progressive_audit_operation_id"]
    policy_snapshot = spec.get("progressive_policy")
    if not isinstance(policy_snapshot, dict):
        raise ValueError("frozen progressive policy is missing")
    policy = validate_policy(policy_snapshot.get("policy"))
    policy_sha = policy_envelope(policy)["policy_sha256"]
    if (policy_sha != spec["progressive_policy_sha256"]
            or policy_snapshot.get("policy_sha256") != policy_sha):
        raise ValueError("frozen progressive policy digest changed")
    job_id = spec.get("job_id")
    if audit_id != job_id:
        parent = ops.get(audit_id)
        if (job_id not in parent.get("spec", {}).get("scan_ids", [])
                or parent.get("spec", {}).get("progressive_triage_policy") != policy_snapshot
                or parent.get("cancel_requested") is True
                or parent.get("status") in {"cancelled", "failed", "timed_out", "interrupted"}):
            raise ValueError("parent audit was cancelled, changed, or no longer owns this endpoint")
    if quick_task["spec"].get("audit_operation_id") != audit_id:
        raise ValueError("L2 and L3 do not share one audit budget")
    ledger = BudgetLedger(settings.data_dir / "progressive-triage-budget.sqlite3")
    ledger.create_audit(audit_id, policy, policy_sha)
    return {**spec, "progressive_policy": {**policy_snapshot, "policy": policy}}, ledger


class BudgetedAgentClient:
    """Reserve every existing Agent Provider request in the parent task ledger."""
    supports_per_request_retry_budget = True

    def __init__(self, client, ledger: BudgetLedger, *, audit_id: str,
                 operation_id: str, endpoint_id: str, group_id: str):
        self.client = client
        self.ledger = ledger
        self.audit_id = audit_id
        self.operation_id = operation_id
        self.endpoint_id = endpoint_id
        self.group_id = group_id
        self.timeout = getattr(client, "timeout", 45)
        self._call_index = 0

    def create_with_timeout(self, payload, timeout, max_retries=None):
        from ..agent import _usage

        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        output_cap = payload.get("max_output_tokens")
        if not isinstance(output_cap, int) or isinstance(output_cap, bool) or output_cap <= 0:
            raise BudgetError("deep Agent request has no enforceable output-token cap")
        input_reservation = len(encoded) + 1024
        self._call_index += 1
        reservation = self.ledger.reserve(
            self.audit_id,
            f"{self.operation_id}:deep:{self._call_index}",
            self.endpoint_id, self.group_id, "deep_agent",
            max_input_tokens=input_reservation,
            max_output_tokens=output_cap,
        )
        if reservation.get("idempotent_replay"):
            raise BudgetError("prior deep Agent request outcome is unknown; request was not replayed")
        try:
            response = self.client.create_with_timeout(payload, timeout, max_retries=0)
        except Exception:
            self.ledger.settle(reservation["reservation_id"], outcome="unknown_outcome")
            raise
        try:
            usage = _usage(response)
        except (TypeError, ValueError):
            self.ledger.settle(reservation["reservation_id"], outcome="unknown_outcome")
            raise BudgetError("Provider usage is missing; reserved budget remains charged conservatively") from None
        settled = self.ledger.settle(
            reservation["reservation_id"], outcome="completed",
            input_tokens=usage["input_tokens"], output_tokens=usage["output_tokens"],
        )
        if settled.get("status") != "completed":
            raise BudgetError("Provider usage exceeded the reserved task budget")
        return response


def execute_progressive_deep_agent(settings, store, ops, task):
    """Run the existing Agent only after the frozen L2 and budget gates pass."""
    spec, ledger = progressive_gate(settings, ops, task)
    audit_id = spec["progressive_audit_operation_id"]
    group_id = spec["progressive_group_id"]
    endpoint_id = spec["job_id"]
    policy = spec["progressive_policy"]["policy"]
    ledger.dispatch_group(audit_id, group_id, endpoint_id, "deep_agent",
                          evidence_gate="quick_screen_investigate")
    from ..agent import ProviderConfig, ResponsesClient, execute_agent
    provider = ProviderConfig.from_env(settings.data_dir)
    if not provider.configured or provider.fingerprint != spec.get("provider_fingerprint"):
        raise ValueError("Provider changed after progressive deep-investigation consent")
    # Opaque retries would spend unreserved Provider calls inside one ledger slot.
    base = ResponsesClient(provider, max_retries=0)
    client = BudgetedAgentClient(base, ledger, audit_id=audit_id,
                                 operation_id=task["id"], endpoint_id=endpoint_id,
                                 group_id=group_id)
    result = execute_agent(settings, store, ops, task, client=client)
    result["progressive_triage"] = {
        "stage": "L3_deep_agent",
        "audit_operation_id": audit_id,
        "group_id": group_id,
        "quick_screen_operation_id": spec["progressive_quick_screen_operation_id"],
        "budget": ledger.get(audit_id),
        "validated_vulnerability": 0,
        "limitations": [
            "Existing fixed-commit read-only Agent workflow was reused.",
            "Agent assessment remains source-scoped and model-unverified; it does not alter candidate confirmation.",
            "USD remains advisory without a verified Provider-side hard cap.",
        ],
    }
    return result

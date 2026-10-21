"""Fixed-source consent and execution adapters for standalone L2 quick screens."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any

from .contracts import content_sha256
from .policy import PolicyStore, policy_envelope, validate_policy
from .quick_screen import (
    MAX_INPUT_TOKENS,
    MAX_REQUEST_SECONDS,
    MAX_RESPONSE_TOKENS,
    PROMPT_VERSION,
    QUICK_SCREEN_VERSION,
    build_quick_screen_request,
    run_quick_screen,
)
from .ranking import rank_groups
from ..store import Store


def prepare_quick_screen(settings, store, job_id: str, candidate_id: str,
                         provider, consent_nonce: str,
                         consent_expires_at: str | None = None,
                         audit_parent: dict[str, Any] | None = None,
                         audit_parent_plan: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the bounded source excerpt and exact disclosure for preview/start."""
    from .. import agent, service, smart_audit

    job = store.job(job_id)
    if job.get("status") not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
        raise ValueError("quick screen requires a completed fixed-snapshot report")
    report = service.read_report(settings, job)
    candidate = service.finding(report, candidate_id)
    if not smart_audit._source_binding_valid(report, candidate):
        raise ValueError("candidate source binding is not verified")
    prepared = agent._prepare_candidate_context(settings, store, job, report, candidate)
    context = prepared["initial_context"]
    source_lines = prepared["source"]["text"].splitlines()
    candidate_line = candidate.get("line")
    if not isinstance(candidate_line, int) or isinstance(candidate_line, bool) or not 1 <= candidate_line <= len(source_lines):
        raise ValueError("candidate source line is not available in the fixed source")
    line_start, line_end = max(1, candidate_line - 19), min(len(source_lines), candidate_line + 20)
    while line_end >= line_start:
        raw_excerpt = "\n".join(source_lines[line_start - 1:line_end])
        if len(raw_excerpt.encode("utf-8")) <= 8_192:
            break
        if line_end - candidate_line >= candidate_line - line_start and line_end > candidate_line:
            line_end -= 1
        elif line_start < candidate_line:
            line_start += 1
        elif line_end > candidate_line:
            line_end -= 1
        else:
            raise ValueError("candidate source line exceeds the quick-screen evidence limit")
    if line_end < line_start:
        raise ValueError("candidate source excerpt is empty")
    excerpt, redaction_categories = agent._redact_sensitive_data(raw_excerpt)
    excerpt_sha256 = hashlib.sha256(excerpt.encode("utf-8")).hexdigest()
    evidence_id = "quick-source-" + content_sha256({
        "repository": report["repository"], "commit": report["commit"],
        "report_sha256": job["report_sha256"], "file": candidate["file"],
        "line_start": line_start, "line_end": line_end,
        "source_sha256": candidate["source_sha256"], "excerpt_sha256": excerpt_sha256,
    })[:24]
    evidence = [{
        "evidence_id": evidence_id,
        "file": candidate["file"],
        "line_start": line_start,
        "line_end": line_end,
        "source_sha256": candidate["source_sha256"],
        "excerpt_sha256": excerpt_sha256,
        "text": excerpt,
        "source_binding_verified": True,
        "repository": report["repository"],
        "commit": report["commit"],
        "report_sha256": job["report_sha256"],
        "provider_fingerprint": provider.fingerprint,
        "redaction_applied": True,
        "redaction_policy_version": agent.REDACTION_POLICY_VERSION,
        "sensitive_redactions": redaction_categories,
    }]
    obligation_rows = context.get("evidence_obligations", [])
    evidence_gaps = []
    for obligation in obligation_rows if isinstance(obligation_rows, list) else []:
        if isinstance(obligation, str):
            value = obligation.strip()
        elif isinstance(obligation, dict):
            value = str(obligation.get("description") or obligation.get("kind") or "").strip()
        else:
            continue
        if value:
            evidence_gaps.append(value[:200])
    group = {
        "group_id": "candidate-" + content_sha256(candidate["id"])[:40],
        "rule_id": candidate.get("rule_id"),
        "weakness_family": candidate.get("cwe"),
        "evidence_gaps": evidence_gaps[:20],
        "members": [{
            "candidate_id": candidate["id"],
            "detector_id": candidate.get("detector_id"),
            "file": candidate.get("file"),
            "line": candidate.get("line"),
            "repository": report["repository"],
            "commit": report["commit"],
            "snapshot_sha256": report["snapshot_sha256"],
            "source_sha256": candidate["source_sha256"],
            "source_binding_verified": True,
            "coverage_status": report.get("status"),
            "severity": candidate.get("severity"),
            "evidence": candidate.get("evidence"),
        }],
    }
    parent_plan_sha256 = None
    selected = None
    ranking = None
    if audit_parent:
        if audit_parent.get("cancel_requested") or audit_parent.get("status") in {
                "cancelled", "failed", "timed_out", "interrupted"}:
            raise ValueError("parent audit is cancelled or not available for follow-up triage")
        if job_id not in audit_parent.get("spec", {}).get("scan_ids", []):
            raise ValueError("scan job is not an endpoint of the selected audit operation")
        policy_state = audit_parent.get("spec", {}).get("progressive_triage_policy")
        if audit_parent.get("spec", {}).get("audit_mode") == "static_only":
            raise ValueError("static-only audit cannot schedule an AI quick screen")
        if not isinstance(policy_state, dict):
            raise ValueError("parent audit has no frozen progressive policy")
        policy = validate_policy(policy_state.get("policy"))
        policy_sha256 = policy_envelope(policy)["policy_sha256"]
        if (policy_state.get("policy_sha256") != policy_sha256
                or not isinstance(policy_state.get("revision"), int)):
            raise ValueError("parent audit progressive policy snapshot is invalid")
        policy_revision = policy_state["revision"]
        audit_operation_id = audit_parent["id"]
        if not isinstance(audit_parent_plan, dict):
            raise ValueError("parent audit has no completed L0/L1 selection plan")
        matching_groups = [item for item in audit_parent_plan.get("groups", [])
                           if isinstance(item, dict) and any(
                               isinstance(member, dict)
                               and member.get("candidate_id") == candidate_id
                               and member.get("repository") == report["repository"]
                               and member.get("commit") == report["commit"]
                               and member.get("report_sha256") == job["report_sha256"]
                               for member in item.get("members", []))]
        if len(matching_groups) > 1:
            raise ValueError("candidate maps to multiple L0 groups for this fixed endpoint")
        planned_group = matching_groups[0] if matching_groups else None
        plan_decision = next((item for item in audit_parent_plan.get("ranking", {}).get("decisions", [])
                              if planned_group and item.get("group_id") == planned_group.get("group_id")), None)
        if not planned_group or not plan_decision or plan_decision.get("selected") is not True:
            raise ValueError("candidate is not selected by the frozen task-wide L1 ranking")
        group = {**planned_group, "representative_candidate_id": candidate_id}
        parent_plan_sha256 = content_sha256(audit_parent_plan)
        ranking = {"decisions": [plan_decision], "plan_sha256": parent_plan_sha256}
        selected = plan_decision
    else:
        audit_operation_id = job_id
        frozen_policy = job.get("spec", {}).get("progressive_triage_policy")
        if isinstance(frozen_policy, dict):
            if job.get("spec", {}).get("audit_mode") == "static_only":
                raise ValueError("static-only audit cannot schedule an AI quick screen")
            policy = validate_policy(frozen_policy.get("policy"))
            policy_sha256 = policy_envelope(policy)["policy_sha256"]
            if (frozen_policy.get("policy_sha256") != policy_sha256
                    or not isinstance(frozen_policy.get("revision"), int)):
                raise ValueError("snapshot progressive policy is invalid")
            policy_revision = frozen_policy["revision"]
            from .runtime import build_operation_plan
            snapshot_plan = build_operation_plan(settings, store, {
                "kind": "snapshot",
                "spec": {"progressive_triage_policy": frozen_policy,
                         "audit_mode": job.get("spec", {}).get("audit_mode", "standard_review"),
                         "scan_ids": [job_id]},
            })
            matches = [item for item in snapshot_plan["groups"]
                       if any(isinstance(member, dict)
                              and member.get("candidate_id") == candidate_id
                              and member.get("repository") == report["repository"]
                              and member.get("commit") == report["commit"]
                              and member.get("report_sha256") == job["report_sha256"]
                              for member in item.get("members", []))]
            if len(matches) != 1:
                raise ValueError("candidate is not uniquely present in the fixed snapshot plan")
            planned_group = matches[0]
            selected = next((row for row in snapshot_plan["ranking"]["decisions"]
                             if row.get("group_id") == planned_group.get("group_id")), None)
            group = {**planned_group, "representative_candidate_id": candidate_id}
            parent_plan_sha256 = content_sha256(snapshot_plan)
            ranking = {"decisions": [selected], "plan_sha256": parent_plan_sha256}
        else:
            policy_state = PolicyStore(settings.data_dir).read()
            policy = validate_policy(policy_state["policy"])
            policy_sha256 = policy_envelope(policy)["policy_sha256"]
            if policy_sha256 != policy_state["policy_sha256"]:
                raise ValueError("progressive triage policy changed while preparing quick-screen consent")
            policy_revision = policy_state["revision"]
            ranking = rank_groups([group], policy["limits"]["quick_screen_groups_per_audit"],
                                  family_quotas=policy["family_quotas"])
            selected = next((row for row in ranking["decisions"]
                             if row["group_id"] == group["group_id"]), None)
    if not selected or not selected["selected"]:
        raise ValueError("local evidence ranking did not select this candidate for quick screen")
    authorization = {
        "authorized": True,
        "audit_mode": "intelligent",
        "consent_sha256": "0" * 64,
        "report_sha256": job["report_sha256"],
        "repository": report["repository"],
        "commit": report["commit"],
        "provider_fingerprint": provider.fingerprint,
        "redaction_policy_version": agent.REDACTION_POLICY_VERSION,
        "model": provider.model,
    }
    # Validate the request before showing a consent screen, not after the user submits it.
    build_quick_screen_request(group, evidence, authorization, provider.fingerprint, provider.model)
    expires_at = consent_expires_at or (
        datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        raise ValueError("quick-screen consent expiry is invalid") from None
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise ValueError("quick-screen consent preview has expired")
    manifest = {
        "consent_nonce": consent_nonce,
        "consent_expires_at": expires_at,
        "quick_screen_version": QUICK_SCREEN_VERSION,
        "prompt_version": PROMPT_VERSION,
        "group": group,
        "evidence": evidence,
        "fixed_source": {key: authorization[key] for key in
                         ("repository", "commit", "report_sha256")},
        "provider_fingerprint": provider.fingerprint,
        "model": provider.model,
        "redaction_policy_version": agent.REDACTION_POLICY_VERSION,
        "policy_revision": policy_revision,
        "policy": policy,
        "policy_sha256": policy_sha256,
        "ranking": ranking,
        "audit_operation_id": audit_operation_id,
        "audit_parent_plan_sha256": parent_plan_sha256,
    }
    consent_sha256 = content_sha256(manifest)
    authorization["consent_sha256"] = consent_sha256
    return {
        "eligible": True,
        "consent_nonce": consent_nonce,
        "consent_sha256": consent_sha256,
        "consent_expires_at": expires_at,
        "group": group,
        "evidence": evidence,
        "authorization": authorization,
        "consent_manifest": manifest,
        "progressive_policy": {"revision": policy_revision, "policy": policy,
                               "policy_sha256": policy_sha256},
        "audit_operation_id": audit_operation_id,
        "ranking": ranking,
        "provider": provider.public,
        "disclosure": {
            "model_calls": 1,
            "tools_enabled": False,
            "max_output_tokens": 512,
            "timeout_seconds": 90,
            "source_excerpt_count": 1,
            "source_excerpt_bytes": len(excerpt.encode("utf-8")),
            "source_excerpt": excerpt,
            "sensitive_redactions": redaction_categories,
            "vulnerability_state_after_review": "candidate",
        },
        "message": "Only this redacted fixed-source excerpt is sent in one no-tools quick-screen request. AI opinion never confirms or closes the finding.",
    }


def execute_quick_screen(settings, task: dict[str, Any], provider=None, ops=None) -> dict[str, Any]:
    """Run one pre-authorized quick-screen request; unknown outcomes stay unknown."""
    from ..agent import ProviderConfig

    spec = task.get("spec") if isinstance(task.get("spec"), dict) else {}
    provider = provider or ProviderConfig.from_env(settings.data_dir)
    manifest = spec.get("consent_manifest")
    expires_at = spec.get("consent_expires_at")
    audit_operation_id = spec.get("audit_operation_id") or spec.get("job_id")
    if not isinstance(audit_operation_id, str) or not audit_operation_id:
        return {"state": "quick_unknown", "reason_code": "audit_budget_binding_missing",
                "vulnerability_state": "candidate", "validated_vulnerability": 0}
    if audit_operation_id != spec.get("job_id"):
        parent_plan = None
        try:
            parent = ops.get(audit_operation_id) if ops else None
            if (not parent or spec.get("job_id") not in parent.get("spec", {}).get("scan_ids", [])
                    or parent.get("spec", {}).get("progressive_triage_policy") != spec.get("progressive_policy")
                    or parent.get("cancel_requested") is True
                    or parent.get("status") in {"cancelled", "failed", "timed_out", "interrupted"}):
                raise ValueError("parent audit changed, was revoked, or no longer owns this endpoint")
            parent_result = ops.result(audit_operation_id)
            parent_plan = parent_result.get("progressive_triage")
            expected_plan_sha256 = manifest.get("audit_parent_plan_sha256") if isinstance(manifest, dict) else None
            if (not isinstance(parent_plan, dict)
                    or content_sha256(parent_plan) != expected_plan_sha256
                    or not any(group.get("group_id") == spec.get("group", {}).get("group_id")
                               and any(member.get("candidate_id") == spec.get("candidate_id")
                                       and member.get("repository") == spec.get("authorization", {}).get("repository")
                                       and member.get("commit") == spec.get("authorization", {}).get("commit")
                                       and member.get("report_sha256") == spec.get("authorization", {}).get("report_sha256")
                                       for member in group.get("members", []) if isinstance(member, dict))
                               for group in parent_plan.get("groups", []) if isinstance(group, dict))
                    or not any(decision.get("group_id") == spec.get("group", {}).get("group_id")
                               and decision.get("selected") is True
                               for decision in parent_plan.get("ranking", {}).get("decisions", [])
                               if isinstance(decision, dict))):
                raise ValueError("parent L0/L1 plan changed or did not select this group")
        except (KeyError, OSError, TypeError, ValueError) as error:
            return {"state": "quick_unknown", "reason_code": "parent_audit_binding:" + str(error),
                    "vulnerability_state": "candidate", "validated_vulnerability": 0}
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        expiry = None
    if (not provider.configured
            or provider.fingerprint != spec.get("authorization", {}).get("provider_fingerprint")
            or provider.model != spec.get("authorization", {}).get("model")
            or not isinstance(manifest, dict)
            or content_sha256(manifest) != spec.get("consent_sha256")
            or manifest.get("group") != spec.get("group")
            or manifest.get("evidence") != spec.get("evidence")
            or manifest.get("consent_expires_at") != expires_at
            or manifest.get("provider_fingerprint") != provider.fingerprint
            or manifest.get("model") != provider.model
            or not isinstance(manifest.get("fixed_source"), dict)
            or manifest.get("audit_operation_id") != audit_operation_id
            or manifest.get("fixed_source", {}).get("repository") != spec.get("authorization", {}).get("repository")
            or manifest.get("fixed_source", {}).get("commit") != spec.get("authorization", {}).get("commit")
            or manifest.get("fixed_source", {}).get("report_sha256") != spec.get("authorization", {}).get("report_sha256")
            or manifest.get("redaction_policy_version") != spec.get("authorization", {}).get("redaction_policy_version")
            or manifest.get("policy_sha256") != spec.get("progressive_policy", {}).get("policy_sha256")
            or expiry is None or expiry.tzinfo is None or expiry <= datetime.now(timezone.utc)
            or spec.get("authorization", {}).get("consent_sha256") != spec.get("consent_sha256")
            or spec.get("source_submission_approved") is not True):
        return {"state": "quick_unknown", "reason_code": "authorization_binding_changed",
                "vulnerability_state": "candidate", "validated_vulnerability": 0}
    try:
        policy_snapshot = spec["progressive_policy"]
        policy = validate_policy(policy_snapshot["policy"])
        if (policy_snapshot["policy_sha256"] != policy_envelope(policy)["policy_sha256"]
                or manifest.get("policy") != policy
                or manifest.get("policy_revision") != policy_snapshot["revision"]):
            raise ValueError("quick-screen policy snapshot changed")
        if audit_operation_id != spec.get("job_id"):
            plan_decision = next((row for row in parent_plan["ranking"]["decisions"]
                                  if row.get("group_id") == spec["group"].get("group_id")), None)
            expected_ranking = {"decisions": [plan_decision],
                                "plan_sha256": content_sha256(parent_plan)}
            if (not plan_decision or plan_decision.get("selected") is not True
                    or manifest.get("ranking") != expected_ranking):
                raise ValueError("quick-screen candidate is not selected by its frozen parent L1 ranking")
        elif manifest.get("audit_parent_plan_sha256"):
            job_store = Store(settings.data_dir)
            job = job_store.job(spec.get("job_id"))
            frozen_policy = job.get("spec", {}).get("progressive_triage_policy")
            if (not isinstance(frozen_policy, dict)
                    or frozen_policy != spec.get("progressive_policy")
                    or job.get("spec", {}).get("audit_mode") == "static_only"):
                raise ValueError("snapshot policy changed or does not authorize intelligent review")
            from .runtime import build_operation_plan
            snapshot_plan = build_operation_plan(settings, job_store, {
                "kind": "snapshot",
                "spec": {"progressive_triage_policy": frozen_policy,
                         "audit_mode": job.get("spec", {}).get("audit_mode", "standard_review"),
                         "scan_ids": [job["id"]]},
            })
            plan_digest = content_sha256(snapshot_plan)
            if manifest.get("audit_parent_plan_sha256") != plan_digest:
                raise ValueError("snapshot L0/L1 plan changed after consent")
            plan_group = next((item for item in snapshot_plan["groups"]
                               if item.get("group_id") == spec["group"].get("group_id")), None)
            plan_decision = next((row for row in snapshot_plan["ranking"]["decisions"]
                                  if row.get("group_id") == spec["group"].get("group_id")), None)
            expected_group = ({**plan_group,
                               "representative_candidate_id": spec.get("candidate_id")}
                              if plan_group else None)
            expected_ranking = {"decisions": [plan_decision], "plan_sha256": plan_digest}
            if (not plan_group or spec.get("group") != expected_group
                    or not plan_decision or plan_decision.get("selected") is not True
                    or manifest.get("ranking") != expected_ranking):
                raise ValueError("quick-screen candidate is not selected by its frozen snapshot L1 ranking")
        else:
            ranking = rank_groups([spec["group"]], policy["limits"]["quick_screen_groups_per_audit"],
                                  family_quotas=policy["family_quotas"])
            ranked = next((row for row in ranking["decisions"]
                           if row["group_id"] == spec["group"].get("group_id")), None)
            if not ranked or not ranked["selected"] or manifest.get("ranking") != ranking:
                raise ValueError("quick-screen candidate is not selected by its frozen local ranking")
    except (KeyError, TypeError, ValueError) as error:
        return {"state": "quick_unknown", "reason_code": str(error),
                "vulnerability_state": "candidate", "validated_vulnerability": 0}

    try:
        payload, _ = build_quick_screen_request(
            spec["group"], spec["evidence"], spec["authorization"],
            provider.fingerprint, provider.model,
        )
    except (KeyError, TypeError, ValueError) as error:
        return {"state": "quick_unknown", "reason_code": "request_preflight:" + str(error),
                "vulnerability_state": "candidate", "validated_vulnerability": 0}
    input_reservation = (len(payload["input"].encode("utf-8"))
                         + len(payload["instructions"].encode("utf-8")) + 1024)
    if input_reservation > MAX_INPUT_TOKENS:
        return {"state": "quick_unknown", "reason_code": "input_token_reservation_exceeds_limit",
                "vulnerability_state": "candidate", "validated_vulnerability": 0}

    from .ledger import BudgetError, BudgetLedger
    ledger = None
    reservation = None
    timeout_seconds = MAX_REQUEST_SECONDS
    try:
        ledger = BudgetLedger(settings.data_dir / "progressive-triage-budget.sqlite3")
        audit_id = audit_operation_id
        policy_snapshot = spec["progressive_policy"]
        ledger.create_audit(audit_id, policy, policy_snapshot["policy_sha256"])
        group_id = spec["group"]["group_id"]
        ledger.dispatch_group(audit_id, group_id, spec["job_id"], "quick_screen",
                              evidence_gate="ranked_and_selected")
        reservation = ledger.reserve(
            audit_id, audit_id + ":" + group_id + ":quick_screen",
            spec["job_id"], group_id, "quick_screen",
            max_input_tokens=input_reservation, max_output_tokens=MAX_RESPONSE_TOKENS,
        )
        if reservation.get("idempotent_replay"):
            return {"state": "quick_unknown", "reason_code": "prior_request_outcome_not_replayed",
                    "vulnerability_state": "candidate", "validated_vulnerability": 0,
                    "budget": ledger.get(audit_id)}
    except (BudgetError, OSError, KeyError, ValueError) as error:
        try:
            budget = ledger.get(audit_operation_id) if ledger else None
        except (BudgetError, OSError, KeyError, ValueError):
            budget = None
        return {"state": "quick_unknown", "reason_code": "budget_gate:" + str(error),
                "vulnerability_state": "candidate", "validated_vulnerability": 0,
                "budget": budget}
    result = run_quick_screen(
        provider, spec["group"], spec["evidence"], spec["authorization"],
        provider_fingerprint=provider.fingerprint, model=provider.model,
        timeout_seconds=timeout_seconds,
    )
    try:
        if result.get("state") == "completed":
            usage = result.get("usage") or {}
            settlement = ledger.settle(reservation["reservation_id"], outcome="completed",
                                       input_tokens=usage.get("input_tokens"),
                                       output_tokens=usage.get("output_tokens"),
                                       quick_assessment=result.get("quick_assessment"))
            if settlement.get("status") != "completed":
                result = {"group_id": spec["group"]["group_id"], "state": "quick_unknown",
                          "reason_code": "provider_usage_exceeded_reserved_budget",
                          "validated_vulnerability": 0}
        else:
            ledger.settle(reservation["reservation_id"], outcome="unknown_outcome")
        budget_snapshot = ledger.get(audit_operation_id)
    except BudgetError as error:
        budget_snapshot = {"state": "settlement_unknown", "reason": str(error)}
    return {
        "state": result.get("state", "quick_unknown"),
        "quick_screen": result,
        "source_binding": {
            "repository": spec["authorization"]["repository"],
            "commit": spec["authorization"]["commit"],
            "report_sha256": spec["authorization"]["report_sha256"],
            "consent_sha256": spec["consent_sha256"],
        },
        "vulnerability_state": "candidate",
        "validated_vulnerability": 0,
        "budget": budget_snapshot,
        "limitations": [
            "L2 quick screen is model triage only; source reachability and vulnerability validity remain unconfirmed.",
            "USD remains advisory because no verified Provider-side hard cap is configured.",
            "The ledger shares task-level budgets across fixed endpoints; L3 requires a separate, explicit consent and is not auto-scheduled.",
        ],
    }

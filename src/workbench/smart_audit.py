from __future__ import annotations

import hashlib
import json
from . import agent, service
from .store import now

RISK_POLICY_VERSION = "ohscanner-evidence-risk-tiers-0.2.0"


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def _severity(candidate):
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
        str(candidate.get("severity", "")).lower(), 0
    )


def coverage_snapshot(job, report):
    """Return scanner coverage facts without turning missing coverage into safety."""
    parsing = report.get("source_parsing", {})
    if not isinstance(parsing, dict):
        parsing = {}
    parsing_status = parsing.get("parsing_status", {})
    if not isinstance(parsing_status, dict):
        parsing_status = {}
    coverage = report.get("detector_coverage", {})
    if not isinstance(coverage, dict):
        coverage = {}
    detectors = coverage.get("detectors", {})
    if not isinstance(detectors, dict):
        detectors = {}
    detector_rows = []
    for detector_id, row in sorted(detectors.items()):
        if not isinstance(row, dict):
            continue
        detector_rows.append({
            "detector_id": detector_id,
            "status": row.get("status", "unknown"),
            "applicable_files": row.get("applicable_files", 0),
            "analyzed_files": len(row.get("analyzed_files", [])),
            "partially_inspected_files": len(row.get("partially_inspected_files", [])),
            "not_analyzed_files": len(row.get("not_analyzed_files", [])),
            "failed_files": len(row.get("failed_files", [])),
            "limitations": row.get("limitations", []),
        })
    return {
        "scan_status": job.get("status", "unknown"),
        "source_files_in_scope": report.get("scope", {}).get("selected_source_files"),
        "source_parsing": parsing_status,
        "detectors": detector_rows,
        "unclaimed_file_count": len(report.get("files_in_scope_without_a_claiming_detector", [])),
        "unclaimed_files": report.get("files_in_scope_without_a_claiming_detector", []),
        "limitations": report.get("limitations", []),
        "semantics": "Coverage describes analysis execution only; partial, blocked, failed and unclaimed ranges remain unknown, not safe.",
    }


def _source_binding_valid(report, candidate):
    evidence = candidate.get("evidence")
    binding = evidence.get("source_binding") if isinstance(evidence, dict) else None
    inventory = report.get("_workbench", {}).get("source_inventory", [])
    inventory_row = next((row for row in inventory if isinstance(row, dict)
                          and row.get("file") == candidate.get("file")), None)
    if not isinstance(binding, dict) or not isinstance(inventory_row, dict):
        return False
    expected = {
        "repository": report.get("repository"),
        "commit": report.get("commit"),
        "snapshot_sha256": report.get("snapshot_sha256"),
        "detector_id": candidate.get("detector_id"),
        "detector_version": candidate.get("detector_version"),
        "rule_id": candidate.get("rule_id"),
        "file": candidate.get("file"),
        "source_sha256": candidate.get("source_sha256"),
    }
    return (all(binding.get(key) == value for key, value in expected.items())
            and inventory_row.get("sha256") == candidate.get("source_sha256")
            and isinstance(candidate.get("source_sha256"), str)
            and len(candidate["source_sha256"]) == 64)


def _r0_gate(records, candidate, report, obligation_count):
    for review in reversed(records):
        if (review.get("job_id") != candidate.get("_job_id")
                or review.get("candidate_id") != candidate.get("id")
                or review.get("report_sha256") != candidate.get("_report_sha256")
                or review.get("commit") != report.get("commit")
                or review.get("source_sha256") != candidate.get("source_sha256")
                or review.get("review_scope") != "static_only_r0_triage"
                or review.get("obligations_truncated")
                or review.get("obligations_reviewed") != obligation_count):
            continue
        rows = review.get("obligation_reviews")
        if not isinstance(rows, list) or len(rows) != obligation_count:
            continue
        dispositions = [row.get("disposition") for row in rows if isinstance(row, dict)]
        if len(dispositions) != obligation_count:
            continue
        return review
    return None


def _agent_source_evidence(ops, job, report, candidate, operations):
    """Return source-bound Agent rationale suitable for a human-review priority tier."""
    workbench = report.get("_workbench")
    inventory = workbench.get("source_inventory", []) if isinstance(workbench, dict) else []
    inventory_files = {row.get("file") for row in inventory if isinstance(row, dict)}
    completed = [item for item in operations
                 if item.get("candidate_id") == candidate.get("id")
                 and item.get("status") in {"completed", "completed_with_limitations"}
                 and item.get("result_sha256")]
    # The latest completed review wins; a newer inconclusive result cannot be hidden
    # by an older positive result.
    for operation in reversed(completed):
        try:
            result = ops.result(operation["id"])
        except Exception:
            return None
        binding = result.get("binding") if isinstance(result, dict) else None
        if not isinstance(binding, dict) or any((
            binding.get("job_id") != job.get("id"),
            binding.get("candidate_id") != candidate.get("id"),
            binding.get("report_sha256") != job.get("report_sha256"),
            binding.get("source_sha256") != candidate.get("source_sha256"),
            binding.get("commit") != report.get("commit"),
        )):
            return None
        if (result.get("status") not in {"completed", "completed_with_limitations"}
                or result.get("structured_answer_validation") != "accepted"
                or result.get("summary_provenance") != "server_generated_from_structured_triage"):
            return None
        integrity = result.get("citation_integrity")
        if (not isinstance(integrity, dict)
                or integrity.get("quote_presence") != "verified_for_all_citations"):
            return None
        assessment = result.get("agent_assessment")
        verdict = result.get("agent_verdict")
        if (not isinstance(assessment, dict)
                or assessment.get("assessment") != "likely_true_positive"
                or not isinstance(verdict, dict)
                or verdict.get("status") not in {"likely_true_positive", "confirmed"}
                or verdict.get("scope") != "fixed_source_code"
                or verdict.get("product_status") != "unknown"
                or assessment.get("unsupported_claims")):
            return None
        initial = result.get("initial_evidence")
        context = initial.get("context", {}) if isinstance(initial, dict) else {}
        routing = context.get("evidence_routing", {}) if isinstance(context, dict) else {}
        source_indices = routing.get("agent_source_review_indices", [])
        reviews = assessment.get("obligation_reviews", [])
        if (not isinstance(source_indices, list) or not source_indices
                or any(not isinstance(index, int) or isinstance(index, bool) or index < 0
                       for index in source_indices)
                or len(source_indices) != len(set(source_indices))
                or not isinstance(reviews, list)):
            return None
        review_by_index = {
            row.get("obligation_index"): row.get("disposition")
            for row in reviews if isinstance(row, dict)
        }
        if any(review_by_index.get(index) not in {"evidence_found", "contrary_evidence", "unresolved"}
               for index in source_indices):
            return None
        if any(review_by_index.get(index) == "contrary_evidence" for index in source_indices):
            return None
        claims = assessment.get("supported_claims")
        if not isinstance(claims, list):
            return None
        selected_claim = None
        selected_citations = []
        for claim in claims:
            if not isinstance(claim, dict) or not isinstance(claim.get("claim"), str):
                continue
            indices = claim.get("obligation_indices")
            if (not isinstance(indices, list)
                    or any(not isinstance(index, int) or isinstance(index, bool) for index in indices)
                    or not any(index in source_indices and review_by_index.get(index) == "evidence_found"
                               for index in indices)):
                continue
            valid = []
            for citation in claim.get("citations", []):
                if not isinstance(citation, dict):
                    continue
                file = citation.get("file")
                start, end = citation.get("line_start"), citation.get("line_end")
                if (not isinstance(citation.get("evidence_id"), str) or not citation.get("evidence_id")
                        or not isinstance(file, str) or file not in inventory_files
                        or not isinstance(start, int) or isinstance(start, bool)
                        or not isinstance(end, int) or isinstance(end, bool)
                        or start < 1 or end < start or end - start > 7
                        or not isinstance(citation.get("quote"), str)
                        or len(citation["quote"]) < 8):
                    continue
                valid.append({"evidence_id": citation.get("evidence_id"), "file": file,
                              "line_start": start, "line_end": end,
                              "quote": citation["quote"][:500]})
            if valid:
                selected_claim = claim["claim"].strip().splitlines()[0]
                for separator in ("。", "！", "？", "!", "?"):
                    if separator in selected_claim:
                        selected_claim = selected_claim.split(separator, 1)[0] + separator
                        break
                selected_claim = selected_claim[:320]
                selected_citations = valid[:4]
                break
        if not selected_claim or not selected_citations:
            return None
        return {
            "summary": selected_claim,
            "assessment": assessment.get("assessment"),
            "operation_id": operation.get("id"),
            "result_sha256": operation.get("result_sha256"),
            "citations": selected_citations,
            "limitations": ["引句来源和逐字匹配已核对；引句语义是否支持模型主张仍需人工复核。",
                            "产品入口、触发条件和实际影响仍未由本条 AI 源码调查确认。"],
        }
    return None


def risk_snapshot(settings, store, ops, job, report):
    """Build deterministic severity and review-priority tiers from bound evidence."""
    candidates = service.findings(report)
    candidate_by_id = {item["id"]: item for item in candidates}
    manual_reviews = {}
    for review in store.reviews(job["id"]):
        manual_reviews[review["candidate_id"]] = review
    baseline_records = ops.agent_baseline_reviews()
    batches = ops.triage_batches_for_job(job["id"], job.get("report_sha256"))
    operation_by_candidate = {}
    triage_by_candidate = {}
    r2_waiting_candidates = set()
    cancellation = ops.triage_cancellation(job["id"], job.get("report_sha256"))
    authorization_exists = store.triage_authorization(job["id"]) is not None
    for batch in batches:
        if batch.get("r2_status") == "awaiting_r1":
            r2_waiting_candidates.update(
                row.get("candidate_id") for row in batch.get("candidate_manifest", [])
                if isinstance(row, dict) and row.get("state") == "selected"
            )
        for row in batch.get("candidate_manifest", []):
            if isinstance(row, dict):
                triage_by_candidate[row.get("candidate_id")] = {
                    "state": row.get("state", "not_triaged"),
                    "reason": row.get("reason"),
                    "batch_id": batch["id"],
                }
    job_agent_operations = ops.agent_investigations_for_job(job["id"], job.get("report_sha256"))
    for operation in job_agent_operations:
        candidate_id = operation.get("candidate_id")
        if candidate_id:
            operation_by_candidate.setdefault(candidate_id, []).append({
                "operation_id": operation["id"],
                "status": operation["status"],
                "mode": operation.get("mode"),
                "result_sha256": operation.get("result_sha256"),
                "cancel_requested": operation.get("cancel_requested", False),
            })

    tier_labels = {
        "high_confidence_candidate": "高可信风险候选（仍为待复核候选）",
        "further_validation": "待进一步验证",
        "low_priority_manual": "低优先级线索（人工标记，不代表安全）",
        "unknown_source_binding": "来源绑定未知",
    }
    items = []
    for original in candidates:
        candidate = {**original, "_job_id": job["id"],
                     "_report_sha256": job.get("report_sha256")}
        evidence = original.get("evidence") if isinstance(original.get("evidence"), dict) else {}
        obligations = evidence.get("obligations") if isinstance(evidence.get("obligations"), list) else []
        bound = _source_binding_valid(report, original)
        manual = manual_reviews.get(original["id"])
        manual_status = manual.get("status") if manual else "unassessed"
        gate_review = _r0_gate(baseline_records, candidate, report, len(obligations))
        gate_complete = bool(
            bound
            and evidence.get("analysis_status") == "analyzed"
            and obligations
            and gate_review
            and gate_review.get("disposition") == "investigate"
            and all(row.get("disposition") == "evidence_found"
                    for row in gate_review.get("obligation_reviews", []) if isinstance(row, dict))
        )
        contrary_reviewed = bool(
            bound and obligations and gate_review
            and gate_review.get("disposition") == "likely_noise"
            and all(row.get("disposition") == "contrary_evidence"
                    for row in gate_review.get("obligation_reviews", []) if isinstance(row, dict))
        )
        ai_evidence = _agent_source_evidence(ops, job, report, candidate, job_agent_operations)
        if not bound:
            tier = "unknown_source_binding"
            reasons = ["candidate source identity does not match the immutable report inventory"]
        elif manual_status in {"likely_false_positive", "refuted"} or contrary_reviewed:
            tier = "low_priority_manual"
            reasons = ["a human marked this item as refuted or low-priority; this is not a safety verdict"]
        elif ai_evidence:
            tier = "high_confidence_candidate"
            reasons = ["AI 在固定源码中给出带可定位引文的支持性判断；仍需人工复核"]
        elif gate_complete:
            tier = "high_confidence_candidate"
            reasons = ["fixed source/report hashes match and every recorded obligation has a quoted R0 evidence_found review"]
        else:
            tier = "further_validation"
            reasons = []
            if evidence.get("analysis_status") != "analyzed":
                reasons.append("candidate analysis is partial or unknown")
            if not obligations:
                reasons.append("no complete evidence-obligation set is available")
            if not gate_review:
                reasons.append("no complete quoted static-human evidence review is recorded")
            elif gate_review.get("disposition") != "investigate":
                reasons.append("static-human review did not meet the high-priority gate")
            elif any(row.get("disposition") != "evidence_found"
                     for row in gate_review.get("obligation_reviews", []) if isinstance(row, dict)):
                reasons.append("one or more evidence obligations remain contrary or unresolved")
            if not reasons:
                reasons.append("additional independent validation remains necessary")

        triage = triage_by_candidate.get(original["id"])
        operations = operation_by_candidate.get(original["id"], [])
        if operations:
            if any(x["status"] == "running" and x.get("cancel_requested") for x in operations):
                operation_state = "stopping"
            elif any(x["status"] in {"queued", "running"} for x in operations):
                operation_state = "in_progress"
            elif cancellation:
                operation_state = "cancelled"
            elif (original["id"] in r2_waiting_candidates):
                operation_state = "in_progress"
            elif all(x["status"] in {"completed", "completed_with_limitations"} for x in operations):
                operation_state = "completed"
            elif all(x["status"] == "cancelled" for x in operations):
                operation_state = "cancelled"
            else:
                operation_state = "partially_completed"
            triage = {"state": operation_state, "reason": None,
                      "batch_id": (triage or {}).get("batch_id")}
        elif triage is None:
            if job["spec"].get("audit_mode") == "static_only":
                triage = {"state": "not_requested", "reason": "static-only audit mode", "batch_id": None}
            elif authorization_exists:
                triage = {"state": "not_triaged", "reason": "authorization exists but no candidate batch was queued", "batch_id": None}
            else:
                triage = {"state": "not_triaged", "reason": "not authorized for model source egress", "batch_id": None}
        if gate_review:
            obligations_open = sum(
                1 for row in gate_review.get("obligation_reviews", [])
                if isinstance(row, dict) and row.get("disposition") == "unresolved"
            )
        else:
            obligations_open = sum(
                1 for row in obligations
                if not isinstance(row, dict) or row.get("status") != "satisfied"
            )
        items.append({
            "candidate_id": original["id"], "file": original.get("file"),
            "line": original.get("line"), "symbol": original.get("symbol"),
            "rule_id": original.get("rule_id"), "detector_id": original.get("detector_id"),
            "detector_version": original.get("detector_version"),
            "source_sha256": original.get("source_sha256"),
            "severity": original.get("severity", "unknown"),
            "evidence_level": "candidate", "vulnerability_state": "candidate",
            "risk_tier": tier, "risk_tier_label": tier_labels[tier],
            "confidence_basis": ("ai_source_evidence" if ai_evidence else
                                 "human_static_review" if gate_complete and tier == "high_confidence_candidate" else None),
            "ai_summary": ai_evidence.get("summary") if ai_evidence else None,
            "ai_evidence": ai_evidence.get("citations", []) if ai_evidence else [],
            "ai_review_operation_id": ai_evidence.get("operation_id") if ai_evidence else None,
            "ai_review_result_sha256": ai_evidence.get("result_sha256") if ai_evidence else None,
            "reasons": reasons, "obligation_count": len(obligations),
            "obligations_open": obligations_open,
            "human_review_status": manual_status,
            "r0_review_id": gate_review.get("id") if gate_review else None,
            "r0_review_sha256": gate_review.get("record_sha256") if gate_review else None,
            "triage": triage, "agent_operations": operations,
            "report_sha256": job.get("report_sha256"),
        })
    tier_order = {"high_confidence_candidate": 0, "further_validation": 1,
                  "unknown_source_binding": 2, "low_priority_manual": 3}
    items.sort(key=lambda item: (tier_order[item["risk_tier"]],
                                 -_severity(candidate_by_id[item["candidate_id"]]),
                                 item.get("file") or "", int(item.get("line") or 0),
                                 item["candidate_id"]))
    counts = {key: sum(1 for item in items if item["risk_tier"] == key)
              for key in tier_labels}
    triage_counts = {}
    for item in items:
        state = item["triage"]["state"]
        triage_counts[state] = triage_counts.get(state, 0) + 1
    return {
        "schema_version": 1, "audit_id": job["id"],
        "source_report_sha256": job.get("report_sha256"),
        "policy_version": RISK_POLICY_VERSION,
        "counts": counts, "triage_counts": triage_counts,
        "validated_vulnerability": 0,
        "items": items,
        "limitations": [
            "A high-confidence tier is a human-review priority: either a bound AI investigation provides a supported source claim with a fixed-file line citation and no source-level contrary finding, or a complete quoted human R0 review supports investigation.",
            "AI citations prove source and quote presence only; they do not prove semantic support, product reachability, trigger conditions, or CIA impact. Every tier remains candidate until the human/runtime confirmation gate passes.",
            "Unreviewed, skipped, budget-limited, partial, or unknown items are not safe and remain visible as untriaged or requiring validation.",
            "Validated vulnerabilities are counted only through the existing human assessment and passed runtime-reachability gate; this static risk view does not set that state.",
        ],
    }


def _path_in_scope(path, includes):
    return any(include == "." or path == include or path.startswith(include.rstrip("/") + "/")
               for include in includes)


def _authorization_is_current(settings, store, job, provider):
    record = store.triage_authorization(job["id"])
    spec_record = job["spec"].get("triage_authorization")
    if not record or not isinstance(spec_record, dict):
        return None, "no task-level source-egress authorization"
    if record["revoked"]:
        return record, "task-level source-egress authorization was revoked"
    if (record["consent_sha256"] != spec_record.get("consent_sha256")
            or record["snapshot"] != spec_record.get("snapshot")):
        return record, "persisted consent snapshot differs from the immutable scan task"
    snapshot = record["snapshot"]
    binding = snapshot.get("binding", {})
    if (binding.get("plan_sha256") != job["spec"].get("plan_sha256")
            or binding.get("workflow_sha256") != job["spec"].get("workflow_sha256")
            or binding.get("commit") != job["spec"].get("commit")
            or binding.get("tree") != job["spec"].get("git_tree")
            or binding.get("include_paths") != sorted(job["spec"].get("include_paths", []))):
        return record, "scan plan binding changed after consent"
    if not provider.configured or provider.fingerprint != snapshot.get("provider", {}).get("fingerprint"):
        return record, "Provider destination or model changed after consent"
    if agent.implementation_fingerprint() != snapshot.get("agent", {}).get("implementation_sha256"):
        return record, "Agent implementation changed after consent"
    if (agent.PROMPT_VERSION != snapshot.get("agent", {}).get("prompt_version")
            or agent.TOOL_POLICY_VERSION != snapshot.get("agent", {}).get("tool_policy_version")
            or agent.CONSENT_PREVIEW_VERSION != snapshot.get("agent", {}).get("consent_preview_version")
            or agent.REDACTION_POLICY_VERSION != snapshot.get("agent", {}).get("redaction_policy_version")):
        return record, "Agent prompt, tool or redaction policy changed after consent"
    refreshed = agent.audit_task_consent_preview(
        job["spec"]["audit_plan"], job["spec"]["workflow_sha256"],
        job["spec"]["include_paths"], snapshot.get("candidate_limit"),
        snapshot.get("consent_nonce"), provider,
        snapshot.get("r2_candidate_limit", 0),
        max_cost_usd=(snapshot.get("cost_budget") or {}).get("maximum_usd"),
    )
    if not refreshed.get("eligible") or refreshed.get("consent_sha256") != record["consent_sha256"]:
        return record, "task-level consent digest no longer matches the current plan"
    return record, None


def enqueue_authorized_triage(settings, store, ops, job):
    """Persist and queue at most five eligible R1 tasks only under an active task consent."""
    spec = job["spec"]
    if spec.get("audit_mode") != "standard_review":
        return None
    if ops.triage_cancellation(job["id"], job.get("report_sha256")):
        return None
    authorization = store.triage_authorization(job["id"])
    if authorization is None or authorization["revoked"]:
        return None
    if job["status"] not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
        return None
    provider = agent.ProviderConfig.from_env(settings.data_dir)
    authorization, error = _authorization_is_current(settings, store, job, provider)
    if authorization is None:
        return None
    snapshot = authorization["snapshot"]
    batch_id = hashlib.sha256(
        (job["id"] + job["report_sha256"] + authorization["consent_sha256"]).encode()
    ).hexdigest()[:32]
    report = service.read_report(settings, job)
    candidates = service.findings(report)
    candidate_manifest = []
    eligible = []
    preview_spec = {
        "mode": "single_shot", "max_steps": 1, "max_output_tokens": 1200,
        "max_total_input_tokens": 24000, "max_total_output_tokens": 2400,
        "timeout_seconds": 180, "max_provider_retries": 1,
        "consent_nonce": snapshot.get("consent_nonce"),
    }
    if error:
        record = {
            "id": batch_id, "audit_id": job["id"], "report_sha256": job["report_sha256"],
            "authorization_sha256": authorization["consent_sha256"],
            "batch_consent_sha256": _digest([authorization["consent_sha256"], job["report_sha256"], "blocked"]),
            "status": "blocked_authorization_changed", "candidate_count": len(candidates),
            "selected_count": 0, "candidate_manifest": [], "operation_ids": [],
            "r2_status": "blocked_authorization_changed",
            "created_at": now(), "error": error,
        }
        return ops.record_triage_batch(record)
    includes = spec.get("include_paths", [])
    for candidate in candidates:
        row = {"candidate_id": candidate["id"], "file": candidate.get("file"),
               "line": candidate.get("line"), "source_sha256": candidate.get("source_sha256")}
        if not isinstance(candidate.get("file"), str) or not _path_in_scope(candidate["file"], includes):
            row.update({"state": "not_triaged", "reason": "outside fixed audit scope"})
            candidate_manifest.append(row)
            continue
        try:
            prepared = agent._prepare_candidate_context(settings, store, job, report, candidate)
            child_preview = agent.consent_preview(
                settings, store, job, report, candidate, preview_spec, provider, prepared=prepared
            )
            route = (prepared["initial_context"].get("evidence_routing")
                     if isinstance(prepared.get("initial_context"), dict) else {})
            open_count = len(route.get("agent_source_review_indices", [])) if isinstance(route, dict) else 0
            if not child_preview.get("agent_execution", {}).get("eligible"):
                row.update({"state": "not_triaged", "reason": "no eligible source-review obligation"})
            else:
                row.update({"state": "eligible", "reason": None, "open_obligations": open_count})
                eligible.append((candidate, child_preview, open_count, row))
        except Exception as exc:
            row.update({"state": "not_triaged", "reason": "candidate context unavailable: " + type(exc).__name__})
        candidate_manifest.append(row)
    eligible.sort(key=lambda item: (
        -item[2], -_severity(item[0]), item[0].get("file", ""),
        int(item[0].get("line") or 0), item[0]["id"],
    ))
    limit = int(snapshot["candidate_limit"])
    selected = eligible[:limit]
    selected_ids = {item[0]["id"] for item in selected}
    for _, _, _, row in eligible:
        if row["candidate_id"] in selected_ids:
            row["state"] = "selected"
            row["reason"] = "selected by deterministic priority within task budget"
        else:
            row["state"] = "not_triaged"
            row["reason"] = "candidate budget reached; not assessed as safe"
    batch_consent = _digest({
        "task_authorization_sha256": authorization["consent_sha256"],
        "report_sha256": job["report_sha256"],
        "selected": [(item[0]["id"], item[1]["consent_sha256"]) for item in selected],
        "candidate_manifest": candidate_manifest,
    })
    record = {
        "id": batch_id, "audit_id": job["id"], "report_sha256": job["report_sha256"],
        "authorization_sha256": authorization["consent_sha256"],
        "batch_consent_sha256": batch_consent,
        "status": "queued" if selected else "no_eligible_candidates",
        "candidate_count": len(candidates), "selected_count": len(selected),
        "candidate_manifest": candidate_manifest, "operation_ids": [],
        "created_at": now(), "error": None,
        "r2_status": "awaiting_r1" if selected and snapshot.get("r2_candidate_limit", 0) else "not_requested",
    }
    if not selected:
        return ops.record_triage_batch(record)
    count = len(selected)
    child_specs = []
    for index, (candidate, child_preview, _, _) in enumerate(selected, 1):
        binding = child_preview["binding"]
        child_specs.append({
            **preview_spec,
            "job_id": job["id"], "candidate_id": candidate["id"], "case_id": None,
            "experiment_id": None, "source_submission_approved": True,
            "source_submission_approved_at": now(),
            "source_consent_sha256": child_preview["consent_sha256"],
            "consent_preview_version": agent.CONSENT_PREVIEW_VERSION,
            "redaction_policy_version": agent.REDACTION_POLICY_VERSION,
            "provider": provider.provider, "provider_model": provider.model,
            "provider_host": provider.endpoint_host, "provider_fingerprint": provider.fingerprint,
            "prompt_version": agent.PROMPT_VERSION,
            "tool_policy_version": agent.TOOL_POLICY_VERSION,
            "max_provider_retries": 1,
            "candidate_source_sha256": binding.get("source_sha256"),
            "source_commit": binding["commit"], "report_sha256": binding["report_sha256"],
            "batch_id": batch_id, "batch_consent_sha256": batch_consent,
            "batch_index": index, "batch_count": count,
            "smart_triage_batch_id": batch_id,
            "triage_authorization_sha256": authorization["consent_sha256"],
        })
    batch, _ = ops.create_authorized_triage_batch(record, child_specs)
    return batch


def _r2_source_obligations(result):
    if not isinstance(result, dict) or result.get("status") not in {"completed", "completed_with_limitations"}:
        return []
    evidence = result.get("initial_evidence")
    context = evidence.get("context") if isinstance(evidence, dict) else None
    routing = context.get("evidence_routing") if isinstance(context, dict) else None
    source_indices = routing.get("agent_source_review_indices") if isinstance(routing, dict) else None
    assessment = result.get("agent_assessment")
    if (not isinstance(source_indices, list) or not isinstance(assessment, dict)
            or assessment.get("assessment") not in {"needs_more_evidence", "unknown"}):
        return []
    obligations = context.get("evidence_obligations") if isinstance(context, dict) else None
    reviews = assessment.get("obligation_reviews")
    if (not isinstance(obligations, list) or not obligations
            or not isinstance(reviews, list) or len(reviews) != len(obligations)):
        return []
    reviewed = {}
    for row in reviews:
        if (not isinstance(row, dict) or not isinstance(row.get("obligation_index"), int)
                or isinstance(row.get("obligation_index"), bool)
                or row.get("disposition") not in {"evidence_found", "contrary_evidence", "unresolved"}):
            return []
        index = row["obligation_index"]
        if index in reviewed or not 0 <= index < len(obligations):
            return []
        reviewed[index] = row["disposition"]
    if set(reviewed) != set(range(len(obligations))):
        return []
    if (any(not isinstance(index, int) or isinstance(index, bool)
            or not 0 <= index < len(obligations) for index in source_indices)
            or len(source_indices) != len(set(source_indices))):
        return []
    return sorted(index for index in source_indices if reviewed[index] == "unresolved")


def enqueue_authorized_r2_followups(settings, store, ops, batch_id):
    """Queue only consented R2 tasks after all fixed-batch R1 tasks are terminal."""
    try:
        batch = ops.triage_batch(batch_id)
    except KeyError:
        return None
    if batch.get("r2_status") != "awaiting_r1":
        return batch
    job = store.job(batch["audit_id"])
    authorization = store.triage_authorization(job["id"])
    if authorization is None:
        return batch
    provider = agent.ProviderConfig.from_env(settings.data_dir)
    authorization, auth_error = _authorization_is_current(settings, store, job, provider)
    r1_operations = [item for item in ops.smart_triage_operations(batch_id)
                     if item.get("spec", {}).get("mode") == "single_shot"]
    from .operations_store import END
    if not r1_operations or any(item["status"] not in END for item in r1_operations):
        return batch
    report = service.read_report(settings, job)
    candidates = {item["id"]: item for item in service.findings(report)}
    manifest = []
    eligible = []
    for operation in r1_operations:
        spec = operation["spec"]
        candidate_id = spec.get("candidate_id")
        candidate = candidates.get(candidate_id)
        row = {"candidate_id": candidate_id, "r1_operation_id": operation["id"],
               "r1_result_sha256": operation.get("result_sha256"),
               "state": "not_eligible", "reason": None, "unresolved_source_obligations": 0}
        if auth_error:
            row.update({"state": "blocked", "reason": auth_error})
        elif operation["status"] not in {"completed", "completed_with_limitations"} or not operation.get("result_sha256"):
            row["reason"] = "R1 did not produce a committed assessment; no automatic R2"
        elif not isinstance(candidate, dict) or not _source_binding_valid(report, candidate):
            row.update({"state": "blocked", "reason": "candidate source binding does not match the fixed scan report"})
        elif _severity(candidate) < 4:
            row["reason"] = "conditional R2 is reserved for critical/high severity candidates"
        else:
            try:
                result = ops.result(operation["id"])
                binding = result.get("binding", {})
                if (binding.get("job_id") != job["id"]
                        or binding.get("candidate_id") != candidate_id
                        or binding.get("report_sha256") != job["report_sha256"]
                        or binding.get("source_sha256") != candidate.get("source_sha256")):
                    row.update({"state": "blocked", "reason": "R1 result binding changed or is incomplete"})
                else:
                    unresolved = _r2_source_obligations(result)
                    if not unresolved:
                        row["reason"] = "R1 left no unresolved source-reviewable obligation"
                    else:
                        row.update({"state": "eligible", "reason": None,
                                    "unresolved_source_obligations": len(unresolved)})
                        eligible.append((candidate, operation, result, unresolved, row))
            except Exception as exc:
                row.update({"state": "blocked", "reason": "R1 result unavailable: " + type(exc).__name__})
        manifest.append(row)
    eligible.sort(key=lambda item: (
        -len(item[3]), -_severity(item[0]), item[0].get("file", ""),
        int(item[0].get("line") or 0), item[0]["id"],
    ))
    limit = int(authorization["snapshot"].get("r2_candidate_limit", 0))
    selected = eligible[:limit] if not auth_error else []
    selected_ids = {item[0]["id"] for item in selected}
    r2_preview_spec = {
        "mode": "tool_agent", "max_steps": 2, "max_output_tokens": 1000,
        "max_total_input_tokens": 36000, "max_total_output_tokens": 5200,
        "timeout_seconds": 240, "max_provider_retries": 1,
        "consent_nonce": authorization["snapshot"].get("consent_nonce"),
    }
    selected_specs = []
    for candidate, r1_operation, _r1_result, unresolved, row in eligible:
        if candidate["id"] not in selected_ids:
            row.update({"state": "not_selected", "reason": "conditional R2 candidate budget reached"})
            continue
        try:
            prepared = agent._prepare_candidate_context(settings, store, job, report, candidate)
            preview = agent.consent_preview(
                settings, store, job, report, candidate, r2_preview_spec,
                provider, prepared=prepared,
            )
            if not preview.get("agent_execution", {}).get("eligible"):
                row.update({"state": "not_selected", "reason": "no eligible fixed-source read-only follow-up"})
                selected_ids.discard(candidate["id"])
                continue
            binding = preview["binding"]
            selected_specs.append({
                **r2_preview_spec, "job_id": job["id"], "candidate_id": candidate["id"],
                "case_id": None, "experiment_id": None, "source_submission_approved": True,
                "source_submission_approved_at": now(),
                "source_consent_sha256": preview["consent_sha256"],
                "consent_preview_version": agent.CONSENT_PREVIEW_VERSION,
                "redaction_policy_version": agent.REDACTION_POLICY_VERSION,
                "provider": provider.provider, "provider_model": provider.model,
                "provider_host": provider.endpoint_host, "provider_fingerprint": provider.fingerprint,
                "prompt_version": agent.PROMPT_VERSION, "tool_policy_version": agent.TOOL_POLICY_VERSION,
                "candidate_source_sha256": binding.get("source_sha256"),
                "source_commit": binding["commit"], "report_sha256": binding["report_sha256"],
                "batch_id": batch_id, "batch_consent_sha256": batch["batch_consent_sha256"],
                "smart_triage_batch_id": batch_id,
                "triage_authorization_sha256": authorization["consent_sha256"],
                "r1_operation_id": r1_operation["id"],
                "r1_result_sha256": r1_operation["result_sha256"],
                "r2_unresolved_obligation_indices": unresolved,
                "r2_reason": "critical/high severity with unresolved source-reviewable obligations after R1",
            })
            row.update({"state": "selected", "reason": "critical/high severity with unresolved source-reviewable obligations after R1"})
        except Exception as exc:
            row.update({"state": "not_selected", "reason": "R2 source preview unavailable: " + type(exc).__name__})
            selected_ids.discard(candidate["id"])
    if auth_error:
        status = "blocked_authorization_changed"
    elif selected_specs:
        status = "budget_limited" if len(eligible) > limit else "queued"
    elif any(row.get("state") == "blocked" for row in manifest) or eligible:
        status = "failed_selection"
    else:
        status = "not_needed"
    decision_sha256 = _digest({
        "batch_id": batch_id, "authorization_sha256": authorization["consent_sha256"],
        "report_sha256": job.get("report_sha256"),
        "r1_results": sorted((item["id"], item.get("result_sha256"), item["status"])
                             for item in r1_operations),
        "candidate_manifest": manifest,
        "selected_consent": [spec["source_consent_sha256"] for spec in selected_specs],
        "status": status,
    })
    saved, operations = ops.create_authorized_r2_batch(
        batch_id, decision_sha256, manifest, selected_specs, status, error=auth_error)
    if operations:
        store.event(job["id"], "triage_r2_queued",
                    "Conditional R2 queued " + str(len(operations))
                    + " critical/high candidate(s); other findings remain candidates or unknown")
    elif saved.get("r2_status") == "blocked_authorization_changed":
        store.event(job["id"], "triage_r2_blocked",
                    saved.get("r2_error") or "Task-level source-egress authorization changed before R2")
    return saved

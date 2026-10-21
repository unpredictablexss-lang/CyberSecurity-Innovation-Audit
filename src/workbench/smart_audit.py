from __future__ import annotations

import hashlib
import json
from . import agent, service
from .store import now
from .triage_limits import (MAX_TRIAGE_CANDIDATES_PER_ENDPOINT,
                            R1_CANDIDATE_SELECTION_POLICY, R1_OVERFLOW_POLICY)

RISK_POLICY_VERSION = "ohscanner-evidence-risk-tiers-0.3.0"


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def _severity(candidate):
    # Use the *same* tentative tier that the risk API displays. The scanner
    # currently emits severity='unassessed'; otherwise AI routing would ignore
    # a CWE-based high-risk label shown in the UI.
    # This changes scheduling priority only, not confidence/verification.
    value = severity_metadata(candidate)["severity"]
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
        value, 0
    )


def _root_cause_group_id(candidate, report_sha256):
    """Group only exact same-source duplicates; nearby/similar findings stay separate."""
    material = "\0".join(str(value or "") for value in (
        report_sha256, candidate.get("detector_id"), candidate.get("detector_version"),
        candidate.get("rule_id"), candidate.get("file"), candidate.get("line"),
        candidate.get("symbol"), candidate.get("source_sha256")))
    return "rc-" + hashlib.sha256(material.encode()).hexdigest()[:20]


SEVERITY_LABELS = {
    "critical": "严重", "high": "高危", "medium": "中危",
    "low": "低危", "info": "提示", "unknown": "未分级",
}

# Conservative *type-based* triage display only. These are NOT CVSS scores,
# demonstrated exploitability, known vulnerable versions, or product impact.
# Missing/ambiguous CWE mappings always stay ungraded.
CWE_TYPE_SEVERITY = {
    "CWE-22": "high",    # path traversal (potential access boundary)
    "CWE-78": "high",    # OS command injection
    "CWE-94": "high",    # code injection
    "CWE-119": "high",   # memory bounds
    "CWE-125": "high",   # out-of-bounds read
    "CWE-415": "high",   # double free
    "CWE-416": "high",   # use after free
    "CWE-787": "high",   # out-of-bounds write
    "CWE-862": "high",   # missing authorization
    "CWE-863": "high",   # incorrect authorization
    "CWE-129": "medium", # improper array index
    "CWE-190": "medium", # integer overflow
    "CWE-191": "medium", # integer underflow
    "CWE-200": "medium", # information exposure
    "CWE-319": "medium", # cleartext transmission
    "CWE-362": "medium", # race condition
    "CWE-400": "medium", # resource exhaustion
    "CWE-476": "medium", # null dereference
    "CWE-522": "medium", # insufficient credentials protection
    "CWE-532": "medium", # sensitive information in log
    "CWE-681": "medium", # numeric conversion
    "CWE-732": "medium", # incorrect permission assignment
    "CWE-770": "medium", # unrestricted resource allocation
}


def severity_metadata(candidate):
    """Return an *unverified* risk-type estimate, not a verified impact score.

    Scanner contract currently sets ToolDiagnostic.severity='unassessed'.
    A CWE can supply an explicitly labeled heuristic tier for user triage;
    it must never influence evidence confidence or confirmation gates.
    """
    value = str(candidate.get("severity") or "").lower()
    if value in SEVERITY_LABELS and value != "unknown":
        return {
            "severity": value, "severity_label": SEVERITY_LABELS[value],
            "severity_evidence": "detector_preliminary_unverified",
            "severity_basis": None,
        }
    for field in ("consequence_cwe", "candidate_cwe"):
        cwe = candidate.get(field)
        if isinstance(cwe, str) and cwe in CWE_TYPE_SEVERITY:
            value = CWE_TYPE_SEVERITY[cwe]
            return {
                "severity": value, "severity_label": SEVERITY_LABELS[value],
                "severity_evidence": "cwe_type_heuristic_unverified",
                "severity_basis": cwe,
            }
    return {
        "severity": "unknown", "severity_label": SEVERITY_LABELS["unknown"],
        "severity_evidence": "insufficient_evidence",
        "severity_basis": None,
    }


def _select_r1_candidates(eligible, candidate_count, limit):
    """Select the deterministic first R1 set, failing closed above the endpoint cap."""
    if candidate_count > MAX_TRIAGE_CANDIDATES_PER_ENDPOINT:
        return [], True
    ordered = sorted(eligible, key=lambda item: (
        -item[2], -_severity(item[0]), item[0].get("file", ""),
        int(item[0].get("line") or 0), item[0]["id"],
    ))
    return ordered[:limit], False


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
            candidate = candidate_by_id.get(candidate_id)
            signal = (_agent_signal(ops, operation, job, report, candidate)
                      if candidate else None)
            operation_by_candidate.setdefault(candidate_id, []).append({
                "operation_id": operation["id"],
                "status": operation["status"],
                "mode": operation.get("mode"),
                "result_sha256": operation.get("result_sha256"),
                "cancel_requested": operation.get("cancel_requested", False),
                "agent_signal": signal,
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
        operations = operation_by_candidate.get(original["id"], [])
        agent_signal = next((item["agent_signal"] for item in reversed(operations)
                             if item.get("agent_signal")), None)
        agent_chain_complete = bool(agent_signal and agent_signal.get("evidence_chain_complete"))
        contrary_reviewed = bool(
            bound and obligations and gate_review
            and gate_review.get("disposition") == "likely_noise"
            and all(row.get("disposition") == "contrary_evidence"
                    for row in gate_review.get("obligation_reviews", []) if isinstance(row, dict))
        )
        confidence_basis = None
        ai_evidence = _agent_source_evidence(ops, job, report, candidate, job_agent_operations)
        if not bound:
            tier = "unknown_source_binding"
            reasons = ["candidate source identity does not match the immutable report inventory"]
        elif manual_status in {"likely_false_positive", "refuted"} or contrary_reviewed:
            tier = "low_priority_manual"
            reasons = ["a human marked this item as refuted or low-priority; this is not a safety verdict"]
        elif ai_evidence:
            confidence_basis = "ai_source_evidence"
            tier = "high_confidence_candidate"
            reasons = ["AI 在固定源码中给出带可定位引文的支持性判断；仍需人工复核"]
        elif gate_complete:
            tier = "high_confidence_candidate"
            confidence_basis = "human_r0"
            reasons = ["固定源码与报告哈希一致；人工 R0 已逐项引用复核全部证据义务。漏洞仍是候选。"]
        elif agent_chain_complete:
            tier = "high_confidence_candidate"
            confidence_basis = "agent_evidence_graph"
            reasons = ["Agent 的固定源码调查、跨文件义务引用、独立反证和报告校验均完成；引用语义与产品影响仍待人工复核。"]
        else:
            confidence_basis = None
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
        root_group = _root_cause_group_id(original, job.get("report_sha256"))
        items.append({
            "candidate_id": original["id"], "root_cause_group_id": root_group,
            "file": original.get("file"),
            "line": original.get("line"), "symbol": original.get("symbol"),
            "rule_id": original.get("rule_id"), "detector_id": original.get("detector_id"),
            "detector_version": original.get("detector_version"),
            "source_sha256": original.get("source_sha256"),
            "severity": original.get("severity", "unknown"),
            "evidence_level": "candidate", "vulnerability_state": "candidate",
            "risk_tier": tier, "risk_tier_label": tier_labels[tier],
            "confidence_basis": confidence_basis,
            # Severity (potential impact) is orthogonal to evidence confidence.
            # Neither the detector nor a model is permitted to confirm a product flaw.
            **severity_metadata(original),
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
            "agent_signal": agent_signal,
            "report_sha256": job.get("report_sha256"),
        })
    tier_order = {"high_confidence_candidate": 0, "further_validation": 1,
                  "unknown_source_binding": 2, "low_priority_manual": 3}
    items.sort(key=lambda item: (tier_order[item["risk_tier"]],
                                 -item["obligations_open"],
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
            "Unreviewed, skipped, per-request-limited, partial, or unknown items are not safe and remain visible as untriaged or requiring validation.",
            "Validated vulnerabilities are counted only through the existing human assessment and passed runtime-reachability gate; this static risk view does not set that state.",
        ],
    }


def _agent_evidence_chain_gate(result, expected, candidate):
    """Qualify a source-bound, cross-file Agent trace as a high-priority candidate only.

    This gate checks completeness and provenance, not whether a citation semantically
    proves the model claim or whether a product entry point is reachable.
    """
    def fail(reason):
        return False, reason

    if not isinstance(result, dict) or result.get("mode") != "tool_agent":
        return fail("tool-agent investigation is missing")
    if (result.get("vulnerability_state") != "candidate"
            or type(result.get("validated_vulnerability")) is not int
            or result.get("validated_vulnerability") != 0):
        return fail("product state is not candidate-only")
    graph = result.get("evidence_graph")
    if not isinstance(graph, dict):
        return fail("server-authored evidence graph is missing")
    graph_binding = graph.get("binding")
    if not isinstance(graph_binding, dict):
        return fail("evidence graph source binding is missing")
    for key in ("job_id", "repository", "commit", "report_sha256", "candidate_id"):
        if not expected.get(key) or graph_binding.get(key) != expected.get(key):
            return fail("evidence graph does not match the fixed scan binding")
    for key in ("tree", "snapshot_sha256"):
        if expected.get(key) is not None and graph_binding.get(key) != expected.get(key):
            return fail("evidence graph does not match the fixed source snapshot")
    if graph_binding.get("source_scope") != "fixed_scan_commit":
        return fail("evidence graph source scope is not fixed")
    if (graph.get("product_state") != "candidate"
            or type(graph.get("validated_vulnerability")) is not int
            or graph.get("validated_vulnerability") != 0):
        return fail("evidence graph does not preserve candidate-only status")
    unresolved = graph.get("unresolved_references")
    if not isinstance(unresolved, list) or unresolved:
        return fail("one or more graph references remain unresolved")

    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return fail("evidence graph nodes or edges are unavailable")
    node_by_id = {node.get("id"): node for node in nodes
                  if isinstance(node, dict) and isinstance(node.get("id"), str)}
    required_stages = {
        "collect_fixed_source_evidence": {"completed"},
        "primary_source_triage": {"accepted"},
        "independent_skeptic": {"completed"},
        "candidate_report_and_poc_draft": {"completed"},
        "validate_report": {"accepted"},
    }
    stage_status = {node.get("stage_id"): node.get("status") for node in nodes
                    if isinstance(node, dict) and node.get("node_type") == "workflow_stage"}
    if any(stage_status.get(stage) not in statuses
           for stage, statuses in required_stages.items()):
        return fail("one or more investigation stages are incomplete")

    assessment = result.get("agent_assessment")
    assessment = assessment if isinstance(assessment, dict) else {}
    if assessment.get("assessment") != "likely_true_positive":
        return fail("Agent did not complete a positive source-level triage")
    if not isinstance(assessment.get("unsupported_claims"), list) or assessment["unsupported_claims"]:
        return fail("unsupported claims remain")
    verdict = result.get("agent_verdict")
    if (not isinstance(verdict, dict) or verdict.get("status") != "confirmed"
            or verdict.get("confidence") != "high"
            or verdict.get("scope") != "fixed_source_code"
            or verdict.get("product_status") != "unknown"):
        return fail("server-derived fixed-source evidence gate did not pass")

    initial = result.get("initial_evidence")
    initial = initial if isinstance(initial, dict) else {}
    context = initial.get("context")
    context = context if isinstance(context, dict) else {}
    obligations = context.get("evidence_obligations")
    reviews = assessment.get("obligation_reviews")
    if (not isinstance(obligations, list) or not obligations
            or not isinstance(reviews, list) or len(reviews) != len(obligations)):
        return fail("not every static evidence obligation has a review")
    source_edges = [edge for edge in edges if isinstance(edge, dict)
                    and edge.get("type") == "validated_citation_reference"
                    and edge.get("source") == "stage:primary_source_triage"]
    review_indices = [row.get("obligation_index") for row in reviews if isinstance(row, dict)]
    expected_indices = set(range(len(obligations)))
    if (len(review_indices) != len(obligations)
            or any(not isinstance(index, int) or isinstance(index, bool)
                   for index in review_indices)
            or set(review_indices) != expected_indices):
        return fail("evidence obligation reviews are missing or duplicated")
    bound_file_names = set()
    for row in reviews:
        if (not isinstance(row, dict) or row.get("disposition") != "evidence_found"
                or not isinstance(row.get("obligation_index"), int)
                or not isinstance(row.get("citations"), list) or not row["citations"]):
            return fail("an evidence obligation is unresolved or lacks a source citation")
        for citation in row["citations"]:
            if not isinstance(citation, dict):
                return fail("an obligation citation is malformed")
            evidence_id, file_name = citation.get("evidence_id"), citation.get("file")
            start, end = citation.get("line_start"), citation.get("line_end")
            if (not isinstance(evidence_id, str) or not isinstance(file_name, str)
                    or not isinstance(start, int) or isinstance(start, bool)
                    or not isinstance(end, int) or isinstance(end, bool)
                    or end < start):
                return fail("an obligation citation has no fixed file and line range")
            target_id = "evidence:" + evidence_id
            target = node_by_id.get(target_id)
            matching_edge = any(
                edge.get("target") == target_id and edge.get("file") == file_name
                and edge.get("line_start") == start and edge.get("line_end") == end
                for edge in source_edges)
            if (not matching_edge or not isinstance(target, dict)
                    or target.get("node_type") != "fixed_source_evidence"
                    or target.get("status") != "available"):
                return fail("an obligation citation is not bound to available fixed-source lines")
            source_binding = target.get("source_binding")
            files = source_binding.get("files", []) if isinstance(source_binding, dict) else []
            file_binding = next((item for item in files if isinstance(item, dict)
                                 and item.get("file") == file_name), None)
            source_hash = file_binding.get("source_sha256") if isinstance(file_binding, dict) else None
            if (not file_binding or file_binding.get("binding_status") != "bound"
                    or not isinstance(source_hash, str) or len(source_hash) != 64
                    or any(character not in "0123456789abcdef" for character in source_hash.lower())):
                return fail("an obligation citation source hash is not fixed")
            bound_file_names.add(file_name)
    if not any(file_name != candidate.get("file") for file_name in bound_file_names):
        return fail("the completed trace contains no cross-file source citation")

    skeptic = result.get("skeptic_review")
    skeptic = skeptic if isinstance(skeptic, dict) else {}
    skeptic_rows = skeptic.get("reviews")
    skeptic_indices = [row.get("obligation_index") for row in skeptic_rows
                       if isinstance(row, dict)] if isinstance(skeptic_rows, list) else []
    if (skeptic.get("status") != "completed" or not isinstance(skeptic_rows, list)
            or len(skeptic_rows) != len(obligations)
            or len(skeptic_indices) != len(obligations)
            or any(not isinstance(index, int) or isinstance(index, bool)
                   for index in skeptic_indices)
            or set(skeptic_indices) != expected_indices
            or any(not isinstance(row, dict)
                   or row.get("result") != "no_counterevidence_observed"
                   for row in skeptic_rows)):
        return fail("independent skeptic left contrary evidence or an obligation unresolved")

    artifact = result.get("artifact_generation")
    report = assessment.get("vulnerability_report")
    if (not isinstance(artifact, dict) or artifact.get("status") != "completed"
            or not isinstance(report, dict) or report.get("status") != "draft_unverified"):
        return fail("candidate report stage is incomplete")
    draft_edges = [edge for edge in edges if isinstance(edge, dict)
                   and edge.get("type") == "draft_citation_reference"
                   and edge.get("source") == "stage:candidate_report_and_poc_draft"]
    if not draft_edges:
        return fail("candidate report has no fixed-source citation")
    return True, "all source trace stages and cross-file citations are complete; semantics and product impact remain for human review"


def _agent_signal(ops, operation, job, report, candidate):
    """Return a source-bound model tendency without promoting candidate state."""
    if not _source_binding_valid(report, candidate):
        return None
    if (operation.get("status") not in {"completed", "completed_with_limitations"}
            or not operation.get("result_sha256")):
        return None
    try:
        result = ops.result(operation["id"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    binding = result.get("binding") if isinstance(result, dict) else None
    if not isinstance(binding, dict):
        return None
    expected = {
        "job_id": job.get("id"), "repository": report.get("repository"),
        "commit": report.get("commit"), "tree": report.get("tree"),
        "snapshot_sha256": report.get("snapshot_sha256"),
        "report_sha256": job.get("report_sha256"),
        "candidate_id": candidate.get("id"), "file": candidate.get("file"),
        "source_sha256": candidate.get("source_sha256"),
    }
    if any(binding.get(key) != value for key, value in expected.items()):
        return None
    if (result.get("vulnerability_state") != "candidate"
            or type(result.get("validated_vulnerability")) is not int
            or result.get("validated_vulnerability") != 0):
        return None
    assessment_record = result.get("agent_assessment")
    assessment = assessment_record.get("assessment") if isinstance(assessment_record, dict) else None
    labels = {
        "likely_true_positive": "模型倾向真实候选",
        "likely_false_positive": "模型倾向误报",
        "needs_more_evidence": "模型认为还需证据",
        "unknown": "模型判断未知",
    }
    if assessment not in labels:
        return None
    chain_complete, chain_reason = _agent_evidence_chain_gate(result, expected, candidate)
    signal = {"assessment": assessment, "label": labels[assessment],
              "operation_id": operation["id"], "human_review_required": True,
              "product_state": "candidate",
              "evidence_chain_complete": chain_complete,
              "evidence_chain_reason": chain_reason if chain_complete else None}
    if chain_complete:
        if (result.get("summary_provenance") == "server_generated_from_structured_triage"
                and isinstance(result.get("summary"), str)):
            signal["summary"] = result["summary"]
            signal["summary_provenance"] = "server_generated_from_structured_triage"
        locations = []
        seen_locations = set()
        for review in (assessment_record.get("obligation_reviews", [])
                       if isinstance(assessment_record, dict) else []):
            if not isinstance(review, dict):
                continue
            for citation in review.get("citations", []):
                if not isinstance(citation, dict):
                    continue
                file_name = citation.get("file")
                line_start, line_end = citation.get("line_start"), citation.get("line_end")
                if (not isinstance(file_name, str) or not file_name
                        or not isinstance(line_start, int) or isinstance(line_start, bool)
                        or not isinstance(line_end, int) or isinstance(line_end, bool)
                        or line_start < 1 or line_end < line_start):
                    continue
                key = (file_name, line_start, line_end)
                if key in seen_locations:
                    continue
                seen_locations.add(key)
                locations.append({"file": file_name, "line_start": line_start, "line_end": line_end})
        signal["evidence_locations"] = locations[:12]
        signal["evidence_locations_truncated_count"] = max(0, len(locations) - 12)
        signal["confidence_reason"] = (
            "每项静态证据义务都有固定源码引用，调查包含跨文件证据，并完成独立反证与报告校验。"
            "引用语义和产品影响仍需人工复核。"
        )
    return signal


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
    """Persist and queue only explicitly authorized eligible R1 tasks."""
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
    limit = int(snapshot["candidate_limit"])
    if len(candidates) > MAX_TRIAGE_CANDIDATES_PER_ENDPOINT:
        candidate_manifest = [{
            "candidate_id": candidate.get("id"),
            "file": candidate.get("file"),
            "line": candidate.get("line"),
            "source_sha256": candidate.get("source_sha256"),
            "state": "not_triaged",
            "reason": "fixed per-endpoint candidate cap exceeded; no Agent operations were queued",
        } for candidate in candidates]
        batch_consent = _digest({
            "task_authorization_sha256": authorization["consent_sha256"],
            "report_sha256": job["report_sha256"],
            "selection_policy": R1_CANDIDATE_SELECTION_POLICY,
            "overflow_policy": R1_OVERFLOW_POLICY,
            "actual_candidate_count": len(candidates),
            "authorized_candidate_count": limit,
            "queued_count": 0,
            "not_triaged_count": len(candidates),
            "candidate_manifest": candidate_manifest,
        })
        return ops.record_triage_batch({
            "id": batch_id, "audit_id": job["id"], "report_sha256": job["report_sha256"],
            "authorization_sha256": authorization["consent_sha256"],
            "batch_consent_sha256": batch_consent,
            "status": "candidate_limit_exceeded", "candidate_count": len(candidates),
            "selected_count": 0, "candidate_manifest": candidate_manifest,
            "operation_ids": [], "created_at": now(),
            "error": ("This fixed report contains " + str(len(candidates))
                      + " candidates, above the per-endpoint limit of "
                      + str(MAX_TRIAGE_CANDIDATES_PER_ENDPOINT)
                      + "; no Agent operation was queued. Narrow the source scope or create separately reviewed smaller audits."),
            "r2_status": "not_requested",
        })
    preview_spec = {
        **agent.bounded_agent_spec({"mode": "single_shot",
                                    "max_output_tokens": provider.request_output_tokens,
                                    "no_cumulative_token_ceiling": True}),
        "mode": "single_shot",
        "max_output_tokens": provider.request_output_tokens,
        "max_request_context_tokens": 65536,
        "max_request_context_bytes": agent.MAX_SMART_REQUEST_CONTEXT_BYTES,
        "request_timeout_seconds": 45,
        "provider_request_timeout_seconds": 45,
        "max_provider_retries": 1,
        "no_cumulative_token_ceiling": True,
        "continuous_investigation": False,
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
        row = {"candidate_id": candidate["id"],
               "root_cause_group_id": _root_cause_group_id(candidate, job.get("report_sha256")),
               "file": candidate.get("file"),
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
    representatives = {}
    deduplicated = []
    for item in eligible:
        group_id = item[3]["root_cause_group_id"]
        if group_id not in representatives:
            representatives[group_id] = item
            deduplicated.append(item)
        else:
            representative = representatives[group_id][0][0]["id"]
            item[3].update({"state": "grouped_duplicate", "grouped_into_candidate_id": representative,
                            "reason": "exact source-bound duplicate grouped; original candidate remains unassessed"})
    eligible = deduplicated
    selected, overflowed = _select_r1_candidates(eligible, len(candidates), limit)
    if overflowed:
        raise AssertionError("candidate cap must fail closed before source triage")
    selected_ids = {item[0]["id"] for item in selected}
    for _, _, _, row in eligible:
        if row["candidate_id"] in selected_ids:
            row["state"] = "selected"
            row["reason"] = "selected by deterministic priority within the user-authorized candidate limit"
        else:
            row["state"] = "not_triaged"
            row["reason"] = "user-authorized candidate limit reached; not assessed as safe"
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
        "r2_status": "awaiting_r1" if selected else "not_needed",
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
    try:
        batch, _ = ops.create_authorized_triage_batch(record, child_specs)
    except ValueError as exc:
        if not str(exc).startswith("authorized triage queue capacity exceeded:"):
            raise
        for row in candidate_manifest:
            if row.get("state") == "selected":
                row["state"] = "not_triaged"
                row["reason"] = "authorized Agent queue capacity reached; split scope and review a fresh authorization"
        queue_record = {
            **record,
            "batch_consent_sha256": _digest({
                "task_authorization_sha256": authorization["consent_sha256"],
                "report_sha256": job["report_sha256"],
                "selection_policy": R1_CANDIDATE_SELECTION_POLICY,
                "queue_policy": "max_80000_authorized_auto_triage_operations",
                "candidate_count": len(candidates),
                "authorized_candidate_count": limit,
                "queued_count": 0,
                "not_triaged_count": len(candidates),
                "candidate_manifest": candidate_manifest,
            }),
            "status": "queue_limit_exceeded",
            "selected_count": 0,
            "candidate_manifest": candidate_manifest,
            "operation_ids": [],
            "r2_status": "not_requested",
            "error": str(exc) + "; no operations from this endpoint were queued; narrow scope or submit a separately previewed and authorized batch.",
        }
        return ops.record_triage_batch(queue_record)
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
        **agent.bounded_agent_spec({"mode": "tool_agent",
                                    "max_output_tokens": provider.request_output_tokens,
                                    "no_cumulative_token_ceiling": True}),
        "provider_request_timeout_seconds": 45, "max_provider_retries": 1,
        "continuous_investigation": False,
        "include_paths": list(job.get("spec", {}).get("include_paths", [])),
        "consent_nonce": authorization["snapshot"].get("consent_nonce"),
    }
    selected_specs = []
    for candidate, r1_operation, _r1_result, unresolved, row in eligible:
        if candidate["id"] not in selected_ids:
            row.update({"state": "not_selected", "reason": "user-authorized conditional R2 candidate limit reached"})
            continue
        try:
            candidate_r2_spec = {
                **r2_preview_spec,
                # Bind the exact child identity before computing source consent.
                # The Worker recomputes the digest from this persisted spec, so
                # preview and execution must observe the same R1/candidate/report.
                "job_id": job["id"],
                "candidate_id": candidate["id"],
                "report_sha256": job["report_sha256"],
                "r1_operation_id": r1_operation["id"],
                "r1_result_sha256": r1_operation["result_sha256"],
                "r2_unresolved_obligation_indices": unresolved,
            }
            prepared = agent._prepare_candidate_context(settings, store, job, report, candidate)
            preview = agent.consent_preview(
                settings, store, job, report, candidate, candidate_r2_spec,
                provider, prepared=prepared,
            )
            if not preview.get("agent_execution", {}).get("eligible"):
                row.update({"state": "not_selected", "reason": "no eligible fixed-source read-only follow-up"})
                selected_ids.discard(candidate["id"])
                continue
            binding = preview["binding"]
            selected_specs.append({
                **candidate_r2_spec, "job_id": job["id"], "candidate_id": candidate["id"],
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
                "continuous_investigation": False,
                "r2_reason": "critical/high severity with unresolved source-reviewable obligations after R1",
            })
            row.update({"state": "selected", "reason": "critical/high severity with unresolved source-reviewable obligations after R1"})
        except Exception as exc:
            row.update({"state": "not_selected", "reason": "R2 source preview unavailable: " + type(exc).__name__})
            selected_ids.discard(candidate["id"])
    if auth_error:
        status = "blocked_authorization_changed"
    elif limit == 0:
        status = "not_needed"
    elif selected_specs:
        status = "candidate_limit_reached" if len(eligible) > limit else "queued"
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

"""Deterministic, source-bound evidence graph for one Agent investigation."""
import hashlib
import json


def _sha256(value):
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _source_ranges(result):
    ranges = []
    if not isinstance(result, dict):
        return ranges
    file = result.get("file")
    start = result.get("start_line")
    end = result.get("end_line")
    if isinstance(file, str):
        row = {"file": file}
        if isinstance(start, int) and not isinstance(start, bool):
            row["line_start"] = start
        if isinstance(end, int) and not isinstance(end, bool):
            row["line_end"] = end
        ranges.append(row)
    matches = result.get("matches")
    if isinstance(matches, list):
        for match in matches:
            if not isinstance(match, dict) or not isinstance(match.get("file"), str):
                continue
            row = {"file": match["file"]}
            explicit_ranges = match.get("ranges")
            if isinstance(explicit_ranges, list) and explicit_ranges:
                for line_range in explicit_ranges:
                    if not isinstance(line_range, dict):
                        continue
                    first = line_range.get("start_line")
                    last = line_range.get("end_line", first)
                    if isinstance(first, int) and not isinstance(first, bool):
                        scoped = {"file": match["file"], "line_start": first}
                        if isinstance(last, int) and not isinstance(last, bool):
                            scoped["line_end"] = last
                        ranges.append(scoped)
                continue
            first = match.get("start_line", match.get("line"))
            last = match.get("end_line", first)
            if isinstance(first, int) and not isinstance(first, bool):
                row["line_start"] = first
            if isinstance(last, int) and not isinstance(last, bool):
                row["line_end"] = last
            ranges.append(row)
    unique = []
    seen = set()
    for row in ranges:
        key = (row["file"], row.get("line_start"), row.get("line_end"))
        if key not in seen:
            seen.add(key)
            unique.append(row)
    return unique[:32]


def build_evidence_graph(binding, initial_evidence, tool_calls, model_calls,
                         assessment, validation_status):
    """Build a hashable provenance DAG; its edges describe citation, not truth."""
    binding = binding if isinstance(binding, dict) else {}
    initial_evidence = initial_evidence if isinstance(initial_evidence, dict) else {}
    tool_calls = tool_calls if isinstance(tool_calls, list) else []
    model_calls = model_calls if isinstance(model_calls, list) else []
    assessment = assessment if isinstance(assessment, dict) else {}
    context = initial_evidence.get("context", {})
    context = context if isinstance(context, dict) else {}
    routing = context.get("evidence_routing", {})
    routing = routing if isinstance(routing, dict) else {}
    source_indices = set(routing.get("agent_source_review_indices", []))
    human_indices = set(routing.get("human_or_runtime_review_indices", []))
    unclassified_indices = set(routing.get("unclassified_indices", []))
    obligations = context.get("evidence_obligations", [])
    obligations = obligations if isinstance(obligations, list) else []
    reviews = assessment.get("obligation_reviews", [])
    reviews = reviews if isinstance(reviews, list) else []
    review_by_index = {row.get("obligation_index"): row
                       for row in reviews if isinstance(row, dict)}
    scope_base = {
        key: binding.get(key) for key in
        ("repository", "commit", "tree", "report_sha256", "candidate_id")
    }
    scope_base["source_sha256"] = binding.get("source_sha256")
    binding_sha256 = _sha256(scope_base)
    nodes = []
    edges = []
    evidence_ids = set()

    def add_node(kind, payload, preferred_id=None):
        body = {"kind": kind, **payload}
        node_id = preferred_id or kind + ":" + _sha256(body)[:20]
        body["id"] = node_id
        body["record_sha256"] = _sha256(body)
        nodes.append(body)
        return node_id

    candidate_node = add_node("candidate", {
        "candidate_id": binding.get("candidate_id"),
        "binding_sha256": binding_sha256,
        "scope": scope_base,
        "summary": "静态扫描候选固定到一次报告、提交和源码版本。",
    }, "candidate:" + str(binding.get("candidate_id") or _sha256(scope_base)[:20]))

    initial_id = initial_evidence.get("evidence_id")
    if isinstance(initial_id, str) and initial_id:
        initial_range = {
            "file": initial_evidence.get("file"),
            "line_start": initial_evidence.get("source_excerpt_start_line"),
            "line_end": initial_evidence.get("source_excerpt_end_line"),
        }
        initial_node = add_node("source_evidence", {
            "evidence_id": initial_id,
            "evidence_kind": "source_code",
            "result_sha256": initial_evidence.get("context_sha256"),
            "source_sha256": initial_evidence.get("source_sha256"),
            "scope": {**scope_base, "source_sha256": initial_evidence.get("source_sha256"),
                      "ranges": [initial_range]},
            "summary": "初始候选源码上下文；引句语义仍需人工复核。",
        }, "evidence:" + initial_id)
        evidence_ids.add(initial_id)
        edges.append({"from": candidate_node, "to": initial_node,
                      "relation": "fixed_source_context"})

    source_tool_evidence = []
    caller_site_evidence = []
    contrary_count = 0
    unresolved_count = 0
    for call in tool_calls:
        if not isinstance(call, dict):
            continue
        evidence_id = call.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            continue
        evidence_ids.add(evidence_id)
        result = call.get("result")
        ranges = _source_ranges(result)
        evidence_node = add_node("source_evidence" if call.get("evidence_kind") == "source_code"
                                 else "tool_record", {
            "evidence_id": evidence_id,
            "evidence_kind": call.get("evidence_kind", "unknown"),
            "tool": call.get("tool"),
            "status": call.get("status", "unknown"),
            "result_sha256": call.get("result_sha256"),
            "scope": {**scope_base, "ranges": ranges},
            "summary": ("固定提交源码工具返回的定位记录。" if call.get("evidence_kind") == "source_code"
                        else "只读工具元数据；不作为源码证明。"),
        }, "evidence:" + evidence_id)
        source_tool_evidence.append(evidence_node)
        if call.get("tool") == "trace_fixed_caller_sites":
            caller_site_evidence.append(evidence_node)
        edges.append({"from": candidate_node, "to": evidence_node,
                      "relation": ("syntax_caller_site_search"
                                   if call.get("tool") == "trace_fixed_caller_sites"
                                   else "fixed_commit_lookup")})
    model_node_ids = []
    for index, call in enumerate(model_calls, start=1):
        if not isinstance(call, dict):
            continue
        model_node = add_node("model_step", {
            "step": index,
            "request_sha256": call.get("request_sha256"),
            "response_sha256": call.get("response_sha256"),
            "request_phase": call.get("request_phase"),
            "response_status": call.get("response_status"),
            "usage": call.get("usage"),
            "binding_sha256": binding_sha256,
            "summary": "模型请求与响应摘要，仅作为流程审计记录。",
        }, "model-step:" + str(index))
        model_node_ids.append(model_node)

    claim_nodes = []
    claims = assessment.get("supported_claims", [])
    claims = claims if isinstance(claims, list) else []
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            continue
        claim_hash = _sha256({"claim": claim.get("claim")})
        citation_ids = [row.get("evidence_id") for row in claim.get("citations", [])
                        if isinstance(row, dict) and row.get("evidence_id") in evidence_ids]
        claim_node = add_node("model_claim", {
            "claim_index": index,
            "claim_sha256": claim_hash,
            "obligation_indices": claim.get("obligation_indices", []),
            "citation_evidence_ids": citation_ids,
            "status": "model_assertion_semantics_unverified",
            "summary": "结构化模型主张；图中的引用边不代表语义已证实。",
        }, "claim:" + str(index) + ":" + claim_hash[:12])
        claim_nodes.append(claim_node)
        for cited_id in citation_ids:
            edges.append({"from": claim_node, "to": "evidence:" + cited_id,
                          "relation": "model_cites_unverified"})
    obligation_nodes = []
    for index, obligation in enumerate(obligations):
        review = review_by_index.get(index, {})
        disposition = review.get("disposition", "unresolved") if isinstance(review, dict) else "unresolved"
        if disposition == "contrary_evidence":
            contrary_count += 1
        if disposition == "unresolved":
            unresolved_count += 1
        route = ("source_reviewable" if index in source_indices else
                 "human_or_runtime" if index in human_indices else
                 "unclassified" if index in unclassified_indices else "not_routed")
        citation_ids = [row.get("evidence_id") for row in review.get("citations", [])
                        if isinstance(row, dict) and row.get("evidence_id") in evidence_ids] if isinstance(review, dict) else []
        obligation_id = add_node("evidence_obligation", {
            "obligation_index": index,
            "route": route,
            "disposition": disposition,
            "citation_evidence_ids": citation_ids,
            "status": "model_triage_unverified",
            "summary": "义务分诊标签不等于满足条件或漏洞事实。",
        }, "obligation:" + str(index))
        obligation_nodes.append(obligation_id)
        for cited_id in citation_ids:
            edges.append({"from": obligation_id, "to": "evidence:" + cited_id,
                          "relation": "model_cites_unverified"})

    trace_calls = [call for call in tool_calls
                   if isinstance(call, dict) and call.get("tool") == "trace_fixed_caller_sites"]
    trace_results = [call.get("result") for call in trace_calls if isinstance(call.get("result"), dict)]
    trace_has_sites = any(isinstance(result.get("matches"), list) and result["matches"]
                          for result in trace_results)
    trace_partial = any(result.get("status") == "partial_parse_only"
                        or result.get("partial_parse_files") for result in trace_results)
    trace_incomplete = any(result.get("truncated") or result.get("files_skipped_oversize")
                           or result.get("status") == "result_too_large" for result in trace_results)
    if not trace_calls:
        trace_status = "not_performed"
    elif trace_has_sites and not trace_incomplete:
        trace_status = "evidence_collected"
    elif trace_partial or trace_incomplete:
        trace_status = "partial_parse"
    else:
        trace_status = "search_completed_no_callsite"
    counterevidence_status = (
        "structured_review_recorded_unverified"
        if validation_status == "accepted" and reviews
        else "not_attested" if validation_status == "accepted" else "incomplete")
    stages = [
        ("candidate_routing", "completed", "静态候选与固定源码身份已绑定。", [], []),
        ("root_cause_hypothesis",
         "recorded" if validation_status == "accepted" and claims else "incomplete",
         "结构化模型假设已记录；解释仍需人工判断。",
         model_node_ids, claim_nodes),
        ("bounded_cross_file_trace",
         trace_status,
         "只记录固定清单中解析完整的 C/C++ 语法调用点；未解析调度目标与运行可达性。",
         model_node_ids, caller_site_evidence),
        ("counterevidence_search",
         counterevidence_status,
         "只记录模型提交的结构化义务处置；源码读取不证明已主动搜索反证，系统也不验证搜索是否穷尽。",
         model_node_ids, obligation_nodes),
        ("official_patch_version_comparison", "not_available",
         "本次操作没有绑定官方公告、受影响版本与修复补丁证据。",
         [], []),
        ("evidence_arbitration",
         "structure_validated_semantics_unverified" if validation_status == "accepted" else "incomplete",
         "服务端校验结构和引文范围；主张语义、产品可达性与影响仍未确认。",
         [], claim_nodes + obligation_nodes),
    ]
    stage_ids = []
    previous_stage = None
    for stage_id, status, summary, model_refs, evidence_refs in stages:
        stage = add_node("workflow_stage", {
            "stage": stage_id,
            "status": status,
            "summary": summary,
            "binding_sha256": binding_sha256,
            "model_step_ids": model_refs,
            "evidence_node_ids": evidence_refs,
            "source_scope": scope_base,
        }, "stage:" + stage_id)
        stage_ids.append(stage)
        if previous_stage:
            edges.append({"from": previous_stage, "to": stage,
                          "relation": "depends_on"})
        previous_stage = stage
    for claim_node in claim_nodes:
        edges.append({"from": "stage:root_cause_hypothesis", "to": claim_node,
                      "relation": "records_hypothesis"})
    for obligation_node in obligation_nodes:
        edges.append({"from": "stage:counterevidence_search", "to": obligation_node,
                      "relation": "records_unverified_review"})
        edges.append({"from": "stage:evidence_arbitration", "to": obligation_node,
                      "relation": "arbitrates_structure_only"})
    for evidence_node in caller_site_evidence:
        edges.append({"from": "stage:bounded_cross_file_trace", "to": evidence_node,
                      "relation": "records_syntactic_call_sites"})
    for model_node in model_node_ids:
        edges.append({"from": "stage:root_cause_hypothesis", "to": model_node,
                      "relation": "uses_model_step"})

    core = {
        "schema_version": "ohscanner-evidence-graph-0.2.0",
        "binding": scope_base,
        "binding_sha256": binding_sha256,
        "root_node_id": candidate_node,
        "product_state": "candidate",
        "validated_vulnerability": 0,
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "source_tool_evidence_count": len(source_tool_evidence) + (1 if initial_id else 0),
            "supported_claim_count": len(claim_nodes),
            "contrary_evidence_obligation_count": contrary_count,
            "unresolved_obligation_count": unresolved_count,
            "semantic_support": "unverified_by_machine",
            "nday_1day_classification": "unknown",
            "official_patch_evidence": "not_collected",
        },
    }
    core["graph_sha256"] = _sha256(core)
    return core
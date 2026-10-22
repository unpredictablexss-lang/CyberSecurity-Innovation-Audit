"""Deterministic review order from accepted, report-bound initial AI assessments."""
from . import service
from .agent import _candidate_evidence_routing
from .smart_audit import severity_metadata

VERSION = "initial-investigation-priority-v1"
SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def investigation_priority(report, job_id, report_sha256, operations, read_result):
    candidates = service.findings(report)
    latest, deep = {}, {}
    # Stable persisted insertion order resolves equal-time batch entries; no page-local ranking.
    for operation in operations:
        target = latest if operation.get("mode") == "single_shot" else deep
        target[operation["candidate_id"]] = operation
    rows = []
    for candidate in candidates:
        identity = candidate["id"]
        operation = latest.get(identity)
        row = {"candidate_id": identity, "file": candidate["file"], "line": candidate["line"],
               "rule_id": candidate["rule_id"], "severity": severity_metadata(candidate)["severity"],
               "cwe": candidate.get("consequence_cwe") or candidate.get("candidate_cwe"),
               "assessment": None, "operation_id": (operation or {}).get("id"),
               "result_sha256": (operation or {}).get("result_sha256"),
               "priority": "not_analyzed", "priority_label": "尚未初判", "reasons": [],
               "source_claim_count": 0, "source_unresolved_count": 0, "source_gaps": [],
               "eligible": False, "auto_select": False, "failure_code": None,
               "deep_status": (deep.get(identity) or {}).get("status"),
               "deep_operation_id": (deep.get(identity) or {}).get("id")}
        if not operation:
            row["reasons"] = ["尚未执行 AI 初步分析，不能据此判断调查优先级。"]
        elif operation["status"] in {"queued", "running"}:
            row.update(priority="pending", priority_label="初判处理中", reasons=["等待本候选最新一次初判完成。"])
        else:
            try:
                result = read_result(operation["id"])
                binding = result.get("binding") or {}
                if any(binding.get(key) != value for key, value in {
                    "job_id": job_id, "candidate_id": identity, "report_sha256": report_sha256}.items()):
                    raise ValueError("source binding mismatch")
                if result.get("structured_answer_validation") != "accepted" or result.get("model_answer_retained") is False:
                    row["failure_code"] = result.get("structured_answer_validation_error_code") or "initial_answer_not_accepted"
                    raise ValueError("initial answer not accepted")
                assessment = result.get("agent_assessment") or {}
                row["assessment"] = assessment.get("assessment")
                obligations = candidate.get("evidence", {}).get("obligations", [])
                routing = _candidate_evidence_routing(report, candidate, obligations)
                source_indices = set(routing.get("agent_source_review_indices", []))
                reviews = assessment.get("obligation_reviews", [])
                unresolved = [x for x in reviews if x.get("obligation_index") in source_indices
                              and x.get("disposition") == "unresolved"]
                claims = [x for x in assessment.get("supported_claims", []) if x.get("citations")
                          and set(x.get("obligation_indices", [])).intersection(source_indices)]
                row["source_gaps"] = [{"obligation_index": x["obligation_index"],
                    "description": str(obligations[x["obligation_index"]].get("description") or
                                       obligations[x["obligation_index"]].get("kind") or "待补充源码证据")[:500]}
                    for x in unresolved if 0 <= x["obligation_index"] < len(obligations)]
                row.update(source_claim_count=len(claims), source_unresolved_count=len(unresolved),
                           eligible=bool(source_indices), priority="supplement", priority_label="待补证")
                if not source_indices:
                    row.update(priority="human_review", priority_label="需人工 / 运行时验证",
                               reasons=["剩余问题不能仅靠只读源码调查解决，建议人工核验或设计运行验证。"])
                elif row["assessment"] == "likely_false_positive":
                    row.update(priority="defer", priority_label="暂缓调查",
                               reasons=["初判倾向误报，已有相反源码线索；可人工复核依据后再决定。"])
                elif unresolved and claims:
                    row.update(priority="investigate", priority_label="优先调查",
                               reasons=[f"已有 {len(claims)} 条带引用的源码主张，仍有 {len(unresolved)} 项源码问题未解决，继续追查可补充关键证据。"])
                elif row["assessment"] == "likely_true_positive" and claims:
                    row.update(priority="investigate", priority_label="优先调查",
                               reasons=["初判倾向真实候选且有源码引用，建议追查调用关系与反证；产品影响仍待核验。"])
                elif unresolved:
                    row["reasons"] = [f"有 {len(unresolved)} 项可继续查源码的问题，但已有支持线索较少，排在证据较充分的候选之后。"]
                else:
                    row["reasons"] = ["初判尚不足以形成明确调查方向，可先查看证据缺口再决定是否追查。"]
                if row["severity"] in {"high", "critical"}:
                    row["reasons"].append("静态等级为高危或严重，仅作潜在影响的辅助排序依据。")
                row["auto_select"] = row["eligible"] and row["priority"] in {"investigate", "supplement"}
            except (KeyError, ValueError, OSError, TypeError):
                row.update(priority="incomplete", priority_label="初判未完成", eligible=False,
                           reasons=["初判调用、结构或来源校验未通过；请先查看失败原因或重新初判，不能按低风险处理。"])
                row["failure_code"] = row["failure_code"] or "initial_result_unavailable_or_mismatched"
        if row["deep_status"] in {"queued", "running"}:
            row.update(eligible=False, auto_select=False)
            row["reasons"].append("本候选已有深入追查正在排队或运行，请勿重复提交。")
        elif deep.get(identity):
            row["auto_select"] = False
            row["reasons"].append("已有深入追查记录，一键推荐默认跳过；如需重查可查看记录后手动选择。")
        rows.append(row)
    order = {"investigate": 0, "supplement": 1, "human_review": 2, "defer": 3,
             "incomplete": 4, "pending": 5, "not_analyzed": 6}
    def sort_key(row):
        return (order[row["priority"]], -bool(row["source_claim_count"]),
                -SEVERITY.get(row["severity"], 0), row["file"], row["line"], row["candidate_id"])
    by_id = {row["candidate_id"]: row for row in rows}
    groups = []
    for cluster in service.finding_clusters(report):
        members = sorted([by_id[x["id"]] for x in cluster["candidates"]], key=sort_key)
        representative = next((x for x in members if x["auto_select"]), next((x for x in members if x["eligible"]), members[0]))
        groups.append({"group_id": cluster["cluster_id"], "file": cluster["file"],
                       "symbol": cluster["symbol"], "rule_id": cluster["rule_id"],
                       "grouping_basis": cluster["grouping_basis"], "root_cause_conclusion": "not_inferred",
                       "member_count": len(members), "members": members,
                       "representative": representative, "priority": representative["priority"],
                       "priority_label": representative["priority_label"],
                       "reasons": representative["reasons"], "auto_select": any(x["auto_select"] for x in members) and not any(x["deep_operation_id"] for x in members)})
    groups.sort(key=lambda group: sort_key(group["representative"]))
    rank = 0
    for group in groups:
        if group["priority"] in {"investigate", "supplement", "human_review", "defer"}:
            rank += 1; group["rank"] = rank
        else:
            group["rank"] = None
    return {"version": VERSION, "job_id": job_id, "report_sha256": report_sha256,
            "ranking_semantics": "调查顺序建议，不是漏洞成立概率；相似分组不代表同一根因。",
            "counts": {"candidates": len(rows), "groups": len(groups),
                       "analyzed": sum(x["priority"] in {"investigate", "supplement", "human_review", "defer"} for x in rows),
                       "incomplete": sum(x["priority"] == "incomplete" for x in rows),
                       "pending": sum(x["priority"] == "pending" for x in rows)},
            "groups": groups}

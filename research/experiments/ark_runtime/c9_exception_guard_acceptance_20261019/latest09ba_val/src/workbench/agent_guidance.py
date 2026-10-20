"""Conservative next-step hints for static-to-Agent candidate review.

This policy routes evidence work only. It never adjudicates a candidate, closes
an evidence obligation, or promotes a vulnerability state.
"""

_SOURCE_REVIEW_KINDS = frozenset({
    "callee_and_policy", "dispatch_binding",
    "descriptor_identity_mismatch", "descriptor_identity_unresolved",
    "receiver_and_guard_binding", "fd_origin_and_capacity",
    "capacity_and_alias_identity", "integer_range_and_signedness",
    "overflow_guard_dominance", "guard_dominance", "control_flow_dominance",
    "allocation_release_alias_state", "cross_function_alias",
    "cross_function_and_macro_context", "cross_function_and_container_transfer",
    "source_control_and_format_identity", "destination_capacity",
    "owner_alias_identity", "control_flow_reachability", "synchronization_proof",
    "argument_control", "not_implicitly_sanitised", "manifest_export_state",
    "native_parameter_check", "bounds_proof", "resolved_callee",
})
_HUMAN_REVIEW_KINDS = frozenset({
    "entry_reachability", "security_impact", "consequence",
    "entry_or_privilege_boundary", "attacker_control", "cia_impact",
    "trigger_conditions", "sensitive_operation_reachability",
    "thread_interleaving", "product_build_context", "compile_context",
    "parse_completeness_impact", "page_origin", "allocation_or_memory_consequence",
    "reachability", "impact",
})
_CLOSED_STATUSES = frozenset({"satisfied", "not_applicable"})
_COVERAGE_COMPLETE = frozenset({"completed", "complete", "analyzed"})


def recommend_investigation_route(obligations, *, scan_status, detector_status,
                                  analysis_status):
    """Suggest a bounded next step; unknown obligation kinds default to humans."""
    items = obligations if isinstance(obligations, list) else []
    source_indices = []
    human_indices = []
    unclassified_indices = []
    closed_count = 0

    for index, item in enumerate(items):
        if not isinstance(item, dict):
            kind = None
            status = "unknown"
        else:
            kind = item.get("kind") if isinstance(item.get("kind"), str) else None
            status = item.get("status")
            if not isinstance(status, str) or status not in {
                    "unknown", "missing", "satisfied", "not_applicable"}:
                status = "unknown"
        if kind not in _SOURCE_REVIEW_KINDS and kind not in _HUMAN_REVIEW_KINDS:
            human_indices.append(index)
            unclassified_indices.append(index)
            continue
        if status in _CLOSED_STATUSES:
            closed_count += 1
            continue
        if kind in _SOURCE_REVIEW_KINDS:
            source_indices.append(index)
        else:
            human_indices.append(index)

    if source_indices and human_indices:
        route = "agent_source_review_with_human_followup"
    elif source_indices:
        route = "agent_source_review"
    elif human_indices:
        route = "human_or_runtime_validation"
    else:
        route = "human_review"

    coverage_incomplete = not (
        scan_status in _COVERAGE_COMPLETE
        and detector_status in _COVERAGE_COMPLETE
        and analysis_status in _COVERAGE_COMPLETE
    )
    return {
        "policy_version": "static-to-agent-guidance-0.1",
        "route": route,
        "agent_source_review_indices": source_indices,
        "human_or_runtime_review_indices": human_indices,
        "unclassified_indices": unclassified_indices,
        "open_obligation_count": len(source_indices) + len(human_indices),
        "closed_obligation_count": closed_count,
        "coverage_incomplete": coverage_incomplete,
        "vulnerability_state": "candidate",
        "validated_vulnerability": 0,
        "note": (
            "Routing is based on the recorded obligation kind and status only. "
            "Agent-source indices identify questions for bounded fixed-source context gathering; "
            "the Agent cannot close obligations or prove semantic support. Human/runtime indices "
            "remain open. Unknown kinds default to human review. Coverage warnings remain separate "
            "from candidate-level analysis."
        ),
    }

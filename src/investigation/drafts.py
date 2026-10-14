"""Validation for LLM/Agent/human investigation drafts.

Drafts are untrusted review aids. Validation binds them to deterministic facts
and persisted evidence IDs, but never accepts a field capable of changing
candidate, obligation, review, case, or vulnerability status.
"""
from typing import Any, Mapping, Optional, Sequence
import re

from .contracts import InvestigationDraft, _exact_keys, _string, _string_list, _sha64

_HEX64 = re.compile(r"[a-f0-9]{64}")
_BUDGET_KEYS = {"input_tokens", "output_tokens", "tool_calls", "wall_clock_seconds"}
_PRODUCER_REQUIRED = {"kind"}
_PRODUCER_OPTIONAL = {
    "provider", "model", "model_version", "prompt_sha256", "tool_versions",
    "parameters", "failures", "retries", "external_run_id",
}
_CONTEXT_REQUIRED = {
    "fact_bundle_sha256", "report_sha256", "tool_call_ids",
    "tool_result_evidence_ids", "budget", "model_parameters",
}
_TOP_REQUIRED = {
    "schema_version", "draft_id", "candidate_id", "producer", "input_context",
    "claims", "assumptions", "missing_evidence", "recommended_probes",
    "limitations", "review_recommendations", "status", "can_promote",
}
_TOP_OPTIONAL = {"supersedes_draft_id", "created_at", "interpretation"}


class DraftValidationError(ValueError):
    """Raised when a proposed draft is malformed, unbound, or status-mutating."""


def _integer(value, name, *, minimum=0):
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise DraftValidationError(f"{name} must be an integer >= {minimum}")
    return value


def _validate_producer(value):
    _exact_keys(value, _PRODUCER_REQUIRED, _PRODUCER_OPTIONAL, "producer")
    kind = value["kind"]
    if kind not in {"human", "llm", "agent", "import"}:
        raise DraftValidationError("unsupported producer kind")
    if kind in {"llm", "agent"}:
        for key in (
            "provider", "model", "model_version", "prompt_sha256",
            "tool_versions", "parameters", "failures", "retries",
        ):
            if key not in value:
                raise DraftValidationError(f"{kind} producer requires {key}")
        _string(value["provider"], "producer.provider")
        _string(value["model"], "producer.model")
        _string(value["model_version"], "producer.model_version")
        _sha64(value["prompt_sha256"], "producer.prompt_sha256")
        if not isinstance(value["tool_versions"], Mapping) or not value["tool_versions"]:
            raise DraftValidationError("producer.tool_versions must be a non-empty object")
        for key in value["tool_versions"]:
            _string(key, "producer.tool_versions key")
            _string(value["tool_versions"][key], "producer.tool_versions value")
        if not isinstance(value["parameters"], Mapping):
            raise DraftValidationError("producer.parameters must be an object")
        if not isinstance(value["failures"], list):
            raise DraftValidationError("producer.failures must be an array")
        for item in value["failures"]:
            if not isinstance(item, Mapping):
                raise DraftValidationError("producer.failures entries must be objects")
            _string(item.get("operation"), "producer.failure.operation")
            _string(item.get("error"), "producer.failure.error")
        _integer(value["retries"], "producer.retries")
    elif kind == "human":
        for key in ("provider", "model", "model_version", "prompt_sha256"):
            if value.get(key):
                raise DraftValidationError("human producer cannot claim model provenance")
    else:
        _string(value.get("provider"), "producer.provider")
    return dict(value)


def _validate_context(value, bundle):
    _exact_keys(value, _CONTEXT_REQUIRED, set(), "input_context")
    _sha64(value["fact_bundle_sha256"], "input_context.fact_bundle_sha256")
    if value["fact_bundle_sha256"] != bundle.fact_bundle_sha256:
        raise DraftValidationError("draft references a different fact bundle")
    _sha64(value["report_sha256"], "input_context.report_sha256")
    if value["report_sha256"] != bundle.source_binding.get("report_sha256"):
        raise DraftValidationError("draft report hash differs from fact bundle")
    tool_call_ids = _string_list(value["tool_call_ids"], "input_context.tool_call_ids")
    result_ids = _string_list(
        value["tool_result_evidence_ids"],
        "input_context.tool_result_evidence_ids",
    )
    if not isinstance(value["budget"], Mapping):
        raise DraftValidationError("input_context.budget must be an object")
    _exact_keys(value["budget"], _BUDGET_KEYS, set(), "input_context.budget")
    _integer(value["budget"]["input_tokens"], "budget.input_tokens")
    _integer(value["budget"]["output_tokens"], "budget.output_tokens")
    _integer(value["budget"]["tool_calls"], "budget.tool_calls")
    wall = value["budget"]["wall_clock_seconds"]
    if isinstance(wall, bool) or not isinstance(wall, (int, float)) or wall < 0:
        raise DraftValidationError("budget.wall_clock_seconds must be nonnegative")
    if value["budget"]["tool_calls"] != len(tool_call_ids):
        raise DraftValidationError("tool-call budget must equal recorded tool-call count")
    if not isinstance(value["model_parameters"], Mapping):
        raise DraftValidationError("input_context.model_parameters must be an object")
    return dict(value), set(result_ids)


def validate_investigation_draft(
    payload: Mapping[str, Any],
    bundle,
    *,
    persisted_evidence_ids: Sequence[str] = (),
    draft_id: Optional[str] = None,
    created_at: Optional[str] = None,
) -> InvestigationDraft:
    """Validate one append-only draft against one immutable fact bundle."""
    if not isinstance(payload, Mapping):
        raise DraftValidationError("draft must be an object")
    data = dict(payload)
    if draft_id is not None:
        if "draft_id" in data and data["draft_id"] != draft_id:
            raise DraftValidationError("draft_id cannot be changed")
        data["draft_id"] = draft_id
    if created_at is not None:
        data["created_at"] = created_at
    _exact_keys(data, _TOP_REQUIRED, _TOP_OPTIONAL, "draft")
    if data["schema_version"] != "ohscanner.investigation-draft-v1":
        raise DraftValidationError("unsupported draft schema version")
    if data["status"] != "draft_only":
        raise DraftValidationError("draft status must remain draft_only")
    if data["can_promote"] is not False:
        raise DraftValidationError("drafts cannot authorize status promotion")
    if data["candidate_id"] != bundle.candidate_identity.get("candidate_id"):
        raise DraftValidationError("draft candidate differs from fact bundle")

    allowed_refs = {fact.fact_id for fact in bundle.facts}
    allowed_refs.update(str(item) for item in persisted_evidence_ids)
    producer = _validate_producer(data["producer"])
    context, result_ids = _validate_context(data["input_context"], bundle)
    if not result_ids.issubset(allowed_refs):
        raise DraftValidationError("tool result contains unknown evidence references")

    claims = []
    for item in data["claims"]:
        _exact_keys(
            item,
            {"claim_id", "kind", "text", "evidence_refs"},
            {"status"},
            "claim",
        )
        refs = _string_list(item["evidence_refs"], "claim.evidence_refs", allow_empty=False)
        if not set(refs).issubset(allowed_refs):
            raise DraftValidationError("claim contains unknown evidence references")
        if item.get("status", "draft") != "draft":
            raise DraftValidationError("claim status must remain draft")
        claims.append({
            "claim_id": item["claim_id"],
            "kind": item["kind"],
            "text": item["text"],
            "evidence_refs": list(refs),
            "status": "draft",
        })

    missing_evidence = []
    for item in data["missing_evidence"]:
        _exact_keys(
            item,
            {
                "item_id", "question", "required_authority", "status",
                "evidence_refs", "next_probe",
            },
            set(),
            "missing_evidence",
        )
        refs = _string_list(
            item["evidence_refs"], "missing_evidence.evidence_refs", allow_empty=False
        )
        if not set(refs).issubset(allowed_refs):
            raise DraftValidationError("missing-evidence item has unknown references")
        missing_evidence.append({
            "item_id": item["item_id"],
            "question": item["question"],
            "required_authority": item["required_authority"],
            "status": item["status"],
            "evidence_refs": list(refs),
            "next_probe": item["next_probe"],
        })

    probes = []
    for item in data["recommended_probes"]:
        _exact_keys(
            item,
            {
                "probe_id", "operation", "rationale", "evidence_refs",
                "authorization",
            },
            {"status"},
            "recommended_probe",
        )
        refs = _string_list(
            item["evidence_refs"], "recommended_probe.evidence_refs", allow_empty=False
        )
        if not set(refs).issubset(allowed_refs):
            raise DraftValidationError("recommended probe has unknown references")
        if item.get("status", "suggested") != "suggested":
            raise DraftValidationError("probe status must remain suggested")
        probes.append({
            "probe_id": item["probe_id"],
            "operation": item["operation"],
            "rationale": item["rationale"],
            "evidence_refs": list(refs),
            "authorization": item["authorization"],
            "status": "suggested",
        })

    assumptions = _string_list(data["assumptions"], "assumptions")
    limitations = _string_list(data["limitations"], "limitations")
    recommendations = _string_list(
        data["review_recommendations"], "review_recommendations"
    )
    return InvestigationDraft(
        draft_id=data["draft_id"],
        candidate_id=data["candidate_id"],
        producer=producer,
        input_context=context,
        claims=tuple(claims),
        assumptions=assumptions,
        missing_evidence=tuple(missing_evidence),
        recommended_probes=tuple(probes),
        limitations=limitations,
        review_recommendations=recommendations,
        supersedes_draft_id=data.get("supersedes_draft_id"),
        created_at=data.get("created_at"),
        status=data["status"],
        can_promote=data["can_promote"],
    )
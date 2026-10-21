"""Typed local API for long-running operations; every input becomes an immutable plan."""
import hashlib
from decimal import Decimal, InvalidOperation
import json
import re
import uuid
from pathlib import Path
from typing import Literal
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .operations import (approved_url, date_selection, enqueue_branch_comparison, enqueue_range,
                         range_plan, multimode_triage_preview, bind_multimode_triage)
from .operations_store import Operations, END
from .operation_limits import MAX_DETECTOR_IDS
from .store import now
from . import service
from .agent_guidance import recommend_investigation_route
from .source_catalog import (CatalogUnavailable, repository_catalog as public_repository_catalog,
                             repository_preview, validate_commit, validate_branch,
                             validate_preview, validate_repository_slug)


_MARKDOWN_INLINE_SPECIAL_CHARS = frozenset(chr(92) + "*_{}[]()#+-.!|<>~" + chr(96))


def _markdown_inline_untrusted(value):
    """Render model, source, and reviewer text as one safe Markdown inline value."""
    normalized = " ".join(str(value if value is not None else "").split())
    return "".join(chr(92) + char if char in _MARKDOWN_INLINE_SPECIAL_CHARS else char
                   for char in normalized)


def _aggregate_agent_budget_cost_estimates(estimates):
    items = list(estimates)
    if not items or any(not isinstance(item, dict)
                        or item.get("status") != "budget_based_upper_estimate"
                        for item in items):
        return None
    rate_cards = {item.get("rate_card_id") for item in items}
    currencies = {item.get("currency") for item in items}
    sources = {item.get("rate_source_url") for item in items}
    if len(rate_cards) != 1 or len(currencies) != 1 or len(sources) != 1:
        return None
    cny_values = [item.get("maximum_cny") for item in items]
    if any(value is not None for value in cny_values) and any(value is None for value in cny_values):
        return None
    try:
        total = sum((Decimal(item["maximum_usd"]) for item in items), Decimal(0))
        cny_total = (sum((Decimal(value) for value in cny_values), Decimal(0))
                     if all(value is not None for value in cny_values) else None)
    except (KeyError, InvalidOperation, TypeError):
        return None
    if (not total.is_finite() or total < 0
            or (cny_total is not None and (not cny_total.is_finite() or cny_total < 0))):
        return None
    result = {
        "status": "budget_based_upper_estimate",
        "currency": next(iter(currencies)),
        "maximum_usd": format(total.quantize(Decimal("0.00000001")), "f"),
        "rate_card_id": next(iter(rate_cards)),
        "rate_source_url": next(iter(sources)),
        "candidate_or_arm_count": len(items),
        "actual_charge_verified": False,
        "hard_spend_cap": False,
    }
    if cny_total is not None:
        result["maximum_cny"] = format(cny_total.quantize(Decimal("0.00000001")), "f")
        result["alternative_currency"] = "CNY"
    return result


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SyncRequest(Strict):
    repository: str = Field(min_length=13, max_length=112)
    url: str = Field(min_length=16, max_length=300)
    timeout_seconds: int = Field(default=900, ge=10, le=3600)

    @field_validator("repository")
    @classmethod
    def valid_repository_name(cls, value):
        prefix = "openharmony/"
        if not value.startswith(prefix):
            raise ValueError("repository must name one OpenHarmony repository")
        validate_repository_slug(value[len(prefix):])
        return value

    @field_validator("url")
    @classmethod
    def valid_repository_url(cls, value):
        approved_url(value)
        return value


class OfficialRepositoryPreviewRequest(Strict):
    slug: str = Field(min_length=1, max_length=100)

    @field_validator("slug")
    @classmethod
    def valid_slug(cls, value):
        return validate_repository_slug(value)


class OfficialRepositoryImportRequest(Strict):
    slug: str = Field(min_length=1, max_length=100)
    branch: str = Field(min_length=1, max_length=200)
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    preview_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] | None = Field(default=None, max_length=MAX_DETECTOR_IDS)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)
    import_timeout_seconds: int = Field(default=1800, ge=30, le=3600)

    @field_validator("slug")
    @classmethod
    def valid_slug(cls, value):
        return validate_repository_slug(value)


class EndpointTriageApproval(Strict):
    consent_nonce: str = Field(pattern=r"^[0-9a-f]{32}$")
    consent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AuthorizedOperationRequest(Strict):
    auto_triage: bool = False
    max_triage_candidates: int = Field(default=3, ge=1, le=5)
    max_r2_candidates: int = Field(default=0, ge=0, le=5)
    max_cost_usd: str | None = Field(default=None, pattern=r"^\d{1,6}(?:\.\d{1,8})?$")
    triage_approvals: list[EndpointTriageApproval] = Field(default_factory=list, max_length=8)


class IntelligentOperationPreviewRequest(Strict):
    kind: Literal["range", "date", "branches", "matrix"]
    payload: dict


class RangeRequest(AuthorizedOperationRequest):
    repository_id: str
    baseline: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    endpoint: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] = Field(min_length=1, max_length=MAX_DETECTOR_IDS)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)
    audit_mode: Literal["standard_review", "static_only"] = "standard_review"


class DateRangeRequest(AuthorizedOperationRequest):
    repository_id: str
    branch: str = Field(min_length=1, max_length=200)
    start: str = Field(min_length=10, max_length=40)
    end: str = Field(min_length=10, max_length=40)
    timezone: str = Field(min_length=1, max_length=100)
    audit_mode: Literal["standard_review", "static_only"] = "standard_review"
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] = Field(min_length=1, max_length=MAX_DETECTOR_IDS)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class DateRangePreviewRequest(Strict):
    repository_id: str
    branch: str = Field(min_length=1, max_length=200)
    start: str = Field(min_length=10, max_length=40)
    end: str = Field(min_length=10, max_length=40)
    timezone: str = Field(min_length=1, max_length=100)


class MatrixRequest(AuthorizedOperationRequest):
    case_id: str
    repository_id: str
    audit_mode: Literal["standard_review", "static_only"] = "standard_review"
    commits: list[str] = Field(min_length=2, max_length=8)
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] = Field(min_length=1, max_length=MAX_DETECTOR_IDS)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class BranchComparisonRequest(AuthorizedOperationRequest):
    repository_id: str
    audit_mode: Literal["standard_review", "static_only"] = "standard_review"
    baseline_ref: str = Field(min_length=1, max_length=200)
    endpoint_ref: str = Field(min_length=1, max_length=200)
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] = Field(min_length=1, max_length=MAX_DETECTOR_IDS)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class ValidationRequest(Strict):
    case_id: str
    harness_id: Literal["auth01_descriptor_bypass"]
    target_repository_id: str
    target_commit: str = Field(min_length=40, max_length=64)
    cutils_repository_id: str
    cutils_commit: str = Field(min_length=40, max_length=64)
    repeats: int = Field(default=3, ge=3, le=3)
    timeout_seconds: int = Field(default=900, ge=60, le=1800)


class InvestigationRequest(Strict):
    job_id: str
    candidate_id: str = Field(min_length=1, max_length=200)
    max_output_bytes: int = Field(default=65536, ge=1024, le=262144)


class CandidateReviewQueueRequest(Strict):
    job_id: str


class TriageAuthorizationRevocationRequest(Strict):
    consent_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ProviderCheckRequest(Strict):
    confirm_no_source_request: Literal[True]


class ProviderSettingsRequest(Strict):
    base_url: str = Field(min_length=1, max_length=500)
    model: str = Field(min_length=1, max_length=200)
    proxy_url: str = Field(default="", max_length=500)
    api_key: str = Field(default="", max_length=4096)


class AgentInvestigationRequest(Strict):
    job_id: str
    candidate_id: str = Field(min_length=1, max_length=200)
    case_id: str | None = Field(default=None, min_length=1, max_length=200)
    experiment_id: str | None = Field(default=None, min_length=1, max_length=64,
                                      pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    mode: Literal["single_shot", "tool_agent"] = "tool_agent"
    max_steps: int = Field(default=4, ge=1, le=6)
    max_output_tokens: int = Field(default=1200, ge=128, le=3000)
    max_total_input_tokens: int = Field(default=24000, ge=1000, le=64000)
    max_total_output_tokens: int = Field(default=4000, ge=512, le=12000)
    timeout_seconds: int = Field(default=240, ge=90, le=480)
    source_submission_approved: bool = False
    consent_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    consent_nonce: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")




class AgentBatchInvestigationRequest(Strict):
    job_id: str
    candidate_ids: list[str] = Field(min_length=1, max_length=5)
    mode: Literal["single_shot", "tool_agent"] = "tool_agent"
    max_steps: int = Field(default=4, ge=1, le=6)
    max_output_tokens: int = Field(default=1200, ge=128, le=3000)
    max_total_input_tokens: int = Field(default=24000, ge=1000, le=64000)
    max_total_output_tokens: int = Field(default=4000, ge=512, le=12000)
    timeout_seconds: int = Field(default=240, ge=90, le=480)
    source_submission_approved: bool = False
    consent_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    consent_nonce: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


class AgentPairedInvestigationRequest(AgentInvestigationRequest):
    experiment_id: str = Field(min_length=1, max_length=64,
                               pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class AgentBaselineObligationReview(Strict):
    obligation_index: int = Field(ge=0, le=39, strict=True)
    disposition: Literal["evidence_found", "contrary_evidence", "unresolved"]
    source_line: int | None = Field(default=None, ge=1, strict=True)
    quote: str | None = Field(default=None, min_length=8, max_length=500)
    notes: str = Field(default="", max_length=800)


class AgentStaticReviewSourceRequest(Strict):
    job_id: str
    candidate_id: str = Field(min_length=1, max_length=200)
    start_line: int = Field(ge=1, strict=True)
    line_count: int = Field(default=40, ge=1, le=40, strict=True)


class AgentBaselineSourceRange(Strict):
    start_line: int = Field(ge=1, strict=True)
    end_line: int = Field(ge=1, strict=True)


class AgentBaselineReviewRequest(Strict):
    job_id: str
    candidate_id: str = Field(min_length=1, max_length=200)
    experiment_id: str = Field(min_length=1, max_length=64,
                               pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    reviewer: str = Field(min_length=1, max_length=100)
    disposition: Literal["investigate", "likely_noise", "unknown"]
    elapsed_seconds: int | None = Field(default=None, ge=0, le=7200)
    notes: str = Field(default="", max_length=1200)
    reviewer_acknowledged: bool = False
    obligation_reviews: list[AgentBaselineObligationReview] = Field(default_factory=list, max_length=40)
    source_ranges: list[AgentBaselineSourceRange] = Field(default_factory=list, max_length=20)

class AgentObligationAdjudication(Strict):
    obligation_index: int = Field(ge=0, le=29)
    disposition: Literal["evidence_found", "contrary_evidence", "unresolved"]


class AgentClaimAdjudication(Strict):
    claim_index: int = Field(ge=0, le=29, strict=True)
    disposition: Literal["supported", "partially_supported", "unsupported", "unverifiable"]


class AgentHumanReviewRequest(Strict):
    reviewer: str = Field(min_length=1, max_length=100)
    usefulness: Literal["useful", "partially_useful", "not_useful", "unsafe"]
    citation_accuracy: Literal["all_accurate", "some_incorrect", "mostly_incorrect", "not_checked"]
    claim_adjudications: list[AgentClaimAdjudication] = Field(default_factory=list, max_length=30)
    post_review_disposition: Literal["investigate", "likely_noise", "unknown"] | None = None
    elapsed_seconds: int | None = Field(default=None, ge=0, le=7200)
    claims_to_correct: str = Field(default="", max_length=1200)
    missed_evidence: str = Field(default="", max_length=1200)
    notes: str = Field(default="", max_length=1000)


class AgentBlindSessionRequest(Strict):
    experiment_id: str = Field(min_length=1, max_length=64,
                               pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    operation_ids: list[str] = Field(min_length=2, max_length=20)


class AgentBlindReviewSubmission(AgentHumanReviewRequest):
    blind_item_id: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")
    packet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    obligation_adjudications: list[AgentObligationAdjudication] = Field(default_factory=list, max_length=30)
    claim_adjudications: list[AgentClaimAdjudication] = Field(default_factory=list, max_length=30)
    guessed_arm: Literal["single_shot", "tool_agent", "unknown"] = "unknown"
    guess_confidence: int | None = Field(default=None, ge=0, le=100)


class AgentBlindReviewImportRequest(Strict):
    reviews: list[AgentBlindReviewSubmission] = Field(min_length=1, max_length=20)


class AgentBlindAgreementRequest(Strict):
    session_ids: list[str] = Field(min_length=2, max_length=10)


class AssessmentRequest(Strict):
    outcome: Literal["candidate", "dynamic_reproduced_component_issue", "confirmed", "reportable",
                     "supports_vulnerability_hypothesis", "supports_false_positive_hypothesis",
                     "unknown", "proposed_confirmation"]
    reviewer_kind: Literal["human", "agent"] = "human"
    reviewer: str = Field(min_length=1, max_length=100)
    notes: str = Field(min_length=1, max_length=8000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    validation_operation_ids: list[str] = Field(default_factory=list, max_length=10)
    remaining_unknowns: list[str] = Field(default_factory=list, max_length=50)


class AgentEvidenceCitation(Strict):
    file: str = Field(min_length=1, max_length=500)
    blob: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    observation: str = Field(min_length=1, max_length=2000)


class AgentProposalRequest(Strict):
    candidate_id: str = Field(min_length=1, max_length=200)
    agent_id: str = Field(min_length=1, max_length=100)
    suggestion: Literal["supports_vulnerability_hypothesis", "supports_false_positive_hypothesis",
                        "unknown", "proposed_confirmation"]
    summary: str = Field(min_length=1, max_length=4000)
    source_commit: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    source_blob: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    supporting_evidence: list[AgentEvidenceCitation] = Field(default_factory=list, max_length=30)
    refuting_evidence: list[AgentEvidenceCitation] = Field(default_factory=list, max_length=30)
    unresolved_obligations: list[str] = Field(default_factory=list, max_length=50)
    provider: str = Field(min_length=1, max_length=100)
    model_version: str = Field(min_length=1, max_length=100)
    prompt_version: str = Field(min_length=1, max_length=100)
    tool_version: str = Field(min_length=1, max_length=100)
    run_id: str = Field(min_length=1, max_length=100)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    duration_ms: int | None = Field(default=None, ge=0)


def _case_links(store, case_id):
    with store.connect() as db:
        return [dict(x) for x in db.execute("SELECT * FROM case_links WHERE case_id=? ORDER BY job_id,candidate_id", (case_id,))]


def _case_review_status(store, ops, case_id):
    assessments = ops.assessments(case_id)
    human_assessments = [item for item in assessments if item.get("reviewer_kind") == "human"]
    latest = human_assessments[-1] if human_assessments else None
    valid_evidence_ids = {
        item["id"]
        for link in _case_links(store, case_id)
        for item in store.source_evidence(link["job_id"], link["candidate_id"])
    }
    validated_by = None
    # The latest human decision controls current case status. An older confirmation
    # must not survive a later append-only candidate/unknown/refutation assessment.
    assessment = latest
    if (assessment and assessment.get("outcome") in {"confirmed", "reportable"}
            and assessment.get("evidence_ids")
            and assessment.get("remaining_unknowns")
            and set(assessment["evidence_ids"]).issubset(valid_evidence_ids)):
        for operation_id in assessment.get("validation_operation_ids", []):
            try:
                task = ops.get(operation_id)
                if (task["kind"] != "validation" or task["spec"].get("case_id") != case_id
                        or task["status"] not in {"completed", "completed_with_limitations"}):
                    continue
                result = ops.result(operation_id)
            except (KeyError, ValueError):
                continue
            if (result.get("validation_gate") == "passed"
                    and result.get("case_id") == case_id
                    and result.get("reachability_status") == "verified"):
                validated_by = {
                    "assessment_id": assessment.get("id"),
                    "validation_operation_id": operation_id,
                    "outcome": assessment["outcome"],
                }
                break
    return {
        "latest_human_assessment": latest,
        "validated_vulnerability": 1 if validated_by else 0,
        "validated_by": validated_by,
        "assessment_count": len(assessments),
    }


def _validated_cases_for_audit(store, ops, audit_id):
    confirmed = []
    for case in store.cases():
        linked = [item for item in case.get("links", []) if item.get("job_id") == audit_id]
        if not linked:
            continue
        status = _case_review_status(store, ops, case["id"])
        if status["validated_vulnerability"]:
            confirmed.append({
                "case_id": case["id"],
                "candidate_ids": sorted({item["candidate_id"] for item in linked}),
                "validation_basis": status["validated_by"],
            })
    return confirmed


def _combined_audit_report_markdown(document):
    md = _markdown_inline_untrusted
    scan = document["scan"]
    risks = document["risk_snapshot"]
    triage = document["triage"]
    authorization = triage.get("authorization") or {}
    cost_budget = authorization.get("cost_budget") or {}
    rows = [
        "# OHScanner 智能安全审计报告",
        "",
        "- 报告快照：`" + md(document["report_snapshot_id"]) + "`",
        "- 快照 SHA-256：`" + md(document["report_snapshot_sha256"]) + "`",
        "- 静态原始报告 SHA-256：`" + md(scan["report_sha256"]) + "`",
        "- 仓库版本：" + md(scan["repository"]) + " @ `" + md(scan["commit"]) + "`",
        "- Tree：`" + md(scan["tree"]) + "`",
        "- 静态扫描：" + md(scan["status"]) + "；智能研判：" + md(triage["state"]),
        "- 漏洞确认数：" + str(document["validated_vulnerability"]),
        "- 工作台模型费用预算：" + ("USD " + md(cost_budget.get("maximum_usd"))
            + "（费率卡估算上限 USD " + md(cost_budget.get("estimated_maximum_usd"))
            + "；不代表 Provider 账单硬上限）" if cost_budget else "未设置任务级自动研判预算"),
        "",
        "## 风险分层",
        "",
        "| 层级 | 数量 |",
        "|---|---:|",
    ]
    labels = {
        "high_confidence_candidate": "高可信风险候选（仍为待复核候选）",
        "further_validation": "待进一步验证",
        "low_priority_manual": "低优先级线索（人工标记，不代表安全）",
        "unknown_source_binding": "来源绑定未知",
    }
    for tier, label in labels.items():
        rows.append("| " + md(label) + " | " + str(risks["counts"].get(tier, 0)) + " |")
    rows.extend(["", "## 优先候选", ""])
    selected = risks.get("items", [])[:20]
    if not selected:
        rows.append("当前没有静态候选；这不表示整个仓库无漏洞。")
    for item in selected:
        rows.extend([
            "### " + md(item.get("risk_tier_label")) + " — "
            + md(item.get("detector_id")) + " / " + md(item.get("rule_id")),
            "",
            "- 候选：`" + md(item.get("candidate_id")) + "`",
            "- 位置：" + md(item.get("file")) + ":" + md(item.get("line")),
            "- 源码 SHA-256：`" + md(item.get("source_sha256")) + "`",
            "- 研判状态：" + md(item.get("triage", {}).get("state")),
            "- 状态边界：candidate；该分层不代表 confirmed。",
            "- 原因：" + md("；".join(item.get("reasons", []))),
            "",
        ])
    rows.extend(["## 覆盖与限制", ""])
    rows.append("静态文件解析：" + md(json.dumps(document["coverage"].get("source_parsing", {}), ensure_ascii=False, sort_keys=True)))
    for limitation in document.get("limitations", []):
        rows.append("- " + md(limitation))
    rows.extend([
        "",
        "> 模型研判是候选调查建议。模型自报置信度和引文存在性均不构成漏洞确认；只有现有人工评估与通过的运行时可达性门才能增加已确认漏洞数。",
        "",
    ])
    return "\n".join(rows)


def _blind_packet(result):
    """Create a review packet without arm/provider identifiers or raw operation metadata."""
    initial = result.get("initial_evidence") or {}
    context = initial.get("context") or {}
    assessment = result.get("agent_assessment") or {}
    if not context.get("source_excerpt") or not isinstance(assessment, dict):
        raise ValueError("Agent result lacks the source-bound context needed for blind review")
    evidence = []
    aliases = {}
    private_keys = {"repository", "repository_id", "commit", "tree", "snapshot_sha256",
        "report_sha256", "source_sha256", "git_blob", "candidate_id", "operation_id",
        "experiment_id", "mode", "model", "provider", "tool", "tool_name",
        "prompt_version", "tool_policy_version", "evidence_id"}
    def scrub_metadata(value):
        if isinstance(value, dict):
            return {key: scrub_metadata(item) for key, item in value.items()
                    if str(key).lower() not in private_keys}
        if isinstance(value, list):
            return [scrub_metadata(item) for item in value]
        return value
    initial_id = initial.get("evidence_id")
    if initial_id:
        aliases[initial_id] = "E1"
    evidence.append({"id": "E1", "kind": "candidate_source", "file": context.get("file"),
        "start_line": context.get("source_excerpt_start_line"),
        "end_line": context.get("source_excerpt_end_line"),
        "content": {"source_excerpt": context.get("source_excerpt"),
                    "evidence_obligations": context.get("evidence_obligations", [])}})
    supplemental = []
    for call in result.get("tool_calls", []):
        evidence_id = call.get("evidence_id")
        payload = call.get("result")
        if not evidence_id or payload is None:
            continue
        alias = "E" + str(len(evidence) + 1)
        aliases[evidence_id] = alias
        evidence.append({"id": alias, "kind": "supplemental_source_evidence",
                         "content": scrub_metadata(payload)})
    def scrub_citations(items):
        citations = []
        for citation in items if isinstance(items, list) else []:
            source_id = citation.get("evidence_id")
            if source_id in aliases:
                citations.append({"evidence_id": aliases[source_id], "quote": citation.get("quote", "")})
        return citations
    def scrub_claims(items):
        output = []
        for claim in items if isinstance(items, list) else []:
            if not isinstance(claim, dict):
                continue
            item = {"claim": claim.get("claim", ""),
                    "citations": scrub_citations(claim.get("citations", []))}
            indices = claim.get("obligation_indices")
            if (isinstance(indices, list)
                    and all(isinstance(index, int) and not isinstance(index, bool) and index >= 0
                            for index in indices)):
                item["obligation_indices"] = indices
            output.append(item)
        return output
    packet = {
        "candidate": {"file": context.get("file"), "line": context.get("line"),
                      "symbol": context.get("symbol"), "source_excerpt": context.get("source_excerpt"),
                      "evidence_obligations": context.get("evidence_obligations", []),
                      "evidence_routing": context.get("evidence_routing")},
        "assessment": {"summary": assessment.get("summary", ""),
                       "summary_provenance": result.get("summary_provenance", "legacy_model_generated_unverified"),
                       "model_summary_unverified": assessment.get("model_summary_unverified",
                           assessment.get("summary", "")),
                       "citation_integrity": result.get("citation_integrity", {
                           "quote_presence": "unknown",
                           "semantic_support": "unverified_by_machine",
                           "note": "This result has no recorded server-side verbatim citation check."}),
                       "narrative_integrity": result.get("narrative_integrity", {
                           "unverified_narrative_fields": ["model_summary_unverified", "unsupported_claims", "unknowns", "next_steps"],
                           "narrative_semantics": "unverified_by_machine"}),
                       "assessment": assessment.get("assessment", "unknown"),
                       "supported_claims": scrub_claims(assessment.get("supported_claims", [])),
                       "obligation_reviews": [{
                           "obligation_index": item.get("obligation_index"),
                           "disposition": item.get("disposition", "unresolved"),
                           "citations": scrub_citations(item.get("citations", [])),
                       } for item in assessment.get("obligation_reviews", []) if isinstance(item, dict)],
                       "unsupported_claims": assessment.get("unsupported_claims", []),
                       "unknowns": assessment.get("unknowns", []),
                       "next_steps": assessment.get("next_steps", [])},
        "evidence": evidence,
        "notice": "Review this anonymized investigation output and evidence. Arm and provider details are hidden until the session is closed.",
    }
    return packet


def install_routes(app: FastAPI, settings, store):
    ops = Operations(store)
    router = APIRouter(prefix="/api/v1")

    @router.get("/cases/review-statuses")
    def case_review_statuses():
        return {"items": [{"case_id": case["id"], **_case_review_status(store, ops, case["id"])}
                          for case in store.cases()]}

    @router.get("/agent/evaluation-summary")
    def agent_evaluation_summary():
        return ops.agent_evaluation_summary()

    @router.get("/agent/static-review-preview")
    def agent_static_review_preview(job_id: str, candidate_id: str):
        job = store.job(job_id)
        if job["status"] not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
            raise ValueError("static review preview requires a completed scan report")
        report = service.read_report(settings, job)
        candidate = service.finding(report, candidate_id)
        source = service.source(settings, store, job, candidate["file"])
        if source.get("sha256") != candidate.get("source_sha256"):
            raise ValueError("static preview source does not match the fixed candidate")
        try:
            line = int(candidate["line"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("static preview candidate has no valid source line") from None
        lines = source["text"].splitlines()
        if line < 1 or line > len(lines):
            raise ValueError("static preview candidate line is outside the fixed source")
        start, end = max(1, line - 20), min(len(lines), line + 20)
        preview_parts = []
        preview_bytes = 0
        truncated = False
        for number in range(start, end + 1):
            encoded = f"{number}: {lines[number - 1]}".encode("utf-8")
            remaining = 32768 - preview_bytes
            if len(encoded) > remaining:
                if remaining > 0:
                    preview_parts.append(encoded[:remaining].decode("utf-8", "ignore"))
                truncated = True
                break
            preview_parts.append(encoded.decode("utf-8"))
            preview_bytes += len(encoded) + 1
        candidate_evidence = candidate.get("evidence")
        if not isinstance(candidate_evidence, dict):
            candidate_evidence = {}
        obligations = candidate_evidence.get("obligations", [])
        if not isinstance(obligations, list):
            obligations = []
        coverage = report.get("detector_coverage")
        if not isinstance(coverage, dict):
            coverage = {}
        detectors = coverage.get("detectors")
        if not isinstance(detectors, dict):
            detectors = {}
        detector_coverage = detectors.get(candidate.get("detector_id"))
        if not isinstance(detector_coverage, dict):
            detector_coverage = {}
        coverage_counts = detector_coverage.get("coverage_counts")
        if not isinstance(coverage_counts, dict):
            coverage_counts = {}
        bounded_obligations = obligations[:40]
        evidence_routing = recommend_investigation_route(
            bounded_obligations,
            scan_status=report.get("status", "unknown"),
            detector_status=detector_coverage.get("status", "unknown"),
            analysis_status=candidate_evidence.get("analysis_status", "unknown"),
        )

        def coverage_count(key, files_key):
            value = coverage_counts.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                return value
            files = detector_coverage.get(files_key)
            return len(files) if isinstance(files, list) else None

        return {
            "schema_version": 1,
            "binding": {"repository": report.get("repository"), "commit": report.get("commit"),
                         "tree": report.get("git_tree", report.get("tree")),
                         "report_sha256": job["report_sha256"]},
            "scan_status": report.get("status", "unknown"),
            "analysis_status": candidate_evidence.get("analysis_status", "unknown"),
            "detector_coverage": {
                "status": detector_coverage.get("status", "unknown"),
                "applicable_files": detector_coverage.get("applicable_files"),
                "analyzed_files": coverage_count("complete", "analyzed_files"),
                "partially_inspected_files": coverage_count("partial", "partially_inspected_files"),
                "not_analyzed_files": coverage_count("not_analyzed", "not_analyzed_files"),
                "failed_files": coverage_count("failed", "failed_files"),
            },
            "evidence_routing": evidence_routing,
            "id": candidate["id"], "file": candidate["file"], "line": line,
            "detector_id": candidate.get("detector_id"),
            "detector_version": candidate.get("detector_version"),
            "rule_id": candidate.get("rule_id"),
            "message": candidate.get("message"),
            "severity": candidate.get("severity"), "confidence": candidate.get("confidence"),
            "source_sha256": candidate.get("source_sha256"),
            "evidence": {"obligations": obligations[:40],
                          "obligations_truncated": len(obligations) > 40},
            "source": {"sha256": source["sha256"], "blob": source.get("blob"),
                        "start_line": start, "end_line": min(end, start + len(preview_parts) - 1),
                        "text": "\n".join(preview_parts), "truncated": truncated},
            "source_line_count": len(lines),
            "semantics": "Static scanner evidence for human R0 triage only; no Agent output or vulnerability conclusion.",
        }

    @router.post("/agent/static-review-source")
    def agent_static_review_source(body: AgentStaticReviewSourceRequest):
        job = store.job(body.job_id)
        if job["status"] not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
            raise ValueError("fixed-source review requires a completed scan report")
        report = service.read_report(settings, job)
        candidate = service.finding(report, body.candidate_id)
        source = service.source(settings, store, job, candidate["file"])
        if source.get("sha256") != candidate.get("source_sha256"):
            raise ValueError("fixed-source excerpt no longer matches the candidate source")
        lines = source.get("text", "").splitlines()
        if body.start_line > len(lines):
            raise ValueError("requested source range starts beyond end of file")
        end_line = min(len(lines), body.start_line + body.line_count - 1)
        excerpt = "\n".join(f"{number}: {lines[number - 1]}"
                            for number in range(body.start_line, end_line + 1))
        if len(excerpt.encode("utf-8")) > 32768:
            raise ValueError("requested source excerpt exceeds the 32 KiB limit; request fewer lines")
        return {"job_id": job["id"], "candidate_id": candidate["id"],
                "repository": report["repository"], "commit": report["commit"],
                "report_sha256": job["report_sha256"], "file": candidate["file"],
                "source_sha256": source["sha256"], "start_line": body.start_line,
                "end_line": end_line, "text": excerpt,
                "semantics": "Read-only excerpt from the candidate file at its fixed source SHA; no provider request was made."}

    @router.post("/agent/baseline-reviews", status_code=201)
    def agent_baseline_review(body: AgentBaselineReviewRequest):
        reviewer = body.reviewer.strip()
        if not reviewer:
            raise ValueError("reviewer name must not be blank")
        job = store.job(body.job_id)
        if job["status"] not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
            raise ValueError("R0 baseline requires a completed scan report")
        report = service.read_report(settings, job)
        candidate = service.finding(report, body.candidate_id)
        source = service.source(settings, store, job, candidate["file"])
        if source.get("sha256") != candidate.get("source_sha256"):
            raise ValueError("R0 baseline source does not match the fixed candidate")
        for task in ops.list():
            spec = task.get("spec") or {}
            if (task["kind"] == "agent_investigation"
                    and spec.get("experiment_id") == body.experiment_id
                    and spec.get("job_id") == body.job_id
                    and spec.get("candidate_id") == body.candidate_id):
                raise ValueError("R0 must be recorded before any LLM operation in this experiment")
        if not body.reviewer_acknowledged:
            raise ValueError("R0 requires explicit reviewer confirmation that each displayed obligation was checked")
        evidence = candidate.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        all_obligations = evidence.get("obligations", [])
        if not isinstance(all_obligations, list):
            all_obligations = []
        obligations = all_obligations[:40]
        reviews = [item.model_dump() for item in body.obligation_reviews]
        indices = [item["obligation_index"] for item in reviews]
        if len(reviews) != len(obligations) or sorted(indices) != list(range(len(obligations))):
            raise ValueError("R0 must record exactly one static review for every displayed evidence obligation")
        source_lines = source.get("text", "").splitlines()
        candidate_line = candidate.get("line")
        if not isinstance(candidate_line, int) or isinstance(candidate_line, bool) or candidate_line < 1:
            raise ValueError("R0 candidate source line is invalid")
        excerpt_start = max(1, candidate_line - 20)
        excerpt_end = min(len(source_lines), candidate_line + 20)
        displayed_lines = set(range(excerpt_start, excerpt_end + 1))
        for source_range in body.source_ranges:
            if (source_range.end_line < source_range.start_line
                    or source_range.end_line - source_range.start_line + 1 > 40
                    or source_range.end_line > len(source_lines)):
                raise ValueError("R0 supplemental source ranges must be valid fixed-file ranges of at most 40 lines")
            displayed_lines.update(range(source_range.start_line, source_range.end_line + 1))
        for review in reviews:
            quote = review.get("quote")
            line = review.get("source_line")
            if review["disposition"] != "unresolved" and (not quote or line is None):
                raise ValueError("R0 evidence_found and contrary_evidence decisions require a quoted source line")
            if quote is not None:
                if line is None or line not in displayed_lines:
                    raise ValueError("R0 source quote line must be inside the initial or supplemental fixed-source excerpt")
                if quote not in source_lines[line - 1]:
                    raise ValueError("R0 source quote does not match the cited fixed-source line")
        record = {
            "experiment_id": body.experiment_id,
            "job_id": body.job_id,
            "candidate_id": body.candidate_id,
            "repository": report["repository"],
            "commit": report["commit"],
            "report_sha256": job["report_sha256"],
            "source_sha256": source["sha256"],
            "source_blob": source.get("blob"),
            "detector_id": candidate.get("detector_id"),
            "detector_version": candidate.get("detector_version"),
            "reviewer": reviewer,
            "disposition": body.disposition,
            "elapsed_seconds": body.elapsed_seconds,
            "notes": body.notes,
            "obligation_reviews": reviews,
            "source_ranges": [item.model_dump() for item in body.source_ranges],
            "obligations_reviewed": len(reviews),
            "obligations_truncated": len(all_obligations) > len(obligations),
            "review_scope": "static_only_r0_triage",
            "vulnerability_state": "candidate",
            "validated_vulnerability": 0,
        }
        return ops.record_agent_baseline_review(record)

    @router.post("/operations/source-sync", status_code=201)
    def source_sync(body: SyncRequest):
        prefix = "openharmony/"
        if not body.repository.startswith(prefix):
            raise ValueError("repository must name one OpenHarmony repository")
        slug = validate_repository_slug(body.repository[len(prefix):])
        url = approved_url(body.url)
        from urllib.parse import quote, urlsplit
        path = urlsplit(url).path
        expected = "/" + prefix + quote(slug, safe="") + (".git" if path.endswith(".git") else "")
        if path != expected:
            raise ValueError("repository URL path must match the approved repository name")
        return ops.create("source_sync", {"name": body.repository, "url": url,
                                          "timeout_seconds": body.timeout_seconds})

    @router.get("/repositories/official-catalog")
    def official_repository_catalog(q: str = "", page: int = 1, per_page: int = 50,
                                    refresh: bool = False):
        try:
            return public_repository_catalog(settings, query=q, page=page,
                                             per_page=per_page, refresh=refresh)
        except CatalogUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None

    @router.post("/repositories/official-catalog/preview")
    def official_repository_preview(body: OfficialRepositoryPreviewRequest):
        try:
            return repository_preview(settings, validate_repository_slug(body.slug))
        except CatalogUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None

    @router.post("/operations/repository-import-scans", status_code=201)
    def import_repository_and_scan(body: OfficialRepositoryImportRequest):
        validate_repository_slug(body.slug)
        branch = validate_branch(body.branch)
        commit = validate_commit(body.commit)
        try:
            preview = validate_preview(settings, body.slug, branch, commit, body.preview_sha256)
        except CatalogUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None
        from .source_catalog import approved_clone_url
        spec = {
            "slug": body.slug, "name": preview["name"], "branch": branch,
            "commit": commit, "preview_sha256": body.preview_sha256,
            "catalog_sha256": preview.get("catalog_sha256"),
            "clone_url": approved_clone_url(body.slug),
            "estimated_size_kib": preview.get("size_kib"),
            "include_paths": body.include_paths, "detector_ids": body.detector_ids,
            "timeout_seconds": body.import_timeout_seconds,
            "scan_timeout_seconds": body.timeout_seconds, "memory_mb": body.memory_mb,
            "audit_mode": "static_only",
        }
        return ops.create("repository_import_scan", spec)

    @router.post("/operations/intelligent-previews")
    def intelligent_operation_preview(body: IntelligentOperationPreviewRequest):
        """Only preview source egress, never queue scans or invoke a provider."""
        from .agent import ProviderConfig
        schemas = {"range": RangeRequest, "date": DateRangeRequest,
                   "branches": BranchComparisonRequest, "matrix": MatrixRequest}
        request = schemas[body.kind].model_validate(body.payload)
        if not request.auto_triage or request.audit_mode != "standard_review":
            raise ValueError("select intelligent review before previewing model source disclosure")
        if request.max_r2_candidates > request.max_triage_candidates:
            raise ValueError("deep research limit cannot exceed candidate limit")
        if request.triage_approvals:
            raise ValueError("preview does not accept previously approved source consent")
        if request.max_cost_usd is None:
            raise ValueError("automatic model triage requires a USD budget")
        payload = request.model_dump()
        if body.kind == "date":
            selection = date_selection(settings, store, request.repository_id, request.branch,
                                       request.start, request.end, request.timezone)
            payload.update({"baseline": selection["baseline"], "endpoint": selection["endpoint"]})
        if body.kind in {"date", "range"}:
            _, left, right, _ = range_plan(
                settings, store, payload["repository_id"], payload["baseline"], payload["endpoint"],
                payload["include_paths"], payload["detector_ids"], payload["timeout_seconds"],
                payload["memory_mb"])
            specs = [left, right]
        elif body.kind == "branches":
            repo = store.repository(request.repository_id)
            service.check_repository(settings, repo["path"])
            commits = [service.revision(repo, ref)["commit"] for ref in
                       (request.baseline_ref, request.endpoint_ref)]
            if commits[0] == commits[1]:
                raise ValueError("comparison refs resolve to the same commit")
            specs = [service.make_spec(repo, ref, request.include_paths, request.detector_ids,
                                      request.timeout_seconds, request.memory_mb) for ref in commits]
        else:
            if len(set(request.commits)) != len(request.commits):
                raise ValueError("version matrix commits must be distinct")
            if any(not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", sha)
                   for sha in request.commits):
                raise ValueError("version matrix requires complete Git commit hashes")
            repo = store.repository(request.repository_id)
            service.check_repository(settings, repo["path"])
            if not any(case["id"] == request.case_id for case in store.cases()):
                raise ValueError("matrix investigation case not found")
            links = _case_links(store, request.case_id)
            if not any(store.repository(store.job(link["job_id"])["repository_id"])["name"] == repo["name"]
                       for link in links):
                raise ValueError("matrix case must link a candidate from this repository")
            specs = [service.make_spec(repo, sha, request.include_paths, request.detector_ids,
                                      request.timeout_seconds, request.memory_mb) for sha in request.commits]
        provider = ProviderConfig.from_env(settings.data_dir)
        previews = multimode_triage_preview(specs, payload, provider,
                                           [uuid.uuid4().hex for _ in specs])
        return {
            "kind": body.kind, "endpoint_count": len(previews),
            "endpoints": previews,
            "aggregate_estimated_cost": _aggregate_agent_budget_cost_estimates(
                item.get("estimated_cost") for item in previews),
            "note": ("Each endpoint has a separate fixed-commit model disclosure consent. "
                     "This preview does not send source; approval binds exact source and provider."),
        }

    @router.post("/operations/revision-ranges", status_code=201)
    def revision_range(body: RangeRequest):
        return enqueue_range(settings, store, ops, body.model_dump())

    @router.post("/operations/date-ranges", status_code=201)
    def date_range(body: DateRangeRequest):
        selection = date_selection(settings, store, body.repository_id, body.branch,
                                   body.start, body.end, body.timezone)
        spec = body.model_dump()
        spec.update({"baseline": selection["baseline"], "endpoint": selection["endpoint"],
                     "date_selection": selection})
        return enqueue_range(settings, store, ops, spec)

    @router.post("/operations/date-ranges/preview")
    def date_range_preview(body: DateRangePreviewRequest):
        return date_selection(settings, store, body.repository_id, body.branch,
                              body.start, body.end, body.timezone)

    @router.post("/operations/branch-comparisons", status_code=201)
    def branch_comparison(body: BranchComparisonRequest):
        return enqueue_branch_comparison(settings, store, ops, body.model_dump())

    @router.post("/operations/version-matrices", status_code=201)
    def version_matrix(body: MatrixRequest):
        if len(set(body.commits)) != len(body.commits):
            raise ValueError("version matrix commits must be unique")
        if any(not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", item) for item in body.commits):
            raise ValueError("version matrix requires complete lowercase Git object IDs")
        with store.connect() as db:
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (body.case_id,)).fetchone():
                raise KeyError("case not found")
        repo = store.repository(body.repository_id)
        service.check_repository(settings, repo["path"])
        links = _case_links(store, body.case_id)
        if not any(store.repository(store.job(link["job_id"])["repository_id"])["name"] == repo["name"] for link in links):
            raise ValueError("version matrix case must already link a candidate from the selected repository")
        specs = [service.make_spec(repo, sha, body.include_paths, body.detector_ids,
                                   body.timeout_seconds, body.memory_mb) for sha in body.commits]
        specs = bind_multimode_triage(
            settings, [{**spec, "audit_mode": body.audit_mode} for spec in specs],
            body.model_dump())
        return ops.create_with_scans("version_matrix", {"case_id": body.case_id,
            "repository_id": repo["id"], "audit_mode": body.audit_mode, "commits": [s["commit"] for s in specs],
            "timeout_seconds": body.timeout_seconds * len(specs) + 120,
            "memory_mb": body.memory_mb}, repo["id"], specs)

    def provider_settings_view():
        from .agent import ProviderConfig
        from .provider_settings import environment_overrides, read_last_provider_check, read_settings
        saved = read_settings(settings.data_dir)
        provider = ProviderConfig.from_env(settings.data_dir)
        env_source = environment_overrides()
        last_check = read_last_provider_check(settings.data_dir, saved) if not env_source else None
        if (not isinstance(last_check, dict) or not provider.configured
                or last_check.get("model") != provider.model
                or last_check.get("endpoint_host") != provider.endpoint_host):
            last_check = None
        else:
            last_check = {key: last_check.get(key) for key in (
                "checked_at", "endpoint_host", "model", "duration_ms", "input_tokens", "output_tokens")}
        return {
            "base_url": provider.base_url if env_source else saved["base_url"],
            "model": provider.model if env_source else saved["model"],
            "proxy_url": provider.proxy_url if env_source else saved["proxy_url"],
            "api_key_configured": bool(provider.api_key),
            "configured": provider.configured,
            "configuration_source": "environment" if env_source else "local_settings",
            "editable": not env_source,
            "storage": "local_private_file" if not env_source else "environment",
            "last_provider_check": last_check,
        }

    @router.get("/agent/provider-settings")
    def agent_provider_settings():
        return provider_settings_view()

    @router.post("/agent/provider-settings")
    def save_agent_provider_settings(body: ProviderSettingsRequest):
        from .agent import validate_base_url, validate_proxy_url
        from .provider_settings import environment_overrides, read_settings, write_settings
        if environment_overrides():
            raise HTTPException(status_code=409, detail="当前 Provider 由服务环境变量管理；请在服务端修改环境配置")
        current = read_settings(settings.data_dir)
        key = body.api_key if body.api_key else current["api_key"]
        if not key:
            raise ValueError("请填写 API Key；已保存时留空可保留原 Key")
        validate_base_url(body.base_url.strip().rstrip("/"))
        if body.proxy_url.strip():
            validate_proxy_url(body.proxy_url.strip())
        model = body.model.strip()
        if not model or any(ord(ch) < 33 or ord(ch) > 126 for ch in model):
            raise ValueError("模型名称格式无效")
        if len(key) > 4096 or any(ord(ch) < 33 or ord(ch) > 126 for ch in key):
            raise ValueError("API Key 格式无效")
        write_settings({
            "base_url": body.base_url.strip().rstrip("/"),
            "model": model,
            "proxy_url": body.proxy_url.strip(),
            "api_key": key,
        }, settings.data_dir)
        return provider_settings_view()

    @router.post("/agent/provider-settings/clear")
    def clear_agent_provider_key():
        from .provider_settings import clear_api_key, environment_overrides
        if environment_overrides():
            raise HTTPException(status_code=409, detail="当前 Provider 由服务环境变量管理；请在服务端修改环境配置")
        clear_api_key(settings.data_dir)
        return provider_settings_view()

    @router.get("/agent/status")
    def agent_status():
        from .agent import public_status
        return public_status(settings.data_dir)


    @router.post("/agent/provider-check")
    def agent_provider_check(body: ProviderCheckRequest):
        from .agent import ProviderConfig, provider_connectivity_check
        from .provider_settings import environment_overrides, record_provider_check
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；没有发送 Provider 请求")
        try:
            result = provider_connectivity_check(config=provider)
        except ValueError as exc:
            raise HTTPException(status_code=502, detail="Provider 连通性检查失败：" + str(exc)) from None
        persisted = None
        if not environment_overrides():
            try:
                persisted = record_provider_check(settings.data_dir, provider, result)
            except (OSError, ValueError):
                persisted = None
        result["probe_persisted"] = persisted is not None
        result["checked_at"] = persisted.get("checked_at") if persisted else None
        return result

    def _agent_consent_preview(body, provider):
        from .agent import consent_preview
        job = store.job(body.job_id)
        if job["status"] not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
            raise ValueError("只允许预览已有完整报告的候选")
        report = service.read_report(settings, job)
        candidate = service.finding(report, body.candidate_id)
        preview = consent_preview(settings, store, job, report, candidate, body.model_dump(), provider)
        return job, report, candidate, preview

    def _r0_review_complete(item, job, report, candidate):
        if not (item.get("job_id") == job["id"]
                and item.get("candidate_id") == candidate["id"]
                and item.get("repository") == report["repository"]
                and item.get("commit") == report["commit"]
                and item.get("report_sha256") == job["report_sha256"]
                and item.get("source_sha256") == candidate.get("source_sha256")):
            return False
        evidence = candidate.get("evidence")
        obligations = evidence.get("obligations", []) if isinstance(evidence, dict) else []
        count = min(len(obligations), 40) if isinstance(obligations, list) else 0
        reviews = item.get("obligation_reviews")
        if not isinstance(reviews, list) or len(reviews) != count:
            return False
        indices = [review.get("obligation_index") for review in reviews if isinstance(review, dict)]
        return len(indices) == count and sorted(indices) == list(range(count))

    def _fresh_consent_nonce(body):
        return body if body.consent_nonce else body.model_copy(update={"consent_nonce": uuid.uuid4().hex})

    def _require_consent_nonce(body):
        if not body.consent_nonce:
            raise HTTPException(status_code=428, detail="缺少本次预览 nonce；请重新预览后再授权提交")

    @router.post("/operations/agent-investigations/preview")
    def agent_investigation_preview(body: AgentInvestigationRequest):
        from .agent import ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        body = _fresh_consent_nonce(body)
        _, _, _, preview = _agent_consent_preview(body, provider)
        return preview

    @router.post("/operations/agent-investigations", status_code=201)
    def agent_investigation(body: AgentInvestigationRequest):
        from .agent import CONSENT_PREVIEW_VERSION, PROMPT_VERSION, REDACTION_POLICY_VERSION, TOOL_POLICY_VERSION, ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        if not body.source_submission_approved:
            raise HTTPException(status_code=428,
                                detail="请先查看本次源码外发预览并明确授权：" + provider.endpoint_host)
        if not body.consent_sha256:
            raise HTTPException(status_code=428, detail="缺少本次源码外发预览指纹，请重新预览")
        _require_consent_nonce(body)
        job, report, candidate, preview = _agent_consent_preview(body, provider)
        if not preview["agent_execution"]["eligible"]:
            raise HTTPException(status_code=409, detail=preview["agent_execution"]["reason"])
        if body.experiment_id:
            baselines = ops.agent_baseline_reviews(body.experiment_id)
            if not any(_r0_review_complete(item, job, report, candidate) for item in baselines):
                raise HTTPException(status_code=409,
                                    detail="实验批次需先为同一固定候选记录 R0 静态人工基线")
        if body.consent_sha256 != preview["consent_sha256"]:
            raise HTTPException(status_code=409, detail="源码外发预览已过期；模型、候选、模式或预算发生变化，请重新预览")
        if body.case_id:
            if not any(case["id"] == body.case_id for case in store.cases()):
                raise KeyError("case not found")
            linked = any(link["job_id"] == body.job_id and link["candidate_id"] == body.candidate_id
                         for link in _case_links(store, body.case_id))
            if not linked:
                raise ValueError("Agent case binding must already contain this exact job and candidate")
        spec = {
            "job_id": body.job_id, "candidate_id": body.candidate_id, "case_id": body.case_id,
            "experiment_id": body.experiment_id,
            "mode": body.mode, "max_steps": body.max_steps, "max_output_tokens": body.max_output_tokens,
            "max_total_input_tokens": body.max_total_input_tokens,
            "max_total_output_tokens": body.max_total_output_tokens,
            "timeout_seconds": body.timeout_seconds,
            "source_submission_approved": True, "source_submission_approved_at": now(),
            "source_consent_sha256": preview["consent_sha256"], "consent_nonce": body.consent_nonce,
            "consent_preview_version": CONSENT_PREVIEW_VERSION,
            "redaction_policy_version": REDACTION_POLICY_VERSION,
            "provider": provider.provider, "provider_model": provider.model,
            "provider_host": provider.endpoint_host, "provider_fingerprint": provider.fingerprint,
            "prompt_version": PROMPT_VERSION,
            "tool_policy_version": TOOL_POLICY_VERSION,
            "candidate_source_sha256": candidate.get("source_sha256"),
            "source_commit": report["commit"], "report_sha256": job["report_sha256"],
        }
        item = ops.create("agent_investigation", spec)
        if item["spec"].get("source_submission_approved_at") == spec["source_submission_approved_at"]:
            ops.event(item["id"], "source_consent",
                      "User approved preview sha256=" + preview["consent_sha256"] +
                      " for " + provider.endpoint_host)
        return ops.get(item["id"])

    def _agent_batch_preview(body, provider):
        if len(set(body.candidate_ids)) != len(body.candidate_ids):
            raise ValueError("候选列表包含重复 ID")
        job = store.job(body.job_id)
        if job["status"] not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
            raise ValueError("只允许预览已有完整报告的候选")
        report = service.read_report(settings, job)
        children = []
        for candidate_id in body.candidate_ids:
            child = AgentInvestigationRequest(job_id=body.job_id, candidate_id=candidate_id,
                consent_nonce=body.consent_nonce,
                mode=body.mode, max_steps=body.max_steps, max_output_tokens=body.max_output_tokens,
                max_total_input_tokens=body.max_total_input_tokens,
                max_total_output_tokens=body.max_total_output_tokens,
                timeout_seconds=body.timeout_seconds)
            _, _, candidate, preview = _agent_consent_preview(child, provider)
            children.append({"candidate_id": candidate_id, "file": candidate["file"],
                             "line": candidate.get("line"), "preview": preview})
        manifest = {"version": 1, "job_id": body.job_id, "report_sha256": job["report_sha256"],
                    "consent_nonce": body.consent_nonce,
                    "provider_fingerprint": provider.fingerprint,
                    "candidates": [{"candidate_id": item["candidate_id"],
                                    "consent_sha256": item["preview"]["consent_sha256"]} for item in children],
                    "mode": body.mode, "max_steps": body.max_steps,
                    "max_output_tokens": body.max_output_tokens,
                    "max_total_input_tokens": body.max_total_input_tokens,
                    "max_total_output_tokens": body.max_total_output_tokens,
                    "timeout_seconds": body.timeout_seconds}
        consent = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        blocked_candidate_ids = [item["candidate_id"] for item in children
                                 if not item["preview"]["agent_execution"]["eligible"]]
        max_repairs_per_candidate = max(
            (item["preview"].get("budgets", {}).get("max_validation_repairs", 0)
             for item in children), default=0)
        model_calls_per_candidate = (
            body.max_steps + 1 + max_repairs_per_candidate if body.mode == "tool_agent" else 1)
        aggregate_cost_estimate = _aggregate_agent_budget_cost_estimates(
            item["preview"].get("budget_cost_estimate") for item in children)
        return {"schema_version": 1, "consent_sha256": consent,
                "consent_nonce": body.consent_nonce, "provider": provider.public,
                "job_id": body.job_id, "report_sha256": job["report_sha256"],
                "candidate_count": len(children), "candidates": children,
                "aggregate_budget_cost_estimate": aggregate_cost_estimate,
                "blocked_candidate_ids": blocked_candidate_ids,
                "aggregate_budget": {"max_model_calls": len(children) * model_calls_per_candidate,
                    "max_validation_repair_calls": len(children) * max_repairs_per_candidate,
                    "max_total_input_tokens": len(children) * body.max_total_input_tokens,
                    "max_total_output_tokens": len(children) * body.max_total_output_tokens,
                    "max_wall_seconds_sequential": len(children) * body.timeout_seconds},
                "disclosure": ["Each selected candidate creates one independent Agent operation.",
                               "Each operation is independently capped by the budgets shown above.",
                               "Exact candidate metadata, bounded source excerpt, and approved fixed-commit tool data may be sent.",
                               "No operation is created until this aggregate preview is approved; batch creation is atomic.",
                               "A model assessment remains a candidate and requires human review."]}

    @router.post("/operations/agent-investigations/batch/preview")
    def agent_investigation_batch_preview(body: AgentBatchInvestigationRequest):
        from .agent import ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        body = _fresh_consent_nonce(body)
        return _agent_batch_preview(body, provider)

    @router.post("/operations/agent-investigations/batch", status_code=201)
    def agent_investigation_batch(body: AgentBatchInvestigationRequest):
        from .agent import CONSENT_PREVIEW_VERSION, PROMPT_VERSION, REDACTION_POLICY_VERSION, TOOL_POLICY_VERSION, ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        if not body.source_submission_approved:
            raise HTTPException(status_code=428, detail="请先查看整批源码外发预览并明确授权：" + provider.endpoint_host)
        if not body.consent_sha256:
            raise HTTPException(status_code=428, detail="缺少整批预览指纹，请重新预览")
        _require_consent_nonce(body)
        preview = _agent_batch_preview(body, provider)
        if preview["blocked_candidate_ids"]:
            raise HTTPException(status_code=409, detail=(
                "批次包含没有可由 Agent 补充源码义务的候选，拒绝将其发送给模型：" +
                ", ".join(preview["blocked_candidate_ids"])))
        if body.consent_sha256 != preview["consent_sha256"]:
            raise HTTPException(status_code=409, detail="整批源码外发预览已过期，请重新预览")
        batch_id = hashlib.sha256((preview["consent_sha256"] + now()).encode()).hexdigest()[:32]
        count = len(preview["candidates"])
        specs = []
        for index, item in enumerate(preview["candidates"], 1):
            child_preview = item["preview"]
            binding = child_preview["binding"]
            specs.append({
                "job_id": body.job_id, "candidate_id": item["candidate_id"], "case_id": None,
                "experiment_id": None, "mode": body.mode, "max_steps": body.max_steps,
                "max_output_tokens": body.max_output_tokens,
                "max_total_input_tokens": body.max_total_input_tokens,
                "max_total_output_tokens": body.max_total_output_tokens,
                "timeout_seconds": body.timeout_seconds,
                "source_submission_approved": True, "source_submission_approved_at": now(),
                "source_consent_sha256": child_preview["consent_sha256"], "consent_nonce": body.consent_nonce,
                "consent_preview_version": CONSENT_PREVIEW_VERSION,
                "redaction_policy_version": REDACTION_POLICY_VERSION,
                "provider": provider.provider, "provider_model": provider.model,
                "provider_host": provider.endpoint_host, "provider_fingerprint": provider.fingerprint,
                "prompt_version": PROMPT_VERSION, "tool_policy_version": TOOL_POLICY_VERSION,
                "candidate_source_sha256": binding.get("source_sha256"),
                "source_commit": binding["commit"], "report_sha256": binding["report_sha256"],
                "batch_id": batch_id, "batch_consent_sha256": preview["consent_sha256"],
                "batch_index": index, "batch_count": count,
            })
        items = ops.create_agent_batch(specs)
        batch_id = items[0]["spec"].get("batch_id", batch_id)
        return {"batch_id": batch_id, "batch_consent_sha256": preview["consent_sha256"],
                "created_count": len(items), "operations": items,
                "note": "每个候选一个独立任务；结论仍为候选，等待人工审核。"}

    def _agent_pair_previews(body, provider):
        previews = []
        for mode in ("single_shot", "tool_agent"):
            child = AgentInvestigationRequest(job_id=body.job_id, candidate_id=body.candidate_id,
                experiment_id=body.experiment_id, consent_nonce=body.consent_nonce,
                mode=mode, max_steps=body.max_steps,
                max_output_tokens=body.max_output_tokens,
                max_total_input_tokens=body.max_total_input_tokens,
                max_total_output_tokens=body.max_total_output_tokens,
                timeout_seconds=body.timeout_seconds)
            job, report, candidate, preview = _agent_consent_preview(child, provider)
            if not preview["agent_execution"]["eligible"]:
                raise HTTPException(status_code=409, detail=preview["agent_execution"]["reason"])
            baselines = ops.agent_baseline_reviews(body.experiment_id)
            if not any(_r0_review_complete(item, job, report, candidate) for item in baselines):
                raise HTTPException(status_code=409,
                                    detail="配对实验需先为同一固定候选记录 R0 静态人工基线")
            previews.append({"mode": mode, "preview": preview,
                             "candidate": candidate, "job": job, "report": report})
        manifest = {"version": 1, "experiment_id": body.experiment_id, "case_id": body.case_id,
                    "consent_nonce": body.consent_nonce,
                    "provider_fingerprint": provider.fingerprint,
                    "arms": [{"mode": item["mode"],
                              "consent_sha256": item["preview"]["consent_sha256"]} for item in previews],
                    "max_steps": body.max_steps, "max_output_tokens": body.max_output_tokens,
                    "max_total_input_tokens": body.max_total_input_tokens,
                    "max_total_output_tokens": body.max_total_output_tokens,
                    "timeout_seconds": body.timeout_seconds}
        consent = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        r2_repair_limit = previews[1]["preview"].get("budgets", {}).get("max_validation_repairs", 0)
        aggregate_cost_estimate = _aggregate_agent_budget_cost_estimates(
            item["preview"].get("budget_cost_estimate") for item in previews)
        return {"schema_version": 1, "consent_sha256": consent,
                "consent_nonce": body.consent_nonce, "experiment_id": body.experiment_id,
                "case_id": body.case_id, "provider": provider.public,
                "candidate": previews[0]["preview"]["binding"],
                "arms": [{"mode": item["mode"], "preview": item["preview"]} for item in previews],
                "aggregate_budget_cost_estimate": aggregate_cost_estimate,
                "aggregate_budget": {"max_model_calls": body.max_steps + 1 + r2_repair_limit,
                    "max_validation_repair_calls": r2_repair_limit,
                    "max_total_input_tokens": 2 * body.max_total_input_tokens,
                    "max_total_output_tokens": 2 * body.max_total_output_tokens,
                    "max_wall_seconds_sequential": 2 * body.timeout_seconds},
                "disclosure": ["This creates exactly one R1 and one R2 task for the same fixed candidate.",
                               "R0 static triage is already recorded and matched to this report and source.",
                               "Each arm receives its own consent-bound initial context; R2 may additionally use only the fixed-commit tools shown in its preview.",
                               "Aggregate budget includes up to two bounded structured-answer repairs per R2 arm; all operation rows are created atomically.",
                               "Both model outputs remain candidate-only and must receive blind human review."]}

    @router.post("/operations/agent-investigations/paired/preview")
    def agent_investigation_pair_preview(body: AgentPairedInvestigationRequest):
        from .agent import ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        body = _fresh_consent_nonce(body)
        return _agent_pair_previews(body, provider)

    @router.post("/operations/agent-investigations/paired", status_code=201)
    def agent_investigation_pair(body: AgentPairedInvestigationRequest):
        from .agent import CONSENT_PREVIEW_VERSION, PROMPT_VERSION, REDACTION_POLICY_VERSION, TOOL_POLICY_VERSION, ProviderConfig
        provider = ProviderConfig.from_env(settings.data_dir)
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        if not body.source_submission_approved:
            raise HTTPException(status_code=428, detail="请先查看 R1/R2 整组源码外发预览并明确授权：" + provider.endpoint_host)
        if not body.consent_sha256:
            raise HTTPException(status_code=428, detail="缺少配对预览指纹，请重新预览")
        _require_consent_nonce(body)
        preview = _agent_pair_previews(body, provider)
        if body.consent_sha256 != preview["consent_sha256"]:
            raise HTTPException(status_code=409, detail="R1/R2 配对预览已过期，请重新预览")
        if body.case_id:
            if not any(case["id"] == body.case_id for case in store.cases()):
                raise KeyError("case not found")
            linked = any(link["job_id"] == body.job_id and link["candidate_id"] == body.candidate_id
                         for link in _case_links(store, body.case_id))
            if not linked:
                raise ValueError("Agent case binding must already contain this exact job and candidate")
        pair_id = hashlib.sha256((preview["consent_sha256"] + now()).encode()).hexdigest()[:32]
        specs = []
        for index, arm in enumerate(preview["arms"], 1):
            arm_preview = arm["preview"]
            binding = arm_preview["binding"]
            specs.append({
                "job_id": body.job_id, "candidate_id": body.candidate_id, "case_id": body.case_id,
                "experiment_id": body.experiment_id, "mode": arm["mode"], "max_steps": body.max_steps,
                "max_output_tokens": body.max_output_tokens,
                "max_total_input_tokens": body.max_total_input_tokens,
                "max_total_output_tokens": body.max_total_output_tokens,
                "timeout_seconds": body.timeout_seconds,
                "source_submission_approved": True, "source_submission_approved_at": now(),
                "source_consent_sha256": arm_preview["consent_sha256"], "consent_nonce": body.consent_nonce,
                "consent_preview_version": CONSENT_PREVIEW_VERSION,
                "redaction_policy_version": REDACTION_POLICY_VERSION,
                "provider": provider.provider, "provider_model": provider.model,
                "provider_host": provider.endpoint_host, "provider_fingerprint": provider.fingerprint,
                "prompt_version": PROMPT_VERSION, "tool_policy_version": TOOL_POLICY_VERSION,
                "candidate_source_sha256": binding.get("source_sha256"),
                "source_commit": binding["commit"], "report_sha256": binding["report_sha256"],
                "pair_id": pair_id, "pair_consent_sha256": preview["consent_sha256"],
                "pair_index": index, "pair_count": 2,
            })
        items = ops.create_agent_batch(specs)
        pair_id = items[0]["spec"].get("pair_id", pair_id)
        return {"pair_id": pair_id, "pair_consent_sha256": preview["consent_sha256"],
                "created_count": len(items), "operations": items,
                "note": "R1/R2 各一个固定候选任务；仅完成配对运行，不代表实验效果。"}

    @router.post("/operations/validations", status_code=201)
    def validation(body: ValidationRequest):
        case = store.cases()
        if not any(c["id"] == body.case_id for c in case):
            raise KeyError("case not found")
        target = store.repository(body.target_repository_id)
        cutils = store.repository(body.cutils_repository_id)
        service.check_repository(settings, target["path"])
        service.check_repository(settings, cutils["path"])
        if target["name"] != "openharmony/inputmethod_imf":
            raise ValueError("AUTH-01 harness is pinned to openharmony/inputmethod_imf")
        pinned_target = {"e663b47013d534a56165ab7467fbb3e14bf7172b", "5eaddcab19bc4b22544f4bee1e8894fc2d6505dc"}
        target_commit = service.revision(target, body.target_commit)["commit"]
        if target_commit not in pinned_target:
            raise ValueError("AUTH-01 only accepts its two fixed source revisions")
        links = _case_links(store, body.case_id)
        manifest_path = Path(__file__).resolve().parents[2] / "src/ohscanner/poc/harnesses/auth01_descriptor_bypass/manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected_source = manifest["sources"][0]["path"]
        linked = False
        for link in links:
            linked_job = store.job(link["job_id"])
            linked_repo = store.repository(linked_job["repository_id"])
            if linked_repo["name"] == target["name"] and linked_job["spec"]["commit"] == target_commit:
                candidate = service.finding(service.read_report(settings, linked_job), link["candidate_id"])
                if candidate["file"] == expected_source:
                    linked = True
        if not linked:
            raise ValueError("case must link a candidate from the pinned AUTH-01 source at the selected commit")
        if cutils["name"] != "openharmony/commonlibrary_c_utils":
            raise ValueError("AUTH-01 requires the registered commonlibrary_c_utils repository")
        cutils_commit = service.revision(cutils, body.cutils_commit)["commit"]
        return ops.create("validation", {**body.model_dump(), "target_commit": target_commit,
            "target_repository": target["name"], "target_path": target["path"], "cutils_path": cutils["path"],
            "cutils_commit": cutils_commit, "timeout_seconds": body.timeout_seconds,
            "memory_mb": 2048})

    @router.post("/operations/investigations", status_code=201)
    def investigation(body: InvestigationRequest):
        job = store.job(body.job_id)
        report = service.read_report(settings, job)
        service.finding(report, body.candidate_id)
        return ops.create("investigation", {**body.model_dump(), "timeout_seconds": 60,
                                             "memory_mb": 512})

    @router.get("/scans/{key}/triage")
    def scan_triage_summary(key: str):
        job = store.job(key)
        authorization = store.triage_authorization(key)
        auth_view = None
        if authorization:
            snapshot = authorization["snapshot"]
            auth_view = {
                "authorized": True,
                "revoked": authorization["revoked"],
                "consent_sha256": authorization["consent_sha256"],
                "created_at": authorization["created_at"],
                "revoked_at": authorization["revoked_at"],
                "provider": snapshot.get("provider"),
                "candidate_limit": snapshot.get("candidate_limit"),
                "conditional_r2_candidate_limit": snapshot.get("r2_candidate_limit", 0),
                "budget": snapshot.get("budgets"),
                "estimated_cost": snapshot.get("estimated_cost"),
                "cost_budget": snapshot.get("cost_budget"),
                "platform_cost_budget_enforced": bool(
                    (snapshot.get("cost_budget") or {}).get("platform_enforced")),
                "hard_spend_cap": False,
            }
        cancellation = ops.triage_cancellation(key, job.get("report_sha256"))
        if not job.get("report_sha256"):
            waiting_state = ("cancelled" if cancellation else "stopped"
                             if authorization and authorization["revoked"] else "waiting_for_scan")
            return {
                "schema_version": 2,
                "audit_id": key,
                "job_id": key,
                "state": waiting_state,
                "scan_status": job["status"],
                "triage_status": waiting_state,
                "report_status": "not_ready",
                "scan_progress": {"status": job["status"], "stage": job.get("stage"),
                                  "report_ready": False},
                "triage_progress": {"state": "cancelled" if cancellation else "stopped" if authorization and authorization["revoked"] else "waiting_for_scan",
                                     "candidate_count": None, "planned_count": 0,
                                     "completed_count": 0, "failed_count": 0,
                                     "pending_count": 0, "cancelled_count": 0,
                                     "stop_requested_count": 0, "not_triaged_count": None},
                "report_sha256": None,
                "counts": {},
                "items": [],
                "batches": [],
                "authorization": auth_view or {"authorized": False, "revoked": False},
                "limitation": "静态报告尚未提交，模型研判未开始。",
            }
        items = ops.agent_investigations_for_job(key, job["report_sha256"])
        batches = ops.triage_batches_for_job(key, job["report_sha256"])
        counts = {}
        for item in items:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        batch_views = []
        for batch in batches:
            operations = ops.smart_triage_operations(batch["id"])
            states = [item["status"] for item in operations]
            stopping = any(item["status"] == "running" and item.get("cancel_requested") for item in operations)
            if stopping:
                batch_state = "stopping"
            elif cancellation:
                batch_state = "cancelled"
            elif batch.get("r2_status") == "awaiting_r1" or any(state in {"queued", "running"} for state in states):
                batch_state = "in_progress"
            elif states:
                batch_state = ("completed" if all(
                    state in {"completed", "completed_with_limitations"} for state in states
                ) else "partially_completed")
            else:
                batch_state = batch["status"]
            batch_views.append({
                "id": batch["id"], "state": batch_state,
                "candidate_count": batch["candidate_count"],
                "selected_count": batch["selected_count"],
                "candidate_manifest": batch["candidate_manifest"],
                "operation_ids": batch["operation_ids"],
                "conditional_r2": {
                    "state": batch.get("r2_status", "not_requested"),
                    "operation_ids": batch.get("r2_operation_ids", []),
                    "candidate_manifest": batch.get("r2_candidate_manifest", []),
                    "decision_sha256": batch.get("r2_decision_sha256"),
                    "error": batch.get("r2_error"),
                },
                "error": batch["error"],
            })
        r2_waiting = any(batch.get("r2_status") == "awaiting_r1" for batch in batches)
        stop_requested_count = sum(
            1 for item in items if item["status"] == "running" and item.get("cancel_requested")
        )
        cancelled_count = sum(1 for item in items if item["status"] == "cancelled")
        if cancellation and stop_requested_count:
            state = "stopping"
        elif cancellation:
            state = "cancelled"
        elif authorization and authorization["revoked"] and stop_requested_count:
            state = "stopping"
        elif job["spec"].get("audit_mode") == "static_only":
            state = "not_requested"
        elif r2_waiting:
            state = "in_progress"
        elif items:
            if any(item["status"] in {"queued", "running"} for item in items):
                state = "stopped" if authorization and authorization["revoked"] else "in_progress"
            elif all(item["status"] in END for item in items):
                state = "completed" if all(
                    item["status"] in {"completed", "completed_with_limitations"} for item in items
                ) else "partially_completed"
            else:
                state = "in_progress"
        elif authorization and authorization["revoked"]:
            state = "stopped"
        elif batch_views:
            state = batch_views[-1]["state"]
        elif authorization:
            state = "queued"
        else:
            state = "waiting_for_authorization"
        candidate_count = sum(batch.get("candidate_count", 0) for batch in batches) or None
        planned_count = len(items)
        if candidate_count is None and items:
            candidate_count = len({item.get("candidate_id") for item in items if item.get("candidate_id")})
        if candidate_count is None and not items:
            try:
                candidate_count = len(service.findings(service.read_report(settings, job)))
            except FileNotFoundError:
                # Some focused API tests stub a report hash without publishing an artifact.
                # Production report-integrity errors remain visible and fail closed.
                candidate_count = None
        if (candidate_count == 0 and not batches and not items
                and job["spec"].get("audit_mode") == "standard_review"):
            state = "no_eligible_candidates"
        completed_count = sum(1 for item in items if item["status"] in {"completed", "completed_with_limitations"})
        failed_count = sum(1 for item in items if item["status"] in {"failed", "timed_out", "interrupted"})
        pending_count = sum(1 for item in items if item["status"] in {"queued", "running"})
        manifest_not_triaged = sum(
            1 for batch in batches for row in batch.get("candidate_manifest", [])
            if isinstance(row, dict) and row.get("state") == "not_triaged"
        )
        not_triaged_count = (max(candidate_count - planned_count, manifest_not_triaged)
                             if candidate_count is not None else None)
        return {
            "schema_version": 2,
            "audit_id": key,
            "job_id": key,
            "state": state,
            "scan_status": job["status"],
            "triage_status": state,
            "report_status": ("ready_with_limitations"
                              if job["status"] == "completed_with_limitations"
                              else "ready" if job["status"] == "completed" else "available"),
            "scan_progress": {"status": job["status"], "stage": job.get("stage"),
                              "report_ready": True, "report_sha256": job["report_sha256"]},
            "triage_progress": {
                "state": state, "candidate_count": candidate_count,
                "planned_count": planned_count, "completed_count": completed_count,
                "failed_count": failed_count, "pending_count": pending_count,
                "cancelled_count": cancelled_count,
                "stop_requested_count": stop_requested_count,
                "r2_waiting_count": sum(1 for batch in batches if batch.get("r2_status") == "awaiting_r1"),
                "not_triaged_count": not_triaged_count,
            },
            "report_sha256": job["report_sha256"],
            "counts": counts,
            "items": items,
            "batches": batch_views,
            "authorization": auth_view or {"authorized": False, "revoked": False},
            "authorization_required": not bool(authorization),
            "limitation": "模型辅助研判输出仍为待复核候选或未知状态；高优先级或模型倾向不能自动确认漏洞。未入选、未授权和预算外候选仍是未研判，不代表安全。",
        }

    @router.post("/scans/{key}/triage/cancel")
    def cancel_scan_triage(key: str):
        job = store.job(key)
        cancellation = ops.cancel_triage_for_job(key, job.get("report_sha256"))
        return {**scan_triage_summary(key), "cancellation": cancellation}

    @router.post("/scans/{key}/triage/revoke")
    def revoke_scan_triage_authorization(key: str, body: TriageAuthorizationRevocationRequest):
        job = store.job(key)
        authorization = store.revoke_triage_authorization(key, body.consent_sha256)
        for operation in ops.list():
            spec = operation.get("spec", {})
            if (spec.get("job_id") == key
                    and spec.get("triage_authorization_sha256") == body.consent_sha256
                    and operation["status"] in {"queued", "running"}):
                ops.cancel(operation["id"])
        return scan_triage_summary(job["id"])

    @router.get("/scans/{key}/risks")
    def scan_risks(key: str, offset: int = 0, limit: int = 100):
        if offset < 0 or not 1 <= limit <= 200:
            raise ValueError("invalid pagination")
        job = store.job(key)
        if not job.get("report_sha256"):
            return {"audit_id": key, "state": "waiting_for_scan", "items": [], "counts": {}}
        report = service.read_report(settings, job)
        from .smart_audit import risk_snapshot as build_risk_snapshot
        snapshot = build_risk_snapshot(settings, store, ops, job, report)
        confirmed_cases = _validated_cases_for_audit(store, ops, key)
        snapshot["validated_vulnerability"] = len(confirmed_cases)
        snapshot["confirmed_cases"] = confirmed_cases
        items = snapshot["items"]
        return {**{name: value for name, value in snapshot.items() if name != "items"},
                "total": len(items), "items": items[offset:offset + limit]}

    @router.get("/scans/{key}/coverage")
    def scan_coverage(key: str):
        job = store.job(key)
        if not job.get("report_sha256"):
            return {"audit_id": key, "state": "waiting_for_scan", "scan_status": job["status"]}
        report = service.read_report(settings, job)
        from .smart_audit import coverage_snapshot
        triage = scan_triage_summary(key)
        return {"schema_version": 1, "audit_id": key,
                "report_sha256": job["report_sha256"],
                "coverage": coverage_snapshot(job, report),
                "scan_progress": triage["scan_progress"],
                "triage_progress": triage["triage_progress"]}

    @router.get("/overview/risks")
    def audit_risk_overview(
        scan_limit: int = 10,
        offset: int = 0,
        limit: int = 12,
        risk_tier: str | None = None,
        triage_state: str | None = None,
        repository: str | None = None,
        detector_id: str | None = None,
        q: str = "",
    ):
        if not 1 <= scan_limit <= 20:
            raise ValueError("scan_limit must be between 1 and 20")
        if offset < 0 or not 1 <= limit <= 100:
            raise ValueError("offset must be non-negative and limit between 1 and 100")
        tier_names = ("high_confidence_candidate", "further_validation",
                      "low_priority_manual", "unknown_source_binding")
        triage_states = {
            "not_requested", "not_triaged", "waiting_for_authorization", "waiting_for_scan",
            "not_started", "queued", "running", "in_progress", "stopping", "cancelled",
            "completed", "completed_with_limitations", "partially_completed", "blocked",
            "blocked_authorization_changed", "no_eligible_candidates", "stopped", "failed",
            "timed_out", "interrupted", "awaiting_r1", "budget_limited", "not_needed",
            "failed_selection", "selected", "not_selected", "unresolved",
        }
        if risk_tier is not None and risk_tier not in tier_names:
            raise ValueError("unsupported risk_tier")
        if triage_state is not None and triage_state not in triage_states:
            raise ValueError("unsupported triage_state")
        if repository is not None and (len(repository) > 200 or not repository.strip()):
            raise ValueError("repository filter must contain 1 to 200 characters")
        if detector_id is not None and (len(detector_id) > 200 or not detector_id.strip()):
            raise ValueError("detector_id filter must contain 1 to 200 characters")
        query = q.strip()
        if len(query) > 160:
            raise ValueError("q must be at most 160 characters")
        jobs = [job for job in store.jobs() if job.get("report_sha256")]
        selected = jobs[:scan_limit]
        from .smart_audit import risk_snapshot as build_risk_snapshot
        tier_counts = {name: 0 for name in tier_names}
        triage_counts = {}
        candidate_items = []
        limitations = []
        evaluated = 0
        validated_count = 0
        for job in selected:
            try:
                report = service.read_report(settings, job)
                risk = build_risk_snapshot(settings, store, ops, job, report)
                confirmed_cases = _validated_cases_for_audit(store, ops, job["id"])
            except Exception as exc:
                limitations.append({
                    "audit_id": job["id"],
                    "reason": "saved report could not be verified: " + type(exc).__name__,
                })
                continue
            evaluated += 1
            for tier in tier_names:
                tier_counts[tier] += int(risk.get("counts", {}).get(tier, 0))
            for state, count in risk.get("triage_counts", {}).items():
                triage_counts[state] = triage_counts.get(state, 0) + int(count)
            validated_count += len(confirmed_cases)
            for item in risk.get("items", []):
                candidate_items.append({
                    "audit_id": job["id"],
                    "repository": job["spec"].get("repository"),
                    "commit": job["spec"].get("commit"),
                    "created_at": job.get("created_at"),
                    "candidate_id": item.get("candidate_id"),
                    "detector_id": item.get("detector_id"),
                    "file": item.get("file"),
                    "line": item.get("line"),
                    "rule_id": item.get("rule_id"),
                    "severity": item.get("severity", "unknown"),
                    "vulnerability_state": item.get("vulnerability_state", "candidate"),
                    "risk_tier": item.get("risk_tier"),
                    "risk_tier_label": item.get("risk_tier_label"),
                    "confidence_basis": item.get("confidence_basis"),
                    "triage_state": item.get("triage", {}).get("state"),
                    "reason": "；".join(item.get("reasons", [])),
                })
        order = {"high_confidence_candidate": 0, "further_validation": 1,
                 "unknown_source_binding": 2, "low_priority_manual": 3}
        candidate_items.sort(key=lambda row: (
            order.get(row["risk_tier"], 4),
            row.get("created_at") or "", row.get("repository") or "",
            row.get("file") or "", int(row.get("line") or 0), row.get("candidate_id") or "",
        ))
        repository_key = repository.casefold() if repository else None
        query_key = query.casefold()
        base_filtered_items = [
            row for row in candidate_items
            if (risk_tier is None or row.get("risk_tier") == risk_tier)
            and (triage_state is None
                 or (triage_state == "unresolved"
                     and row.get("triage_state") not in {"completed", "completed_with_limitations"})
                 or row.get("triage_state") == triage_state)
            and (repository_key is None or str(row.get("repository") or "").casefold() == repository_key)
            and (not query_key or any(query_key in str(row.get(field) or "").casefold()
                                      for field in ("repository", "commit", "candidate_id", "file", "rule_id", "detector_id")))
        ]
        detector_counts = {}
        for row in base_filtered_items:
            detector = row.get("detector_id")
            if isinstance(detector, str) and detector:
                detector_counts[detector] = detector_counts.get(detector, 0) + 1
        filtered_items = [
            row for row in base_filtered_items
            if detector_id is None or row.get("detector_id") == detector_id
        ]
        total = sum(tier_counts.values())
        return {
            "schema_version": 1,
            "scope": "Most recent report-bearing scans, bounded to 20 and up to the latest 200 retained scan tasks.",
            "scan_limit": scan_limit,
            "available_report_count": len(jobs),
            "evaluated_scan_count": evaluated,
            "unavailable_report_count": len(limitations),
            "candidate_observation_count": total,
            "counts": tier_counts,
            "triage_counts": triage_counts,
            "detector_counts": [
                {"detector_id": detector, "candidate_count": count}
                for detector, count in sorted(detector_counts.items())
            ],
            "not_triaged_candidate_count": sum(
                count for state, count in triage_counts.items()
                if state not in {"completed", "completed_with_limitations"}
            ),
            "validated_vulnerability": validated_count,
            "offset": offset,
            "limit": limit,
            "filtered_candidate_count": len(filtered_items),
            "items": filtered_items[offset:offset + limit],
            "limitations": limitations,
            "semantics": "Counts are candidate observations across selected scans, not deduplicated root causes, vulnerability totals, recall, or proof that unobserved code is safe.",
        }

    @router.get("/scans/{key}/reports/snapshots")
    def audit_report_snapshots(key: str):
        store.job(key)
        return {"audit_id": key, "items": ops.audit_report_snapshots(key)}

    @router.post("/scans/{key}/reports/snapshots", status_code=201)
    def create_audit_report_snapshot(key: str):
        job = store.job(key)
        report = service.read_report(settings, job)
        from .smart_audit import coverage_snapshot, risk_snapshot as build_risk_snapshot
        risk = build_risk_snapshot(settings, store, ops, job, report)
        coverage = coverage_snapshot(job, report)
        triage = scan_triage_summary(key)
        confirmed_cases = _validated_cases_for_audit(store, ops, key)
        validated_count = sum(1 for item in confirmed_cases)
        risk["validated_vulnerability"] = validated_count
        risk["confirmed_cases"] = confirmed_cases
        batch_views = [{key_name: batch.get(key_name) for key_name in
                        ("id", "state", "candidate_count", "selected_count", "operation_ids", "error")}
                       for batch in triage.get("batches", [])]
        operation_views = [{key_name: item.get(key_name) for key_name in
                            ("id", "status", "candidate_id", "mode", "created_at", "finished_at", "result_sha256")}
                           for item in triage.get("items", [])]
        report_payload = {
            "schema_version": 1,
            "audit_id": key,
            "source_report_sha256": job["report_sha256"],
            "scan": {
                "repository": report["repository"], "commit": report["commit"],
                "tree": report.get("git_tree"), "include_paths": job["spec"].get("include_paths", []),
                "status": job["status"], "stage": job.get("stage"),
                "created_at": job.get("created_at"), "finished_at": job.get("finished_at"),
                "report_sha256": job["report_sha256"],
                "snapshot_sha256": report.get("snapshot_sha256"),
                "detector_versions": job["spec"].get("detector_versions", {}),
            },
            "scan_progress": triage.get("scan_progress"),
            "triage": {
                "state": triage["state"], "progress": triage.get("triage_progress"),
                "authorization": triage.get("authorization"),
                "batches": batch_views, "operations": operation_views,
            },
            "coverage": coverage,
            "risk_snapshot": risk,
            "confirmed_cases": confirmed_cases,
            "validated_vulnerability": validated_count,
            "limitations": list(dict.fromkeys(
                list(report.get("limitations", [])) + risk["limitations"]
                + ([triage["limitation"]] if triage.get("limitation") else [])
            )),
            "evidence_boundary": "静态与模型辅助发现均保持待复核候选或未知状态。只有现行人工评估关联有效源码证据，且通过运行时验证门确认产品可达性时，才计为已验证漏洞。",
        }
        snapshot = ops.create_audit_snapshots(
            risk, report_payload, _combined_audit_report_markdown,
        )
        return {key_name: snapshot[key_name] for key_name in
                ("id", "audit_id", "report_sha256", "risk_snapshot_id", "content_sha256",
                 "json_sha256", "markdown_sha256", "created_at")}

    @router.get("/scans/{key}/reports/snapshots/{snapshot_id}/json")
    def download_audit_report_json(key: str, snapshot_id: str):
        snapshot = ops.audit_report_snapshot(key, snapshot_id)
        return Response(snapshot["json_content"], media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="ohscanner-report-{snapshot_id}.json"',
                                 "X-Content-SHA256": snapshot["json_sha256"]})

    @router.get("/scans/{key}/reports/snapshots/{snapshot_id}/markdown")
    def download_audit_report_markdown(key: str, snapshot_id: str):
        snapshot = ops.audit_report_snapshot(key, snapshot_id)
        return Response(snapshot["markdown_content"], media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="ohscanner-report-{snapshot_id}.md"',
                                 "X-Content-SHA256": snapshot["markdown_sha256"]})

    @router.get("/operations/agent-review-queue/status")
    def agent_review_queue_status():
        return ops.candidate_review_queue()

    @router.post("/operations/agent-review-queue", status_code=201)
    def agent_review_queue(body: CandidateReviewQueueRequest):
        """Queue every candidate in one immutable report; never Top-K truncate."""
        job = store.job(body.job_id)
        report = service.read_report(settings, job)
        candidates = service.findings(report)
        spec = {"job_id": job["id"], "report_sha256": job["report_sha256"],
                "candidate_count_at_enqueue": len(candidates), "timeout_seconds": 60,
                "memory_mb": 512}
        operation = ops.create("candidate_review_batch", spec)
        return {**operation, "candidate_count": len(candidates),
                "review_mode": "candidate_only", "model_available": False,
                "note": "Candidates remain queued until a configured, source-bound review provider is available; no conclusion was inferred."}

    @router.get("/operations")
    def list_operations():
        return ops.list()

    @router.get("/operations/{key}")
    def operation(key: str):
        item = ops.get(key)
        item["events"] = ops.events(key)
        if item["result_sha256"]:
            item["result"] = ops.result(key)
        item["agent_reviews"] = ops.agent_reviews(key) if item["kind"] == "agent_investigation" else []
        if item["kind"] in {"revision_range", "branch_comparison", "version_matrix"}:
            endpoint_progress = []
            for job_id in item["spec"].get("scan_ids", []):
                job = store.job(job_id)
                authorized = store.triage_authorization(job_id)
                batches = (ops.triage_batches_for_job(job_id, job.get("report_sha256"))
                           if job.get("report_sha256") else [])
                if job["spec"].get("audit_mode") == "static_only":
                    state = "static_only"
                elif job["status"] not in {"completed", "completed_with_limitations"}:
                    state = ("awaiting_static" if job["status"] in {"queued", "running"}
                             else "static_incomplete")
                elif authorized is None:
                    state = "awaiting_individual_consent"
                elif authorized["revoked"]:
                    state = "authorization_revoked"
                elif not batches:
                    state = "awaiting_model_schedule"
                else:
                    batch = batches[-1]
                    ids = batch["operation_ids"] + batch["r2_operation_ids"]
                    statuses = [ops.get(operation_id)["status"] for operation_id in ids]
                    if batch["status"] == "blocked_authorization_changed":
                        state = "authorization_changed"
                    elif batch["status"] == "no_eligible_candidates":
                        state = "no_eligible_candidates"
                    elif (statuses and all(status in END for status in statuses)
                          and batch["r2_status"] != "awaiting_r1"):
                        state = ("completed" if all(status in {"completed", "completed_with_limitations"}
                                                  for status in statuses) else "partially_completed")
                    else:
                        state = "agent_in_progress"
                endpoint_progress.append({
                    "scan_id": job_id, "commit": job["spec"].get("commit"),
                    "scan_status": job["status"], "agent_status": state,
                    "agent_authorized": bool(authorized and not authorized["revoked"]),
                    "report_available": bool(job.get("report_sha256")),
                    "model_result_is_product_vulnerability_confirmation": False,
                })
            item["intelligent_review_progress"] = endpoint_progress
        return item

    @router.post("/operations/{key}/agent-reviews", status_code=201)
    def agent_human_review(key: str, body: AgentHumanReviewRequest):
        task = ops.get(key)
        if task["kind"] != "agent_investigation":
            raise ValueError("human Agent review requires an Agent investigation")
        record = body.model_dump()
        record["reviewer"] = record["reviewer"].strip()
        if not record["reviewer"]:
            raise ValueError("reviewer name must not be blank")
        return ops.record_agent_review(key, record)

    @router.post("/agent/blind-sessions", status_code=201)
    def create_agent_blind_session(body: AgentBlindSessionRequest):
        if len(set(body.operation_ids)) != len(body.operation_ids):
            raise HTTPException(status_code=422, detail="operation_ids must be unique")
        grouped = {}
        experiment_profiles = set()
        packets = []
        paired_budget_keys = ("max_steps", "max_output_tokens", "max_total_input_tokens",
                              "max_total_output_tokens", "timeout_seconds")
        for operation_id in body.operation_ids:
            task = ops.get(operation_id)
            if task["kind"] != "agent_investigation" or task["status"] not in {"completed", "completed_with_limitations"}:
                raise HTTPException(status_code=409, detail="blind review requires completed Agent results")
            result = ops.result(operation_id)
            if result.get("experiment_id") != body.experiment_id:
                raise HTTPException(status_code=409, detail="operation is outside the requested experiment")
            if result.get("vulnerability_state") != "candidate" or result.get("validated_vulnerability") != 0:
                raise HTTPException(status_code=409, detail="only candidate-only results may enter blind review")
            binding = result.get("binding") or {}
            spec = task.get("spec") or {}
            mode = result.get("mode")
            if mode not in {"single_shot", "tool_agent"} or spec.get("mode") != mode:
                raise HTTPException(status_code=409, detail="unsupported or mismatched Agent experiment arm")
            candidate_key = (binding.get("repository"), binding.get("commit"),
                             binding.get("report_sha256"), binding.get("candidate_id"),
                             binding.get("source_sha256"))
            if any(value is None for value in candidate_key):
                raise HTTPException(status_code=409, detail="result lacks a fixed source and report binding")
            provider_result = result.get("provider") or {}
            required_profile = (spec.get("provider_fingerprint"), spec.get("provider_model"),
                                spec.get("prompt_version"), spec.get("tool_policy_version"),
                                result.get("implementation_sha256"),
                                *(spec.get(key) for key in paired_budget_keys))
            if any(value is None for value in required_profile):
                raise HTTPException(status_code=409, detail="result lacks the immutable model, implementation, or budget profile")
            if (provider_result.get("model") != spec.get("provider_model")
                    or result.get("prompt_version") != spec.get("prompt_version")
                    or result.get("tool_policy_version") != spec.get("tool_policy_version")):
                raise HTTPException(status_code=409, detail="stored Agent profile does not match the executed result")
            experiment_profiles.add(required_profile)
            modes = grouped.setdefault(candidate_key, {})
            if mode in modes:
                raise HTTPException(status_code=409, detail="experiment has duplicate results for a candidate arm")
            modes[mode] = required_profile
            packets.append({"operation_id": operation_id, "result_sha256": task["result_sha256"],
                            "packet": _blind_packet(result)})
        if not grouped or any(set(modes) != {"single_shot", "tool_agent"} for modes in grouped.values()):
            raise HTTPException(status_code=409, detail="select complete R1/R2 pairs for each candidate")
        if len(experiment_profiles) != 1 or any(len(set(modes.values())) != 1 for modes in grouped.values()):
            raise HTTPException(status_code=409,
                                detail="R1/R2 results must use the same provider, model, implementation, prompt, and budget profile")
        baselines = ops.agent_baseline_reviews(body.experiment_id)
        baseline_keys = {(item["repository"], item["commit"], item["report_sha256"],
                          item["candidate_id"], item["source_sha256"]) for item in baselines}
        if any(candidate_key not in baseline_keys for candidate_key in grouped):
            raise HTTPException(status_code=409, detail="every candidate needs a source-matched R0 review")
        return ops.create_agent_blind_session(body.experiment_id, packets)

    @router.get("/agent/blind-sessions/{session_id}")
    def get_agent_blind_session(session_id: str):
        return ops.agent_blind_session(session_id)

    @router.post("/agent/blind-review-agreement")
    def agent_blind_review_agreement(body: AgentBlindAgreementRequest):
        return ops.agent_blind_review_agreement(body.session_ids)

    @router.get("/agent/blind-reviewer.html")
    def agent_blind_reviewer_page():
        path = Path(__file__).resolve().parents[2] / "web" / "agent-blind-reviewer.html"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="offline blind review form is not installed")
        return FileResponse(path, media_type="text/html")

    @router.get("/agent/blind-sessions/{session_id}/export")
    def export_agent_blind_session(session_id: str):
        data = ops.agent_blind_export(session_id)
        return Response(json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2),
                        media_type="application/json",
                        headers={"Content-Disposition": "attachment; filename=ohscanner-blind-session.json"})

    @router.get("/agent/blind-sessions/{session_id}/evidence-bundle")
    def export_agent_blind_evidence_bundle(session_id: str):
        data = ops.agent_blind_evidence_bundle(session_id)
        return Response(json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2),
                        media_type="application/json",
                        headers={"Content-Disposition":
                                 "attachment; filename=ohscanner-agent-evidence-bundle.json"})

    @router.post("/agent/blind-sessions/{session_id}/import", status_code=201)
    def import_agent_blind_reviews(session_id: str, body: AgentBlindReviewImportRequest):
        records = []
        for item in body.reviews:
            record = item.model_dump(exclude={"blind_item_id"})
            record["reviewer"] = record["reviewer"].strip()
            if not record["reviewer"]:
                raise ValueError("reviewer name must not be blank")
            records.append({"blind_item_id": item.blind_item_id, "record": record})
        return ops.import_agent_blind_reviews(session_id, records)

    @router.post("/agent/blind-sessions/{session_id}/close")
    def close_agent_blind_session(session_id: str):
        return ops.close_agent_blind_session(session_id)

    @router.get("/operations/{key}/result")
    def operation_result(key: str):
        return ops.result(key)

    @router.get("/operations/{key}/log")
    def operation_log(key: str):
        path = ops.directory(key) / "worker.log"
        if not path.is_file():
            raise KeyError("operation log not available")
        return Response(path.read_bytes()[-256 * 1024:], media_type="text/plain")

    @router.post("/operations/{key}/cancel")
    def cancel(key: str):
        return ops.cancel(key)

    @router.get("/cases/{case_id}/report.json")
    def case_report_json(case_id: str):
        links = _case_links(store, case_id)
        if not links:
            raise KeyError("case not found or empty")
        records = []
        for link in links:
            job = store.job(link["job_id"])
            report = service.read_report(settings, job)
            item = service.finding(report, link["candidate_id"])
            records.append({"job_id": job["id"], "report_sha256": job["report_sha256"],
                "repository": report["repository"], "commit": report["commit"],
                "candidate": item, "rationale": link["rationale"],
                "reviews": store.reviews(job["id"], item["id"]),
                "source_evidence": store.source_evidence(job["id"], item["id"])})
        operations = [x for x in ops.list() if x["spec"].get("case_id") == case_id and x["result_sha256"]]
        operation_summaries = []
        for x in operations[:20]:
            result = ops.result(x["id"])
            summary = {"id": x["id"], "kind": x["kind"], "status": x["status"],
                "result_sha256": x["result_sha256"], "validation_gate": result.get("validation_gate"),
                "gate_reason": result.get("gate_reason"), "reachability_status": result.get("reachability_status"),
                "validated_vulnerability": result.get("validated_vulnerability", 0),
                "commit": result.get("commit"), "commits": result.get("commits")}
            if x["kind"] == "agent_investigation":
                assessment = result.get("agent_assessment", {})
                summary["agent_triage"] = {
                    "triage_only": True, "assessment": assessment.get("assessment", "unknown"),
                    "summary": assessment.get("summary", ""),
                    "summary_provenance": result.get("summary_provenance", "legacy_model_generated_unverified"),
                    "model_summary_unverified": assessment.get("model_summary_unverified",
                        assessment.get("summary", "")),
                    "experiment_id": result.get("experiment_id"),
                    "supported_claims": assessment.get("supported_claims", []),
                    "obligation_reviews": assessment.get("obligation_reviews", []),
                    "citation_integrity": result.get("citation_integrity"),
                    "narrative_integrity": result.get("narrative_integrity", {
                        "unverified_narrative_fields": ["model_summary_unverified", "unsupported_claims", "unknowns", "next_steps"],
                        "narrative_semantics": "unverified_by_machine"}),
                    "unsupported_claims": assessment.get("unsupported_claims", []),
                    "unknowns": assessment.get("unknowns", []),
                    "next_steps": assessment.get("next_steps", []),
                    "mode": result.get("mode"),
                    "model": (result.get("provider") or {}).get("model"),
                    "model_usage": result.get("model_usage"),
                    "model_calls": result.get("model_calls", []),
                    "initial_evidence": result.get("initial_evidence"),
                    "tool_calls": result.get("tool_calls", []),
                    "prompt_version": result.get("prompt_version"),
                    "tool_policy_version": result.get("tool_policy_version"),
                    "source_submission": result.get("source_submission"),
                    "human_reviews": ops.agent_reviews(x["id"]),
                    "binding": result.get("binding"),
                    "limitations": result.get("limitations", []),
                    "vulnerability_state": result.get("vulnerability_state", "candidate"),
                }
            operation_summaries.append(summary)
        review_status = _case_review_status(store, ops, case_id)
        return {"schema_version": 1, "case_id": case_id, "candidates": records,
                "operations": operation_summaries,
                "assessments": ops.assessments(case_id),
                "latest_human_assessment": review_status["latest_human_assessment"],
                "validation_basis": review_status["validated_by"],
                "validated_vulnerability": review_status["validated_vulnerability"],
                "limitations": ["Static candidates and component harness observations do not establish product reachability or reportability.",
                                "A confirmed case count requires an append-only human assessment plus a matching passed runtime gate and verified product reachability."]}

    @router.get("/cases/{case_id}/report.md")
    def case_report_md(case_id: str):
        data = case_report_json(case_id)
        md = _markdown_inline_untrusted
        rows = ["# OHScanner 调查案例报告", "", "案例 ID：" + md(case_id), "", "## 候选与证据"]
        for row in data["candidates"]:
            c = row["candidate"]
            rows += ["", "### " + md(c["detector_id"]) + " / " + md(c["rule_id"]),
                     "", "- 来源：" + md(row["repository"]) + " @ " + md(row["commit"]),
                     "- 文件：" + md(c["file"]) + ":" + md(c["line"]),
                     "- 报告 SHA-256：" + md(row["report_sha256"]),
                     "- 结论：candidate；影响范围 unknown"]
        agent_ops = [item for item in data["operations"] if item.get("kind") == "agent_investigation"
                     and item.get("agent_triage")]
        if agent_ops:
            rows += ["", "## Agent 分诊建议（非漏洞确认）", "", "> 引用校验只确认引句逐字出现在绑定证据中；不验证引句是否支持模型陈述，语义推理仍需人工复核。"]
            for operation in agent_ops:
                triage = operation["agent_triage"]
                binding = triage["binding"] or {}
                usage = triage["model_usage"] or {}
                rows += ["", "- 操作：" + md(operation["id"]) + "；结果 SHA-256：" + md(operation["result_sha256"]),
                         "- 模式：" + md(triage["mode"] or "unknown") + "；模型倾向：" + md(triage["assessment"]) + "；漏洞状态：" + md(triage["vulnerability_state"]),
                         "- 模型：" + md(triage["model"] or "unknown") + "；提示词/工具策略：" + md(triage["prompt_version"]) + " / " + md(triage["tool_policy_version"]),
                         "- 来源绑定：" + md(binding.get("repository") or "unknown") + " @ " + md(binding.get("commit") or "unknown") +
                         "；" + md(binding.get("file") or "unknown") + "；candidate " + md(binding.get("candidate_id") or "unknown"),
                         "- 摘要（" + md(triage.get("summary_provenance", "legacy_model_generated_unverified")) + "）：“" + md(triage["summary"]) + "”",
                         "- Token：输入 " + md(usage.get("input_tokens") if usage.get("input_tokens") is not None else "unknown") +
                         " / 输出 " + md(usage.get("output_tokens") if usage.get("output_tokens") is not None else "unknown") +
                         "；缓存命中输入（输入内） " + md(usage.get("cached_input_tokens") if usage.get("cached_input_tokens") is not None else "unknown") +
                         "；推理 Token（输出内） " + md(usage.get("reasoning_tokens") if usage.get("reasoning_tokens") is not None else "unknown") +
                         "；Provider 实际费用 " + md(usage.get("cost", "unknown"))]
                estimate = usage.get("cost_estimate") if isinstance(usage.get("cost_estimate"), dict) else None
                if estimate and estimate.get("status") == "estimated_range":
                    rows += ["- 估算费用区间（非实账）：" + md(estimate.get("currency", "unknown")) + " " +
                             md(estimate.get("minimum_usd", "unknown")) + "–" +
                             md(estimate.get("maximum_usd", "unknown")) +
                             "；费率快照 " + md(estimate.get("rate_card_id", "unknown")) +
                             "；来源 " + md(estimate.get("rate_source_url", "unknown"))]
                elif estimate and estimate.get("status") == "estimated_amount":
                    amount_text = "USD " + md(estimate.get("amount_usd", "unknown"))
                    if estimate.get("amount_cny") is not None:
                        amount_text += " / CNY " + md(estimate["amount_cny"])
                    rows += ["- 估算费用（非实账）：" + amount_text +
                             "；费率快照 " + md(estimate.get("rate_card_id", "unknown")) +
                             "；来源 " + md(estimate.get("rate_source_url", "unknown"))]
                if triage.get("model_summary_unverified"):
                    rows += ["- 模型原始摘要（未核验文本）：“" + md(triage["model_summary_unverified"]) + "”"]
                if triage["initial_evidence"]:
                    rows += ["- 初始证据：" + md(triage["initial_evidence"].get("evidence_id")) +
                             "；context SHA-256 " + md(triage["initial_evidence"].get("context_sha256"))]
                for review in triage.get("human_reviews", []):
                    rows += ["- 人工评价（仅评价 Agent 分诊，不是漏洞结论）：" +
                             md(review.get("reviewer")) + "；有用性 " + md(review.get("usefulness")) +
                             "；引文准确性 " + md(review.get("citation_accuracy")) +
                             "；复核耗时秒 " + md(review.get("elapsed_seconds") if review.get("elapsed_seconds") is not None else "unknown")]
                    if review.get("claims_to_correct"):
                        rows += ["  - 需更正陈述：" + md(review["claims_to_correct"])]
                    if review.get("missed_evidence"):
                        rows += ["  - 遗漏证据：" + md(review["missed_evidence"])]
                    if review.get("notes"):
                        rows += ["  - 复核备注：" + md(review["notes"])]
                for claim in triage["supported_claims"]:
                    citations = claim.get("citations", [])
                    if citations:
                        citation_text = "；".join(md(item["evidence_id"]) + "：“" + md(item["quote"]) + "”"
                                                  for item in citations)
                    else:
                        citation_text = md("；".join(claim.get("evidence_ids", [])))
                    mapping = claim.get("obligation_indices")
                    mapping_text = ("; source obligations " + ", ".join("#" + str(index) for index in mapping)
                                    if isinstance(mapping, list) and mapping else "; legacy result lacks obligation mapping")
                    rows += ["- Supported claim: " + md(claim["claim"]) + " (" + md(mapping_text) +
                             "; cited evidence: " + citation_text + ")"]
                initial_context = (triage.get("initial_evidence") or {}).get("context") or {}
                obligations = initial_context.get("evidence_obligations", [])
                if triage.get("obligation_reviews"):
                    rows += ["- 证据义务逐项分诊（引文存在性已核验；语义是否支持仍需人工判断）："]
                    for item in triage["obligation_reviews"]:
                        index = item.get("obligation_index", -1)
                        obligation = obligations[index] if isinstance(index, int) and 0 <= index < len(obligations) else "unknown obligation"
                        if isinstance(obligation, dict):
                            obligation = obligation.get("description") or obligation.get("kind") or str(obligation)
                        citations = item.get("citations", [])
                        citation_text = "；".join(
                            md(citation.get("evidence_id", "unknown")) + "：“" + md(citation.get("quote", "")) + "”"
                            for citation in citations) or "无引文；保持未决"
                        rows += ["  - #" + md(index) + " " + md(item.get("disposition", "unresolved")) +
                                 " · " + md(obligation) + "（" + citation_text + "）"]
                if triage["unsupported_claims"]:
                    rows += ["- 无证据支持的陈述：" + md("；".join(triage["unsupported_claims"]))]
                if triage["unknowns"]:
                    rows += ["- 未知项：" + md("；".join(triage["unknowns"]))]
                if triage["next_steps"]:
                    rows += ["- 建议复核步骤：" + md("；".join(triage["next_steps"]))]
                if triage["limitations"]:
                    rows += ["- 调查限制：" + md("；".join(triage["limitations"]))]
                if triage["source_submission"]:
                    consent = triage["source_submission"]
                    rows += ["- 源码外发目的地：" + md(consent.get("destination_host") or "unknown") +
                             "；授权预览 SHA-256 " + md(consent.get("consent_sha256") or "unknown") +
                             "；预览版本 " + md(consent.get("consent_preview_version") or "unknown")]
        human_assessments = [item for item in data["assessments"] if item.get("reviewer_kind") == "human"]
        if human_assessments:
            rows += ["", "## 人工案例复核"]
            for assessment in human_assessments:
                rows += ["", "- 复核人：" + md(assessment.get("reviewer")) +
                         "；结论：" + md(assessment.get("outcome")) +
                         "；证据 ID：" + md("、".join(assessment.get("evidence_ids", [])))]
                if assessment.get("notes"):
                    rows += ["  - 记录：" + md(assessment["notes"])]
                if assessment.get("remaining_unknowns"):
                    rows += ["  - 未决项：" + md("；".join(assessment["remaining_unknowns"]))]
        rows += ["", "## 限制", "", *["- " + md(x) for x in data["limitations"]],
                 "", "经门控确认的漏洞数：" + md(data["validated_vulnerability"]) +
                 "（候选数不计入；模型建议不能单独确认）。"]
        return Response("\n".join(rows) + "\n", media_type="text/markdown")

    @router.post("/cases/{case_id}/agent-assessments", status_code=201)
    def agent_assessment(case_id: str, body: AgentProposalRequest):
        links = [link for link in _case_links(store, case_id) if link["candidate_id"] == body.candidate_id]
        if not links:
            raise KeyError("candidate is not linked to this case")
        link = links[0]
        job = store.job(link["job_id"])
        report = service.read_report(settings, job)
        candidate = service.finding(report, body.candidate_id)
        if report["commit"] != body.source_commit:
            raise ValueError("agent citation commit does not match the candidate's fixed source")
        source = service.source(settings, store, job, candidate["file"])
        if source["blob"] != body.source_blob or source["sha256"] != body.source_sha256:
            raise ValueError("agent citation blob/hash does not match the fixed source")
        lines = source["text"].splitlines()
        if body.line_end < body.line_start or body.line_end > len(lines):
            raise ValueError("agent citation line range is outside the fixed source")
        for citation in (*body.supporting_evidence, *body.refuting_evidence):
            cited_source = service.source(settings, store, job, citation.file)
            cited_lines = cited_source["text"].splitlines()
            if (cited_source["blob"] != citation.blob or cited_source["sha256"] != citation.source_sha256
                    or citation.line_end < citation.line_start or citation.line_end > len(cited_lines)):
                raise ValueError("agent evidence citation does not match the fixed source blob/hash/line range")
        record = {
            "record_kind": "agent_proposal", "reviewer_kind": "agent", "reviewer": body.agent_id,
            "outcome": body.suggestion, "notes": body.summary,
            "source_binding": {"job_id": job["id"], "report_sha256": job["report_sha256"],
                "repository": report["repository"], "commit": report["commit"],
                "candidate_id": candidate["id"], "file": candidate["file"],
                "blob": source["blob"], "source_sha256": source["sha256"],
                "line_start": body.line_start, "line_end": body.line_end},
            "supporting_evidence": [c.model_dump() for c in body.supporting_evidence],
            "refuting_evidence": [c.model_dump() for c in body.refuting_evidence],
            "unresolved_obligations": body.unresolved_obligations,
            "model_runtime": {"provider": body.provider, "model_version": body.model_version,
                "prompt_version": body.prompt_version, "tool_version": body.tool_version,
                "run_id": body.run_id, "input_tokens": body.input_tokens,
                "output_tokens": body.output_tokens, "duration_ms": body.duration_ms,
                "attestation": "provider/runtime metadata is caller-supplied and not authenticated"},
            "confirmation_effect": "none; human approval and existing validation gate remain required",
        }
        return ops.assessment(case_id, record)

    @router.post("/cases/{case_id}/assessments", status_code=201)
    def assessment(case_id: str, body: AssessmentRequest):
        links = _case_links(store, case_id)
        if not links:
            raise KeyError("case not found or empty")
        record = body.model_dump()
        if body.reviewer_kind == "agent":
            raise ValueError("Agent proposals must use the source-bound /agent-assessments endpoint")
        valid_refs = {e["id"] for link in links for e in store.source_evidence(link["job_id"], link["candidate_id"])}
        if not set(body.evidence_ids).issubset(valid_refs):
            raise ValueError("assessment references evidence outside this case")
        if body.outcome in {"confirmed", "reportable"}:
            eligible = False
            for oid in body.validation_operation_ids:
                task = ops.get(oid)
                if task["kind"] == "validation" and task["spec"].get("case_id") == case_id and task["status"] in {"completed", "completed_with_limitations"}:
                    result = ops.result(oid)
                    if (result.get("validation_gate") == "passed" and result.get("case_id") == case_id
                            and result.get("reachability_status") == "verified"):
                        eligible = True
            if not eligible or not body.evidence_ids or not body.remaining_unknowns:
                raise ValueError("confirmed/reportable requires a passed bound runtime gate, verified product reachability, case evidence IDs, and explicit remaining unknowns")
        return ops.assessment(case_id, record)

    app.include_router(router)
    return ops

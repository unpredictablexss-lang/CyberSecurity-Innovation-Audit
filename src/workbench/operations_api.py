"""Typed local API for long-running operations; every input becomes an immutable plan."""
import hashlib
import json
import re
from pathlib import Path
from typing import Literal
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from .operations import approved_url, date_selection, enqueue_branch_comparison, enqueue_range
from .operations_store import Operations, END
from .store import now
from . import service


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SyncRequest(Strict):
    repository: str = Field(pattern=r"^openharmony/[A-Za-z0-9_-]{1,100}$")
    url: str = Field(min_length=16, max_length=300)
    timeout_seconds: int = Field(default=900, ge=10, le=3600)


class RangeRequest(Strict):
    repository_id: str
    baseline: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    endpoint: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] = Field(min_length=1, max_length=10)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class DateRangeRequest(Strict):
    repository_id: str
    branch: str = Field(min_length=1, max_length=200)
    start: str = Field(min_length=10, max_length=40)
    end: str = Field(min_length=10, max_length=40)
    timezone: str = Field(min_length=1, max_length=100)
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] = Field(min_length=1, max_length=10)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class DateRangePreviewRequest(Strict):
    repository_id: str
    branch: str = Field(min_length=1, max_length=200)
    start: str = Field(min_length=10, max_length=40)
    end: str = Field(min_length=10, max_length=40)
    timezone: str = Field(min_length=1, max_length=100)


class MatrixRequest(Strict):
    case_id: str
    repository_id: str
    commits: list[str] = Field(min_length=2, max_length=8)
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] = Field(min_length=1, max_length=10)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class BranchComparisonRequest(Strict):
    repository_id: str
    baseline_ref: str = Field(min_length=1, max_length=200)
    endpoint_ref: str = Field(min_length=1, max_length=200)
    include_paths: list[str] = Field(default_factory=lambda: ["."], min_length=1, max_length=100)
    detector_ids: list[str] = Field(min_length=1, max_length=10)
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




class AgentBaselineReviewRequest(Strict):
    job_id: str
    candidate_id: str = Field(min_length=1, max_length=200)
    experiment_id: str = Field(min_length=1, max_length=64,
                               pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    reviewer: str = Field(min_length=1, max_length=100)
    disposition: Literal["investigate", "likely_noise", "unknown"]
    elapsed_seconds: int | None = Field(default=None, ge=0, le=7200)
    notes: str = Field(default="", max_length=1200)

class AgentHumanReviewRequest(Strict):
    reviewer: str = Field(min_length=1, max_length=100)
    usefulness: Literal["useful", "partially_useful", "not_useful", "unsafe"]
    citation_accuracy: Literal["all_accurate", "some_incorrect", "mostly_incorrect", "not_checked"]
    elapsed_seconds: int | None = Field(default=None, ge=0, le=7200)
    claims_to_correct: str = Field(default="", max_length=1200)
    missed_evidence: str = Field(default="", max_length=1200)
    notes: str = Field(default="", max_length=1000)


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


def install_routes(app: FastAPI, settings, store):
    ops = Operations(store)
    router = APIRouter(prefix="/api/v1")

    @router.get("/agent/evaluation-summary")
    def agent_evaluation_summary():
        return ops.agent_evaluation_summary()

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
            "review_scope": "static_only_r0_triage",
            "vulnerability_state": "candidate",
            "validated_vulnerability": 0,
        }
        return ops.record_agent_baseline_review(record)

    @router.post("/operations/source-sync", status_code=201)
    def source_sync(body: SyncRequest):
        url = approved_url(body.url)
        expected = "/" + body.repository + (".git" if body.url.endswith(".git") else "")
        from urllib.parse import urlsplit
        if urlsplit(url).path != expected:
            raise ValueError("repository URL path must match the approved repository name")
        return ops.create("source_sync", {"name": body.repository, "url": url,
                                          "timeout_seconds": body.timeout_seconds})

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
        return ops.create_with_scans("version_matrix", {"case_id": body.case_id,
            "repository_id": repo["id"], "commits": [s["commit"] for s in specs],
            "timeout_seconds": body.timeout_seconds * len(specs) + 120,
            "memory_mb": body.memory_mb}, repo["id"], specs)

    @router.get("/agent/status")
    def agent_status():
        from .agent import public_status
        return public_status()

    def _agent_consent_preview(body, provider):
        from .agent import consent_preview
        job = store.job(body.job_id)
        if job["status"] not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
            raise ValueError("只允许预览已有完整报告的候选")
        report = service.read_report(settings, job)
        candidate = service.finding(report, body.candidate_id)
        preview = consent_preview(settings, store, job, report, candidate, body.model_dump(), provider)
        return job, report, candidate, preview

    @router.post("/operations/agent-investigations/preview")
    def agent_investigation_preview(body: AgentInvestigationRequest):
        from .agent import ProviderConfig
        provider = ProviderConfig.from_env()
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        _, _, _, preview = _agent_consent_preview(body, provider)
        return preview

    @router.post("/operations/agent-investigations", status_code=201)
    def agent_investigation(body: AgentInvestigationRequest):
        from .agent import CONSENT_PREVIEW_VERSION, PROMPT_VERSION, TOOL_POLICY_VERSION, ProviderConfig
        provider = ProviderConfig.from_env()
        if not provider.configured:
            raise HTTPException(status_code=503, detail="真实模型未配置；静态扫描和只读调查仍可使用")
        if not body.source_submission_approved:
            raise HTTPException(status_code=428,
                                detail="请先查看本次源码外发预览并明确授权：" + provider.endpoint_host)
        if not body.consent_sha256:
            raise HTTPException(status_code=428, detail="缺少本次源码外发预览指纹，请重新预览")
        job, report, candidate, preview = _agent_consent_preview(body, provider)
        if body.experiment_id:
            baselines = ops.agent_baseline_reviews(body.experiment_id)
            if not any(item["job_id"] == body.job_id
                       and item["candidate_id"] == body.candidate_id
                       and item["repository"] == report["repository"]
                       and item["commit"] == report["commit"]
                       and item["report_sha256"] == job["report_sha256"]
                       and item["source_sha256"] == candidate.get("source_sha256")
                       for item in baselines):
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
            "source_consent_sha256": preview["consent_sha256"],
            "consent_preview_version": CONSENT_PREVIEW_VERSION,
            "provider": provider.provider, "provider_model": provider.model,
            "provider_host": provider.endpoint_host, "provider_fingerprint": provider.fingerprint,
            "prompt_version": PROMPT_VERSION,
            "tool_policy_version": TOOL_POLICY_VERSION,
            "candidate_source_sha256": candidate.get("source_sha256"),
            "source_commit": report["commit"], "report_sha256": job["report_sha256"],
        }
        item = ops.create("agent_investigation", spec)
        ops.event(item["id"], "source_consent",
                  "User approved preview sha256=" + preview["consent_sha256"] +
                  " for " + provider.endpoint_host)
        return ops.get(item["id"])

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
                "gate_reason": result.get("gate_reason"), "validated_vulnerability": result.get("validated_vulnerability", 0),
                "commit": result.get("commit"), "commits": result.get("commits")}
            if x["kind"] == "agent_investigation":
                assessment = result.get("agent_assessment", {})
                summary["agent_triage"] = {
                    "triage_only": True, "assessment": assessment.get("assessment", "unknown"),
                    "summary": assessment.get("summary", ""),
                    "experiment_id": result.get("experiment_id"),
                    "supported_claims": assessment.get("supported_claims", []),
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
        return {"schema_version": 1, "case_id": case_id, "candidates": records,
                "operations": operation_summaries,
                "assessments": ops.assessments(case_id),
                "validated_vulnerability": 0,
                "limitations": ["Static candidates and component harness observations do not establish product reachability or reportability."]}

    @router.get("/cases/{case_id}/report.md")
    def case_report_md(case_id: str):
        data = case_report_json(case_id)
        rows = ["# OHScanner 调查案例报告", "", "案例 ID：" + case_id, "", "## 候选与证据"]
        for row in data["candidates"]:
            c = row["candidate"]
            rows += ["", "### " + c["detector_id"] + " / " + c["rule_id"],
                     "", "- 来源：" + row["repository"] + " @ " + row["commit"],
                     "- 文件：" + c["file"] + ":" + str(c["line"]),
                     "- 报告 SHA-256：" + row["report_sha256"],
                     "- 结论：candidate；影响范围 unknown"]
        agent_ops = [item for item in data["operations"] if item.get("kind") == "agent_investigation"
                     and item.get("agent_triage")]
        if agent_ops:
            rows += ["", "## Agent 分诊建议（非漏洞确认）"]
            for operation in agent_ops:
                triage = operation["agent_triage"]
                binding = triage["binding"] or {}
                usage = triage["model_usage"] or {}
                rows += ["", "- 操作：" + operation["id"] + "；结果 SHA-256：" + str(operation["result_sha256"]),
                         "- 模式：" + str(triage["mode"] or "unknown") + "；模型倾向：" + triage["assessment"] + "；漏洞状态：" + triage["vulnerability_state"],
                         "- 模型：" + str(triage["model"] or "unknown") + "；提示词/工具策略：" + str(triage["prompt_version"]) + " / " + str(triage["tool_policy_version"]),
                         "- 来源绑定：" + str(binding.get("repository") or "unknown") + " @ " + str(binding.get("commit") or "unknown") +
                         "；" + str(binding.get("file") or "unknown") + "；candidate " + str(binding.get("candidate_id") or "unknown"),
                         "- 摘要：" + str(triage["summary"]),
                         "- Token：输入 " + str(usage.get("input_tokens") if usage.get("input_tokens") is not None else "unknown") +
                         " / 输出 " + str(usage.get("output_tokens") if usage.get("output_tokens") is not None else "unknown") +
                         "；费用 " + str(usage.get("cost", "unknown"))]
                if triage["initial_evidence"]:
                    rows += ["- 初始证据：" + str(triage["initial_evidence"].get("evidence_id")) +
                             "；context SHA-256 " + str(triage["initial_evidence"].get("context_sha256"))]
                for review in triage.get("human_reviews", []):
                    rows += ["- 人工评价（仅评价 Agent 分诊，不是漏洞结论）：" +
                             str(review.get("reviewer")) + "；有用性 " + str(review.get("usefulness")) +
                             "；引文准确性 " + str(review.get("citation_accuracy")) +
                             "；复核耗时秒 " + str(review.get("elapsed_seconds") if review.get("elapsed_seconds") is not None else "unknown")]
                    if review.get("claims_to_correct"):
                        rows += ["  - 需更正陈述：" + review["claims_to_correct"]]
                    if review.get("missed_evidence"):
                        rows += ["  - 遗漏证据：" + review["missed_evidence"]]
                    if review.get("notes"):
                        rows += ["  - 复核备注：" + review["notes"]]
                for claim in triage["supported_claims"]:
                    citations = claim.get("citations", [])
                    if citations:
                        citation_text = "；".join(item["evidence_id"] + "：“" + item["quote"] + "”"
                                                  for item in citations)
                    else:
                        citation_text = "；".join(claim.get("evidence_ids", []))
                    rows += ["- 支持陈述：" + claim["claim"] + "（证据引句：" + citation_text + "）"]
                if triage["unsupported_claims"]:
                    rows += ["- 无证据支持的陈述：" + "；".join(triage["unsupported_claims"])]
                if triage["unknowns"]:
                    rows += ["- 未知项：" + "；".join(triage["unknowns"])]
                if triage["next_steps"]:
                    rows += ["- 建议复核步骤：" + "；".join(triage["next_steps"])]
                if triage["limitations"]:
                    rows += ["- 调查限制：" + "；".join(triage["limitations"])]
                if triage["source_submission"]:
                    consent = triage["source_submission"]
                    rows += ["- 源码外发目的地：" + str(consent.get("destination_host") or "unknown") +
                             "；授权预览 SHA-256 " + str(consent.get("consent_sha256") or "unknown") +
                             "；预览版本 " + str(consent.get("consent_preview_version") or "unknown")]
        rows += ["", "## 限制", "", *["- " + x for x in data["limitations"]],
                 "", "确认漏洞数：0（本报告不会根据候选自动确认）。"]
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

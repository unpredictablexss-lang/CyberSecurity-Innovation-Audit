"""Typed local API for long-running operations; every input becomes an immutable plan."""
import hashlib
import json
import re
from pathlib import Path
from typing import Literal
from fastapi import APIRouter, FastAPI
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from .operations import approved_url, date_selection, enqueue_range
from .operations_store import Operations, END
from . import service
from .service import MAX_INCLUDE_PATHS


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
    include_paths: list[str] = Field(
        default_factory=lambda: ["."], min_length=1, max_length=MAX_INCLUDE_PATHS
    )
    detector_ids: list[str] = Field(min_length=1, max_length=10)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class DateRangeRequest(Strict):
    repository_id: str
    branch: str = Field(min_length=1, max_length=200)
    start: str = Field(min_length=10, max_length=40)
    end: str = Field(min_length=10, max_length=40)
    timezone: str = Field(min_length=1, max_length=100)
    include_paths: list[str] = Field(
        default_factory=lambda: ["."], min_length=1, max_length=MAX_INCLUDE_PATHS
    )
    detector_ids: list[str] = Field(min_length=1, max_length=10)
    timeout_seconds: int = Field(default=600, ge=30, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class MatrixRequest(Strict):
    case_id: str
    repository_id: str
    commits: list[str] = Field(min_length=2, max_length=8)
    include_paths: list[str] = Field(
        default_factory=lambda: ["."], min_length=1, max_length=MAX_INCLUDE_PATHS
    )
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


class AssessmentRequest(Strict):
    outcome: Literal["candidate", "dynamic_reproduced_component_issue", "confirmed", "reportable"]
    reviewer: str = Field(min_length=1, max_length=100)
    notes: str = Field(min_length=1, max_length=8000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    validation_operation_ids: list[str] = Field(default_factory=list, max_length=10)
    remaining_unknowns: list[str] = Field(default_factory=list, max_length=50)


def _case_links(store, case_id):
    with store.connect() as db:
        return [dict(x) for x in db.execute("SELECT * FROM case_links WHERE case_id=? ORDER BY job_id,candidate_id", (case_id,))]


def install_routes(app: FastAPI, settings, store):
    ops = Operations(store)
    router = APIRouter(prefix="/api/v1")

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

    @router.get("/operations")
    def list_operations():
        return ops.list()

    @router.get("/operations/{key}")
    def operation(key: str):
        item = ops.get(key)
        item["events"] = ops.events(key)
        if item["result_sha256"]:
            item["result"] = ops.result(key)
        return item

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
            operation_summaries.append({"id": x["id"], "kind": x["kind"], "status": x["status"],
                "result_sha256": x["result_sha256"], "validation_gate": result.get("validation_gate"),
                "gate_reason": result.get("gate_reason"), "validated_vulnerability": result.get("validated_vulnerability", 0),
                "commit": result.get("commit"), "commits": result.get("commits")})
        payload = {"schema_version": 1, "case_id": case_id, "candidates": records,
                "operations": operation_summaries,
                "assessments": ops.assessments(case_id),
                "validated_vulnerability": 0,
                "limitations": ["Static candidates and component harness observations do not establish product reachability or reportability."]}
        return Response(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{case_id}.json"'
            },
        )

    @router.get("/cases/{case_id}/report.md")
    def case_report_md(case_id: str):
        data = json.loads(case_report_json(case_id).body)
        rows = ["# OHScanner 调查案例报告", "", "案例 ID：" + case_id, "", "## 候选与证据"]
        for row in data["candidates"]:
            c = row["candidate"]
            rows += ["", "### " + c["detector_id"] + " / " + c["rule_id"],
                     "", "- 来源：" + row["repository"] + " @ " + row["commit"],
                     "- 文件：" + c["file"] + ":" + str(c["line"]),
                     "- 报告 SHA-256：" + row["report_sha256"],
                     "- 结论：candidate；影响范围 unknown"]
        rows += ["", "## 限制", "", *["- " + x for x in data["limitations"]],
                 "", "确认漏洞数：0（本报告不会根据候选自动确认）。"]
        return Response(
            "\n".join(rows) + "\n",
            media_type="text/markdown",
            headers={
                "Content-Disposition": f'attachment; filename="{case_id}.md"'
            },
        )

    @router.post("/cases/{case_id}/assessments", status_code=201)
    def assessment(case_id: str, body: AssessmentRequest):
        links = _case_links(store, case_id)
        if not links:
            raise KeyError("case not found or empty")
        record = body.model_dump()
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

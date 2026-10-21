"""Loopback-only API; same-origin UI, registered local repositories, no arbitrary execution."""

import json
from pathlib import Path
import fcntl
import sqlite3
import subprocess
import uuid
from typing import Literal
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware
from .settings import Settings
from .store import Store, TERMINAL
from . import service
from .repository_management import (discover_repositories, online_repository_catalog,
                                   repository_catalog, repository_roots)
from .source_roots import add_managed_root, record_root_check, remove_managed_root
from .triage_limits import MAX_TRIAGE_CANDIDATES_PER_ENDPOINT


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceRootInput(StrictModel):
    alias: str = Field(default="", max_length=80)
    path: str = Field(min_length=1, max_length=4096)


class RepositoryInput(StrictModel):
    name: str = Field(
        min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
    )
    path: str = Field(min_length=1, max_length=1000)


class AuditPlanInput(StrictModel):
    repository_id: str
    revision: str = Field(min_length=1, max_length=200)
    base_commit: str | None = Field(default=None, pattern=r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
    include_paths: list[str] = Field(
        default_factory=lambda: ["."], min_length=1, max_length=100
    )
    detector_ids: list[str] | None = Field(default=None, max_length=16)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)
    audit_mode: Literal["standard_review", "static_only"] = "standard_review"
    auto_triage: bool = False
    max_triage_candidates: int = Field(default=5, ge=1, le=MAX_TRIAGE_CANDIDATES_PER_ENDPOINT)
    max_r2_candidates: int = Field(default=0, ge=0, le=MAX_TRIAGE_CANDIDATES_PER_ENDPOINT)
    max_cost_usd: str | None = Field(default=None, min_length=1, max_length=16,
                                     pattern=r"^\d{1,6}(?:\.\d{1,8})?$")

    @model_validator(mode="after")
    def default_r2_for_opted_in_triage(self):
        if "max_r2_candidates" not in self.model_fields_set:
            self.max_r2_candidates = (
                min(3, self.max_triage_candidates) if self.auto_triage else 0
            )
        return self


class ScanInput(AuditPlanInput):
    detector_ids: list[str] | None = Field(default=None, min_length=1, max_length=16)
    expected_plan_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    expected_workflow_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    expected_triage_consent_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    triage_consent_nonce: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    memory_mb: int = Field(default=2048, ge=256, le=8192)


class ReviewInput(StrictModel):
    status: Literal[
        "under_review",
        "plausible_unproven",
        "likely_false_positive",
        "refuted",
        "unassessed",
    ]
    reviewer: str = Field(min_length=1, max_length=100)
    notes: str = Field(min_length=1, max_length=8000)
    expected_id: int = Field(default=0, ge=0)


class CaseLink(StrictModel):
    job_id: str
    candidate_id: str
    rationale: str = Field(min_length=1, max_length=4000)


class CaseInput(StrictModel):
    title: str = Field(min_length=1, max_length=200)
    links: list[CaseLink] = Field(min_length=1, max_length=100)


class CaseLinksInput(StrictModel):
    links: list[CaseLink] = Field(min_length=1, max_length=100)


class SourceExcerptInput(StrictModel):
    file: str = Field(min_length=1, max_length=1000)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    note: str = Field(min_length=1, max_length=4000)


def create_app(settings=None):
    settings = settings or Settings.from_env()
    settings.initialize()
    store = Store(settings.data_dir)
    app = FastAPI(title="OHScanner Local Audit Workbench", version="0.1.0")
    from .progressive_triage.api import install_routes as install_triage_policy_routes
    app.state.triage_policy = install_triage_policy_routes(app, settings.data_dir)
    app.state.store = store
    app.state.settings = settings
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"],
    )

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        origin = request.headers.get("origin")
        if origin and origin != str(request.base_url).rstrip("/"):
            return JSONResponse(
                {"detail": "cross-origin requests are disabled"}, status_code=403
            )
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if request.headers.get("x-ohscanner-client") != "workbench-v1":
                return JSONResponse(
                    {"detail": "missing local workbench request header"},
                    status_code=403,
                )
            length = request.headers.get("content-length", "0")
            if not length.isdecimal():
                return JSONResponse(
                    {"detail": "invalid content length"}, status_code=400
                )
            if int(length) > 256 * 1024:
                return JSONResponse({"detail": "request too large"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(KeyError)
    async def not_found(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(FileNotFoundError)
    async def missing_file(request, exc):
        return JSONResponse(
            {
                "detail": "Local repository or artifact is unavailable; analysis remains unknown"
            },
            status_code=409,
        )

    @app.exception_handler(sqlite3.IntegrityError)
    async def duplicate(request, exc):
        return JSONResponse(
            {"detail": "duplicate repository or inconsistent link"}, status_code=409
        )

    def worker_running():
        with (settings.data_dir / "worker.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return False
            except BlockingIOError:
                return True

    @app.get("/api/v1/health")
    def health():
        from .agent import public_status
        agent = public_status(settings.data_dir)
        from src.ohscanner.indexing import cpu_quota_info
        cpu_quota = cpu_quota_info()
        with store.connect() as db:
            queue_counts = {row["status"]: row["n"] for row in db.execute(
                "SELECT status,count(*) AS n FROM jobs WHERE status IN ('queued','running') GROUP BY status")}
        return {
            "status": "ok",
            "version": "0.1.0",
            "target_root_count": len(settings.target_roots),
            "capabilities": {
                "snapshot_scan": True,
                "audit_planning": True,
                "detector_admission": True,
                "operations_framework": True,
                "source_sync": True,
                "online_repository_catalog": True,
                "repository_import_scan": True,
                "revision_range": True,
                "read_only_investigation": True,
                "manual_review": True,
                "case_linking": True,
                "agent": agent["configured"],
                "agent_provider": agent,
                "runtime_validation": False,
                "version_impact": False,
            },
            "limits": {
                "source_files": 2000,
                "source_bytes": 32 * 1024 * 1024,
                "blob_bytes": 1024 * 1024,
                "concurrent_scans": settings.max_concurrent_scans,
                "queue_capacity": 100,
                "queued_scans": queue_counts.get("queued", 0),
                "running_scans": queue_counts.get("running", 0),
                "performance_mode": settings.performance_mode,
                "cpu_quota": cpu_quota,
                "memory_limit": {"status": "per_job_rlimit_as", "enforced_mb": None,
                                  "scope": "scan spec memory_mb", "measures": "virtual address space, not RSS"},
            },
            "worker_running": worker_running(),
        }

    @app.get("/api/v1/detectors")
    def detectors():
        return service.detector_metadata()

    @app.get("/api/v1/detector-admissions")
    def detector_admissions():
        from src.ohscanner.detectors.admission import pending_admissions
        return pending_admissions()

    @app.get("/api/v1/repositories")
    def repositories():
        """Return the ordinary user catalog without server filesystem paths."""
        return [{"id": item["id"], "name": item["name"]} for item in store.repositories()]

    @app.get("/api/v1/repositories/list")
    def repository_list():
        return [{"id": item["id"], "name": item["name"]} for item in store.repositories()]

    @app.get("/api/v1/repositories/managed")
    def managed_repositories():
        """Return path-bearing records for the settings management view."""
        return store.repositories()

    @app.get("/api/v1/repositories/catalog")
    def repository_catalog_route():
        return repository_catalog(settings, store)

    @app.get("/api/v1/repositories/online-catalog")
    def online_repository_catalog_route(page: int = Query(default=1, ge=1, le=20)):
        return online_repository_catalog(page)

    @app.get("/api/v1/repositories/roots")
    def repository_roots_route():
        return repository_roots(settings, store)

    @app.post("/api/v1/repositories/roots", status_code=201)
    def add_repository_root(body: SourceRootInput):
        root = add_managed_root(settings, body.alias, body.path)
        return {
            key: root[key]
            for key in ("id", "alias", "path", "managed", "last_checked_at", "discovery")
        }

    @app.delete("/api/v1/repositories/roots/{root_id}")
    def delete_repository_root(root_id: str):
        return remove_managed_root(settings, root_id)

    @app.get("/api/v1/repositories/discover")
    def repository_discover(root_index: int | None = None, root_id: str | None = None):
        result = discover_repositories(settings, store, root_index, root_id)
        record_root_check(settings, result["root_id"])
        return result

    @app.post("/api/v1/repositories", status_code=201)
    def register(body: RepositoryInput):
        path = service.check_repository(settings, body.path)
        return store.add_repository(body.name, path)

    @app.get("/api/v1/repositories/{key}/revisions")
    def revisions(key: str):
        repo = store.repository(key)
        service.check_repository(settings, repo["path"])
        return service.revisions(repo)

    def progressive_policy_snapshot():
        current = app.state.triage_policy.read()
        return {
            "revision": current["revision"],
            "policy": current["policy"],
            "policy_sha256": current["policy_sha256"],
        }

    @app.get("/api/v1/scans")
    def scans():
        return store.jobs()

    @app.post("/api/v1/audit-plans")
    def audit_plan(body: AuditPlanInput):
        if body.max_r2_candidates > body.max_triage_candidates:
            raise ValueError("conditional R2 candidate budget cannot exceed the R1 candidate budget")
        if body.max_r2_candidates and not body.auto_triage:
            raise ValueError("conditional R2 requires task-level automatic triage authorization")
        repo = store.repository(body.repository_id)
        service.check_repository(settings, repo["path"])
        _, plan = service.audit_plan(
            repo, body.revision, body.include_paths, body.detector_ids,
            body.timeout_seconds, body.memory_mb, base_commit=body.base_commit,
        )
        progressive_policy = progressive_policy_snapshot()
        workflow_sha256 = service.audit_workflow_sha256(
            plan["plan_sha256"], body.audit_mode, body.auto_triage,
            body.max_triage_candidates, body.max_r2_candidates,
            body.max_cost_usd,
            progressive_policy_sha256=progressive_policy["policy_sha256"],
            base_commit=body.base_commit)
        triage_preview = None
        if body.auto_triage:
            if body.audit_mode != "standard_review":
                raise ValueError("automatic triage is only available in standard review mode")
            from .agent import ProviderConfig, audit_task_consent_preview
            provider = ProviderConfig.from_env(settings.data_dir)
            triage_preview = audit_task_consent_preview(
                plan, workflow_sha256, body.include_paths, body.max_triage_candidates,
                uuid.uuid4().hex, provider, body.max_r2_candidates,
            )
            if not triage_preview.get("eligible"):
                raise ValueError("automatic triage cannot be authorized: " + triage_preview.get("reason", "provider unavailable"))
        result = {
            **plan,
            "audit_mode": body.audit_mode,
            "workflow_sha256": workflow_sha256,
            "workflow": service.audit_workflow_summary(
                body.audit_mode, body.auto_triage, body.max_triage_candidates,
                body.max_r2_candidates),
            "progressive_triage_policy": progressive_policy,
        }
        if body.base_commit:
            result["base_commit"] = body.base_commit
            result["incremental_mode"] = "full_scan_fallback_if_dependency_reuse_unproven"
        if triage_preview is not None:
            result["triage_authorization_preview"] = triage_preview
        return result

    @app.post("/api/v1/scans", status_code=201)
    def scan(body: ScanInput):
        if body.max_r2_candidates > body.max_triage_candidates:
            raise ValueError("conditional R2 candidate budget cannot exceed the R1 candidate budget")
        if body.max_r2_candidates and not body.auto_triage:
            raise ValueError("conditional R2 requires task-level automatic triage authorization")
        repo = store.repository(body.repository_id)
        service.check_repository(settings, repo["path"])
        spec = service.make_spec(
            repo,
            body.revision,
            body.include_paths,
            body.detector_ids,
            body.timeout_seconds,
            body.memory_mb,
            base_commit=body.base_commit,
        )
        if body.expected_plan_sha256 and body.expected_plan_sha256 != spec["plan_sha256"]:
            raise ValueError("Source or rule plan changed since preview; refresh the plan before scanning")
        progressive_policy = progressive_policy_snapshot()
        workflow_sha256 = service.audit_workflow_sha256(
            spec["plan_sha256"], body.audit_mode, body.auto_triage,
            body.max_triage_candidates, body.max_r2_candidates,
            body.max_cost_usd,
            progressive_policy_sha256=progressive_policy["policy_sha256"],
            base_commit=body.base_commit)
        if body.expected_workflow_sha256 and body.expected_workflow_sha256 != workflow_sha256:
            raise ValueError("Audit workflow changed since preview; refresh the plan before scanning")
        spec["audit_mode"] = body.audit_mode
        spec["max_r2_candidates"] = body.max_r2_candidates
        spec["max_cost_usd"] = body.max_cost_usd
        spec["workflow_sha256"] = workflow_sha256
        spec["progressive_triage_policy"] = progressive_policy
        if body.auto_triage:
            if body.audit_mode != "standard_review":
                raise ValueError("automatic triage is only available in standard review mode")
            if not body.expected_triage_consent_sha256 or not body.triage_consent_nonce:
                raise ValueError("task-level model source egress preview and explicit authorization are required")
            from .agent import ProviderConfig, audit_task_consent_preview
            provider = ProviderConfig.from_env(settings.data_dir)
            preview = audit_task_consent_preview(
                spec["audit_plan"], workflow_sha256, body.include_paths,
                body.max_triage_candidates, body.triage_consent_nonce, provider,
                body.max_r2_candidates,
            )
            if preview["consent_sha256"] != body.expected_triage_consent_sha256:
                raise ValueError("task-level source egress preview expired; provider, source, scope, policy or provider changed")
            spec["triage_authorization"] = {
                "authorized": True,
                "consent_sha256": preview["consent_sha256"],
                "snapshot": preview["manifest"],
            }
        elif body.expected_triage_consent_sha256 or body.triage_consent_nonce:
            raise ValueError("triage consent cannot be submitted unless automatic triage was selected")
        return store.create_job(repo["id"], spec)

    @app.get("/api/v1/scans/{key}")
    def scan_detail(key: str):
        return store.job(key)

    @app.get("/api/v1/scans/{key}/progressive-triage")
    def scan_progressive_triage(key: str, offset: int = Query(default=0, ge=0),
                                limit: int = Query(default=50, ge=1, le=200)):
        job = store.job(key)
        policy_snapshot = job.get("spec", {}).get("progressive_triage_policy")
        if not isinstance(policy_snapshot, dict):
            return {
                "state": "not_available",
                "reason": "legacy_scan_has_no_frozen_progressive_policy",
                "candidate_disposition_changed": False,
                "validated_vulnerability": 0,
            }
        parent_operation_id = job.get("spec", {}).get("progressive_audit_operation_id")
        if not parent_operation_id:
            try:
                parent = app.state.operations.audit_parent_for_scan(key)
                parent_operation_id = parent.get("id") if parent else None
            except (KeyError, ValueError):
                parent_operation_id = None
        if parent_operation_id:
            return {
                "state": "planned_by_parent_operation",
                "parent_operation_id": parent_operation_id,
                "reason": "multi_endpoint_budget_and_ranking_are_owned_by_the_parent_audit",
                "candidate_disposition_changed": False,
                "validated_vulnerability": 0,
            }
        if job.get("status") not in {"completed", "completed_with_limitations"} or not job.get("report_sha256"):
            return {
                "state": "awaiting_static_report",
                "policy_revision": policy_snapshot.get("revision"),
                "policy_sha256": policy_snapshot.get("policy_sha256"),
                "candidate_disposition_changed": False,
                "validated_vulnerability": 0,
            }
        from .progressive_triage.runtime import build_operation_plan
        result = build_operation_plan(settings, store, {
            "kind": "snapshot",
            "spec": {
                "progressive_triage_policy": policy_snapshot,
                "scan_ids": [key],
                "audit_mode": job.get("spec", {}).get("audit_mode", "static_only"),
            },
        })
        total = len(result["groups"])
        page_groups = result["groups"][offset:offset + limit]
        page_group_ids = {item["group_id"] for item in page_groups}
        page_decisions = [item for item in result["ranking"]["decisions"]
                          if item["group_id"] in page_group_ids]
        return {
            **result,
            "group_total": total,
            "offset": offset,
            "limit": limit,
            "groups": page_groups,
            "ranking": {**result["ranking"], "decisions": page_decisions},
        }

    @app.post("/api/v1/scans/{key}/cancel")
    def cancel(key: str):
        before = store.job(key)
        job = store.cancel(key)
        # Cancelling an audit stops its static worker and any task-bound model work.
        app.state.operations.cancel_triage_for_job(
            key, before.get("report_sha256"),
            force=before["status"] not in TERMINAL,
        )
        return job

    @app.post("/api/v1/scans/{key}/retry", status_code=201)
    def retry(key: str):
        job = store.job(key)
        if job["status"] not in TERMINAL:
            raise ValueError("only finished/interrupted jobs can be retried")
        repo = store.repository(job["repository_id"])
        service.check_repository(settings, repo["path"])
        old = job["spec"]
        # Retry preserves the resolved commit, never follows the former moving branch.
        spec = service.make_spec(
            repo,
            old["commit"],
            old["include_paths"],
            old["detector_ids"],
            old["timeout_seconds"],
            old["memory_mb"],
            base_commit=old.get("base_commit"),
        )
        spec["retry_of"] = key
        audit_mode = old.get("audit_mode", "static_only")
        spec["audit_mode"] = audit_mode
        old_policy = old.get("progressive_triage_policy")
        if isinstance(old_policy, dict):
            spec["progressive_triage_policy"] = old_policy
        spec["workflow_sha256"] = service.audit_workflow_sha256(
            spec["plan_sha256"], audit_mode,
            max_cost_usd=old.get("max_cost_usd"),
            progressive_policy_sha256=(old_policy.get("policy_sha256")
                                       if isinstance(old_policy, dict) else None),
            base_commit=spec.get("base_commit"))
        return store.create_job(repo["id"], spec)

    @app.get("/api/v1/scans/{key}/events")
    def events(key: str, after: int = 0):
        return store.events(key, after)

    @app.get("/api/v1/scans/{key}/report")
    def report(key: str):
        return service.read_report(settings, store.job(key))

    @app.get("/api/v1/scans/{key}/findings")
    def findings(
        key: str,
        offset: int = 0,
        limit: int = 50,
        q: str = "",
        detector: str = "",
        review_status: str = "",
    ):
        if offset < 0 or not 1 <= limit <= 200:
            raise ValueError("invalid pagination")
        report = service.read_report(settings, store.job(key))
        items = service.findings(report)
        from .smart_audit import severity_metadata
        latest = {}
        for entry in store.reviews(key):
            latest[entry["candidate_id"]] = entry
        for item in items:
            # Keep the immutable/raw diagnostic severity intact. Presentation is
            # a separate derived field shared with /overview/risks.
            item["risk_presentation"] = severity_metadata(item)
            item["latest_review"] = latest.get(item["id"])
            item["review_status"] = (
                item["latest_review"]["status"]
                if item["latest_review"]
                else "unassessed"
            )
        items = [
            i
            for i in items
            if (not detector or i["detector_id"] == detector)
            and (not review_status or i["review_status"] == review_status)
            and (not q or q.lower() in json.dumps(i, ensure_ascii=False).lower())
        ]
        return {"total": len(items), "items": items[offset : offset + limit]}

    @app.get("/api/v1/scans/{key}/clusters")
    def clusters(
        key: str, offset: int = 0, limit: int = 50, q: str = "", detector: str = ""
    ):
        if offset < 0 or not 1 <= limit <= 200:
            raise ValueError("invalid pagination")
        report = service.read_report(settings, store.job(key))
        items = service.finding_clusters(report)
        latest = {}
        for entry in store.reviews(key):
            latest[entry["candidate_id"]] = entry
        for group in items:
            for candidate in group["candidates"]:
                review = latest.get(candidate["id"])
                candidate["review_status"] = review["status"] if review else "unassessed"
        items = [
            group for group in items
            if (not detector or group["detector_id"] == detector)
            and (not q or q.lower() in json.dumps(group, ensure_ascii=False).lower())
        ]
        return {
            "total": len(items),
            "items": items[offset : offset + limit],
            "semantics": (
                "review grouping only; cluster membership is not a root-cause "
                "or vulnerability conclusion"
            ),
        }

    @app.get("/api/v1/scans/{key}/findings/{identity}")
    def finding(key: str, identity: str):
        job = store.job(key)
        report = service.read_report(settings, job)
        item = service.finding(report, identity)
        from .smart_audit import severity_metadata
        try:
            source = service.source(settings, store, job, item["file"])
        except (ValueError, KeyError, OSError, subprocess.SubprocessError, UnicodeError):
            source = None
            source_status = "unavailable"
            source_limitation = (
                "固定报告中的候选和证据义务仍可查看，但原仓库源码当前无法从已批准的本地源码根目录重新读取。"
                "请到“系统设置 → 仓库与源码管理”检查源码根目录和登记状态；恢复访问前，源码复核与模型研判保持未知。"
            )
        else:
            source_status = "available"
            source_limitation = None
        return {
            **item,
            "risk_presentation": severity_metadata(item),
            "source": source,
            "source_status": source_status,
            "source_limitation": source_limitation,
            "reviews": store.reviews(key, identity),
            "supplemental_evidence": store.source_evidence(key, identity),
            "binding": {
                "repository": report["repository"],
                "commit": report["commit"],
                "snapshot_sha256": report["snapshot_sha256"],
                "report_sha256": job["report_sha256"],
            },
        }

    @app.get("/api/v1/scans/{key}/source")
    def source(key: str, file: str):
        return service.source(settings, store, store.job(key), file)

    @app.post("/api/v1/scans/{key}/findings/{identity}/reviews", status_code=201)
    def review(key: str, identity: str, body: ReviewInput):
        service.finding(service.read_report(settings, store.job(key)), identity)
        return store.add_review(
            key, identity, body.status, body.reviewer, body.notes, body.expected_id
        )

    @app.post("/api/v1/scans/{key}/findings/{identity}/evidence", status_code=201)
    def source_evidence(key: str, identity: str, body: SourceExcerptInput):
        return service.source_excerpt(
            settings,
            store,
            store.job(key),
            identity,
            body.file,
            body.start_line,
            body.end_line,
            body.note,
        )

    @app.get("/api/v1/cases")
    def cases():
        return store.cases()

    @app.post("/api/v1/cases", status_code=201)
    def case(body: CaseInput):
        links = [item.model_dump() for item in body.links]
        for link in links:
            service.finding(
                service.read_report(settings, store.job(link["job_id"])),
                link["candidate_id"],
            )
        key = store.create_case(body.title, links)
        return next(case for case in store.cases() if case["id"] == key)

    @app.post("/api/v1/cases/{case_id}/links", status_code=201)
    def case_links(case_id: str, body: CaseLinksInput):
        links = [item.model_dump() for item in body.links]
        for link in links:
            service.finding(
                service.read_report(settings, store.job(link["job_id"])),
                link["candidate_id"],
            )
        store.link_case(case_id, links)
        return next(case for case in store.cases() if case["id"] == case_id)

    @app.get("/api/v1/scans/{key}/artifacts/{kind}")
    def artifact(key: str, kind: str):
        job = store.job(key)
        if kind == "manifest.json":
            report_data = service.read_report(settings, job)
            data = json.dumps(
                {
                    "schema_version": 1,
                    "job_id": key,
                    "spec": job["spec"],
                    "artifacts": {
                        "report.json": job["report_sha256"],
                        "report.md": report_data["_workbench"]["markdown_sha256"],
                    },
                },
                indent=2,
            )
        elif kind in {"review.json", "review.md"}:
            bundle = service.review_bundle(settings, store, job)
            data = (
                json.dumps(bundle, indent=2, ensure_ascii=False)
                if kind.endswith("json")
                else service.review_markdown(bundle)
            )
        elif kind in {"report.json", "report.md"}:
            service.read_report(settings, job)
            if kind == "report.json":
                data = (service.artifact_dir(settings, key) / kind).read_text()
            else:
                # Markdown shares the complete JSON report's immutable source binding;
                # its individual hash is verified against the committed worker manifest.
                report_data = service.read_report(settings, job)
                raw = (service.artifact_dir(settings, key) / kind).read_bytes()
                if service.sha(raw) != report_data["_workbench"]["markdown_sha256"]:
                    raise ValueError("Markdown artifact integrity check failed")
                data = raw.decode()
        elif kind == "worker.log":
            path = service.artifact_dir(settings, key) / kind
            if not path.is_file():
                raise KeyError("log not yet available")
            data = path.read_bytes()[-256 * 1024 :].decode("utf-8", "replace")
        else:
            raise KeyError("unknown artifact")
        return Response(
            data,
            media_type="application/json" if kind.endswith("json") else "text/plain",
            headers={"Content-Disposition": f'attachment; filename="{key}_{kind}"'},
        )

    from .operations_api import install_routes
    app.state.operations = install_routes(app, settings, store)

    web = Path(__file__).resolve().parents[2] / "web" / "dist"
    if web.is_dir():
        app.mount("/", StaticFiles(directory=web, html=True), name="web")
    return app

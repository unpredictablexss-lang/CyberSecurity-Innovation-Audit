"""Workbench adapter for deterministic facts and append-only draft records."""
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4
import json

from src.investigation.drafts import validate_investigation_draft
from src.investigation.ipc_deterministic import build_ipc_fact_bundle
from . import service


def _utcnow():
    return datetime.now(timezone.utc).isoformat()


def _report_bytes(settings, job):
    path = service.artifact_dir(settings, job["id"]) / "report.json"
    data = path.read_bytes()
    if service.sha(data) != job["report_sha256"]:
        raise ValueError("report integrity check failed")
    return data


def build_fact_bundle(settings, store, job, candidate_id):
    report = service.read_report(settings, job)
    candidate = service.finding(report, candidate_id)
    source = service.source(settings, store, job, candidate["file"])
    source_evidence = store.source_evidence(job["id"], candidate_id)
    return build_ipc_fact_bundle(
        report=report,
        candidate_id=candidate_id,
        candidate_record=candidate,
        source=source,
        report_sha256=job["report_sha256"],
        report_bytes=_report_bytes(settings, job),
        source_evidence=source_evidence,
        source_loader=lambda file: service.source(settings, store, job, file),
    )


def _allowed_evidence_refs(store, job, candidate_id):
    refs = set()
    for record in store.source_evidence(job["id"], candidate_id):
        refs.add("source_evidence:" + record["id"])
    for record in store.reviews(job["id"], candidate_id):
        refs.add("review:" + str(record["id"]))
    return refs


def investigation_bundle(settings, store, job, candidate_id):
    bundle = build_fact_bundle(settings, store, job, candidate_id)
    return {
        "schema_version": "ohscanner.workbench-investigation-v1",
        "kind": "ipc_interface_investigation",
        "job_id": job["id"],
        "candidate_id": candidate_id,
        "fact_bundle": bundle.to_dict(),
        "drafts": store.investigation_drafts(job["id"], candidate_id),
        "draft_policy": {
            "status": "draft_only",
            "can_promote": False,
            "append_only": True,
            "model_integration": "not_enabled",
            "untrusted_content": True,
        },
        "validated_vulnerability": 0,
        "interpretation": (
            "Deterministic facts and untrusted investigation drafts are separate. "
            "Drafts cannot change findings, obligations, reviews, cases or status."
        ),
    }


def save_draft(settings, store, job, candidate_id, payload):
    bundle = build_fact_bundle(settings, store, job, candidate_id)
    if not isinstance(payload, Mapping):
        raise ValueError("draft must be an object")
    data = dict(payload)
    for reserved in ("draft_id", "created_at"):
        if reserved in data:
            raise ValueError(f"{reserved} is assigned by the server")
    draft_id = uuid4().hex
    created_at = _utcnow()
    draft = validate_investigation_draft(
        data,
        bundle,
        persisted_evidence_ids=_allowed_evidence_refs(store, job, candidate_id),
        draft_id=draft_id,
        created_at=created_at,
    ).to_dict()
    return store.add_investigation_draft(
        job["id"],
        candidate_id,
        bundle.fact_bundle_sha256,
        draft,
    )


def investigation_markdown(bundle):
    fenced = json.dumps(bundle, indent=2, ensure_ascii=False).replace(
        "~~~~", "\\u007e\\u007e\\u007e\\u007e"
    )
    return (
        "# OHScanner IPC/接口调查包\n\n"
        "确定性事实与调查草案；`draft_only`，不是已确认漏洞报告。\n\n"
        "- Candidate: `" + bundle["candidate_id"] + "`\n"
        "- Fact bundle SHA-256: `"
        + bundle["fact_bundle"]["fact_bundle_sha256"] + "`\n"
        "- Drafts: " + str(len(bundle["drafts"])) + "\n"
        "- Confirmed/reportable: 0\n\n"
        "## Structured investigation record\n\n"
        "~~~~json\n" + fenced + "\n~~~~\n"
    )
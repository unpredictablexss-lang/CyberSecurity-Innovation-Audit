"""Reproduce API/Worker/CLI parity on a fixed real local component.

Generated artifacts remain outside version control. This checks engineering
consistency, not detection accuracy or a vulnerability verdict.
"""

import argparse
import json
from pathlib import Path
import time
from fastapi.testclient import TestClient
from src.ohscanner.execution import run_fixed_commit_scan
from src.workbench.api import create_app
from src.workbench.settings import Settings
from src.workbench.worker import Worker
from src.workbench import service


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repo-dir", type=Path, required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--data-dir", type=Path, required=True)
    p.add_argument("--include", action="append", default=[])
    args = p.parse_args()
    repo = args.repo_dir.resolve()
    settings = Settings(args.data_dir.resolve(), (repo.parent,))
    settings.initialize()
    client = TestClient(create_app(settings))
    headers = {"x-ohscanner-client": "workbench-v1"}
    registered = next(
        (
            r
            for r in client.get("/api/v1/repositories/managed").json()
            if r["path"] == str(repo)
        ),
        None,
    )
    if not registered:
        response = client.post(
            "/api/v1/repositories",
            json={"name": args.repository, "path": str(repo)},
            headers=headers,
        )
        response.raise_for_status()
        registered = response.json()
    detector_ids = [d["id"] for d in service.detector_metadata()]
    response = client.post(
        "/api/v1/scans",
        json={
            "repository_id": registered["id"],
            "revision": args.commit,
            "include_paths": args.include or ["."],
            "detector_ids": detector_ids,
            "timeout_seconds": 600,
            "memory_mb": 4096,
        },
        headers=headers,
    )
    response.raise_for_status()
    job = response.json()
    start = time.monotonic()
    Worker(settings).run(once=True)
    job = client.get("/api/v1/scans/" + job["id"]).json()
    if not job["report_sha256"]:
        raise RuntimeError(json.dumps(job, ensure_ascii=False))
    report = client.get("/api/v1/scans/" + job["id"] + "/report").json()
    out = settings.data_dir / "verification" / job["id"]
    out.mkdir(parents=True)
    cli = run_fixed_commit_scan(
        repo,
        args.repository,
        args.commit,
        tuple(args.include or ["."]),
        tuple(detector_ids),
        out / "cli.json",
        out / "cli.md",
    )
    assert report["snapshot_sha256"] == cli["snapshot_sha256"]
    assert report["detector_coverage"] == cli["detector_coverage"]
    for a, b in zip(report["detector_runs"], cli["detector_runs"]):
        assert a["diagnostics"] == b["diagnostics"]
    assert report["scope"] == cli["scope"]
    assert report["source_parsing"] == cli["source_parsing"]
    candidates = service.findings(report)
    for item in candidates:
        response = client.get("/api/v1/scans/" + job["id"] + "/findings/" + item["id"])
        response.raise_for_status()
        assert response.json()["source"]["sha256"] == item["evidence"]["source_sha256"]
    for kind in ("report.json", "report.md", "review.json", "review.md"):
        client.get(
            "/api/v1/scans/" + job["id"] + "/artifacts/" + kind
        ).raise_for_status()
    result = {
        "job_id": job["id"],
        "repository": args.repository,
        "commit": report["commit"],
        "git_tree": report["git_tree"],
        "engine_sha256": job["spec"]["engine_sha256"],
        "status": job["status"],
        "indexed_files": report["scope"]["selected_source_files"],
        "source_bytes": report["scope"]["selected_source_bytes"],
        "parse": report["source_parsing"],
        "candidate_count": report["diagnostic_count"],
        "validated_vulnerability": 0,
        "candidate_sources_verified": len(candidates),
        "cli_parity": True,
        "report_sha256": job["report_sha256"],
        "scan_seconds": job["elapsed_seconds"],
        "verification_seconds": time.monotonic() - start,
        "artifact_directory": str(service.artifact_dir(settings, job["id"])),
        "coverage": report["detector_coverage"],
        "scope": report["scope"],
        "limitations": [
            "Not an accuracy benchmark or runtime vulnerability validation.",
            "Uses the explicitly requested include scope, not a production exclusion profile.",
        ],
    }
    (out / "verification.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    )
    print(
        json.dumps(
            {k: v for k, v in result.items() if k not in ("coverage", "scope")},
            indent=2,
            ensure_ascii=False,
        )
    )
    client.close()


if __name__ == "__main__":
    main()

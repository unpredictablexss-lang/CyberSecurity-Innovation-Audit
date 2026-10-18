#!/usr/bin/env python3
"""Exercise the selected D38 rule through Workbench API, Worker, report and source viewer."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient
from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector
from src.workbench.api import create_app
from src.workbench.settings import Settings
from src.workbench.worker import Worker
from src.workbench import service

CURL_REPO = "/tmp/d-curl-92392"
CASES = (
    ("curl-vulnerable", "d0386aa3e805543ce464c993e1eb31b4d92c6356"),
    ("curl-fixed", "4c24dd7ba7244e0206d91a72fe414823add8a034"),
)
PATHS = ("lib/multi.c", "include/curl/curlver.h")
HEADERS = {"x-ohscanner-client": "workbench-v1"}
DETECTOR = "ohscanner.known_disclosed_cves"


def git(repo: Path, *args: str, env=None) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True, env=env).strip()


def source_bytes(repo: Path, revision: str, path: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), "show", f"{revision}:{path}"])


def scan_case(root: Path, name: str, upstream_repo: Path, revision: str) -> dict:
    target = root / "targets" / name
    target.mkdir(parents=True)
    blobs = {path: source_bytes(upstream_repo, revision, path) for path in PATHS}
    for path, content in blobs.items():
        destination = target / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    git(target, "init", "-q")
    git(target, "config", "user.name", "OHScanner D38 replay")
    git(target, "config", "user.email", "d38-replay@example.invalid")
    git(target, "add", ".")
    commit_env = os.environ.copy()
    commit_env.update(GIT_AUTHOR_DATE="2026-10-14T00:00:00+00:00", GIT_COMMITTER_DATE="2026-10-14T00:00:00+00:00")
    git(target, "commit", "-qm", "materialize pinned curl source files", env=commit_env)
    local_commit = git(target, "rev-parse", "HEAD")

    settings = Settings(root / f"data-{name}", (root / "targets",))
    app = create_app(settings)
    with TestClient(app) as client:
        catalog = client.get("/api/v1/detectors")
        catalog.raise_for_status()
        metadata = next(item for item in catalog.json() if item["id"] == DETECTOR)
        registered = metadata["version"] == KnownDisclosedCveDetector.version and not metadata["default_enabled"]
        if not registered:
            raise AssertionError(f"Catalog did not expose opt-in detector metadata: {metadata}")

        repository_response = client.post(
            "/api/v1/repositories", json={"name": f"fixture/{name}", "path": str(target)}, headers=HEADERS
        )
        repository_response.raise_for_status()
        queued = client.post(
            "/api/v1/scans",
            json={"repository_id": repository_response.json()["id"], "revision": "HEAD", "detector_ids": [DETECTOR]},
            headers=HEADERS,
        )
        queued.raise_for_status()
        job_id = queued.json()["id"]
        Worker(settings).run(once=True)
        job = app.state.store.job(job_id)
        report = service.read_report(settings, job)
        runs = [item for item in report["detector_runs"] if item["tool"] == DETECTOR]
        if len(runs) != 1:
            raise AssertionError(f"expected one selected detector run, got {len(runs)}")
        findings = [item for item in runs[0]["diagnostics"] if item["symbol"] == "CVE-2026-92392"]
        expected = 1 if name == "curl-vulnerable" else 0
        if len(findings) != expected:
            raise AssertionError(f"{name}: expected {expected} candidates, got {len(findings)}")
        viewer = None
        if findings:
            finding = findings[0]
            if finding["source_sha256"] != hashlib.sha256(blobs["lib/multi.c"]).hexdigest():
                raise AssertionError("candidate source SHA did not bind to the pinned upstream blob")
            response = client.get(f"/api/v1/scans/{job_id}/source", params={"file": finding["file"]})
            response.raise_for_status()
            viewer = response.json()
            if hashlib.sha256(viewer["text"].encode()).hexdigest() != finding["source_sha256"]:
                raise AssertionError("source viewer returned bytes not bound to the candidate")
        if report["validated_vulnerability"] != 0:
            raise AssertionError("static candidate path must not self-confirm a vulnerability")
        return {
            "case": name,
            "upstream_commit": git(upstream_repo, "rev-parse", revision),
            "local_scan_commit": local_commit,
            "job_status": job["status"],
            "detector_version": runs[0]["tool_version"],
            "detector_status": runs[0]["status"],
            "coverage": report["detector_coverage"]["detectors"][DETECTOR],
            "candidate_count": len(findings),
            "candidate_id": findings[0]["diagnostic_id"] if findings else None,
            "candidate_file": findings[0]["file"] if findings else None,
            "candidate_line": findings[0]["line"] if findings else None,
            "source_sha256": findings[0]["source_sha256"] if findings else None,
            "source_viewer_sha256": hashlib.sha256(viewer["text"].encode()).hexdigest() if viewer else None,
            "validated_vulnerability": report["validated_vulnerability"],
            "limitations": report.get("limitations", []),
        }


def main() -> None:
    root = Path(tempfile.mkdtemp(prefix="ohscanner-d38-panel-"))
    upstream_repo = Path(CURL_REPO)
    rounds = []
    for round_number in (1, 2):
        round_root = root / f"round-{round_number}"
        round_root.mkdir(parents=True)
        cases = [scan_case(round_root, name, upstream_repo, revision) for name, revision in CASES]
        rounds.append(cases)

    stable_fields = ("case", "upstream_commit", "local_scan_commit", "job_status", "detector_version",
                     "detector_status", "candidate_count", "candidate_id", "candidate_file", "candidate_line",
                     "source_sha256", "source_viewer_sha256", "validated_vulnerability")
    signatures = [[{key: item[key] for key in stable_fields} for item in round_cases] for round_cases in rounds]
    if signatures[0] != signatures[1]:
        raise AssertionError("API replay candidate, coverage status, source binding, or fix delta drifted across rounds")
    cases = rounds[0]
    output = {
        "schema": 1,
        "experiment": "D38 Workbench API to Worker to report and hash-checked source viewer replay",
        "detector": DETECTOR,
        "detector_version": KnownDisclosedCveDetector.version,
        "upstream_repository": "curl/curl",
        "source_profile": "two pinned source files per case, materialized in isolated temporary Git repositories",
        "validated_vulnerability": 0,
        "product_status": "unknown",
        "limitations": [
            "This verifies explicit Catalog selection, API planning, Worker execution, report persistence, and source hash binding; it is not a browser automation run.",
            "The temporary repositories contain only lib/multi.c and curlver.h from pinned upstream revisions, not a complete curl build or OpenHarmony product.",
            "Tree-sitter or full repository coverage may remain partial/blocked; a candidate does not confirm product impact or exploitability.",
        ],
        "repeat_run_count": 2,
        "repeat_runs_semantically_identical": True,
        "repeat_run_signatures": signatures,
        "cases": cases,
    }
    output_path = Path(__file__).with_name("D38_CVE_2026_92392_PANEL_REPLAY.json")
    output_path.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output_path), "cases": [{"case": item["case"], "status": item["job_status"], "detector_status": item["detector_status"], "candidates": item["candidate_count"]} for item in cases]}, ensure_ascii=False))


if __name__ == "__main__":
    main()

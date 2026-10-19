#!/usr/bin/env python3
"""Replay D39 old/fixed source through Workbench API, Worker, report and viewer."""
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
from src.workbench import service
from src.workbench.settings import Settings
from src.workbench.worker import Worker

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests/fixtures/data_sensitive"
SOURCE_PATH = "frameworks/common/include/utils/lru_cache_util.h"
DETECTOR = "ohscanner.known_disclosed_cves"
HEADERS = {"x-ohscanner-client": "workbench-v1"}
CASES = (
    ("vulnerable", FIXTURES / "d39_cve_2026_58313_lru_vulnerable.h", 1),
    ("fixed", FIXTURES / "d39_cve_2026_58313_lru_fixed.h", 0),
)


def git(repo: Path, *args: str, env=None) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True, env=env).strip()


def replay_case(root: Path, label: str, fixture: Path, expected: int) -> dict:
    target = root / "targets" / label
    target_path = target / SOURCE_PATH
    target_path.parent.mkdir(parents=True)
    source = fixture.read_bytes()
    target_path.write_bytes(source)
    git(target, "init", "-q")
    git(target, "config", "user.name", "OHScanner D39 replay")
    git(target, "config", "user.email", "d39-replay@example.invalid")
    git(target, "add", ".")
    commit_env = os.environ.copy()
    commit_env.update(
        GIT_AUTHOR_DATE="2026-10-19T00:00:00+00:00",
        GIT_COMMITTER_DATE="2026-10-19T00:00:00+00:00",
    )
    git(target, "commit", "-qm", "materialize pinned D39 source", env=commit_env)
    local_commit = git(target, "rev-parse", "HEAD")

    settings = Settings(root / f"data-{label}", (root / "targets",))
    app = create_app(settings)
    with TestClient(app) as client:
        catalog_response = client.get("/api/v1/detectors")
        catalog_response.raise_for_status()
        metadata = next(item for item in catalog_response.json() if item["id"] == DETECTOR)
        if metadata["version"] != KnownDisclosedCveDetector.version or metadata["default_enabled"]:
            raise AssertionError(f"unexpected detector Catalog metadata: {metadata}")

        repository_response = client.post(
            "/api/v1/repositories",
            json={"name": f"fixture/d39-{label}", "path": str(target)},
            headers=HEADERS,
        )
        repository_response.raise_for_status()
        queued = client.post(
            "/api/v1/scans",
            json={
                "repository_id": repository_response.json()["id"],
                "revision": "HEAD",
                "detector_ids": [DETECTOR],
            },
            headers=HEADERS,
        )
        queued.raise_for_status()
        job_id = queued.json()["id"]
        Worker(settings).run(once=True)
        job = app.state.store.job(job_id)
        report = service.read_report(settings, job)
        runs = [run for run in report["detector_runs"] if run["tool"] == DETECTOR]
        if len(runs) != 1:
            raise AssertionError(f"expected one selected detector run, got {len(runs)}")
        findings = [
            item for item in runs[0]["diagnostics"] if item["symbol"] == "CVE-2026-58313"
        ]
        if len(findings) != expected:
            raise AssertionError(f"{label}: expected {expected} candidates, got {len(findings)}")
        if report["validated_vulnerability"] != 0:
            raise AssertionError("static candidate path must not self-confirm a vulnerability")

        viewer_sha256 = None
        if findings:
            finding = findings[0]
            source_sha256 = hashlib.sha256(source).hexdigest()
            if finding["source_sha256"] != source_sha256:
                raise AssertionError("candidate source hash does not match the pinned fixture")
            response = client.get(
                f"/api/v1/scans/{job_id}/source", params={"file": finding["file"]}
            )
            response.raise_for_status()
            viewer_sha256 = hashlib.sha256(response.json()["text"].encode()).hexdigest()
            if viewer_sha256 != source_sha256:
                raise AssertionError("source viewer bytes do not match candidate source hash")

        return {
            "case": label,
            "fixture": fixture.name,
            "source_sha256": hashlib.sha256(source).hexdigest(),
            "local_scan_commit": local_commit,
            "job_status": job["status"],
            "detector_version": runs[0]["tool_version"],
            "detector_status": runs[0]["status"],
            "coverage": report["detector_coverage"]["detectors"][DETECTOR],
            "candidate_count": len(findings),
            "candidate_id": findings[0]["diagnostic_id"] if findings else None,
            "candidate_file": findings[0]["file"] if findings else None,
            "candidate_line": findings[0]["line"] if findings else None,
            "source_viewer_sha256": viewer_sha256,
            "validated_vulnerability": report["validated_vulnerability"],
            "limitations": report.get("limitations", []),
        }


def main() -> None:
    root = Path(tempfile.mkdtemp(prefix="ohscanner-d39-panel-"))
    rounds = []
    for number in (1, 2):
        round_root = root / f"round-{number}"
        round_root.mkdir()
        rounds.append([replay_case(round_root, *case) for case in CASES])

    stable_fields = (
        "case", "fixture", "source_sha256", "local_scan_commit", "job_status",
        "detector_version", "detector_status", "candidate_count", "candidate_id",
        "candidate_file", "candidate_line", "source_viewer_sha256", "validated_vulnerability",
    )
    signatures = [
        [{field: item[field] for field in stable_fields} for item in run]
        for run in rounds
    ]
    if signatures[0] != signatures[1]:
        raise AssertionError("panel replay candidate, status, hash binding or fix delta drifted")

    output = {
        "schema": 1,
        "experiment": "D39 Workbench Catalog/API/Worker/report/source-viewer old/fixed replay",
        "detector": DETECTOR,
        "detector_version": KnownDisclosedCveDetector.version,
        "upstream_repository": "openharmony/bundlemanager_app_domain_verify",
        "upstream_vulnerable_commit": "7121401db97c3fedba57ae188148249567e09e18",
        "upstream_fixed_commit": "d01a9581e35a22c0a58e1e446556ae3d3c189af3",
        "validated_vulnerability": 0,
        "product_status": "unknown",
        "independent_human_review": "pending",
        "repeat_run_count": 2,
        "repeat_runs_semantically_identical": True,
        "repeat_run_signatures": signatures,
        "limitations": [
            "This verifies opt-in Catalog selection, API planning, Worker execution, report persistence and source hash binding; it is not browser automation.",
            "The repositories contain only one pinned header and are not a complete component or OpenHarmony product build.",
            "Static candidates and the separate component ASan harness do not establish product reachability or impact.",
        ],
        "cases": rounds[0],
    }
    out = Path(__file__).with_name("D39_CVE_2026_58313_PANEL_REPLAY.json")
    out.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(out), "cases": [
        {"case": item["case"], "job": item["job_status"],
         "detector": item["detector_status"], "candidates": item["candidate_count"]}
        for item in rounds[0]
    ]}, ensure_ascii=False))


if __name__ == "__main__":
    main()

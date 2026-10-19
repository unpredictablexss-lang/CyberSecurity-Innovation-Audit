#!/usr/bin/env python3
"""Replay one fixed Wi-Fi sensitive-log candidate through the Workbench API."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.workbench import service
from src.workbench.api import create_app
from src.workbench.settings import Settings
from src.workbench.worker import Worker

DETECTOR = "ohscanner.data.sensitive_exposure"
SOURCE_PATH = "wifi/services/wifi_standard/wifi_framework/wifi_toolkit/utils/softap_parser.cpp"
HEADERS = {"x-ohscanner-client": "workbench-v1"}
EXPECTED_LINE = 93


def git(repo: Path, *args: str, env=None) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True, env=env).strip()


def source_bytes(repo: Path, commit: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), "show", f"{commit}:{SOURCE_PATH}"])


def scan_case(root: Path, repo: Path, commit: str) -> dict:
    target = root / "targets" / "wifi-softap"
    source = source_bytes(repo, commit)
    target_file = target / SOURCE_PATH
    target_file.parent.mkdir(parents=True)
    target_file.write_bytes(source)
    git(target, "init", "-q")
    git(target, "config", "user.name", "OHScanner D40 replay")
    git(target, "config", "user.email", "d40-replay@example.invalid")
    git(target, "add", ".")
    env = os.environ.copy()
    env.update(GIT_AUTHOR_DATE="2026-10-19T00:00:00+00:00", GIT_COMMITTER_DATE="2026-10-19T00:00:00+00:00")
    git(target, "commit", "-qm", "materialize pinned Wi-Fi source", env=env)
    local_commit = git(target, "rev-parse", "HEAD")
    expected_sha256 = hashlib.sha256(source).hexdigest()

    settings = Settings(root / "workbench-data", (root / "targets",))
    app = create_app(settings)
    with TestClient(app) as client:
        catalog_response = client.get("/api/v1/detectors")
        catalog_response.raise_for_status()
        metadata = next(item for item in catalog_response.json() if item["id"] == DETECTOR)
        if metadata["version"] != SensitiveExposureDetector.version or metadata["default_enabled"]:
            raise AssertionError(f"unexpected opt-in Catalog metadata: {metadata}")
        repository_response = client.post(
            "/api/v1/repositories", json={"name": "fixture/d40-wifi", "path": str(target)}, headers=HEADERS
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
        runs = [item for item in report["detector_runs"] if item["tool"] == DETECTOR]
        if len(runs) != 1:
            raise AssertionError(f"expected one D detector run, got {len(runs)}")
        findings = [
            item for item in runs[0]["diagnostics"]
            if item["rule_id"] == "data.log.sensitive-value"
            and item["file"] == SOURCE_PATH
            and item["line"] == EXPECTED_LINE
        ]
        if len(findings) != 1:
            raise AssertionError(f"expected the PreSharedKey public-log candidate at line {EXPECTED_LINE}, got {len(findings)}")
        finding = findings[0]
        if finding["candidate_cwe"] != "CWE-532" or finding["source_sha256"] != expected_sha256:
            raise AssertionError("candidate classification or source binding drifted")
        if report["validated_vulnerability"] != 0:
            raise AssertionError("static candidate must not self-confirm a vulnerability")
        viewer_response = client.get(
            f"/api/v1/scans/{job_id}/source", params={"file": finding["file"]}
        )
        viewer_response.raise_for_status()
        viewer_sha256 = hashlib.sha256(viewer_response.json()["text"].encode()).hexdigest()
        if viewer_sha256 != expected_sha256:
            raise AssertionError("source viewer returned bytes not bound to the candidate")
        return {
            "upstream_commit": git(repo, "rev-parse", commit),
            "local_scan_commit": local_commit,
            "source_sha256": expected_sha256,
            "job_status": job["status"],
            "detector_version": runs[0]["tool_version"],
            "detector_status": runs[0]["status"],
            "coverage": report["detector_coverage"]["detectors"][DETECTOR],
            "candidate_count_in_file": len([item for item in runs[0]["diagnostics"] if item["file"] == SOURCE_PATH]),
            "candidate_id": finding["diagnostic_id"],
            "candidate_rule": finding["rule_id"],
            "candidate_cwe": finding["candidate_cwe"],
            "candidate_file": finding["file"],
            "candidate_line": finding["line"],
            "source_viewer_sha256": viewer_sha256,
            "validated_vulnerability": report["validated_vulnerability"],
            "limitations": report.get("limitations", []),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-dir", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    repo = args.repo_dir.resolve(strict=True)
    commit = git(repo, "rev-parse", "--verify", f"{args.commit}^{{commit}}")
    upstream_blob = git(repo, "rev-parse", f"{commit}:{SOURCE_PATH}")
    root = Path(tempfile.mkdtemp(prefix="ohscanner-d40-wifi-panel-"))
    rounds = []
    for number in (1, 2):
        round_root = root / f"round-{number}"
        round_root.mkdir()
        rounds.append(scan_case(round_root, repo, commit))
    stable_fields = (
        "upstream_commit", "local_scan_commit", "source_sha256", "job_status", "detector_version",
        "detector_status", "candidate_id", "candidate_rule", "candidate_cwe", "candidate_file",
        "candidate_line", "source_viewer_sha256", "validated_vulnerability",
    )
    signatures = [{key: item[key] for key in stable_fields} for item in rounds]
    if signatures[0] != signatures[1]:
        raise AssertionError("panel candidate, status or source hash drifted between repeated runs")
    output = {
        "schema": 1,
        "experiment": "D40 Workbench API/Worker/report/source-viewer replay for Wi-Fi PreSharedKey log candidate",
        "repository": "openharmony/communication_wifi",
        "commit": commit,
        "tree": git(repo, "rev-parse", f"{commit}^{{tree}}"),
        "source_path": SOURCE_PATH,
        "upstream_blob": upstream_blob,
        "detector": DETECTOR,
        "detector_version": SensitiveExposureDetector.version,
        "validated_vulnerability": 0,
        "product_status": "unknown",
        "independent_human_review": "pending",
        "repeat_run_count": 2,
        "repeat_runs_semantically_identical": True,
        "repeat_run_signatures": signatures,
        "limitations": [
            "The source uses a pre-shared key passed through PassWordAnonymize and emitted by WIFI_LOGI as a public string; the helper masks part of the value, so residual disclosure severity needs human review.",
            "This is one fixed source file, not a complete Wi-Fi build or independent holdout; the detector run remains blocked/partial.",
            "The static result is candidate-only and does not prove production log enablement, unauthorized readership, product impact, or a confirmed vulnerability.",
        ],
        "cases": rounds,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "candidate": rounds[0]["candidate_id"],
                      "line": rounds[0]["candidate_line"], "detector_status": rounds[0]["detector_status"],
                      "repeat_equal": True}, ensure_ascii=False))


if __name__ == "__main__":
    main()
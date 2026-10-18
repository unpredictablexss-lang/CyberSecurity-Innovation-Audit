"""Reproduce the real libpng archive scan through the Workbench API and Worker."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from src.workbench import service
from src.workbench.api import create_app
from src.workbench.settings import Settings
from src.workbench.worker import Worker

REPOSITORY_ROOT = Path("/mnt/g/OpenHarmony-GitCode-Mirror/campaign-100-20261017/repos")
REPOSITORY = REPOSITORY_ROOT / "third_party_libpng"
COMMIT = "e57b1079564a02a50321ec528aa6e41884979d32"
ARCHIVE = "libpng-1.6.55.tar.gz"
DETECTOR = "ohscanner.known_disclosed_cves"


def scan_once(client, app, settings, repository_id, headers):
    response = client.post("/api/v1/scans", headers=headers, json={
        "repository_id": repository_id, "revision": COMMIT,
        "include_paths": [ARCHIVE], "detector_ids": [DETECTOR],
    })
    if response.status_code != 201:
        raise RuntimeError(response.text)
    key = response.json()["id"]
    Worker(settings).run(once=True)
    job = app.state.store.job(key)
    report = service.read_report(settings, job)
    matches = [d for run in report["detector_runs"] for d in run["diagnostics"]
               if d.get("symbol") == "CVE-2026-46675"]
    if not matches:
        raise RuntimeError("expected disclosed CVE candidate not found in panel report")
    source = service.source(settings, app.state.store, job, matches[0]["file"])
    if source["sha256"] != matches[0]["source_sha256"]:
        raise RuntimeError("source viewer hash does not match candidate source")
    signature = [(d["symbol"], d["file"], d["line"], d["source_sha256"])
                 for run in report["detector_runs"] for d in run["diagnostics"]]
    return {
        "job_id": key, "job_status": job["status"],
        "git_tree": report["git_tree"], "snapshot_sha256": report["snapshot_sha256"],
        "report_sha256": job["report_sha256"], "diagnostic_count": report["diagnostic_count"],
        "detector_status": report["detector_runs"][0]["status"],
        "candidate_signature": signature, "candidate": matches[0]["symbol"],
        "file": matches[0]["file"], "line": matches[0]["line"],
        "source_sha256": source["sha256"], "source_blob": source["blob"],
        "archive_binding": source["archive_binding"],
        "archive_inventory": report["scope"]["source_archives"],
        "validated_vulnerability": report["validated_vulnerability"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("D22_ARCHIVE_RUNNER_PANEL.json"))
    args = parser.parse_args()
    if not REPOSITORY.is_dir():
        raise SystemExit(f"required pinned G-drive mirror is unavailable: {REPOSITORY}")
    with tempfile.TemporaryDirectory(prefix="ohscanner-d22-panel-") as data_dir:
        settings = Settings(Path(data_dir) / "data", (REPOSITORY_ROOT,))
        app = create_app(settings)
        headers = {"x-ohscanner-client": "workbench-v1"}
        with TestClient(app) as client:
            homepage = client.get("/")
            if homepage.status_code != 200:
                raise RuntimeError(f"workbench homepage returned HTTP {homepage.status_code}")
            repo_response = client.post("/api/v1/repositories", headers=headers, json={
                "name": "OpenHarmony-GitCode-Mirror/third_party_libpng",
                "path": str(REPOSITORY),
            })
            if repo_response.status_code != 201:
                raise RuntimeError(repo_response.text)
            catalog_response = client.get("/api/v1/detectors")
            if catalog_response.status_code != 200:
                raise RuntimeError(f"detector catalog returned HTTP {catalog_response.status_code}")
            catalog = catalog_response.json()
            catalog_ids = {item["id"] for item in catalog}
            if DETECTOR not in catalog_ids:
                raise RuntimeError("known disclosed CVE scanner is absent from the panel detector catalog")
            repository_id = repo_response.json()["id"]
            first = scan_once(client, app, settings, repository_id, headers)
            second = scan_once(client, app, settings, repository_id, headers)
        stable = (first["git_tree"], first["snapshot_sha256"], first["candidate_signature"]) == (second["git_tree"], second["snapshot_sha256"], second["candidate_signature"])
        if not stable:
            raise RuntimeError("repeat scan differs for the same pinned source")
        output = {
            "schema": 1, "experiment": "D22 real libpng archive Runner and Workbench API/Worker replay",
            "repository": "OpenHarmony-GitCode-Mirror/third_party_libpng", "commit": COMMIT,
            "include_paths": [ARCHIVE], "detector": DETECTOR, "detector_version": "0.3.0",
            "homepage_http_status": 200, "detector_catalog_http_status": 200,
            "catalog_includes_known_disclosed_cves": True, "repeat_equal": stable,
            "results": [first, second],
            "limits": ["All matches remain candidate evidence; validated_vulnerability=0.",
                       "The repository is a component mirror, not a product image or official build manifest.",
                       "libpng parse coverage is partial; detector status blocked and task completed_with_limitations.",
                       "The TestClient exercises the same API/Worker/report/source-viewer path in an isolated data directory; it does not touch the user's running port 8765."],
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "repeat_equal": output["repeat_equal"],
                      "candidate": first["candidate"], "file": first["file"], "line": first["line"],
                      "report_sha256": [first["report_sha256"], second["report_sha256"]]}, ensure_ascii=False))


if __name__ == "__main__":
    main()

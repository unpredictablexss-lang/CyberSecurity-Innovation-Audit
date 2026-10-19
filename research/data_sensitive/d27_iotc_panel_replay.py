"""Replay D's exact-revision IoT Connect key-to-public-log profile through Workbench."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from src.workbench import service
from src.workbench.api import create_app
from src.workbench.settings import Settings
from src.workbench.worker import Worker

REPOSITORY_ROOT = Path("/mnt/g/OpenHarmony-GitCode-Mirror/campaign-100-20261017/repos")
REPOSITORY = REPOSITORY_ROOT / "communication_iot_connect"
COMMIT = "d8c0aef305601770c912dbdedc58a3f1e6efd30c"
SOURCE_PATH = "core/wifi/application/local_control/local_ctl_coap_api.c"
DETECTOR = "ohscanner.data.sensitive_exposure"


def scan_once(client, app, settings, repository_id, headers):
    response = client.post("/api/v1/scans", headers=headers, json={
        "repository_id": repository_id, "revision": COMMIT,
        "include_paths": [SOURCE_PATH], "detector_ids": [DETECTOR],
    })
    if response.status_code != 201:
        raise RuntimeError(response.text)
    job_id = response.json()["id"]
    Worker(settings).run(once=True)
    job = app.state.store.job(job_id)
    report = service.read_report(settings, job)
    runs = [run for run in report["detector_runs"] if run["tool"] == DETECTOR]
    if len(runs) != 1:
        raise RuntimeError("expected exactly one D detector run")
    run = runs[0]
    candidates = [item for item in run["diagnostics"]
                  if item["file"] == SOURCE_PATH and item["rule_id"] == "data.log.sensitive-value"]
    if len(candidates) != 1:
        raise RuntimeError(f"expected one derived-key log candidate, got {len(candidates)}")
    candidate = candidates[0]
    candidate_view = next(
        item for item in service.findings(report) if item["diagnostic_id"] == candidate["diagnostic_id"]
    )
    source = service.source(settings, app.state.store, job, candidate["file"])
    if source["sha256"] != candidate["source_sha256"]:
        raise RuntimeError("source viewer hash does not match D candidate")
    return {
        "job_id": job_id,
        "job_status": job["status"],
        "git_tree": report["git_tree"],
        "snapshot_sha256": report["snapshot_sha256"],
        "report_sha256": job["report_sha256"],
        "detector_status": run["status"],
        "candidate_count": len(candidates),
        "candidate": {
            "rule_id": candidate["rule_id"],
            "symbol": candidate["symbol"],
            "line": candidate["line"],
            "source_sha256": candidate["source_sha256"],
            "message": candidate["message"],
            "evidence_obligations": candidate_view["evidence"].get("obligations", []),
        },
        "source": {
            "sha256": source["sha256"],
            "blob": source["blob"],
        },
        "validated_vulnerability": report["validated_vulnerability"],
        "coverage": run.get("file_outcomes"),
        "limitations": run.get("limitations"),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("D27_IOTC_PANEL_REPLAY.json"))
    args = parser.parse_args()
    if not REPOSITORY.is_dir():
        raise SystemExit(f"required pinned G-drive repository is unavailable: {REPOSITORY}")
    with tempfile.TemporaryDirectory(prefix="ohscanner-d27-iotc-panel-") as data_dir:
        settings = Settings(Path(data_dir) / "data", (REPOSITORY_ROOT,))
        app = create_app(settings)
        headers = {"x-ohscanner-client": "workbench-v1"}
        with TestClient(app) as client:
            homepage = client.get("/")
            if homepage.status_code != 200:
                raise RuntimeError(f"Workbench returned HTTP {homepage.status_code}")
            registered = client.post("/api/v1/repositories", headers=headers, json={
                "name": "openharmony/communication_iot_connect",
                "path": str(REPOSITORY),
            })
            if registered.status_code != 201:
                raise RuntimeError(registered.text)
            catalog = client.get("/api/v1/detectors")
            if catalog.status_code != 200:
                raise RuntimeError(f"detector Catalog returned HTTP {catalog.status_code}")
            metadata = next((item for item in catalog.json() if item["id"] == DETECTOR), None)
            if metadata is None:
                raise RuntimeError("D detector is absent from the panel Catalog")
            repository_id = registered.json()["id"]
            first = scan_once(client, app, settings, repository_id, headers)
            second = scan_once(client, app, settings, repository_id, headers)
        same = (first["git_tree"], first["snapshot_sha256"],
                first["candidate"], first["source"]) == (
                second["git_tree"], second["snapshot_sha256"],
                second["candidate"], second["source"])
        if not same:
            raise RuntimeError("two scans of the same pinned Git source produced different evidence")
        output = {
            "schema": 1,
            "experiment": "D27 exact-revision communication_iot_connect derived-key public log replay",
            "repository": "openharmony/communication_iot_connect",
            "commit": COMMIT,
            "git_tree": first["git_tree"],
            "include_paths": [SOURCE_PATH],
            "detector": DETECTOR,
            "detector_version": metadata["version"],
            "catalog_kind": metadata["kind"],
            "catalog_default_enabled": metadata["default_enabled"],
            "homepage_http_status": homepage.status_code,
            "catalog_http_status": catalog.status_code,
            "two_runs_identical": same,
            "runs": [first, second],
            "classification": "source-bound candidate; product applicability and impact unknown",
            "limitations": [
                "G-drive mirror worktree may contain local modifications; only the exact Git commit/blob was scanned.",
                "The PBKDF2 output and UtilsHexify mapping are source-model facts for this pinned revision.",
                "The audit found the logged PBKDF2 output and a separate transKey derivation path; equality of their authCode inputs is unknown.",
                "Product build inclusion, INFO log enablement/collection, log-reader authorization, and security impact remain unknown.",
                "Workbench TestClient covers API -> Worker -> report -> source-view; it does not exercise the user's live panel server."
            ]
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "repeatable": output["two_runs_identical"],
        "candidate": first["candidate"]["symbol"],
        "line": first["candidate"]["line"],
        "detector_status": first["detector_status"],
        "job_status": first["job_status"],
        "validated_vulnerability": first["validated_vulnerability"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()

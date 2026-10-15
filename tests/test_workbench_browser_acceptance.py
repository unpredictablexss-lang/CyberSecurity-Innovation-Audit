"""Persistence and operation planning behind the browser acceptance flow."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.ohscanner.execution import run_fixed_commit_scan
from src.ohscanner.git_source import load_git_sources
from src.workbench.api import create_app
from src.workbench.operation_worker import OperationWorker
from src.workbench.operations_store import Operations
from src.workbench.service import engine_fingerprint
from src.workbench.settings import Settings
from src.workbench.store import Store

ROOT = Path(__file__).resolve().parents[1]
HEADERS = {"x-ohscanner-client": "workbench-v1"}
DETECTOR = "ohscanner.interface.ipc"


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True
    ).strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


class BrowserAcceptanceFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "targets" / "sample"
        self.repo.mkdir(parents=True)
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
        git(self.repo, "config", "user.name", "test")
        git(self.repo, "config", "user.email", "test@example.invalid")
        self.write_and_commit(
            "seed.txt",
            "baseline\n",
            "baseline",
            "2025-01-01T00:00:00+00:00",
        )
        self.commit_a = git(self.repo, "rev-parse", "HEAD")
        self.write_and_commit(
            "middle.txt",
            "middle\n",
            "middle",
            "2025-01-02T00:00:00+00:00",
        )
        self.commit_b = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "common_types.h").write_text(
            (ROOT / "tests/fixtures/ipc/common_types.h").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (self.repo / "cluster.cpp").write_text(
            "#define Stub BrowserFixture\n"
            '#include "common_types.h"\n'
            "\n"
            "int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,"
            "MessageParcel &reply,MessageOption &option) {\n"
            "if (data.ReadInterfaceToken() != GetDescriptor()) return -1;\n"
            "StartAbility();\n"
            "StartAbility();\n"
            "return 0;\n"
            "}\n",
            encoding="utf-8",
        )
        git(self.repo, "add", "common_types.h", "cluster.cpp")
        env_date = "2025-01-03T00:00:00+00:00"
        subprocess.run(
            ["git", "commit", "-q", "-m", "candidate"],
            cwd=self.repo,
            check=True,
            env={
                **__import__("os").environ,
                "GIT_AUTHOR_DATE": env_date,
                "GIT_COMMITTER_DATE": env_date,
            },
        )
        self.commit_c = git(self.repo, "rev-parse", "HEAD")
        self.settings = Settings(self.root / "data", (self.root / "targets",))
        self.settings.initialize()
        self.store = Store(self.settings.data_dir)
        self.repo_record = self.store.add_repository(
            "fixture/sample", str(self.repo)
        )

    def write_and_commit(self, name, text, message, date):
        (self.repo / name).write_text(text, encoding="utf-8")
        git(self.repo, "add", name)
        subprocess.run(
            ["git", "commit", "-q", "-m", message],
            cwd=self.repo,
            check=True,
            env={
                **__import__("os").environ,
                "GIT_AUTHOR_DATE": date,
                "GIT_COMMITTER_DATE": date,
            },
        )

    def seed_completed_scan(self):
        artifacts = self.settings.data_dir / "artifacts"
        job_id = "b" * 32
        out = artifacts / job_id
        out.mkdir(parents=True)
        report = run_fixed_commit_scan(
            self.repo,
            "fixture/sample",
            self.commit_c,
            (".",),
            (DETECTOR,),
            out / "report.json",
            out / "report.md",
        )
        _, _, sources, _ = load_git_sources(self.repo, self.commit_c, (".",))
        report["_workbench"] = {
            "engine_sha256": engine_fingerprint(),
            "total_source_lines": sum(len(source.data.splitlines()) for source in sources),
            "execution_boundary": {
                "kind": "local_static_scan_process",
                "hard_task_timeout_seconds": 300,
                "address_space_limit_mb": 2048,
                "per_detector_hard_timeout": False,
                "untrusted_build_sandbox": False,
            },
            "markdown_sha256": digest((out / "report.md").read_bytes()),
            "source_inventory": [
                {
                    "file": source.path,
                    "blob": source.oid,
                    "sha256": digest(source.data),
                }
                for source in sources
            ],
        }
        raw = (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        (out / "report.json").write_bytes(raw)
        spec = {
            "commit": self.commit_c,
            "git_tree": git(self.repo, "rev-parse", self.commit_c + "^{tree}"),
            "repository": "fixture/sample",
            "include_paths": ["."],
            "detector_ids": [DETECTOR],
            "timeout_seconds": 300,
            "memory_mb": 2048,
        }
        with self.store.connect() as db:
            db.execute(
                "INSERT INTO jobs(id,repository_id,spec,status,stage,created_at)"
                " VALUES(?,?,?,?,?,?)",
                (
                    job_id,
                    self.repo_record["id"],
                    json.dumps(spec, sort_keys=True),
                    "queued",
                    "source_pinned",
                    "2025-01-01T00:00:00+00:00",
                ),
            )
        self.store.claim()
        self.store.finish(
            job_id,
            status=report["status"],
            report_sha256=digest(raw),
            elapsed=0.1,
        )
        return job_id, digest(raw), report

    def api(self, settings=None):
        app = create_app(settings or self.settings)
        client = TestClient(app)
        self.addCleanup(client.close)
        return app, client


class PersistenceRestartTests(BrowserAcceptanceFixture):
    def test_restart_recovers_operation_review_evidence_and_report(self):
        job_id, report_sha, report = self.seed_completed_scan()
        app, client = self.api()
        findings = client.get(
            f"/api/v1/scans/{job_id}/findings", headers=HEADERS
        ).json()["items"]
        self.assertGreaterEqual(len(findings), 2)
        identity = findings[0]["id"]
        review = client.post(
            f"/api/v1/scans/{job_id}/findings/{identity}/reviews",
            headers=HEADERS,
            json={
                "status": "under_review",
                "reviewer": "browser-acceptance",
                "notes": "persisted append-only review",
                "expected_id": 0,
            },
        )
        self.assertEqual(review.status_code, 201, review.text)
        evidence = client.post(
            f"/api/v1/scans/{job_id}/findings/{identity}/evidence",
            headers=HEADERS,
            json={
                "file": findings[0]["file"],
                "start_line": 1,
                "end_line": 2,
                "note": "persisted source evidence",
            },
        )
        self.assertEqual(evidence.status_code, 201, evidence.text)
        evidence_id = evidence.json()["id"]
        case = client.post(
            "/api/v1/cases",
            headers=HEADERS,
            json={
                "title": "browser restart case",
                "links": [
                    {
                        "job_id": job_id,
                        "candidate_id": identity,
                        "rationale": "cluster expansion and report recovery",
                    }
                ],
            },
        )
        self.assertEqual(case.status_code, 201, case.text)
        case_id = case.json()["id"]
        operation = client.post(
            "/api/v1/operations/source-sync",
            headers=HEADERS,
            json={
                "repository": "openharmony/c_utils",
                "url": "https://github.com/openharmony/c_utils.git",
                "timeout_seconds": 10,
            },
        ).json()
        app.state.operations.claim()
        self.assertEqual(app.state.operations.get(operation["id"])["status"], "running")
        client.close()

        restarted_app, restarted = self.api()
        restarted_app.state.operations.recover()
        recovered = restarted.get(
            f"/api/v1/operations/{operation['id']}", headers=HEADERS
        ).json()
        self.assertEqual(recovered["status"], "interrupted")
        detail = restarted.get(
            f"/api/v1/scans/{job_id}/findings/{identity}", headers=HEADERS
        ).json()
        self.assertEqual(detail["reviews"][0]["id"], 1)
        self.assertEqual(detail["supplemental_evidence"][0]["id"], evidence_id)
        self.assertEqual(detail["binding"]["report_sha256"], report_sha)
        clusters = restarted.get(
            f"/api/v1/scans/{job_id}/clusters", headers=HEADERS
        ).json()
        self.assertTrue(any(len(group["candidates"]) >= 2 for group in clusters["items"]))
        report_response = restarted.get(
            f"/api/v1/cases/{case_id}/report.json", headers=HEADERS
        )
        self.assertEqual(report_response.status_code, 200)
        self.assertIn("attachment", report_response.headers["content-disposition"])
        self.assertEqual(report_response.json()["candidates"][0]["candidate"]["id"], identity)
        markdown = restarted.get(
            f"/api/v1/cases/{case_id}/report.md", headers=HEADERS
        )
        self.assertEqual(markdown.status_code, 200)
        self.assertIn("attachment", markdown.headers["content-disposition"])
        self.assertIn("candidate", markdown.text)
        self.assertEqual(report["detector_runs"][0]["schema_version"], 2)


class MigrationOrderTests(BrowserAcceptanceFixture):
    def test_investigation_v4_requires_operations_v3(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory))
            with self.assertRaisesRegex(RuntimeError, "operations schema v3"):
                store.migrate_investigation_drafts()
            Operations(store)
            with store.connect() as db:
                versions = [
                    row[0]
                    for row in db.execute(
                        "SELECT version FROM schema_migrations ORDER BY version"
                    )
                ]
            self.assertEqual(versions, [1, 2, 3, 4])


class OperationPlanningTests(BrowserAcceptanceFixture):
    def test_revision_date_and_matrix_operations_keep_fixed_scans(self):
        app, client = self.api()
        job_id, _, _ = self.seed_completed_scan()
        finding = client.get(
            f"/api/v1/scans/{job_id}/findings", headers=HEADERS
        ).json()["items"][0]
        case_id = client.post(
            "/api/v1/cases",
            headers=HEADERS,
            json={
                "title": "matrix case",
                "links": [
                    {
                        "job_id": job_id,
                        "candidate_id": finding["id"],
                        "rationale": "fixed version observations",
                    }
                ],
            },
        ).json()["id"]
        common = {
            "repository_id": self.repo_record["id"],
            "include_paths": ["."],
            "detector_ids": [DETECTOR],
            "timeout_seconds": 30,
            "memory_mb": 256,
        }
        revision = client.post(
            "/api/v1/operations/revision-ranges",
            headers=HEADERS,
            json={**common, "baseline": self.commit_a, "endpoint": self.commit_c},
        )
        self.assertEqual(revision.status_code, 201, revision.text)
        self.assertEqual(len(revision.json()["spec"]["scan_ids"]), 2)
        dated = client.post(
            "/api/v1/operations/date-ranges",
            headers=HEADERS,
            json={
                **common,
                "branch": "HEAD",
                "start": "2025-01-02T00:00:00",
                "end": "2025-01-04T00:00:00",
                "timezone": "UTC",
            },
        )
        self.assertEqual(dated.status_code, 201, dated.text)
        self.assertEqual(
            dated.json()["spec"]["date_selection"]["selected_commits"],
            [self.commit_c, self.commit_b],
        )
        matrix = client.post(
            "/api/v1/operations/version-matrices",
            headers=HEADERS,
            json={
                **common,
                "case_id": case_id,
                "commits": [self.commit_a, self.commit_c],
            },
        )
        self.assertEqual(matrix.status_code, 201, matrix.text)
        self.assertEqual(len(matrix.json()["spec"]["scan_ids"]), 2)
        self.assertEqual(matrix.json()["spec"]["commits"], [self.commit_a, self.commit_c])


class OperationWorkerBoundaryTests(BrowserAcceptanceFixture):
    class FakeProcess:
        def __init__(self):
            self.pid = 4242
            self.returncode = None

        def poll(self):
            return self.returncode

    def test_hard_deadline_publishes_timed_out_without_partial_result(self):
        ops = Operations(self.store)
        task = ops.create("source_sync", {"timeout_seconds": 1})
        task = ops.claim()
        fake = self.FakeProcess()
        def terminate_once(process):
            process.returncode = -15

        with patch("src.workbench.operation_worker.subprocess.Popen", return_value=fake), \
             patch("src.workbench.operation_worker.time.monotonic", side_effect=[0, 2]), \
             patch("src.workbench.operation_worker.Worker.terminate", side_effect=terminate_once) as terminate:
            OperationWorker(self.settings).execute(task)
        terminate.assert_called_once_with(fake)
        self.assertEqual(ops.get(task["id"])["status"], "timed_out")
        self.assertIsNone(ops.get(task["id"])["result_sha256"])

    def test_running_cancellation_does_not_publish_a_result(self):
        ops = Operations(self.store)
        task = ops.create("source_sync", {"timeout_seconds": 30})
        ops.claim()
        ops.cancel(task["id"])
        fake = self.FakeProcess()
        def terminate_once(process):
            process.returncode = -15

        with patch("src.workbench.operation_worker.subprocess.Popen", return_value=fake), \
             patch("src.workbench.operation_worker.Worker.terminate", side_effect=terminate_once) as terminate:
            OperationWorker(self.settings).execute(ops.get(task["id"]))
        terminate.assert_called_once_with(fake)
        self.assertEqual(ops.get(task["id"])["status"], "cancelled")
        self.assertIsNone(ops.get(task["id"])["result_sha256"])

    def test_child_failure_preserves_stage_and_process_output(self):
        ops = Operations(self.store)
        task = ops.create("source_sync", {"timeout_seconds": 30})
        task = ops.claim()
        folder = ops.directory(task["id"])
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "child-error.json").write_text(json.dumps({
            "stage": "source_sync.git_process",
            "type": "RuntimeError",
            "message": "source sync Git process exited 7; stdout=fixture-out; stderr=fixture-err",
            "stdout": "fixture-out",
            "stderr": "fixture-err",
        }, sort_keys=True), encoding="utf-8")
        fake = self.FakeProcess()
        fake.returncode = 7
        with patch("src.workbench.operation_worker.subprocess.Popen", return_value=fake):
            OperationWorker(self.settings).execute(task)
        finished = ops.get(task["id"])
        self.assertEqual(finished["status"], "failed")
        self.assertIn("Operation child exited 7", finished["error"])
        self.assertIn("stage=source_sync.git_process", finished["error"])
        self.assertIn("fixture-out; stderr=fixture-err", finished["error"])
        self.assertIsNone(finished["result_sha256"])


class HistoricalBaselineTests(unittest.TestCase):
    def test_clean_checkout_ships_valid_m1_identity_baseline(self):
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.verify_owner_ipc_components",
                "--validate-baseline-only",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            json.loads(completed.stdout)["counts"],
            {
                "pre_m1": 41,
                "post_m1": 24,
                "expected_current": 23,
                "m1_removed": 17,
                "m2_removed": 1,
            },
        )


if __name__ == "__main__":
    unittest.main()

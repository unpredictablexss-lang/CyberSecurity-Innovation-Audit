import os
import json
import subprocess
import tempfile
import time
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from src.workbench.api import create_app
from src.workbench.operations import approved_url, compare_reports, date_selection
from src.workbench import operations
from src.workbench.operations_store import Operations
from src.workbench.settings import Settings
from src.workbench.store import Store
from src.workbench import validation
from src.workbench.operation_worker import OperationWorker
from src.workbench.worker import Worker
from src.workbench import service


class OperationsStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.settings = Settings(self.root / "data", (self.root / "targets",))
        self.settings.initialize()
        self.store = Store(self.settings.data_dir)
        self.ops = Operations(self.store)
        self.repo_path = self.root / "targets" / "repo"
        self.repo_path.mkdir(parents=True)
        self.repo = self.store.add_repository("openharmony/sample", str(self.repo_path))

    def tearDown(self):
        self.temp.cleanup()

    def test_first_start_store_schema_initialization_is_serialized(self):
        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "fresh-data"
            barrier = threading.Barrier(8)

            def construct():
                barrier.wait()
                return Store(data_dir)

            with ThreadPoolExecutor(max_workers=8) as pool:
                stores = list(pool.map(lambda _: construct(), range(8)))
            self.assertEqual(len(stores), 8)
            with stores[0].connect() as db:
                self.assertEqual(
                    db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0],
                    2,
                )

    def test_operation_and_endpoint_scans_are_committed_together(self):
        spec = {"commit": "a" * 40, "repository": "openharmony/sample"}
        item = self.ops.create_with_scans("revision_range", {"baseline": "a" * 40},
                                          self.repo["id"], [spec, {**spec, "commit": "b" * 40}])
        self.assertEqual(len(item["spec"]["scan_ids"]), 2)
        self.assertEqual([self.store.job(x)["spec"]["commit"] for x in item["spec"]["scan_ids"]],
                         ["a" * 40, "b" * 40])
        self.assertEqual(len(self.ops.events(item["id"])), 1)

    def test_claim_lanes_do_not_take_each_others_work(self):
        a = self.ops.create("source_sync", {"name": "openharmony/a"})
        b = self.ops.create("validation", {"harness_id": "auth01_descriptor_bypass"})
        self.assertEqual(self.ops.claim(validation=True)["id"], b["id"])
        self.assertEqual(self.ops.claim(validation=False)["id"], a["id"])

    def test_candidate_review_batches_are_idempotent_unbounded_and_stay_queued_without_provider(self):
        spec = {"job_id": "a" * 32, "report_sha256": "b" * 64,
                "candidate_count_at_enqueue": 125, "timeout_seconds": 60, "memory_mb": 512}
        first = self.ops.create("candidate_review_batch", spec)
        duplicate = self.ops.create("candidate_review_batch", spec)
        self.assertEqual(first["id"], duplicate["id"])
        self.assertEqual(first["status"], "queued")
        self.assertEqual(first["spec"]["candidate_count_at_enqueue"], 125)
        summary = self.ops.candidate_review_queue()
        self.assertEqual(summary["queued_batches"], 1)
        self.assertEqual(summary["queued_candidates"], 125)
        self.assertFalse(summary["model_provider_configured"])
        self.assertIsNone(self.ops.claim())
        self.assertEqual(self.ops.get(first["id"])["status"], "queued")

    def test_candidate_batches_do_not_consume_normal_operation_capacity(self):
        batch = self.ops.create("candidate_review_batch", {"job_id": "a" * 32, "report_sha256": "b" * 64})
        normal = self.ops.create("investigation", {"job_id": "c" * 32})
        self.assertEqual(self.ops.claim()["id"], normal["id"])
        self.assertEqual(self.ops.get(batch["id"])["status"], "queued")

    def test_candidate_review_queue_cannot_be_cancelled_and_lose_candidates(self):
        batch = self.ops.create("candidate_review_batch", {"job_id": "a" * 32, "report_sha256": "b" * 64})
        with self.assertRaisesRegex(ValueError, "cannot be cancelled"):
            self.ops.cancel(batch["id"])
        self.assertEqual(self.ops.get(batch["id"])["status"], "queued")

    def test_result_integrity_detects_tampering(self):
        task = self.ops.create("investigation", {})
        self.ops.claim()
        self.ops.finish(task["id"], {"status": "completed", "answer": "read-only"})
        self.assertEqual(self.ops.result(task["id"])["answer"], "read-only")
        path = self.ops.directory(task["id"]) / "result.json"
        path.write_text("{}")
        with self.assertRaisesRegex(ValueError, "integrity"):
            self.ops.result(task["id"])

    def test_cancel_only_requests_cancellation_for_owned_child_scans(self):
        other = self.store.create_job(self.repo["id"], {"commit": "c" * 40})
        task = self.ops.create("revision_range", {"scan_ids": []})
        self.ops.cancel(task["id"])
        self.assertEqual(self.store.job(other["id"])["status"], "queued")

    def test_v3_migration_makes_a_backup(self):
        backups = list((self.settings.data_dir / "backups").glob("before-v3-*.sqlite3"))
        self.assertTrue(backups)


class PlanningTests(unittest.TestCase):
    def test_date_selection_uses_committer_time_and_records_topology_span(self):
        import os
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo_path = root / "repo"
            repo_path.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo_path, check=True)
            env = {**os.environ, "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
                   "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.invalid"}
            commits = []
            for index, stamp in enumerate(("2025-01-01T00:00:00Z", "2025-01-02T00:00:00Z", "2025-01-03T00:00:00Z")):
                (repo_path / "source.cpp").write_text("int x = " + str(index) + ";\n")
                subprocess.run(["git", "add", "source.cpp"], cwd=repo_path, env=env, check=True)
                commit_env = {**env, "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp}
                subprocess.run(["git", "commit", "-q", "-m", str(index)], cwd=repo_path, env=commit_env, check=True)
                commits.append(subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo_path,
                                              capture_output=True, text=True, check=True).stdout.strip())
            settings = Settings(root / "data", (root,))
            settings.initialize()
            store = Store(settings.data_dir)
            registered = store.add_repository("openharmony/date-test", str(repo_path))
            selected = date_selection(settings, store, registered["id"], "HEAD",
                                      "2025-01-02T00:00:00+00:00", "2025-01-04T00:00:00+00:00", "UTC")
            self.assertEqual(selected["selected_commits"], [commits[2], commits[1]])
            self.assertEqual(selected["baseline"], commits[0])
            self.assertEqual(selected["endpoint"], commits[2])
            self.assertEqual(selected["boundary"], "[start,end)")

    def test_source_sync_allowlist_rejects_userinfo_ports_and_other_paths(self):
        self.assertEqual(approved_url("https://github.com/openharmony/c_utils.git"),
                         "https://github.com/openharmony/c_utils.git")
        for url in ("http://github.com/openharmony/a", "https://user@github.com/openharmony/a",
                    "https://github.com:443/openharmony/a", "https://github.com/other/a",
                    "https://github.com/openharmony/a?x=1", "https://evil.example/openharmony/a"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                approved_url(url)

    def test_range_comparison_does_not_call_static_candidate_a_fix(self):
        before = {"detector_runs": [], "detector_coverage": {"detectors": {"d": {"analyzed_files": ["a.cpp"], "evidence_obligations": []}}},
                  "_workbench": {"source_inventory": [{"file": "a.cpp"}]}}
        after = {"detector_runs": [], "detector_coverage": {"detectors": {"d": {"analyzed_files": ["a.cpp"], "evidence_obligations": []}}},
                 "_workbench": {"source_inventory": [{"file": "a.cpp"}]}}
        rows = compare_reports(before, after, [])
        self.assertEqual(rows, [])

    def test_missing_coverage_leaves_candidate_delta_unknown(self):
        before = {"repository": "openharmony/test", "commit": "a" * 40, "snapshot_sha256": "1" * 64,
                  "detector_runs": [], "detector_coverage": {"detectors": {"d": {"analyzed_files": [], "evidence_obligations": []}}},
                  "_workbench": {"source_inventory": [{"file": "a.cpp"}]}}
        finding = {"diagnostic_id": "diagnostic", "rule_id": "r", "file": "a.cpp", "line": 1, "symbol": "f"}
        after = {**before, "commit": "b" * 40, "detector_runs": [{"tool": "d", "tool_version": "1", "diagnostics": [finding]}]}
        rows = compare_reports(before, after, [])
        self.assertEqual(rows[0]["status"], "unknown")
        self.assertEqual(rows[0]["vulnerability_introduced_or_fixed"], "unknown")

    def test_failed_branch_endpoint_keeps_comparison_and_impact_unknown(self):
        task = {"kind": "branch_comparison", "spec": {
            "baseline_ref": "refs/heads/main", "baseline": "a" * 40,
            "endpoint_ref": "refs/heads/feature", "endpoint": "b" * 40,
            "scan_ids": ["1" * 32, "2" * 32],
        }}
        with patch.object(operations, "wait_reports", return_value=[None, None]):
            result = operations.execute(None, None, None, task)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["impact"], "unknown")
        self.assertEqual(result["candidate_comparison"][0]["status"], "unknown")
        self.assertEqual(result["validated_vulnerability"], 0)


class DockerBoundaryTests(unittest.TestCase):
    def test_runtime_never_falls_back_to_host_when_docker_is_not_ready(self):
        class FakeOps:
            def directory(self, key):
                return Path(tempfile.gettempdir()) / key
        class FakeStore:
            pass
        task = {"id": "a" * 32, "spec": {"target_path": "/tmp", "cutils_path": "/tmp"}}
        with patch.object(validation, "readiness", return_value={"ready": False, "reason": "no daemon"}):
            result = validation.execute_validation(None, FakeStore(), FakeOps(), task)
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["isolation"]["host_fallback"])


class OperationsApiTests(unittest.TestCase):
    def test_operations_queue_is_exposed_by_local_api(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory) / "data", (Path(directory) / "targets",))
            client = TestClient(create_app(settings))
            response = client.get("/api/v1/operations")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), [])

    def test_local_api_rejects_arbitrary_git_sync_url(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory) / "data", (Path(directory) / "targets",))
            client = TestClient(create_app(settings))
            response = client.post("/api/v1/operations/source-sync", headers={"X-OHScanner-Client": "workbench-v1"},
                                   json={"repository": "openharmony/a", "url": "https://evil.example/openharmony/a"})
            self.assertIn(response.status_code, (409, 422))


class OperationEndToEndTests(unittest.TestCase):
    """Drive fixed-source operations through API, isolated Worker, and saved report."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo_path = self.root / "targets" / "repo"
        self.repo_path.mkdir(parents=True)
        self.repo_path.joinpath("demo.cpp").write_text(
            (Path(__file__).parent / "detectors/fixtures/cpp_lifetime/vulnerable_unserialized.cpp").read_text()
        )
        subprocess.run(["git", "init", "-q"], cwd=self.repo_path, check=True)
        subprocess.run(["git", "config", "user.name", "fixture"], cwd=self.repo_path, check=True)
        subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=self.repo_path, check=True)
        self.commits = []
        self._commit("2025-01-01T00:00:00Z", "vulnerable endpoint")
        self.repo_path.joinpath("demo.cpp").write_text(
            (Path(__file__).parent / "detectors/fixtures/cpp_lifetime/fixed_alias_rebind.cpp").read_text()
        )
        self._commit("2025-01-02T00:00:00Z", "fixed endpoint")
        self.repo_path.joinpath("notes.txt").write_text("third revision\n")
        self._commit("2025-01-03T00:00:00Z", "later revision")
        subprocess.run(["git", "branch", "-M", "main"], cwd=self.repo_path, check=True)
        subprocess.run(["git", "checkout", "-q", "-b", "feature", self.commits[0]], cwd=self.repo_path, check=True)
        self.repo_path.joinpath("feature.txt").write_text("divergent branch endpoint\n")
        self._commit("2025-01-04T00:00:00Z", "feature endpoint")
        self.feature_commit = self.commits[-1]
        subprocess.run(["git", "checkout", "-q", "main"], cwd=self.repo_path, check=True)

        self.settings = Settings(self.root / "data", (self.root / "targets",))
        self.client = TestClient(create_app(self.settings))
        self.addCleanup(self.client.close)
        self.store = self.client.app.state.store
        response = self.client.post("/api/v1/repositories", headers={"X-OHScanner-Client": "workbench-v1"},
                                    json={"name": "openharmony/flow-test", "path": str(self.repo_path)})
        self.assertEqual(response.status_code, 201, response.text)
        self.repo = response.json()
        self.detectors = ["ohscanner.cpp.lifetime"]

    def _commit(self, stamp, message):
        subprocess.run(["git", "add", "."], cwd=self.repo_path, check=True)
        env = {**os.environ, "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
               "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
               "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp}
        subprocess.run(["git", "commit", "-q", "-m", message], cwd=self.repo_path, env=env, check=True)
        self.commits.append(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo_path, text=True).strip())

    def _scan(self, commit):
        response = self.client.post("/api/v1/scans", headers={"X-OHScanner-Client": "workbench-v1"},
                                    json={"repository_id": self.repo["id"], "revision": commit,
                                          "detector_ids": self.detectors})
        self.assertEqual(response.status_code, 201, response.text)
        Worker(self.settings).run(once=True)
        job = self.store.job(response.json()["id"])
        self.assertIn(job["status"], {"completed", "completed_with_limitations"}, job)
        return job

    def _run_operation(self, operation):
        thread = threading.Thread(target=lambda: OperationWorker(self.settings).run(once=True))
        thread.start()
        deadline = time.monotonic() + 40
        while thread.is_alive() and time.monotonic() < deadline:
            for scan_id in operation["spec"]["scan_ids"]:
                if self.store.job(scan_id)["status"] == "queued":
                    Worker(self.settings).run(once=True)
                    break
            thread.join(0.05)
        if thread.is_alive():
            raise AssertionError("operation worker did not finish within 40 seconds")
        completed = self.client.get("/api/v1/operations/" + operation["id"])
        self.assertEqual(completed.status_code, 200, completed.text)
        item = completed.json()
        self.assertEqual(item["status"], "completed_with_limitations", item)
        self.assertEqual(len(item["result"]["scan_ids"]), len(operation["spec"]["scan_ids"]))
        self.assertEqual(len(item["result_sha256"]), 64)
        return item

    def test_sha_range_date_range_and_version_matrix_reach_persisted_reports(self):
        source_job = self._scan(self.commits[0])
        report = service.read_report(self.settings, source_job)
        candidates = service.findings(report)
        self.assertTrue(candidates, "fixture must produce a reviewable candidate")
        case_response = self.client.post("/api/v1/cases", headers={"X-OHScanner-Client": "workbench-v1"},
            json={"title": "temporary integration case", "links": [{"job_id": source_job["id"],
                  "candidate_id": candidates[0]["id"], "rationale": "isolated test fixture"}]})
        self.assertEqual(case_response.status_code, 201, case_response.text)
        case_id = case_response.json()["id"]

        headers = {"X-OHScanner-Client": "workbench-v1"}
        base = {"repository_id": self.repo["id"], "include_paths": ["."], "detector_ids": self.detectors,
                "timeout_seconds": 30, "memory_mb": 512}
        sha_range = self.client.post("/api/v1/operations/revision-ranges", headers=headers, json={
            **base, "baseline": self.commits[0], "endpoint": self.commits[1]})
        self.assertEqual(sha_range.status_code, 201, sha_range.text)
        self.assertEqual(sha_range.json()["spec"]["commits"], [self.commits[1]])
        range_result = self._run_operation(sha_range.json())
        self.assertEqual(range_result["result"]["baseline"], self.commits[0])
        self.assertEqual(range_result["result"]["endpoint"], self.commits[1])

        date_range = self.client.post("/api/v1/operations/date-ranges", headers=headers, json={
            **base, "branch": "HEAD", "start": "2025-01-02T00:00:00+00:00",
            "end": "2025-01-03T00:00:00+00:00", "timezone": "UTC"})
        self.assertEqual(date_range.status_code, 201, date_range.text)
        selection = date_range.json()["spec"]["date_selection"]
        self.assertEqual(selection["selected_commits"], [self.commits[1]])
        self.assertEqual(selection["baseline"], self.commits[0])
        self.assertEqual(selection["endpoint"], self.commits[1])
        operation_count_before_preview = len(self.client.get("/api/v1/operations").json())
        preview = self.client.post("/api/v1/operations/date-ranges/preview", headers=headers, json={
            "repository_id": self.repo["id"], "branch": "refs/heads/main", "start": "2025-01-02T00:00:00",
            "end": "2025-01-03T00:00:00", "timezone": "UTC"})
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertEqual(preview.json()["branch"], "refs/heads/main")
        self.assertEqual(preview.json()["selected_commits"], [self.commits[1]])
        shanghai_preview = self.client.post("/api/v1/operations/date-ranges/preview", headers=headers, json={
            "repository_id": self.repo["id"], "branch": "refs/heads/main", "start": "2025-01-02T08:00:00",
            "end": "2025-01-02T08:00:01", "timezone": "Asia/Shanghai"})
        self.assertEqual(shanghai_preview.status_code, 200, shanghai_preview.text)
        self.assertEqual(shanghai_preview.json()["selected_commits"], [self.commits[1]])
        empty_preview = self.client.post("/api/v1/operations/date-ranges/preview", headers=headers, json={
            "repository_id": self.repo["id"], "branch": "refs/heads/main", "start": "2025-01-02T08:00:00",
            "end": "2025-01-02T08:00:00", "timezone": "Asia/Shanghai"})
        self.assertEqual(empty_preview.status_code, 409)
        self.assertEqual(len(self.client.get("/api/v1/operations").json()), operation_count_before_preview)
        date_result = self._run_operation(date_range.json())
        self.assertEqual(date_result["result"]["date_selection"]["boundary"], "[start,end)")

        matrix = self.client.post("/api/v1/operations/version-matrices", headers=headers, json={
            **base, "case_id": case_id, "commits": self.commits[:2]})
        self.assertEqual(matrix.status_code, 201, matrix.text)
        self.assertEqual(matrix.json()["spec"]["commits"], self.commits[:2])
        matrix_result = self._run_operation(matrix.json())
        self.assertEqual(len(matrix_result["result"]["versions"]), 2)
        self.assertEqual(len(matrix_result["result"]["comparisons"]), 1)
        self.assertEqual(matrix_result["result"]["validated_vulnerability"], 0)

        refs = self.client.get("/api/v1/repositories/" + self.repo["id"] + "/revisions").json()
        self.assertIn("refs/heads/main", {item["ref"] for item in refs})
        self.assertIn("refs/heads/feature", {item["ref"] for item in refs})
        branch_comparison = self.client.post("/api/v1/operations/branch-comparisons", headers=headers, json={
            **base, "baseline_ref": "refs/heads/main", "endpoint_ref": "refs/heads/feature"})
        self.assertEqual(branch_comparison.status_code, 201, branch_comparison.text)
        branch_spec = branch_comparison.json()["spec"]
        self.assertEqual(branch_spec["baseline"], self.commits[2])
        self.assertEqual(branch_spec["endpoint"], self.feature_commit)
        self.assertEqual(branch_spec["baseline_ref"], "refs/heads/main")
        self.assertEqual(branch_spec["endpoint_ref"], "refs/heads/feature")
        self.assertNotEqual(branch_spec["baseline"], branch_spec["endpoint"])
        invalid_ref = self.client.post("/api/v1/operations/branch-comparisons", headers=headers, json={
            **base, "baseline_ref": "refs/heads/not-present", "endpoint_ref": "refs/heads/feature"})
        self.assertEqual(invalid_ref.status_code, 409)
        same_ref = self.client.post("/api/v1/operations/branch-comparisons", headers=headers, json={
            **base, "baseline_ref": "refs/heads/main", "endpoint_ref": "refs/heads/main"})
        self.assertEqual(same_ref.status_code, 409)
        # Move the selected branch after queueing; the operation must keep its pinned object ID.
        subprocess.run(["git", "update-ref", "refs/heads/feature", self.commits[1]], cwd=self.repo_path, check=True)
        branch_result = self._run_operation(branch_comparison.json())
        self.assertEqual(branch_result["result"]["baseline"], self.commits[2])
        self.assertEqual(branch_result["result"]["endpoint"], self.feature_commit)
        self.assertEqual(branch_result["result"]["impact"], "unknown")
        self.assertEqual(branch_result["result"]["validated_vulnerability"], 0)
        self.assertEqual(len(branch_result["result"]["candidate_comparison"]), 1)

        # A newly opened Store sees the exact same hashed operation artifact.
        reopened = Operations(Store(self.settings.data_dir))
        self.assertEqual(reopened.result(range_result["id"]), range_result["result"])


class OperationLifecycleTests(unittest.TestCase):
    """Exercise persisted operation state transitions without touching live data."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = Settings(self.root / "data", (self.root / "targets",))
        self.settings.initialize()
        self.store = Store(self.settings.data_dir)
        self.ops = Operations(self.store)

    def test_worker_restart_marks_running_operations_interrupted(self):
        task = self.ops.create("investigation", {"job_id": "j" * 32})
        self.assertEqual(self.ops.claim()["id"], task["id"])

        # Starting a fresh operation worker performs crash recovery before claims.
        OperationWorker(self.settings).run(once=True)

        recovered = self.ops.get(task["id"])
        self.assertEqual(recovered["status"], "interrupted")
        self.assertIsNone(recovered["result_sha256"])
        self.assertIn("retry explicitly", recovered["error"])

    def test_running_operation_cancel_terminates_its_child(self):
        task = self.ops.create("investigation", {"job_id": "j" * 32, "timeout_seconds": 10})
        claimed = self.ops.claim()
        real_popen = subprocess.Popen
        processes = []

        def sleeper(*args, **kwargs):
            proc = real_popen(["/usr/bin/python3", "-c", "import time; time.sleep(30)"], **kwargs)
            processes.append(proc)
            return proc

        cancel = threading.Thread(target=lambda: (time.sleep(0.3), self.ops.cancel(task["id"])))
        cancel.start()
        with patch("src.workbench.operation_worker.subprocess.Popen", side_effect=sleeper):
            OperationWorker(self.settings).execute(claimed)
        cancel.join()

        self.assertEqual(self.ops.get(task["id"])["status"], "cancelled")
        self.assertIsNone(self.ops.get(task["id"])["result_sha256"])
        self.assertTrue(processes)
        self.assertIsNotNone(processes[0].poll())

    def test_operation_hard_timeout_terminates_child_and_records_no_result(self):
        task = self.ops.create("investigation", {"job_id": "j" * 32, "timeout_seconds": 1})
        claimed = self.ops.claim()
        real_popen = subprocess.Popen
        processes = []

        def sleeper(*args, **kwargs):
            proc = real_popen(["/usr/bin/python3", "-c", "import time; time.sleep(30)"], **kwargs)
            processes.append(proc)
            return proc

        start = time.monotonic()
        with patch("src.workbench.operation_worker.subprocess.Popen", side_effect=sleeper):
            OperationWorker(self.settings).execute(claimed)

        result = self.ops.get(task["id"])
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(result["status"], "timed_out")
        self.assertIsNone(result["result_sha256"])
        self.assertTrue(processes)
        self.assertIsNotNone(processes[0].poll())


if __name__ == "__main__":
    unittest.main()

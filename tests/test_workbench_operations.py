import os
import json
import hashlib
import subprocess
import tempfile
import time
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

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

    def test_legacy_r2_budget_status_is_exposed_as_candidate_limit(self):
        row = {"r2_status": "budget_limited", "candidate_manifest": "[]",
               "operation_ids": "[]", "r2_operation_ids": "[]",
               "r2_candidate_manifest": "[]"}
        self.assertEqual(Operations.triage_batch_row(row)["r2_status"],
                         "candidate_limit_reached")

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

    def test_recent_window_planner_freezes_disjoint_n_day_and_one_day_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo_path = root / "targets" / "repo"
            repo_path.mkdir(parents=True)
            subprocess.run(["git", "init", "-q"], cwd=repo_path, check=True)
            env = {**os.environ, "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
                   "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.invalid"}
            for index, stamp in enumerate(("2024-12-31T00:00:00Z", "2025-01-01T00:00:00Z",
                                           "2025-01-02T00:00:00Z", "2025-01-03T00:00:00Z",
                                           "2025-01-04T00:00:00Z")):
                (repo_path / "source.cpp").write_text("int x = " + str(index) + ";\n")
                subprocess.run(["git", "add", "source.cpp"], cwd=repo_path, env=env, check=True)
                commit_env = {**env, "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp}
                subprocess.run(["git", "commit", "-q", "-m", str(index)], cwd=repo_path,
                               env=commit_env, check=True)
            settings = Settings(root / "data", (root / "targets",))
            settings.initialize()
            store = Store(settings.data_dir)
            repo = store.add_repository("openharmony/recent-test", str(repo_path))
            selected = operations.recent_window_selections(settings, store, repo["id"], "HEAD", 3,
                "2025-01-05T00:00:00", "UTC")
            long_commits = selected["long_window"]["selected_commits"]
            one_day_commits = selected["one_day_window"]["selected_commits"]
            self.assertEqual(len(long_commits), 2)
            self.assertEqual(len(one_day_commits), 1)
            self.assertFalse(set(long_commits) & set(one_day_commits))
            self.assertEqual(selected["long_window"]["endpoint"], selected["one_day_window"]["baseline"])

    def test_sync_and_scan_helper_queues_a_pinned_scan_without_implicit_model_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "targets" / "repo"
            target.mkdir(parents=True)
            settings = Settings(root / "data", (root / "targets",))
            settings.initialize()
            store = Store(settings.data_dir)
            repo = store.add_repository("openharmony/sync-test", str(target))
            ops = Operations(store)
            task = ops.create("source_sync", {"scan_after_sync": True, "revision": "HEAD",
                "include_paths": ["."], "detector_ids": ["test-detector"],
                "scan_timeout_seconds": 60, "memory_mb": 512, "audit_mode": "standard_review"})
            pinned = {"commit": "b" * 40, "git_tree": "c" * 40, "plan_sha256": "d" * 64,
                "repository": repo["name"], "include_paths": ["."], "detector_ids": ["test-detector"],
                "detector_versions": {}, "audit_plan": {"plan_sha256": "d" * 64},
                "timeout_seconds": 60, "memory_mb": 512}
            with patch.object(service, "revisions", return_value=[]), \
                    patch.object(service, "make_spec", return_value=pinned):
                job = operations.enqueue_synced_scan(settings, store, ops, task, repo)
            self.assertEqual(job["status"], "queued")
            self.assertEqual(job["spec"]["commit"], "b" * 40)
            self.assertEqual(job["spec"]["audit_mode"], "standard_review")
            self.assertIsNone(store.triage_authorization(job["id"]))

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

    def test_sync_api_persists_explicit_auto_scan_request_and_defaults_to_static_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory) / "data", (Path(directory) / "targets",))
            client = TestClient(create_app(settings))
            response = client.post("/api/v1/operations/source-sync",
                headers={"X-OHScanner-Client": "workbench-v1"},
                json={"repository": "openharmony/sample", "url": "https://github.com/openharmony/sample.git",
                    "scan_after_sync": True, "revision": "HEAD", "include_paths": ["."],
                    "detector_ids": ["ohscanner.cpp.lifetime"], "audit_mode": "static_only"})
            self.assertEqual(response.status_code, 201, response.text)
            self.assertEqual(response.json()["kind"], "source_sync")
            self.assertTrue(response.json()["spec"]["scan_after_sync"])
            self.assertEqual(response.json()["spec"]["revision"], "HEAD")
            self.assertEqual(response.json()["spec"]["audit_mode"], "static_only")
            client.close()


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

    def test_branch_operation_binds_per_endpoint_model_consent_to_fixed_plans(self):
        provider = SimpleNamespace(configured=True, public={"endpoint_host": "model.example", "model": "review-model"})

        def fake_preview(plan, workflow, includes, candidate_limit, nonce, active_provider,
                         r2_limit=0, *, max_cost_usd=None):
            digest = hashlib.sha256((plan["plan_sha256"] + workflow + nonce).encode()).hexdigest()
            estimate = {"status": "budget_based_upper_estimate", "currency": "USD",
                "maximum_usd": "0.02", "rate_card_id": "test-card", "rate_source_url": "https://example.invalid/rates",
                "actual_charge_verified": False, "hard_spend_cap": False}
            return {"eligible": True, "consent_sha256": digest, "consent_nonce": nonce,
                "provider": active_provider.public,
                "manifest": {"consent_nonce": nonce,
                    "binding": {"plan_sha256": plan["plan_sha256"],
                                "workflow_sha256": workflow},
                    "source_disclosure": ["fixed source excerpts"],
                    "budgets": {"max_requests": candidate_limit * 2,
                        "r1_max_model_calls": candidate_limit, "r2_max_model_calls": 0},
                    "cost_budget": {"maximum_usd": max_cost_usd}},
                "estimated_cost": estimate, "cost_budget": {"maximum_usd": max_cost_usd}}

        base = {"repository_id": self.repo["id"], "include_paths": ["."],
            "detector_ids": self.detectors, "timeout_seconds": 30, "memory_mb": 512,
            "audit_mode": "standard_review", "auto_triage": True,
            "max_triage_candidates": 2, "max_r2_candidates": 0,
            "baseline_ref": "refs/heads/main", "endpoint_ref": "refs/heads/feature"}
        headers = {"X-OHScanner-Client": "workbench-v1"}
        with patch("src.workbench.agent.ProviderConfig.from_env", return_value=provider), \
                patch("src.workbench.agent.audit_task_consent_preview", side_effect=fake_preview):
            response = self.client.post("/api/v1/operations/scan-previews", headers=headers,
                                        json={"kind": "branches", "payload": base})
            self.assertEqual(response.status_code, 200, response.text)
            preview = response.json()["triage_authorization_preview"]
            self.assertTrue(preview["eligible"])
            self.assertEqual(len(preview["scans"]), 2)
            auths = [{key: item[key] for key in ("plan_sha256", "workflow_sha256", "consent_sha256", "consent_nonce")}
                     for item in preview["scans"]]
            submitted = self.client.post("/api/v1/operations/branch-comparisons", headers=headers,
                json={**base, "triage_authorizations": auths})
        self.assertEqual(submitted.status_code, 201, submitted.text)
        scans = [self.store.job(key) for key in submitted.json()["spec"]["scan_ids"]]
        self.assertEqual(len(scans), 2)
        for job in scans:
            authorization = self.store.triage_authorization(job["id"])
            self.assertIsNotNone(authorization)
            self.assertEqual(job["spec"]["audit_mode"], "standard_review")
            self.assertTrue(job["spec"]["workflow"]["automatic_model_calls"])
            self.assertEqual(job["spec"]["workflow"]["platform_cumulative_usage_budget"], "none")
            self.assertIsNone(job["spec"]["max_cost_usd"])
            self.assertEqual(authorization["consent_sha256"], job["spec"]["triage_authorization"]["consent_sha256"])

    def test_recent_window_endpoint_queues_four_fixed_scans_and_keeps_impact_unknown(self):
        headers = {"X-OHScanner-Client": "workbench-v1"}
        payload = {"repository_id": self.repo["id"], "branch": "refs/heads/main",
            "lookback_days": 2, "reference_time": "2025-01-04T00:00:00", "timezone": "UTC",
            "include_paths": ["."], "detector_ids": self.detectors,
            "timeout_seconds": 30, "memory_mb": 512, "audit_mode": "static_only"}
        preview = self.client.post("/api/v1/operations/recent-comparisons/preview",
            headers=headers, json=payload)
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertEqual(len(preview.json()["long_window"]["selected_commits"]), 1)
        self.assertEqual(len(preview.json()["one_day_window"]["selected_commits"]), 1)
        operation = self.client.post("/api/v1/operations/recent-comparisons",
            headers=headers, json=payload)
        self.assertEqual(operation.status_code, 201, operation.text)
        self.assertEqual(len(operation.json()["spec"]["scan_ids"]), 4)
        result = self._run_operation(operation.json())["result"]
        self.assertEqual(len(result["windows"]), 2)
        self.assertEqual([item["selected_commit_count"] for item in result["windows"]], [1, 1])
        self.assertEqual(result["impact"], "unknown")
        self.assertEqual(result["validated_vulnerability"], 0)

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
            **base, "audit_mode": "static_only", "baseline": self.commits[0], "endpoint": self.commits[1]})
        self.assertEqual(sha_range.status_code, 201, sha_range.text)
        self.assertEqual(sha_range.json()["spec"]["commits"], [self.commits[1]])
        self.assertEqual(sha_range.json()["spec"]["audit_mode"], "static_only")
        self.assertEqual([self.store.job(key)["spec"]["audit_mode"] for key in sha_range.json()["spec"]["scan_ids"]], ["static_only", "static_only"])
        range_result = self._run_operation(sha_range.json())
        self.assertEqual(range_result["result"]["baseline"], self.commits[0])
        self.assertEqual(range_result["result"]["endpoint"], self.commits[1])

        date_range = self.client.post("/api/v1/operations/date-ranges", headers=headers, json={
            **base, "audit_mode": "static_only", "branch": "HEAD",
            "start": "2025-01-02T00:00:00+00:00",
            "end": "2025-01-03T00:00:00+00:00", "timezone": "UTC"})
        self.assertEqual(date_range.status_code, 201, date_range.text)
        self.assertEqual(date_range.json()["spec"]["audit_mode"], "static_only")
        self.assertEqual([self.store.job(key)["spec"]["audit_mode"] for key in date_range.json()["spec"]["scan_ids"]], ["static_only", "static_only"])
        self.assertTrue(all(self.store.triage_authorization(key) is None
                            for key in date_range.json()["spec"]["scan_ids"]))
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
            **base, "audit_mode": "static_only", "case_id": case_id, "commits": self.commits[:2]})
        self.assertEqual(matrix.status_code, 201, matrix.text)
        self.assertEqual(matrix.json()["spec"]["commits"], self.commits[:2])
        self.assertEqual(matrix.json()["spec"]["audit_mode"], "static_only")
        self.assertEqual([self.store.job(key)["spec"]["audit_mode"] for key in matrix.json()["spec"]["scan_ids"]], ["static_only", "static_only"])
        matrix_result = self._run_operation(matrix.json())
        self.assertEqual(len(matrix_result["result"]["versions"]), 2)
        self.assertEqual(len(matrix_result["result"]["comparisons"]), 1)
        self.assertEqual(matrix_result["result"]["validated_vulnerability"], 0)

        refs = self.client.get("/api/v1/repositories/" + self.repo["id"] + "/revisions").json()
        self.assertIn("refs/heads/main", {item["ref"] for item in refs})
        self.assertIn("refs/heads/feature", {item["ref"] for item in refs})
        branch_comparison = self.client.post("/api/v1/operations/branch-comparisons", headers=headers, json={
            **base, "audit_mode": "static_only", "baseline_ref": "refs/heads/main",
            "endpoint_ref": "refs/heads/feature"})
        self.assertEqual(branch_comparison.status_code, 201, branch_comparison.text)
        branch_spec = branch_comparison.json()["spec"]
        self.assertEqual(branch_spec["audit_mode"], "static_only")
        self.assertEqual([self.store.job(key)["spec"]["audit_mode"] for key in branch_spec["scan_ids"]], ["static_only", "static_only"])
        self.assertTrue(all(self.store.triage_authorization(key) is None
                            for key in branch_spec["scan_ids"]))
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

    def test_four_operation_kinds_static_and_smart_modes_persist_through_workers(self):
        """Exercise all eight mode combinations through HTTP, scan workers and saved operations.

        Smart mode only persists endpoint authorization and queues eligible follow-up
        operations; this test never dispatches an Agent request to a Provider.
        """
        source_job = self._scan(self.commits[0])
        source_report = service.read_report(self.settings, source_job)
        candidates = service.findings(source_report)
        self.assertTrue(candidates, "fixture must provide a candidate for the version matrix case")
        case_response = self.client.post(
            "/api/v1/cases", headers={"X-OHScanner-Client": "workbench-v1"},
            json={"title": "eight-mode endpoint consent fixture", "links": [{
                "job_id": source_job["id"], "candidate_id": candidates[0]["id"],
                "rationale": "isolated operation mode acceptance fixture"}]})
        self.assertEqual(case_response.status_code, 201, case_response.text)

        base = {"repository_id": self.repo["id"], "include_paths": ["."],
                "detector_ids": self.detectors, "timeout_seconds": 30, "memory_mb": 512}
        scenarios = [
            ("date", "/api/v1/operations/date-ranges", {
                "branch": "refs/heads/main", "start": "2025-01-02T00:00:00+00:00",
                "end": "2025-01-03T00:00:00+00:00", "timezone": "UTC"}),
            ("range", "/api/v1/operations/revision-ranges", {
                "baseline": self.commits[0], "endpoint": self.commits[1]}),
            ("branches", "/api/v1/operations/branch-comparisons", {
                "baseline_ref": "refs/heads/main", "endpoint_ref": "refs/heads/feature"}),
            ("matrix", "/api/v1/operations/version-matrices", {
                "case_id": case_response.json()["id"], "commits": self.commits[:2]}),
        ]
        headers = {"X-OHScanner-Client": "workbench-v1"}
        provider_env = {
            "OHSCANNER_LLM_BASE_URL": "https://api.xiaomimimo.com/v1",
            "OHSCANNER_LLM_MODEL": "mimo-v2.6-pro",
            "OHSCANNER_LLM_API_KEY": "eight-mode-test-key",
        }
        ops = Operations(self.store)

        with patch.dict("os.environ", provider_env, clear=False):
            for kind, route, fields in scenarios:
                for audit_mode in ("static_only", "standard_review"):
                    with self.subTest(kind=kind, audit_mode=audit_mode):
                        payload = {**base, **fields, "audit_mode": audit_mode}
                        if audit_mode == "standard_review":
                            payload["auto_triage"] = True
                            preview_response = self.client.post(
                                "/api/v1/operations/intelligent-previews", headers=headers,
                                json={"kind": kind, "payload": payload})
                            self.assertEqual(preview_response.status_code, 200,
                                             preview_response.text)
                            preview = preview_response.json()
                            self.assertEqual(preview["endpoint_count"], 2, preview)
                            self.assertEqual(len({row["commit"] for row in preview["endpoints"]}), 2)
                            self.assertEqual(len({row["consent_sha256"]
                                                  for row in preview["endpoints"]}), 2)
                            payload["triage_approvals"] = [{
                                "consent_nonce": row["consent_nonce"],
                                "consent_sha256": row["consent_sha256"],
                            } for row in preview["endpoints"]]

                        created = self.client.post(route, headers=headers, json=payload)
                        self.assertEqual(created.status_code, 201, created.text)
                        operation = created.json()
                        scan_ids = operation["spec"]["scan_ids"]
                        self.assertEqual(len(scan_ids), 2)
                        scan_jobs = [self.store.job(key) for key in scan_ids]
                        self.assertEqual({job["spec"]["audit_mode"] for job in scan_jobs},
                                         {audit_mode})

                        if audit_mode == "static_only":
                            for job in scan_jobs:
                                self.assertIsNone(self.store.triage_authorization(job["id"]))
                        else:
                            saved_authorizations = [self.store.triage_authorization(job["id"])
                                                    for job in scan_jobs]
                            self.assertTrue(all(saved_authorizations))
                            self.assertEqual(len({row["consent_sha256"]
                                                  for row in saved_authorizations}), 2)
                            for job, auth in zip(scan_jobs, saved_authorizations):
                                self.assertFalse(auth["revoked"])
                                self.assertEqual(auth["snapshot"]["binding"]["plan_sha256"],
                                                 job["spec"]["plan_sha256"])
                                self.assertEqual(auth["snapshot"]["binding"]["commit"],
                                                 job["spec"]["commit"])

                        completed = self._run_operation(operation)
                        self.assertEqual(len(completed["result"]["scan_ids"]), 2)
                        for scan_id in scan_ids:
                            job = self.store.job(scan_id)
                            self.assertTrue(job["report_sha256"], scan_id)
                            self.assertIn(job["status"],
                                          {"completed", "completed_with_limitations"}, job)
                            if audit_mode == "static_only":
                                self.assertIsNone(self.store.triage_authorization(scan_id))
                                self.assertEqual(ops.triage_batches_for_job(
                                    scan_id, job["report_sha256"]), [])
                                self.assertEqual(ops.agent_investigations_for_job(
                                    scan_id, job["report_sha256"]), [])
                            else:
                                self.assertTrue(self.store.triage_authorization(scan_id))

                        detail = self.client.get(
                            "/api/v1/operations/" + operation["id"], headers=headers)
                        self.assertEqual(detail.status_code, 200, detail.text)
                        progress = detail.json()["intelligent_review_progress"]
                        self.assertEqual(len(progress), 2)
                        self.assertTrue(all(row["report_available"] for row in progress))
                        if audit_mode == "static_only":
                            self.assertTrue(all(row["agent_status"] == "static_only"
                                                and not row["agent_authorized"]
                                                for row in progress))
                        else:
                            self.assertTrue(all(row["agent_authorized"] for row in progress))
                            self.assertTrue(all(not row[
                                "model_result_is_product_vulnerability_confirmation"]
                                for row in progress))
                            # This proves authorization and static persistence, not a
                            # live Provider call. Stop queued follow-up before the next
                            # operation so no Agent worker can consume it accidentally.
                            for scan_id in scan_ids:
                                stopped = self.client.post(
                                    "/api/v1/scans/" + scan_id + "/triage/cancel",
                                    headers=headers)
                                self.assertEqual(stopped.status_code, 200, stopped.text)




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

    def test_continuous_agent_has_no_outer_deadline_and_quota_is_explicit_failure(self):
        from src.workbench.agent import ProviderQuotaError
        from src.workbench.operation_worker import (
            _commit_provider_quota_failure, _hard_deadline_seconds, _provider_quota_failure,
        )

        continuous = {"kind": "agent_investigation",
                      "spec": {"mode": "tool_agent", "continuous_investigation": True,
                               "timeout_seconds": 90}}
        bounded = {"kind": "agent_investigation",
                   "spec": {"mode": "tool_agent", "continuous_investigation": False,
                            "timeout_seconds": 90}}
        single_shot = {"kind": "agent_investigation",
                       "spec": {"mode": "single_shot", "continuous_investigation": True}}
        self.assertIsNone(_hard_deadline_seconds(continuous))
        self.assertEqual(_hard_deadline_seconds(bounded), 90)
        self.assertIsNone(_hard_deadline_seconds(single_shot))

        result = _provider_quota_failure(
            ProviderQuotaError("Provider quota or billing limit exhausted (HTTP 429; code=insufficient_quota)"))
        self.assertEqual(result["_operation_error"]["code"], "provider_quota_exhausted")
        self.assertIn("insufficient_quota", result["_operation_error"]["message"])

        class CapturingOps:
            def __init__(self):
                self.finished = None

            def finish(self, operation_id, **kwargs):
                self.finished = (operation_id, kwargs)

        ops = CapturingOps()
        self.assertTrue(_commit_provider_quota_failure(ops, {"id": "op-1", **continuous}, result))
        self.assertEqual(ops.finished, ("op-1", {
            "error": "provider_quota_exhausted: " + result["_operation_error"]["message"],
            "state": "failed",
        }))

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

    def test_authorized_smart_worker_trims_logs_without_stopping_and_accepts_large_result(self):
        task = self.ops.create("agent_investigation", {
            "job_id": "a" * 32, "report_sha256": "b" * 64,
            "smart_triage_batch_id": "c" * 32, "triage_authorization_sha256": "d" * 64,
            "no_cumulative_token_ceiling": True, "timeout_seconds": 1, "memory_mb": 512})
        claimed = self.ops.claim()
        child_result = {"status": "completed_with_limitations", "padding": "x" * (16 * 1024 * 1024 + 1)}

        class FakeChild:
            def __init__(self, command, **kwargs):
                self.returncode = None
                self.poll_count = 0
                kwargs["stdout"].write(b"diagnostic\n" * (1024 * 1024))
                kwargs["stdout"].flush()
                child_id = command[command.index("--child") + 1]
                self_result_path = self_outer.ops.directory(child_id) / "child-result.json"
                self_result_path.write_text(json.dumps(child_result))
            def poll(self):
                self.poll_count += 1
                if self.poll_count == 1:
                    return None
                self.returncode = 0
                return self.returncode

        self_outer = self
        with patch("src.workbench.operation_worker._authorized_smart_batch", return_value=True), \
             patch("src.workbench.operation_worker.subprocess.Popen", side_effect=FakeChild):
            OperationWorker(self.settings).execute(claimed)

        final = self.ops.get(task["id"])
        self.assertEqual(final["status"], "completed_with_limitations", final)
        stored = self.ops.result(task["id"])
        self.assertEqual(len(stored["padding"]), 16 * 1024 * 1024 + 1)
        log = (self.ops.directory(task["id"]) / "worker.log").read_bytes()
        self.assertIn(b"older diagnostic output trimmed", log)
        self.assertLess(len(log), 2 * 1024 * 1024)




if __name__ == "__main__":
    unittest.main()

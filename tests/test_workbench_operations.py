import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from src.workbench.api import create_app
from src.workbench.operations import approved_url, compare_reports, date_selection
from src.workbench.operations_store import Operations
from src.workbench.settings import Settings
from src.workbench.store import Store
from src.workbench import validation


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


if __name__ == "__main__":
    unittest.main()
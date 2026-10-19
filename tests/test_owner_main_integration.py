"""Independent owner checks for integration boundaries; no real model traffic."""
import os
import subprocess
import unittest
from unittest.mock import patch
from src.workbench import agent, service
from src.workbench.operations_store import Operations
from tests import test_workbench as wb

PROVIDER = {"OHSCANNER_LLM_MODEL": "owner-test-model", "OHSCANNER_LLM_API_KEY": "owner-test-key"}

class OwnerMainIntegrationTests(unittest.TestCase):
    setUp = wb.WorkbenchTests.setUp
    queue = wb.WorkbenchTests.queue

    def candidate(self):
        job = wb.WorkbenchTests.completed(self)
        report = service.read_report(self.settings, job)
        candidate = service.findings(report)[0]
        source = service.source(self.settings, self.store, job, candidate["file"])
        return job, report, candidate, source

    def test_agent_preview_carries_real_tree_and_rejects_changed_implementation(self):
        job, report, candidate, _ = self.candidate()
        payload = {"job_id": job["id"], "candidate_id": candidate["id"], "mode": "single_shot"}
        with patch.dict(os.environ, PROVIDER, clear=False):
            response = self.client.post("/api/v1/operations/agent-investigations/preview",
                                        headers=wb.HEADERS, json=payload)
            self.assertEqual(response.status_code, 200, response.text)
            preview = response.json()
            self.assertEqual(preview["binding"]["tree"], report["git_tree"])
            self.assertEqual(preview["initial_context"]["tree"], report["git_tree"])
            before = self.client.get("/api/v1/operations").json()
            with patch.object(agent, "implementation_fingerprint", return_value="0" * 64):
                response = self.client.post("/api/v1/operations/agent-investigations",
                    headers=wb.HEADERS, json={**payload, "source_submission_approved": True,
                                             "consent_sha256": preview["consent_sha256"], "consent_nonce": preview["consent_nonce"]})
            self.assertEqual(response.status_code, 409, response.text)
            self.assertEqual(self.client.get("/api/v1/operations").json(), before)

    def test_agent_git_tools_are_offline_and_ignore_dirty_source(self):
        job, report, candidate, source = self.candidate()
        tools = agent._tool_specs(self.settings, self.store, job, report, candidate, source,
                                  source["text"], (1, len(source["text"].splitlines())))
        path = self.repo / candidate["file"]
        path.write_text(path.read_text() + "\nint ProbeOnlyInDirtyWorktree = 1;\n")
        run = subprocess.run
        bounded_search = agent._run_bounded_stdout
        with patch.object(agent.subprocess, "run", wraps=run) as history_calls, \
             patch.object(agent, "_run_bounded_stdout", wraps=bounded_search) as symbol_search_calls:
            history = tools["read_fixed_git_history"]({})
            lookup = tools["lookup_symbol_in_fixed_commit"]({"symbol": "ProbeOnlyInDirtyWorktree"})
        self.assertTrue(history["entries"])
        self.assertEqual(lookup["matches"], [])
        self.assertEqual(len(history_calls.call_args_list), 1)
        self.assertEqual(len(symbol_search_calls.call_args_list), 1)
        history_call = history_calls.call_args_list[0]
        search_call = symbol_search_calls.call_args_list[0]
        self.assertEqual(history_call.kwargs["env"]["GIT_ALLOW_PROTOCOL"], "")
        self.assertEqual(history_call.kwargs["env"]["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(history_call.kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertIn(report["commit"], history_call.args[0])
        self.assertEqual(search_call.args[3]["GIT_ALLOW_PROTOCOL"], "")
        self.assertEqual(search_call.args[3]["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(search_call.args[3]["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertIn(report["commit"], search_call.args[0])

    def test_provider_status_does_not_start_automatic_batch_egress(self):
        job, _, _, _ = self.candidate()
        ops = Operations(self.store)
        with patch.dict(os.environ, PROVIDER, clear=False):
            status = self.client.get("/api/v1/operations/agent-review-queue/status").json()
        self.assertTrue(status["model_provider_configured"])
        self.assertFalse(status["automatic_batch_processing_enabled"])
        self.assertGreater(status["queued_candidates"], 0)
        self.assertIsNone(ops.claim())

    def test_v4_schema_migration_is_recorded_and_backup_preserved(self):
        Operations(self.store)
        with self.store.connect() as db:
            versions = [row[0] for row in db.execute("SELECT version FROM schema_migrations")]
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn(4, versions)
        self.assertIn("agent_baseline_reviews", tables)
        self.assertEqual(len(list((self.store.root / "backups").glob("before-v4-*.sqlite3"))), 1)

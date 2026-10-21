import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.workbench.api import create_app, AuditPlanInput
from src.workbench.operations_api import TaskTriageOptions
from src.workbench.settings import Settings
from src.workbench import agent
from src.workbench.progressive_triage.policy import (
    PolicyStore, build_policy, apply_task_candidate_scope)


class CandidateScopePolicyTests(unittest.TestCase):
    def test_new_task_defaults_are_resolved_from_policy_and_explicit_consent_is_preserved(self):
        for cls, extra in [(AuditPlanInput, {"repository_id": "r", "revision": "main"}), (TaskTriageOptions, {})]:
            body = cls(auto_triage=True, **extra)
            self.assertNotIn("max_r2_candidates", body.model_fields_set)
            apply_task_candidate_scope(body, build_policy())
            self.assertEqual((body.max_triage_candidates, body.max_r2_candidates), (30, 6))
            explicit = cls(auto_triage=True, max_triage_candidates=4, max_r2_candidates=0, **extra)
            apply_task_candidate_scope(explicit, build_policy("deep"))
            self.assertEqual((explicit.max_triage_candidates, explicit.max_r2_candidates), (4, 0))
            smaller = cls(auto_triage=True, max_triage_candidates=2, **extra)
            apply_task_candidate_scope(smaller, build_policy())
            self.assertEqual((smaller.max_triage_candidates, smaller.max_r2_candidates), (2, 2))

    def test_batch_accepts_six_rejects_seven_and_invalidates_consent_when_policy_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory), ())
            app = create_app(settings)
            repo = app.state.store.add_repository("openharmony/test", directory)
            job = app.state.store.create_job(repo["id"], {"commit": "c" * 40})
            job.update(status="completed", report_sha256="b" * 64)
            candidate = {"id": "c", "file": "src/c.cpp", "line": 1, "source_sha256": "a" * 64}
            def consent(*args, **kwargs):
                return {"agent_execution": {"eligible": True}, "consent_sha256": "d" * 64,
                    "consent_nonce": args[5]["consent_nonce"], "budgets": {"max_total_model_calls": None},
                    "binding": {"source_sha256": "a" * 64, "commit": "c" * 40, "report_sha256": "b" * 64}}
            with TestClient(app, headers={"x-ohscanner-client": "workbench-v1"}) as client, \
                    patch.dict(os.environ, {"OHSCANNER_LLM_MODEL": "test", "OHSCANNER_LLM_API_KEY": "fake-key"}), \
                    patch.object(app.state.store, "job", return_value=job), \
                    patch.object(agent.service, "read_report", return_value={"commit": "c" * 40}), \
                    patch.object(agent.service, "finding", return_value=candidate), \
                    patch.object(agent, "consent_preview", side_effect=consent):
                body = {"job_id": job["id"], "candidate_ids": [str(i) for i in range(6)], "mode": "tool_agent"}
                preview = client.post("/api/v1/operations/agent-investigations/batch/preview", json=body)
                self.assertEqual(preview.status_code, 200, preview.text)
                self.assertEqual(preview.json()["candidate_count"], 6)
                self.assertEqual(preview.json()["aggregate_budget"]["candidate_scope_limit"], 6)
                rejected = client.post("/api/v1/operations/agent-investigations/batch/preview", json={**body, "candidate_ids": [str(i) for i in range(7)]})
                self.assertEqual(rejected.status_code, 409)
                self.assertIn("6", rejected.json()["detail"])
                created = client.post("/api/v1/operations/agent-investigations/batch", json={**body,
                    "source_submission_approved": True, "consent_sha256": preview.json()["consent_sha256"],
                    "consent_nonce": preview.json()["consent_nonce"]})
                self.assertEqual(created.status_code, 201, created.text)
                self.assertEqual(created.json()["created_count"], 6)
                self.assertTrue(all(item["status"] == "queued" for item in created.json()["operations"]))
                limits = {**build_policy()["limits"], "deep_groups_per_audit": 8}
                PolicyStore(settings.data_dir).update(build_policy("custom", limits), 0)
                stale = client.post("/api/v1/operations/agent-investigations/batch", json={**body,
                    "source_submission_approved": True, "consent_sha256": preview.json()["consent_sha256"],
                    "consent_nonce": preview.json()["consent_nonce"]})
                self.assertEqual(stale.status_code, 409, stale.text)
                eight = client.post("/api/v1/operations/agent-investigations/batch/preview", json={**body, "candidate_ids": [str(i) for i in range(8)]})
                self.assertEqual(eight.status_code, 200, eight.text)
                limits["deep_groups_per_audit"] = 0
                PolicyStore(settings.data_dir).update(build_policy("custom", limits), 1)
                disabled = client.post("/api/v1/operations/agent-investigations/batch/preview", json={**body, "candidate_ids": ["0"]})
                self.assertEqual(disabled.status_code, 409)

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from pydantic import ValidationError
from src.workbench.api import create_app
from src.workbench.settings import Settings
from src.workbench.operations_api import AgentBatchInvestigationRequest, AgentPairedInvestigationRequest, _agent_policy_child_request
from src.workbench.progressive_triage.policy import PolicyStore, build_policy
from src.workbench import agent


class BatchPreviewSystemPolicyTests(unittest.TestCase):
    def test_resolved_children_preserve_all_budgets_without_relaxing_http_input(self):
        for request_type in (AgentBatchInvestigationRequest, AgentPairedInvestigationRequest):
            identity = {"job_id": "job", "mode": "tool_agent"}
            identity.update({"candidate_ids": ["candidate"]} if request_type is AgentBatchInvestigationRequest
                            else {"candidate_id": "candidate", "experiment_id": "experiment"})
            with self.assertRaises(ValidationError):
                request_type(**identity, max_output_tokens=32768)
            for cap in (32768, None):
                budgets = dict(max_output_tokens=cap, max_steps=40,
                    max_total_input_tokens=3000000, max_total_output_tokens=600000,
                    max_total_model_calls=301, timeout_seconds=20000)
                resolved = request_type(**identity).model_copy(update=budgets)
                child = _agent_policy_child_request(resolved, candidate_id="candidate", mode="tool_agent")
                for key, value in budgets.items():
                    self.assertEqual(getattr(child, key), value, key)

    def test_batch_preview_and_create_use_high_or_uncapped_system_output_for_both_modes(self):
        for cap in (32768, None):
            for mode in ("single_shot", "tool_agent"):
                with self.subTest(cap=cap, mode=mode), tempfile.TemporaryDirectory() as directory:
                    settings = Settings(Path(directory), ())
                    policies = PolicyStore(settings.data_dir)
                    policy = build_policy(request_output_tokens=cap)
                    policy["profile"] = "custom"
                    policy["limits"]["max_model_calls_per_audit"] = 301
                    policies.update(policy, 0)
                    app = create_app(settings)
                    repo = app.state.store.add_repository("openharmony/test", directory)
                    job = app.state.store.create_job(repo["id"], {"commit": "c"*40})
                    job.update(status="completed", report_sha256="b"*64)
                    report = {"repository": "openharmony/test", "commit": "c"*40}
                    candidates = {key: {"id": key, "file": key+".cpp", "line": 1, "source_sha256": "a"*64}
                                  for key in ("one", "two", "three")}
                    seen = []
                    def consent(*args, **kwargs):
                        spec = args[5]
                        seen.append(spec)
                        return {"agent_execution": {"eligible": True},
                            "consent_sha256": hashlib.sha256((spec["candidate_id"]+str(spec["max_output_tokens"])+str(spec["max_total_model_calls"])).encode()).hexdigest(),
                            "consent_nonce": spec["consent_nonce"],
                            "binding": {"source_sha256": "a"*64, "commit": "c"*40, "report_sha256": "b"*64},
                            "budgets": {"max_total_model_calls": spec["max_total_model_calls"],
                                        "max_validation_repairs": 2, "max_skeptic_calls": 1}}
                    with TestClient(app, headers={"x-ohscanner-client": "workbench-v1"}) as client, \
                         patch.dict(os.environ, {"OHSCANNER_LLM_MODEL": "test-model", "OHSCANNER_LLM_API_KEY": "fake-key"}), \
                         patch.object(app.state.store, "job", return_value=job), \
                         patch.object(agent.service, "read_report", return_value=report), \
                         patch.object(agent.service, "finding", side_effect=lambda _, key: candidates[key]), \
                         patch.object(agent, "consent_preview", side_effect=consent):
                        body = {"job_id": job["id"], "candidate_ids": list(candidates), "mode": mode}
                        response = client.post("/api/v1/operations/agent-investigations/batch/preview", json=body)
                        self.assertEqual(response.status_code, 200, response.text)
                        preview = response.json()
                        self.assertEqual(preview["candidate_count"], 3)
                        self.assertEqual(preview["aggregate_budget"]["max_output_tokens_per_provider_request"], cap)
                        self.assertEqual(preview["aggregate_budget"]["max_total_model_calls"], 903)
                        self.assertTrue(all(row["max_output_tokens"] == cap and row["max_total_model_calls"] == 301 for row in seen))
                        response = client.post("/api/v1/operations/agent-investigations/batch", json={**body,
                            "source_submission_approved": True, "consent_sha256": preview["consent_sha256"],
                            "consent_nonce": preview["consent_nonce"]})
                        self.assertEqual(response.status_code, 201, response.text)
                        operations = response.json()["operations"]
                        self.assertEqual(len(operations), 3)
                        for item in operations:
                            self.assertEqual(item["spec"]["max_output_tokens"], cap)
                            self.assertEqual(item["spec"]["max_total_model_calls"], 301)

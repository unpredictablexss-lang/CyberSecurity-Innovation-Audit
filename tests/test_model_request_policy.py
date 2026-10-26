import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.workbench.api import create_app
from src.workbench.settings import Settings
from src.workbench import agent
from src.workbench.progressive_triage.policy import PolicyStore, build_policy, policy_envelope
from tests import test_agent_workflow as workflow_tests


class ModelRequestPolicyTests(unittest.TestCase):
    def test_legacy_policy_hash_and_uncapped_setting_round_trip(self):
        legacy = build_policy()
        self.assertNotIn("request_output_tokens", legacy)
        self.assertEqual(policy_envelope(legacy)["policy"], legacy)
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory), ())
            with TestClient(create_app(settings)) as client:
                payload = {"expected_revision": 0, "profile": "standard", "request_output_tokens": None}
                updated = client.put("/api/v1/agent/triage-policy", json=payload,
                    headers={"x-ohscanner-client": "workbench-v1"})
                self.assertEqual(updated.status_code, 200, updated.text)
                self.assertIsNone(updated.json()["policy"]["request_output_tokens"])
                self.assertIsNone(agent.ProviderConfig.from_env(Path(directory)).request_output_tokens)
                self.assertEqual(client.put("/api/v1/agent/triage-policy", json=payload,
                    headers={"x-ohscanner-client": "workbench-v1"}).status_code, 409)
                invalid = client.put("/api/v1/agent/triage-policy",
                    json={**payload, "expected_revision": 1, "request_output_tokens": True},
                    headers={"x-ohscanner-client": "workbench-v1"})
                self.assertEqual(invalid.status_code, 422)
                legacy_profile_change = client.put("/api/v1/agent/triage-policy",
                    json={"expected_revision": 1, "profile": "economical"},
                    headers={"x-ohscanner-client": "workbench-v1"})
                self.assertEqual(legacy_profile_change.status_code, 200, legacy_profile_change.text)
                self.assertIsNone(legacy_profile_change.json()["policy"]["request_output_tokens"])

    def test_all_agent_stages_omit_cap_when_explicitly_uncapped(self):
        result, client, preview = workflow_tests.CandidateArtifactGenerationTests()._run(
            "likely_true_positive", uncapped_output=True)
        self.assertIsNone(preview["budgets"]["max_output_tokens_per_request"])
        self.assertIsNone(result["model_usage"]["per_request_output_limit_tokens"])
        self.assertEqual(result["artifact_generation"]["status"], "completed")
        self.assertTrue(client.payloads)
        self.assertTrue(all("max_output_tokens" not in payload for payload in client.payloads))
        phases = [row["request_phase"] for row in result["model_calls"]]
        self.assertIn("tool_call", phases)
        self.assertIn("structured_output", phases)
        self.assertIn("skeptic_review", phases)
        self.assertIn("artifact_generation", phases)

    def test_api_preview_and_queued_spec_use_only_global_setting(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory), ())
            store = PolicyStore(settings.data_dir)
            store.update(build_policy(request_output_tokens=None), 0)
            app = create_app(settings)
            repo = app.state.store.add_repository("openharmony/test", str(Path(directory)))
            job = app.state.store.create_job(repo["id"], {"commit": "c" * 40})
            job.update(status="completed", report_sha256="b" * 64)
            report = {"repository": "openharmony/test", "commit": "c" * 40}
            candidate = {"id": "candidate", "source_sha256": "a" * 64}
            seen = []
            def consent(*args, **kwargs):
                seen.append(args[5])
                return {"agent_execution": {"eligible": True}, "consent_sha256": "d" * 64, "consent_nonce": args[5]["consent_nonce"]}
            with TestClient(app, headers={"x-ohscanner-client": "workbench-v1"}) as client, \
                    patch.dict(os.environ, {"OHSCANNER_LLM_MODEL": "test-model", "OHSCANNER_LLM_API_KEY": "fake-key"}), \
                    patch.object(app.state.store, "job", return_value=job), \
                    patch.object(agent.service, "read_report", return_value=report), \
                    patch.object(agent.service, "finding", return_value=candidate), \
                    patch.object(agent, "consent_preview", side_effect=consent):
                body = {"job_id": job["id"], "candidate_id": "candidate", "mode": "tool_agent"}
                preview = client.post("/api/v1/operations/agent-investigations/preview", json=body)
                self.assertEqual(preview.status_code, 200, preview.text)
                value = preview.json()
                queued = client.post("/api/v1/operations/agent-investigations", json={**body,
                    "source_submission_approved": True, "consent_sha256": value["consent_sha256"],
                    "consent_nonce": value["consent_nonce"]})
                self.assertEqual(queued.status_code, 201, queued.text)
                self.assertIsNone(queued.json()["spec"]["max_output_tokens"])
                self.assertTrue(all(spec["max_output_tokens"] is None for spec in seen))
                override = client.post("/api/v1/operations/agent-investigations/preview",
                    json={**body, "max_output_tokens": 1200})
                self.assertEqual(override.status_code, 409)
                store.update(build_policy(request_output_tokens=32768), 1)
                high_preview = client.post("/api/v1/operations/agent-investigations/preview",
                    json={**body, "mode": "single_shot"})
                self.assertEqual(high_preview.status_code, 200, high_preview.text)
                self.assertEqual(seen[-1]["max_output_tokens"], 32768)
                self.assertGreaterEqual(seen[-1]["max_total_output_tokens"], 32768)

    def test_l2_respects_new_output_policy_without_changing_legacy_default(self):
        from tests import test_progressive_triage as triage_tests
        from src.workbench.progressive_triage.quick_screen import run_quick_screen
        fixture = triage_tests.QuickScreenTests()
        fixture.setUp()
        class Provider:
            def __init__(self): self.payloads = []
            def create(self, payload, **kwargs):
                self.payloads.append(payload)
                response = fixture.response()
                response["usage"]["output_tokens"] = 600
                return response
        for cap in [5000, None]:
            with self.subTest(cap=cap):
                provider = Provider()
                result = run_quick_screen(provider, fixture.group, fixture.evidence,
                    fixture.authorization, provider_fingerprint=fixture.provider_fingerprint,
                    model=fixture.model, max_output_tokens=cap)
                self.assertEqual(result["state"], "completed")
                self.assertEqual(result["usage"]["output_tokens"], 600)
                if cap is None: self.assertNotIn("max_output_tokens", provider.payloads[0])
                else: self.assertEqual(provider.payloads[0]["max_output_tokens"], cap)
        legacy = Provider()
        self.assertEqual(run_quick_screen(legacy, fixture.group, fixture.evidence,
            fixture.authorization, provider_fingerprint=fixture.provider_fingerprint,
            model=fixture.model)["state"], "quick_unknown")
        self.assertEqual(legacy.payloads[0]["max_output_tokens"], 512)

    def test_validator_failure_codes_name_the_actual_contract_failure(self):
        self.assertEqual(agent._validation_error_code(ValueError(
            "supported claim must contain bounded obligation mappings and evidence citations")), "invalid_claim_structure")
        self.assertEqual(agent._validation_error_code(ValueError(
            "model must review every supplied evidence obligation exactly once")), "incomplete_obligation_reviews")
        self.assertEqual(agent._validation_error_code(ValueError("private model prose")), "server_validation_rejected")

    def test_l2_operation_transport_and_ledger_use_frozen_request_cap(self):
        import json
        from types import SimpleNamespace
        from tests import test_progressive_triage as triage_tests
        from src.workbench.progressive_triage.contracts import content_sha256
        from src.workbench.progressive_triage.policy import build_policy, policy_envelope
        from src.workbench.progressive_triage.quick_screen_operation import execute_quick_screen
        for cap in [5000, None]:
            fixture, task = triage_tests.QuickScreenOperationTests()._task()
            config = agent.ProviderConfig("https://api.xiaomimimo.com/v1", fixture.model,
                "fake-test-key", request_output_tokens=cap)
            spec = task["spec"]
            policy = build_policy(request_output_tokens=cap)
            policy_sha256 = policy_envelope(policy)["policy_sha256"]
            spec["progressive_policy"].update(policy=policy, policy_sha256=policy_sha256)
            spec["consent_manifest"].update(provider_fingerprint=config.fingerprint,
                request_output_tokens=cap, policy=policy, policy_sha256=policy_sha256)
            digest = content_sha256(spec["consent_manifest"])
            spec["consent_sha256"] = digest
            spec["authorization"].update(provider_fingerprint=config.fingerprint, consent_sha256=digest)
            calls = []
            class Response:
                status = 200
                def __enter__(self): return self
                def __exit__(self, *_): return False
                def read(self, _limit):
                    value = fixture.response()
                    value["usage"]["output_tokens"] = 600
                    return json.dumps(value).encode()
            class Opener:
                def open(self, request, **kwargs):
                    calls.append(json.loads(request.data))
                    return Response()
            with tempfile.TemporaryDirectory() as directory, \
                    patch.object(agent.ProviderConfig, "from_env", return_value=config), \
                    patch.object(agent, "build_opener", return_value=Opener()):
                result = execute_quick_screen(SimpleNamespace(data_dir=Path(directory)), task)
            self.assertEqual(result["state"], "completed", result)
            self.assertEqual(result["quick_screen"]["usage"]["output_tokens"], 600)
            if cap is None: self.assertNotIn("max_output_tokens", calls[0])
            else: self.assertEqual(calls[0]["max_output_tokens"], cap)

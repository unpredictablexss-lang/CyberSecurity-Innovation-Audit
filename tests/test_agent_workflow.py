import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from src.workbench import agent
from src.workbench.api import create_app
from src.workbench.settings import Settings
from src.workbench.operations_store import Operations
from src.workbench.operation_worker import OperationWorker
from src.workbench.store import Store
from src.workbench import operations


def bind_test_consent(task, store, report, candidate, source):
    spec = task["spec"]
    provider = agent.ProviderConfig.from_env()
    job = store.job(spec["job_id"])
    with patch.object(agent.service, "source", return_value=source):
        preview = agent.consent_preview(None, store, job, report, candidate, spec, provider)
    spec["source_consent_sha256"] = preview["consent_sha256"]
    spec["consent_preview_version"] = agent.CONSENT_PREVIEW_VERSION


class SensitiveDataRedactionTests(unittest.TestCase):
    def test_common_credential_patterns_are_removed_and_categories_reported(self):
        raw = {
            "aws": "AKIA1234567890ABCDEF",
            "github": "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
            "bearer": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
            "assignment": json.dumps({"api_key": "secret-value-123456789"}),
            "pem": "-----BEGIN PRIVATE KEY-----\nFAKE-PRIVATE-MATERIAL\n-----END PRIVATE KEY-----",
        }
        clean, categories = agent._redact_sensitive_data(raw)
        encoded = json.dumps(clean)
        self.assertNotIn("secret-value-123456789", encoded)
        for value in raw.values():
            self.assertNotIn(value, encoded)
        self.assertIn("REDACTED_SECRET", encoded)
        self.assertEqual(set(categories), {"cloud_access_key", "provider_or_source_token",
            "bearer_token", "credential_assignment", "private_key"})


class ProviderConfigTests(unittest.TestCase):
    def test_endpoint_requires_https_without_credentials_or_custom_port(self):
        for value in ("http://api.example/v1", "https://user:pass@api.example/v1",
                      "https://api.example:8443/v1", "https://api.example/v1?token=x"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                agent.validate_base_url(value)

    def test_api_key_control_characters_fail_without_echoing_secret(self):
        secret = "key-do-not-leak\r\nAuthorization: injected"
        with patch.dict(os.environ, {"OHSCANNER_LLM_MODEL": "review", "OHSCANNER_LLM_API_KEY": secret}, clear=False):
            with self.assertRaisesRegex(ValueError, "invalid LLM API key format") as caught:
                agent.ProviderConfig.from_env()
        self.assertNotIn(secret, str(caught.exception))

    def test_provider_http_error_body_never_reaches_operation_error(self):
        from urllib.error import HTTPError
        config = agent.ProviderConfig("https://api.openai.com/v1", "review", "secret-value")
        client = agent.ResponsesClient(config)
        error = HTTPError("https://api.openai.com/v1/responses", 429, "rate limited", {}, io.BytesIO(b"secret-value echoed"))
        with patch.object(client.opener, "open", side_effect=error):
            with self.assertRaisesRegex(ValueError, "HTTP 429") as caught:
                client.create({"model": "review"})
        self.assertNotIn("secret-value", str(caught.exception))

    def test_redirect_handler_blocks_credential_forwarding(self):
        from urllib.error import URLError
        from urllib.request import Request
        handler = agent._NoRedirect()
        with self.assertRaisesRegex(URLError, "redirects are disabled"):
            handler.redirect_request(Request("https://api.openai.com"), None, 302, "found", {}, "https://other.example")

    def test_status_is_safe_when_provider_is_unconfigured(self):
        with patch.dict(os.environ, {"OHSCANNER_LLM_MODEL": "", "OHSCANNER_LLM_API_KEY": ""}, clear=False):
            status = agent.public_status()
        self.assertFalse(status["configured"])
        self.assertEqual(set(status["missing"]), {"OHSCANNER_LLM_MODEL", "OHSCANNER_LLM_API_KEY"})
        self.assertNotIn("secret-value", json.dumps(status))


class AgentExecutionTests(unittest.TestCase):
    def test_fake_model_gets_fixed_readonly_evidence_and_never_promotes_candidate(self):
        candidate = {
            "id": "candidate-1", "file": "src/vulnerable.cpp", "line": 8,
            "source_sha256": "a" * 64, "symbol": "run", "detector_id": "test.rule",
            "detector_version": "0.1", "rule_id": "R1", "cwe": "CWE-000",
            "evidence": {"analysis_status": "complete", "obligations": ["reachability unknown"]},
        }
        class Store:
            def job(self, key):
                return {"id": key, "repository_id": "repo-1", "status": "completed",
                        "report_sha256": "b" * 64}
            def repository(self, key):
                return {"id": key, "path": "/fixed/repository"}
        class Ops:
            def __init__(self): self.events = []
            def get(self, key): return {"cancel_requested": False}
            def event(self, *args): self.events.append(args)
        class FakeClient:
            def __init__(self): self.payloads = []
            def create(self, payload):
                self.payloads.append(payload)
                if len(self.payloads) == 1:
                    return {"status": "completed", "output": [{"type": "function_call",
                        "name": "read_candidate_source", "arguments": "{}", "call_id": "call-1"}],
                        "usage": {"input_tokens": 22, "output_tokens": 4, "total_tokens": 26}}
                if len(self.payloads) == 2:
                    return {"status": "completed", "output": [{"type": "message", "content": [
                        {"type": "output_text", "text": "I will inspect the evidence and remain cautious."}]}],
                        "usage": {"input_tokens": 31, "output_tokens": 5, "total_tokens": 36}}
                evidence_item = next(item for item in reversed(payload["input"]) if item.get("type") == "function_call_output")
                evidence_id = json.loads(evidence_item["output"])["evidence_id"]
                final = {"summary": "Evidence is incomplete.", "assessment": "needs_more_evidence",
                    "supported_claims": [{"claim": "The fixed source excerpt was reviewed.", "citations": [{"evidence_id": evidence_id, "quote": "dangerous();"}]}],
                    "unsupported_claims": ["Exploitability is not established."],
                    "unknowns": ["Reachability and impact"], "next_steps": ["Human review"]}
                return {"status": "completed", "output": [{"type": "message", "content": [
                    {"type": "output_text", "text": json.dumps(final)}]}],
                    "usage": {"input_tokens": 40, "output_tokens": 50, "total_tokens": 90}}
        report = {"repository": "openharmony/sample", "commit": "c" * 40,
                  "tree": "d" * 40, "snapshot_sha256": "e" * 64}
        source = {"sha256": "a" * 64, "blob": "f" * 40,
                  "text": "int run() {\n  dangerous();\n  return 0;\n}\n// AKIA1234567890ABCDEF\n"}
        task = {"id": "task-1", "spec": {"job_id": "job-1", "candidate_id": "candidate-1",
            "max_steps": 3, "max_output_tokens": 500, "max_total_input_tokens": 24000,
            "max_total_output_tokens": 1000,
            "timeout_seconds": 90, "source_submission_approved": True,
            "provider_fingerprint": "unused", "prompt_version": agent.PROMPT_VERSION,
            "tool_policy_version": agent.TOOL_POLICY_VERSION}}
        with patch.dict(os.environ, {"OHSCANNER_LLM_MODEL": "test-model", "OHSCANNER_LLM_API_KEY": "test-secret"}, clear=False):
            config = agent.ProviderConfig.from_env()
            task["spec"]["provider_fingerprint"] = config.fingerprint
            fake = FakeClient()
            bind_test_consent(task, Store(), report, candidate, source)
            with patch.object(agent.service, "read_report", return_value=report), \
                 patch.object(agent.service, "finding", return_value=candidate), \
                 patch.object(agent.service, "source", return_value=source):
                result = agent.execute_agent(None, Store(), Ops(), task, client=fake)
        self.assertEqual(result["vulnerability_state"], "candidate")
        self.assertEqual(result["validated_vulnerability"], 0)
        self.assertEqual(result["agent_assessment"]["assessment"], "needs_more_evidence")
        self.assertEqual(result["binding"]["commit"], "c" * 40)
        self.assertEqual(result["tool_calls"][0]["tool"], "read_candidate_source")
        self.assertNotIn("AKIA1234567890ABCDEF", json.dumps(fake.payloads))
        self.assertIn("cloud_access_key", result["initial_evidence"]["sensitive_redactions"])
        self.assertNotIn("AKIA1234567890ABCDEF", json.dumps(result["tool_calls"]))
        self.assertEqual(len(fake.payloads), 3)
        self.assertEqual(result["model_usage"]["output_tokens"], 59)
        self.assertTrue(result["model_usage"]["input_usage_complete"])
        self.assertTrue(all(payload["store"] is False for payload in fake.payloads))
        self.assertEqual(fake.payloads[-1]["text"]["format"]["type"], "json_schema")
        self.assertNotIn("test-secret", json.dumps(result))


class AgentRouteTests(unittest.TestCase):
    def test_unconfigured_model_rejects_enqueue_and_status_discloses_no_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(root / "data", (root / "targets",))
            app = create_app(settings)
            with TestClient(app) as client, patch.dict(os.environ, {
                "OHSCANNER_LLM_MODEL": "", "OHSCANNER_LLM_API_KEY": ""}, clear=False):
                status = client.get("/api/v1/agent/status")
                self.assertEqual(status.status_code, 200)
                self.assertFalse(status.json()["configured"])
                response = client.post("/api/v1/operations/agent-investigations", headers={
                    "x-ohscanner-client": "workbench-v1"}, json={"job_id": "x", "candidate_id": "y"})
                self.assertEqual(response.status_code, 503)
                self.assertEqual(client.get("/api/v1/operations").json(), [])


    def test_configured_model_still_requires_per_request_source_consent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(root / "data", (root / "targets",))
            app = create_app(settings)
            with TestClient(app) as client, patch.dict(os.environ, {
                "OHSCANNER_LLM_MODEL": "review-model", "OHSCANNER_LLM_API_KEY": "test-secret"}, clear=False):
                response = client.post("/api/v1/operations/agent-investigations", headers={
                    "x-ohscanner-client": "workbench-v1"},
                    json={"job_id": "not-read-before-consent", "candidate_id": "candidate-1"})
                self.assertEqual(response.status_code, 428)
                self.assertIn("api.openai.com", response.json()["detail"])
                no_preview = client.post("/api/v1/operations/agent-investigations", headers={
                    "x-ohscanner-client": "workbench-v1"},
                    json={"job_id": "not-read-before-consent", "candidate_id": "candidate-1",
                          "source_submission_approved": True})
                self.assertEqual(no_preview.status_code, 428)
                self.assertIn("预览指纹", no_preview.json()["detail"])
                self.assertEqual(client.get("/api/v1/operations").json(), [])


    def test_explicit_consent_queues_only_sanitized_fixed_candidate_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(root / "data", (root / "targets",))
            app = create_app(settings)
            repo = app.state.store.add_repository("openharmony/sample", str(root))
            with app.state.store.connect() as db:
                db.execute("INSERT INTO jobs(id,repository_id,spec,status,stage,created_at) VALUES(?,?,?,?,?,?)",
                           ("job-1", repo["id"], "{}", "completed", "complete", "2026-10-18T00:00:00Z"))
            job = {"id": "job-1", "repository_id": repo["id"], "status": "completed",
                   "report_sha256": "b" * 64}
            report = {"repository": "openharmony/sample", "commit": "c" * 40}
            candidate = {"id": "candidate-1", "file": "src/sample.cpp", "line": 1,
                         "source_sha256": "a" * 64, "evidence": {"obligations": ["review reachability"]}}
            source = {"sha256": "a" * 64, "blob": "f" * 40, "text": "int check() {}"}
            with TestClient(app) as client, patch.dict(os.environ, {
                "OHSCANNER_LLM_MODEL": "review-model", "OHSCANNER_LLM_API_KEY": "test-secret"}, clear=False), \
                 patch.object(app.state.store, "job", return_value=job), \
                 patch("src.workbench.operations_api.service.read_report", return_value=report), \
                 patch("src.workbench.operations_api.service.finding", return_value=candidate), \
                 patch("src.workbench.operations_api.service.source", return_value=source):
                preview_payload = {"job_id": "job-1", "candidate_id": "candidate-1",
                                   "experiment_id": "paired-test-1", "mode": "single_shot",
                                   "source_submission_approved": False}
                preview_response = client.post("/api/v1/operations/agent-investigations/preview",
                    headers={"x-ohscanner-client": "workbench-v1"}, json=preview_payload)
                self.assertEqual(preview_response.status_code, 200, preview_response.text)
                preview = preview_response.json()
                without_r0 = client.post("/api/v1/operations/agent-investigations", headers={
                    "x-ohscanner-client": "workbench-v1"}, json={**preview_payload,
                    "source_submission_approved": True, "consent_sha256": preview["consent_sha256"]})
                self.assertEqual(without_r0.status_code, 409)
                self.assertIn("R0", without_r0.json()["detail"])
                self.assertEqual(client.get("/api/v1/operations").json(), [])
                baseline_response = client.post("/api/v1/agent/baseline-reviews", headers={
                    "x-ohscanner-client": "workbench-v1"}, json={
                    "job_id": "job-1", "candidate_id": "candidate-1", "experiment_id": "paired-test-1",
                    "reviewer": "reviewer-r0", "disposition": "investigate", "elapsed_seconds": 75,
                    "notes": "Static-only triage before seeing any model output."})
                self.assertEqual(baseline_response.status_code, 201, baseline_response.text)
                self.assertEqual(baseline_response.json()["review_scope"], "static_only_r0_triage")
                self.assertEqual(baseline_response.json()["vulnerability_state"], "candidate")
                self.assertEqual(len(client.get("/api/v1/agent/evaluation-summary").json()["r0_baseline_reviews"]), 1)
                self.assertEqual(preview["initial_context"]["source_excerpt"], "int check() {}")
                self.assertEqual(preview["binding"]["commit"], "c" * 40)
                self.assertNotIn("test-secret", json.dumps(preview))
                stale = client.post("/api/v1/operations/agent-investigations", headers={
                    "x-ohscanner-client": "workbench-v1"},
                    json={**preview_payload, "source_submission_approved": True,
                          "consent_sha256": preview["consent_sha256"], "timeout_seconds": 180})
                self.assertEqual(stale.status_code, 409)
                self.assertEqual(client.get("/api/v1/operations").json(), [])
                mismatch_case = app.state.store.create_case("wrong candidate", [{
                    "job_id": "job-1", "candidate_id": "candidate-other", "rationale": "test"}])
                wrong = client.post("/api/v1/operations/agent-investigations", headers={
                    "x-ohscanner-client": "workbench-v1"},
                    json={**preview_payload, "case_id": mismatch_case,
                          "source_submission_approved": True, "consent_sha256": preview["consent_sha256"]})
                self.assertEqual(wrong.status_code, 409)
                self.assertEqual(client.get("/api/v1/operations").json(), [])
                case_id = app.state.store.create_case("linked candidate", [{
                    "job_id": "job-1", "candidate_id": "candidate-1", "rationale": "test"}])
                response = client.post("/api/v1/operations/agent-investigations", headers={
                    "x-ohscanner-client": "workbench-v1"},
                    json={**preview_payload, "case_id": case_id,
                          "source_submission_approved": True, "consent_sha256": preview["consent_sha256"]})
                self.assertEqual(response.status_code, 201, response.text)
                late_baseline = client.post("/api/v1/agent/baseline-reviews", headers={
                    "x-ohscanner-client": "workbench-v1"}, json={
                    "job_id": "job-1", "candidate_id": "candidate-1", "experiment_id": "paired-test-1",
                    "reviewer": "late-reviewer", "disposition": "unknown"})
                self.assertEqual(late_baseline.status_code, 409)
                self.assertIn("before any LLM", late_baseline.json()["detail"])
                plan = response.json()["spec"]
                self.assertEqual(plan["source_commit"], "c" * 40)
                self.assertEqual(plan["report_sha256"], "b" * 64)
                self.assertEqual(plan["mode"], "single_shot")
                self.assertEqual(plan["experiment_id"], "paired-test-1")
                self.assertEqual(plan["case_id"], case_id)
                self.assertEqual(plan["prompt_version"], agent.PROMPT_VERSION)
                self.assertEqual(plan["tool_policy_version"], agent.TOOL_POLICY_VERSION)
                self.assertTrue(plan["source_submission_approved"])
                self.assertEqual(plan["source_consent_sha256"], preview["consent_sha256"])
                self.assertEqual(plan["consent_preview_version"], agent.CONSENT_PREVIEW_VERSION)
                self.assertNotIn("test-secret", json.dumps(plan))
                self.assertNotIn("api_key", plan)
                claimed = Operations(app.state.store).claim()
                self.assertEqual(claimed["kind"], "agent_investigation")
                self.assertEqual(claimed["spec"]["mode"], "single_shot")
                self.assertNotIn("test-secret", json.dumps(claimed["spec"]))


    def test_fake_provider_end_to_end_api_queue_dispatch_result_and_audit_events(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(root / "data", (root / "targets",))
            app = create_app(settings)
            store = app.state.store
            repo = store.add_repository("openharmony/sample", str(root))
            with store.connect() as db:
                db.execute("INSERT INTO jobs(id,repository_id,spec,status,stage,created_at) VALUES(?,?,?,?,?,?)",
                           ("job-1", repo["id"], "{}", "completed", "complete", "2026-10-18T00:00:00Z"))
            case_id = store.create_case("synthetic candidate", [{
                "job_id": "job-1", "candidate_id": "candidate-1", "rationale": "fixture"}])
            job = {"id": "job-1", "repository_id": repo["id"], "status": "completed",
                   "report_sha256": "b" * 64}
            report = {"repository": "openharmony/sample", "commit": "c" * 40,
                      "tree": "d" * 40, "snapshot_sha256": "e" * 64}
            candidate = {"id": "candidate-1", "file": "src/sample.cpp", "line": 2,
                         "source_sha256": "a" * 64, "symbol": "check",
                         "detector_id": "test.rule", "detector_version": "1",
                         "rule_id": "R1", "evidence": {"analysis_status": "partial",
                                                       "obligations": ["reachability unknown"]}}
            source = {"sha256": "a" * 64, "blob": "f" * 40,
                      "text": "void check() {\n  guarded_call();\n}\n"}
            class FakeClient:
                def create(self, payload):
                    context = json.loads(payload["input"][0]["content"][0]["text"])
                    final = {"summary": "Synthetic candidate needs human review.",
                        "assessment": "needs_more_evidence",
                        "supported_claims": [{"claim": "The source is bound to this candidate.",
                                              "citations": [{"evidence_id": context["evidence_id"], "quote": "guarded_call();"}]}],
                        "unsupported_claims": [], "unknowns": ["Product reachability"],
                        "next_steps": ["Human review"]}
                    return {"status": "completed", "output": [{"type": "message", "content": [
                        {"type": "output_text", "text": json.dumps(final)}]}],
                        "usage": {"input_tokens": 321, "output_tokens": 55, "total_tokens": 376}}
            headers = {"x-ohscanner-client": "workbench-v1"}
            ops = Operations(store)
            with TestClient(app) as client, patch.dict(os.environ, {
                "OHSCANNER_LLM_BASE_URL": "https://api.openai.com/v1",
                "OHSCANNER_LLM_MODEL": "synthetic-test-model",
                "OHSCANNER_LLM_API_KEY": "synthetic-no-network-key"}, clear=False), \
                 patch.object(store, "job", return_value=job), \
                 patch.object(agent.service, "read_report", return_value=report), \
                 patch.object(agent.service, "finding", return_value=candidate), \
                 patch.object(agent.service, "source", return_value=source), \
                 patch.object(agent, "ResponsesClient", return_value=FakeClient()):
                request_body = {"job_id": "job-1", "candidate_id": "candidate-1",
                    "case_id": case_id, "mode": "single_shot", "source_submission_approved": False}
                preview_response = client.post("/api/v1/operations/agent-investigations/preview",
                    headers=headers, json=request_body)
                self.assertEqual(preview_response.status_code, 200, preview_response.text)
                consent_sha256 = preview_response.json()["consent_sha256"]
                response = client.post("/api/v1/operations/agent-investigations",
                    headers=headers, json={**request_body, "source_submission_approved": True,
                                           "consent_sha256": consent_sha256})
                self.assertEqual(response.status_code, 201, response.text)
                operation_id = response.json()["id"]
                task = ops.claim()
                self.assertEqual(task["id"], operation_id)
                result = operations.execute(settings, store, ops, task)
                ops.finish(operation_id, result)
                detail = client.get("/api/v1/operations/" + operation_id)
                self.assertEqual(detail.status_code, 200)
                body = detail.json()
                self.assertEqual(body["status"], "completed_with_limitations")
                self.assertEqual(body["result"]["vulnerability_state"], "candidate")
                self.assertEqual(body["result"]["validated_vulnerability"], 0)
                self.assertEqual(body["result"]["model_usage"]["total_tokens"], 376)
                self.assertEqual(body["result"]["case_id"], case_id)
                self.assertEqual(body["result"]["source_submission"]["consent_sha256"], consent_sha256)
                self.assertEqual(body["result"]["agent_assessment"]["assessment"], "needs_more_evidence")
                self.assertTrue(any(event["stage"] == "agent_model_call" for event in body["events"]))
                self.assertTrue(body["result_sha256"])
                self.assertNotIn("synthetic-no-network-key", json.dumps(body))
                blank_reviewer = client.post("/api/v1/operations/" + operation_id + "/agent-reviews",
                    headers=headers, json={"reviewer": "   ", "usefulness": "useful",
                    "citation_accuracy": "not_checked"})
                self.assertEqual(blank_reviewer.status_code, 409)
                review_response = client.post("/api/v1/operations/" + operation_id + "/agent-reviews",
                    headers=headers, json={"reviewer": "reviewer-1", "usefulness": "partially_useful",
                    "citation_accuracy": "all_accurate", "elapsed_seconds": 82,
                    "claims_to_correct": "", "missed_evidence": "Product permission boundary",
                    "notes": "Synthetic feedback only."})
                self.assertEqual(review_response.status_code, 201, review_response.text)
                review = review_response.json()
                self.assertEqual(review["result_sha256"], body["result_sha256"])
                self.assertEqual(review["binding"]["candidate_id"], "candidate-1")
                self.assertEqual(review["review_scope"], "model_triage_quality_only")
                body_after_review = client.get("/api/v1/operations/" + operation_id).json()
                self.assertEqual(body_after_review["result_sha256"], body["result_sha256"])
                self.assertEqual(body_after_review["result"]["vulnerability_state"], "candidate")
                self.assertEqual(len(body_after_review["agent_reviews"]), 1)
                evaluation = client.get("/api/v1/agent/evaluation-summary").json()
                self.assertEqual(evaluation["scope"], "operator_feedback_only")
                self.assertFalse(evaluation["accuracy_claim"])
                self.assertEqual(len(evaluation["groups"]), 1)
                self.assertEqual(evaluation["groups"][0]["review_count"], 1)
                self.assertEqual(evaluation["groups"][0]["median_elapsed_seconds"], 82)
                second_review = client.post("/api/v1/operations/" + operation_id + "/agent-reviews",
                    headers=headers, json={"reviewer": "reviewer-2", "usefulness": "unsafe",
                    "citation_accuracy": "some_incorrect", "elapsed_seconds": 10})
                self.assertEqual(second_review.status_code, 201, second_review.text)
                self.assertEqual(len(client.get("/api/v1/operations/" + operation_id).json()["agent_reviews"]), 2)
                evaluation = client.get("/api/v1/agent/evaluation-summary").json()
                self.assertEqual(evaluation["groups"][0]["review_count"], 2)
                self.assertEqual(evaluation["groups"][0]["usefulness"]["unsafe"], 1)
                self.assertEqual(evaluation["groups"][0]["median_elapsed_seconds"], 46)
                report_json = client.get("/api/v1/cases/" + case_id + "/report.json")
                self.assertEqual(report_json.status_code, 200, report_json.text)
                summaries = report_json.json()["operations"]
                self.assertEqual(len(summaries), 1)
                self.assertTrue(summaries[0]["agent_triage"]["triage_only"])
                triage = summaries[0]["agent_triage"]
                self.assertEqual(triage["assessment"], "needs_more_evidence")
                self.assertEqual(triage["vulnerability_state"], "candidate")
                cited = [citation["evidence_id"] for claim in triage["supported_claims"] for citation in claim["citations"]]
                self.assertIn(triage["initial_evidence"]["evidence_id"], cited)
                self.assertEqual(triage["supported_claims"][0]["citations"][0]["quote"], "guarded_call();")
                self.assertEqual(triage["binding"]["commit"], "c" * 40)
                self.assertEqual(len(triage["human_reviews"]), 2)
                self.assertEqual(triage["human_reviews"][0]["usefulness"], "partially_useful")
                report_md = client.get("/api/v1/cases/" + case_id + "/report.md")
                self.assertEqual(report_md.status_code, 200, report_md.text)
                self.assertIn("Agent 分诊建议（非漏洞确认）", report_md.text)
                self.assertIn("Token：输入 321 / 输出 55", report_md.text)
                self.assertIn("授权预览 SHA-256", report_md.text)
                self.assertIn(consent_sha256, report_md.text)
                self.assertIn("支持陈述：", report_md.text)
                self.assertIn("guarded_call();", report_md.text)
                self.assertIn("人工评价", report_md.text)
                self.assertIn("Product permission boundary", report_md.text)

    def test_agent_review_is_rejected_before_a_completed_agent_result_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(root / "data", (root / "targets",))
            app = create_app(settings)
            ops = Operations(app.state.store)
            agent_task = ops.create("agent_investigation", {"job_id": "j", "candidate_id": "c"})
            ordinary_task = ops.create("investigation", {"job_id": "j", "candidate_id": "c"})
            record = {"reviewer": "r", "usefulness": "useful", "citation_accuracy": "all_accurate"}
            with self.assertRaisesRegex(ValueError, "completed Agent investigation"):
                ops.record_agent_review(agent_task["id"], record)
            with self.assertRaisesRegex(ValueError, "completed Agent investigation"):
                ops.record_agent_review(ordinary_task["id"], record)

    def test_independent_operation_worker_fails_closed_when_provider_is_unconfigured(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(root / "data", (root / "targets",))
            settings.initialize()
            store = Store(settings.data_dir)
            ops = Operations(store)
            task = ops.create("agent_investigation", {
                "job_id": "job-1", "candidate_id": "candidate-1",
                "source_submission_approved": True, "timeout_seconds": 90, "memory_mb": 512,
                "provider_fingerprint": "unused"})
            claimed = ops.claim()
            with patch.dict(os.environ, {
                "OHSCANNER_DATA": str(settings.data_dir),
                "OHSCANNER_TARGET_ROOTS": os.pathsep.join(map(str, settings.target_roots)),
                "OHSCANNER_LLM_BASE_URL": "https://api.openai.com/v1",
                "OHSCANNER_LLM_MODEL": "", "OHSCANNER_LLM_API_KEY": ""}, clear=False):
                OperationWorker(settings).execute(claimed)
            final = ops.get(task["id"])
            self.assertEqual(final["status"], "failed")
            self.assertIsNone(final["result_sha256"])
            log = (ops.directory(task["id"]) / "worker.log").read_text(errors="replace")
            self.assertIn("LLM provider became unconfigured before execution", log)
            self.assertNotIn("Authorization", log)

    def test_fake_provider_success_through_independent_operation_worker_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(root / "data", (root / "targets",))
            settings.initialize()
            store = Store(settings.data_dir)
            repo = store.add_repository("openharmony/worker-fixture", str(root))
            ops = Operations(store)
            with patch.dict(os.environ, {
                "OHSCANNER_LLM_BASE_URL": "https://api.openai.com/v1",
                "OHSCANNER_LLM_MODEL": "worker-fixture-model",
                "OHSCANNER_LLM_API_KEY": "test-worker-only-key"}, clear=False):
                config = agent.ProviderConfig.from_env()
                site = root / "test-python-hooks"
                site.mkdir()
                hook_lines = [
                    "import json",
                    "from src.workbench import agent, service",
                    "from src.workbench.store import Store",
                    "_REPORT = {'repository': 'openharmony/worker-fixture', 'commit': 'c' * 40, 'tree': 'd' * 40, 'snapshot_sha256': 'e' * 64}",
                    "_CANDIDATE = {'id': 'candidate-1', 'file': 'src/fixed.cpp', 'line': 2, 'source_sha256': 'a' * 64, 'symbol': 'check', 'detector_id': 'sample.rule', 'detector_version': '0.1', 'rule_id': 'R1', 'evidence': {'analysis_status': 'partial', 'obligations': ['reachability unknown']}}",
                    "_SOURCE = {'sha256': 'a' * 64, 'blob': 'f' * 40, 'text': 'void check() {\\n  guarded_call();\\n}\\n'}",
                    "service.read_report = lambda settings, job: _REPORT",
                    "service.finding = lambda report, candidate_id: _CANDIDATE",
                    "service.source = lambda settings, store, job, file: _SOURCE",
                    "_original_job = Store.job",
                    "def _job(self, key):",
                    "    if key == 'job-worker-fixture':",
                    "        return {'id': key, 'repository_id': 'repo-worker-fixture', 'status': 'completed', 'report_sha256': 'b' * 64}",
                    "    return _original_job(self, key)",
                    "Store.job = _job",
                    "class _FakeResponses:",
                    "    def __init__(self, config): pass",
                    "    def create(self, payload):",
                    "        context = json.loads(payload['input'][0]['content'][0]['text'])",
                    "        answer = {'summary': 'Synthetic child-process review.', 'assessment': 'needs_more_evidence', 'supported_claims': [{'claim': 'Candidate source was bound.', 'citations': [{'evidence_id': context['evidence_id'], 'quote': 'guarded_call();'}]}], 'unsupported_claims': [], 'unknowns': ['Product reachability'], 'next_steps': ['Human review']}",
                    "        return {'status': 'completed', 'output': [{'type': 'message', 'content': [{'type': 'output_text', 'text': json.dumps(answer)}]}], 'usage': {'input_tokens': 222, 'output_tokens': 41, 'total_tokens': 263}}",
                    "agent.ResponsesClient = _FakeResponses",
                ]
                hook_lines = [line.replace("repo-worker-fixture", repo["id"]) for line in hook_lines]
                site.joinpath("sitecustomize.py").write_text("\n".join(hook_lines) + "\n")
                spec = {"job_id": "job-worker-fixture", "candidate_id": "candidate-1",
                    "mode": "single_shot", "max_steps": 2, "max_output_tokens": 500,
                    "max_total_input_tokens": 24000, "max_total_output_tokens": 1000,
                    "timeout_seconds": 90, "memory_mb": 768,
                    "source_submission_approved": True, "provider_fingerprint": config.fingerprint,
                    "prompt_version": agent.PROMPT_VERSION, "tool_policy_version": agent.TOOL_POLICY_VERSION,
                    "consent_preview_version": agent.CONSENT_PREVIEW_VERSION}
                preview_job = {"id": "job-worker-fixture", "repository_id": repo["id"],
                    "status": "completed", "report_sha256": "b" * 64}
                preview_report = {"repository": "openharmony/worker-fixture", "commit": "c" * 40,
                    "tree": "d" * 40, "snapshot_sha256": "e" * 64}
                preview_candidate = {"id": "candidate-1", "file": "src/fixed.cpp", "line": 2,
                    "source_sha256": "a" * 64, "symbol": "check", "detector_id": "sample.rule",
                    "detector_version": "0.1", "rule_id": "R1",
                    "evidence": {"analysis_status": "partial", "obligations": ["reachability unknown"]}}
                preview_source = {"sha256": "a" * 64, "blob": "f" * 40,
                    "text": "void check() {\n  guarded_call();\n}\n"}
                with patch.object(agent.service, "source", return_value=preview_source):
                    consent = agent.consent_preview(settings, store, preview_job, preview_report,
                                                    preview_candidate, spec, config)
                spec["source_consent_sha256"] = consent["consent_sha256"]
                task = ops.create("agent_investigation", spec)
                claimed = ops.claim()
                child_env = {**os.environ,
                    "OHSCANNER_DATA": str(settings.data_dir),
                    "OHSCANNER_TARGET_ROOTS": os.pathsep.join(map(str, settings.target_roots)),
                    "PYTHONPATH": os.pathsep.join([str(site), str(Path(__file__).resolve().parents[1])])}
                with patch.dict(os.environ, child_env, clear=True):
                    OperationWorker(settings).execute(claimed)
            final = ops.get(task["id"])
            self.assertEqual(final["status"], "completed_with_limitations",
                str(final) + "\\n" + (ops.directory(task["id"]) / "worker.log").read_text(errors="replace"))
            result = ops.result(task["id"])
            self.assertEqual(result["mode"], "single_shot")
            self.assertEqual(result["binding"]["commit"], "c" * 40)
            self.assertEqual(result["model_usage"]["total_tokens"], 263)
            self.assertEqual(result["vulnerability_state"], "candidate")
            self.assertEqual(result["validated_vulnerability"], 0)
            self.assertTrue(any(event["stage"] == "agent_model_call" for event in ops.events(task["id"])))
            self.assertTrue(any(event["stage"] == "agent_completed" for event in ops.events(task["id"])))
            self.assertNotIn("test-worker-only-key", json.dumps(result))
            self.assertTrue((ops.directory(task["id"]) / "worker.log").is_file())

    def test_operation_dispatch_routes_to_the_agent_executor(self):
        task = {"id": "operation-1", "kind": "agent_investigation", "spec": {"mode": "single_shot"}}
        expected = {"status": "completed_with_limitations", "vulnerability_state": "candidate"}
        with patch("src.workbench.agent.execute_agent", return_value=expected) as execute_agent:
            result = operations.execute(None, None, "ops", task)
        self.assertEqual(result, expected)
        execute_agent.assert_called_once_with(None, None, "ops", task)


    def test_triage_schema_rejects_confirmed_or_reportable_verdicts(self):
        value = {"summary": "unsafe", "assessment": "confirmed", "supported_claims": [],
                 "unsupported_claims": [], "unknowns": [], "next_steps": []}
        with self.assertRaisesRegex(ValueError, "disallowed assessment"):
            agent._validate_final(json.dumps(value), set())


    def test_input_budget_stops_before_model_call(self):
        class Store:
            def job(self, key):
                return {"id": key, "repository_id": "repo-1", "status": "completed", "report_sha256": "b" * 64}
            def repository(self, key):
                return {"id": key, "path": "/fixed/repository"}
        class Ops:
            def get(self, key): return {"cancel_requested": False}
            def event(self, *args): pass
        class NeverCall:
            def create(self, payload):
                raise AssertionError("provider must not be called after input budget exhaustion")
        report = {"repository": "openharmony/sample", "commit": "c" * 40}
        candidate = {"id": "candidate-1", "file": "source.cpp", "line": 1,
                     "source_sha256": "a" * 64, "evidence": {}}
        source = {"sha256": "a" * 64, "text": "风险" * 500}
        task = {"id": "task-budget", "spec": {"job_id": "j", "candidate_id": "candidate-1",
            "max_steps": 1, "max_output_tokens": 128, "max_total_input_tokens": 1000,
            "max_total_output_tokens": 512, "timeout_seconds": 90, "source_submission_approved": True,
            "provider_fingerprint": "", "prompt_version": agent.PROMPT_VERSION,
            "tool_policy_version": agent.TOOL_POLICY_VERSION}}
        with patch.dict(os.environ, {"OHSCANNER_LLM_MODEL": "test-model", "OHSCANNER_LLM_API_KEY": "key"}, clear=False):
            task["spec"]["provider_fingerprint"] = agent.ProviderConfig.from_env().fingerprint
            bind_test_consent(task, Store(), report, candidate, source)
            with patch.object(agent.service, "read_report", return_value=report), \
                 patch.object(agent.service, "finding", return_value=candidate), \
                 patch.object(agent.service, "source", return_value=source):
                with self.assertRaisesRegex(ValueError, "conservative input request budget"):
                    agent.execute_agent(None, Store(), Ops(), task, client=NeverCall())


    def test_supported_claims_must_have_a_real_evidence_id(self):
        value = {"summary": "triage", "assessment": "likely_true_positive",
                 "supported_claims": [{"claim": "unsupported", "citations": [{"evidence_id": "ev-not-real", "quote": "supported quote"}]}],
                 "unsupported_claims": [], "unknowns": [], "next_steps": []}
        with self.assertRaisesRegex(ValueError, "invalid evidence"):
            agent._validate_final(json.dumps(value), {"ev-real": ["supported quote"]})


    def test_supported_claim_citations_require_exact_verbatim_quotes(self):
        value = {"summary": "triage", "assessment": "likely_true_positive",
                 "supported_claims": [{"claim": "The source calls the guarded function.",
                    "citations": [{"evidence_id": "ev-source", "quote": "guarded_call();"}]}],
                 "unsupported_claims": [], "unknowns": [], "next_steps": []}
        valid = agent._validate_final(json.dumps(value), {"ev-source": ["void check() { guarded_call(); }"]})
        self.assertEqual(valid["supported_claims"][0]["citations"][0]["quote"], "guarded_call();")
        value["supported_claims"][0]["citations"][0]["quote"] = "invented claim"
        with self.assertRaisesRegex(ValueError, "invalid evidence quote"):
            agent._validate_final(json.dumps(value), {"ev-source": ["void check() { guarded_call(); }"]})


    def test_provider_cannot_exceed_the_output_token_budget(self):
        class Store:
            def job(self, key):
                return {"id": key, "repository_id": "repo-1", "status": "completed", "report_sha256": "b" * 64}
            def repository(self, key):
                return {"id": key, "path": "/fixed/repository"}
        class Ops:
            def get(self, key): return {"cancel_requested": False}
            def event(self, *args): pass
        class OverBudget:
            def create(self, payload):
                return {"status": "completed", "output": [],
                        "usage": {"input_tokens": 30, "output_tokens": 129, "total_tokens": 159}}
        report = {"repository": "openharmony/sample", "commit": "c" * 40}
        candidate = {"id": "candidate-1", "file": "source.cpp", "line": 1,
                     "source_sha256": "a" * 64, "evidence": {}}
        source = {"sha256": "a" * 64, "text": "safe"}
        task = {"id": "task-budget", "spec": {"job_id": "j", "candidate_id": "candidate-1",
            "max_steps": 1, "max_output_tokens": 128, "max_total_input_tokens": 24000,
            "max_total_output_tokens": 512, "timeout_seconds": 90, "source_submission_approved": True,
            "provider_fingerprint": "", "prompt_version": agent.PROMPT_VERSION,
            "tool_policy_version": agent.TOOL_POLICY_VERSION}}
        with patch.dict(os.environ, {"OHSCANNER_LLM_MODEL": "test-model", "OHSCANNER_LLM_API_KEY": "key"}, clear=False):
            task["spec"]["provider_fingerprint"] = agent.ProviderConfig.from_env().fingerprint
            bind_test_consent(task, Store(), report, candidate, source)
            with patch.object(agent.service, "read_report", return_value=report), \
                 patch.object(agent.service, "finding", return_value=candidate), \
                 patch.object(agent.service, "source", return_value=source):
                with self.assertRaisesRegex(ValueError, "output token usage exceeded"):
                    agent.execute_agent(None, Store(), Ops(), task, client=OverBudget())


    def test_cancellation_is_checked_before_model_call(self):
        class Store:
            def job(self, key):
                return {"id": key, "repository_id": "repo-1", "status": "completed", "report_sha256": "b" * 64}
            def repository(self, key):
                return {"id": key, "path": "/fixed/repository"}
        class Ops:
            def get(self, key): return {"cancel_requested": True}
            def event(self, *args): pass
        class NeverCall:
            def create(self, payload):
                raise AssertionError("cancelled task must not call the provider")
        report = {"repository": "openharmony/sample", "commit": "c" * 40}
        candidate = {"id": "candidate-1", "file": "source.cpp", "line": 1,
                     "source_sha256": "a" * 64, "evidence": {}}
        source = {"sha256": "a" * 64, "text": "safe"}
        task = {"id": "task-cancel", "spec": {"job_id": "j", "candidate_id": "candidate-1",
            "max_steps": 1, "max_output_tokens": 128, "max_total_input_tokens": 24000,
            "max_total_output_tokens": 512, "timeout_seconds": 90, "source_submission_approved": True,
            "provider_fingerprint": "", "prompt_version": agent.PROMPT_VERSION,
            "tool_policy_version": agent.TOOL_POLICY_VERSION}}
        with patch.dict(os.environ, {"OHSCANNER_LLM_MODEL": "test-model", "OHSCANNER_LLM_API_KEY": "key"}, clear=False):
            task["spec"]["provider_fingerprint"] = agent.ProviderConfig.from_env().fingerprint
            bind_test_consent(task, Store(), report, candidate, source)
            with patch.object(agent.service, "read_report", return_value=report), \
                 patch.object(agent.service, "finding", return_value=candidate), \
                 patch.object(agent.service, "source", return_value=source):
                with self.assertRaisesRegex(InterruptedError, "cancelled"):
                    agent.execute_agent(None, Store(), Ops(), task, client=NeverCall())


    def test_cancellation_during_provider_call_prevents_followup_tool_execution(self):
        class Store:
            def job(self, key):
                return {"id": key, "repository_id": "repo-1", "status": "completed",
                        "report_sha256": "b" * 64}
            def repository(self, key):
                return {"id": key, "path": "/fixed/repository"}
        class Ops:
            def __init__(self): self.reads, self.events = 0, []
            def get(self, key):
                self.reads += 1
                return {"cancel_requested": self.reads > 1}
            def event(self, *args): self.events.append(args)
        class ToolRequester:
            def create(self, payload):
                return {"status": "completed", "output": [{"type": "function_call",
                    "name": "read_candidate_source", "arguments": "{}", "call_id": "call-cancel"}],
                    "usage": {"input_tokens": 300, "output_tokens": 20, "total_tokens": 320}}
        report = {"repository": "openharmony/sample", "commit": "c" * 40}
        candidate = {"id": "candidate-1", "file": "src/sample.cpp", "line": 1,
                     "source_sha256": "a" * 64, "evidence": {}}
        source = {"sha256": "a" * 64, "blob": "f" * 40, "text": "void f() {}"}
        task = {"id": "task-cancel-in-flight", "spec": {"job_id": "j",
            "candidate_id": "candidate-1", "mode": "tool_agent", "max_steps": 2,
            "max_output_tokens": 500, "max_total_input_tokens": 24000,
            "max_total_output_tokens": 1000, "timeout_seconds": 90,
            "source_submission_approved": True, "provider_fingerprint": "",
            "prompt_version": agent.PROMPT_VERSION, "tool_policy_version": agent.TOOL_POLICY_VERSION}}
        with patch.dict(os.environ, {"OHSCANNER_LLM_MODEL": "test-model", "OHSCANNER_LLM_API_KEY": "key"}, clear=False):
            task["spec"]["provider_fingerprint"] = agent.ProviderConfig.from_env().fingerprint
            bind_test_consent(task, Store(), report, candidate, source)
            ops = Ops()
            with patch.object(agent.service, "read_report", return_value=report), \
                 patch.object(agent.service, "finding", return_value=candidate), \
                 patch.object(agent.service, "source", return_value=source):
                with self.assertRaisesRegex(InterruptedError, "cancelled"):
                    agent.execute_agent(None, Store(), ops, task, client=ToolRequester())
        self.assertEqual(ops.reads, 2)
        self.assertIn("agent_cancelled", [event[1] for event in ops.events])
        self.assertNotIn("agent_tool", [event[1] for event in ops.events])

    def test_single_shot_r1_uses_fixed_context_once_and_cites_it(self):
        class Store:
            def job(self, key):
                return {"id": key, "repository_id": "repo-1", "status": "completed", "report_sha256": "b" * 64}
            def repository(self, key):
                return {"id": key, "path": "/fixed/repository"}
        class Ops:
            def __init__(self): self.events = []
            def get(self, key): return {"cancel_requested": False}
            def event(self, *args): self.events.append(args)
        class OneShot:
            def __init__(self, assessment="needs_more_evidence", include_usage=True):
                self.payloads, self.assessment, self.include_usage = [], assessment, include_usage
            def create(self, payload):
                self.payloads.append(payload)
                context = json.loads(payload["input"][0]["content"][0]["text"])
                final = {"summary": "One-pass triage only.", "assessment": self.assessment,
                    "supported_claims": [{"claim": "The candidate source binding is present.",
                                           "citations": [{"evidence_id": context["evidence_id"], "quote": "return 0;"}]}],
                    "unsupported_claims": [], "unknowns": ["Reachability"], "next_steps": ["Human review"]}
                response = {"status": "completed", "output": [{"type": "message", "content": [
                    {"type": "output_text", "text": json.dumps(final)}]}]}
                if self.include_usage:
                    response["usage"] = {"input_tokens": 500, "output_tokens": 45, "total_tokens": 545}
                return response
        report = {"repository": "openharmony/sample", "commit": "c" * 40}
        candidate = {"id": "candidate-1", "file": "source.cpp", "line": 2,
                     "source_sha256": "a" * 64, "evidence": {"obligations": []}}
        source = {"sha256": "a" * 64, "blob": "f" * 40, "text": "int f() { return 0; }"}
        task = {"id": "task-r1", "spec": {"job_id": "j", "candidate_id": "candidate-1",
            "mode": "single_shot", "max_steps": 6, "max_output_tokens": 500,
            "max_total_input_tokens": 24000, "max_total_output_tokens": 1000,
            "timeout_seconds": 90, "source_submission_approved": True, "provider_fingerprint": "",
            "prompt_version": agent.PROMPT_VERSION, "tool_policy_version": agent.TOOL_POLICY_VERSION}}
        with patch.dict(os.environ, {"OHSCANNER_LLM_MODEL": "test-model", "OHSCANNER_LLM_API_KEY": "key"}, clear=False):
            task["spec"]["provider_fingerprint"] = agent.ProviderConfig.from_env().fingerprint
            bind_test_consent(task, Store(), report, candidate, source)
            fake = OneShot()
            ops = Ops()
            with patch.object(agent.service, "read_report", return_value=report), \
                 patch.object(agent.service, "finding", return_value=candidate), \
                 patch.object(agent.service, "source", return_value=source):
                result = agent.execute_agent(None, Store(), ops, task, client=fake)
                failing_ops = Ops()
                with self.assertRaisesRegex(ValueError, "disallowed assessment"):
                    agent.execute_agent(None, Store(), failing_ops, task, client=OneShot("confirmed"))
                no_usage_result = agent.execute_agent(None, Store(), Ops(), task,
                                                       client=OneShot(include_usage=False))
        self.assertEqual(len(fake.payloads), 1)
        model_events = [event for event in failing_ops.events if event[1] == "agent_model_call"]
        self.assertEqual(len(model_events), 1)
        self.assertIn("response_sha256=", model_events[0][2])
        self.assertIn("duration_ms=", model_events[0][2])
        self.assertNotIn("tools", fake.payloads[0])
        self.assertEqual(result["mode"], "single_shot")
        self.assertEqual(result["tool_calls"], [])
        self.assertEqual(result["vulnerability_state"], "candidate")
        self.assertEqual(result["agent_assessment"]["assessment"], "needs_more_evidence")
        self.assertEqual(result["initial_evidence"]["evidence_id"],
                         result["agent_assessment"]["supported_claims"][0]["citations"][0]["evidence_id"])
        self.assertIsNone(no_usage_result["model_usage"]["input_tokens"])
        self.assertIsNone(no_usage_result["model_usage"]["output_tokens"])
        self.assertIsNone(no_usage_result["model_usage"]["total_tokens"])
        self.assertFalse(no_usage_result["model_usage"]["usage_complete"])


if __name__ == "__main__":
    unittest.main()


class AgentPairedEvaluationTests(unittest.TestCase):
    def test_r1_r2_pair_only_when_experiment_and_source_binding_match(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = create_app(Settings(root / "data", (root / "targets",)))
            ops = Operations(app.state.store)
            binding = {"repository": "controlled/sample", "commit": "a" * 40,
                       "candidate_id": "candidate-1"}
            ops.record_agent_baseline_review({
                "experiment_id": "study-1", "job_id": "a" * 32,
                "candidate_id": "candidate-1", "repository": binding["repository"],
                "commit": binding["commit"], "report_sha256": "b" * 64,
                "source_sha256": "c" * 64, "reviewer": "r0-reviewer",
                "disposition": "investigate", "elapsed_seconds": 60,
                "notes": "static-only", "review_scope": "static_only_r0_triage",
                "vulnerability_state": "candidate", "validated_vulnerability": 0,
            })
            for mode, experiment_id, usefulness, citation, elapsed in (
                ("single_shot", "study-1", "useful", "all_accurate", 50),
                ("tool_agent", "study-1", "partially_useful", "some_incorrect", 80),
                ("tool_agent", "study-2", "useful", "all_accurate", 40),
                ("single_shot", None, "useful", "not_checked", 30),
            ):
                item = ops.create("agent_investigation", {"experiment_id": experiment_id})
                claimed = ops.claim()
                self.assertEqual(claimed["id"], item["id"])
                result = {
                    "status": "completed_with_limitations", "kind": "agent_candidate_investigation",
                    "mode": mode, "experiment_id": experiment_id, "provider": {"model": "eval-model"},
                    "prompt_version": "prompt-1", "tool_policy_version": "tools-1",
                    "binding": binding, "agent_assessment": {"assessment": "needs_more_evidence"},
                    "vulnerability_state": "candidate", "validated_vulnerability": 0,
                }
                ops.finish(item["id"], result=result)
                ops.record_agent_review(item["id"], {
                    "reviewer": "reviewer", "usefulness": usefulness,
                    "citation_accuracy": citation, "elapsed_seconds": elapsed,
                    "claims_to_correct": "", "missed_evidence": "", "notes": "",
                })

            summary = ops.agent_evaluation_summary()
            self.assertEqual(summary["scope"], "operator_feedback_only")
            self.assertFalse(summary["accuracy_claim"])
            self.assertEqual(summary["paired_comparison_scope"],
                             "matched_candidate_operator_feedback_only")
            self.assertEqual(len(summary["paired_comparisons"]), 1)
            pair = summary["paired_comparisons"][0]
            self.assertEqual(pair["experiment_id"], "study-1")
            self.assertEqual(pair["candidate_id"], "candidate-1")
            self.assertEqual(pair["r0_static_baseline"]["review_count"], 1)
            self.assertEqual(pair["r0_static_baseline"]["dispositions"]["investigate"], 1)
            self.assertEqual(pair["r0_static_baseline"]["median_elapsed_seconds"], 60)
            self.assertEqual(pair["single_shot"]["median_elapsed_seconds"], 50)
            self.assertEqual(pair["tool_agent"]["median_elapsed_seconds"], 80)
            self.assertEqual(pair["tool_agent"]["citation_accuracy"]["some_incorrect"], 1)
            self.assertIn("R0 static-only human triage is shown", summary["limitation"])
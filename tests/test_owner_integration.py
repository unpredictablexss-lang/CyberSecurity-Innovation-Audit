"""Owner integration: real fixed Git, bounded planning, API/Worker/CLI parity.

Authored controls verify wiring/evidence gates, not product accuracy.
"""
import json
import os
import subprocess
import unittest
from unittest.mock import patch
from tests import test_workbench as fixtures
from src.ohscanner.execution import run_fixed_commit_scan
from src.workbench import operations, service, smart_audit
from tests.test_risk_confidence import build_valid_agent_result
from src.workbench.operations_store import Operations
from src.workbench.operation_worker import OperationWorker
from src.workbench.worker import Worker


@unittest.skipIf(fixtures.create_app is None, 'optional web dependencies unavailable')
class OwnerIntegrationTests(unittest.TestCase):
    setUp = fixtures.WorkbenchTests.setUp

    def request(self, **extra):
        return {'repository_id': self.repo_id, 'revision': self.commit,
                'include_paths': ['.'], **extra}

    def plan(self, **extra):
        r = self.client.post('/api/v1/audit-plans', json=self.request(**extra), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def scan(self, **extra):
        r = self.client.post('/api/v1/scans', json=self.request(**extra), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def test_automatic_plan_is_frozen_and_worker_matches_cli(self):
        plan = self.plan()
        static_plan = {key: value for key, value in plan.items()
                       if key not in {'audit_mode', 'workflow_sha256', 'workflow',
                                      'progressive_triage_policy'}}
        self.assertEqual(plan['audit_mode'], 'standard_review')
        self.assertEqual(plan['workflow']['triage_stage'], 'user_authorized_candidate_batch')
        self.assertEqual(plan['selection_mode'], 'automatic')
        self.assertIn('ohscanner.cpp.null_dereference', plan['suggested_detector_ids'])
        self.assertIn('ohscanner.cpp.path_traversal', plan['suggested_detector_ids'])
        self.assertIn('ohscanner.ark.runtime.type_safety', plan['suggested_detector_ids'])
        self.assertIn('ohscanner.data.sensitive_exposure', plan['suggested_detector_ids'])
        self.assertIn('ohscanner.known_disclosed_cves', plan['suggested_detector_ids'])
        self.assertEqual(plan['execution_status'], 'not_run')
        null = next(d for d in plan['detectors'] if d['id']=='ohscanner.cpp.null_dereference')
        self.assertEqual(null['decision'], 'planned')
        self.assertIn('partial.cpp', [f['file'] for f in plan['parse_limitations']])
        job = self.scan(expected_plan_sha256=plan['plan_sha256'])
        self.assertEqual(job['spec']['audit_plan'], static_plan)
        self.assertEqual(job['spec']['progressive_triage_policy'],
                         plan['progressive_triage_policy'])
        self.assertEqual(job['spec']['plan_sha256'], plan['plan_sha256'])
        self.assertEqual(job['spec']['audit_mode'], 'standard_review')
        self.assertEqual(job['spec']['workflow_sha256'], plan['workflow_sha256'])
        Worker(self.settings).run(once=True)
        job = self.store.job(job['id'])
        self.assertEqual(job['status'], 'completed_with_limitations', job)
        report = service.read_report(self.settings, job)
        self.assertEqual(report['audit_plan'], static_plan)
        cli = run_fixed_commit_scan(self.repo, 'fixture/sample', self.commit, ('.',),
                                    None, self.root/'cli.json', self.root/'cli.md', expected_plan=static_plan)
        self.assertEqual(cli['audit_plan'], static_plan)
        for a, b in zip(cli['detector_runs'], report['detector_runs']):
            for field in ('tool', 'tool_version', 'status', 'diagnostics', 'parsing'):
                self.assertEqual(a[field], b[field])
        self.assertEqual(cli['detector_coverage'], report['detector_coverage'])
        self.assertGreater(report['diagnostic_count'], 0)
        self.assertEqual(report['validated_vulnerability'], 0)
        for item in service.findings(report):
            self.assertTrue(item['evidence']['obligations'])

    def test_new_single_and_multi_endpoint_disclosures_follow_candidate_policy(self):
        from src.workbench.progressive_triage.policy import PolicyStore, build_policy
        from src.workbench.operations_api import TaskTriageOptions, _preview_operation_triage
        with patch.dict(os.environ, {"OHSCANNER_LLM_MODEL": "test", "OHSCANNER_LLM_API_KEY": "fake-key"}):
            plan = self.plan(auto_triage=True)
            self.assertEqual(plan["workflow"]["candidate_limit_per_authorized_batch"], 30)
            self.assertEqual(plan["workflow"]["conditional_r2_candidate_limit"], 6)
            PolicyStore(self.settings.data_dir).update(build_policy("deep"), 0)
            plan = self.plan(auto_triage=True)
            self.assertEqual(plan["workflow"]["candidate_limit_per_authorized_batch"], 100)
            self.assertEqual(plan["workflow"]["conditional_r2_candidate_limit"], 20)
            spec = service.make_spec(self.store.repository(self.repo_id), self.commit, ["."], None, 300, 2048)
            body = TaskTriageOptions(auto_triage=True)
            preview = _preview_operation_triage(self.settings, body, [spec, spec])
            self.assertEqual((body.max_triage_candidates, body.max_r2_candidates), (100, 20))
            self.assertEqual(len(preview["scans"]), 2)
            self.assertTrue(all(item["manifest"]["candidate_selection"]["authorized_candidate_count"] == 100 for item in preview["scans"]))

    def test_task_level_triage_consent_is_bound_and_revocable(self):
        with patch.dict("os.environ", {
            "OHSCANNER_LLM_BASE_URL": "https://api.xiaomimimo.com/v1",
            "OHSCANNER_LLM_MODEL": "mimo-v2.6-pro",
            "OHSCANNER_LLM_API_KEY": "test-provider-key",
        }, clear=False):
            plan = self.plan(auto_triage=True, max_triage_candidates=2)
            consent = plan["triage_authorization_preview"]
            self.assertTrue(consent["eligible"])
            self.assertEqual(consent["manifest"]["candidate_selection"]["authorized_candidate_count"], 2)
            self.assertEqual(consent["manifest"]["binding"]["commit"], self.commit)
            self.assertFalse(consent["hard_spend_cap"])
            self.assertNotIn("test-provider-key", json.dumps(consent))
            self.assertTrue(plan["workflow"]["automatic_model_calls"])

            job = self.scan(
                auto_triage=True, max_triage_candidates=2,
                expected_plan_sha256=plan["plan_sha256"],
                expected_workflow_sha256=plan["workflow_sha256"],
                expected_triage_consent_sha256=consent["consent_sha256"],
                triage_consent_nonce=consent["consent_nonce"],
            )
            saved = self.store.triage_authorization(job["id"])
            self.assertEqual(saved["consent_sha256"], consent["consent_sha256"])
            self.assertFalse(saved["revoked"])
            self.assertEqual(self.store.job(job["id"])["status"], "queued")
            summary = self.client.get(
                "/api/v1/scans/" + job["id"] + "/triage", headers=fixtures.HEADERS
            ).json()
            self.assertEqual(summary["state"], "waiting_for_scan")
            self.assertTrue(summary["authorization"]["authorized"])

            revoked = self.client.post(
                "/api/v1/scans/" + job["id"] + "/triage/revoke",
                json={"consent_sha256": consent["consent_sha256"]},
                headers=fixtures.HEADERS,
            )
            self.assertEqual(revoked.status_code, 200, revoked.text)
            self.assertTrue(revoked.json()["authorization"]["revoked"])
            self.assertEqual(self.store.job(job["id"])["status"], "queued")
            self.assertEqual(self.store.triage_authorization(job["id"])["consent_sha256"],
                             consent["consent_sha256"])

    def test_real_workers_fixed_endpoints_and_fake_agent_provider_e2e(self):
        """Exercise static and Agent subprocess Workers; the fake provider proves wiring only."""
        (self.repo / "endpoint-note.txt").write_text("second fixed endpoint\n")
        fixtures.git(self.repo, "add", "endpoint-note.txt")
        fixtures.git(self.repo, "commit", "-qm", "second endpoint")
        endpoint = fixtures.git(self.repo, "rev-parse", "HEAD")
        payload = {
            "repository_id": self.repo_id, "baseline": self.commit, "endpoint": endpoint,
            "include_paths": ["."], "detector_ids": [
                "ohscanner.cpp.lifetime", "ohscanner.cpp.shared_ptr_race",
            ],
            "timeout_seconds": 90, "memory_mb": 1024, "audit_mode": "standard_review",
            "auto_triage": True, "max_triage_candidates": 1,
            "max_r2_candidates": 0,
        }
        provider_env = {
            "OHSCANNER_LLM_BASE_URL": "https://api.xiaomimimo.com/v1",
            "OHSCANNER_LLM_MODEL": "mimo-v2.6-pro",
            "OHSCANNER_LLM_API_KEY": "synthetic-no-network-key",
        }
        with patch.dict(os.environ, provider_env, clear=False):
            preview_response = self.client.post(
                "/api/v1/operations/scan-previews",
                json={"kind": "range", "payload": payload}, headers=fixtures.HEADERS,
            )
            self.assertEqual(preview_response.status_code, 200, preview_response.text)
            preview = preview_response.json()["triage_authorization_preview"]
            self.assertTrue(preview["eligible"])
            authorizations = [
                {key: item[key] for key in (
                    "plan_sha256", "workflow_sha256", "consent_sha256", "consent_nonce")}
                for item in preview["scans"]
            ]
            created = self.client.post(
                "/api/v1/operations/revision-ranges",
                json={**payload, "triage_authorizations": authorizations},
                headers=fixtures.HEADERS,
            )
            self.assertEqual(created.status_code, 201, created.text)
            operation_id = created.json()["id"]
            scan_ids = created.json()["spec"]["scan_ids"]

            # Run the actual isolated scanner subprocess for both immutable commits.
            Worker(self.settings).run(once=True)
            triage_batches = []
            for job_id, expected_commit in zip(scan_ids, (self.commit, endpoint)):
                job = self.store.job(job_id)
                self.assertEqual(job["status"], "completed_with_limitations", job)
                self.assertEqual(job["spec"]["commit"], expected_commit)
                self.assertTrue(job["report_sha256"])
                batch = Operations(self.store).triage_batches_for_job(
                    job_id, job["report_sha256"])[-1]
                self.assertEqual(batch["status"], "queued", batch)
                self.assertGreaterEqual(batch["candidate_count"], 2, batch)
                self.assertEqual(batch["selected_count"], 1, batch)
                triage_batches.append(batch)

            queued = self.client.get(
                "/api/v1/operations/" + operation_id, headers=fixtures.HEADERS)
            self.assertEqual(queued.status_code, 200, queued.text)
            progress = queued.json()["intelligent_review_progress"]
            self.assertEqual([item["scan_status"] for item in progress],
                             ["completed_with_limitations"] * 2)
            self.assertTrue(all(item["agent_authorized"] for item in progress))
            self.assertTrue(all(item["agent_status"] == "queued" for item in progress))
            for item, batch in zip(progress, triage_batches):
                self.assertEqual(len(item["r1_operations"]), 1)
                queued_summary = item["r1_operations"][0]
                queued_operation = Operations(self.store).smart_triage_operations(batch["id"])[0]
                self.assertEqual(queued_summary["id"], queued_operation["id"])
                self.assertEqual(queued_summary["status"], "queued")
                self.assertIsNone(queued_summary["result_sha256"])
                self.assertEqual(queued_summary["candidate_id"], queued_operation["spec"]["candidate_id"])
                self.assertEqual(queued_summary["commit"], queued_operation["spec"]["source_commit"])
                self.assertEqual(queued_summary["report_sha256"], queued_operation["spec"]["report_sha256"])
                self.assertEqual(item["r2_operations"], [])

            ops = Operations(self.store)
            # A test-only sitecustomize replaces the provider client inside the real
            # child process. The production OperationWorker still applies its process
            # boundary, environment filter, resource limits, timeout and result write.
            fake_provider_dir = self.root / "fake-provider"
            fake_provider_dir.mkdir()
            fake_provider_dir.joinpath("sitecustomize.py").write_text(r'''
import json
import os

if os.environ.get("OHSCANNER_TEST_PROVIDER_TRACE"):
    from src.workbench import agent

    class FakeResponsesClient:
        def __init__(self, *args, **kwargs):
            pass

        def create_with_timeout(self, request, timeout):
            return self.create(request)

        def create(self, request, **kwargs):
            context = json.loads(request["input"][0]["content"][0]["text"])
            candidate_id = context.get("candidate_id")
            obligations = context.get("evidence_obligations", [])
            if not candidate_id or not obligations:
                raise ValueError("fake provider received an incomplete candidate request")
            trace_path = os.environ["OHSCANNER_TEST_PROVIDER_TRACE"]
            with open(trace_path, "a", encoding="utf-8") as trace:
                trace.write(json.dumps({"candidate_id": candidate_id,
                                        "obligation_count": len(obligations)}) + "\n")
            result = {
                "summary": "Synthetic review; human verification remains required.",
                "assessment": "needs_more_evidence",
                "supported_claims": [],
                "obligation_reviews": [
                    {"obligation_index": index, "disposition": "unresolved", "citations": []}
                    for index in range(len(obligations))
                ],
                "unsupported_claims": [], "unknowns": ["产品入口是否可达尚未确认"],
                "next_steps": ["Review the fixed source and runtime path."],
            }
            return {
                "status": "completed",
                "output": [{"type": "message", "content": [
                    {"type": "output_text", "text": json.dumps(result)}]}],
                "usage": {"input_tokens": 120, "output_tokens": 30, "total_tokens": 150},
            }

    agent.ResponsesClient = FakeResponsesClient
''')
            trace_path = self.root / "fake-provider-trace.jsonl"
            old_pythonpath = os.environ.get("PYTHONPATH", "")
            worker_pythonpath = os.pathsep.join(
                path for path in (str(fake_provider_dir), str(fixtures.ROOT), old_pythonpath)
                if path
            )
            worker_test_env = {
                "PYTHONPATH": worker_pythonpath,
                "OHSCANNER_TEST_PROVIDER_TRACE": str(trace_path),
            }
            # The operation itself uses the production parent/child dispatcher.
            with patch.dict(os.environ, worker_test_env, clear=False):
                OperationWorker(self.settings).run(once=True)
                parent = ops.get(operation_id)
                self.assertIn(parent["status"], {"completed", "completed_with_limitations"}, parent)
            expected_agent_ids = [key for batch in triage_batches for key in batch["operation_ids"]]
            self.assertEqual(len(expected_agent_ids), 2)
            for expected_id in expected_agent_ids:
                with patch.dict(os.environ, worker_test_env, clear=False):
                    OperationWorker(self.settings).run(once=True)
                task = ops.get(expected_id)
                self.assertEqual(task["kind"], "agent_investigation")
                stored = self.client.get(
                    "/api/v1/operations/" + task["id"], headers=fixtures.HEADERS).json()
                self.assertIn(
                    stored["status"], {"completed", "completed_with_limitations"},
                    {"operation": stored, "worker_log":
                     (ops.directory(task["id"]) / "worker.log").read_text(errors="replace")},
                )
                self.assertEqual(stored["result"]["vulnerability_state"], "candidate")
                self.assertEqual(stored["result"]["validated_vulnerability"], 0)
                self.assertTrue(stored["result"]["agent_assessment"]["obligation_reviews"])
                self.assertNotIn("synthetic-no-network-key", json.dumps(stored))
                self.assertTrue((ops.directory(task["id"]) / "child-result.json").is_file())

            provider_trace = [json.loads(line) for line in trace_path.read_text().splitlines()]
            self.assertEqual(len(provider_trace), 2)
            self.assertTrue(all(item["obligation_count"] > 0 for item in provider_trace))

            completed = self.client.get(
                "/api/v1/operations/" + operation_id, headers=fixtures.HEADERS).json()
            final_progress = completed["intelligent_review_progress"]
            self.assertTrue(all(item["agent_status"] == "partially_completed" for item in final_progress))
            for index, (item, batch) in enumerate(zip(final_progress, triage_batches)):
                self.assertEqual(len(item["r1_operations"]), 1)
                completed_summary = item["r1_operations"][0]
                completed_operation = Operations(self.store).smart_triage_operations(batch["id"])[0]
                self.assertEqual(completed_summary["status"], "completed_with_limitations")
                self.assertTrue(completed_summary["result_sha256"])
                self.assertEqual(completed_summary["id"], expected_agent_ids[index])
                self.assertEqual(completed_summary["candidate_id"], completed_operation["spec"]["candidate_id"])
                self.assertEqual(completed_summary["commit"], completed_operation["spec"]["source_commit"])
                self.assertEqual(completed_summary["report_sha256"], completed_operation["spec"]["report_sha256"])
                self.assertEqual(item["r2_operations"], [])
            self.assertTrue(all(item["candidate_count"] >= 2 for item in final_progress))
            self.assertTrue(all(item["r1_selected_count"] == 1 for item in final_progress))
            self.assertTrue(all(item["r1_not_selected_count"] >= 1 for item in final_progress))
            self.assertTrue(all(item["report_available"] for item in final_progress))
            self.assertTrue(all(not item["model_result_is_product_vulnerability_confirmation"]
                                for item in final_progress))

    def test_tool_agent_worker_e2e_reads_bound_source_and_preserves_candidate(self):
        job = self.scan(detector_ids=["ohscanner.cpp.lifetime"])
        Worker(self.settings).run(once=True)
        job = self.store.job(job["id"])
        self.assertIn(job["status"], {"completed", "completed_with_limitations"}, job)
        report = service.read_report(self.settings, job)
        candidate = next(item for item in service.findings(report)
                         if item["file"] == "lifetime.cpp")
        payload = {"job_id": job["id"], "candidate_id": candidate["id"],
                   "mode": "tool_agent", "max_steps": 2}
        provider_env = {
            "OHSCANNER_LLM_BASE_URL": "https://api.xiaomimimo.com/v1",
            "OHSCANNER_LLM_MODEL": "mimo-v2.6-pro",
            "OHSCANNER_LLM_API_KEY": "synthetic-no-network-key",
        }
        with patch.dict(os.environ, provider_env, clear=False):
            preview_response = self.client.post(
                "/api/v1/operations/agent-investigations/preview",
                json=payload, headers=fixtures.HEADERS)
            self.assertEqual(preview_response.status_code, 200, preview_response.text)
            preview = preview_response.json()
            self.assertTrue(preview["agent_execution"]["eligible"], preview)
            self.assertEqual(preview["budgets"]["max_output_tokens_per_request"],
                             preview["budgets"]["max_output_tokens"])
            created = self.client.post(
                "/api/v1/operations/agent-investigations",
                json={**payload, "source_submission_approved": True,
                      "consent_sha256": preview["consent_sha256"],
                      "consent_nonce": preview["consent_nonce"]},
                headers=fixtures.HEADERS)
            self.assertEqual(created.status_code, 201, created.text)

        fake_provider_dir = self.root / "fake-tool-provider"
        fake_provider_dir.mkdir()
        fake_provider_dir.joinpath("sitecustomize.py").write_text(r'''
import json
import os

if os.environ.get("OHSCANNER_TEST_TOOL_TRACE"):
    from src.workbench import agent

    class FakeResponsesClient:
        def __init__(self, *args, **kwargs):
            self.tool_requests = 0
            self.obligation_count = 0
            self.candidate_id = None

        def create_with_timeout(self, request, timeout):
            return self.create(request)

        def create(self, request, **kwargs):
            schema_name = request.get("text", {}).get("format", {}).get("name")
            if schema_name == "ohscanner_skeptic_review":
                context = {"candidate_id": self.candidate_id,
                           "evidence_obligations": [None] * self.obligation_count}
            else:
                inputs = request.get("input", [])
                context = json.loads(inputs[0]["content"][0]["text"])
                self.candidate_id = context.get("candidate_id")
                self.obligation_count = len(context.get("evidence_obligations", []))
            trace_path = os.environ["OHSCANNER_TEST_TOOL_TRACE"]
            if request.get("tools"):
                self.tool_requests += 1
                if self.tool_requests == 1:
                    with open(trace_path, "a", encoding="utf-8") as trace:
                        trace.write(json.dumps({"phase": "tool_call",
                            "commit": os.environ["OHSCANNER_TEST_TOOL_EXPECTED_COMMIT"],
                            "candidate_id": context["candidate_id"]}) + "\n")
                    return {"status": "completed", "output": [{
                        "type": "function_call", "call_id": "fixed-source-call-1",
                        "name": "read_candidate_enclosing_function", "arguments": "{}"}],
                        "usage": {"input_tokens": 100, "output_tokens": 20,
                                  "total_tokens": 120}}
                return {"status": "completed", "output": [{"type": "message",
                    "content": [{"type": "output_text", "text": "Synthesize only cited source evidence."}]}],
                    "usage": {"input_tokens": 110, "output_tokens": 15,
                              "total_tokens": 125}}

            obligations = context.get("evidence_obligations", [])
            if schema_name == "ohscanner_skeptic_review":
                value = {"reviews": [{"obligation_index": index, "result": "unknown",
                                      "citations": []}
                                     for index in range(len(obligations))]}
                phase = "skeptic"
                trace_extra = {}
            elif schema_name == "ohscanner_candidate_artifacts":
                value = {
                    "vulnerability_report": {
                        "title": "固定源码候选报告",
                        "summary": "证据尚不完整，产品入口是否可达仍未知。",
                        "root_cause": "源码路径需要人工复核。",
                        "impact": "目前无法确定产品影响范围。", "preconditions": [],
                        "attack_path": [], "remediation": "复核适用的产品策略。",
                        "citations": [],
                    },
                    "poc_draft": {
                        "title": "经证据门控的本地测试草案", "language": "",
                        "code": "", "prerequisites": [], "run_steps": [],
                        "expected_observation": "当前证据不足以形成测试草案。",
                        "negative_control": "", "citations": [],
                    },
                }
                phase = "artifact_generation"
                trace_extra = {
                    "candidate_binding": context.get("candidate_binding"),
                    "source_evidence_ids": [item.get("evidence_id")
                        for item in context.get("source_evidence", [])
                        if isinstance(item, dict)],
                }
            else:
                value = {"summary": "模拟源码调查；仍需人工或运行时证据。",
                    "assessment": "needs_more_evidence", "supported_claims": [],
                    "obligation_reviews": [
                        {"obligation_index": index, "disposition": "unresolved", "citations": []}
                        for index in range(len(obligations))],
                    "unsupported_claims": [], "unknowns": ["产品入口是否可达尚未确认"],
                    "next_steps": ["复核固定源码并验证运行时调用路径。"]}
                phase = "structured_review"
                trace_extra = {}
            with open(trace_path, "a", encoding="utf-8") as trace:
                trace.write(json.dumps({"phase": phase, "schema": schema_name,
                                        "candidate_id": context["candidate_id"],
                                        **trace_extra}) + "\n")
            return {"status": "completed", "output": [{"type": "message", "content": [
                {"type": "output_text", "text": json.dumps(value)}]}],
                "usage": {"input_tokens": 130, "output_tokens": 30,
                          "total_tokens": 160}}

    agent.ResponsesClient = FakeResponsesClient
''')
        trace_path = self.root / "tool-agent-provider-trace.jsonl"
        old_pythonpath = os.environ.get("PYTHONPATH", "")
        worker_pythonpath = os.pathsep.join(
            path for path in (str(fake_provider_dir), str(fixtures.ROOT), old_pythonpath)
            if path)
        with patch.dict(os.environ, {
            "PYTHONPATH": worker_pythonpath,
            **provider_env,
            "OHSCANNER_TEST_TOOL_TRACE": str(trace_path),
            "OHSCANNER_TEST_TOOL_EXPECTED_COMMIT": self.commit,
        }, clear=False):
            OperationWorker(self.settings).run(once=True)

        operation = Operations(self.store).get(created.json()["id"])
        self.assertIn(operation["status"], {"completed", "completed_with_limitations"},
                      {"operation": operation, "worker_log":
                       (Operations(self.store).directory(operation["id"]) / "worker.log").read_text(errors="replace")})
        stored = self.client.get("/api/v1/operations/" + operation["id"],
                                 headers=fixtures.HEADERS).json()
        result = stored["result"]
        self.assertEqual(result["binding"]["commit"], self.commit)
        self.assertEqual(result["binding"]["candidate_id"], candidate["id"])
        self.assertEqual(result["vulnerability_state"], "candidate")
        self.assertEqual(result["validated_vulnerability"], 0)
        tool_calls = result["tool_calls"]
        self.assertEqual(len(tool_calls), 1)
        self.assertEqual(tool_calls[0]["tool"], "read_candidate_enclosing_function")
        self.assertEqual(tool_calls[0]["evidence_kind"], "source_code")
        self.assertIn("lifetime.cpp", tool_calls[0]["result"]["file"])
        self.assertTrue(tool_calls[0]["result_sha256"])
        self.assertEqual(result["agent_assessment"]["assessment"], "needs_more_evidence")
        self.assertEqual(result["skeptic_review"]["status"], "completed")
        self.assertEqual(result["artifact_generation"]["status"], "completed")
        self.assertEqual(result["agent_assessment"]["vulnerability_report"]["status"], "draft_unverified")
        self.assertEqual(result["agent_assessment"]["poc_draft"]["status"], "insufficient_evidence")
        self.assertEqual(result["agent_assessment"]["poc_draft"]["code"], "")
        self.assertNotIn("synthetic-no-network-key", json.dumps(stored))
        provider_trace = [json.loads(line) for line in trace_path.read_text().splitlines()]
        self.assertEqual([item["phase"] for item in provider_trace],
                         ["tool_call", "structured_review", "skeptic", "artifact_generation"])
        self.assertTrue(all(item["candidate_id"] == candidate["id"]
                            for item in provider_trace))
        artifact_trace = provider_trace[-1]
        self.assertEqual(artifact_trace["candidate_binding"]["candidate_id"], candidate["id"])
        self.assertEqual(artifact_trace["candidate_binding"]["commit"], result["binding"]["commit"])
        self.assertEqual(artifact_trace["candidate_binding"]["report_sha256"],
                         result["binding"]["report_sha256"])
        self.assertEqual(artifact_trace["candidate_binding"]["source_sha256"],
                         result["binding"]["source_sha256"])
        self.assertIn(tool_calls[0]["evidence_id"], artifact_trace["source_evidence_ids"])

    def test_task_triage_has_no_platform_budget_cap_and_is_bound_to_preview(self):
        with patch.dict("os.environ", {
            "OHSCANNER_LLM_BASE_URL": "https://api.xiaomimimo.com/v1",
            "OHSCANNER_LLM_MODEL": "mimo-v2.6-pro",
            "OHSCANNER_LLM_API_KEY": "test-provider-key",
        }, clear=False):
            no_budget = self.client.post(
                "/api/v1/audit-plans",
                json=self.request(auto_triage=True, max_triage_candidates=1),
                headers=fixtures.HEADERS,
            )
            self.assertEqual(no_budget.status_code, 200, no_budget.text)
            preview = no_budget.json()["triage_authorization_preview"]
            self.assertTrue(preview["eligible"])
            manifest = preview["manifest"]
            for key in ("max_total_model_calls", "max_total_tool_calls",
                        "cumulative_token_ceiling", "cumulative_request_ceiling",
                        "cumulative_spend_ceiling"):
                self.assertIsNone(manifest["budgets"][key], key)
            self.assertEqual(manifest["budgets"]["local_cumulative_token_budget"], "none")
            self.assertEqual(manifest["budgets"]["local_cumulative_usd_budget"], "none")
            self.assertEqual(manifest["budgets"]["local_total_wall_time_budget"],
                             "until terminal response, provider/API error, cancellation, or repeated validation failure")
            self.assertEqual(manifest["usage_policy"]["local_cumulative_token_budget"], "none")
            self.assertEqual(manifest["usage_policy"]["local_cumulative_usd_budget"], "none")
            self.assertEqual(manifest["usage_policy"]["local_total_wall_time_budget"], "until_terminal_condition")

            plan = self.plan(auto_triage=True, max_triage_candidates=2)
            changed_plan = self.plan(auto_triage=True, max_triage_candidates=1)
            self.assertNotEqual(plan["workflow_sha256"], changed_plan["workflow_sha256"])
            consent = plan["triage_authorization_preview"]
            accepted = self.client.post(
                "/api/v1/scans",
                json=self.request(
                    auto_triage=True, max_triage_candidates=2,
                    expected_plan_sha256=plan["plan_sha256"],
                    expected_workflow_sha256=plan["workflow_sha256"],
                    expected_triage_consent_sha256=consent["consent_sha256"],
                    triage_consent_nonce=consent["consent_nonce"],
                ),
                headers=fixtures.HEADERS,
            )
            self.assertEqual(accepted.status_code, 201, accepted.text)
            self.assertEqual(self.store.triage_authorization(accepted.json()["id"])["consent_sha256"],
                             consent["consent_sha256"])

    def test_authorized_scan_queues_every_eligible_r1_once_without_calling_provider(self):
        import hashlib
        from src.workbench.operations_store import Operations

        def fake_prepare(_settings, _store, _job, _report, _candidate):
            return {"initial_context": {
                "evidence_routing": {"agent_source_review_indices": [0, 1]},
            }}

        def fake_preview(_settings, _store, job, report, candidate, _spec, _provider, prepared=None):
            return {
                "agent_execution": {"eligible": True},
                "consent_sha256": hashlib.sha256(candidate["id"].encode()).hexdigest(),
                "binding": {
                    "source_sha256": candidate.get("source_sha256"),
                    "commit": report["commit"],
                    "report_sha256": job["report_sha256"],
                },
            }

        with patch.dict("os.environ", {
            "OHSCANNER_LLM_BASE_URL": "https://api.xiaomimimo.com/v1",
            "OHSCANNER_LLM_MODEL": "mimo-v2.6-pro",
            "OHSCANNER_LLM_API_KEY": "test-provider-key",
        }, clear=False):
            plan = self.plan(auto_triage=True, max_triage_candidates=2)
            consent = plan["triage_authorization_preview"]
            job = self.scan(
                auto_triage=True, max_triage_candidates=2,
                expected_plan_sha256=plan["plan_sha256"],
                expected_workflow_sha256=plan["workflow_sha256"],
                expected_triage_consent_sha256=consent["consent_sha256"],
                triage_consent_nonce=consent["consent_nonce"],
            )
            with patch("src.workbench.smart_audit.agent._prepare_candidate_context",
                       side_effect=fake_prepare), patch(
                    "src.workbench.smart_audit.agent.consent_preview",
                    side_effect=fake_preview):
                Worker(self.settings).run(once=True)
                operations = Operations(self.store)
                batches = operations.triage_batches_for_job(
                    job["id"], self.store.job(job["id"])["report_sha256"])
                self.assertEqual(len(batches), 1)
                batch = batches[0]
                self.assertEqual(batch["candidate_count"], service.findings(
                    service.read_report(self.settings, self.store.job(job["id"]))).__len__())
                selected_manifest = [row for row in batch["candidate_manifest"]
                                     if row.get("state") == "selected"]
                self.assertGreater(batch["selected_count"], 0)
                self.assertEqual(batch["selected_count"], len(selected_manifest))
                queued = operations.smart_triage_operations(batch["id"])
                self.assertEqual(len(queued), batch["selected_count"])
                self.assertTrue(all(item["status"] == "queued" for item in queued))
                self.assertTrue(all(item["spec"]["mode"] == "single_shot"
                                    and item["spec"]["source_submission_approved"]
                                    and item["spec"]["triage_authorization_sha256"] == consent["consent_sha256"]
                                    for item in queued))

                Worker(self.settings).run(once=True)
                self.assertEqual(len(operations.smart_triage_operations(batch["id"])),
                                 batch["selected_count"])

                # A result-free interrupted Provider call can only be recovered
                # through a new, explicitly billed attempt bound to the same audit.
                old_attempt = operations.smart_triage_operations(batch["id"])[0]
                with self.store.connect() as db:
                    db.execute("UPDATE operations SET status='interrupted',finished_at=? WHERE id=?",
                               ("2026-10-21T00:00:00+00:00", old_attempt["id"]))
                detail = self.client.get(
                    "/api/v1/operations/" + old_attempt["id"], headers=fixtures.HEADERS)
                self.assertEqual(detail.status_code, 200, detail.text)
                self.assertTrue(detail.json()["retry_available"])
                triage = self.client.get(
                    "/api/v1/scans/" + job["id"] + "/triage", headers=fixtures.HEADERS)
                self.assertEqual(triage.status_code, 200, triage.text)
                triage_item = next(item for item in triage.json()["items"]
                                   if item["id"] == old_attempt["id"])
                self.assertTrue(triage_item["retry_available"])
                retry = self.client.post(
                    "/api/v1/operations/" + old_attempt["id"] + "/retry",
                    json={}, headers=fixtures.HEADERS)
                self.assertEqual(retry.status_code, 201, retry.text)
                new_attempt = retry.json()
                self.assertEqual(new_attempt["status"], "queued")
                self.assertEqual(new_attempt["spec"]["retry_parent_operation_id"], old_attempt["id"])
                self.assertEqual(new_attempt["spec"]["retry_root_operation_id"], old_attempt["id"])
                self.assertEqual(new_attempt["spec"]["retry_attempt"], 1)
                for field in ("job_id", "report_sha256", "candidate_id", "smart_triage_batch_id",
                              "triage_authorization_sha256", "source_submission_approved",
                              "source_consent_sha256", "source_sha256", "source_commit"):
                    if field in old_attempt["spec"]:
                        self.assertEqual(new_attempt["spec"].get(field), old_attempt["spec"].get(field), field)
                self.assertEqual(operations.get(old_attempt["id"])["status"], "interrupted")
                self.assertFalse(operations.get(old_attempt["id"])["result_sha256"])
                old_events = operations.events(old_attempt["id"])
                self.assertTrue(any(event["stage"] == "retry_created"
                                    and new_attempt["id"] in event["message"]
                                    and "may bill" in event["message"] for event in old_events))
                retry_events = operations.events(new_attempt["id"])
                self.assertTrue(any(event["stage"] == "queued"
                                    and old_attempt["id"] in event["message"] for event in retry_events))
                updated_batch = operations.triage_batches_for_job(
                    job["id"], self.store.job(job["id"])["report_sha256"])[0]
                self.assertIn(new_attempt["id"], updated_batch["operation_ids"])

                revoked = self.client.post(
                    "/api/v1/scans/" + job["id"] + "/triage/revoke",
                    json={"consent_sha256": consent["consent_sha256"]},
                    headers=fixtures.HEADERS,
                )
                self.assertEqual(revoked.status_code, 200, revoked.text)
                self.assertTrue(revoked.json()["authorization"]["revoked"])
                final_operations = operations.smart_triage_operations(batch["id"])
                self.assertEqual(operations.get(old_attempt["id"])["status"], "interrupted")
                self.assertTrue(all(item["status"] == "cancelled"
                                    for item in final_operations if item["id"] != old_attempt["id"]))

    def test_authorized_smart_queue_persists_all_candidates_above_legacy_100_limit(self):
        import uuid
        from src.workbench.operations_store import Operations

        job = self.scan()
        Worker(self.settings).run(once=True)
        job = self.store.job(job["id"])
        self.assertTrue(job["report_sha256"])
        ops = Operations(self.store)
        batch_id = uuid.uuid4().hex
        authorization_sha = "a" * 64
        candidate_count = 101
        actual_candidates = service.findings(service.read_report(self.settings, job))
        self.assertTrue(actual_candidates)
        risk_candidate = actual_candidates[0]
        manifest = [{"candidate_id": risk_candidate["id"], "state": "selected"}]
        manifest.extend({"candidate_id": "candidate-" + str(index), "state": "selected"}
                        for index in range(1, candidate_count))
        record = {
            "id": batch_id, "audit_id": job["id"],
            "report_sha256": job["report_sha256"],
            "authorization_sha256": authorization_sha,
            "batch_consent_sha256": "b" * 64,
            "candidate_count": candidate_count, "selected_count": candidate_count,
            "candidate_manifest": manifest, "r2_status": "not_requested",
        }
        specs = [{"job_id": job["id"], "report_sha256": job["report_sha256"],
                  "candidate_id": item["candidate_id"],
                  "smart_triage_batch_id": batch_id,
                  "triage_authorization_sha256": authorization_sha,
                  "no_cumulative_token_ceiling": True}
                 for item in manifest]
        saved_batch, created = ops.create_authorized_triage_batch(record, specs)
        self.assertEqual(saved_batch["selected_count"], candidate_count)
        self.assertEqual(len(created), candidate_count)
        self.assertTrue(all(item["status"] == "queued" for item in created))
        recovered = ops.triage_batches_for_job(job["id"], job["report_sha256"])
        self.assertEqual(len(recovered), 1)
        self.assertEqual(len(recovered[0]["operation_ids"]), candidate_count)
        self.assertEqual(len(ops.smart_triage_operations(batch_id)), candidate_count)

        risk_operation = next(item for item in created
                              if item["spec"]["candidate_id"] == risk_candidate["id"])
        claimed = ops.claim()
        self.assertEqual(claimed["id"], risk_operation["id"])
        ops.finish(risk_operation["id"], {
            "status": "completed_with_limitations", "vulnerability_state": "candidate",
            "validated_vulnerability": 0,
            "agent_assessment": {"assessment": "unknown",
                                 "summary": "人工复核授权策略与可达性。"},
        })
        risk_response = self.client.get(
            "/api/v1/scans/" + job["id"] + "/risks", headers=fixtures.HEADERS)
        self.assertEqual(risk_response.status_code, 200, risk_response.text)
        risk_item = next(item for item in risk_response.json()["items"]
                         if item["candidate_id"] == risk_candidate["id"])
        self.assertEqual(risk_item["agent_operations"][0]["operation_id"], risk_operation["id"])
        self.assertEqual(risk_item["agent_operations"][0]["status"], "completed_with_limitations")
        detail = self.client.get("/api/v1/operations/" + risk_operation["id"],
                                 headers=fixtures.HEADERS)
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertEqual(detail.json()["result"]["agent_assessment"]["summary"],
                         "人工复核授权策略与可达性。")
        self.assertEqual(detail.json()["result"]["vulnerability_state"], "candidate")
        self.assertEqual(detail.json()["result"]["validated_vulnerability"], 0)

    def test_overview_risk_summary_is_bounded_evidence_labeled_and_path_free(self):
        job = self.scan()
        Worker(self.settings).run(once=True)
        job = self.store.job(job["id"])
        self.assertTrue(job["report_sha256"])
        response = self.client.get("/api/v1/overview/risks?scan_limit=10",
                                   headers=fixtures.HEADERS)
        self.assertEqual(response.status_code, 200, response.text)
        summary = response.json()
        self.assertEqual(summary["evaluated_scan_count"], 1)
        self.assertEqual(summary["available_report_count"], 1)
        self.assertGreater(summary["candidate_observation_count"], 0)
        self.assertGreater(summary["counts"]["further_validation"], 0)
        first_risk = summary["items"][0]
        self.assertIn("severity", first_risk)
        self.assertIn("confidence_basis", first_risk)
        self.assertEqual(first_risk["vulnerability_state"], "candidate")
        self.assertEqual(summary["validated_vulnerability"], 0)
        self.assertIn("not deduplicated", summary["semantics"])
        self.assertTrue(summary["detector_counts"])
        detector_id = summary["detector_counts"][0]["detector_id"]
        detector_filtered = self.client.get(
            "/api/v1/overview/risks?scan_limit=10&detector_id=" + detector_id,
            headers=fixtures.HEADERS,
        )
        self.assertEqual(detector_filtered.status_code, 200, detector_filtered.text)
        detector_page = detector_filtered.json()
        self.assertEqual(detector_page["filtered_candidate_count"],
                         next(item["candidate_count"] for item in summary["detector_counts"]
                              if item["detector_id"] == detector_id))
        self.assertTrue(all(item["detector_id"] == detector_id
                            for item in detector_page["items"]))
        self.assertNotIn(str(self.root), response.text)
        self.assertTrue(all(item["audit_id"] == job["id"] for item in summary["items"]))
        self.assertTrue(all(not item["file"].startswith("/") for item in summary["items"]))
        self.assertEqual(summary["filtered_candidate_count"], summary["candidate_observation_count"])
        filtered = self.client.get(
            "/api/v1/overview/risks?scan_limit=10&risk_tier=further_validation&limit=1",
            headers=fixtures.HEADERS,
        )
        self.assertEqual(filtered.status_code, 200, filtered.text)
        self.assertEqual(filtered.json()["filtered_candidate_count"],
                         summary["counts"]["further_validation"])
        self.assertLessEqual(len(filtered.json()["items"]), 1)
        if filtered.json()["items"]:
            candidate_id = filtered.json()["items"][0]["candidate_id"]
            searched = self.client.get(
                "/api/v1/overview/risks?scan_limit=10&q=" + candidate_id,
                headers=fixtures.HEADERS,
            )
            self.assertEqual(searched.status_code, 200, searched.text)
            self.assertEqual([item["candidate_id"] for item in searched.json()["items"]],
                             [candidate_id])
        unresolved = self.client.get(
            "/api/v1/overview/risks?scan_limit=10&triage_state=unresolved",
            headers=fixtures.HEADERS,
        )
        self.assertEqual(unresolved.status_code, 200, unresolved.text)
        self.assertEqual(unresolved.json()["filtered_candidate_count"],
                         summary["not_triaged_candidate_count"])
        invalid = self.client.get(
            "/api/v1/overview/risks?risk_tier=confirmed_vulnerability",
            headers=fixtures.HEADERS,
        )
        self.assertEqual(invalid.status_code, 409)
        invalid_detector = self.client.get(
            "/api/v1/overview/risks?detector_id=" + ("x" * 201),
            headers=fixtures.HEADERS,
        )
        self.assertEqual(invalid_detector.status_code, 409)

    def test_risk_overview_surfaces_bound_agent_tendency_without_confirming_vulnerability(self):
        job = self.scan()
        Worker(self.settings).run(once=True)
        job = self.store.job(job["id"])
        report = service.read_report(self.settings, job)
        candidate = service.findings(report)[0]
        operations = Operations(self.store)
        operation = operations.create("agent_investigation", {
            "job_id": job["id"], "report_sha256": job["report_sha256"],
            "candidate_id": candidate["id"], "mode": "tool_agent",
        })
        claimed = operations.claim()
        self.assertEqual(claimed["id"], operation["id"])
        result = {
            "status": "completed_with_limitations",
            "vulnerability_state": "candidate",
            "validated_vulnerability": 0,
            "binding": {
                "job_id": job["id"], "repository": report["repository"],
                "commit": report["commit"], "tree": report.get("tree"),
                "snapshot_sha256": report.get("snapshot_sha256"),
                "report_sha256": job["report_sha256"],
                "candidate_id": candidate["id"], "file": candidate["file"],
                "source_sha256": candidate["source_sha256"],
            },
            "agent_assessment": {"assessment": "likely_true_positive"},
        }
        operations.finish(operation["id"], result=result)
        response = self.client.get("/api/v1/overview/risks?scan_limit=10",
                                   headers=fixtures.HEADERS)
        self.assertEqual(response.status_code, 200, response.text)
        item = next(row for row in response.json()["items"]
                    if row["audit_id"] == job["id"] and row["candidate_id"] == candidate["id"])
        self.assertEqual(item["agent_signal"], {
            "assessment": "likely_true_positive", "label": "模型倾向真实候选",
            "operation_id": operation["id"],
            "human_review_required": True, "product_state": "candidate",
            "evidence_chain_complete": False, "evidence_chain_reason": None,
        })
        self.assertEqual(item["vulnerability_state"], "candidate")
        self.assertEqual(response.json()["validated_vulnerability"], 0)

    def test_complete_agent_evidence_graph_raises_only_candidate_confidence(self):
        job = self.scan()
        Worker(self.settings).run(once=True)
        job = self.store.job(job["id"])
        report = service.read_report(self.settings, job)
        candidate = service.findings(report)[0]
        obligations = candidate.get("evidence", {}).get("obligations", [])
        binding = {
            "job_id": job["id"], "repository": report["repository"],
            "commit": report["commit"], "tree": report.get("tree"),
            "snapshot_sha256": report.get("snapshot_sha256"),
            "report_sha256": job["report_sha256"], "candidate_id": candidate["id"],
            "file": candidate["file"], "source_sha256": candidate["source_sha256"],
        }
        result = build_valid_agent_result(
            binding=binding, candidate_file=candidate["file"],
            obligation_count=len(obligations),
        )
        result["summary"] = "模型分诊倾向：倾向真阳性；结构化主张 1 条；语义仍需人工复核。"
        result["summary_provenance"] = "server_generated_from_structured_triage"
        operations = Operations(self.store)
        operation = operations.create("agent_investigation", {
            "job_id": job["id"], "report_sha256": job["report_sha256"],
            "candidate_id": candidate["id"], "mode": "tool_agent",
        })
        self.assertEqual(operations.claim()["id"], operation["id"])
        operations.finish(operation["id"], result=result)
        self.assertTrue(smart_audit._source_binding_valid(report, candidate), candidate)
        stored_result = operations.result(operation["id"])
        self.assertEqual(stored_result["binding"], result["binding"])
        self.assertEqual(stored_result["mode"], "tool_agent")
        stored_operation = operations.agent_investigations_for_job(
            job["id"], job.get("report_sha256"))[0]
        self.assertIsNotNone(
            smart_audit._agent_signal(operations, stored_operation, job, report, candidate),
            {"operation": stored_operation, "binding": stored_result.get("binding"),
             "agent_assessment": stored_result.get("agent_assessment"),
             "state": stored_result.get("vulnerability_state"),
             "validated": stored_result.get("validated_vulnerability")},
        )

        response = self.client.get("/api/v1/overview/risks?scan_limit=10",
                                   headers=fixtures.HEADERS)
        self.assertEqual(response.status_code, 200, response.text)
        item = next(row for row in response.json()["items"]
                    if row["audit_id"] == job["id"] and row["candidate_id"] == candidate["id"])
        self.assertEqual(item["risk_tier"], "high_confidence_candidate", repr(item.get("agent_signal")))
        self.assertTrue(item["agent_signal"]["evidence_chain_complete"],
                        item["agent_signal"].get("evidence_chain_reason"))
        self.assertEqual(item["confidence_basis"], "agent_evidence_graph")
        self.assertTrue(item["agent_signal"]["evidence_chain_complete"])
        self.assertEqual(item["agent_signal"]["summary"], result["summary"])
        self.assertEqual(item["agent_signal"]["summary_provenance"],
                         "server_generated_from_structured_triage")
        locations = item["agent_signal"]["evidence_locations"]
        self.assertTrue(any(location["file"] != candidate["file"] for location in locations))
        self.assertTrue(all(location["line_start"] >= 1 for location in locations))
        self.assertIn("固定源码引用", item["agent_signal"]["confidence_reason"])
        self.assertEqual(item["vulnerability_state"], "candidate")
        self.assertEqual(response.json()["validated_vulnerability"], 0)
        focused = self.client.get(
            "/api/v1/scans/" + job["id"] + "/risks?candidate_id="
            + candidate["id"] + "&limit=1",
            headers=fixtures.HEADERS,
        )
        self.assertEqual(focused.status_code, 200, focused.text)
        self.assertEqual(focused.json()["total"], 1)
        self.assertEqual(focused.json()["items"][0]["candidate_id"], candidate["id"])

    def test_overview_risk_queue_paginates_after_combined_filters(self):
        job = self.scan()
        Worker(self.settings).run(once=True)
        job = self.store.job(job["id"])
        self.assertTrue(job["report_sha256"])
        items = [
            {"candidate_id": f"candidate-{index}", "file": f"src/sample-{index}.cpp",
             "line": index + 1, "detector_id": "scanner-a" if index < 2 else "scanner-b",
             "rule_id": "test.rule",
             "risk_tier": "further_validation", "risk_tier_label": "待进一步验证",
             "triage": {"state": "selected" if index == 0 else "not_triaged"},
             "reasons": []}
            for index in range(3)
        ]
        snapshot = {
            "counts": {"high_confidence_candidate": 0, "further_validation": 3,
                       "low_priority_manual": 0, "unknown_source_binding": 0},
            "triage_counts": {"selected": 1, "not_triaged": 2},
            "items": items,
        }
        with patch("src.workbench.smart_audit.risk_snapshot", return_value=snapshot):
            response = self.client.get(
                "/api/v1/overview/risks?scan_limit=10&risk_tier=further_validation"
                "&triage_state=unresolved&repository=fixture%2Fsample&offset=1&limit=1",
                headers=fixtures.HEADERS,
            )
            detector_page = self.client.get(
                "/api/v1/overview/risks?scan_limit=10&risk_tier=further_validation"
                "&triage_state=unresolved&repository=fixture%2Fsample&detector_id=scanner-a",
                headers=fixtures.HEADERS,
            )
        self.assertEqual(response.status_code, 200, response.text)
        page = response.json()
        self.assertEqual(page["filtered_candidate_count"], 3)
        self.assertEqual(page["offset"], 1)
        self.assertEqual(page["limit"], 1)
        self.assertEqual(page["detector_counts"], [
            {"detector_id": "scanner-a", "candidate_count": 2},
            {"detector_id": "scanner-b", "candidate_count": 1},
        ])
        self.assertEqual([item["candidate_id"] for item in page["items"]], ["candidate-1"])
        self.assertEqual(detector_page.status_code, 200, detector_page.text)
        self.assertEqual(detector_page.json()["filtered_candidate_count"], 2)
        self.assertEqual({item["detector_id"] for item in detector_page.json()["items"]},
                         {"scanner-a"})

    def test_cancel_triage_preserves_scan_and_prevents_r1_r2_rescheduling(self):
        from src.workbench.operations_store import Operations
        from src.workbench.smart_audit import enqueue_authorized_triage

        def fake_prepare(_settings, _store, _job, _report, _candidate):
            return {"initial_context": {
                "evidence_routing": {"agent_source_review_indices": [0]},
            }}

        def fake_preview(_settings, _store, job, report, candidate, _spec, _provider, prepared=None):
            import hashlib
            return {
                "agent_execution": {"eligible": True},
                "consent_sha256": hashlib.sha256(candidate["id"].encode()).hexdigest(),
                "binding": {"source_sha256": candidate.get("source_sha256"),
                            "commit": report["commit"],
                            "report_sha256": job["report_sha256"]},
            }

        with patch.dict("os.environ", {
            "OHSCANNER_LLM_BASE_URL": "https://api.xiaomimimo.com/v1",
            "OHSCANNER_LLM_MODEL": "mimo-v2.6-pro",
            "OHSCANNER_LLM_API_KEY": "test-provider-key",
        }, clear=False):
            plan = self.plan(auto_triage=True, max_triage_candidates=2, max_r2_candidates=1,
                             max_cost_usd="0.10")
            consent = plan["triage_authorization_preview"]
            job = self.scan(
                auto_triage=True, max_triage_candidates=2, max_r2_candidates=1,
                max_cost_usd="0.10",
                expected_plan_sha256=plan["plan_sha256"],
                expected_workflow_sha256=plan["workflow_sha256"],
                expected_triage_consent_sha256=consent["consent_sha256"],
                triage_consent_nonce=consent["consent_nonce"],
            )
            with patch("src.workbench.smart_audit.agent._prepare_candidate_context",
                       side_effect=fake_prepare), patch(
                    "src.workbench.smart_audit.agent.consent_preview",
                    side_effect=fake_preview):
                Worker(self.settings).run(once=True)
                saved_job = self.store.job(job["id"])
                operations = Operations(self.store)
                batch = operations.triage_batches_for_job(
                    job["id"], saved_job["report_sha256"])[0]
                queued = operations.smart_triage_operations(batch["id"])
                self.assertTrue(queued)
                frozen_limit = saved_job["spec"]["progressive_triage_policy"]["policy"]["limits"]["max_output_tokens_per_request"]
                self.assertTrue(all(item["spec"]["max_output_tokens"] == frozen_limit
                                    for item in queued))
                self.assertEqual(saved_job["status"], "completed_with_limitations")
                self.assertTrue(all(item["status"] == "queued" for item in queued))

                stopped = self.client.post(
                    "/api/v1/scans/" + job["id"] + "/triage/cancel",
                    headers=fixtures.HEADERS,
                )
                self.assertEqual(stopped.status_code, 200, stopped.text)
                self.assertEqual(stopped.json()["state"], "cancelled")
                self.assertTrue(stopped.json()["cancellation"]["stopped"])
                self.assertEqual(stopped.json()["cancellation"]["cancelled_operation_count"],
                                 len(queued))
                self.assertFalse(stopped.json()["authorization"]["revoked"])
                self.assertEqual(self.store.job(job["id"])["status"], "completed_with_limitations")
                self.assertEqual(operations.triage_batch(batch["id"])["r2_status"], "cancelled")
                self.assertTrue(all(item["status"] == "cancelled"
                                    for item in operations.smart_triage_operations(batch["id"])))

                recovered = enqueue_authorized_triage(
                    self.settings, self.store, operations, self.store.job(job["id"]))
                self.assertIsNone(recovered)
                self.assertEqual(len(operations.smart_triage_operations(batch["id"])), len(queued))

    def test_cancel_entire_audit_stops_authorized_triage_before_scan_runs(self):
        from src.workbench.operations_store import Operations
        with patch.dict("os.environ", {
            "OHSCANNER_LLM_BASE_URL": "https://api.xiaomimimo.com/v1",
            "OHSCANNER_LLM_MODEL": "mimo-v2.6-pro",
            "OHSCANNER_LLM_API_KEY": "test-provider-key",
        }, clear=False):
            plan = self.plan(auto_triage=True, max_triage_candidates=1)
            consent = plan["triage_authorization_preview"]
            job = self.scan(
                auto_triage=True, max_triage_candidates=1,
                expected_plan_sha256=plan["plan_sha256"],
                expected_workflow_sha256=plan["workflow_sha256"],
                expected_triage_consent_sha256=consent["consent_sha256"],
                triage_consent_nonce=consent["consent_nonce"],
            )
            cancelled = self.client.post(
                "/api/v1/scans/" + job["id"] + "/cancel", headers=fixtures.HEADERS
            )
            self.assertEqual(cancelled.status_code, 200, cancelled.text)
            self.assertEqual(cancelled.json()["status"], "cancelled")
            self.assertFalse(self.store.triage_authorization(job["id"])["revoked"])
            triage = self.client.get(
                "/api/v1/scans/" + job["id"] + "/triage", headers=fixtures.HEADERS
            ).json()
            self.assertEqual(triage["state"], "cancelled")
            self.assertFalse(triage["scan_progress"]["report_ready"])
            Worker(self.settings).run(once=True)
            self.assertEqual(self.store.job(job["id"])["status"], "cancelled")
            self.assertEqual(Operations(self.store).triage_batches_for_job(job["id"]), [])

    def test_finding_detail_keeps_report_candidate_when_fixed_source_is_unavailable(self):
        job = self.scan()
        Worker(self.settings).run(once=True)
        saved = self.store.job(job["id"])
        report = service.read_report(self.settings, saved)
        candidate = service.findings(report)[0]
        with patch("src.workbench.api.service.source",
                   side_effect=ValueError("repository outside configured target roots")):
            response = self.client.get(
                "/api/v1/scans/" + job["id"] + "/findings/" + candidate["id"],
                headers=fixtures.HEADERS,
            )
        self.assertEqual(response.status_code, 200, response.text)
        detail = response.json()
        self.assertEqual(detail["id"], candidate["id"])
        self.assertIsNone(detail["source"])
        self.assertEqual(detail["source_status"], "unavailable")
        self.assertIn("已批准的本地源码根目录", detail["source_limitation"])
        self.assertNotIn("outside configured target roots", detail["source_limitation"])
        self.assertEqual(detail["evidence"], candidate["evidence"])

    def test_conditional_r2_queues_once_only_for_bound_high_severity_unresolved_source_obligations(self):
        import hashlib
        from src.workbench.operations_store import Operations
        from src.workbench import agent, smart_audit
        from src.workbench.smart_audit import enqueue_authorized_r2_followups

        def fake_prepare(_settings, _store, _job, _report, _candidate):
            return {"initial_context": {
                "evidence_routing": {"agent_source_review_indices": [0]},
            }}

        def fake_preview(_settings, _store, job, report, candidate, spec, _provider, prepared=None):
            return {
                "agent_execution": {"eligible": True},
                "consent_sha256": hashlib.sha256(
                    (candidate["id"] + spec["mode"]).encode()).hexdigest(),
                "binding": {
                    "source_sha256": candidate.get("source_sha256"),
                    "commit": report["commit"],
                    "report_sha256": job["report_sha256"],
                },
            }

        with patch.dict("os.environ", {
            "OHSCANNER_LLM_BASE_URL": "https://api.xiaomimimo.com/v1",
            "OHSCANNER_LLM_MODEL": "mimo-v2.6-pro",
            "OHSCANNER_LLM_API_KEY": "test-provider-key",
        }, clear=False):
            plan = self.plan(auto_triage=True, max_triage_candidates=2, max_r2_candidates=1)
            consent = plan["triage_authorization_preview"]
            self.assertEqual(consent["manifest"]["conditional_r2"]["mode"], "tool_agent")
            self.assertEqual(consent["manifest"]["r2_candidate_limit"], 1)
            budgets = consent["manifest"]["budgets"]
            for key in ("max_total_model_calls", "max_total_tool_calls",
                        "cumulative_token_ceiling", "cumulative_request_ceiling",
                        "cumulative_spend_ceiling"):
                self.assertIsNone(budgets[key], key)
            self.assertEqual(budgets["local_cumulative_token_budget"], "none")
            self.assertEqual(budgets["local_cumulative_usd_budget"], "none")
            self.assertEqual(budgets["local_total_wall_time_budget"],
                             "until terminal response, provider/API error, cancellation, or repeated validation failure")
            job = self.scan(
                auto_triage=True, max_triage_candidates=2, max_r2_candidates=1,
                expected_plan_sha256=plan["plan_sha256"],
                expected_workflow_sha256=plan["workflow_sha256"],
                expected_triage_consent_sha256=consent["consent_sha256"],
                triage_consent_nonce=consent["consent_nonce"],
            )
            with patch("src.workbench.smart_audit.agent._prepare_candidate_context",
                       side_effect=fake_prepare), patch(
                    "src.workbench.smart_audit.agent.consent_preview",
                    side_effect=fake_preview):
                Worker(self.settings).run(once=True)
                ops = Operations(self.store)
                batch = ops.triage_batches_for_job(
                    job["id"], self.store.job(job["id"])["report_sha256"])[0]
                self.assertEqual(batch["r2_status"], "awaiting_r1")
                r1_operations = ops.smart_triage_operations(batch["id"])
                self.assertGreater(len(r1_operations), 0)
                self.assertTrue(all(item["spec"].get("no_cumulative_token_ceiling") is True
                                    for item in r1_operations))
                report = service.read_report(self.settings, self.store.job(job["id"]))
                candidates = []
                completed_r1 = []
                for queued_r1 in r1_operations:
                    claimed = ops.claim()
                    self.assertEqual(claimed["id"], queued_r1["id"])
                    original = service.finding(report, queued_r1["spec"]["candidate_id"])
                    candidate = {**original, "severity": "high"}
                    candidates.append(candidate)
                    obligations = candidate["evidence"]["obligations"]
                    result = {
                        "status": "completed_with_limitations",
                        "binding": {"job_id": job["id"], "candidate_id": candidate["id"],
                                    "report_sha256": queued_r1["spec"]["report_sha256"],
                                    "source_sha256": candidate["source_sha256"]},
                        "initial_evidence": {"context": {
                            "evidence_obligations": obligations,
                            "evidence_routing": {"agent_source_review_indices": [0]},
                        }},
                        "agent_assessment": {
                            "assessment": "needs_more_evidence",
                            "obligation_reviews": [
                                {"obligation_index": index, "disposition": "unresolved"}
                                for index in range(len(obligations))
                            ],
                        },
                    }
                    ops.finish(queued_r1["id"], result)
                    completed_r1.append(ops.get(queued_r1["id"]))
                with patch.object(smart_audit.service, "findings",
                                  return_value=candidates), patch.object(
                        smart_audit, "_source_binding_valid", return_value=True) as source_gate:
                    saved = enqueue_authorized_r2_followups(
                        self.settings, self.store, ops, batch["id"])
                    self.assertTrue(source_gate.called, repr(saved.get("r2_candidate_manifest")))
                    self.assertEqual(saved["r2_status"], "candidate_limit_reached")
                    self.assertEqual(len(saved["r2_operation_ids"]), 1)
                    r2 = ops.get(saved["r2_operation_ids"][0])
                    parent = next(item for item in completed_r1
                                  if item["id"] == r2["spec"]["r1_operation_id"])
                    selected_candidate = next(item for item in candidates
                                              if item["id"] == r2["spec"]["candidate_id"])
                    self.assertEqual(r2["spec"]["mode"], "tool_agent")
                    self.assertEqual(r2["spec"]["max_output_tokens"],
                                     self.store.job(job["id"])["spec"]["progressive_triage_policy"]["policy"]["limits"]["max_output_tokens_per_request"])
                    self.assertFalse(r2["spec"]["continuous_investigation"])
                    self.assertGreater(r2["spec"]["max_steps"], 0)
                    self.assertEqual(r2["spec"]["r1_result_sha256"], parent["result_sha256"])
                    prepared = {
                        "source": {"sha256": selected_candidate["source_sha256"]},
                        "initial_context": {"source_excerpt": "fixed excerpt"},
                    }
                    augmented = agent._apply_conditional_r2_context(
                        self.settings, self.store, r2["spec"], prepared)
                    self.assertEqual(
                        augmented["initial_context"]["conditional_r2_followup"]["unresolved_source_reviewable_obligation_indices"],
                        [0])
                    self.assertIn(parent["result_sha256"],
                                  augmented["initial_context"]["conditional_r2_followup"]["prior_result_sha256"])
                    again = enqueue_authorized_r2_followups(
                        self.settings, self.store, ops, batch["id"])
                    self.assertEqual(again["r2_operation_ids"], saved["r2_operation_ids"])
                    self.assertEqual(len(ops.smart_triage_operations(batch["id"])),
                                     len(completed_r1) + len(saved["r2_operation_ids"]))
                    summary = self.client.get(
                        "/api/v1/scans/" + job["id"] + "/triage",
                        headers=fixtures.HEADERS,
                    )
                    self.assertEqual(summary.status_code, 200, summary.text)
                    batch_view = next(item for item in summary.json()["batches"]
                                      if item["id"] == batch["id"])
                    self.assertEqual(batch_view["conditional_r2"]["state"], "candidate_limit_reached")
                    self.assertEqual(batch_view["conditional_r2"]["operation_ids"],
                                     saved["r2_operation_ids"])
                    revoked = self.client.post(
                        "/api/v1/scans/" + job["id"] + "/triage/revoke",
                        json={"consent_sha256": consent["consent_sha256"]},
                        headers=fixtures.HEADERS,
                    )
                    self.assertEqual(revoked.status_code, 200, revoked.text)
                    self.assertEqual(ops.get(r2["id"])["status"], "cancelled")

    def test_ai_source_evidence_can_raise_review_priority_without_confirming_product_vulnerability(self):
        from src.workbench.operations_store import Operations

        job = self.scan()
        Worker(self.settings).run(once=True)
        job = self.store.job(job["id"])
        report = service.read_report(self.settings, job)
        candidate = service.findings(report)[0]
        ops = Operations(self.store)
        source = service.source(self.settings, self.store, job, candidate["file"])
        citation_quote = source["text"].splitlines()[candidate["line"] - 1].strip()
        self.assertGreaterEqual(len(citation_quote), 8)

        self.assertGreaterEqual(len(candidate["evidence"]["obligations"]), 2,
                                "the relaxed-confidence control needs one supported and one unresolved obligation")

        def create_result(assessment, *, positive):
            operation = ops.create("agent_investigation", {
                "job_id": job["id"], "candidate_id": candidate["id"],
                "report_sha256": job["report_sha256"], "mode": "tool_agent",
            })
            claimed = ops.claim()
            self.assertEqual(claimed["id"], operation["id"])
            obligations = candidate["evidence"]["obligations"]
            review_rows = [
                {"obligation_index": index,
                 "disposition": "evidence_found" if positive and index == 0 else "unresolved",
                 "citations": ([{"evidence_id": "source-1", "file": candidate["file"],
                                 "line_start": candidate["line"], "line_end": candidate["line"],
                                 "quote": citation_quote}]
                               if positive and index == 0 else [])}
                for index in range(len(obligations))
            ]
            if positive:
                self.assertTrue(any(row["disposition"] == "unresolved" for row in review_rows))
            supported_claims = ([{
                "claim": "固定源码中的候选路径到达了需要复核的敏感操作。",
                "obligation_indices": [0],
                "citations": [{"evidence_id": "source-1", "file": candidate["file"],
                               "line_start": candidate["line"], "line_end": candidate["line"],
                               "quote": citation_quote}],
            }] if positive else [])
            result = {
                "status": "completed_with_limitations",
                "structured_answer_validation": "accepted",
                "summary_provenance": "server_generated_from_structured_triage",
                "binding": {"job_id": job["id"], "candidate_id": candidate["id"],
                            "report_sha256": job["report_sha256"], "source_sha256": candidate["source_sha256"],
                            "commit": report["commit"]},
                "citation_integrity": {"quote_presence": "verified_for_all_citations" if positive else "no_citations"},
                "agent_assessment": {
                    "assessment": assessment,
                    "unsupported_claims": [],
                    "supported_claims": supported_claims,
                    "obligation_reviews": review_rows,
                },
                "agent_verdict": {
                    "status": "likely_true_positive" if positive else "needs_more_evidence",
                    "confidence": "medium" if positive else "low",
                    "scope": "fixed_source_code", "product_status": "unknown",
                },
                "initial_evidence": {"context": {
                    "evidence_routing": {
                        "agent_source_review_indices": list(range(len(candidate["evidence"]["obligations"])))},
                }},
                "vulnerability_state": "candidate", "validated_vulnerability": 0,
            }
            ops.finish(operation["id"], result)
            return operation

        create_result("likely_true_positive", positive=True)
        risks = self.client.get("/api/v1/scans/" + job["id"] + "/risks",
                                headers=fixtures.HEADERS)
        self.assertEqual(risks.status_code, 200, risks.text)
        high = next(item for item in risks.json()["items"]
                    if item["candidate_id"] == candidate["id"])
        self.assertEqual(high["risk_tier"], "high_confidence_candidate")
        self.assertEqual(high["confidence_basis"], "ai_source_evidence")
        self.assertEqual(high["ai_summary"], "固定源码中的候选路径到达了需要复核的敏感操作。")
        self.assertEqual(high["ai_evidence"][0]["file"], candidate["file"])
        self.assertEqual(high["ai_evidence"][0]["line_start"], candidate["line"])
        from src.workbench.smart_audit import severity_metadata
        self.assertEqual(high["severity"], severity_metadata(candidate)["severity"])
        self.assertEqual(high["vulnerability_state"], "candidate")
        self.assertEqual(risks.json()["validated_vulnerability"], 0)

        create_result("needs_more_evidence", positive=False)
        latest = self.client.get("/api/v1/scans/" + job["id"] + "/risks",
                                 headers=fixtures.HEADERS)
        self.assertEqual(latest.status_code, 200, latest.text)
        current = next(item for item in latest.json()["items"]
                       if item["candidate_id"] == candidate["id"])
        self.assertEqual(current["risk_tier"], "further_validation")
        self.assertIsNone(current["ai_summary"])
        self.assertEqual(latest.json()["validated_vulnerability"], 0)

    def test_risk_tiers_require_complete_human_evidence_and_report_snapshots_are_immutable(self):
        import hashlib
        from src.workbench.operations_store import Operations

        job = self.scan()
        Worker(self.settings).run(once=True)
        job = self.store.job(job["id"])
        report = service.read_report(self.settings, job)
        candidate = service.findings(report)[0]

        risks = self.client.get("/api/v1/scans/" + job["id"] + "/risks",
                                headers=fixtures.HEADERS)
        self.assertEqual(risks.status_code, 200, risks.text)
        risk_item = next(item for item in risks.json()["items"]
                         if item["candidate_id"] == candidate["id"])
        self.assertEqual(risk_item["risk_tier"], "further_validation")
        self.assertEqual(risk_item["vulnerability_state"], "candidate")
        self.assertEqual(risk_item["triage"]["state"], "not_triaged")

        coverage = self.client.get("/api/v1/scans/" + job["id"] + "/coverage",
                                   headers=fixtures.HEADERS)
        self.assertEqual(coverage.status_code, 200, coverage.text)
        self.assertTrue(coverage.json()["scan_progress"]["report_ready"])
        self.assertEqual(coverage.json()["report_sha256"], job["report_sha256"])

        preview = self.client.get(
            "/api/v1/agent/static-review-preview",
            params={"job_id": job["id"], "candidate_id": candidate["id"]},
            headers=fixtures.HEADERS,
        )
        self.assertEqual(preview.status_code, 200, preview.text)
        quote_line = None
        quote = None
        for raw_line in preview.json()["source"]["text"].splitlines():
            line_number, separator, code = raw_line.partition(":")
            if separator and line_number.isdecimal() and len(code.strip()) >= 8:
                quote_line, quote = int(line_number), code.strip()[:160]
                break
        self.assertIsNotNone(quote_line)
        obligations = candidate["evidence"]["obligations"]
        baseline = self.client.post(
            "/api/v1/agent/baseline-reviews",
            json={
                "job_id": job["id"], "candidate_id": candidate["id"],
                "experiment_id": "risk-tier-control", "reviewer": "test reviewer",
                "disposition": "investigate", "reviewer_acknowledged": True,
                "obligation_reviews": [
                    {"obligation_index": index, "disposition": "evidence_found",
                     "source_line": quote_line, "quote": quote, "notes": "synthetic gate control"}
                    for index in range(len(obligations))
                ],
            },
            headers=fixtures.HEADERS,
        )
        self.assertEqual(baseline.status_code, 201, baseline.text)

        risks_after_review = self.client.get(
            "/api/v1/scans/" + job["id"] + "/risks", headers=fixtures.HEADERS
        ).json()
        high = next(item for item in risks_after_review["items"]
                    if item["candidate_id"] == candidate["id"])
        self.assertEqual(high["risk_tier"], "high_confidence_candidate")
        self.assertEqual(high["evidence_level"], "candidate")
        self.assertEqual(risks_after_review["validated_vulnerability"], 0)

        first = self.client.post("/api/v1/scans/" + job["id"] + "/reports/snapshots",
                                 json={}, headers=fixtures.HEADERS)
        self.assertEqual(first.status_code, 201, first.text)
        first_snapshot = first.json()
        repeated = self.client.post("/api/v1/scans/" + job["id"] + "/reports/snapshots",
                                    json={}, headers=fixtures.HEADERS)
        self.assertEqual(repeated.status_code, 201, repeated.text)
        self.assertEqual(repeated.json()["id"], first_snapshot["id"])

        old_json = self.client.get(
            "/api/v1/scans/" + job["id"] + "/reports/snapshots/"
            + first_snapshot["id"] + "/json", headers=fixtures.HEADERS,
        )
        self.assertEqual(old_json.status_code, 200, old_json.text)
        self.assertEqual(hashlib.sha256(old_json.content).hexdigest(), first_snapshot["json_sha256"])
        old_markdown = self.client.get(
            "/api/v1/scans/" + job["id"] + "/reports/snapshots/"
            + first_snapshot["id"] + "/markdown", headers=fixtures.HEADERS,
        )
        self.assertEqual(old_markdown.status_code, 200, old_markdown.text)
        self.assertEqual(hashlib.sha256(old_markdown.content).hexdigest(), first_snapshot["markdown_sha256"])
        self.assertEqual(next(item for item in old_json.json()["risk_snapshot"]["items"]
                              if item["candidate_id"] == candidate["id"])["risk_tier"],
                         "high_confidence_candidate")

        reviewed = self.client.post(
            "/api/v1/scans/" + job["id"] + "/findings/" + candidate["id"] + "/reviews",
            json={"status": "refuted", "reviewer": "test reviewer",
                  "notes": "new human review changes priority", "expected_id": 0},
            headers=fixtures.HEADERS,
        )
        self.assertEqual(reviewed.status_code, 201, reviewed.text)
        changed = self.client.post("/api/v1/scans/" + job["id"] + "/reports/snapshots",
                                   json={}, headers=fixtures.HEADERS)
        self.assertEqual(changed.status_code, 201, changed.text)
        self.assertNotEqual(changed.json()["id"], first_snapshot["id"])
        latest_risk = self.client.get("/api/v1/scans/" + job["id"] + "/risks",
                                      headers=fixtures.HEADERS).json()
        low = next(item for item in latest_risk["items"]
                   if item["candidate_id"] == candidate["id"])
        self.assertEqual(low["risk_tier"], "low_priority_manual")
        self.assertEqual(low["vulnerability_state"], "candidate")

        old_json_again = self.client.get(
            "/api/v1/scans/" + job["id"] + "/reports/snapshots/"
            + first_snapshot["id"] + "/json", headers=fixtures.HEADERS,
        )
        self.assertEqual(hashlib.sha256(old_json_again.content).hexdigest(), first_snapshot["json_sha256"])
        old_markdown_again = self.client.get(
            "/api/v1/scans/" + job["id"] + "/reports/snapshots/"
            + first_snapshot["id"] + "/markdown", headers=fixtures.HEADERS,
        )
        self.assertEqual(hashlib.sha256(old_markdown_again.content).hexdigest(), first_snapshot["markdown_sha256"])
        self.assertEqual(len(Operations(self.store).audit_report_snapshots(job["id"])), 2)

    def test_zero_candidates_are_reported_as_no_eligible_candidates(self):
        for path in self.repo.glob("*.cpp"):
            path.write_text("int clean_control() { return 0; }\n")
        (self.repo / "index.ets").write_text("export function cleanControl(): number { return 0; }\n")
        fixtures.git(self.repo, "add", ".")
        fixtures.git(self.repo, "commit", "-qm", "zero-candidate control")
        self.commit = fixtures.git(self.repo, "rev-parse", "HEAD")
        job = self.scan()
        Worker(self.settings).run(once=True)
        report = service.read_report(self.settings, self.store.job(job["id"]))
        self.assertEqual(service.findings(report), [])

        response = self.client.get(
            "/api/v1/scans/" + job["id"] + "/triage", headers=fixtures.HEADERS,
        )
        self.assertEqual(response.status_code, 200, response.text)
        summary = response.json()
        self.assertEqual(summary["state"], "no_eligible_candidates")
        self.assertEqual(summary["triage_progress"]["state"], "no_eligible_candidates")
        self.assertEqual(summary["triage_progress"]["candidate_count"], 0)
        self.assertEqual(summary["triage_progress"]["planned_count"], 0)
        self.assertEqual(summary["triage_progress"]["not_triaged_count"], 0)

    def test_js_only_auto_selects_script_detector_and_real_eval_candidate(self):
        (self.repo/'dynamic.js').write_text('export function run(input) { eval(input); }\n')
        fixtures.git(self.repo, 'add', '.')
        fixtures.git(self.repo, 'commit', '-qm', 'script control')
        self.commit = fixtures.git(self.repo, 'rev-parse', 'HEAD')
        plan = self.plan(include_paths=['dynamic.js'])
        self.assertEqual(plan['suggested_detector_ids'], ['ohscanner.oh.arkts_js'])
        self.assertTrue(all(d['decision']=='skipped' for d in plan['detectors']
                            if d['id'] != 'ohscanner.oh.arkts_js' and not d.get('admission')))
        self.assertTrue(all(d['decision']=='blocked' for d in plan['detectors'] if d.get('admission')))
        job = self.scan(include_paths=['dynamic.js'])
        Worker(self.settings).run(once=True)
        report = service.read_report(self.settings, self.store.job(job['id']))
        self.assertEqual(len(report['detector_runs']), 1)
        run = report['detector_runs'][0]
        self.assertEqual(run['tool'], 'ohscanner.oh.arkts_js')
        self.assertTrue(any(d['rule_id']=='ohscanner.js.dangerous_eval' for d in run['diagnostics']))

    def test_legacy_explicit_selection_still_runs_only_requested_ids(self):
        job = self.scan(detector_ids=fixtures.IDS)
        self.assertEqual(job['spec']['detector_ids'], fixtures.IDS)
        self.assertEqual(job['spec']['audit_plan']['selection_mode'], 'explicit')
        Worker(self.settings).run(once=True)
        report = service.read_report(self.settings, self.store.job(job['id']))
        self.assertEqual({r['tool'] for r in report['detector_runs']}, set(fixtures.IDS))

    def test_preview_does_not_enqueue_and_empty_selection_is_not_auto(self):
        plan = self.plan(detector_ids=[])
        self.assertEqual(plan['suggested_detector_ids'], [])
        self.assertEqual(plan['status'], 'blocked')
        self.assertEqual(self.store.jobs(), [])
        r = self.client.post('/api/v1/scans', json=self.request(detector_ids=[]), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 422)
        self.assertEqual(self.store.jobs(), [])

    def test_default_scan_includes_all_research_candidates_and_explicit_subsets_still_work(self):
        c_id = 'ohscanner.ark.runtime.type_safety'
        plan = self.plan(detector_ids=[c_id])
        self.assertEqual(plan['selection_mode'], 'explicit')
        self.assertEqual(plan['suggested_detector_ids'], [c_id])
        self.assertEqual(self.store.jobs(), [])

        d_id = 'ohscanner.data.sensitive_exposure'
        automatic = self.plan()
        d_row = next(row for row in automatic['detectors'] if row['id'] == d_id)
        self.assertEqual(d_row['decision'], 'planned')
        self.assertIn(d_id, automatic['suggested_detector_ids'])
        # Unknown-source fallback should preserve a name-based finding through
        # the same API -> Worker -> report path, without changing its status.
        (self.repo/'sensitive.cpp').write_text('''void logCredential(const char *password) {
            HILOG_INFO(1, "%{public}s", password);
        }
''')
        fixtures.git(self.repo, 'add', 'sensitive.cpp')
        fixtures.git(self.repo, 'commit', '-qm', 'unknown-source candidate fixture')
        self.commit = fixtures.git(self.repo, 'rev-parse', 'HEAD')
        plan = self.plan(detector_ids=[d_id])
        self.assertEqual(plan['suggested_detector_ids'], [d_id])
        job = self.scan(detector_ids=[d_id], expected_plan_sha256=plan['plan_sha256'])
        self.assertEqual(job['spec']['detector_ids'], [d_id])
        Worker(self.settings).run(once=True)
        completed = self.store.job(job['id'])
        self.assertEqual(completed['status'], 'completed_with_limitations')
        report = service.read_report(self.settings, completed)
        run = next(item for item in report['detector_runs'] if item['tool'] == d_id)
        self.assertEqual(run['status'], 'blocked')
        self.assertIn('No reviewed sensitive-source model', ' '.join(run['limitations']))
        self.assertTrue(any(item['rule_id'] == 'data.log.sensitive-value'
                            for item in run['diagnostics']))
        self.assertEqual(run['tool_version'], '0.21.17')
        self.assertEqual(report['validated_vulnerability'], 0)

    def test_changed_branch_after_preview_requires_new_plan(self):
        plan = self.plan(revision='HEAD')
        (self.repo/'later.cpp').write_text('int later(){ return 0; }\n')
        fixtures.git(self.repo, 'add', '.')
        fixtures.git(self.repo, 'commit', '-qm', 'branch advanced')
        r = self.client.post('/api/v1/scans', json=self.request(
            revision='HEAD', expected_plan_sha256=plan['plan_sha256']), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 409, r.text)
        self.assertEqual(self.store.jobs(), [])

    def test_tampered_queued_plan_fails_without_published_result(self):
        job = self.scan()
        spec = job['spec']; spec['audit_plan']['metadata_sha256'] = '0'*64
        with self.store.connect() as db:
            db.execute('UPDATE jobs SET spec=? WHERE id=?', (json.dumps(spec), job['id']))
        Worker(self.settings).run(once=True)
        result = self.store.job(job['id'])
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['report_sha256'])
        log = service.artifact_dir(self.settings, job['id'])/'worker.log'
        self.assertIn('Frozen audit plan drifted', log.read_text())

    def test_planning_timeout_does_not_enqueue(self):
        run = subprocess.run
        def timeout_only_planner(args, **kwargs):
            if 'src.workbench.plan_child' in args:
                raise subprocess.TimeoutExpired(args, 35)
            return run(args, **kwargs)
        with patch('src.workbench.service.subprocess.run', side_effect=timeout_only_planner):
            r = self.client.post('/api/v1/scans', json=self.request(), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 409)
        self.assertIn('deadline exceeded', r.text)
        self.assertEqual(self.store.jobs(), [])

    def test_client_header_and_cross_origin_still_required_for_plan_preview(self):
        r = self.client.post('/api/v1/audit-plans', json=self.request())
        self.assertEqual(r.status_code, 403)
        r = self.client.post('/api/v1/audit-plans', json=self.request(),
                             headers={**fixtures.HEADERS, 'origin':'https://untrusted.example'})
        self.assertEqual(r.status_code, 403)

    def test_registered_null_rule_requires_explicit_selection(self):
        plan = self.plan(detector_ids=['ohscanner.cpp.null_dereference'])
        self.assertEqual(plan['suggested_detector_ids'], ['ohscanner.cpp.null_dereference'])
        self.assertEqual(plan['selection_mode'], 'explicit')

    def test_report_budget_rejects_before_creating_truncated_artifact(self):
        from src.ohscanner.execution import write_report_json
        target = self.root/'bounded.json'
        with patch('src.ohscanner.execution.MAX_REPORT_BYTES', 8):
            with self.assertRaisesRegex(ValueError, 'publication budget'):
                write_report_json({'too_large': 'sample'}, target)
        self.assertFalse(target.exists())
        self.assertFalse(target.with_suffix('.json.tmp').exists())

    def test_changed_candidate_and_cost_budgets_require_new_authorization(self):
        with patch.dict("os.environ", {
            "OHSCANNER_LLM_BASE_URL": "https://api.xiaomimimo.com/v1",
            "OHSCANNER_LLM_MODEL": "mimo-v2.6-pro",
            "OHSCANNER_LLM_API_KEY": "test-provider-key",
        }, clear=False):
            no_budget = self.client.post(
                "/api/v1/audit-plans",
                json=self.request(auto_triage=True, max_triage_candidates=1),
                headers=fixtures.HEADERS,
            )
            self.assertEqual(no_budget.status_code, 200, no_budget.text)
            cost_budget = no_budget.json()["triage_authorization_preview"]["cost_budget"]
            self.assertEqual(cost_budget["status"], "unbounded_local_usage")
            self.assertFalse(cost_budget["hard_spend_cap"])
            self.assertEqual(cost_budget["local_cumulative_usd_budget"], "none")
            self.assertFalse(no_budget.json()["triage_authorization_preview"]["platform_cost_budget_enforced"])

            plan = self.plan(auto_triage=True, max_triage_candidates=1,
                             max_r2_candidates=0, max_cost_usd="10.00")
            changed_plan = self.plan(auto_triage=True, max_triage_candidates=500,
                                     max_r2_candidates=100, max_cost_usd="5000")
            self.assertNotEqual(plan["workflow_sha256"], changed_plan["workflow_sha256"])
            consent = plan["triage_authorization_preview"]
            accepted = self.client.post(
                "/api/v1/scans",
                json=self.request(
                    auto_triage=True, max_triage_candidates=500, max_r2_candidates=100,
                    max_cost_usd="5000",
                    expected_plan_sha256=plan["plan_sha256"],
                    expected_workflow_sha256=plan["workflow_sha256"],
                    expected_triage_consent_sha256=consent["consent_sha256"],
                    triage_consent_nonce=consent["consent_nonce"],
                ),
                headers=fixtures.HEADERS,
            )
            self.assertEqual(accepted.status_code, 409, accepted.text)

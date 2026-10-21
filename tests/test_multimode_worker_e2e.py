"""End-to-end tests for consented multi-endpoint date and version scans.

These tests exercise the real fixed-commit scanner Worker and the production
OperationWorker child boundary. A test-only sitecustomize replaces the model
client; it verifies wiring and source binding only, never model correctness.
The fake Provider URL is loopback-only so a missing test hook cannot reach an
external service.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.workbench.api import create_app
from src.workbench.operations_store import Operations
from src.workbench.operation_worker import OperationWorker
from src.workbench.service import findings, read_report
from src.workbench.settings import Settings
from src.workbench.store import Store
from src.workbench.worker import Worker


ROOT = Path(__file__).resolve().parents[1]
HEADERS = {"x-ohscanner-client": "workbench-v1"}
DETECTORS = ["ohscanner.cpp.lifetime"]
PROVIDER_ENV = {
    "OHSCANNER_LLM_BASE_URL": "https://127.0.0.1/v1",
    "OHSCANNER_LLM_MODEL": "offline-e2e-fixture",
    "OHSCANNER_LLM_API_KEY": "offline-test-only-key",
    "OHSCANNER_LLM_PROXY_URL": "",
}


@unittest.skipUnless(os.name == "posix", "OperationWorker child limits require Linux/WSL")
class MultiModeWorkerE2ETests(unittest.TestCase):
    """Fixed-source API → scan Worker → automatic Agent child → persisted progress."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo_path = self.root / "targets" / "repo"
        self.repo_path.mkdir(parents=True)
        fixture = ROOT / "tests" / "detectors" / "fixtures" / "cpp_lifetime" / "vulnerable_unserialized.cpp"
        (self.repo_path / "demo.cpp").write_text(fixture.read_text())
        (self.repo_path / "endpoint-note.txt").write_text("fixed endpoint zero\n")
        subprocess.run(["git", "init", "-q"], cwd=self.repo_path, check=True)
        subprocess.run(["git", "config", "user.name", "offline-fixture"], cwd=self.repo_path, check=True)
        subprocess.run(["git", "config", "user.email", "offline@example.invalid"], cwd=self.repo_path, check=True)
        self.commits = []
        self._commit("2025-01-01T00:00:00Z", "baseline")
        (self.repo_path / "endpoint-note.txt").write_text("fixed endpoint one\n")
        self._commit("2025-01-02T00:00:00Z", "first update")
        (self.repo_path / "endpoint-note.txt").write_text("fixed endpoint two\n")
        self._commit("2025-01-03T00:00:00Z", "second update")
        (self.repo_path / "endpoint-note.txt").write_text("fixed endpoint three\n")
        self._commit("2025-01-04T00:00:00Z", "third update")
        subprocess.run(["git", "branch", "-M", "main"], cwd=self.repo_path, check=True)

        self.settings = Settings(self.root / "data", (self.root / "targets",))
        self.client = TestClient(create_app(self.settings))
        self.addCleanup(self.client.close)
        self.store = Store(self.settings.data_dir)
        registered = self.client.post("/api/v1/repositories", headers=HEADERS,
            json={"name": "openharmony/multimode-fixture", "path": str(self.repo_path)})
        self.assertEqual(registered.status_code, 201, registered.text)
        self.repo = registered.json()

    def _commit(self, stamp, message):
        subprocess.run(["git", "add", "."], cwd=self.repo_path, check=True)
        env = {**os.environ,
            "GIT_AUTHOR_NAME": "offline-fixture", "GIT_AUTHOR_EMAIL": "offline@example.invalid",
            "GIT_COMMITTER_NAME": "offline-fixture", "GIT_COMMITTER_EMAIL": "offline@example.invalid",
            "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp}
        subprocess.run(["git", "commit", "-q", "-m", message], cwd=self.repo_path,
                       env=env, check=True)
        self.commits.append(subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo_path, text=True).strip())

    def _static_scan(self, commit):
        response = self.client.post("/api/v1/scans", headers=HEADERS, json={
            "repository_id": self.repo["id"], "revision": commit,
            "include_paths": ["."], "detector_ids": DETECTORS,
            "timeout_seconds": 90, "memory_mb": 1024, "audit_mode": "static_only"})
        self.assertEqual(response.status_code, 201, response.text)
        Worker(self.settings).run(once=True)
        job = self.store.job(response.json()["id"])
        self.assertIn(job["status"], {"completed", "completed_with_limitations"}, job)
        self.assertTrue(job.get("report_sha256"), job)
        report = read_report(self.settings, job)
        self.assertEqual(report["validated_vulnerability"], 0)
        return job, report

    def _create_matrix_case(self):
        job, report = self._static_scan(self.commits[0])
        candidates = findings(report)
        self.assertTrue(candidates, "the pinned positive fixture must emit a static candidate")
        response = self.client.post("/api/v1/cases", headers=HEADERS, json={
            "title": "Offline version-matrix fixture",
            "links": [{"job_id": job["id"], "candidate_id": candidates[0]["id"],
                       "rationale": "Test-only fixed-source control; not a vulnerability confirmation."}]})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    def _preview_and_submit(self, kind, route, payload, expected_commits):
        with patch.dict(os.environ, PROVIDER_ENV, clear=False):
            preview_response = self.client.post("/api/v1/operations/scan-previews",
                headers=HEADERS, json={"kind": kind, "payload": payload})
            self.assertEqual(preview_response.status_code, 200, preview_response.text)
            preview = preview_response.json()["triage_authorization_preview"]
            self.assertTrue(preview["eligible"], preview)
            scans = preview["scans"]
            self.assertEqual([item["commit"] for item in scans], expected_commits)
            self.assertTrue(all(item.get("consent_nonce") and item.get("consent_sha256") for item in scans))
            # A repeated commit in two date windows still receives two independent approvals.
            self.assertEqual(len({item["consent_nonce"] for item in scans}), len(scans))
            approvals = [{"consent_nonce": item["consent_nonce"],
                          "consent_sha256": item["consent_sha256"]} for item in scans]
            created = self.client.post(route, headers=HEADERS,
                                       json={**payload, "triage_approvals": approvals})
        self.assertEqual(created.status_code, 201, created.text)
        operation = created.json()
        self.assertEqual(operation["spec"]["audit_mode"], "standard_review")
        self.assertEqual(len(operation["spec"]["scan_ids"]), len(scans))
        for scan_id, approved in zip(operation["spec"]["scan_ids"], scans):
            job = self.store.job(scan_id)
            authorization = self.store.triage_authorization(scan_id)
            self.assertEqual(job["spec"]["commit"], approved["commit"])
            self.assertTrue(authorization and not authorization["revoked"])
            self.assertEqual(authorization["consent_sha256"], approved["consent_sha256"])
            binding = authorization["snapshot"]["binding"]
            self.assertEqual(binding["commit"], job["spec"]["commit"])
            self.assertEqual(binding["tree"], job["spec"]["git_tree"])
            self.assertEqual(binding["plan_sha256"], job["spec"]["plan_sha256"])
        return operation, scans

    def _fake_provider_environment(self):
        fake_provider_dir = self.root / "offline-fake-provider"
        fake_provider_dir.mkdir()
        fake_provider_dir.joinpath("sitecustomize.py").write_text(r'''
import json
import os

if os.environ.get("OHSCANNER_TEST_PROVIDER_TRACE"):
    from src.workbench import agent

    class FakeResponsesClient:
        def __init__(self, *args, **kwargs):
            self.traced = False
            self.tool_call_sent = False

        def create_with_timeout(self, request, timeout):
            fail_mode = os.environ.get("OHSCANNER_TEST_PROVIDER_FAIL", "")
            fail_commit = (fail_mode.split(":", 1)[1]
                           if fail_mode.startswith("quota:") else "")
            if fail_mode == "quota" or (
                    fail_commit and any(
                        context.get("commit") == fail_commit
                        or context.get("source_commit") == fail_commit
                        for context in self._contexts(request))):
                raise agent.ProviderQuotaError("offline provider quota fixture")
            return self.create(request)

        @staticmethod
        def _contexts(request):
            contexts = []
            for item in request.get("input", []):
                content = item.get("content", []) if isinstance(item, dict) else []
                if isinstance(content, str):
                    parts = [content]
                elif isinstance(content, list):
                    parts = [part.get("text") for part in content if isinstance(part, dict)]
                else:
                    parts = []
                for text in parts:
                    if not isinstance(text, str):
                        continue
                    try:
                        value = json.loads(text)
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if isinstance(value, dict):
                        contexts.append(value)
            return contexts

        @staticmethod
        def _response(value):
            return {"status": "completed", "output": [{"type": "message", "content": [
                {"type": "output_text", "text": json.dumps(value)}]}],
                "usage": {"input_tokens": 120, "output_tokens": 30, "total_tokens": 150}}

        @staticmethod
        def _investigation(context):
            obligations = context.get("evidence_obligations", [])
            return {
                "summary": "Offline synthetic triage; human review remains required.",
                "assessment": "needs_more_evidence",
                "supported_claims": [],
                "obligation_reviews": [
                    {"obligation_index": index, "disposition": "unresolved", "citations": []}
                    for index in range(len(obligations))],
                "unsupported_claims": [],
                "unknowns": ["Product reachability and impact remain unverified."],
                "next_steps": ["Review fixed-source evidence and product entry points."],
            }

        def create(self, request, **kwargs):
            contexts = self._contexts(request)
            context = next((item for item in contexts if item.get("candidate_id")
                            and item.get("commit") and item.get("report_sha256")
                            and item.get("source_sha256") and item.get("evidence_id")), {})
            obligations = context.get("evidence_obligations", [])
            required = ("candidate_id", "commit", "report_sha256", "source_sha256", "evidence_id")
            if not self.traced:
                if not obligations or any(not context.get(key) for key in required):
                    raise ValueError("fake Provider received incomplete fixed-source context")
                trace = {key: context[key] for key in required}
                trace["obligation_count"] = len(obligations)
                with open(os.environ["OHSCANNER_TEST_PROVIDER_TRACE"], "a", encoding="utf-8") as stream:
                    stream.write(json.dumps(trace) + "\n")
                self.traced = True

            format_name = request.get("text", {}).get("format", {}).get("name")
            if format_name == "ohscanner_skeptic_review":
                skeptic_context = next((item for item in contexts
                    if "obligations_are_untrusted_routing_metadata" in item), {})
                return self._response({"reviews": [
                    {"obligation_index": item["obligation_index"], "result": "unknown", "citations": []}
                    for item in skeptic_context.get("obligations_are_untrusted_routing_metadata", [])]})

            if format_name == "ohscanner_candidate_artifacts":
                artifact_context = next((item for item in contexts if item.get("source_evidence")), {})
                evidence = artifact_context["source_evidence"][0]
                first_line = evidence["numbered_lines"].splitlines()[0]
                line_number = int(first_line.split(":", 1)[0])
                citation = {"evidence_id": evidence["evidence_id"], "file": evidence["file"],
                            "line_start": line_number, "line_end": line_number}
                return self._response({
                    "vulnerability_report": {
                        "title": "Fixed-source candidate",
                        "summary": "Synthetic offline draft; product impact remains unknown.",
                        "root_cause": "The source candidate requires independent review.",
                        "impact": "Product reachability and impact are unknown.",
                        "preconditions": ["A product caller reaches the source path."],
                        "attack_path": ["Caller", "Candidate source path"],
                        "remediation": "Review the applicable product policy.",
                        "citations": [citation]},
                    "poc_draft": {
                        "title": "Offline test draft", "language": "C++",
                        "code": "// Draft only; do not execute without human review.\n",
                        "prerequisites": ["Use an isolated local test target."],
                        "run_steps": ["Review this draft before use."],
                        "expected_observation": "A human-reviewed test observes the candidate behavior.",
                        "negative_control": "A permitted control path remains unaffected.",
                        "citations": [citation]},
                })

            if "tools" in request and not any(item.get("type") == "function_call_output"
                                                for item in request.get("input", [])):
                return {"status": "completed", "output": [{
                    "type": "function_call", "name": "read_candidate_source",
                    "arguments": "{}", "call_id": "offline-fixed-source-read"}],
                    "usage": {"input_tokens": 120, "output_tokens": 30, "total_tokens": 150}}
            return self._response(self._investigation(context))

    agent.ResponsesClient = FakeResponsesClient
''')
        old_pythonpath = os.environ.get("PYTHONPATH", "")
        pythonpath = os.pathsep.join(part for part in (
            str(fake_provider_dir), str(ROOT), old_pythonpath) if part)
        trace_path = self.root / "offline-provider-trace.jsonl"
        return {"PYTHONPATH": pythonpath,
                "OHSCANNER_TEST_PROVIDER_TRACE": str(trace_path),
                **PROVIDER_ENV}, trace_path

    def _finish_operation_scans(self, operation):
        # Run only the real static scan Worker here. The operation queue also
        # contains the comparison parent and auto-authorized Agent children;
        # those must wait until the fake Provider hook is installed below.
        for scan_id in operation["spec"]["scan_ids"]:
            with patch.dict(os.environ, PROVIDER_ENV, clear=False):
                Worker(self.settings).run(once=True)
            job = self.store.job(scan_id)
            self.assertIn(job["status"], {"completed", "completed_with_limitations"}, job)
            self.assertTrue(job.get("report_sha256"), job)
            report = read_report(self.settings, job)
            self.assertEqual(report["validated_vulnerability"], 0)

    def _finish_agent_children(self, operation, preview_scans, *, expect_r2=False):
        ops = Operations(self.store)
        endpoint_batches = []
        expected_agent_ids = []
        for scan_id, preview in zip(operation["spec"]["scan_ids"], preview_scans):
            job = self.store.job(scan_id)
            self.assertEqual(job["spec"]["commit"], preview["commit"])
            report = read_report(self.settings, job)
            self.assertTrue(findings(report), f"fixed endpoint {preview['commit']} must retain a candidate")
            batches = ops.triage_batches_for_job(scan_id, job["report_sha256"])
            self.assertEqual(len(batches), 1, (scan_id, batches))
            batch = batches[0]
            self.assertEqual(batch["status"], "queued", batch)
            self.assertGreater(batch["candidate_count"], 0, batch)
            self.assertEqual(batch["selected_count"], 1, batch)
            tasks = ops.smart_triage_operations(batch["id"])
            self.assertEqual(len(tasks), 1, tasks)
            task = tasks[0]
            self.assertEqual(task["kind"], "agent_investigation")
            self.assertEqual(task["status"], "queued", task)
            self.assertEqual(task["spec"]["mode"], "single_shot")
            self.assertEqual(task["spec"]["source_commit"], job["spec"]["commit"])
            self.assertEqual(task["spec"]["report_sha256"], job["report_sha256"])
            self.assertEqual(task["spec"]["triage_authorization_sha256"],
                             self.store.triage_authorization(scan_id)["consent_sha256"])
            expected_agent_ids.append(task["id"])
            endpoint_batches.append(batch)

        worker_env, trace_path = self._fake_provider_environment()
        r2_operation_ids = []
        with patch.dict(os.environ, worker_env, clear=False):
            # OperationWorker --once executes exactly one claimed operation.
            # The comparison parent was queued before scan-time Agent children.
            OperationWorker(self.settings).run(once=True)
            parent = ops.get(operation["id"])
            self.assertIn(parent["status"], {"completed", "completed_with_limitations"}, parent)
            self.assertEqual(ops.result(operation["id"])["validated_vulnerability"], 0)

            for task_id in expected_agent_ids:
                OperationWorker(self.settings).run(once=True)
                finished = ops.get(task_id)
                self.assertIn(finished["status"], {"completed", "completed_with_limitations"},
                    {"operation": finished,
                     "worker_log": (ops.directory(task_id) / "worker.log").read_text(errors="replace")})
                result = ops.result(task_id)
                self.assertEqual(result["vulnerability_state"], "candidate")
                self.assertEqual(result["validated_vulnerability"], 0)
                self.assertEqual(result["binding"]["commit"], finished["spec"]["source_commit"])
                self.assertEqual(result["binding"]["report_sha256"], finished["spec"]["report_sha256"])
                self.assertTrue((ops.directory(task_id) / "child-result.json").is_file())
                self.assertNotIn(PROVIDER_ENV["OHSCANNER_LLM_API_KEY"], json.dumps(result))

            for batch in endpoint_batches:
                current = ops.triage_batch(batch["id"])
                r2_operation_ids.extend(current["r2_operation_ids"])
            if expect_r2:
                self.assertTrue(r2_operation_ids,
                    [ops.triage_batch(batch["id"]) for batch in endpoint_batches])
            else:
                self.assertFalse(r2_operation_ids, r2_operation_ids)
            for task_id in r2_operation_ids:
                OperationWorker(self.settings).run(once=True)
                finished = ops.get(task_id)
                self.assertIn(finished["status"], {"completed", "completed_with_limitations"},
                    {"operation": finished,
                     "worker_log": (ops.directory(task_id) / "worker.log").read_text(errors="replace")})
                result = ops.result(task_id)
                self.assertEqual(result["vulnerability_state"], "candidate")
                self.assertEqual(result["validated_vulnerability"], 0)
                self.assertEqual(result["binding"]["commit"], finished["spec"]["source_commit"])
                self.assertEqual(result["binding"]["report_sha256"], finished["spec"]["report_sha256"])
                self.assertEqual(result["artifact_generation"]["status"], "completed")
                self.assertEqual(result["agent_assessment"]["vulnerability_report"]["status"], "draft_unverified")
                # This E2E R1 intentionally has needs_more_evidence and no supported claims.
                # Draft generation may complete, but it must not retain an executable-looking PoC.
                self.assertEqual(result["agent_assessment"]["poc_draft"]["status"], "insufficient_evidence")
                self.assertEqual(result["agent_assessment"]["poc_draft"]["code"], "")
                self.assertTrue(result["agent_assessment"]["poc_draft"]["citations"])
                self.assertNotIn(PROVIDER_ENV["OHSCANNER_LLM_API_KEY"], json.dumps(result))

        all_agent_ids = expected_agent_ids + r2_operation_ids
        trace = [json.loads(line) for line in trace_path.read_text().splitlines()]
        self.assertEqual(len(trace), len(all_agent_ids), trace)
        self.assertTrue(all(item["obligation_count"] > 0 for item in trace))
        expected_sources = {
            (task["spec"]["source_commit"], task["spec"]["report_sha256"], task["spec"]["candidate_id"])
            for task_id in all_agent_ids for task in [ops.get(task_id)]
        }
        self.assertEqual({(item["commit"], item["report_sha256"], item["candidate_id"])
                          for item in trace}, expected_sources)

        status = self.client.get("/api/v1/operations/" + operation["id"], headers=HEADERS)
        self.assertEqual(status.status_code, 200, status.text)
        operation_view = status.json()
        self.assertIn(operation_view["status"], {"completed", "completed_with_limitations"}, operation_view)
        self.assertEqual(operation_view["result"]["status"], "completed_with_limitations")
        self.assertEqual(operation_view["result"]["validated_vulnerability"], 0)
        progress = operation_view["intelligent_review_progress"]
        self.assertEqual(len(progress), len(operation["spec"]["scan_ids"]))
        for item, batch in zip(progress, endpoint_batches):
            expected_state = ("completed" if batch["selected_count"] == batch["candidate_count"]
                              else "partially_completed")
            if expected_state == "completed":
                self.assertIn(item["agent_status"], {"completed", "completed_with_limitations"}, item)
            else:
                self.assertEqual(item["agent_status"], expected_state, item)
            self.assertTrue(item["agent_authorized"], item)
            self.assertTrue(item["report_available"], item)
            self.assertEqual(item["r1_selected_count"], batch["selected_count"])
            self.assertEqual(item["candidate_count"], batch["candidate_count"])
            self.assertFalse(item["model_result_is_product_vulnerability_confirmation"])
        return operation_view

    def _create_single_intelligent_scan(self):
        payload = {
            "repository_id": self.repo["id"], "revision": self.commits[0],
            "include_paths": ["."], "detector_ids": DETECTORS,
            "timeout_seconds": 90, "memory_mb": 1024,
            "audit_mode": "standard_review", "auto_triage": True,
            "max_triage_candidates": 1, "max_r2_candidates": 0,
        }
        with patch.dict(os.environ, PROVIDER_ENV, clear=False):
            planned = self.client.post("/api/v1/audit-plans", headers=HEADERS, json=payload)
        self.assertEqual(planned.status_code, 200, planned.text)
        plan = planned.json()
        consent = plan["triage_authorization_preview"]
        self.assertTrue(consent["eligible"], consent)
        with patch.dict(os.environ, PROVIDER_ENV, clear=False):
            created = self.client.post("/api/v1/scans", headers=HEADERS, json={
                **payload, "expected_plan_sha256": plan["plan_sha256"],
                "expected_workflow_sha256": plan["workflow_sha256"],
                "expected_triage_consent_sha256": consent["consent_sha256"],
                "triage_consent_nonce": consent["consent_nonce"],
            })
        self.assertEqual(created.status_code, 201, created.text)
        scan_id = created.json()["id"]
        with patch.dict(os.environ, PROVIDER_ENV, clear=False):
            Worker(self.settings).run(once=True)
        job = self.store.job(scan_id)
        self.assertEqual(job["status"], "completed", job)
        self.assertEqual(job["spec"]["audit_mode"], "standard_review")
        self.assertIsNotNone(self.store.triage_authorization(scan_id))
        report = read_report(self.settings, job)
        self.assertTrue(findings(report))
        self.assertEqual(report["validated_vulnerability"], 0)
        ops = Operations(self.store)
        batches = ops.triage_batches_for_job(scan_id, job["report_sha256"])
        self.assertEqual(len(batches), 1, batches)
        self.assertEqual(batches[0]["selected_count"], 1, batches[0])
        tasks = ops.smart_triage_operations(batches[0]["id"])
        self.assertEqual(len(tasks), 1, tasks)
        return job, report, ops, batches[0], tasks[0]

    def test_single_repository_intelligent_scan_authorizes_and_runs_fixed_candidate_r1(self):
        job, _report, ops, batch, task = self._create_single_intelligent_scan()
        worker_env, trace_path = self._fake_provider_environment()
        with patch.dict(os.environ, worker_env, clear=False):
            OperationWorker(self.settings).run(once=True)
        finished = ops.get(task["id"])
        self.assertIn(finished["status"], {"completed", "completed_with_limitations"}, finished)
        result = ops.result(task["id"])
        self.assertEqual(result["vulnerability_state"], "candidate")
        self.assertEqual(result["validated_vulnerability"], 0)
        self.assertEqual(result["binding"]["commit"], job["spec"]["commit"])
        self.assertEqual(result["binding"]["report_sha256"], job["report_sha256"])
        self.assertEqual(ops.triage_batch(batch["id"])["selected_count"], 1)
        trace = [json.loads(line) for line in trace_path.read_text().splitlines()]
        self.assertTrue(trace)
        self.assertTrue(all(row["commit"] == job["spec"]["commit"] for row in trace))

    def test_provider_quota_failure_keeps_the_completed_static_report_available(self):
        job, report, ops, _batch, task = self._create_single_intelligent_scan()
        worker_env, _trace_path = self._fake_provider_environment()
        worker_env["OHSCANNER_TEST_PROVIDER_FAIL"] = "quota"
        with patch.dict(os.environ, worker_env, clear=False):
            OperationWorker(self.settings).run(once=True)
        failed = ops.get(task["id"])
        self.assertEqual(failed["status"], "failed", failed)
        current_job = self.store.job(job["id"])
        self.assertEqual(current_job["status"], "completed")
        self.assertEqual(current_job["report_sha256"], job["report_sha256"])
        self.assertEqual(read_report(self.settings, current_job), report)
        self.assertEqual(current_job["spec"]["audit_mode"], "standard_review")

    def test_single_repository_static_scan_does_not_queue_agent_work(self):
        job, report = self._static_scan(self.commits[0])
        self.assertEqual(job["spec"]["audit_mode"], "static_only")
        self.assertIsNone(self.store.triage_authorization(job["id"]))
        self.assertFalse(Operations(self.store).triage_batches_for_job(job["id"], job["report_sha256"]))
        self.assertTrue(findings(report))
        self.assertEqual(report["validated_vulnerability"], 0)

    def test_date_window_each_fixed_endpoint_has_independent_consent_and_finishes(self):
        payload = {
            "repository_id": self.repo["id"], "branch": "refs/heads/main",
            "lookback_days": 2, "reference_time": "2025-01-05T00:00:00+00:00",
            "timezone": "UTC", "include_paths": ["."], "detector_ids": DETECTORS,
            "timeout_seconds": 90, "memory_mb": 1024,
            "audit_mode": "standard_review", "auto_triage": True,
            "max_triage_candidates": 1, "max_r2_candidates": 0,
        }
        # The recent-window operation has four endpoint jobs (two per window).
        expected_commits = [self.commits[1], self.commits[2], self.commits[2], self.commits[3]]
        operation, previews = self._preview_and_submit(
            "recent", "/api/v1/operations/recent-comparisons", payload, expected_commits)
        self.assertEqual(operation["kind"], "recent_window_comparison")
        self.assertEqual(len(set(item["consent_nonce"] for item in previews)), 4)
        self._finish_operation_scans(operation)
        self._finish_agent_children(operation, previews)

    def test_date_range_intelligent_mode_authorizes_both_fixed_endpoints_and_finishes(self):
        payload = {
            "repository_id": self.repo["id"], "branch": "refs/heads/main",
            "start": "2025-01-02T00:00:00+00:00",
            "end": "2025-01-03T00:00:00+00:00", "timezone": "UTC",
            "include_paths": ["."], "detector_ids": DETECTORS,
            "timeout_seconds": 90, "memory_mb": 1024,
            "audit_mode": "standard_review", "auto_triage": True,
            "max_triage_candidates": 1, "max_r2_candidates": 0,
        }
        operation, previews = self._preview_and_submit(
            "date", "/api/v1/operations/date-ranges", payload,
            [self.commits[0], self.commits[1]])
        self.assertEqual(operation["kind"], "revision_range")
        self.assertEqual(operation["spec"]["date_selection"]["selected_commits"],
                         [self.commits[1]])
        self._finish_operation_scans(operation)
        self._finish_agent_children(operation, previews)

    def test_branch_comparison_each_fixed_endpoint_has_independent_consent_and_finishes(self):
        payload = {
            "repository_id": self.repo["id"],
            "baseline_ref": self.commits[1], "endpoint_ref": self.commits[2],
            "include_paths": ["."], "detector_ids": DETECTORS,
            "timeout_seconds": 90, "memory_mb": 1024,
            "audit_mode": "standard_review", "auto_triage": True,
            "max_triage_candidates": 1, "max_r2_candidates": 0,
        }
        operation, previews = self._preview_and_submit(
            "branches", "/api/v1/operations/branch-comparisons", payload,
            [self.commits[1], self.commits[2]])
        self.assertEqual(operation["kind"], "branch_comparison")
        self._finish_operation_scans(operation)
        self._finish_agent_children(operation, previews)

    def test_version_matrix_each_commit_has_independent_consent_and_finishes(self):
        case_id = self._create_matrix_case()
        payload = {
            "case_id": case_id, "repository_id": self.repo["id"],
            "commits": self.commits[:2], "include_paths": ["."],
            "detector_ids": DETECTORS, "timeout_seconds": 90, "memory_mb": 1024,
            "audit_mode": "standard_review", "auto_triage": True,
            "max_triage_candidates": 1, "max_r2_candidates": 1,
        }
        operation, previews = self._preview_and_submit(
            "matrix", "/api/v1/operations/version-matrices", payload, self.commits[:2])
        self.assertEqual(operation["kind"], "version_matrix")
        self.assertEqual(len(previews), 2)
        self._finish_operation_scans(operation)
        result = self._finish_agent_children(operation, previews, expect_r2=True)
        self.assertEqual(len(result["result"]["versions"]), 2)
        self.assertEqual(len(result["result"]["comparisons"]), 1)


    def _finish_static_multi_endpoint_operation(self, operation):
        ops = Operations(self.store)
        scan_ids = operation["spec"]["scan_ids"]
        self.assertGreaterEqual(len(scan_ids), 2)
        for scan_id in scan_ids:
            self.assertEqual(self.store.job(scan_id)["spec"]["audit_mode"], "static_only")
            self.assertIsNone(self.store.triage_authorization(scan_id))
        for _ in scan_ids:
            Worker(self.settings).run(once=True)
        for scan_id in scan_ids:
            job = self.store.job(scan_id)
            self.assertIn(job["status"], {"completed", "completed_with_limitations"}, job)
            self.assertTrue(job.get("report_sha256"), job)
            report = read_report(self.settings, job)
            self.assertTrue(findings(report))
            self.assertEqual(report["validated_vulnerability"], 0)
            self.assertIsNone(self.store.triage_authorization(scan_id))
            self.assertFalse(ops.triage_batches_for_job(scan_id, job["report_sha256"]))
        OperationWorker(self.settings).run(once=True)
        finished = ops.get(operation["id"])
        self.assertIn(finished["status"], {"completed", "completed_with_limitations"}, finished)
        result = ops.result(operation["id"])
        self.assertEqual(result["validated_vulnerability"], 0)
        view = self.client.get("/api/v1/operations/" + operation["id"], headers=HEADERS)
        self.assertEqual(view.status_code, 200, view.text)
        progress = view.json()["intelligent_review_progress"]
        self.assertEqual([item["scan_id"] for item in progress], scan_ids)
        self.assertTrue(all(item["agent_status"] == "static_only" for item in progress), progress)
        self.assertTrue(all(not item["agent_authorized"] for item in progress), progress)
        expected_candidate_counts = [
            len(findings(read_report(self.settings, self.store.job(scan_id)))) for scan_id in scan_ids
        ]
        self.assertEqual([item["candidate_count"] for item in progress], expected_candidate_counts, progress)

    def test_static_multi_endpoint_operations_finish_without_model_authorization(self):
        common = {
            "repository_id": self.repo["id"], "include_paths": ["."],
            "detector_ids": DETECTORS, "timeout_seconds": 90, "memory_mb": 1024,
            "audit_mode": "static_only", "auto_triage": False,
        }
        recent = self.client.post("/api/v1/operations/recent-comparisons", headers=HEADERS,
            json={**common, "branch": "refs/heads/main", "lookback_days": 2,
                  "reference_time": "2025-01-05T00:00:00+00:00", "timezone": "UTC"})
        self.assertEqual(recent.status_code, 201, recent.text)
        self.assertEqual(recent.json()["kind"], "recent_window_comparison")
        self.assertEqual(len(recent.json()["spec"]["scan_ids"]), 4)
        self._finish_static_multi_endpoint_operation(recent.json())

        branches = self.client.post("/api/v1/operations/branch-comparisons", headers=HEADERS,
            json={**common, "baseline_ref": self.commits[1], "endpoint_ref": self.commits[2]})
        self.assertEqual(branches.status_code, 201, branches.text)
        self.assertEqual(branches.json()["kind"], "branch_comparison")
        self._finish_static_multi_endpoint_operation(branches.json())

        case_id = self._create_matrix_case()
        matrix = self.client.post("/api/v1/operations/version-matrices", headers=HEADERS,
            json={**common, "case_id": case_id, "commits": self.commits[:2]})
        self.assertEqual(matrix.status_code, 201, matrix.text)
        self.assertEqual(matrix.json()["kind"], "version_matrix")
        self._finish_static_multi_endpoint_operation(matrix.json())

    def test_revoking_one_endpoint_keeps_its_static_report_and_stops_its_agent_queue(self):
        payload = {
            "repository_id": self.repo["id"],
            "baseline_ref": self.commits[1], "endpoint_ref": self.commits[2],
            "include_paths": ["."], "detector_ids": DETECTORS,
            "timeout_seconds": 90, "memory_mb": 1024,
            "audit_mode": "standard_review", "auto_triage": True,
            "max_triage_candidates": 1, "max_r2_candidates": 0,
        }
        operation, previews = self._preview_and_submit(
            "branches", "/api/v1/operations/branch-comparisons", payload,
            [self.commits[1], self.commits[2]])
        revoked_id, active_id = operation["spec"]["scan_ids"]
        authorization = self.store.triage_authorization(revoked_id)
        self.assertTrue(authorization and not authorization["revoked"])
        revoked = self.client.post(
            "/api/v1/scans/" + revoked_id + "/triage/revoke", headers=HEADERS,
            json={"consent_sha256": authorization["consent_sha256"]})
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertTrue(revoked.json()["authorization"]["revoked"])

        self._finish_operation_scans(operation)
        ops = Operations(self.store)
        self.assertTrue(read_report(self.settings, self.store.job(revoked_id)))
        self.assertTrue(read_report(self.settings, self.store.job(active_id)))
        self.assertFalse(ops.triage_batches_for_job(
            revoked_id, self.store.job(revoked_id)["report_sha256"]))
        active_batches = ops.triage_batches_for_job(
            active_id, self.store.job(active_id)["report_sha256"])
        self.assertEqual(len(active_batches), 1, active_batches)
        active_tasks = ops.smart_triage_operations(active_batches[0]["id"])
        self.assertEqual(len(active_tasks), 1, active_tasks)

        worker_env, trace_path = self._fake_provider_environment()
        with patch.dict(os.environ, worker_env, clear=False):
            OperationWorker(self.settings).run(once=True)
            OperationWorker(self.settings).run(once=True)
        task = ops.get(active_tasks[0]["id"])
        self.assertIn(task["status"], {"completed", "completed_with_limitations"}, task)
        result = ops.result(task["id"])
        self.assertEqual(result["vulnerability_state"], "candidate")
        self.assertEqual(result["validated_vulnerability"], 0)
        trace = [json.loads(line) for line in trace_path.read_text().splitlines()]
        self.assertTrue(trace)
        self.assertEqual({item["commit"] for item in trace}, {previews[1]["commit"]})

        view = self.client.get("/api/v1/operations/" + operation["id"], headers=HEADERS)
        self.assertEqual(view.status_code, 200, view.text)
        progress = view.json()["intelligent_review_progress"]
        self.assertEqual([item["scan_id"] for item in progress], [revoked_id, active_id])
        self.assertEqual(progress[0]["agent_status"], "revoked", progress[0])
        self.assertEqual(progress[1]["agent_status"], "completed", progress[1])
        self.assertFalse(progress[0]["agent_authorized"])
        self.assertTrue(progress[1]["agent_authorized"])
        self.assertEqual(view.json()["result"]["validated_vulnerability"], 0)

    def test_provider_quota_failure_is_isolated_to_one_authorized_endpoint(self):
        payload = {
            "repository_id": self.repo["id"],
            "baseline_ref": self.commits[1], "endpoint_ref": self.commits[2],
            "include_paths": ["."], "detector_ids": DETECTORS,
            "timeout_seconds": 90, "memory_mb": 1024,
            "audit_mode": "standard_review", "auto_triage": True,
            "max_triage_candidates": 1, "max_r2_candidates": 0,
        }
        operation, previews = self._preview_and_submit(
            "branches", "/api/v1/operations/branch-comparisons", payload,
            [self.commits[1], self.commits[2]])
        self._finish_operation_scans(operation)
        ops = Operations(self.store)
        endpoint_tasks = []
        for scan_id in operation["spec"]["scan_ids"]:
            job = self.store.job(scan_id)
            self.assertTrue(job.get("report_sha256"), job)
            self.assertEqual(read_report(self.settings, job)["validated_vulnerability"], 0)
            batches = ops.triage_batches_for_job(scan_id, job["report_sha256"])
            self.assertEqual(len(batches), 1, batches)
            tasks = ops.smart_triage_operations(batches[0]["id"])
            self.assertEqual(len(tasks), 1, tasks)
            endpoint_tasks.append(tasks[0])

        worker_env, trace_path = self._fake_provider_environment()
        worker_env["OHSCANNER_TEST_PROVIDER_FAIL"] = "quota:" + previews[0]["commit"]
        with patch.dict(os.environ, worker_env, clear=False):
            OperationWorker(self.settings).run(once=True)  # Parent comparison.
            for _task in endpoint_tasks:
                OperationWorker(self.settings).run(once=True)

        statuses = {}
        for task in endpoint_tasks:
            finished = ops.get(task["id"])
            statuses[finished["spec"]["source_commit"]] = finished["status"]
            if finished["status"] in {"completed", "completed_with_limitations"}:
                self.assertEqual(ops.result(task["id"])["validated_vulnerability"], 0)
            else:
                self.assertIsNone(finished["result_sha256"], finished)
        self.assertEqual(statuses[previews[0]["commit"]], "failed", statuses)
        self.assertIn(statuses[previews[1]["commit"]],
                      {"completed", "completed_with_limitations"}, statuses)
        trace = [json.loads(line) for line in trace_path.read_text().splitlines()]
        self.assertTrue(trace)
        self.assertEqual({item["commit"] for item in trace}, {previews[1]["commit"]})

        view = self.client.get("/api/v1/operations/" + operation["id"], headers=HEADERS)
        self.assertEqual(view.status_code, 200, view.text)
        progress = view.json()["intelligent_review_progress"]
        self.assertEqual([item["scan_id"] for item in progress], operation["spec"]["scan_ids"])
        self.assertEqual(progress[0]["agent_status"], "failed", progress[0])
        self.assertEqual(progress[1]["agent_status"], "completed", progress[1])
        for item in progress:
            self.assertTrue(item["report_available"], item)
            self.assertTrue(item["agent_authorized"], item)
            self.assertFalse(item["model_result_is_product_vulnerability_confirmation"])
        self.assertEqual(view.json()["result"]["validated_vulnerability"], 0)


if __name__ == "__main__":
    unittest.main()

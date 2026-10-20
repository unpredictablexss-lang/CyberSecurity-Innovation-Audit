"""Owner integration: real fixed Git, bounded planning, API/Worker/CLI parity.

Authored controls verify wiring/evidence gates, not product accuracy.
"""
import json
import subprocess
import unittest
from unittest.mock import patch
from tests import test_workbench as fixtures
from src.ohscanner.execution import run_fixed_commit_scan
from src.workbench import service
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
                       if key not in {'audit_mode', 'workflow_sha256', 'workflow'}}
        self.assertEqual(plan['audit_mode'], 'standard_review')
        self.assertEqual(plan['workflow']['triage_stage'], 'user_authorized_candidate_batch')
        self.assertEqual(plan['selection_mode'], 'automatic')
        self.assertEqual(len(plan['suggested_detector_ids']), 8)
        self.assertEqual(plan['execution_status'], 'not_run')
        null = next(d for d in plan['detectors'] if d['id']=='ohscanner.cpp.null_dereference')
        self.assertEqual(null['reason_codes'], ['explicit_selection_required'])
        self.assertIn('partial.cpp', [f['file'] for f in plan['parse_limitations']])
        job = self.scan(expected_plan_sha256=plan['plan_sha256'])
        self.assertEqual(job['spec']['audit_plan'], static_plan)
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

    def test_task_level_triage_consent_is_bound_and_revocable(self):
        with patch.dict("os.environ", {
            "OHSCANNER_LLM_BASE_URL": "https://api.xiaomimimo.com/v1",
            "OHSCANNER_LLM_MODEL": "mimo-v2.6-pro",
            "OHSCANNER_LLM_API_KEY": "test-provider-key",
        }, clear=False):
            plan = self.plan(auto_triage=True, max_triage_candidates=2, max_cost_usd="0.10")
            consent = plan["triage_authorization_preview"]
            self.assertTrue(consent["eligible"])
            self.assertEqual(consent["manifest"]["candidate_limit"], 2)
            self.assertEqual(consent["manifest"]["binding"]["commit"], self.commit)
            self.assertFalse(consent["hard_spend_cap"])
            self.assertNotIn("test-provider-key", json.dumps(consent))
            self.assertTrue(plan["workflow"]["automatic_model_calls"])

            job = self.scan(
                auto_triage=True, max_triage_candidates=2, max_cost_usd="0.10",
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

    def test_task_cost_budget_is_required_and_bound_to_preview(self):
        with patch.dict("os.environ", {
            "OHSCANNER_LLM_BASE_URL": "https://api.xiaomimimo.com/v1",
            "OHSCANNER_LLM_MODEL": "mimo-v2.6-pro",
            "OHSCANNER_LLM_API_KEY": "test-provider-key",
        }, clear=False):
            no_budget = self.client.post(
                "/api/v1/audit-plans",
                json=self.request(auto_triage=True, max_triage_candidates=2),
                headers=fixtures.HEADERS,
            )
            self.assertEqual(no_budget.status_code, 409, no_budget.text)
            self.assertIn("费用上限", no_budget.text)

            plan = self.plan(auto_triage=True, max_triage_candidates=2,
                             max_cost_usd="0.10")
            changed_plan = self.plan(auto_triage=True, max_triage_candidates=2,
                                     max_cost_usd="0.11")
            self.assertNotEqual(plan["workflow_sha256"], changed_plan["workflow_sha256"])
            consent = plan["triage_authorization_preview"]
            stale = self.client.post(
                "/api/v1/scans",
                json=self.request(
                    auto_triage=True, max_triage_candidates=2, max_cost_usd="0.11",
                    expected_plan_sha256=plan["plan_sha256"],
                    expected_workflow_sha256=plan["workflow_sha256"],
                    expected_triage_consent_sha256=consent["consent_sha256"],
                    triage_consent_nonce=consent["consent_nonce"],
                ),
                headers=fixtures.HEADERS,
            )
            self.assertEqual(stale.status_code, 409, stale.text)
            self.assertIn("workflow changed", stale.text.lower())

    def test_authorized_scan_queues_bounded_r1_once_without_calling_provider(self):
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
            plan = self.plan(auto_triage=True, max_triage_candidates=2, max_cost_usd="0.10")
            consent = plan["triage_authorization_preview"]
            job = self.scan(
                auto_triage=True, max_triage_candidates=2, max_cost_usd="0.10",
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
                self.assertGreater(batch["selected_count"], 0)
                self.assertLessEqual(batch["selected_count"], 2)
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
                revoked = self.client.post(
                    "/api/v1/scans/" + job["id"] + "/triage/revoke",
                    json={"consent_sha256": consent["consent_sha256"]},
                    headers=fixtures.HEADERS,
                )
                self.assertEqual(revoked.status_code, 200, revoked.text)
                self.assertTrue(revoked.json()["authorization"]["revoked"])
                self.assertTrue(all(item["status"] == "cancelled"
                                    for item in operations.smart_triage_operations(batch["id"])))

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
            plan = self.plan(auto_triage=True, max_triage_candidates=1, max_cost_usd="0.10")
            consent = plan["triage_authorization_preview"]
            job = self.scan(
                auto_triage=True, max_triage_candidates=1, max_cost_usd="0.10",
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
            plan = self.plan(auto_triage=True, max_triage_candidates=2, max_r2_candidates=1,
                             max_cost_usd="0.10")
            consent = plan["triage_authorization_preview"]
            self.assertEqual(consent["manifest"]["conditional_r2"]["mode"], "tool_agent")
            self.assertEqual(consent["manifest"]["r2_candidate_limit"], 1)
            self.assertEqual(consent["manifest"]["budgets"]["max_requests"], 14)
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
                ops = Operations(self.store)
                batch = ops.triage_batches_for_job(
                    job["id"], self.store.job(job["id"])["report_sha256"])[0]
                self.assertEqual(batch["r2_status"], "awaiting_r1")
                r1_operations = ops.smart_triage_operations(batch["id"])
                self.assertEqual(len(r1_operations), 2)
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
                    self.assertEqual(saved["r2_status"], "budget_limited")
                    self.assertEqual(len(saved["r2_operation_ids"]), 1)
                    r2 = ops.get(saved["r2_operation_ids"][0])
                    parent = next(item for item in completed_r1
                                  if item["id"] == r2["spec"]["r1_operation_id"])
                    selected_candidate = next(item for item in candidates
                                              if item["id"] == r2["spec"]["candidate_id"])
                    self.assertEqual(r2["spec"]["mode"], "tool_agent")
                    self.assertEqual(r2["spec"]["max_steps"], 2)
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
                    self.assertEqual(len(ops.smart_triage_operations(batch["id"])), 3)
                    summary = self.client.get(
                        "/api/v1/scans/" + job["id"] + "/triage",
                        headers=fixtures.HEADERS,
                    )
                    self.assertEqual(summary.status_code, 200, summary.text)
                    batch_view = next(item for item in summary.json()["batches"]
                                      if item["id"] == batch["id"])
                    self.assertEqual(batch_view["conditional_r2"]["state"], "budget_limited")
                    self.assertEqual(batch_view["conditional_r2"]["operation_ids"],
                                     saved["r2_operation_ids"])
                    revoked = self.client.post(
                        "/api/v1/scans/" + job["id"] + "/triage/revoke",
                        json={"consent_sha256": consent["consent_sha256"]},
                        headers=fixtures.HEADERS,
                    )
                    self.assertEqual(revoked.status_code, 200, revoked.text)
                    self.assertEqual(ops.get(r2["id"])["status"], "cancelled")

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

    def test_c_remains_blocked_while_d_requires_explicit_research_selection(self):
        c_id = 'ohscanner.ark.runtime.type_safety'
        r = self.client.post('/api/v1/scans', json=self.request(detector_ids=[c_id]), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 409, r.text)
        self.assertIn('not-yet-approved', r.text)
        self.assertEqual(self.store.jobs(), [])

        d_id = 'ohscanner.data.sensitive_exposure'
        automatic = self.plan()
        d_row = next(row for row in automatic['detectors'] if row['id'] == d_id)
        self.assertEqual(d_row['decision'], 'skipped')
        self.assertIn('explicit_selection_required', d_row['reason_codes'])
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
        self.assertEqual(run['tool_version'], '0.21.0')
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

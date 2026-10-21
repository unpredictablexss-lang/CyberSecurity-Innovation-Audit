"""Offline fixed-Git and fake-Provider coverage for the joint candidate API/Worker path."""
import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch


from src.workbench.operations_store import Operations
from src.workbench.operation_worker import OperationWorker


ROOT = Path(__file__).resolve().parents[1]
_fixture_spec = importlib.util.spec_from_file_location(
    "offline_multimode_fixtures", ROOT / "tests" / "test_multimode_worker_e2e.py")
_fixture_module = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(_fixture_module)
def _multi():
    return getattr(_fixture_module, "MultiModeWorkerE2ETests")
HEADERS = {"x-ohscanner-client": "workbench-v1"}
DETECTORS = ["ohscanner.cpp.lifetime"]


class JointCandidateComparisonWorkerE2ETests(unittest.TestCase):
    """Real local scans and operation subprocesses; model boundary is replaced offline."""

    def setUp(self):
        _multi().setUp(self)

    def _commit(self, stamp, message):
        return _multi()._commit(self, stamp, message)

    def _static_scan(self, commit):
        return _multi()._static_scan(self, commit)

    def _fake_provider_environment(self):
        return _multi()._fake_provider_environment(self)

    def test_matrix_pair_preview_explicit_consent_and_real_worker_are_bound(self):
        case_id = _multi()._create_matrix_case(self)
        payload = {
            "case_id": case_id, "repository_id": self.repo["id"],
            "commits": self.commits[:2], "include_paths": ["."],
            "detector_ids": DETECTORS, "timeout_seconds": 90, "memory_mb": 1024,
            "audit_mode": "standard_review", "auto_triage": True,
            "max_triage_candidates": 1, "max_r2_candidates": 1,
        }
        operation, endpoint_previews = _multi()._preview_and_submit(
            self, "matrix", "/api/v1/operations/version-matrices", payload, self.commits[:2])
        self.assertEqual(operation["kind"], "version_matrix")
        _multi()._finish_operation_scans(self, operation)
        _multi()._finish_agent_children(self, operation, endpoint_previews, expect_r2=True)

        ops = Operations(self.store)
        matrix_result = ops.result(operation["id"])
        pair_rows = []
        for pair in matrix_result["comparisons"]:
            for match in pair.get("candidate_comparison", []):
                before, after = match.get("before"), match.get("after")
                if (pair.get("from") == self.commits[0] and pair.get("to") == self.commits[1]
                        and isinstance(before, list) and len(before) == 1
                        and isinstance(after, list) and len(after) == 1):
                    pair_rows.append((pair, match))
        self.assertEqual(len(pair_rows), 1, pair_rows)
        _, match = pair_rows[0]
        selectors = {
            "matrix_operation_id": operation["id"],
            "from_commit": self.commits[0], "from_candidate_id": match["before"][0]["id"],
            "to_commit": self.commits[1], "to_candidate_id": match["after"][0]["id"],
        }
        with patch.dict(os.environ, _fixture_module.PROVIDER_ENV, clear=False):
            preview_response = self.client.post(
                "/api/v1/operations/version-matrix-candidate-comparisons/preview",
                headers=HEADERS, json=selectors)
        self.assertEqual(preview_response.status_code, 200, preview_response.text)
        preview = preview_response.json()
        self.assertTrue(preview["eligible"])
        consent = preview["consent"]
        self.assertEqual(consent["binding"]["matrix_operation_id"], operation["id"])
        self.assertEqual(consent["binding"]["matrix_result_sha256"], ops.get(operation["id"])["result_sha256"])
        self.assertEqual(consent["binding"]["from"]["commit"], self.commits[0])
        self.assertEqual(consent["binding"]["to"]["commit"], self.commits[1])
        self.assertGreaterEqual(preview["context_summary"]["source_evidence_count"], 2)
        children = preview["context_summary"]["linked_agent_children"]
        self.assertTrue(children["from"] and children["to"], children)
        self.assertTrue(all(item["status"] in {"completed", "completed_with_limitations"}
                            and item["result_sha256"] for side in ("from", "to")
                            for item in children[side]), children)
        for side in ("from", "to"):
            modes = {ops.get(item["operation_id"])["spec"]["mode"] for item in children[side]}
            self.assertEqual(modes, {"single_shot", "tool_agent"})

        base_count = len(ops.list())
        create_path = "/api/v1/operations/version-matrix-candidate-comparisons"
        unapproved = self.client.post(create_path, headers=HEADERS, json={
            **selectors, "approved": False, "consent_nonce": consent["consent_nonce"],
            "expected_consent_sha256": consent["consent_sha256"], "expires_at": consent["expires_at"],
        })
        self.assertEqual(unapproved.status_code, 422, unapproved.text)
        stale = self.client.post(create_path, headers=HEADERS, json={
            **selectors, "approved": True, "consent_nonce": consent["consent_nonce"],
            "expected_consent_sha256": "0" * 64, "expires_at": consent["expires_at"],
        })
        self.assertEqual(stale.status_code, 409, stale.text)
        wrong_candidate = self.client.post(
            "/api/v1/operations/version-matrix-candidate-comparisons/preview",
            headers=HEADERS, json={**selectors, "from_candidate_id": "not-in-the-saved-matrix"})
        self.assertEqual(wrong_candidate.status_code, 409, wrong_candidate.text)
        self.assertEqual(len(ops.list()), base_count)

        approved_body = {
            **selectors, "approved": True, "consent_nonce": consent["consent_nonce"],
            "expected_consent_sha256": consent["consent_sha256"], "expires_at": consent["expires_at"],
        }
        with patch.dict(os.environ, _fixture_module.PROVIDER_ENV, clear=False):
            created_response = self.client.post(create_path, headers=HEADERS, json=approved_body)
        self.assertEqual(created_response.status_code, 201, created_response.text)
        created = created_response.json()
        with patch.dict(os.environ, _fixture_module.PROVIDER_ENV, clear=False):
            replayed_response = self.client.post(create_path, headers=HEADERS, json=approved_body)
        self.assertEqual(replayed_response.status_code, 201, replayed_response.text)
        self.assertEqual(replayed_response.json()["id"], created["id"])
        self.assertEqual(created["kind"], "version_candidate_comparison")
        self.assertEqual(created["status"], "queued")
        saved = created["spec"]
        from src.workbench.operation_worker import _is_consented_joint_comparison
        self.assertTrue(_is_consented_joint_comparison(created, ops))
        self.assertFalse(_is_consented_joint_comparison({
            "id": "f" * 32, "kind": created["kind"], "spec": saved,
        }, ops))
        with self.assertRaisesRegex(ValueError, "expired"):
            ops.issue_joint_comparison_preview_ticket(
                "a" * 32, "b" * 64, "2000-01-01T00:00:00+00:00")
        self.assertTrue(ops.joint_comparison_ticket_allows_worker(
            created["id"], saved["consent_nonce"], saved["consent_sha256"]))
        self.assertFalse(ops.joint_comparison_ticket_allows_worker(
            "0" * 32, saved["consent_nonce"], saved["consent_sha256"]))
        with ops.store.connect() as db:
            self.assertEqual(db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0], 11)
        unissued = dict(saved)
        unissued["consent_nonce"] = "f" * 32
        unissued["consent_sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "ticket"):
            ops.create("version_candidate_comparison", unissued)
        for side in ("from", "to"):
            observed = saved["joint_binding_snapshot"]["linked_agent_children_observed"][side]
            self.assertEqual(
                {(item["operation_id"], item["status"], item["result_sha256"]) for item in observed},
                {(item["operation_id"], item["status"], item["result_sha256"]) for item in children[side]},
            )
            complete = saved["joint_binding_snapshot"]["linked_agent_results"][side]
            self.assertEqual(
                {(item["operation_id"], item["status"], item["result_sha256"]) for item in complete},
                {(item["operation_id"], item["status"], item["result_sha256"]) for item in children[side]},
            )

        joint_fake = self.root / "joint-fake-provider"
        joint_fake.mkdir()
        joint_fake.joinpath("sitecustomize.py").write_text(r'''
import json
import os
from src.workbench import agent

class FakeJointResponsesClient:
    def __init__(self, *args, **kwargs):
        pass

    def create(self, request, **kwargs):
        format_name = request.get("text", {}).get("format", {}).get("name")
        if format_name != "ohscanner_joint_candidate_comparison":
            raise ValueError("unexpected Provider schema in joint comparison test")
        content = request["input"][0]["content"][0]["text"]
        sent = json.loads(content)
        context = sent["context"]
        rows = {
            side: context.get(side + "_linked_agent_results", [])
            for side in ("from", "to")
        }
        if any(not rows[side] for side in ("from", "to")):
            raise ValueError("linked Agent result context was not sent")
        with open(os.environ["OHSCANNER_TEST_JOINT_TRACE"], "w", encoding="utf-8") as stream:
            stream.write(json.dumps({
                "format_name": format_name,
                "linked_agent_results": rows,
                "citable_fixed_source_evidence": sent["citable_fixed_source_evidence"],
                "redaction_policy_version": sent["redaction_policy_version"],
            }))
        value = {
            "assessment": "unknown",
            "summary": "Offline fake Provider: comparative root cause remains unknown.",
            "introduced_or_fixed": "unknown",
            "supported_claims": [],
            "unknowns": ["The fixture does not establish product impact or version causation."],
            "limitations": ["Synthetic Provider response used for wiring verification only."],
        }
        return {"status": "completed", "output": [{
            "type": "message", "content": [{
                "type": "output_text", "text": json.dumps(value),
            }],
        }], "usage": {"input_tokens": 50, "output_tokens": 20, "total_tokens": 70}}

agent.ResponsesClient = FakeJointResponsesClient
''', encoding="utf-8")
        trace = self.root / "joint-provider-trace.json"
        worker_env = {
            **_fixture_module.PROVIDER_ENV,
            "PYTHONPATH": os.pathsep.join([
                str(joint_fake), str(ROOT), str(self.root / "offline-fake-provider")]),
            "OHSCANNER_TEST_JOINT_TRACE": str(trace),
        }
        with patch.dict(os.environ, worker_env, clear=False):
            OperationWorker(self.settings).run(once=True)

        finished = ops.get(created["id"])
        self.assertIn(finished["status"], {"completed", "completed_with_limitations"}, finished)
        result = ops.result(created["id"])
        self.assertEqual(result["kind"], "joint_version_candidate_root_cause")
        self.assertEqual(result["assessment"], "unknown")
        self.assertEqual(result["introduced_or_fixed"], "unknown")
        self.assertEqual(result["validated_vulnerability"], 0)
        self.assertIsNone(result["poc"])
        self.assertTrue(result["model_called"])
        self.assertEqual(result["provider_call_state"], "response_received")
        self.assertTrue(trace.is_file())
        sent = json.loads(trace.read_text(encoding="utf-8"))
        self.assertEqual(sent["format_name"], "ohscanner_joint_candidate_comparison")
        self.assertEqual(sent["redaction_policy_version"],
                         preview["context_summary"]["redaction_policy_version"])
        evidence_preview = preview["context_summary"]["evidence_preview"]
        sent_evidence = sent["citable_fixed_source_evidence"]
        self.assertEqual(len(sent_evidence), preview["context_summary"]["source_evidence_count"])
        self.assertEqual(
            [{
                key: item[key] for key in (
                    "evidence_id", "side", "file", "line_start", "line_end", "source_sha256", "lines"
                )
            } for item in sent_evidence],
            [{
                key: item[key] for key in (
                    "evidence_id", "side", "file", "line_start", "line_end", "source_sha256", "lines"
                )
            } for item in evidence_preview],
        )
        review_manifest = preview["context_summary"]["linked_review_manifest"]
        self.assertEqual(set(review_manifest), {"from", "to"})
        for side in ("from", "to"):
            context_rows = sent["linked_agent_results"][side]
            manifest_rows = review_manifest[side]
            self.assertEqual(len(context_rows), len(manifest_rows))
            for sent_row, manifest_row in zip(context_rows, manifest_rows):
                self.assertEqual(manifest_row["operation_id"], sent_row["operation_id"])
                self.assertEqual(manifest_row["status"], sent_row["status"])
                self.assertEqual(manifest_row["result_sha256"], sent_row["result_sha256"])
                self.assertEqual(manifest_row["assessment"], sent_row["assessment"])
                self.assertEqual(manifest_row["summary_transmitted"], sent_row["summary"])
                self.assertEqual(manifest_row["claims_transmitted"], sent_row["supported_claims"])
                self.assertEqual(manifest_row["unknowns_transmitted"], sent_row["unknowns"])
                self.assertEqual(manifest_row["next_steps_transmitted"], sent_row["next_steps"])
                self.assertEqual(manifest_row["fixed_source_evidence_ids"], sent_row["tool_evidence_ids"])
                self.assertEqual(manifest_row["prior_citations_transmitted"], 0)
        self.assertEqual(result["bindings"]["linked_agent_results"],
                         saved["joint_binding_snapshot"]["linked_agent_results"])

    def test_recent_window_pair_uses_fixed_endpoints_completed_agents_and_explicit_consent(self):
        payload = {
            "repository_id": self.repo["id"], "branch": "refs/heads/main",
            "lookback_days": 2, "reference_time": "2025-01-05T00:00:00+00:00",
            "timezone": "UTC", "include_paths": ["."], "detector_ids": DETECTORS,
            "timeout_seconds": 90, "memory_mb": 1024,
            "audit_mode": "standard_review", "auto_triage": True,
            "max_triage_candidates": 1, "max_r2_candidates": 1,
        }
        expected_commits = [self.commits[1], self.commits[2], self.commits[2], self.commits[3]]
        operation, endpoint_previews = _multi()._preview_and_submit(
            self, "recent", "/api/v1/operations/recent-comparisons", payload, expected_commits)
        _multi()._finish_operation_scans(self, operation)
        _multi()._finish_agent_children(self, operation, endpoint_previews, expect_r2=True)

        ops = Operations(self.store)
        parent_result = ops.result(operation["id"])
        self.assertEqual(parent_result["validated_vulnerability"], 0)
        between = parent_result["between_window_endpoints"]
        self.assertEqual((between["from"], between["to"]), (self.commits[2], self.commits[3]))
        pair_rows = []
        for match in between["candidate_comparison"]:
            before, after = match.get("before"), match.get("after")
            if (isinstance(before, list) and len(before) == 1
                    and isinstance(after, list) and len(after) == 1):
                pair_rows.append(match)
        self.assertEqual(len(pair_rows), 1, pair_rows)
        match = pair_rows[0]
        selectors = {
            "recent_window_operation_id": operation["id"],
            "from_commit": between["from"], "from_candidate_id": match["before"][0]["id"],
            "to_commit": between["to"], "to_candidate_id": match["after"][0]["id"],
        }
        preview_path = "/api/v1/operations/joint-candidate-comparisons/preview"
        create_path = "/api/v1/operations/joint-candidate-comparisons"
        with patch.dict(os.environ, _fixture_module.PROVIDER_ENV, clear=False):
            both_parents = self.client.post(preview_path, headers=HEADERS, json={
                **selectors, "matrix_operation_id": "a" * 32})
            self.assertEqual(both_parents.status_code, 422, both_parents.text)
            preview_response = self.client.post(preview_path, headers=HEADERS, json=selectors)
        self.assertEqual(preview_response.status_code, 200, preview_response.text)
        preview = preview_response.json()
        consent = preview["consent"]
        binding = consent["binding"]
        self.assertEqual(binding["source_operation_id"], operation["id"])
        self.assertEqual(binding["source_operation_kind"], "recent_window_comparison")
        self.assertEqual(binding["source_operation_result_sha256"], ops.get(operation["id"])["result_sha256"])
        self.assertEqual(binding["recent_window_operation_id"], operation["id"])
        self.assertEqual(binding["from"]["job_id"], operation["spec"]["scan_ids"][1])
        self.assertEqual(binding["to"]["job_id"], operation["spec"]["scan_ids"][3])
        self.assertEqual(binding["from"]["commit"], self.commits[2])
        self.assertEqual(binding["to"]["commit"], self.commits[3])

        children = preview["context_summary"]["linked_agent_children"]
        for side in ("from", "to"):
            self.assertTrue(children[side], children)
            self.assertTrue(all(row["status"] in {"completed", "completed_with_limitations"}
                                and row["result_sha256"] for row in children[side]), children)
            modes = {ops.get(row["operation_id"])["spec"]["mode"] for row in children[side]}
            self.assertEqual(modes, {"single_shot", "tool_agent"})

        wrong_endpoint = self.client.post(preview_path, headers=HEADERS, json={
            **selectors, "from_commit": self.commits[1]})
        self.assertEqual(wrong_endpoint.status_code, 409, wrong_endpoint.text)
        unapproved = self.client.post(create_path, headers=HEADERS, json={
            **selectors, "approved": False, "consent_nonce": consent["consent_nonce"],
            "expected_consent_sha256": consent["consent_sha256"], "expires_at": consent["expires_at"],
        })
        self.assertEqual(unapproved.status_code, 422, unapproved.text)
        stale = self.client.post(create_path, headers=HEADERS, json={
            **selectors, "approved": True, "consent_nonce": consent["consent_nonce"],
            "expected_consent_sha256": "0" * 64, "expires_at": consent["expires_at"],
        })
        self.assertEqual(stale.status_code, 409, stale.text)
        with patch.dict(os.environ, _fixture_module.PROVIDER_ENV, clear=False):
            created_response = self.client.post(create_path, headers=HEADERS, json={
                **selectors, "approved": True, "consent_nonce": consent["consent_nonce"],
                "expected_consent_sha256": consent["consent_sha256"],
                "expires_at": consent["expires_at"],
            })
        self.assertEqual(created_response.status_code, 201, created_response.text)
        created = created_response.json()
        self.assertEqual(created["kind"], "version_candidate_comparison")
        self.assertTrue(created["spec"]["source_submission_approved"])
        self.assertEqual(created["spec"]["joint_binding_snapshot"]["recent_window_operation_id"],
                         operation["id"])

        fake_provider = self.root / "joint-recent-fake-provider"
        fake_provider.mkdir()
        fake_provider.joinpath("sitecustomize.py").write_text(r'''
import json
import os
from src.workbench import agent

class FakeRecentJointProvider:
    def __init__(self, *args, **kwargs):
        pass

    def create(self, request, **kwargs):
        if request.get("text", {}).get("format", {}).get("name") != "ohscanner_joint_candidate_comparison":
            raise ValueError("unexpected Provider schema in recent-window test")
        sent = json.loads(request["input"][0]["content"][0]["text"])
        context = sent["context"]
        evidence = sent["citable_fixed_source_evidence"]
        if not context.get("from_linked_agent_results") or not context.get("to_linked_agent_results"):
            raise ValueError("completed R1/R2 child context missing on an endpoint")
        if {item.get("side") for item in evidence} != {"from", "to"}:
            raise ValueError("fixed evidence from both endpoint sides was not provided")
        with open(os.environ["OHSCANNER_TEST_RECENT_JOINT_TRACE"], "w", encoding="utf-8") as stream:
            stream.write(json.dumps({
                "endpoint_match": context.get("endpoint_match"),
                "from_commit": context["from"]["commit"],
                "to_commit": context["to"]["commit"],
                "evidence_sides": sorted({item["side"] for item in evidence}),
                "linked_agent_results": {
                    side: context[side + "_linked_agent_results"] for side in ("from", "to")
                },
            }))
        value = {
            "assessment": "unknown",
            "summary": "Synthetic offline comparison; product impact remains unknown.",
            "introduced_or_fixed": "unknown",
            "supported_claims": [],
            "unknowns": ["No product execution or exploitability evidence was supplied."],
            "limitations": ["Synthetic Provider response used for wiring verification only."],
        }
        return {"status": "completed", "output": [{
            "type": "message", "content": [{
                "type": "output_text", "text": json.dumps(value),
            }],
        }], "usage": {"input_tokens": 30, "output_tokens": 10, "total_tokens": 40}}

agent.ResponsesClient = FakeRecentJointProvider
''', encoding="utf-8")
        trace = self.root / "recent-joint-provider-trace.json"
        worker_env = {
            **_fixture_module.PROVIDER_ENV,
            "PYTHONPATH": os.pathsep.join([str(fake_provider), str(ROOT)]),
            "OHSCANNER_TEST_RECENT_JOINT_TRACE": str(trace),
        }
        with patch.dict(os.environ, worker_env, clear=False):
            OperationWorker(self.settings).run(once=True)
        finished = ops.get(created["id"])
        self.assertIn(finished["status"], {"completed", "completed_with_limitations"}, finished)
        result = ops.result(created["id"])
        self.assertEqual(result["assessment"], "unknown")
        self.assertEqual(result["vulnerability_state"], "unknown")
        self.assertEqual(result["validated_vulnerability"], 0)
        self.assertIsNone(result["poc"])
        self.assertEqual(result["bindings"]["recent_window_operation_id"], operation["id"])
        self.assertEqual(result["bindings"]["from"]["job_id"], operation["spec"]["scan_ids"][1])
        self.assertEqual(result["bindings"]["to"]["job_id"], operation["spec"]["scan_ids"][3])
        sent = json.loads(trace.read_text())
        self.assertEqual((sent["from_commit"], sent["to_commit"]), (self.commits[2], self.commits[3]))
        self.assertEqual(sent["evidence_sides"], ["from", "to"])
        self.assertTrue(sent["linked_agent_results"]["from"])
        self.assertTrue(sent["linked_agent_results"]["to"])

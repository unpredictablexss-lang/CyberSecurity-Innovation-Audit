"""Multi-endpoint model egress consent is immutable, scoped and atomic."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.workbench.api import create_app

from src.workbench import operations, service
from src.workbench.operations_api import BranchComparisonRequest, RangeRequest
from src.workbench.operations_store import Operations
from src.workbench.settings import Settings
from src.workbench.store import Store


class MultiEndpointAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.settings = Settings(root / "data", (root / "targets",))
        self.settings.initialize()
        self.store = Store(self.settings.data_dir)
        self.ops = Operations(self.store)
        path = root / "targets" / "sample"
        path.mkdir(parents=True)
        self.repo = self.store.add_repository("openharmony/sample", str(path))
        self.specs = [
            {"commit": char * 40, "repository": self.repo["name"], "include_paths": ["."],
             "plan_sha256": (char * 64), "audit_plan": {"source": {
                 "repository": self.repo["name"], "commit": char * 40,
                 "git_tree": "c" * 40}, "plan_sha256": char * 64}}
            for char in ("a", "b")
        ]
        self.body = {"audit_mode": "standard_review", "auto_triage": True,
                     "max_triage_candidates": 2, "max_r2_candidates": 1,
                     "max_cost_usd": "5.00"}

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def fake_preview(plan, workflow, paths, candidates, nonce, provider, r2):
        digest = hashlib.sha256((plan["plan_sha256"] + workflow + nonce).encode()).hexdigest()
        return {"eligible": True, "consent_sha256": digest, "consent_nonce": nonce,
                "manifest": {"binding": {"plan_sha256": plan["plan_sha256"],
                                         "workflow_sha256": workflow},
                             "candidate_limit": candidates, "r2_candidate_limit": r2,
                             "consent_nonce": nonce}}

    def approved(self):
        provider = SimpleNamespace(configured=True)
        with patch("src.workbench.agent.ProviderConfig.from_env", return_value=provider), \
             patch("src.workbench.agent.audit_task_consent_preview", side_effect=self.fake_preview):
            previews = operations.multimode_triage_preview(
                self.specs, self.body, provider, ["1" * 32, "2" * 32])
            body = {**self.body, "triage_approvals": [
                {"consent_nonce": preview["consent_nonce"],
                 "consent_sha256": preview["consent_sha256"]} for preview in previews]}
            enriched = operations.bind_multimode_triage(self.settings, self.specs, body)
        return body, enriched

    def test_all_endpoints_store_approved_consents_in_same_transaction(self):
        _, scans = self.approved()
        record = self.ops.create_with_scans("revision_range", {"baseline": "a" * 40},
                                            self.repo["id"], scans)
        self.assertEqual(len(record["spec"]["scan_ids"]), 2)
        for job_id, scan in zip(record["spec"]["scan_ids"], scans):
            job = self.store.job(job_id)
            auth = self.store.triage_authorization(job_id)
            self.assertEqual(job["spec"]["commit"], scan["commit"])
            self.assertEqual(auth["consent_sha256"],
                             scan["triage_authorization"]["consent_sha256"])
            self.assertEqual(auth["snapshot"]["binding"]["plan_sha256"],
                             scan["plan_sha256"])
            self.assertFalse(auth["revoked"])

    def test_retried_approved_submission_reuses_original_operation_and_jobs(self):
        _, scans = self.approved()
        first = self.ops.create_with_scans("revision_range", {"baseline": "a" * 40},
                                           self.repo["id"], scans)
        second = self.ops.create_with_scans("revision_range", {"baseline": "a" * 40},
                                            self.repo["id"], scans)
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(first["spec"]["scan_ids"], second["spec"]["scan_ids"])
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM operations").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 2)

    def test_replaying_other_endpoint_approval_is_rejected(self):
        body, _ = self.approved()
        body["triage_approvals"].reverse()
        provider = SimpleNamespace(configured=True)
        with patch("src.workbench.agent.ProviderConfig.from_env", return_value=provider), \
             patch("src.workbench.agent.audit_task_consent_preview", side_effect=self.fake_preview):
            with self.assertRaisesRegex(ValueError, "consent expired"):
                operations.bind_multimode_triage(self.settings, self.specs, body)

    def test_static_only_does_not_accept_model_authorization(self):
        body, _ = self.approved()
        body["audit_mode"] = "static_only"
        body["auto_triage"] = False
        with self.assertRaisesRegex(ValueError, "static-only"):
            operations.bind_multimode_triage(self.settings, self.specs, body)
        self.assertEqual(operations.bind_multimode_triage(
            self.settings, self.specs, {"audit_mode": "static_only"}), self.specs)

    def test_malformed_second_endpoint_rolls_back_all_rows(self):
        _, scans = self.approved()
        scans[1]["triage_authorization"]["snapshot"]["binding"]["plan_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "another scan plan"):
            self.ops.create_with_scans("revision_range", {"baseline": "a" * 40},
                                       self.repo["id"], scans)
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM jobs").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM operations").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM triage_authorizations").fetchone()[0], 0)

    def test_http_preview_then_submit_builds_real_operation_and_endpoint_auth_rows(self):
        body = {**self.body, "repository_id": self.repo["id"],
                "baseline": "a" * 40, "endpoint": "b" * 40,
                "detector_ids": ["ohscanner.cpp.lifetime"]}
        app = create_app(self.settings)
        with patch("src.workbench.operations_api.range_plan",
                   return_value=(self.repo, self.specs[0], self.specs[1], [])), \
             patch("src.workbench.operations.range_plan",
                   return_value=(self.repo, self.specs[0], self.specs[1], [])), \
             patch("src.workbench.agent.ProviderConfig.from_env",
                   return_value=SimpleNamespace(configured=True)), \
             patch("src.workbench.agent.audit_task_consent_preview",
                   side_effect=self.fake_preview):
            with TestClient(app) as client:
                resp = client.post("/api/v1/operations/intelligent-previews",
                                   json={"kind": "range", "payload": body},
                                   headers={"x-ohscanner-client": "workbench-v1"})
                self.assertEqual(resp.status_code, 200, resp.text)
                previews = resp.json()["endpoints"]
                self.assertEqual(len(previews), 2)
                approvals = [{"consent_nonce": preview["consent_nonce"],
                              "consent_sha256": preview["consent_sha256"]}
                             for preview in previews]
                submitted = client.post("/api/v1/operations/revision-ranges",
                                        json={**body, "triage_approvals": approvals},
                                        headers={"x-ohscanner-client": "workbench-v1"})
                self.assertEqual(submitted.status_code, 201, submitted.text)
                job_ids = submitted.json()["spec"]["scan_ids"]
                self.assertEqual(len(job_ids), 2)
                for key, preview in zip(job_ids, previews):
                    self.assertEqual(self.store.triage_authorization(key)["consent_sha256"],
                                     preview["consent_sha256"])
                status = client.get("/api/v1/operations/" + submitted.json()["id"])
                self.assertEqual(status.status_code, 200, status.text)
                phases = status.json()["intelligent_review_progress"]
                self.assertEqual(len(phases), 2)
                self.assertTrue(all(phase["agent_authorized"] for phase in phases))
                self.assertTrue(all(phase["agent_status"] == "awaiting_static" for phase in phases))
                self.assertTrue(all(not phase["model_result_is_product_vulnerability_confirmation"]
                                    for phase in phases))

    def test_strict_request_budget_and_nonce_validation(self):
        base = {"repository_id": self.repo["id"], "baseline": "a" * 40,
                "endpoint": "b" * 40, "detector_ids": ["ohscanner.cpp.lifetime"]}
        good = RangeRequest.model_validate({**base, "auto_triage": True, "max_cost_usd": "5.00"})
        self.assertTrue(good.auto_triage)
        for cost in ("abc", "0x55", "5.2.1", "-1", "5 USD"):
            with self.subTest(cost=cost):
                request = RangeRequest.model_validate({**base, "max_cost_usd": cost})
                self.assertEqual(request.max_cost_usd, cost)  # Legacy field is ignored by smart-audit policy.
        with self.assertRaises(Exception):
            BranchComparisonRequest.model_validate({
                "repository_id": self.repo["id"], "baseline_ref": "main", "endpoint_ref": "dev",
                "triage_approvals": [{"consent_nonce": "abc", "consent_sha256": "f" * 64}]
            })


if __name__ == "__main__":
    unittest.main()

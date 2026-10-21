"""Task-level consent and sequential execution tests for the L2 scheduler."""
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from src.workbench.progressive_triage import build_policy
from src.workbench.progressive_triage.contracts import content_sha256
from src.workbench.progressive_triage.policy import policy_envelope
from src.workbench.progressive_triage.quick_screen_batch import (
    execute_quick_screen_batch,
    prepare_quick_screen_batch,
)


def make_batch_fixture(count=3, audit_id="audit-parent"):
    policy = build_policy("custom", {
        **build_policy()["limits"], "quick_screen_groups_per_audit": count,
        "deep_groups_per_audit": 0,
    }, True)
    frozen = {"revision": 4, "policy": policy,
              "policy_sha256": policy_envelope(policy)["policy_sha256"]}
    report_sha = "e" * 64
    groups = []
    decisions = []
    for index in range(count):
        group_id = f"group-{index + 1}"
        candidate_id = f"candidate-{index + 1}"
        groups.append({"group_id": group_id, "members": [{
            "candidate_id": candidate_id, "repository": "open-harmony/example",
            "commit": "a" * 40, "report_sha256": report_sha,
            "source_binding_verified": True,
        }]})
        decisions.append({"group_id": group_id, "selected": True, "rank": index + 1})
    plan = {"ranking": {"decisions": decisions}, "groups": groups,
            "original_observation_count": count, "validated_vulnerability": 0}
    audit = {"id": audit_id, "kind": "revision_range", "status": "completed",
             "result_sha256": "f" * 64, "cancel_requested": False,
             "spec": {"audit_mode": "standard_review", "scan_ids": ["a" * 32],
                      "progressive_triage_policy": frozen}}

    class FakeStore:
        def job(self, key):
            return {"id": key, "status": "completed", "report_sha256": report_sha,
                    "spec": {"audit_mode": "standard_review",
                             "progressive_triage_policy": frozen}}

    class FakeOperations:
        def get(self, key):
            if key == audit_id:
                return audit
            return {"id": key, "cancel_requested": False}

        def result(self, _key):
            return {"progressive_triage": plan}

        def progressive_operations_for_audit(self, _key):
            return []

    provider = SimpleNamespace(configured=True, fingerprint="d" * 64,
                               model="quick-model", public={"model": "quick-model"})

    def prepare(_settings, _store, job_id, candidate_id, active_provider,
                nonce, expiry, audit_parent=None, audit_parent_plan=None):
        group_id = candidate_id.replace("candidate-", "group-")
        group = {"group_id": group_id, "members": [{"candidate_id": candidate_id}]}
        evidence = [{"evidence_id": "evidence-" + group_id, "file": "src/a.cpp",
                     "line_start": 10, "line_end": 11, "source_sha256": "c" * 64,
                     "text": "dangerous_call();", "report_sha256": report_sha,
                     "commit": "a" * 40, "sensitive_redactions": []}]
        authorization = {"authorized": True, "audit_mode": "intelligent",
                         "consent_sha256": "0" * 64, "report_sha256": report_sha,
                         "repository": "open-harmony/example", "commit": "a" * 40,
                         "provider_fingerprint": active_provider.fingerprint,
                         "model": active_provider.model,
                         "redaction_policy_version": "redaction-v1"}
        item_manifest = {"consent_nonce": nonce, "consent_expires_at": expiry,
                         "group": group, "evidence": evidence,
                         "policy": frozen["policy"],
                         "policy_sha256": frozen["policy_sha256"],
                         "policy_revision": frozen["revision"],
                         "audit_operation_id": audit_id,
                         "ranking": {"decisions": [{"group_id": group_id, "selected": True}]}}
        digest = content_sha256(item_manifest)
        authorization["consent_sha256"] = digest
        return {"eligible": True, "audit_operation_id": audit_id,
                "consent_sha256": digest, "consent_manifest": item_manifest,
                "consent_expires_at": expiry, "progressive_policy": frozen,
                "ranking": item_manifest["ranking"], "group": group,
                "evidence": evidence, "authorization": authorization,
                "provider": active_provider.public,
                "disclosure": {"source_excerpt": "dangerous_call();"}}

    return policy, frozen, plan, audit, FakeStore(), FakeOperations(), provider, prepare


class ProgressiveQuickScreenBatchTests(unittest.TestCase):
    def test_preview_freezes_all_selected_fixed_source_excerpts_under_one_digest(self):
        policy, frozen, plan, audit, store, ops, provider, prepare = make_batch_fixture()
        with tempfile.TemporaryDirectory() as directory, \
                patch("src.workbench.progressive_triage.quick_screen_operation.prepare_quick_screen",
                      side_effect=prepare):
            preview = prepare_quick_screen_batch(
                SimpleNamespace(data_dir=Path(directory)), store, ops,
                "audit-parent", provider, "1" * 32,
            )
        self.assertEqual(preview["scheduled_group_count"], 3)
        self.assertEqual(len(preview["disclosures"]), 3)
        self.assertEqual([row["group_id"] for row in preview["disclosures"]],
                         ["group-1", "group-2", "group-3"])
        self.assertEqual(preview["batch_manifest"]["plan_sha256"], content_sha256(plan))
        self.assertEqual(preview["consent_sha256"], content_sha256(preview["batch_manifest"]))
        self.assertTrue(all(item["spec"]["source_submission_approved"] for item in preview["items"]))
        self.assertEqual(preview["vulnerability_state_after_review"], "candidate")

    def test_worker_stops_on_shared_budget_gate_and_keeps_remaining_groups_candidate(self):
        policy, frozen, plan, audit, store, ops, provider, prepare = make_batch_fixture()
        with tempfile.TemporaryDirectory() as directory, \
                patch("src.workbench.progressive_triage.quick_screen_operation.prepare_quick_screen",
                      side_effect=prepare):
            preview = prepare_quick_screen_batch(
                SimpleNamespace(data_dir=Path(directory)), store, ops,
                "audit-parent", provider, "2" * 32,
            )
        spec = {"source_submission_approved": True,
                "audit_operation_id": "audit-parent",
                "progressive_policy": frozen,
                "consent_nonce": preview["consent_nonce"],
                "consent_sha256": preview["consent_sha256"],
                "consent_expires_at": preview["consent_expires_at"],
                "consent_manifest": preview["batch_manifest"],
                "items": preview["items"],
                "provider_fingerprint": provider.fingerprint,
                "provider_model": provider.model}
        settings = SimpleNamespace(data_dir=Path(directory))
        responses = [
            {"state": "completed", "quick_screen": {"state": "completed", "quick_assessment": "investigate"}},
            {"state": "quick_unknown", "reason_code": "budget_gate:task-wide model-call budget exhausted"},
        ]
        with patch("src.workbench.agent.ProviderConfig.from_env", return_value=provider), \
                patch("src.workbench.progressive_triage.quick_screen_operation.execute_quick_screen",
                      side_effect=responses) as execute:
            result = execute_quick_screen_batch(
                settings, store, ops, {"id": "batch-task", "spec": spec})
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(result["stop_reason"], "budget_exhausted")
        self.assertEqual(result["processed_group_count"], 2)
        self.assertEqual(result["not_started"], [{"group_id": "group-3", "state": "not_started_candidate"}])
        self.assertFalse(result["candidate_disposition_changed"])
        self.assertEqual(result["validated_vulnerability"], 0)

    def test_worker_rechecks_static_only_parent_before_any_model_call(self):
        _, frozen, _, audit, store, ops, provider, prepare = make_batch_fixture()
        with tempfile.TemporaryDirectory() as directory, \
                patch("src.workbench.progressive_triage.quick_screen_operation.prepare_quick_screen",
                      side_effect=prepare):
            preview = prepare_quick_screen_batch(
                SimpleNamespace(data_dir=Path(directory)), store, ops,
                "audit-parent", provider, "3" * 32,
            )
        spec = {"source_submission_approved": True,
                "audit_operation_id": "audit-parent",
                "progressive_policy": frozen,
                "consent_nonce": preview["consent_nonce"],
                "consent_sha256": preview["consent_sha256"],
                "consent_expires_at": preview["consent_expires_at"],
                "consent_manifest": preview["batch_manifest"],
                "items": preview["items"],
                "provider_fingerprint": provider.fingerprint,
                "provider_model": provider.model}
        audit["spec"]["audit_mode"] = "static_only"
        with patch("src.workbench.agent.ProviderConfig.from_env", return_value=provider), \
                patch("src.workbench.progressive_triage.quick_screen_operation.execute_quick_screen") as execute:
            with self.assertRaisesRegex(ValueError, "parent audit changed"):
                execute_quick_screen_batch(
                    SimpleNamespace(data_dir=Path(directory)), store, ops,
                    {"id": "batch-task", "spec": spec})
        execute.assert_not_called()

    def test_api_requires_reviewed_batch_consent_and_persists_one_idempotent_operation(self):
        from fastapi.testclient import TestClient
        from src.workbench.api import create_app
        from src.workbench.settings import Settings

        _, frozen, _, _, _, _, provider, _ = make_batch_fixture()
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory) / "data", ())
            app = create_app(settings)
            parent = app.state.operations.create("revision_range", {
                "audit_mode": "standard_review", "scan_ids": ["a" * 32],
                "progressive_triage_policy": frozen,
            })
            with app.state.store.connect() as db:
                db.execute("UPDATE operations SET status='completed' WHERE id=?", (parent["id"],))

            def prepared(_settings, _store, _ops, audit_id, active_provider, nonce, expiry=None):
                _, _, _, _, fake_store, fake_ops, _, quick_preview = make_batch_fixture(audit_id=audit_id)
                with patch("src.workbench.progressive_triage.quick_screen_operation.prepare_quick_screen",
                           side_effect=quick_preview):
                    return prepare_quick_screen_batch(_settings, fake_store, fake_ops,
                                                      audit_id, active_provider, nonce, expiry)

            with patch("src.workbench.agent.ProviderConfig.from_env", return_value=provider), \
                    patch("src.workbench.progressive_triage.quick_screen_batch.prepare_quick_screen_batch",
                          side_effect=prepared):
                with TestClient(app, headers={"x-ohscanner-client": "workbench-v1"}) as client:
                    preview_response = client.post(
                        "/api/v1/operations/progressive-quick-screen-batches/preview",
                        json={"audit_operation_id": parent["id"]})
                    self.assertEqual(preview_response.status_code, 200, preview_response.text)
                    preview = preview_response.json()
                    denied = client.post("/api/v1/operations/progressive-quick-screen-batches", json={
                        "audit_operation_id": parent["id"], "consent_sha256": preview.get("consent_sha256"),
                        "consent_nonce": preview.get("consent_nonce"),
                        "consent_expires_at": preview.get("consent_expires_at"),
                        "source_submission_approved": False,
                    })
                    payload = {"audit_operation_id": parent["id"],
                               "consent_sha256": preview["consent_sha256"],
                               "consent_nonce": preview["consent_nonce"],
                               "consent_expires_at": preview["consent_expires_at"],
                               "source_submission_approved": True}
                    started = client.post("/api/v1/operations/progressive-quick-screen-batches", json=payload)
                    replay = client.post("/api/v1/operations/progressive-quick-screen-batches", json=payload)
        self.assertEqual(preview_response.status_code, 200, preview_response.text)
        self.assertEqual(len(preview["disclosures"]), 3)
        self.assertEqual(denied.status_code, 428, denied.text)
        self.assertEqual(started.status_code, 201, started.text)
        self.assertEqual(replay.status_code, 201, replay.text)
        self.assertEqual(started.json()["id"], replay.json()["id"])
        self.assertEqual(started.json()["kind"], "progressive_quick_screen_batch")

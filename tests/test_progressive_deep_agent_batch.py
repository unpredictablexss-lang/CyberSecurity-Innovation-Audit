"""Task-consented L3 batches stop safely and reuse the existing Agent path."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from src.workbench.progressive_triage import build_policy
from src.workbench.progressive_triage.contracts import content_sha256
from src.workbench.progressive_triage.deep_agent_batch import (
    execute_progressive_deep_agent_batch,
    deep_batch_manifest_sha,
)
from src.workbench.progressive_triage.policy import policy_envelope
from src.workbench.operations_store import Operations
from src.workbench.store import Store


def make_task(count=2):
    policy = build_policy("custom", {
        **build_policy()["limits"], "deep_groups_per_audit": count,
    }, True)
    frozen = {"revision": 3, "policy": policy,
              "policy_sha256": policy_envelope(policy)["policy_sha256"]}
    audit_id = "a" * 32
    l2_id = "b" * 32
    l2_result_sha = "c" * 64
    groups, l2_items, manifest_items = [], [], []
    for index in range(count):
        group_id = f"group-{index + 1}"
        candidate_id = f"candidate-{index + 1}"
        child = {
            "job_id": audit_id, "candidate_id": candidate_id,
            "progressive_group_id": group_id,
            "progressive_audit_operation_id": audit_id,
            "progressive_quick_screen_operation_id": l2_id,
            "progressive_quick_screen_result_sha256": l2_result_sha,
            "progressive_quick_screen_batch_group_id": group_id,
            "progressive_policy": frozen,
            "progressive_consent_sha256": str(index + 1) * 64,
            "source_consent_sha256": str(index + 3) * 64,
            "report_sha256": "d" * 64, "source_commit": "e" * 40,
            "source_submission_approved": True,
        }
        groups.append({"group_id": group_id, "candidate_id": candidate_id,
                       "state": "completed", "quick_assessment": "investigate"})
        l2_items.append({"group_id": group_id, "spec": {"job_id": audit_id,
                        "candidate_id": candidate_id, "authorization": {"report_sha256": "d" * 64}}})
        manifest_items.append({
            "group_id": group_id,
            "progressive_consent_sha256": child["progressive_consent_sha256"],
            "source_consent_sha256": child["source_consent_sha256"],
            "job_id": child["job_id"], "candidate_id": child["candidate_id"],
            "report_sha256": child["report_sha256"], "source_commit": child["source_commit"],
        })
        groups[index]["_child_spec"] = child
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    manifest = {
        "audit_operation_id": audit_id, "l2_batch_operation_id": l2_id,
        "l2_batch_result_sha256": l2_result_sha, "policy_sha256": frozen["policy_sha256"],
        "consent_nonce": "f" * 32, "consent_expires_at": expires,
        "provider_fingerprint": "1" * 64, "model": "test-model",
        "items": manifest_items,
    }
    items = [{"group_id": row["group_id"], "spec": row.pop("_child_spec")}
             for row in groups]
    spec = {
        "source_submission_approved": True, "audit_operation_id": audit_id,
        "l2_batch_operation_id": l2_id, "l2_batch_result_sha256": l2_result_sha,
        "progressive_policy": frozen, "consent_nonce": manifest["consent_nonce"],
        "consent_expires_at": expires, "provider_fingerprint": "1" * 64,
        "provider_model": "test-model", "consent_manifest": manifest,
        "consent_sha256": content_sha256(manifest), "items": items,
    }
    l2 = {"id": l2_id, "kind": "progressive_quick_screen_batch",
          "status": "completed", "result_sha256": l2_result_sha,
          "spec": {"audit_operation_id": audit_id, "items": l2_items}}
    l2_result = {"groups": groups}
    return audit_id, l2_id, l2, l2_result, {"id": "9" * 32, "spec": spec}


class ProgressiveDeepAgentBatchTests(unittest.TestCase):
    def test_store_replays_exact_l3_consent_before_expiry_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "data")
            ops = Operations(store)
            spec = {
                "consent_sha256": "1" * 64,
                "consent_manifest": {"scope": ["fixed L2 result"]},
                "audit_operation_id": "a" * 32,
                "l2_batch_operation_id": "b" * 32,
                "items": [{"group_id": "group-1"}],
            }
            with store.connect() as db:
                db.execute(
                    "INSERT INTO operations(id,kind,spec,status,created_at) VALUES(?,?,?,?,?)",
                    ("9" * 32, "progressive_deep_agent_batch", json.dumps(spec),
                     "queued", datetime.now(timezone.utc).isoformat()),
                )

            replay = ops.create("progressive_deep_agent_batch", spec)
            self.assertEqual(replay["id"], "9" * 32)
            with self.assertRaisesRegex(ValueError, "conflicts with this consent digest"):
                ops.create("progressive_deep_agent_batch", {**spec, "items": [{"group_id": "other"}]})

    def test_manifest_digest_binds_all_members(self):
        *_, task = make_task()
        spec = task["spec"]
        self.assertEqual(deep_batch_manifest_sha(spec), spec["consent_sha256"])
        changed = {**spec, "consent_manifest": {**spec["consent_manifest"], "items": []}}
        self.assertNotEqual(deep_batch_manifest_sha(changed), spec["consent_sha256"])

    def test_worker_runs_groups_sequentially_through_existing_l3_and_logs_on_parent(self):
        audit_id, l2_id, l2, l2_result, task = make_task()
        events = []

        class FakeOps:
            def get(self, key):
                if key == l2_id:
                    return l2
                if key == task["id"]:
                    return {**task, "cancel_requested": False}
                raise KeyError(key)

            def result(self, key):
                if key == l2_id:
                    return l2_result
                raise KeyError(key)

            def event(self, key, stage, message):
                events.append((key, stage, message))

        provider = SimpleNamespace(configured=True, fingerprint="1" * 64,
                                   model="test-model")
        calls = []

        def execute(_settings, _store, proxy, child_task):
            calls.append(child_task["spec"]["progressive_group_id"])
            proxy.event(child_task["id"], "agent_model_call", "bounded test event")
            return {"status": "completed", "progressive_triage": {"validated_vulnerability": 0}}

        with tempfile.TemporaryDirectory() as directory, \
                patch("src.workbench.agent.ProviderConfig.from_env", return_value=provider), \
                patch("src.workbench.progressive_triage.deep_agent_operation.execute_progressive_deep_agent",
                      side_effect=execute):
            result = execute_progressive_deep_agent_batch(
                SimpleNamespace(data_dir=Path(directory)), object(), FakeOps(), task)
        self.assertEqual(calls, ["group-1", "group-2"])
        self.assertEqual(result["completed_group_count"], 2)
        self.assertEqual(result["validated_vulnerability"], 0)
        self.assertEqual(len(events), 2)
        self.assertTrue(all(row[0] == task["id"] for row in events))

    def test_provider_quota_stops_and_preserves_remaining_group_as_candidate(self):
        audit_id, l2_id, l2, l2_result, task = make_task()

        class FakeOps:
            def get(self, key):
                if key == l2_id:
                    return l2
                if key == task["id"]:
                    return {**task, "cancel_requested": False}
                raise KeyError(key)

            def result(self, key):
                if key == l2_id:
                    return l2_result
                raise KeyError(key)

            def event(self, *_args):
                pass

        provider = SimpleNamespace(configured=True, fingerprint="1" * 64,
                                   model="test-model")
        with tempfile.TemporaryDirectory() as directory, \
                patch("src.workbench.agent.ProviderConfig.from_env", return_value=provider), \
                patch("src.workbench.progressive_triage.deep_agent_operation.execute_progressive_deep_agent",
                      side_effect=ValueError("Provider quota or billing limit exhausted")) as execute:
            result = execute_progressive_deep_agent_batch(
                SimpleNamespace(data_dir=Path(directory)), object(), FakeOps(), task)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(result["stop_reason"], "provider_quota_exhausted")
        self.assertEqual(result["not_started"], [{"group_id": "group-2", "state": "not_started_candidate"}])
        self.assertFalse(result["candidate_disposition_changed"])

    def test_batch_api_requires_explicit_consent_and_replays_same_approval(self):
        from fastapi.testclient import TestClient
        from src.workbench.api import create_app
        from src.workbench.settings import Settings

        audit_id = "a" * 32
        l2_id = "b" * 32
        result_sha = "c" * 64
        report_sha = "d" * 64
        source_sha = "e" * 64
        commit = "f" * 40
        group_id = "group-api"
        candidate_id = "candidate-api"
        policy = build_policy()
        frozen = {"revision": 1, "policy": policy,
                  "policy_sha256": policy_envelope(policy)["policy_sha256"]}
        l2 = {"id": l2_id, "kind": "progressive_quick_screen_batch",
              "status": "completed", "result_sha256": result_sha,
              "spec": {"audit_operation_id": audit_id, "progressive_policy": frozen,
                       "items": [{"group_id": group_id, "spec": {
                           "job_id": audit_id, "candidate_id": candidate_id,
                           "audit_operation_id": audit_id, "progressive_policy": frozen,
                           "authorization": {"report_sha256": report_sha},
                           "group": {"group_id": group_id},
                       }}]}}
        l2_result = {"groups": [{
            "group_id": group_id, "candidate_id": candidate_id, "job_id": audit_id,
            "state": "completed", "quick_assessment": "investigate",
            "result": {
                "quick_screen": {"state": "completed", "quick_assessment": "investigate"},
                "source_binding": {"report_sha256": report_sha, "commit": commit},
            },
        }]}
        provider = SimpleNamespace(
            configured=True, provider="test-provider", model="test-model",
            fingerprint="1" * 64, endpoint_host="provider.test",
            public={"provider": "test-provider", "model": "test-model"},
        )
        agent_preview = {
            "agent_execution": {"eligible": True}, "consent_sha256": "2" * 64,
            "binding": {"source_sha256": source_sha, "commit": commit,
                        "report_sha256": report_sha, "repository": "fixture/repo",
                        "file": "src/a.cpp"},
            "allowed_tools": ["find_callers"], "initial_context": {"file": "src/a.cpp"},
            "additional_tool_data_scope": ["src/**"],
            "disclosure": ["fixed-commit read-only investigation"],
            "budgets": {"max_total_input_tokens": 4000, "max_total_output_tokens": 1000,
                        "max_steps": 4, "timeout_seconds": 90},
        }

        with tempfile.TemporaryDirectory() as directory:
            app = create_app(Settings(Path(directory) / "data", ()))
            ops = app.state.operations
            created = []
            job = {"id": audit_id, "status": "completed", "report_sha256": report_sha,
                   "spec": {"audit_mode": "standard_review"}}
            app.state.store.job = lambda _key: job
            ops.get = lambda key: l2 if key == l2_id else (_ for _ in ()).throw(KeyError(key))
            ops.result = lambda key: l2_result if key == l2_id else (_ for _ in ()).throw(KeyError(key))
            ops.progressive_operations_for_audit = lambda _audit: list(created)

            def create(kind, spec):
                item = {"id": "9" * 32, "kind": kind, "status": "queued", "spec": spec}
                created.append(item)
                return item

            ops.create = create
            with patch("src.workbench.agent.ProviderConfig.from_env", side_effect=[provider, provider]) as provider_from_env, \
                    patch("src.workbench.agent.consent_preview",
                          side_effect=lambda *_args, **_kwargs: dict(agent_preview)), \
                    patch("src.workbench.service.read_report", return_value={"repository": "fixture/repo", "commit": commit}), \
                    patch("src.workbench.service.finding", return_value={"id": candidate_id}):
                with TestClient(app, headers={"x-ohscanner-client": "workbench-v1"}) as client:
                    preview_response = client.post(
                        "/api/v1/operations/progressive-deep-investigation-batches/preview",
                        json={"progressive_quick_screen_batch_id": l2_id})
                    self.assertEqual(preview_response.status_code, 200, preview_response.text)
                    preview = preview_response.json()
                    payload = {
                        "progressive_quick_screen_batch_id": l2_id,
                        "consent_sha256": preview["consent_sha256"],
                        "consent_nonce": preview["consent_nonce"],
                        "consent_expires_at": preview["consent_expires_at"],
                    }
                    denied = client.post(
                        "/api/v1/operations/progressive-deep-investigation-batches",
                        json={**payload, "source_submission_approved": False})
                    started = client.post(
                        "/api/v1/operations/progressive-deep-investigation-batches",
                        json={**payload, "source_submission_approved": True})
                    replay = client.post(
                        "/api/v1/operations/progressive-deep-investigation-batches",
                        json={**payload, "source_submission_approved": True})
                    self.assertEqual(provider_from_env.call_count, 2,
                                     "idempotent replay should not require current Provider configuration")

        self.assertEqual(len(preview["disclosures"]), 1)
        self.assertEqual(preview["disclosures"][0]["allowed_tools"], ["find_callers"])
        self.assertEqual(denied.status_code, 428, denied.text)
        self.assertEqual(started.status_code, 201, started.text)
        self.assertEqual(replay.status_code, 201, replay.text)
        self.assertEqual(started.json()["id"], replay.json()["id"])
        self.assertEqual(len(created), 1, "replaying consent must not queue a second L3 batch")


if __name__ == "__main__":
    unittest.main()

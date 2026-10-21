"""Task-consented L3 batches stop safely and reuse the existing Agent path."""
from datetime import datetime, timedelta, timezone
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

    def test_budget_gate_stops_and_preserves_remaining_group_as_candidate(self):
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
                      side_effect=ValueError("task-wide model-call budget exhausted")) as execute:
            result = execute_progressive_deep_agent_batch(
                SimpleNamespace(data_dir=Path(directory)), object(), FakeOps(), task)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(result["stop_reason"], "budget_exhausted")
        self.assertEqual(result["not_started"], [{"group_id": "group-2", "state": "not_started_candidate"}])
        self.assertFalse(result["candidate_disposition_changed"])


if __name__ == "__main__":
    unittest.main()

"""L3 must resolve each task-consented L2 batch member to its fixed evidence."""
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

from src.workbench.progressive_triage import build_policy
from src.workbench.progressive_triage.contracts import content_sha256
from src.workbench.progressive_triage.deep_agent_operation import progressive_gate
from src.workbench.progressive_triage.policy import policy_envelope


class ProgressiveDeepBatchBindingTests(unittest.TestCase):
    def test_l3_gate_resolves_only_the_matching_investigate_member(self):
        policy = build_policy()
        frozen = {"revision": 7, "policy": policy,
                  "policy_sha256": policy_envelope(policy)["policy_sha256"]}
        group_id = "group-fixed"
        candidate_id = "candidate-fixed"
        job_id = "a" * 32
        batch_id = "b" * 32
        report_sha = "c" * 64
        commit = "d" * 40
        child_spec = {
            "job_id": job_id, "candidate_id": candidate_id,
            "audit_operation_id": job_id, "progressive_policy": frozen,
            "group": {"group_id": group_id},
        }
        child_result = {
            "quick_screen": {"state": "completed", "quick_assessment": "investigate"},
            "source_binding": {"report_sha256": report_sha, "commit": commit},
        }
        batch_result = {"groups": [{"group_id": group_id, "candidate_id": candidate_id,
                                    "state": "completed", "result": child_result}]}
        batch = {"id": batch_id, "kind": "progressive_quick_screen_batch",
                 "status": "completed", "result_sha256": "e" * 64,
                 "spec": {"audit_operation_id": job_id, "items": [
                     {"group_id": group_id, "spec": child_spec}]}}

        class FakeOperations:
            def get(self, operation_id):
                if operation_id == batch_id:
                    return batch
                raise KeyError(operation_id)

            def result(self, operation_id):
                if operation_id == batch_id:
                    return batch_result
                raise KeyError(operation_id)

        task = {"id": "f" * 32, "spec": {
            "progressive_quick_screen_operation_id": batch_id,
            "progressive_quick_screen_result_sha256": "e" * 64,
            "progressive_quick_screen_batch_group_id": group_id,
            "progressive_audit_operation_id": job_id,
            "progressive_group_id": group_id,
            "progressive_policy_sha256": frozen["policy_sha256"],
            "progressive_policy": frozen,
            "job_id": job_id, "candidate_id": candidate_id,
            "report_sha256": report_sha, "source_commit": commit,
        }}
        with tempfile.TemporaryDirectory() as directory:
            settings = SimpleNamespace(data_dir=Path(directory))
            resolved, ledger = progressive_gate(settings, FakeOperations(), task)
            self.assertEqual(resolved["progressive_group_id"], group_id)
            self.assertEqual(ledger.get(job_id)["phase_counts"]["deep_agent_groups"], 0)


if __name__ == "__main__":
    unittest.main()

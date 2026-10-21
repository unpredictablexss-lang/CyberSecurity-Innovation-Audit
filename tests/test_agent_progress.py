"""Progress classification must distinguish terminal failure from completion."""
import unittest

from src.workbench.operations_api import _classify_intelligent_review


def operation(identifier, status, *, candidate_id=None, error=None):
    return {"id": identifier, "status": status,
            "spec": {"candidate_id": candidate_id or identifier},
            "error": error}


def batch(**overrides):
    value = {"status": "queued", "candidate_count": 2, "selected_count": 2,
             "r2_status": "not_requested"}
    value.update(overrides)
    return value


class IntelligentReviewProgressTests(unittest.TestCase):
    def test_all_failed_is_failed_and_exposes_stage_reason(self):
        progress = _classify_intelligent_review(batch(), [
            operation("r1-a", "failed", error="provider quota exhausted"),
            operation("r1-b", "timed_out", error="per-request timeout"),
        ], [])
        self.assertEqual(progress["state"], "failed")
        self.assertEqual(progress["r1"]["failed_count"], 2)
        self.assertEqual(progress["r1"]["timed_out_count"], 1)
        self.assertEqual(len(progress["r1"]["failure_reasons"]), 2)
        self.assertEqual(progress["r1"]["failure_reasons"][0]["reason"],
                         "provider quota exhausted")

    def test_mixed_success_and_failure_is_partially_completed(self):
        progress = _classify_intelligent_review(batch(), [
            operation("r1-a", "completed"),
            operation("r1-b", "failed", error="provider error"),
        ], [])
        self.assertEqual(progress["state"], "partially_completed")
        self.assertEqual(progress["r1"]["completed_count"], 1)
        self.assertEqual(progress["r1"]["failed_count"], 1)

    def test_completed_with_limitations_is_separate_from_full_completion(self):
        progress = _classify_intelligent_review(batch(), [
            operation("r1-a", "completed_with_limitations"),
            operation("r1-b", "completed"),
        ], [])
        self.assertEqual(progress["state"], "completed_with_limitations")
        self.assertEqual(progress["r1"]["completed_count"], 1)
        self.assertEqual(progress["r1"]["completed_with_limitations_count"], 1)
        self.assertEqual(progress["r1"]["status_counts"]["completed_with_limitations"], 1)

    def test_queued_only_is_queued_and_not_completed(self):
        progress = _classify_intelligent_review(batch(), [
            operation("r1-a", "queued"), operation("r1-b", "queued"),
        ], [])
        self.assertEqual(progress["state"], "queued")
        self.assertEqual(progress["r1"]["queued_count"], 2)
        self.assertEqual(progress["r1"]["completed_count"], 0)

    def test_revoked_authorization_is_explicit_even_when_work_is_pending(self):
        progress = _classify_intelligent_review(batch(), [
            operation("r1-a", "queued"),
        ], [], revoked=True)
        self.assertEqual(progress["state"], "revoked")
        self.assertEqual(progress["r1"]["queued_count"], 1)


if __name__ == "__main__":
    unittest.main()

import unittest

from src.workbench.agent_guidance import recommend_investigation_route


class InvestigationGuidanceTests(unittest.TestCase):
    def test_auth_candidate_splits_source_assist_and_human_runtime_gates(self):
        result = recommend_investigation_route([
            {"kind": "entry_reachability", "status": "unknown"},
            {"kind": "callee_and_policy", "status": "unknown"},
            {"kind": "security_impact", "status": "unknown"},
            {"kind": "consequence", "status": "unknown"},
        ], scan_status="completed_with_limitations", detector_status="partial",
           analysis_status="analyzed")
        self.assertEqual(result["route"], "agent_source_review_with_human_followup")
        self.assertEqual(result["agent_source_review_indices"], [1])
        self.assertEqual(result["human_or_runtime_review_indices"], [0, 2, 3])
        self.assertEqual(result["unclassified_indices"], [])
        self.assertTrue(result["coverage_incomplete"])
        self.assertEqual(result["vulnerability_state"], "candidate")
        self.assertEqual(result["validated_vulnerability"], 0)

    def test_unknown_obligation_kind_defaults_to_human_review(self):
        result = recommend_investigation_route([
            {"kind": "future_detector_obligation", "status": "missing"},
        ], scan_status="completed", detector_status="complete",
           analysis_status="analyzed")
        self.assertEqual(result["route"], "human_or_runtime_validation")
        self.assertEqual(result["agent_source_review_indices"], [])
        self.assertEqual(result["unclassified_indices"], [0])

    def test_unknown_kind_cannot_be_hidden_by_closed_status(self):
        result = recommend_investigation_route([
            {"kind": "future_detector_obligation", "status": "satisfied"},
        ], scan_status="completed", detector_status="complete",
           analysis_status="analyzed")
        self.assertEqual(result["route"], "human_or_runtime_validation")
        self.assertEqual(result["human_or_runtime_review_indices"], [0])
        self.assertEqual(result["unclassified_indices"], [0])
        self.assertEqual(result["closed_obligation_count"], 0)
        self.assertEqual(result["vulnerability_state"], "candidate")
        self.assertEqual(result["validated_vulnerability"], 0)

    def test_closed_obligations_do_not_request_llm_but_candidate_stays_candidate(self):
        result = recommend_investigation_route([
            {"kind": "callee_and_policy", "status": "satisfied"},
            {"kind": "entry_reachability", "status": "not_applicable"},
        ], scan_status="completed", detector_status="complete",
           analysis_status="analyzed")
        self.assertEqual(result["route"], "human_review")
        self.assertEqual(result["open_obligation_count"], 0)
        self.assertEqual(result["closed_obligation_count"], 2)
        self.assertEqual(result["vulnerability_state"], "candidate")
        self.assertEqual(result["validated_vulnerability"], 0)

    def test_string_and_malformed_obligations_stay_unknown_for_humans(self):
        result = recommend_investigation_route(["untyped", {"kind": "callee_and_policy"}],
            scan_status="unknown", detector_status="unknown", analysis_status="unknown")
        self.assertEqual(result["human_or_runtime_review_indices"], [0])
        self.assertEqual(result["agent_source_review_indices"], [1])
        self.assertEqual(result["unclassified_indices"], [0])
        self.assertTrue(result["coverage_incomplete"])


if __name__ == "__main__":
    unittest.main()

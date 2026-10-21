import copy
import unittest

from src.workbench import agent
from src.workbench.smart_audit import _agent_evidence_chain_gate


def build_valid_agent_result(binding=None, candidate_file="src/guard.cpp", obligation_count=2):
    """Build a synthetic, fully source-bound tool-agent graph for gate controls."""
    binding = dict(binding or {
        "job_id": "job-fixed", "repository": "org/repo", "commit": "c" * 40,
        "tree": "d" * 40, "snapshot_sha256": "e" * 64,
        "report_sha256": "f" * 64, "candidate_id": "candidate-fixed",
        "file": candidate_file, "source_sha256": "a" * 64,
    })
    candidate_file = binding["file"]
    helper_file = "src/helper.cpp" if candidate_file != "src/helper.cpp" else "src/other.cpp"
    helper_hash = "b" * 64
    source_id = "ev-candidate-source"
    helper_id = "ev-cross-file-source"
    local_citation = {"evidence_id": source_id, "file": candidate_file,
                      "line_start": 10, "line_end": 10}
    helper_citation = {"evidence_id": helper_id, "file": helper_file,
                       "line_start": 20, "line_end": 20}
    count = max(1, obligation_count)
    obligation_reviews = []
    for index in range(count):
        citations = [local_citation, helper_citation]
        obligation_reviews.append({
            "obligation_index": index, "disposition": "evidence_found",
            "citations": copy.deepcopy(citations),
        })
    result = {
        "status": "completed_with_limitations",
        "mode": "tool_agent",
        "vulnerability_state": "candidate",
        "validated_vulnerability": 0,
        "binding": {**binding, "git_blob": "1" * 40},
        "initial_evidence": {
            "evidence_id": "ev-initial", "file": candidate_file,
            "source_sha256": binding["source_sha256"], "git_blob": "1" * 40,
            "source_excerpt_start_line": 1, "source_excerpt_end_line": 2,
            "context_sha256": "2" * 64,
            "context": {"evidence_obligations": [
                {"index": index, "description": f"obligation {index}"} for index in range(count)
            ]},
        },
        "tool_calls": [
            {"step": 1, "tool": "read_fixed_source_range", "evidence_id": source_id,
             "evidence_kind": "source_code", "status": "completed",
             "result_sha256": "3" * 64,
             "result": {"commit": binding["commit"], "file": candidate_file,
                        "source_sha256": binding["source_sha256"], "git_blob": "4" * 40,
                        "start_line": 10, "end_line": 10}},
            {"step": 2, "tool": "read_fixed_source_range", "evidence_id": helper_id,
             "evidence_kind": "source_code", "status": "completed",
             "result_sha256": "5" * 64,
             "result": {"commit": binding["commit"], "file": helper_file,
                        "source_sha256": helper_hash, "git_blob": "6" * 40,
                        "start_line": 20, "end_line": 20}},
        ],
        "agent_assessment": {
            "assessment": "likely_true_positive", "supported_claims": [
                {"claim": "source-level candidate", "citations": [copy.deepcopy(helper_citation)]}
            ],
            "unsupported_claims": [],
            "obligation_reviews": obligation_reviews,
            "vulnerability_report": {
                "status": "draft_unverified", "citations": [copy.deepcopy(helper_citation)]
            },
            "poc_draft": {"status": "draft_unexecuted", "citations": [copy.deepcopy(helper_citation)]},
        },
        "agent_verdict": {
            "status": "confirmed", "confidence": "high", "scope": "fixed_source_code",
            "product_status": "unknown",
        },
        "skeptic_review": {
            "status": "completed",
            "reviews": [{"obligation_index": index,
                         "result": "no_counterevidence_observed", "citations": []}
                        for index in range(count)],
        },
        "artifact_generation": {"status": "completed"},
        "citation_integrity": {"status": "accepted"},
        "workflow": {"stages": [
            {"id": "collect_fixed_source_evidence", "status": "completed"},
            {"id": "primary_source_triage", "status": "accepted"},
            {"id": "independent_skeptic", "status": "completed"},
            {"id": "candidate_report_and_poc_draft", "status": "completed"},
            {"id": "validate_report", "status": "accepted"},
        ]},
    }
    evidence_lines = {
        "ev-initial": {candidate_file: {1: "void guard() {", 2: "}"}},
        source_id: {candidate_file: {10: "check local invariant();"}},
        helper_id: {helper_file: {20: "enforce shared policy();"}},
    }
    result["evidence_graph"] = agent._build_evidence_graph(result, evidence_lines)
    return result


class AgentEvidenceChainGateTests(unittest.TestCase):
    def setUp(self):
        self.expected = {
            "job_id": "job-fixed", "repository": "org/repo", "commit": "c" * 40,
            "tree": "d" * 40, "snapshot_sha256": "e" * 64,
            "report_sha256": "f" * 64, "candidate_id": "candidate-fixed",
        }
        self.candidate = {"file": "src/guard.cpp"}

    def test_complete_fixed_source_cross_file_graph_passes_as_candidate(self):
        result = build_valid_agent_result()
        accepted, reason = _agent_evidence_chain_gate(result, self.expected, self.candidate)
        self.assertTrue(accepted, reason)
        self.assertEqual(result["vulnerability_state"], "candidate")
        self.assertEqual(result["validated_vulnerability"], 0)

    def test_incomplete_provenance_or_review_never_passes(self):
        mutations = {
            "unresolved_reference": lambda result: result["evidence_graph"]["unresolved_references"].append(
                {"status": "unknown"}),
            "unresolved_obligation": lambda result: result["agent_assessment"]["obligation_reviews"][0].update(
                disposition="unresolved"),
            "counterevidence": lambda result: result["skeptic_review"]["reviews"][0].update(
                result="counterevidence_candidate"),
            "binding_mismatch": lambda result: result["evidence_graph"]["binding"].update(
                commit="0" * 40),
            "no_cross_file_citation": self._remove_cross_file_reviews,
            "cross_file_missing_for_one_obligation": self._remove_one_obligation_cross_file_review,
            "non_integer_zero": lambda result: result.update(validated_vulnerability=False),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                result = build_valid_agent_result()
                mutate(result)
                accepted, _ = _agent_evidence_chain_gate(result, self.expected, self.candidate)
                self.assertFalse(accepted)

    @staticmethod
    def _remove_one_obligation_cross_file_review(result):
        result["agent_assessment"]["obligation_reviews"][0]["citations"] = [{
            "evidence_id": "ev-candidate-source", "file": "src/guard.cpp",
            "line_start": 10, "line_end": 10,
        }]

    @staticmethod
    def _remove_cross_file_reviews(result):
        for row in result["agent_assessment"]["obligation_reviews"]:
            row["citations"] = [{
                "evidence_id": "ev-candidate-source", "file": "src/guard.cpp",
                "line_start": 10, "line_end": 10,
            }]
        result["evidence_graph"] = agent._build_evidence_graph(result, {
            "ev-initial": {"src/guard.cpp": {1: "void guard() {", 2: "}"}},
            "ev-candidate-source": {"src/guard.cpp": {10: "check local invariant();"}},
            "ev-cross-file-source": {"src/helper.cpp": {20: "enforce shared policy();"}},
        })


if __name__ == "__main__":
    unittest.main()

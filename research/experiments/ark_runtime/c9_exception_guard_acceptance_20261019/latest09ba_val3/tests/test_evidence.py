import unittest

from src.benchmark.tool_result import ToolDiagnostic
from src.evidence.from_tool_result import evidence_from_tool_diagnostic
from src.evidence.from_triage import evidence_from_review_packet
from src.triage.review import CandidateReviewPacket, ReviewState


def _packet() -> CandidateReviewPacket:
    return CandidateReviewPacket(
        candidate_id="id-1",
        rule_id="cpp.dangerous_call.strcpy",
        file="/target/x.c",
        line=10,
        function="demo",
        call_name="strcpy",
        call_parse_status="parsed_text_call",
        call_start_line=10,
        call_end_line=10,
        call_expression="strcpy(a, b)",
        call_arguments=["a", "b"],
        context_status="ast_function_context",
        context="strcpy(a, b);",
        obligations=["destination capacity"],
        review=ReviewState(),
    )


class EvidenceFromToolResultTests(unittest.TestCase):
    def test_tool_diagnostic_becomes_evidence(self) -> None:
        diagnostic = ToolDiagnostic(
            diagnostic_id="semgrep:x.c:10:r:0",
            provider="semgrep",
            evidence_type="pattern",
            file="x.c",
            line=10,
            column=1,
            rule_id="r",
            severity="warning",
            message="unsafe strcpy",
            candidate_cwe="CWE-120",
        )
        evidence = evidence_from_tool_diagnostic(diagnostic, "t1")

        self.assertEqual(evidence.type, "pattern")
        self.assertEqual(evidence.source, "semgrep")
        self.assertEqual(evidence.location, "x.c:10")
        self.assertEqual(evidence.content, "unsafe strcpy")
        self.assertIn("semgrep reported", evidence.proposition)
        self.assertEqual(evidence.confidence, 0.0)

    def test_tool_diagnostic_without_line_uses_file_only(self) -> None:
        diagnostic = ToolDiagnostic(
            diagnostic_id="d",
            provider="codeql",
            evidence_type="dataflow",
            file="x.c",
            line=None,
            column=None,
            rule_id=None,
            severity="warning",
            message="flow",
        )
        evidence = evidence_from_tool_diagnostic(diagnostic, "t1")
        self.assertEqual(evidence.location, "x.c")


class EvidenceFromTriageTests(unittest.TestCase):
    def test_reviewed_packet_yields_evidence_per_dimension(self) -> None:
        packet = _packet()
        packet.review.review_status = "likely_safe_static"
        packet.review.destination_capacity = "sufficient_static"
        evidences = evidence_from_review_packet(packet)

        self.assertEqual(len(evidences), 2)
        self.assertTrue(all(item.type == "human_review" for item in evidences))
        propositions = {item.proposition for item in evidences}
        self.assertIn("Manual review set status to likely_safe_static", propositions)

    def test_unreviewed_packet_yields_no_evidence(self) -> None:
        packet = _packet()
        evidences = evidence_from_review_packet(packet)
        self.assertEqual(evidences, [])

    def test_reviewer_notes_become_evidence(self) -> None:
        packet = _packet()
        packet.review.reviewer_notes = ["checked alloc"]
        evidences = evidence_from_review_packet(packet)
        self.assertEqual(len(evidences), 1)
        self.assertEqual(evidences[0].content, "checked alloc")


if __name__ == "__main__":
    unittest.main()

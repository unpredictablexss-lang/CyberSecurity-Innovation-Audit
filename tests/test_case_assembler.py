import unittest

from src.case.assembler import assemble_case_draft
from src.core.evidence import Evidence


def _evidence(content: str) -> Evidence:
    return Evidence(
        evidence_id=f"evt-{content}",
        type="human_review",
        source="manual_review",
        content=content,
    )


class CaseAssemblerTests(unittest.TestCase):
    def test_draft_case_has_draft_status_and_unassessed_confidence(self) -> None:
        case = assemble_case_draft("cand-1", [_evidence("x")])
        self.assertEqual(case.report_status, "draft")
        self.assertEqual(case.confidence, "unassessed")
        self.assertEqual(case.severity, "unassessed")

    def test_draft_case_carries_evidence_and_related_finding(self) -> None:
        evidences = [_evidence("a"), _evidence("b")]
        case = assemble_case_draft("cand-1", evidences)
        self.assertEqual(case.evidence, evidences)
        self.assertEqual(case.related_findings, ["cand-1"])
        self.assertEqual(case.title, "Draft case for cand-1")

    def test_draft_case_id_is_stable(self) -> None:
        first = assemble_case_draft("cand-1", [])
        second = assemble_case_draft("cand-1", [])
        other = assemble_case_draft("cand-2", [])
        self.assertEqual(first.case_id, second.case_id)
        self.assertNotEqual(first.case_id, other.case_id)

    def test_draft_case_never_becomes_reportable(self) -> None:
        case = assemble_case_draft("cand-1", [_evidence("x")])
        self.assertNotEqual(case.report_status, "reportable")
        self.assertNotEqual(case.report_status, "validated_target")

    def test_rejects_empty_candidate_id(self) -> None:
        with self.assertRaises(ValueError):
            assemble_case_draft("   ", [])


if __name__ == "__main__":
    unittest.main()

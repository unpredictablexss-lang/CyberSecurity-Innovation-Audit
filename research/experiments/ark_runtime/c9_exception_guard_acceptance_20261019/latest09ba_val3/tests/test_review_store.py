import json
import tempfile
import unittest
from pathlib import Path

from src.triage.review import CandidateReviewPacket, ReviewState, TriageReport
from src.triage.review_store import export_review_template, merge_review_annotations


def _packet(candidate_id: str, line: int) -> CandidateReviewPacket:
    return CandidateReviewPacket(
        candidate_id=candidate_id,
        rule_id="cpp.dangerous_call.strcpy",
        file="/target/x.c",
        line=line,
        function="demo",
        call_name="strcpy",
        call_parse_status="parsed_text_call",
        call_start_line=line,
        call_end_line=line,
        call_expression="strcpy(a, b)",
        call_arguments=["a", "b"],
        context_status="ast_function_context",
        context="strcpy(a, b);",
        obligations=["destination capacity"],
        review=ReviewState(),
    )


def _report() -> TriageReport:
    return TriageReport(
        source_report="/tmp/scan.json",
        target="/target",
        candidate_count=2,
        packet_count=2,
        packets=[_packet("id-1", 10), _packet("id-2", 20)],
    )


class ReviewStoreTests(unittest.TestCase):
    def test_export_writes_one_entry_per_packet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "reviews.json"
            export_review_template(_report(), out)
            data = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(len(data), 2)
        self.assertEqual({item["candidate_id"] for item in data}, {"id-1", "id-2"})
        self.assertEqual(data[0]["review_status"], "unreviewed")
        self.assertEqual(data[0]["reviewer"], "")

    def test_merge_updates_review_fields_only(self) -> None:
        report = _report()
        with tempfile.TemporaryDirectory() as directory:
            review_file = Path(directory) / "reviews.json"
            review_file.write_text(
                json.dumps(
                    [
                        {
                            "candidate_id": "id-1",
                            "review_status": "likely_safe_static",
                            "destination_capacity": "sufficient_static",
                            "reviewer": "ttl",
                            "notes": "checked alloc",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            merge_review_annotations(report, review_file)

        packet1 = next(p for p in report.packets if p.candidate_id == "id-1")
        packet2 = next(p for p in report.packets if p.candidate_id == "id-2")
        self.assertEqual(packet1.review.review_status, "likely_safe_static")
        self.assertEqual(packet1.review.destination_capacity, "sufficient_static")
        self.assertEqual(packet1.line, 10)  # identity not overwritten
        self.assertEqual(packet2.review.review_status, "unreviewed")
        self.assertIn("reviewer: ttl", packet1.review.reviewer_notes)
        self.assertIn("checked alloc", packet1.review.reviewer_notes)

    def test_merge_skips_unknown_candidate_id(self) -> None:
        report = _report()
        with tempfile.TemporaryDirectory() as directory:
            review_file = Path(directory) / "reviews.json"
            review_file.write_text(
                json.dumps([{"candidate_id": "unknown", "review_status": "x"}]),
                encoding="utf-8",
            )
            result = merge_review_annotations(report, review_file)

        self.assertEqual(result, report)
        self.assertTrue(all(p.review.review_status == "unreviewed" for p in report.packets))

    def test_merge_rejects_non_array_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            review_file = Path(directory) / "reviews.json"
            review_file.write_text(json.dumps({"candidate_id": "x"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                merge_review_annotations(_report(), review_file)


if __name__ == "__main__":
    unittest.main()

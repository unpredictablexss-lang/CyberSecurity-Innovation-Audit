from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from research.tests.a_null_03_unsafe_memory_review.merge_review_labels import merge_locked_labels


class MergeBlindReviewLabelsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.reviewer = self.root / "reviewer"
        self.coordinator = self.root / "coordinator"
        self.reviewer.mkdir()
        self.coordinator.mkdir()
        self.canonical = self.reviewer / "blind_review_queue.csv"
        self.submitted = self.root / "submitted.csv"
        self.key = self.coordinator / "review_key.csv"
        self._write_csv(self.canonical, [
            {
                "review_sample_id": "sample-a", "repository": "org/a", "commit": "abc",
                "file": "a.c", "line": "3", "source_sha256": "sha-a",
                "source_binding_status": "source_bound", "source_context": "line 3",
                "reviewer_disposition": "", "reviewer_rationale": "",
                "evidence_reference": "", "confidence": "", "reviewer_id": "",
            },
            {
                "review_sample_id": "sample-b", "repository": "org/b", "commit": "def",
                "file": "b.c", "line": "8", "source_sha256": "sha-b",
                "source_binding_status": "source_bound", "source_context": "line 8",
                "reviewer_disposition": "", "reviewer_rationale": "",
                "evidence_reference": "", "confidence": "", "reviewer_id": "",
            },
        ])
        self._write_csv(self.key, [
            {"review_sample_id": "sample-a", "inclusion_probability": "0.5", "rule_id": "r1", "scanner_message": "hidden a"},
            {"review_sample_id": "sample-b", "inclusion_probability": "0.5", "rule_id": "r2", "scanner_message": "hidden b"},
        ])
        self._write_csv(self.submitted, [
            {**row, "reviewer_disposition": label, "reviewer_rationale": "checked call and dataflow",
             "evidence_reference": f"{row['file']}:{row['line']}", "confidence": "medium", "reviewer_id": "reviewer-1"}
            for row, label in zip(self._read_csv(self.canonical), ("confirmed", "safe_or_fixed"))
        ])
        (self.reviewer.parent / "sampling_manifest.json").write_text(json.dumps({
            "report_count_dimensions": {
                "raw_observation_rows": {"count": 5, "status": "counted"},
                "within_repository_root_cause_clusters": {"count": None, "status": "not_established"},
                "cross_repository_identical_source_clusters": {"count": 1, "status": "counted"},
            }
        }), encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def _read_csv(path: Path) -> list[dict[str, str]]:
        with path.open(encoding="utf-8", newline="") as source:
            return list(csv.DictReader(source))

    def test_freeze_merges_labels_and_keeps_all_four_count_dimensions(self) -> None:
        import hashlib

        lock = hashlib.sha256(self.submitted.read_bytes()).hexdigest()
        merged, summary = merge_locked_labels(self.canonical, self.submitted, self.key, lock)
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0]["scanner_message"], "hidden a")
        self.assertEqual(summary["report_count_dimensions"]["raw_observation_rows"]["count"], 5)
        self.assertIsNone(summary["report_count_dimensions"]["within_repository_root_cause_clusters"]["count"])
        human = summary["report_count_dimensions"]["human_review_outcomes"]
        self.assertEqual(human["disposition_counts_in_sample"], {"confirmed": 1, "safe_or_fixed": 1})
        self.assertEqual(human["estimated_population_by_disposition_ht"], {"confirmed": 2.0, "safe_or_fixed": 2.0})

    def test_rejects_wrong_lock_hash(self) -> None:
        with self.assertRaisesRegex(ValueError, "hash does not match"):
            merge_locked_labels(self.canonical, self.submitted, self.key, "0" * 64)

    def test_rejects_changed_source_evidence_even_when_lock_is_updated(self) -> None:
        import hashlib

        rows = self._read_csv(self.submitted)
        rows[0]["source_context"] = "changed"
        self._write_csv(self.submitted, rows)
        lock = hashlib.sha256(self.submitted.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "immutable source/evidence field changed"):
            merge_locked_labels(self.canonical, self.submitted, self.key, lock)


if __name__ == "__main__":
    unittest.main()

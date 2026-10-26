from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from merge_null_candidate_review import merge_labels


class MergeNullCandidateReviewTests(unittest.TestCase):
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
        self.manifest = self.root / "sampling_manifest.json"
        self.headers = [
            "review_sample_id", "repository", "commit", "file", "line",
            "source_sha256", "source_binding_status", "source_context",
            "reviewer_disposition", "reviewer_rationale", "evidence_reference",
            "confidence", "reviewer_id",
        ]
        self.rows = [
            {
                "review_sample_id": f"sample-{i}", "repository": "repo/project", "commit": "abc123",
                "file": f"src/{i}.cpp", "line": str(i), "source_sha256": "a" * 64,
                "source_binding_status": "source_hash_matched", "source_context": f"{i}: *p;",
                "reviewer_disposition": "", "reviewer_rationale": "", "evidence_reference": "",
                "confidence": "", "reviewer_id": "",
            }
            for i in (1, 2)
        ]
        self._write_csv(self.canonical, self.headers, self.rows)
        self._write_csv(self.submitted, self.headers, [
            {**row, "reviewer_disposition": "confirmed" if i == 1 else "unknown",
             "reviewer_rationale": "checked source and control flow", "evidence_reference": f"src/{i}.cpp:{i}",
             "confidence": "medium", "reviewer_id": "reviewer-test"}
            for i, row in enumerate(self.rows, start=1)
        ])
        self._write_csv(self.key, ["review_sample_id", "source_role", "stratum", "inclusion_probability"], [
            {"review_sample_id": f"sample-{i}", "source_role": "blind", "stratum": "blind", "inclusion_probability": "0.5"}
            for i in (1, 2)
        ])
        self.manifest.write_text(json.dumps({
            "sample_size": 2,
            "run_identity": {"run_signature": "run"},
            "observed_raw_population": 10,
            "expected_population_claim": 99,
        }), encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _write_csv(path: Path, headers: list[str], rows: list[dict[str, str]]) -> None:
        with path.open("w", encoding="utf-8-sig", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)

    def _sha(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_merges_complete_labels_and_private_key(self) -> None:
        headers, rows, summary = merge_labels(self.canonical, self.submitted, self.key, self._sha(self.submitted))
        self.assertEqual(len(rows), 2)
        self.assertIn("source_role", headers)
        self.assertEqual(rows[0]["source_role"], "blind")
        self.assertEqual(summary["disposition_counts_in_sample"], {"confirmed": 1, "unknown": 1})
        self.assertEqual(summary["human_review_outcomes"]["pending"], 0)

    def test_rejects_wrong_frozen_hash(self) -> None:
        with self.assertRaisesRegex(ValueError, "frozen label lock"):
            merge_labels(self.canonical, self.submitted, self.key, "0" * 64)

    def test_rejects_changed_source_identity(self) -> None:
        _headers, submitted_rows = self._read_csv(self.submitted)
        submitted_rows[0]["source_context"] = "rewritten"
        self._write_csv(self.submitted, self.headers, submitted_rows)
        with self.assertRaisesRegex(ValueError, "immutable evidence changed"):
            merge_labels(self.canonical, self.submitted, self.key, self._sha(self.submitted))

    @staticmethod
    def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
        with path.open(encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            return list(reader.fieldnames or []), list(reader)


if __name__ == "__main__":
    unittest.main()

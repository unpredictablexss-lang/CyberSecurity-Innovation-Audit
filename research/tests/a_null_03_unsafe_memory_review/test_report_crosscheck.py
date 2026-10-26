from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from research.tests.a_null_03_unsafe_memory_review.build_review_sample import crosscheck_report, sha256


class ReportCrosscheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.run_config = {
            "run_signature": "a" * 64,
            "scanner_commit": "b" * 40,
            "manifest_sha256": "c" * 64,
        }
        summary = {
            "scanner": {
                "run_signature": self.run_config["run_signature"],
                "commit": self.run_config["scanner_commit"],
                "manifest_sha256": self.run_config["manifest_sha256"],
            },
            "candidate_counts_by_detector": {"ohscanner.cpp.unsafe_memory_call": 5},
        }
        (self.root / "compact-summary.json").write_text(json.dumps(summary), encoding="utf-8")
        with (self.root / "检测器能力.csv").open("w", encoding="utf-8", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=("detector", "candidate_count"))
            writer.writeheader()
            writer.writerow({"detector": "ohscanner.cpp.unsafe_memory_call", "candidate_count": 5})
        checksums = {
            "compact-summary.json": sha256(self.root / "compact-summary.json"),
            "检测器能力.csv": sha256(self.root / "检测器能力.csv"),
        }
        (self.root / "checksums.json").write_text(json.dumps(checksums), encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_requires_same_run_identity_count_and_checksums(self) -> None:
        result = crosscheck_report(self.root, self.run_config, 5)
        self.assertEqual(result["status"], "matched_same_run_signature_and_count")
        self.assertEqual(result["unsafe_memory_candidate_count"], 5)

    def test_rejects_report_from_a_different_scan(self) -> None:
        other_run = {**self.run_config, "run_signature": "d" * 64}
        with self.assertRaisesRegex(ValueError, "run_signature"):
            crosscheck_report(self.root, other_run, 5)


if __name__ == "__main__":
    unittest.main()

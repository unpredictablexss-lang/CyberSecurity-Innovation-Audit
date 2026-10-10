from __future__ import annotations

import json
import unittest

from tests.detectors.fixture_support import ROOT


MANIFEST_PATH = (
    ROOT
    / "research"
    / "corpus"
    / "native"
    / "lifetime_uaf_native_run_2026-10-10.json"
)


@unittest.skipUnless(MANIFEST_PATH.exists(), "ignored native replay manifest is not present")
class NativeLifetimeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest_path = MANIFEST_PATH
        cls.manifest = json.loads(cls.manifest_path.read_text(encoding="utf-8"))

    def test_real_vulnerable_fixed_safe_runs_are_separate_and_not_misses(self) -> None:
        records = self.manifest["records"]
        self.assertEqual(
            [record["control_role"] for record in records],
            ["vulnerable", "fixed", "safe"],
        )
        self.assertEqual(len({record["run_id"] for record in records}), 3)
        self.assertEqual(len({record["evidence_unit_id"] for record in records}), 3)
        expected_inputs = {
            "vulnerable": "ce04ace5a2ad702d3f56e30be347dc9583c808dcf5aac80ee761bd70e05f1ad4",
            "fixed": "9ed18694defc088c7bfe69327f6e4668d6c23d72a4f3c5516ad4635e9e511606",
            "safe": "9ed18694defc088c7bfe69327f6e4668d6c23d72a4f3c5516ad4635e9e511606",
        }
        for record in records:
            with self.subTest(role=record["control_role"]):
                self.assertEqual(
                    record["input_sha256"],
                    expected_inputs[record["control_role"]],
                )
                self.assertEqual(record["result_status"], "not_applicable")
                self.assertEqual(record["result_evidence_count"], 0)
                self.assertEqual(record["status_semantics"]["miss"], "not assigned")
                self.assertIn("shared_ptr", record["not_applicable_reason"])
                self.assertIn("unique_ptr", record["not_applicable_reason"])
                self.assertTrue(record["source_artifact"]["source_file_sha256"])
                self.assertTrue(record["config_sha256"])
                self.assertTrue(record["normalized_artifact"]["sha256"])

        by_role = {record["control_role"]: record for record in records}
        self.assertEqual(by_role["vulnerable"]["execution_status"], "blocked")
        self.assertEqual(by_role["vulnerable"]["failure_status"], "blocked")
        self.assertIn("shared_ptr.reset", by_role["vulnerable"]["failure_reason"])
        self.assertEqual(by_role["fixed"]["execution_status"], "completed")
        self.assertEqual(by_role["safe"]["execution_status"], "completed")
        self.assertEqual(by_role["fixed"]["failure_status"], "none")
        self.assertEqual(by_role["safe"]["failure_status"], "none")

    def test_line_count_discrepancy_is_preserved_not_renamed_raw_backed(self) -> None:
        for record in self.manifest["records"]:
            observation = record["source_artifact"]["line_count_observation"]
            with self.subTest(role=record["control_role"]):
                self.assertEqual(observation["status"], "metadata_mismatch_preserved")
                self.assertEqual(observation["raw_splitlines"], observation["raw_newlines"])
                self.assertEqual(
                    observation["metadata_lines"],
                    observation["raw_splitlines"] + 1,
                )


if __name__ == "__main__":
    unittest.main()

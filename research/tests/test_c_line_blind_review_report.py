from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HOLDOUT = ROOT / "research/deliveries/cpp/holdout-arkcompiler-ets-frontend-fadba67"
SCRIPT = HOLDOUT / "report_blind_review.py"
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("c_line_blind_review_report", SCRIPT)
assert spec and spec.loader
report = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = report
spec.loader.exec_module(report)


class BlindReviewReportTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((HOLDOUT / "blind_manifest.json").read_text(encoding="utf-8"))
        self.census = json.loads((HOLDOUT / "component_census.json").read_text(encoding="utf-8"))
        self.attestation = {
            "reviewer_role": "independent reviewer",
            "independent_from_rule_development": True,
            "saw_detector_output_before_labeling": False,
            "blind_packet_only_until_labels_completed": True,
            "reviewed_detector_version": self.manifest["current_binding_version"],
            "labels_completed_utc": "2026-10-20T00:00:00Z",
        }
        self.rows = []
        for index in range(self.manifest["review"]["sample_count"]):
            label = "unknown" if index == 0 else "safe"
            self.rows.append({
                "sample_id": f"F{index + 1:03d}",
                "model_scope": "uncertain" if label == "unknown" else "out_of_scope",
                "evidence_label": label,
                "root_cause": "" if label == "unknown" else "not_applicable",
                "unknown_reason": "insufficient excerpt evidence" if label == "unknown" else "",
                "evidence_lines": "1-2",
                "reviewer_notes": "",
            })

    def test_requires_complete_rows_independence_and_blind_attestation(self):
        with self.assertRaisesRegex(ValueError, "exactly once"):
            report.validate_and_summarize(
                self.manifest, self.census, self.rows[:-1], self.attestation,
                packet_path=HOLDOUT / "blind_packet.md",
                labels_path=HOLDOUT / "reviewer_labels.csv",
            )
        bad = dict(self.attestation, saw_detector_output_before_labeling=True)
        with self.assertRaisesRegex(ValueError, "not seen"):
            report.validate_and_summarize(
                self.manifest, self.census, self.rows, bad,
                packet_path=HOLDOUT / "blind_packet.md",
                labels_path=HOLDOUT / "reviewer_labels.csv",
            )

    def test_reports_unknown_reasons_root_causes_and_coverage(self):
        result = report.validate_and_summarize(
            self.manifest, self.census, self.rows, self.attestation,
            packet_path=HOLDOUT / "blind_packet.md",
            labels_path=HOLDOUT / "reviewer_labels.csv",
        )
        self.assertEqual(result["unknown"], {
            "count": 1,
            "reasons": {"insufficient excerpt evidence": 1},
        })
        self.assertEqual(result["root_causes_by_label"], {"safe": {"not_applicable": 20}})
        self.assertEqual(result["coverage"]["samples_total"], 21)
        self.assertEqual(result["coverage"]["sampled_translation_units"], 21)

    def test_refuses_packet_content_changed_after_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            changed_packet = Path(temp) / "packet.md"
            changed_packet.write_text(
                (HOLDOUT / "blind_packet.md").read_text(encoding="utf-8") + "changed\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "packet content hash"):
                report.validate_and_summarize(
                    self.manifest, self.census, self.rows, self.attestation,
                    packet_path=changed_packet,
                    labels_path=HOLDOUT / "reviewer_labels.csv",
                )

    def test_refuses_component_census_manifest_drift(self):
        manifest = deepcopy(self.manifest)
        manifest["component_census"]["census_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "census content hash"):
            report.validate_and_summarize(
                manifest, self.census, self.rows, self.attestation,
                packet_path=HOLDOUT / "blind_packet.md",
                labels_path=HOLDOUT / "reviewer_labels.csv",
            )

    def test_refuses_component_census_manifest_drift(self):
        manifest = deepcopy(self.manifest)
        manifest["component_census"]["census_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "census content hash"):
            report.validate_and_summarize(
                manifest, self.census, self.rows, self.attestation,
                packet_path=HOLDOUT / "blind_packet.md",
                labels_path=HOLDOUT / "reviewer_labels.csv",
            )


if __name__ == "__main__":
    unittest.main()

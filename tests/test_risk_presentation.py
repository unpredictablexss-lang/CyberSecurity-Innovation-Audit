"""User-facing risk presentation must not turn candidate severity into product confirmation."""
import unittest

from src.workbench.smart_audit import severity_metadata, _severity


class SeverityPresentationTests(unittest.TestCase):
    def test_tentative_severity_is_preserved_without_trust_promotion(self):
        for value, expected in (("critical", "严重"), ("high", "高危"),
                                ("medium", "中危"), ("low", "低危"), ("info", "提示")):
            with self.subTest(value=value):
                actual = severity_metadata({"severity": value})
                self.assertEqual(actual["severity"], value)
                self.assertEqual(actual["severity_label"], expected)
                self.assertEqual(actual["severity_evidence"], "detector_preliminary_unverified")
                self.assertNotIn("validated_vulnerability", actual)
                self.assertNotIn("vulnerability_state", actual)

    def test_unassessed_scanner_severity_uses_known_cwe_as_unverified_hint(self):
        null_row = severity_metadata({
            "severity": "unassessed", "candidate_cwe": "CWE-476",
        })
        self.assertEqual(null_row["severity"], "medium")
        self.assertEqual(null_row["severity_label"], "中危")
        self.assertEqual(null_row["severity_basis"], "CWE-476")
        self.assertEqual(null_row["severity_evidence"], "cwe_type_heuristic_unverified")
        uaf = severity_metadata({
            "severity": "unassessed", "candidate_cwe": "CWE-416",
        })
        self.assertEqual(uaf["severity"], "high")
        self.assertEqual(uaf["severity_label"], "高危")

    def test_consequence_cwe_takes_precedence_without_claiming_impact(self):
        row = severity_metadata({
            "severity": "unassessed", "candidate_cwe": "CWE-190",
            "consequence_cwe": "CWE-787", "consequence_impact": "potential_memory_safety",
        })
        self.assertEqual(row["severity"], "high")
        self.assertEqual(row["severity_basis"], "CWE-787")
        self.assertNotIn("vulnerability_state", row)

    def test_agent_router_uses_same_tentative_tier_as_risk_badge(self):
        # Real ToolDiagnostic entries are currently always unassessed.
        self.assertEqual(_severity({"severity": "unassessed", "candidate_cwe": "CWE-416"}), 4)
        self.assertEqual(_severity({"severity": "unassessed", "candidate_cwe": "CWE-476"}), 3)
        self.assertEqual(_severity({"severity": "unassessed", "candidate_cwe": "CWE-999999"}), 0)
        self.assertEqual(_severity({"severity": "high", "candidate_cwe": "CWE-476"}), 4)
        self.assertEqual(_severity({"severity": "unassessed",
                                    "candidate_cwe": "CWE-190",
                                    "consequence_cwe": "CWE-787"}), 4)

    def test_unmapped_or_unproven_risk_remains_ungraded(self):
        for candidate in (
            {"severity": "unassessed"},
            {"severity": "unassessed", "candidate_cwe": None},
            {"severity": "unassessed", "candidate_cwe": "CWE-999999"},
            {"severity": "unassessed", "candidate_cwe": "CWE-532", "severity": "unknown",
             "consequence_cwe": "invalid"},
        ):
            actual = severity_metadata(candidate)
            if candidate.get("candidate_cwe") == "CWE-532":
                self.assertEqual(actual["severity"], "medium")
            else:
                self.assertEqual(actual["severity"], "unknown")

    def test_unknown_never_defaults_to_low_or_high(self):
        for value in (None, "", "not-provided", 0, "confirmed"):
            with self.subTest(value=value):
                actual = severity_metadata({"severity": value})
                self.assertEqual(actual["severity"], "unknown")
                self.assertEqual(actual["severity_label"], "未分级")


if __name__ == "__main__":
    unittest.main()

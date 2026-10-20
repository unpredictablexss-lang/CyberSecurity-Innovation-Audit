"""User-facing risk presentation must not turn candidate severity into product confirmation."""
import unittest

from src.workbench.smart_audit import severity_metadata


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

    def test_unknown_never_defaults_to_low_or_high(self):
        for value in (None, "", "not-provided", 0, "confirmed"):
            with self.subTest(value=value):
                actual = severity_metadata({"severity": value})
                self.assertEqual(actual["severity"], "unknown")
                self.assertEqual(actual["severity_label"], "未分级")


if __name__ == "__main__":
    unittest.main()

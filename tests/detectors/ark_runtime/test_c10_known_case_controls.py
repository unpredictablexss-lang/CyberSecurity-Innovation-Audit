import hashlib
import unittest
from pathlib import Path
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from .support import unit

FIXTURES = Path(__file__).parent / "fixtures" / "c10_semantics"

EXPECTED = {
    "cve_2025_24304_parent.cpp": "candidate",
    "cve_2025_24304_fixed.cpp": "matched",
    "ibs5yg_parent.cpp": "candidate",
    "ibs5yg_fixed.cpp": "matched",
    "safe_same_type.cpp": "matched",
    "unrelated.cpp": "not_analyzed",
    "unknown_effect.cpp": "unknown",
}


class C10KnownCaseControls(unittest.TestCase):
    def test_known_case_matrix_is_source_bound_and_fail_closed(self):
        for name, expected in EXPECTED.items():
            with self.subTest(fixture=name):
                text = (FIXTURES / name).read_text(encoding="utf-8")
                source = unit(text, "tests/detectors/ark_runtime/fixtures/c10_semantics/" + name)
                self.assertEqual(source.sha256, hashlib.sha256(text.encode("utf-8")).hexdigest())
                result = analyze_unit(source)
                kinds = [item.kind for item in result.observations]
                if expected == "candidate":
                    self.assertIn("candidate", kinds)
                    self.assertFalse(any(kind in ("matched", "confirmed", "reportable") for kind in kinds))
                elif expected == "matched":
                    self.assertIn("matched", kinds)
                    self.assertNotIn("candidate", kinds)
                elif expected == "unknown":
                    self.assertIn("unknown", kinds)
                    self.assertFalse(any(kind in ("candidate", "matched") for kind in kinds))
                else:
                    self.assertFalse(result.observations)
                    self.assertEqual(result.file_outcome, "complete")

    def test_safe_control_is_not_a_security_verdict(self):
        text = (FIXTURES / "safe_same_type.cpp").read_text(encoding="utf-8")
        result = analyze_unit(unit(text))
        self.assertFalse(any(item.kind in ("candidate", "confirmed", "reportable") for item in result.observations))


if __name__ == "__main__":
    unittest.main()

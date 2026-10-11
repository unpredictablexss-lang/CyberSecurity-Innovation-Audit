from __future__ import annotations

import unittest

from research.experiments.cpp.shared_ptr_race_version_impact import classify_blob


class SharedPtrRaceVersionImpactTests(unittest.TestCase):
    def test_classifies_exact_blob_identity(self) -> None:
        self.assertEqual(classify_blob("0e0c91010e39558202ab1c7f628c618fd7a09d23"), "affected")
        self.assertEqual(classify_blob("fb65b4d89ff9c60c54bc6a8e106b06935f23f633"), "fixed")
        self.assertEqual(classify_blob(None), "not_present")
        self.assertEqual(classify_blob("1" * 40), "unknown")


if __name__ == "__main__":
    unittest.main()

import unittest

from src.ohscanner.detectors.admission import pending_admission
from src.ohscanner.detectors.catalog import (
    build_registry,
    catalog_metadata,
    default_detector_ids,
)


DETECTOR_ID = "ohscanner.ark.runtime.type_safety"


class ArkRuntimeCatalogTests(unittest.TestCase):
    def test_static_candidate_is_explicit_and_default_off(self):
        self.assertNotIn(DETECTOR_ID, default_detector_ids())
        self.assertIsNotNone(pending_admission(DETECTOR_ID))
        metadata = catalog_metadata()[DETECTOR_ID]
        self.assertEqual(metadata["kind"], "research_candidate")
        self.assertFalse(metadata["default_enabled"])
        with self.assertRaisesRegex(ValueError, "admission blocked"):
            build_registry((DETECTOR_ID,))


if __name__ == "__main__":
    unittest.main()

import unittest

from src.ohscanner.detectors.admission import pending_admission
from src.ohscanner.detectors.catalog import (
    build_registry,
    catalog_metadata,
    default_detector_ids,
)


DETECTOR_ID = "ohscanner.ark.runtime.type_safety"


class ArkRuntimeCatalogTests(unittest.TestCase):
    def test_static_candidate_is_included_in_default_research_scan(self):
        self.assertIn(DETECTOR_ID, default_detector_ids())
        metadata = catalog_metadata()[DETECTOR_ID]
        self.assertEqual(metadata["kind"], "research_candidate")
        self.assertTrue(metadata.get("default_enabled", True))
        self.assertIn("candidate_only", metadata["admission_reason"])
        self.assertEqual(build_registry((DETECTOR_ID,)).detectors()[0].detector_id, DETECTOR_ID)


if __name__ == "__main__":
    unittest.main()

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
        self.assertIsNone(pending_admission(DETECTOR_ID))
        metadata = catalog_metadata()[DETECTOR_ID]
        self.assertEqual(metadata["kind"], "research_candidate")
        self.assertFalse(metadata["default_enabled"])
        detector = build_registry((DETECTOR_ID,)).detectors()[0]
        self.assertEqual(detector.detector_id, DETECTOR_ID)
        self.assertEqual(detector.version, "0.6.2")
        self.assertEqual(detector.model.target_bindings[0][0],
                         "a65a2853ccae13da167d9aa4720ab8b11ec16656")
        self.assertEqual(detector.model.source_dependencies, ((
            "ecmascript/compiler/new_object_stub_builder.cpp",
            "991ac5ac034a1a027e3200787ec25c55b3f15b69"),))


if __name__ == "__main__":
    unittest.main()

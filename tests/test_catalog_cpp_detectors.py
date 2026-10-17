from __future__ import annotations

import unittest

from src.ohscanner.detectors.catalog import (
    build_registry,
    catalog_metadata,
    default_detector_ids,
)


EXPECTED = {
    "ohscanner.cpp.bounds": "0.2.0",
    "ohscanner.cpp.integer_bounds": "0.2.0",
    "ohscanner.cpp.lifetime": "0.4.0",
    "ohscanner.cpp.null_dereference": "0.2.0",
    "ohscanner.cpp.resource_lifetime": "0.1.0",
    "ohscanner.cpp.shared_ptr_race": "0.5.0",
    "ohscanner.cpp.unsafe_memory_call": "0.1.0",
}


class CppCatalogRegistrationTests(unittest.TestCase):
    def test_frozen_cpp_detectors_are_explicitly_registered(self):
        registry = build_registry(EXPECTED)
        observed = {
            detector.detector_id: detector.version
            for detector in registry.detectors()
        }
        self.assertEqual(observed, EXPECTED)
        self.assertTrue(set(EXPECTED).issubset(default_detector_ids()))
        self.assertTrue(
            all(
                catalog_metadata()[name]["kind"] == "research_candidate"
                for name in EXPECTED
            )
        )

    def test_unknown_detector_is_still_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown or not-yet-approved detector"):
            build_registry(("ohscanner.cpp.not-reviewed",))


if __name__ == "__main__":
    unittest.main()

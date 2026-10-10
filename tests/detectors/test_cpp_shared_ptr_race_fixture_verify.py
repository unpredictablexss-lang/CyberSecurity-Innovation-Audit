from __future__ import annotations

import unittest

from research.experiments.cpp.verify_shared_ptr_race_fixtures import build_summary


class SharedPtrRaceFixtureVerifyTests(unittest.TestCase):
    def test_summary_matches_manifest_and_units(self) -> None:
        summary = build_summary()
        self.assertEqual(summary["unit_count"], 12)
        self.assertEqual(summary["categories"]["fixed"], 1)
        self.assertEqual(summary["categories"]["not_applicable"], 1)
        self.assertEqual(summary["categories"]["safe"], 2)
        self.assertEqual(summary["categories"]["unrelated"], 2)
        self.assertEqual(summary["categories"]["unknown"], 5)
        self.assertEqual(summary["categories"]["vulnerable"], 1)
        self.assertEqual(summary["languages"], {"cpp": 11, "js": 1})
        self.assertEqual(
            summary["parse_statuses"],
            {"complete": 8, "failed": 1, "not_run": 1, "partial": 2},
        )


if __name__ == "__main__":
    unittest.main()

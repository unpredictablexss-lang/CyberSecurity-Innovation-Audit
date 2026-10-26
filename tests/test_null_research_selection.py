import hashlib
import json
import unittest

from src.ohscanner.detectors.catalog import build_registry
from src.ohscanner.planning import approved_metadata
from src.workbench.planning.audit import plan_audit
from src.workbench.operation_limits import MAX_DETECTOR_IDS
from src.workbench.sources.manifest import SourceFile, SourceManifest


NULL_ID = "ohscanner.cpp.null_dereference"


class NullResearchSelectionTests(unittest.TestCase):
    def setUp(self):
        snapshot = hashlib.sha256(
            json.dumps([("sample.cpp", "cpp", "d" * 64)], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        self.source = SourceManifest(
            repository="fixture/null-research-selection",
            commit="a" * 40,
            git_tree="b" * 40,
            snapshot_sha256=snapshot,
            files=(SourceFile("sample.cpp", "cpp", "d" * 64, "complete", "e" * 40),),
            provenance="context_snapshot_checked",
        )
        self.metadata = approved_metadata()

    def test_ordinary_plan_omits_null_and_explicit_research_plan_selects_it(self):
        ordinary = plan_audit(self.source, self.metadata)
        selected = plan_audit(self.source, self.metadata, selected_detector_ids=[NULL_ID])

        ordinary_null = next(row for row in ordinary["detectors"] if row["id"] == NULL_ID)
        selected_null = next(row for row in selected["detectors"] if row["id"] == NULL_ID)
        self.assertEqual(ordinary_null["decision"], "skipped")
        self.assertEqual(ordinary_null["reason_codes"], ["explicit_selection_required"])
        self.assertNotIn(NULL_ID, ordinary["suggested_detector_ids"])
        self.assertEqual(selected["requested_detector_ids"], [NULL_ID])
        self.assertEqual(selected_null["decision"], "planned")
        self.assertEqual(selected["suggested_detector_ids"], [NULL_ID])

    def test_all_explicit_research_ids_fit_strictest_operation_limit_and_registry(self):
        research_ids = [row["id"] for row in self.metadata if row.get("kind") == "research_candidate"]
        self.assertLessEqual(len(research_ids), MAX_DETECTOR_IDS)
        self.assertIn(NULL_ID, research_ids)
        registry = build_registry(tuple(research_ids))
        self.assertIn(NULL_ID, {detector.detector_id for detector in registry.detectors()})


if __name__ == "__main__":
    unittest.main()

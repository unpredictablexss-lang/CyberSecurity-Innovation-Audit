from __future__ import annotations

import hashlib
import json
import unittest

from research.experiments.cpp.bounds_length_parcel_slice import (
    ExperimentUnit,
    evaluate_slice,
)
from src.ohscanner.detectors.cpp.lifetime_detector import (
    LifetimeAnalysisOptions,
    LifetimeOwnershipGuardDetector,
)
from tests.detectors.fixture_support import (
    BOUNDS_FIXTURES,
    ROOT,
    lifetime_context,
    load_lifetime_units,
)


class ResearchSliceTests(unittest.TestCase):
    def test_manifest_hashes_bind_all_fixture_text(self) -> None:
        fixture_dirs = (
            ROOT / "tests" / "detectors" / "fixtures" / "cpp_lifetime",
            BOUNDS_FIXTURES,
        )
        for fixture_dir in fixture_dirs:
            manifest = json.loads((fixture_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(
                manifest["provenance"]["kind"],
                "self_authored_synthetic_fixture",
            )
            for item in manifest["units"]:
                text = (ROOT / item["path"]).read_text(encoding="utf-8")
                self.assertEqual(
                    hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    item["sha256"],
                )

    def test_bounds_slice_ablation_needs_guard_shape(self) -> None:
        manifest = json.loads((BOUNDS_FIXTURES / "manifest.json").read_text(encoding="utf-8"))
        units = tuple(
            ExperimentUnit(
                path=item["path"],
                text=(ROOT / item["path"]).read_text(encoding="utf-8"),
                parse_status=item["parse_status"],
            )
            for item in manifest["units"]
        )
        base = evaluate_slice(units, use_guard_shape=False)
        guarded = evaluate_slice(units, use_guard_shape=True)
        base_counts = {item.path: item.candidate_shapes for item in base}
        guarded_counts = {item.path: item.candidate_shapes for item in guarded}
        self.assertEqual(
            base_counts["tests/detectors/fixtures/cpp_bounds_length_parcel/vulnerable_unbounded_parcel.cpp"],
            1,
        )
        self.assertEqual(
            base_counts["tests/detectors/fixtures/cpp_bounds_length_parcel/fixed_guarded_parcel.cpp"],
            1,
        )
        self.assertEqual(
            guarded_counts["tests/detectors/fixtures/cpp_bounds_length_parcel/vulnerable_unbounded_parcel.cpp"],
            1,
        )
        self.assertEqual(
            guarded_counts["tests/detectors/fixtures/cpp_bounds_length_parcel/fixed_guarded_parcel.cpp"],
            0,
        )
        fixed = next(item for item in guarded if item.path.endswith("fixed_guarded_parcel.cpp"))
        self.assertTrue(fixed.guard_shape)
        self.assertTrue(any(item.kind == "upper_bound_guard_shape" for item in fixed.facts))
        self.assertTrue(any("not CFG dominance" in item for item in fixed.limitations))

    def test_lifetime_ablation_shows_alias_liveness_and_sync_contribution(self) -> None:
        units = load_lifetime_units()
        context = lifetime_context()
        base = LifetimeOwnershipGuardDetector(
            LifetimeAnalysisOptions(suppress_rebound_alias=False, classify_sync_scope=False)
        ).detect(context, units)
        alias = LifetimeOwnershipGuardDetector(
            LifetimeAnalysisOptions(suppress_rebound_alias=True, classify_sync_scope=False)
        ).detect(context, units)
        complete = LifetimeOwnershipGuardDetector(
            LifetimeAnalysisOptions(suppress_rebound_alias=True, classify_sync_scope=True)
        ).detect(context, units)
        self.assertEqual(len(base.findings), 4)
        self.assertEqual(len(alias.findings), 3)
        self.assertEqual(len(complete.findings), 3)
        self.assertTrue(all("sync_scope=not_classified" in item.message for item in base.findings))
        self.assertTrue(
            any("sync_scope=same_scoped_mutex_lock" in item.message for item in complete.findings)
        )


if __name__ == "__main__":
    unittest.main()

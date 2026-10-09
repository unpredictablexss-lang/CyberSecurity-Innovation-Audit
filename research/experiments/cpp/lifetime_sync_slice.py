"""Reproduce the lifetime/synchronization minimal slice and its ablation."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from src.ohscanner.contracts import ScanContext, SourceUnit
from src.ohscanner.detectors.cpp.lifetime_detector import (
    LifetimeAnalysisOptions,
    LifetimeOwnershipGuardDetector,
)
from tests.detectors.fixture_support import (
    load_lifetime_units,
    load_manifest,
    make_context as make_bound_context,
)


ROOT = Path(__file__).resolve().parents[3]
FIXTURE_DIR = ROOT / "tests" / "detectors" / "fixtures" / "cpp_lifetime"


def load_units() -> Sequence[SourceUnit]:
    return load_lifetime_units()


def make_context(units: Sequence[SourceUnit]) -> ScanContext:
    return make_bound_context(
        units,
        "research-fixture:lifetime-sync-slice",
        load_manifest(FIXTURE_DIR)["provenance"],
    )


def run_mode(name: str, options: LifetimeAnalysisOptions, units: Sequence[SourceUnit]) -> dict:
    context = make_context(units)
    run = LifetimeOwnershipGuardDetector(options).detect(context, tuple(units))
    counts = {}
    for unit in units:
        counts[unit.path] = sum(1 for item in run.findings if item.file == unit.path)
    return {
        "mode": name,
        "total_candidates": len(run.findings),
        "candidates_by_fixture": counts,
        "run_status": run.status,
        "analyzed_files": list(run.analyzed_files),
        "coverage": [
            {
                "file": unit.path,
                "parse_status": unit.parse_status,
                "analyzed": unit.path in run.analyzed_files,
            }
            for unit in units
        ],
    }


if __name__ == "__main__":
    import json

    units = load_units()
    modes = (
        run_mode(
            "base_pattern",
            LifetimeAnalysisOptions(suppress_rebound_alias=False, classify_sync_scope=False),
            units,
        ),
        run_mode(
            "plus_alias_liveness",
            LifetimeAnalysisOptions(suppress_rebound_alias=True, classify_sync_scope=False),
            units,
        ),
        run_mode(
            "plus_alias_liveness_and_sync_scope",
            LifetimeAnalysisOptions(suppress_rebound_alias=True, classify_sync_scope=True),
            units,
        ),
    )
    print(json.dumps({"experiment": "lifetime_sync_minimal_slice", "modes": modes}, indent=2))

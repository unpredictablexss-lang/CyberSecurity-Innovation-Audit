"""Reproduce the lifetime/synchronization minimal slice and its ablation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Sequence

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.lifetime_detector import (
    LifetimeAnalysisOptions,
    LifetimeOwnershipGuardDetector,
)
from src.ohscanner.fixture import snapshot_digest


ROOT = Path(__file__).resolve().parents[3]
FIXTURE_DIR = ROOT / "tests" / "detectors" / "fixtures" / "cpp_lifetime"


def load_units() -> Sequence[SourceUnit]:
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    units = []
    for item in manifest["units"]:
        text = (ROOT / item["path"]).read_text(encoding="utf-8")
        units.append(
            SourceUnit(
                path=item["path"],
                language="cpp",
                text=text,
                sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                parse_status=item["parse_status"],
                parse_issues=tuple(item.get("parse_issues", ())),
            )
        )
    return tuple(sorted(units, key=lambda unit: unit.path))


def make_context(units: Sequence[SourceUnit]) -> ScanContext:
    ordered = tuple(sorted(units, key=lambda unit: unit.path))
    request = ScanRequest(
        request_id="research-fixture:lifetime-sync-slice",
        target_id="current-component:synthetic/fixture",
        repository="synthetic/fixture",
        commit="1" * 40,
        snapshot_sha256=snapshot_digest(ordered),
        profile_id="fixture-no-build",
        provenance="fixture",
    )
    return ScanContext(request=request, units=ordered)


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

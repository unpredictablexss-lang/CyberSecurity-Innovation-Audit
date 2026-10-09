"""Reproduce the lifetime/synchronization minimal slice and its ablation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Sequence

from src.ohscanner.detectors.cpp.lifetime_detector import (
    LifetimeAnalysisOptions,
    LifetimeOwnershipGuardDetector,
)
from src.ohscanner.detectors.cpp.proposed_contract import (
    ProposedScanContext,
    ProposedScanRequest,
    ProposedSourceUnit,
)


ROOT = Path(__file__).resolve().parents[3]
FIXTURE_DIR = ROOT / "tests" / "detectors" / "fixtures" / "cpp_lifetime"


def load_units() -> Sequence[ProposedSourceUnit]:
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    units = []
    for item in manifest["units"]:
        text = (ROOT / item["path"]).read_text(encoding="utf-8")
        units.append(
            ProposedSourceUnit(
                path=item["path"],
                language="cpp",
                sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                text=text,
                parse_status=item["parse_status"],
                parse_issues=tuple(item.get("parse_issues", ())),
            )
        )
    return tuple(units)


def make_context() -> ProposedScanContext:
    return ProposedScanContext(
        request=ProposedScanRequest(
            request_id="research-fixture:lifetime-sync-slice",
            target_id="fixture:cpp-lifetime-local",
            repository="local-synthetic-fixture",
            commit="1" * 40,
            snapshot_sha256="2" * 64,
            profile_id="fixture-no-build",
        ),
        model_version="cpp-lifetime-local-proposed-v1",
    )


def run_mode(name: str, options: LifetimeAnalysisOptions, units: Sequence[ProposedSourceUnit]) -> dict:
    run = LifetimeOwnershipGuardDetector(options).detect(make_context(), units)
    counts = {}
    for unit in units:
        counts[unit.path] = sum(1 for item in run.diagnostics if item.file == unit.path)
    return {
        "mode": name,
        "total_diagnostics": len(run.diagnostics),
        "diagnostics_by_fixture": counts,
        "run_status": run.status,
        "coverage": [
            {"file": item.file, "parse_status": item.parse_status, "analyzed": item.analyzed}
            for item in run.coverage
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

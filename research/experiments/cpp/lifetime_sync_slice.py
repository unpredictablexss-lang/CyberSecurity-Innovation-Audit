"""Reproduce the lifetime/synchronization minimal slice and its ablation.

Evidence classes are kept in separate runs. Vulnerable, fixed, safe and unknown
fixtures are never combined into one review result.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Sequence, Tuple

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.lifetime_detector import (
    LifetimeAnalysisOptions,
    LifetimeOwnershipGuardDetector,
)
from src.ohscanner.fixture import snapshot_digest
from tests.detectors.fixture_support import (
    LIFETIME_FIXTURES,
    load_lifetime_units,
    load_manifest,
)


ROOT = Path(__file__).resolve().parents[3]
FIXTURE_DIR = ROOT / "tests" / "detectors" / "fixtures" / "cpp_lifetime"


def _evidence_class(category: str) -> str:
    for prefix in (
        "vulnerable",
        "fixed",
        "unrelated",
        "safe",
        "unknown",
        "not_applicable",
    ):
        if category.startswith(prefix):
            return prefix
    raise ValueError(f"unsupported fixture category: {category}")


def load_units() -> Sequence[SourceUnit]:
    return load_lifetime_units()


def make_context(units: Sequence[SourceUnit]) -> ScanContext:
    provenance = load_manifest(FIXTURE_DIR)["provenance"]
    ordered = tuple(sorted(units, key=lambda unit: unit.path))
    return ScanContext(
        request=ScanRequest(
            request_id="research-fixture:lifetime-sync-slice",
            target_id="current-component:" + provenance["repository"],
            repository=provenance["repository"],
            commit=provenance["commit"],
            snapshot_sha256=snapshot_digest(ordered),
            profile_id=provenance["profile_id"],
            provenance="fixture",
        ),
        units=ordered,
    )


def evidence_groups(units: Sequence[SourceUnit]) -> Dict[str, Tuple[SourceUnit, ...]]:
    manifest = load_manifest(FIXTURE_DIR)
    classes = {
        item["path"]: _evidence_class(item["fixture_category"])
        for item in manifest["units"]
    }
    grouped: Dict[str, list] = {}
    for unit in units:
        grouped.setdefault(classes[unit.path], []).append(unit)
    return {
        name: tuple(sorted(items, key=lambda unit: unit.path))
        for name, items in sorted(grouped.items())
    }


def run_mode(
    name: str,
    options: LifetimeAnalysisOptions,
    units: Sequence[SourceUnit],
) -> dict:
    selected = tuple(unit for unit in units if unit.language == "cpp")
    if not selected:
        return {
            "mode": name,
            "total_candidates": 0,
            "candidates_by_fixture": {unit.path: 0 for unit in units},
            "run_status": "blocked",
            "analyzed_files": [],
            "coverage": [
                {
                    "file": unit.path,
                    "parse_status": unit.parse_status,
                    "analyzed": False,
                    "interpretation": "not_applicable_no_matching_language",
                }
                for unit in units
            ],
        }
    context = make_context(selected)
    run = LifetimeOwnershipGuardDetector(options).detect(context, selected)
    counts = {}
    for unit in selected:
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
                "interpretation": (
                    "analyzed_scope_only"
                    if unit.path in run.analyzed_files
                    else "unknown_incomplete_analysis"
                ),
            }
            for unit in units
        ],
    }


def run_group(
    group_name: str,
    units: Sequence[SourceUnit],
) -> dict:
    return {
        "evidence_class": group_name,
        "unit_count": len(units),
        "modes": [
            run_mode(
                "base_pattern",
                LifetimeAnalysisOptions(
                    suppress_rebound_alias=False, classify_sync_scope=False
                ),
                units,
            ),
            run_mode(
                "plus_alias_liveness",
                LifetimeAnalysisOptions(
                    suppress_rebound_alias=True, classify_sync_scope=False
                ),
                units,
            ),
            run_mode(
                "plus_alias_liveness_and_sync_scope",
                LifetimeAnalysisOptions(
                    suppress_rebound_alias=True, classify_sync_scope=True
                ),
                units,
            ),
        ],
    }


if __name__ == "__main__":
    units = load_units()
    groups = evidence_groups(units)
    print(
        json.dumps(
            {
                "experiment": "lifetime_sync_minimal_slice",
                "evidence_groups_are_separate_runs": True,
                "groups": [run_group(name, items) for name, items in groups.items()],
            },
            indent=2,
        )
    )

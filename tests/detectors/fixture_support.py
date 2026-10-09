from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Tuple

from src.ohscanner.detectors.cpp.proposed_contract import (
    ProposedScanContext,
    ProposedScanRequest,
    ProposedSourceUnit,
)


ROOT = Path(__file__).resolve().parents[2]
LIFETIME_FIXTURES = ROOT / "tests" / "detectors" / "fixtures" / "cpp_lifetime"
BOUNDS_FIXTURES = ROOT / "tests" / "detectors" / "fixtures" / "cpp_bounds_length_parcel"


def load_manifest(fixture_dir: Path) -> dict:
    return json.loads((fixture_dir / "manifest.json").read_text(encoding="utf-8"))


def load_lifetime_units() -> Tuple[ProposedSourceUnit, ...]:
    manifest = load_manifest(LIFETIME_FIXTURES)
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
                parse_issues=tuple(item["parse_issues"]),
            )
        )
    return tuple(units)


def lifetime_context() -> ProposedScanContext:
    return ProposedScanContext(
        request=ProposedScanRequest(
            request_id="test-fixture:lifetime",
            target_id="fixture:cpp-lifetime-local",
            repository="local-synthetic-fixture",
            commit="1" * 40,
            snapshot_sha256="2" * 64,
            profile_id="fixture-no-build",
        ),
        model_version="cpp-lifetime-local-proposed-v1",
    )


def unit_by_path(units: Tuple[ProposedSourceUnit, ...], suffix: str) -> ProposedSourceUnit:
    matches = [unit for unit in units if unit.path.endswith(suffix)]
    if len(matches) != 1:
        raise AssertionError(f"expected one fixture ending in {suffix}, found {len(matches)}")
    return matches[0]

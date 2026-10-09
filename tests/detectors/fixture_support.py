from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable, Tuple

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest


ROOT = Path(__file__).resolve().parents[2]
LIFETIME_FIXTURES = ROOT / "tests" / "detectors" / "fixtures" / "cpp_lifetime"
BOUNDS_FIXTURES = ROOT / "tests" / "detectors" / "fixtures" / "cpp_bounds_length_parcel"
REPOSITORY = "synthetic/fixture"


def load_manifest(fixture_dir: Path) -> dict:
    return json.loads((fixture_dir / "manifest.json").read_text(encoding="utf-8"))


def load_units(fixture_dir: Path) -> Tuple[SourceUnit, ...]:
    manifest = load_manifest(fixture_dir)
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
                parse_issues=tuple(item["parse_issues"]),
            )
        )
    return tuple(sorted(units, key=lambda unit: unit.path))


def load_lifetime_units() -> Tuple[SourceUnit, ...]:
    return load_units(LIFETIME_FIXTURES)


def make_context(
    units: Iterable[SourceUnit],
    request_id: str = "test-fixture:lifetime",
) -> ScanContext:
    ordered = tuple(sorted(units, key=lambda unit: unit.path))
    request = ScanRequest(
        request_id=request_id,
        target_id="current-component:" + REPOSITORY,
        repository=REPOSITORY,
        commit="1" * 40,
        snapshot_sha256=snapshot_digest(ordered),
        profile_id="fixture-no-build",
        provenance="fixture",
    )
    return ScanContext(request=request, units=ordered)


def lifetime_context() -> ScanContext:
    return make_context(load_lifetime_units())


def unit_by_path(units: Tuple[SourceUnit, ...], suffix: str) -> SourceUnit:
    matches = [unit for unit in units if unit.path.endswith(suffix)]
    if len(matches) != 1:
        raise AssertionError(f"expected one fixture ending in {suffix}, found {len(matches)}")
    return matches[0]

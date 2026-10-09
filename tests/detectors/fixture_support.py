from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping, Tuple

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest


ROOT = Path(__file__).resolve().parents[2]
LIFETIME_FIXTURES = ROOT / "tests" / "detectors" / "fixtures" / "cpp_lifetime"
BOUNDS_FIXTURES = ROOT / "tests" / "detectors" / "fixtures" / "cpp_bounds_length_parcel"


def load_manifest(fixture_dir: Path) -> dict:
    manifest = json.loads((fixture_dir / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported fixture manifest schema")
    provenance = manifest.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("fixture manifest requires provenance")
    if provenance.get("kind") != "self_authored_synthetic_fixture":
        raise ValueError("fixture provenance must remain synthetic")
    if not isinstance(manifest.get("units"), list) or not manifest["units"]:
        raise ValueError("fixture manifest requires source units")
    return manifest


def load_units(fixture_dir: Path) -> Tuple[SourceUnit, ...]:
    manifest = load_manifest(fixture_dir)
    resolved_fixture_dir = fixture_dir.resolve()
    resolved_root = ROOT.resolve()
    fixture_prefix = resolved_fixture_dir.relative_to(resolved_root).as_posix() + "/"
    seen = set()
    units = []
    for item in manifest["units"]:
        if not isinstance(item, dict):
            raise ValueError("fixture unit metadata must be an object")
        path = item.get("path")
        if (
            not isinstance(path, str)
            or not path.startswith(fixture_prefix)
            or Path(path).is_absolute()
            or ".." in Path(path).parts
        ):
            raise ValueError("fixture unit is outside its manifest directory")
        if path in seen:
            raise ValueError("duplicate fixture unit path")
        seen.add(path)
        resolved_unit_path = (ROOT / path).resolve()
        if not resolved_unit_path.is_relative_to(resolved_fixture_dir):
            raise ValueError("fixture unit is outside its manifest directory")
        text = resolved_unit_path.read_text(encoding="utf-8")
        actual_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if actual_sha256 != item.get("sha256"):
            raise ValueError("manifest source hash mismatch")
        units.append(
            SourceUnit(
                path=path,
                language="cpp",
                text=text,
                sha256=item["sha256"],
                parse_status=item["parse_status"],
                parse_issues=tuple(item["parse_issues"]),
            )
        )
    ordered = tuple(sorted(units, key=lambda unit: unit.path))
    if snapshot_digest(ordered) != manifest["provenance"].get("snapshot_sha256"):
        raise ValueError("manifest snapshot hash mismatch")
    return ordered


def load_lifetime_units() -> Tuple[SourceUnit, ...]:
    return load_units(LIFETIME_FIXTURES)


def make_context(
    units: Iterable[SourceUnit],
    request_id: str,
    provenance: Mapping[str, str],
) -> ScanContext:
    ordered = tuple(sorted(units, key=lambda unit: unit.path))
    if snapshot_digest(ordered) != provenance.get("snapshot_sha256"):
        raise ValueError("context units do not match manifest snapshot")
    request = ScanRequest(
        request_id=request_id,
        target_id="current-component:" + provenance["repository"],
        repository=provenance["repository"],
        commit=provenance["commit"],
        snapshot_sha256=provenance["snapshot_sha256"],
        profile_id=provenance["profile_id"],
        provenance="fixture",
    )
    return ScanContext(request=request, units=ordered)


def load_context(fixture_dir: Path, request_id: str) -> ScanContext:
    manifest = load_manifest(fixture_dir)
    return make_context(load_units(fixture_dir), request_id, manifest["provenance"])


def lifetime_context() -> ScanContext:
    return load_context(LIFETIME_FIXTURES, "test-fixture:lifetime")


def bounds_context() -> ScanContext:
    return load_context(BOUNDS_FIXTURES, "test-fixture:bounds")


def unit_by_path(units: Tuple[SourceUnit, ...], suffix: str) -> SourceUnit:
    matches = [unit for unit in units if unit.path.endswith(suffix)]
    if len(matches) != 1:
        raise AssertionError(f"expected one fixture ending in {suffix}, found {len(matches)}")
    return matches[0]

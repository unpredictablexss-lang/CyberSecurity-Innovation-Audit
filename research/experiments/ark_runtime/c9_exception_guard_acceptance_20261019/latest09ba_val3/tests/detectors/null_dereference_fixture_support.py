from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import LANGUAGES, snapshot_digest


ROOT = Path(__file__).resolve().parents[2]
A_NULL_01 = ROOT / "research" / "tests" / "a_null_01"
MANIFEST_PATH = A_NULL_01 / "manifest.json"
MATRIX_PATH = A_NULL_01 / "regression_matrix.json"

EXPECTED_FIXTURE_COUNT = 18
EXPECTED_MANIFEST_SHA256 = (
    "8e0b16819c6a36e8ed407f233127923f21367da12c3716ed7182b46f97d8ecf2"
)
EXPECTED_MATRIX_SHA256 = (
    "9bd5f8db1a712dbd048d3713dd8fee6cd9e13c0b91f5024c34ff15db4596d55a"
)
EXPECTED_SNAPSHOT_SHA256 = (
    "8f881c60dc49784191bef602bd1574dec02f5bf78adf6515a3bd0be9d6c1f81c"
)


@dataclass(frozen=True)
class NullFixturePackage:
    manifest: dict
    matrix: dict
    units: Tuple[SourceUnit, ...]
    context: ScanContext
    cases_by_fixture: Dict[str, dict]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_blob_sha1(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def load_null_fixture_package() -> NullFixturePackage:
    if _sha256_file(MANIFEST_PATH) != EXPECTED_MANIFEST_SHA256:
        raise ValueError("A-NULL-01 manifest SHA-256 mismatch")
    if _sha256_file(MATRIX_PATH) != EXPECTED_MATRIX_SHA256:
        raise ValueError("A-NULL-01 regression matrix SHA-256 mismatch")

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported A-NULL-01 manifest schema")
    if matrix.get("schema_version") != "ohscanner.a-null-01-regression-matrix-v1":
        raise ValueError("unsupported A-NULL-01 regression matrix schema")
    if manifest.get("provenance", {}).get("kind") != "self_authored_synthetic_fixture":
        raise ValueError("A-NULL-01 fixtures must remain self-authored synthetic controls")
    if manifest.get("provenance", {}).get("regression_matrix_sha256") != EXPECTED_MATRIX_SHA256:
        raise ValueError("manifest does not bind the regression matrix")
    if matrix.get("change_request_id") != "A-NULL-01":
        raise ValueError("regression matrix change request mismatch")

    raw_units = manifest.get("units")
    raw_cases = matrix.get("cases")
    if not isinstance(raw_units, list) or len(raw_units) != EXPECTED_FIXTURE_COUNT:
        raise ValueError("A-NULL-01 manifest must contain exactly 18 fixtures")
    if not isinstance(raw_cases, list) or len(raw_cases) != EXPECTED_FIXTURE_COUNT:
        raise ValueError("A-NULL-01 matrix must contain exactly 18 cases")

    cases_by_fixture: Dict[str, dict] = {}
    for case in raw_cases:
        if not isinstance(case, dict) or not isinstance(case.get("fixture"), str):
            raise ValueError("invalid A-NULL-01 matrix case")
        fixture = case["fixture"]
        if fixture in cases_by_fixture:
            raise ValueError("duplicate A-NULL-01 matrix fixture: " + fixture)
        cases_by_fixture[fixture] = case

    units = []
    seen_paths = set()
    resolved_root = ROOT.resolve()
    for item in raw_units:
        if not isinstance(item, dict):
            raise ValueError("invalid A-NULL-01 manifest unit")
        relative = item.get("path")
        if not isinstance(relative, str):
            raise ValueError("A-NULL-01 unit path must be a string")
        path = (ROOT / relative).resolve()
        if not path.is_relative_to(resolved_root) or path.is_symlink():
            raise ValueError("A-NULL-01 fixture escaped the repository root")
        if relative in seen_paths:
            raise ValueError("duplicate A-NULL-01 fixture path: " + relative)
        seen_paths.add(relative)
        fixture_name = relative.rsplit("/", 1)[-1]
        if fixture_name not in cases_by_fixture:
            raise ValueError("fixture has no matrix case: " + relative)

        data = path.read_bytes()
        text = data.decode("utf-8")
        if len(data) != item.get("byte_length"):
            raise ValueError("fixture byte length mismatch: " + relative)
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != item.get("sha256"):
            raise ValueError("fixture source SHA-256 mismatch: " + relative)
        if _git_blob_sha1(data) != item.get("git_blob_sha1"):
            raise ValueError("fixture Git blob SHA-1 mismatch: " + relative)
        language = item.get("language")
        if language != LANGUAGES.get(path.suffix.lower()):
            raise ValueError("fixture language mismatch: " + relative)
        parse_status = item.get("parse_status")
        if parse_status not in ("complete", "partial", "failed", "not_run"):
            raise ValueError("fixture parse status mismatch: " + relative)
        case = cases_by_fixture[fixture_name]
        if case.get("parse_status") != parse_status:
            raise ValueError("matrix parse status mismatch: " + relative)
        if item.get("fixture_category") != case.get("fixture_category"):
            raise ValueError("matrix fixture category mismatch: " + relative)
        units.append(
            SourceUnit(
                path=relative,
                language=language,
                text=text,
                sha256=actual_sha256,
                parse_status=parse_status,
                parse_issues=tuple(item.get("parse_issues", ())),
            )
        )

    units = tuple(sorted(units, key=lambda unit: unit.path))
    if set(cases_by_fixture) != {unit.path.rsplit("/", 1)[-1] for unit in units}:
        raise ValueError("matrix and manifest fixture sets differ")
    if snapshot_digest(units) != EXPECTED_SNAPSHOT_SHA256:
        raise ValueError("A-NULL-01 fixture snapshot SHA-256 mismatch")
    if manifest["provenance"].get("snapshot_sha256") != EXPECTED_SNAPSHOT_SHA256:
        raise ValueError("manifest snapshot provenance mismatch")

    provenance = manifest["provenance"]
    request = ScanRequest(
        request_id="test-fixture:a-null-01",
        target_id="current-component:" + provenance["repository"],
        repository=provenance["repository"],
        commit=provenance["commit"],
        snapshot_sha256=provenance["snapshot_sha256"],
        profile_id=provenance["profile_id"],
        provenance="fixture",
    )
    context = ScanContext(request=request, units=units)
    return NullFixturePackage(
        manifest=manifest,
        matrix=matrix,
        units=units,
        context=context,
        cases_by_fixture=cases_by_fixture,
    )

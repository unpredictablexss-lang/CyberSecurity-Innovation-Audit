"""Read-only fixture loader for M0 contract testing; NOT a Git provenance verifier."""

import hashlib
import json
from pathlib import Path

from .contracts import ScanContext, ScanRequest, SourceUnit, safe_relative_path

LANGUAGES = {
    ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".h": "cpp", ".hpp": "cpp",
    ".js": "js", ".ts": "ts", ".ets": "arkts",
}
MAX_FIXTURE_BYTES = 1024 * 1024


def _read_units(root: Path):
    if not root.is_dir() or root.is_symlink():
        raise ValueError("fixture root must be a real directory")
    units = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("fixture cannot contain symlinks")
        if not path.is_file():
            continue
        relative = safe_relative_path(path.relative_to(root).as_posix())
        language = LANGUAGES.get(path.suffix.lower())
        if language is None:
            raise ValueError("unexpected file in M0 fixture: " + relative)
        if path.stat().st_size > MAX_FIXTURE_BYTES:
            raise ValueError("fixture file is too large")
        data = path.read_bytes()
        text = data.decode("utf-8")
        units.append(SourceUnit(relative, language, text, hashlib.sha256(data).hexdigest()))
    if not units:
        raise ValueError("fixture has no source units")
    return tuple(units)


def snapshot_digest(units):
    manifest = [(u.path, u.language, u.sha256) for u in units]
    return hashlib.sha256(json.dumps(manifest, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def load_fixture(root: Path):
    # M0 explicitly avoids pretending arbitrary local paths are verified OpenHarmony Git objects.
    units = _read_units(root)
    request = ScanRequest(
        request_id="m0-contract-fixture-v1",
        repository="fixture/ohscanner-core",
        commit="synthetic-fixture-v1",
        snapshot_sha256=snapshot_digest(units),
        target_id="current-component:fixture/ohscanner-core",
    )
    return ScanContext(request=request, units=units)


def verify_fixture_unchanged(root: Path, context: ScanContext):
    units = _read_units(root)
    if snapshot_digest(units) != context.request.snapshot_sha256:
        raise ValueError("fixture changed during scan")

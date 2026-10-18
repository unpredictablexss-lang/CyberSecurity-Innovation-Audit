#!/usr/bin/env python3
"""Read-only verification for the C-line exact-snapshot dependency manifest.

The verifier never runs a compiler, build script, or preprocessor. It hashes the
declared byte inputs and canonical profile metadata, then fails closed when a
declared file is missing, has drifted, or lacks trusted provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "ohscanner.ark-runtime-exact-snapshot-dependencies/v1"
HEX256 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def canonical_json_bytes(value: Any) -> bytes:
    """UTF-8 JSON, sorted keys, compact separators, no Unicode normalization."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def _safe_relative_path(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and "\\" not in value


def payload_for_digest(manifest: dict[str, Any], observations: dict[str, str | None] | None = None) -> dict[str, Any]:
    """Return the fully specified deterministic digest input.

    With observations=None, use the frozen expected hashes (manifest creation).
    Verification supplies hashes actually read from disk, so changed bytes
    produce a changed observed digest even though the manifest is immutable.
    """
    entries = []
    for entry in manifest["inputs"]:
        item = {key: value for key, value in entry.items() if key != "observed_sha256"}
        if observations is not None:
            item["content_sha256"] = observations.get(entry["id"])
        entries.append(item)
    result = {key: value for key, value in manifest.items() if key not in ("summary_sha256", "verification")}
    result["inputs"] = entries
    return result


def calculate_summary(manifest: dict[str, Any], observations: dict[str, str | None] | None = None) -> str:
    return sha256(canonical_json_bytes(payload_for_digest(manifest, observations)))


def verify_manifest(manifest: dict[str, Any], workspace_root: Path) -> dict[str, Any]:
    errors: list[str] = []
    observations: dict[str, str | None] = {}
    seen: set[str] = set()
    ids = [entry.get("id", "") for entry in manifest.get("inputs", [])]
    if manifest.get("schema") != SCHEMA:
        errors.append("unsupported_schema")
    if ids != sorted(ids):
        errors.append("inputs_not_sorted_by_id")
    for entry in manifest.get("inputs", []):
        input_id = entry.get("id", "")
        if not input_id or input_id in seen:
            errors.append(f"duplicate_or_empty_input_id:{input_id or '<empty>'}")
            continue
        seen.add(input_id)
        rel = entry.get("workspace_path", "")
        if not _safe_relative_path(rel):
            errors.append(f"unsafe_workspace_path:{input_id}")
            observations[input_id] = None
            continue
        path = workspace_root.joinpath(*PurePosixPath(rel).parts)
        try:
            data = path.read_bytes()
        except OSError:
            errors.append(f"missing_dependency:{input_id}")
            observations[input_id] = None
            continue
        digest = sha256(data)
        observations[input_id] = digest
        if len(data) != entry.get("bytes"):
            errors.append(f"byte_length_mismatch:{input_id}")
        if digest != entry.get("content_sha256"):
            errors.append(f"sha256_mismatch:{input_id}")
        source = entry.get("source", {})
        source_expected_sha = source.get("expected_sha256_from_profile")
        if source_expected_sha and digest != source_expected_sha:
            errors.append(f"profile_recorded_sha256_mismatch:{input_id}")
        if source.get("kind") == "git_blob":
            oid = source.get("git_blob_oid", "")
            if not HEX40.fullmatch(oid) or git_blob_sha1(data) != oid:
                errors.append(f"git_blob_mismatch:{input_id}")
            if source.get("verification") != "verified_at_pinned_commit_from_local_git_objects":
                errors.append(f"untrusted_git_origin:{input_id}")
        elif source.get("verification") != "sha256_bound_local_evidence" and source.get("verification") != "verified_tool_or_profile_identity":
            errors.append(f"untrusted_origin:{input_id}")
        if not HEX256.fullmatch(entry.get("content_sha256", "")):
            errors.append(f"invalid_expected_sha256:{input_id}")

    expected = manifest.get("summary_sha256")
    declared = calculate_summary(manifest)
    observed = calculate_summary(manifest, observations)
    if expected != declared:
        errors.append("manifest_summary_mismatch")
    if observed != expected:
        errors.append("observed_summary_mismatch")
    blockers = manifest.get("unresolved", [])
    if blockers:
        errors.extend(f"unresolved_dependency:{item.get('id', 'unknown')}" for item in blockers)
    status = "verified" if not errors and manifest.get("declared_status") == "complete" else "blocked"
    return {
        "schema": "ohscanner.ark-runtime-dependency-verification/v1",
        "status": status,
        "expected_summary_sha256": expected,
        "declared_summary_sha256": declared,
        "observed_summary_sha256": observed,
        "report_reference": {
            "manifest_schema": manifest.get("schema"),
            "dependency_summary_sha256": observed,
            "verification_status": status,
        },
        "input_count": len(manifest.get("inputs", [])),
        "unresolved_count": len(blockers),
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("exact_snapshot_manifest.v1.json"))
    parser.add_argument("--workspace-root", type=Path, help="workspace containing the manifest's workspace_path inputs")
    args = parser.parse_args(argv)
    workspace_root = (args.workspace_root or Path(__file__).resolve().parents[5]).resolve()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        result = verify_manifest(manifest, workspace_root)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        result = {
            "schema": "ohscanner.ark-runtime-dependency-verification/v1",
            "status": "blocked",
            "expected_summary_sha256": None,
            "declared_summary_sha256": None,
            "observed_summary_sha256": None,
            "report_reference": None,
            "errors": [f"invalid_manifest:{type(exc).__name__}:{exc}"],
        }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if result["status"] == "verified" else 2


if __name__ == "__main__":
    raise SystemExit(main())

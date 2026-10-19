#!/usr/bin/env python3
"""Fail-closed structural checker for the IBS5YG D5 target intake.

This tool binds submitted evidence references to bytes beneath an explicit
evidence root and checks that all six declared fields carry one consistent
build identity. It does not parse or authenticate evidence content or issuers,
prove product/build association, establish custody, or authorize admission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
from typing import Any
from urllib.parse import parse_qs, urlsplit


SCHEMA = "ohscanner.ark-runtime.ibs5yg-d5-intake/v1"
CASE_ID = "ARK-TYPEDARRAY-FILTER-RESULT-TYPE-ORIGIN-IBS5YG"
FIELDS = (
    "openharmony_release",
    "product_build_id_or_image_version",
    "source_branch_or_release_tag",
    "locked_manifest_uri_plus_sha256_or_immutable_commit",
    "product_name",
    "board_or_device_target",
)
HEX_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
IMMUTABLE_COMMIT = re.compile(r"^(?:commit:)?(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    attrs = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attrs & REPARSE_POINT)


def _safe_evidence_file(root: Path, reference: str) -> tuple[Path | None, str | None]:
    if not isinstance(reference, str) or not reference:
        return None, "evidence_path_missing"
    # The schema uses POSIX-style relative paths on every host. Reject Windows
    # separators/drives explicitly rather than letting host Path semantics vary.
    if "\\" in reference or ":" in reference or "\x00" in reference:
        return None, "evidence_path_not_safe_relative"
    relative = PurePosixPath(reference)
    if (relative.is_absolute() or any(part in ("", ".", "..") for part in reference.split("/"))
            or "/".join(relative.parts) != reference):
        return None, "evidence_path_not_safe_relative"
    if _is_reparse_or_symlink(root):
        return None, "evidence_root_is_symlink_or_reparse_point"
    if not root.is_dir():
        return None, "evidence_root_not_directory"
    candidate = root.joinpath(*relative.parts)
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if _is_reparse_or_symlink(cursor):
            return None, "evidence_path_contains_symlink_or_reparse_point"
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except FileNotFoundError:
        return None, "evidence_file_missing"
    except (OSError, RuntimeError, ValueError):
        return None, "evidence_path_resolution_failed_or_escaped_root"
    if not resolved.is_file():
        return None, "evidence_reference_not_regular_file"
    return resolved, None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_immutable_manifest_reference(value: str) -> bool:
    if IMMUTABLE_COMMIT.fullmatch(value):
        return True
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.netloc:
        return False
    for encoded in (parsed.query, parsed.fragment):
        params = parse_qs(encoded, keep_blank_values=True)
        digests = params.get("sha256", [])
        if len(digests) == 1 and HEX_SHA256.fullmatch(digests[0]):
            return True
    return False


def validate(document: Any, evidence_root: Path) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(document, dict):
        errors.append({"code": "document_not_object", "field": "$"})
        return _result(errors)
    if document.get("schema") != SCHEMA:
        errors.append({"code": "schema_mismatch", "field": "schema"})
    if document.get("case_id") != CASE_ID:
        errors.append({"code": "case_id_mismatch", "field": "case_id"})
    if set(document) != {"schema", "case_id", "fields"}:
        errors.append({"code": "unexpected_or_missing_top_level_keys", "field": "$"})
    fields = document.get("fields")
    if not isinstance(fields, dict):
        errors.append({"code": "fields_not_object", "field": "fields"})
        return _result(errors)
    if set(fields) != set(FIELDS):
        errors.append({"code": "field_set_mismatch", "field": "fields"})

    expected_identity: dict[str, str] | None = None
    for field in FIELDS:
        entry = fields.get(field)
        if not isinstance(entry, dict):
            errors.append({"code": "field_missing_or_not_object", "field": field})
            continue
        if set(entry) != {"value", "evidence"}:
            errors.append({"code": "field_keys_mismatch", "field": field})
        value = entry.get("value")
        if not isinstance(value, str) or not value.strip():
            errors.append({"code": "field_value_missing", "field": field})
        elif field == "locked_manifest_uri_plus_sha256_or_immutable_commit" and not _is_immutable_manifest_reference(value):
            errors.append({"code": "manifest_reference_not_immutable", "field": field})
        evidence = entry.get("evidence")
        if not isinstance(evidence, dict):
            errors.append({"code": "evidence_reference_missing", "field": field})
            continue
        if set(evidence) != {"path", "sha256", "issuer", "build_identity"}:
            errors.append({"code": "evidence_keys_mismatch", "field": field})
        issuer = evidence.get("issuer")
        if not isinstance(issuer, str) or not issuer.strip():
            errors.append({"code": "issuer_missing", "field": field})
        expected_hash = evidence.get("sha256")
        if not isinstance(expected_hash, str) or not HEX_SHA256.fullmatch(expected_hash):
            errors.append({"code": "evidence_sha256_invalid", "field": field})
        else:
            path, path_error = _safe_evidence_file(evidence_root, evidence.get("path"))
            if path_error:
                errors.append({"code": path_error, "field": field})
            elif path is not None:
                try:
                    if _sha256(path).lower() != expected_hash.lower():
                        errors.append({"code": "evidence_sha256_mismatch", "field": field})
                except OSError:
                    errors.append({"code": "evidence_read_failed", "field": field})

        identity = evidence.get("build_identity")
        if not isinstance(identity, dict) or set(identity) != set(FIELDS):
            errors.append({"code": "build_identity_incomplete_or_malformed", "field": field})
            continue
        if any(not isinstance(identity.get(key), str) or not identity[key].strip() for key in FIELDS):
            errors.append({"code": "build_identity_has_empty_values", "field": field})
            continue
        if value != identity.get(field):
            errors.append({"code": "field_value_conflicts_with_build_identity", "field": field})
        if expected_identity is None:
            expected_identity = identity
        elif identity != expected_identity:
            errors.append({"code": "conflicting_build_identity", "field": field})

    return _result(errors)


def _result(errors: list[dict[str, str]]) -> dict[str, Any]:
    complete = not errors
    return {
        "schema": "ohscanner.ark-runtime.ibs5yg-d5-intake-result/v1",
        "status": "STRUCTURE_COMPLETE_REQUIRES_INDEPENDENT_REVIEW" if complete else "WAITING_OR_BLOCKED",
        "admission_ready": False,
        "errors": errors,
        "scope_limit": "Only structure, safe path containment, byte SHA-256 and declared identity consistency are checked. Issuer authenticity, evidence meaning/sufficiency, custody, product truth and product-build association are not verified.",
    }


def _synthetic_document(root: Path) -> dict[str, Any]:
    values = {
        "openharmony_release": "SYNTHETIC-RELEASE",
        "product_build_id_or_image_version": "SYNTHETIC-BUILD",
        "source_branch_or_release_tag": "SYNTHETIC-REF",
        "locked_manifest_uri_plus_sha256_or_immutable_commit": "commit:" + "a" * 40,
        "product_name": "SYNTHETIC-PRODUCT",
        "board_or_device_target": "SYNTHETIC-BOARD",
    }
    evidence_root = root / "evidence"
    evidence_root.mkdir()
    fields: dict[str, Any] = {}
    for index, (field, value) in enumerate(values.items()):
        rel = f"evidence/{field}.txt"
        payload = f"synthetic-evidence-{index}\n".encode()
        (root / rel).write_bytes(payload)
        fields[field] = {
            "value": value,
            "evidence": {
                "path": rel,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "issuer": "SYNTHETIC-ISSUER",
                "build_identity": values.copy(),
            },
        }
    return {"schema": SCHEMA, "case_id": CASE_ID, "fields": fields}


def self_test() -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="ibs5yg-d5-selftest-") as directory:
        root = Path(directory)
        doc = _synthetic_document(root)

        def check(name: str, mutate: Any, expected_code: str | None) -> None:
            candidate = json.loads(json.dumps(doc))
            mutate(candidate)
            result = validate(candidate, root)
            codes = {item["code"] for item in result["errors"]}
            passed = (result["status"] == "STRUCTURE_COMPLETE_REQUIRES_INDEPENDENT_REVIEW") if expected_code is None else expected_code in codes
            checks.append({"name": name, "passed": passed, "status": result["status"], "error_codes": sorted(codes)})

        check("synthetic_complete_structure", lambda d: None, None)
        check("missing_field_value", lambda d: d["fields"][FIELDS[0]].update(value=None), "field_value_missing")
        check("missing_issuer", lambda d: d["fields"][FIELDS[0]]["evidence"].update(issuer=""), "issuer_missing")
        check("tampered_bytes", lambda d: (root / d["fields"][FIELDS[0]]["evidence"]["path"]).write_bytes(b"tampered"), "evidence_sha256_mismatch")
        check("path_traversal", lambda d: d["fields"][FIELDS[0]]["evidence"].update(path="../outside"), "evidence_path_not_safe_relative")
        check("absolute_path", lambda d: d["fields"][FIELDS[0]]["evidence"].update(path=str((root / "evidence").resolve())), "evidence_path_not_safe_relative")
        check("missing_file", lambda d: d["fields"][FIELDS[0]]["evidence"].update(path="evidence/missing"), "evidence_file_missing")
        check("conflicting_build_identity", lambda d: d["fields"][FIELDS[1]]["evidence"]["build_identity"].update(product_name="OTHER"), "conflicting_build_identity")
        check("value_disagrees_with_binding", lambda d: d["fields"][FIELDS[0]].update(value="OTHER"), "field_value_conflicts_with_build_identity")
        check("mutable_manifest_reference", lambda d: d["fields"][FIELDS[3]].update(value="https://example.invalid/manifest.xml"), "manifest_reference_not_immutable")

        link_supported = False
        outside = root.parent / (root.name + "-outside")
        outside.mkdir()
        (outside / "outside.txt").write_text("outside", encoding="utf-8")
        junction = root / "evidence" / "junction"
        try:
            if os.name == "nt":
                completed = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)], capture_output=True, check=False)
                link_supported = completed.returncode == 0
            else:
                junction.symlink_to(outside, target_is_directory=True)
                link_supported = True
            if link_supported:
                digest = hashlib.sha256(b"outside").hexdigest()
                check("junction_or_symlink_escape", lambda d: d["fields"][FIELDS[0]]["evidence"].update(path="evidence/junction/outside.txt", sha256=digest), "evidence_path_contains_symlink_or_reparse_point")
            else:
                checks.append({"name": "junction_or_symlink_escape", "passed": None, "status": "NOT_SUPPORTED_BY_HOST", "error_codes": []})
        except (OSError, NotImplementedError):
            checks.append({"name": "junction_or_symlink_escape", "passed": None, "status": "NOT_SUPPORTED_BY_HOST", "error_codes": []})
        finally:
            try:
                if junction.exists() or junction.is_symlink():
                    junction.rmdir()
                (outside / "outside.txt").unlink()
                outside.rmdir()
            except OSError:
                pass

    return {"schema": "ohscanner.ark-runtime.ibs5yg-d5-intake-selftest/v1", "passed": all(c["passed"] is True for c in checks if c["passed"] is not None), "checks": checks, "note": "Synthetic structure/byte-binding checks only; no product or issuer authenticity is tested."}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = self_test()
        print(json.dumps(result, indent=2))
        return 0 if result["passed"] else 1
    if args.manifest is None or args.evidence_root is None:
        parser.error("--manifest and --evidence-root are required unless --self-test is used")
    try:
        document = json.loads(args.manifest.read_text(encoding="utf-8"))
        result = validate(document, args.evidence_root)
    except (OSError, json.JSONDecodeError) as exc:
        result = _result([{"code": "input_read_or_json_error", "field": str(exc)}])
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "STRUCTURE_COMPLETE_REQUIRES_INDEPENDENT_REVIEW" else 2


if __name__ == "__main__":
    raise SystemExit(main())

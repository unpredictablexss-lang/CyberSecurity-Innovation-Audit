#!/usr/bin/env python3
"""Recompute a fail-closed Ark parent/fix build/preprocess profile manifest.

The script reads only pinned local Git objects and local evidence. It never
fetches, checks out, builds, preprocesses, or executes target code. Missing
product build/profile inputs remain explicit blockers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

LEDGER_COMMIT = "e4e0761501a83ac25cc67d04c527eefe9f4a1b50"
LEDGER_PATH = "research/deliveries/c-line/ark-runtime-coverage-ledger-20261019.json"
SOURCE_AUDIT_COMMIT = LEDGER_COMMIT
SOURCE_AUDIT_TREE = "307ac8237263db793028e0bf34a82a85f60821a5"
SOURCE_AUDIT_BLOB = "dbedea677c8dc70c1b0066c7bc52df27bcff06ea"
SOURCE_AUDIT_PATH = "research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md"
SOURCE_AUDIT_SHA256 = "732b17b4adba11f1fefb93940859d951e03d35a69987b77a61f9a785eefe1240"
PROFILE_SCHEMA = "ohscanner.ark-parent-fix-build-preprocess-profile/v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def run_git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.STDOUT)


def git_object(repo: Path, revision: str) -> dict[str, Any]:
    object_type = run_git(repo, "cat-file", "-t", revision).decode("ascii").strip()
    size = int(run_git(repo, "cat-file", "-s", revision).decode("ascii").strip())
    return {"oid": revision, "type": object_type, "bytes": size}


def file_identity(path: Path, repo: Path | None = None) -> dict[str, Any]:
    data = path.read_bytes()
    item = {
        "path": str(path),
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "git_blob_sha1_recomputed": git_blob_sha1(data),
    }
    if repo is not None:
        try:
            rel = path.resolve().relative_to(repo.resolve()).as_posix()
            item["workspace_path"] = rel
            item["tracked_git_blob_oid"] = run_git(repo, "hash-object", rel).decode("ascii").strip()
        except (ValueError, subprocess.CalledProcessError):
            item["workspace_path"] = None
            item["tracked_git_blob_oid"] = None
    return item


def probe_tool(name: str) -> dict[str, Any]:
    executable = shutil.which(name)
    if not executable:
        return {"name": name, "status": "unavailable_on_host_path", "path": None, "sha256": None, "version": None}
    path = Path(executable)
    try:
        data = path.read_bytes()
        digest = sha256_bytes(data)
    except OSError:
        digest = None
    try:
        version = subprocess.check_output([executable, "--version"], stderr=subprocess.STDOUT, text=True).splitlines()[0]
    except (OSError, subprocess.CalledProcessError, IndexError):
        version = None
    return {"name": name, "status": "host_tool_observed_not_product_toolchain", "path": str(path), "sha256": digest, "version": version}


def python_runtime_identity() -> dict[str, Any]:
    executable = Path(sys.executable)
    data = executable.read_bytes()
    modules: dict[str, Any] = {}
    for name in ("tree_sitter", "tree_sitter_c", "tree_sitter_cpp"):
        try:
            module = __import__(name)
            module_path = Path(module.__file__)
            modules[name] = {
                "module_path": str(module_path),
                "module_sha256": sha256_bytes(module_path.read_bytes()),
                "version": getattr(module, "__version__", None),
            }
        except Exception as exc:  # explicit identity unavailable
            modules[name] = {"status": "unavailable", "error": type(exc).__name__}
    return {
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "executable": str(executable),
        "executable_sha256": sha256_bytes(data),
        "parser_modules": modules,
    }


def source_identity_entry(file_item: Any) -> dict[str, Any]:
    if not isinstance(file_item, dict):
        return {
            "path": file_item if isinstance(file_item, str) else None,
            "recorded_git_blob_oid": None,
            "recorded_source_sha256": None,
            "recorded_bytes": None,
            "identity_schema_valid": False,
            "local_git_object_verification": "not_verified_official_ark_store_unavailable",
            "source_bytes_available_in_this_checkout": False,
        }
    blob = file_item.get("blob")
    digest = file_item.get("sha256")
    return {
        "path": file_item.get("path"),
        "recorded_git_blob_oid": blob,
        "recorded_source_sha256": digest,
        "recorded_bytes": file_item.get("bytes"),
        "identity_schema_valid": bool(
            isinstance(file_item.get("path"), str)
            and isinstance(blob, str)
            and HEX40.fullmatch(blob)
            and isinstance(digest, str)
            and HEX256.fullmatch(digest)
        ),
        "local_git_object_verification": "not_verified_official_ark_store_unavailable",
        "source_bytes_available_in_this_checkout": False,
    }


def normalized_case(case: dict[str, Any]) -> dict[str, Any]:
    parent_files = [source_identity_entry(item) for item in case.get("vulnerable_files", [])]
    fixed_files = [source_identity_entry(item) for item in case.get("fixed_files", [])]
    complete_identity = bool(
        case.get("vulnerable_commit")
        and case.get("vulnerable_tree")
        and case.get("fixed_commit")
        and case.get("fixed_tree")
        and parent_files
        and fixed_files
        and all(item["identity_schema_valid"] for item in parent_files + fixed_files)
    )
    blockers = [
        "official Ark Git object store is not bound by OHSCANNER_ARK_OFFICIAL_GIT",
        "exact product args.gn / GN target / product manifest is absent",
        "compiler and preprocessor toolchain identity is absent",
        "compile_commands.json and exact include closure are absent",
        "preprocessed translation-unit outputs and macro expansion log are absent",
        "source-to-shipped-product binary/version/branch binding is absent",
    ]
    if not complete_identity:
        blockers.insert(0, "one or more parent/fixed commit/tree/blob/source identities are incomplete")
    return {
        "case_id": case.get("case_id"),
        "evidence_class": "development_case_not_independent_holdout",
        "component": case.get("component"),
        "cve_or_advisory": case.get("CVE_or_advisory"),
        "parent": {
            "commit": case.get("vulnerable_commit"),
            "tree": case.get("vulnerable_tree"),
            "files": parent_files,
        },
        "fixed": {
            "commit": case.get("fixed_commit"),
            "tree": case.get("fixed_tree"),
            "files": fixed_files,
        },
        "source_identity_status": "recorded_complete" if complete_identity else "recorded_incomplete",
        "build_profile": {
            "status": "BLOCKED",
            "product_manifest_locked": False,
            "product_target": None,
            "args_gn": None,
            "compile_commands_json": None,
            "include_closure": None,
            "preprocessor": {"status": "NOT_RUN", "outputs": [], "macro_expansion_log": None},
            "toolchain": {"product_compiler": None, "product_linker": None, "sysroot": None},
        },
        "preprocess_profile": {
            "declared_scan_profile": "light-ast",
            "macro_expansion": False,
            "translation_unit": None,
            "actual_include_closure": None,
            "status": "BLOCKED",
        },
        "product_association": case.get("product_build_association"),
        "scan_scope": (case.get("baseline_scan", {}).get("scope") or case.get("baseline_scan", {}).get("declared_scope")) if isinstance(case.get("baseline_scan"), dict) else None,
        "blockers": blockers,
    }


def build_manifest(repo: Path) -> dict[str, Any]:
    ledger_blob = run_git(repo, "show", f"{LEDGER_COMMIT}:{LEDGER_PATH}")
    ledger = json.loads(ledger_blob)
    audit_blob = run_git(repo, "cat-file", "blob", SOURCE_AUDIT_BLOB)
    audit_identity_ok = (
        sha256_bytes(audit_blob) == SOURCE_AUDIT_SHA256
        and git_blob_sha1(audit_blob) == SOURCE_AUDIT_BLOB
    )
    source_hashes_path = repo / "research/experiments/ark_runtime/c11_alias_cross_helper_20261019/source-hashes.json"
    syntax_path = repo / "src/ohscanner/detectors/ark_runtime/syntax.py"
    model_path = repo / "src/ohscanner/detectors/ark_runtime/model.py"
    profile_spec = Path(__file__).with_name("profile-spec.json")
    cases = [normalized_case(case) for case in ledger.get("cases", [])]
    required = [
        "commit", "tree", "blob", "source_sha256",
        "detector_rule_version", "scope", "profile", "config_hash",
        "parser_identity", "toolchain_identity",
    ]
    payload = {
        "schema": PROFILE_SCHEMA,
        "status": "BLOCKED",
        "decision": "NOT_ADMITTED",
        "generated_from": {
            "ohscanner_repository": run_git(repo, "remote", "get-url", "origin").decode("utf-8").strip(),
            "ohscanner_head": run_git(repo, "rev-parse", "HEAD").decode("ascii").strip(),
            "ohscanner_tree": run_git(repo, "rev-parse", "HEAD^{tree}").decode("ascii").strip(),
            "ledger_commit": LEDGER_COMMIT,
            "ledger_path": LEDGER_PATH,
            "ledger_blob_oid": git_blob_sha1(ledger_blob),
            "ledger_sha256": sha256_bytes(ledger_blob),
        },
        "source_audit_identity": {
            "path": SOURCE_AUDIT_PATH,
            "commit": SOURCE_AUDIT_COMMIT,
            "tree": SOURCE_AUDIT_TREE,
            "blob": SOURCE_AUDIT_BLOB,
            "sha256": SOURCE_AUDIT_SHA256,
            "local_pinned_object_verified": audit_identity_ok,
        },
        "required_identity_fields": required,
        "identity_coverage": {
            "all_required_present_for_product_build": False,
            "missing_for_product_build": [
                "product commit/tree/blob/source mapping",
                "Detector/rule version bound to exact product source",
                "scope/profile tied to product target",
                "config_hash",
                "parser binary identity",
                "product toolchain identity",
            ],
        },
        "detector_identity": {
            "detector_id": "ohscanner.ark.runtime.type_safety",
            "detector_version": "0.6.2",
            "source_hashes_manifest": file_identity(source_hashes_path, repo) if source_hashes_path.exists() else None,
        },
        "parser_identity": {
            "implementation_source": file_identity(syntax_path, repo) if syntax_path.exists() else None,
            "model_source": file_identity(model_path, repo) if model_path.exists() else None,
            "runtime": python_runtime_identity(),
            "binary_identity_complete": False,
        },
        "config_identity": {
            "profile_spec": file_identity(profile_spec) if profile_spec.exists() else None,
            "profile_id": "light-ast",
            "preprocessing_enabled": False,
        },
        "host_toolchain_probe": {
            "note": "Host probes are not the target product toolchain.",
            "python": python_runtime_identity(),
            "tools": [probe_tool(name) for name in ("git", "clang", "clang++", "cmake", "ninja", "gn")],
        },
        "cases": cases,
        "global_blockers": [
            "No product build/profile manifest is locked.",
            "No product preprocessed translation units or complete include closure are available.",
            "No shipped product binary/version/branch/source association is established.",
            "No product entry/privilege/trigger/CIA/PoC/fix revalidation closure is established.",
        ],
        "metrics": {
            "case_count": len(cases),
            "recorded_complete_source_identity_count": sum(c["source_identity_status"] == "recorded_complete" for c in cases),
            "product_build_profile_complete_count": 0,
            "precision": None,
            "recall": None,
            "reason_no_metrics": "No independent reliable labelled holdout exists.",
        },
    }
    payload["payload_sha256"] = sha256_bytes(canonical_json_bytes(payload))
    return payload


def verify_manifest(repo: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Backward-compatible alias for environment reproduction, not integrity."""
    return reproduce_environment(repo, manifest)


def verify_manifest_integrity(manifest: dict[str, Any]) -> dict[str, Any]:
    """Verify only the manifest's self-recorded canonical content digest.

    A valid digest shows internal consistency, not authenticity, provenance,
    correctness of claims, source object existence, or a product build.
    """
    errors = []
    if manifest.get("schema") != PROFILE_SCHEMA:
        errors.append("schema_mismatch")
    recorded = manifest.get("payload_sha256")
    if not isinstance(recorded, str) or not HEX256.fullmatch(recorded):
        errors.append("payload_digest_missing_or_malformed")
    else:
        payload = dict(manifest)
        payload.pop("payload_sha256", None)
        computed = sha256_bytes(canonical_json_bytes(payload))
        if recorded != computed:
            errors.append("payload_digest_mismatch")

    unsafe = []
    if manifest.get("status") != "BLOCKED":
        unsafe.append("manifest_status_not_blocked")
    if manifest.get("decision") != "NOT_ADMITTED":
        unsafe.append("decision_not_not_admitted")
    for case in manifest.get("cases", []):
        if case.get("build_profile", {}).get("status") != "BLOCKED":
            unsafe.append(f"build_profile_not_blocked:{case.get('case_id')}")
        if case.get("preprocess_profile", {}).get("status") != "BLOCKED":
            unsafe.append(f"preprocess_profile_not_blocked:{case.get('case_id')}")
    if manifest.get("metrics", {}).get("product_build_profile_complete_count") != 0:
        unsafe.append("product_build_profile_complete_count_not_zero")
    errors.extend(unsafe)
    result = {
        "schema": "ohscanner.ark-parent-fix-manifest-integrity/v1",
        "manifest_integrity": "valid" if not errors else "invalid",
        "recorded_payload_sha256": recorded,
        "computed_payload_sha256": computed if isinstance(recorded, str) and HEX256.fullmatch(recorded) else None,
        "case_count": len(manifest.get("cases", [])) if isinstance(manifest.get("cases"), list) else None,
        "product_profile_status": "BLOCKED" if not unsafe else "UNSAFE_OR_INCOMPLETE",
        "errors": errors,
        "scope_note": "Internal content-digest consistency only; no authenticity, source provenance, Git object, product build, or preprocess verification.",
    }
    return result


ENVIRONMENT_FINGERPRINT_FIELDS = (
    "generated_from",
    "source_audit_identity",
    "detector_identity",
    "parser_identity",
    "config_identity",
    "host_toolchain_probe",
)


def environment_fingerprint(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: manifest.get(key) for key in ENVIRONMENT_FINGERPRINT_FIELDS}


def changed_paths(expected: Any, actual: Any, prefix: str = "") -> list[str]:
    if isinstance(expected, dict) and isinstance(actual, dict):
        paths = []
        for key in sorted(set(expected) | set(actual)):
            child = f"{prefix}.{key}" if prefix else key
            if key not in expected or key not in actual:
                paths.append(child)
            else:
                paths.extend(changed_paths(expected[key], actual[key], child))
        return paths
    if isinstance(expected, list) and isinstance(actual, list):
        paths = []
        if len(expected) != len(actual):
            paths.append(f"{prefix}.length")
        for index, (left, right) in enumerate(zip(expected, actual)):
            paths.extend(changed_paths(left, right, f"{prefix}[{index}]"))
        return paths
    return [] if expected == actual else [prefix]


def compare_environment_fingerprints(expected_manifest: dict[str, Any], recomputed_manifest: dict[str, Any]) -> dict[str, Any]:
    expected = environment_fingerprint(expected_manifest)
    actual = environment_fingerprint(recomputed_manifest)
    paths = changed_paths(expected, actual)
    return {
        "environment_reproduction": "environment_match" if not paths else "environment_drift",
        "expected_environment_fingerprint_sha256": sha256_bytes(canonical_json_bytes(expected)),
        "recomputed_environment_fingerprint_sha256": sha256_bytes(canonical_json_bytes(actual)),
        "changed_paths": paths,
    }


def reproduce_environment(repo: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Compare the stored environment/source fingerprint with this host now."""
    recomputed_manifest = build_manifest(repo)
    comparison = compare_environment_fingerprints(manifest, recomputed_manifest)
    integrity = verify_manifest_integrity(manifest)
    return {
        "schema": "ohscanner.ark-parent-fix-environment-reproduction/v1",
        **comparison,
        "manifest_integrity": integrity["manifest_integrity"],
        "case_count": len(manifest.get("cases", [])),
        "product_profile_status": integrity["product_profile_status"],
        "scope_note": "Reproduction is checkout/host sensitive; a match does not verify upstream Git objects or product build/preprocess evidence.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("ark_parent_fix_build_profile_manifest.v1.json"))
    parser.add_argument("--verification-output", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--verify-integrity-only", action="store_true", help="Check the stored manifest's canonical self-digest and blocked-state invariants; no repo required")
    modes.add_argument("--reproduce-environment", action="store_true", help="Recompute current checkout/host fingerprint and compare it to the stored manifest")
    modes.add_argument("--verify-only", action="store_true", help="Deprecated alias for --reproduce-environment")
    args = parser.parse_args(argv)
    if args.verify_integrity_only:
        manifest = json.loads(args.output.read_text(encoding="utf-8"))
        verification = verify_manifest_integrity(manifest)
        print(json.dumps(verification, ensure_ascii=False, sort_keys=True, indent=2))
        return 0 if verification["manifest_integrity"] == "valid" else 2

    if args.reproduce_environment or args.verify_only:
        if args.repo_root is None:
            parser.error("--repo-root is required for --reproduce-environment")
        manifest = json.loads(args.output.read_text(encoding="utf-8"))
        verification = reproduce_environment(args.repo_root.resolve(), manifest)
        if args.verify_only:
            print("warning: --verify-only is deprecated; this is host/checkout-dependent reproduction, not integrity verification", file=sys.stderr)
        if args.verification_output:
            args.verification_output.write_text(json.dumps(verification, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(verification, ensure_ascii=False, sort_keys=True, indent=2))
        return 0 if verification["environment_reproduction"] == "environment_match" else 2

    if args.repo_root is None:
        parser.error("--repo-root is required to generate a manifest")
    manifest = build_manifest(args.repo_root.resolve())
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    verification = verify_manifest_integrity(manifest)
    if args.verification_output:
        args.verification_output.write_text(json.dumps(verification, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(verification, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if verification["manifest_integrity"] == "valid" else 2


if __name__ == "__main__":
    raise SystemExit(main())

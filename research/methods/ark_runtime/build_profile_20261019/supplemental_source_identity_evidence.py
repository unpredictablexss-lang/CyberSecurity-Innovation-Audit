#!/usr/bin/env python3
"""Recompute source identities for the remaining Ark cases with commit anchors.

This is an offline, read-only supplemental check. It never fetches or checks out
source and it does not modify the historical profile manifest. Computed object
identity is evidence about the configured local object store; it does not prove
the store's acquisition/custody chain or a product build association.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

PROFILE_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = PROFILE_DIR / "ark_parent_fix_build_profile_manifest.v1.json"
OUTPUT_PATH = PROFILE_DIR / "supplemental_source_identity_evidence.v1.json"
EXPECTED_MANIFEST_PAYLOAD_SHA256 = "a33c893cce5ba4bd2dbc80e7f94b3ce47a5c6c0ed8b62f5157fb7db8aeb7c214"
EXPECTED_CASE_IDS = {
    "ARK-RUNTIME-CALLINFO-CONSTRUCTION-PENDING-EXCEPTION-I7K7L6",
    "ARK-RUNTIME-NEWCALLINFO-EXCEPTION-GUARD-IB40SU",
    "ARK-RUNTIME-INSTANCEOF-EXCEPTION-RETURN-VALUE-I7SDBG",
    "ARK-SHAREDARRAY-FINDINDEX-EXCEPTION-PROPAGATION-PARTIAL-2A9BCFB",
    "ARK-TYPEDARRAY-MAP-STORE-TYPE-ORIGIN-CVE-2025-24304",
    "ARK-TYPEDARRAY-MAP-NEWARRAY-PENDING-EXCEPTION-IC7B8Q",
    "ARK-TYPEDARRAY-FILTER-RECEIVER-TYPE-GUARD-IAO7E8",
}
UNRESOLVED_CASES = {
    "ARK-ARRAY-CALLBACK-ABRUPT-COMPLETION-HISTORY-VARIANT":
        "parent/fixed commit and scope are null; the manifest text mentions two history commits but does not bind either to this pair",
    "ARK-TYPEDARRAY-CONSTRUCTOR-LENGTH-NARROWING-I7W51D":
        "parent/fixed commit, tree, and file paths are null",
    "ARK-DATAVIEW-INDEX-WIDTH-AND-BOUNDS-IB8BCA":
        "parent/fixed commit, tree, and file paths are null",
}
OFFICIAL_REMOTE = "https://gitee.com/openharmony/arkcompiler_ets_runtime.git"
HEX40 = re.compile(r"^[0-9a-f]{40}$")


class EvidenceError(RuntimeError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def git(git_dir: Path, *args: str, check: bool = True) -> bytes:
    result = subprocess.run(["git", "--git-dir", str(git_dir), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        raise EvidenceError(f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout


def payload_digest(manifest: dict[str, Any]) -> str:
    payload = dict(manifest)
    payload.pop("payload_sha256", None)
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def compare_recorded(expected: Any, observed: Any) -> str:
    """Keep absent expectations distinct from successful comparisons."""
    if expected is None:
        return "NOT_RECORDED"
    return "MATCH" if expected == observed else "MISMATCH"


def summarize(evidence: list[dict[str, Any]], unresolved_cases: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"MATCH": 0, "NOT_RECORDED": 0, "MISMATCH": 0}
    by_field = {field: dict(counts) for field in ("tree", "recorded_git_blob_oid", "recorded_source_sha256", "recorded_bytes")}
    missing_side_paths = 0
    blocked_paths = 0
    blockers = {
        "missing_commit_sides": 0,
        "missing_or_wrong_type_commit_objects": 0,
        "missing_trees": 0,
        "ancestry_failures": 0,
        "ancestry_errors": 0,
        "ancestry_unknown": 0,
    }
    for case in evidence:
        for side in ("parent", "fixed"):
            side_data = case.get(side) or {}
            side_status = side_data.get("status")
            if side_status == "UNKNOWN":
                blockers["missing_commit_sides"] += 1
            elif side_status == "BLOCKED_OBJECT_MISSING_OR_WRONG_TYPE":
                blockers["missing_or_wrong_type_commit_objects"] += 1
            elif side_status == "BLOCKED_TREE_MISSING":
                blockers["missing_trees"] += 1
            tree_state = side_data.get("tree_check")
            if tree_state in counts:
                counts[tree_state] += 1
                by_field["tree"][tree_state] += 1
            for file_record in side_data.get("files", []):
                path_state = file_record.get("status")
                if path_state == "NOT_PRESENT_IN_THIS_SIDE":
                    missing_side_paths += 1
                elif isinstance(path_state, str) and path_state.startswith("BLOCKED"):
                    blocked_paths += 1
                for field, state in (file_record.get("checks_against_manifest") or {}).items():
                    if field in by_field and state in counts:
                        counts[state] += 1
                        by_field[field][state] += 1
        ancestry = case.get("parent_is_ancestor_of_fixed")
        if ancestry == "FAIL":
            blockers["ancestry_failures"] += 1
        elif ancestry == "BLOCKED_ERROR":
            blockers["ancestry_errors"] += 1
        elif ancestry != "PASS":
            blockers["ancestry_unknown"] += 1
    return {
        "anchored_cases": len(evidence),
        "unanchored_cases": len(unresolved_cases),
        "recorded_identity_checks": counts,
        "checks_by_field": by_field,
        "missing_side_paths": missing_side_paths,
        "blocked_expected_paths": blocked_paths,
        "blockers": blockers,
    }


def has_verification_failure(summary: dict[str, Any]) -> bool:
    blockers = summary["blockers"]
    return bool(summary["recorded_identity_checks"]["MISMATCH"]
                or summary["blocked_expected_paths"]
                or any(blockers.values()))


def self_test() -> None:
    """Synthetic negative check: a bad recorded value fails; None stays unknown."""
    assert compare_recorded("expected", "expected") == "MATCH"
    assert compare_recorded("expected", "observed") == "MISMATCH"
    assert compare_recorded(None, "observed") == "NOT_RECORDED"
    synthetic = [{
        "parent": {"tree_check": "MISMATCH", "files": [{"status": "OBJECT_BYTES_RECOMPUTED", "checks_against_manifest": {
            "recorded_git_blob_oid": "MATCH", "recorded_source_sha256": "NOT_RECORDED", "recorded_bytes": "MISMATCH"}}]},
        "fixed": {"tree_check": "NOT_RECORDED", "files": [{"status": "NOT_PRESENT_IN_THIS_SIDE"}]},
    }]
    summary = summarize(synthetic, [{"case_id": "synthetic-unanchored"}])
    assert summary["recorded_identity_checks"] == {"MATCH": 1, "NOT_RECORDED": 2, "MISMATCH": 2}
    assert summary["missing_side_paths"] == 1
    assert has_verification_failure(summary), "recorded mismatch must fail the verification gate"
    clean_summary = summarize([{"parent": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []},
                                "fixed": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []},
                                "parent_is_ancestor_of_fixed": "PASS"}], [])
    assert not has_verification_failure(clean_summary), "NOT_RECORDED alone must not be treated as mismatch"
    blocked_mutations = [
        {"parent": {"status": "BLOCKED_OBJECT_MISSING_OR_WRONG_TYPE", "files": []}, "fixed": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []}, "parent_is_ancestor_of_fixed": "PASS"},
        {"parent": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []}, "fixed": {"status": "BLOCKED_TREE_MISSING", "tree_check": "NOT_RECORDED", "files": []}, "parent_is_ancestor_of_fixed": "PASS"},
        {"parent": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []}, "fixed": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []}, "parent_is_ancestor_of_fixed": "FAIL"},
        {"parent": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []}, "fixed": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []}, "parent_is_ancestor_of_fixed": "BLOCKED_ERROR"},
    ]
    for mutation in blocked_mutations:
        assert has_verification_failure(summarize([mutation], [])), f"must fail closed for mutation {mutation}"


def validate_store(git_dir: Path) -> dict[str, Any]:
    if git(git_dir, "rev-parse", "--is-bare-repository").decode("ascii").strip() != "true":
        raise EvidenceError("configured object store is not bare")
    if git(git_dir, "rev-parse", "--is-shallow-repository").decode("ascii").strip() != "false":
        raise EvidenceError("configured object store is shallow; ancestry cannot be evaluated")
    fetch = git(git_dir, "remote", "get-url", "--all", "origin").decode("utf-8", "replace").splitlines()
    push = git(git_dir, "remote", "get-url", "--push", "--all", "origin").decode("utf-8", "replace").splitlines()
    normalize = lambda values: [value.strip().rstrip("/").lower() for value in values if value.strip()]
    if normalize(fetch) != [OFFICIAL_REMOTE] or normalize(push) != [OFFICIAL_REMOTE]:
        raise EvidenceError("origin fetch/push URL is not exactly the declared official Gitee URL")
    return {"git_dir": str(git_dir.resolve()), "bare": True, "shallow": False,
            "origin_fetch_urls": fetch, "origin_push_urls": push,
            "custody": "NOT_INDEPENDENTLY_VERIFIED"}


def manifest_paths(case: dict[str, Any]) -> tuple[list[str], str]:
    scope = case.get("scan_scope")
    if isinstance(scope, list) and scope and all(isinstance(x, str) for x in scope):
        return sorted(set(scope)), "case.scan_scope"
    paths = {entry.get("path") for side in ("parent", "fixed")
             for entry in (case.get(side) or {}).get("files", [])
             if isinstance(entry, dict) and isinstance(entry.get("path"), str)}
    if paths:
        return sorted(paths), "parent/fixed.files.path union"
    return [], "UNKNOWN"


def expected_file(case: dict[str, Any], side: str, path: str) -> dict[str, Any] | None:
    for entry in (case.get(side) or {}).get("files", []):
        if isinstance(entry, dict) and entry.get("path") == path:
            return entry
    return None


def inspect_case(git_dir: Path, case: dict[str, Any]) -> dict[str, Any]:
    paths, paths_basis = manifest_paths(case)
    sides: dict[str, Any] = {}
    for side in ("parent", "fixed"):
        item = case.get(side) or {}
        commit = item.get("commit")
        if not isinstance(commit, str) or not HEX40.fullmatch(commit):
            sides[side] = {"status": "UNKNOWN", "commit": commit, "tree": None, "files": []}
            continue
        commit_type = git(git_dir, "cat-file", "-t", commit, check=False).decode("ascii", "replace").strip()
        if commit_type != "commit":
            sides[side] = {"status": "BLOCKED_OBJECT_MISSING_OR_WRONG_TYPE", "commit": commit, "tree": None, "files": []}
            continue
        raw_commit = git(git_dir, "cat-file", "commit", commit)
        tree_line = next((line for line in raw_commit.splitlines() if line.startswith(b"tree ")), None)
        actual_tree = tree_line[5:].decode("ascii") if tree_line else None
        recorded_tree = item.get("tree")
        tree_status = ("MATCH" if recorded_tree == actual_tree else
                       "NOT_RECORDED" if not isinstance(recorded_tree, str) or not HEX40.fullmatch(recorded_tree)
                       else "MISMATCH")
        files = []
        for path in paths:
            expected = expected_file(case, side, path)
            spec = f"{commit}:{path}"
            blob_type = git(git_dir, "cat-file", "-t", spec, check=False).decode("ascii", "replace").strip()
            if blob_type != "blob":
                files.append({"path": path,
                              "status": "NOT_PRESENT_IN_THIS_SIDE" if expected is None else "BLOCKED_EXPECTED_PATH_NOT_BLOB_AT_COMMIT",
                              "recorded_git_blob_oid": (expected or {}).get("recorded_git_blob_oid"),
                              "recorded_source_sha256": (expected or {}).get("recorded_source_sha256")})
                continue
            blob_oid = git(git_dir, "rev-parse", spec).decode("ascii").strip()
            data = git(git_dir, "cat-file", "blob", spec)
            raw_sha256 = hashlib.sha256(data).hexdigest()
            raw_blob_oid = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
            oid_match = (expected or {}).get("recorded_git_blob_oid")
            sha_match = (expected or {}).get("recorded_source_sha256")
            length_match = (expected or {}).get("recorded_bytes")
            checks = {
                "recorded_git_blob_oid": compare_recorded(oid_match, blob_oid if blob_oid == raw_blob_oid else "<raw-blob-oid-mismatch>"),
                "recorded_source_sha256": compare_recorded(sha_match, raw_sha256),
                "recorded_bytes": compare_recorded(length_match, len(data)),
            }
            failures = [key for key, state in checks.items() if state == "MISMATCH"]
            files.append({"path": path, "status": "MISMATCH" if failures else "OBJECT_BYTES_RECOMPUTED",
                          "blob_oid": blob_oid, "source_sha256": raw_sha256, "bytes": len(data),
                          "checks_against_manifest": checks})
        sides[side] = {"status": "OBJECTS_RECOMPUTED" if actual_tree else "BLOCKED_TREE_MISSING",
                       "commit": commit, "tree": actual_tree, "recorded_tree": recorded_tree,
                       "tree_check": tree_status, "files": files}
    parent_commit = (case.get("parent") or {}).get("commit")
    fixed_commit = (case.get("fixed") or {}).get("commit")
    ancestry = "UNKNOWN"
    if isinstance(parent_commit, str) and isinstance(fixed_commit, str) and HEX40.fullmatch(parent_commit) and HEX40.fullmatch(fixed_commit):
        result = subprocess.run(["git", "--git-dir", str(git_dir), "merge-base", "--is-ancestor", parent_commit, fixed_commit], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ancestry = "PASS" if result.returncode == 0 else "FAIL" if result.returncode == 1 else "BLOCKED_ERROR"
    return {"case_id": case["case_id"], "paths_basis": paths_basis, "paths": paths,
            "parent": sides["parent"], "fixed": sides["fixed"], "parent_is_ancestor_of_fixed": ancestry}


def generate(git_dir: Path) -> dict[str, Any]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    digest = payload_digest(manifest)
    if digest != EXPECTED_MANIFEST_PAYLOAD_SHA256 or manifest.get("payload_sha256") != digest:
        raise EvidenceError("historical profile manifest payload digest mismatch")
    cases = {case["case_id"]: case for case in manifest.get("cases", [])}
    present_ids = {case_id for case_id in EXPECTED_CASE_IDS if case_id in cases and any((cases[case_id].get(side) or {}).get("commit") for side in ("parent", "fixed"))}
    if present_ids != EXPECTED_CASE_IDS:
        raise EvidenceError(f"expected case set/commit anchors mismatch: missing={sorted(EXPECTED_CASE_IDS-present_ids)}")
    store = validate_store(git_dir)
    evidence = [inspect_case(git_dir, cases[case_id]) for case_id in sorted(EXPECTED_CASE_IDS)]
    # Do not upgrade UNKNOWN entries or product statuses from source-only results.
    result = {
        "schema": "ohscanner.ark-supplemental-source-identity-evidence/v1",
        "profile_manifest": {"path": MANIFEST_PATH.name, "payload_sha256": digest},
        "configured_store": store,
        "scope": "7 remaining cases with manifest-bound commit anchors; paths use explicit scan_scope or the manifest's listed parent/fixed file-path union",
        "cases": evidence,
        "unresolved_cases": [{"case_id": key, "status": "UNKNOWN", "reason": reason}
                             for key, reason in sorted(UNRESOLVED_CASES.items())],
        "limitations": [
            "A local object database matching its declared official Gitee remote does not independently prove acquisition, custody, or server authenticity.",
            "Source object identity does not establish product inclusion, build configuration, preprocessing, runtime reachability, or vulnerability impact.",
            "The three unresolved cases have no sufficient manifest-bound commit/path pair; no commits or paths were inferred.",
            "Any absent recorded raw SHA/length is reported as not recorded; a recomputed value is not an independent expected value.",
        ],
        "summary": summarize(evidence, [{"case_id": key, "status": "UNKNOWN", "reason": reason}
                                        for key, reason in sorted(UNRESOLVED_CASES.items())]),
        "portfolio_status": "PC-1 IN_PROGRESS_BLOCKED; product build/preprocess profiles remain BLOCKED and 0/16 complete",
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-dir", type=Path, help="path to the local bare Ark Git object store")
    parser.add_argument("--write", action="store_true", help="write deterministic JSON evidence")
    parser.add_argument("--verify-only", action="store_true", help="recompute and compare saved JSON; performs no writes")
    parser.add_argument("--self-test", action="store_true", help="run synthetic MATCH/NOT_RECORDED/MISMATCH checks; no Git store required")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("synthetic verifier checks passed: MATCH, NOT_RECORDED, MISMATCH, and missing-side path are distinct")
        return 0
    if args.git_dir is None:
        parser.error("--git-dir is required unless --self-test is selected")
    try:
        result = generate(args.git_dir)
        encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        summary = result["summary"]
        checks = summary["recorded_identity_checks"]
        blockers = summary["blockers"]
        print("cases: anchored={anchored_cases} unanchored={unanchored_cases}; identity checks: MATCH={MATCH} NOT_RECORDED={NOT_RECORDED} MISMATCH={MISMATCH}; missing-side paths={missing_side_paths}; blocked expected paths={blocked_expected_paths}; blockers: missing commit sides={missing_commit_sides}, missing/wrong-type commit objects={missing_or_wrong_type_commit_objects}, missing trees={missing_trees}, ancestry FAIL={ancestry_failures}, ancestry BLOCKED_ERROR={ancestry_errors}, ancestry UNKNOWN={ancestry_unknown}".format(
            **summary, **checks, **blockers))
        if has_verification_failure(summary):
            print("FAIL: recorded mismatch or blocked/failed source identity check", file=sys.stderr)
            return 2
        if args.verify_only:
            saved = OUTPUT_PATH.read_text(encoding="utf-8")
            if saved != encoded:
                raise EvidenceError("saved supplemental evidence differs from recomputed object-store evidence")
            print("verified artifact bytes against current recomputation; NOT_RECORDED values are excluded from MATCH")
        elif args.write:
            OUTPUT_PATH.write_text(encoded, encoding="utf-8", newline="\n")
            print(f"wrote {OUTPUT_PATH}")
        else:
            sys.stdout.write(encoded)
        return 0
    except (EvidenceError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

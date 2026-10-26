from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = ROOT / "research" / "tests" / "a_null_01"
FIXTURES = PACKAGE / "fixtures"
MATRIX = PACKAGE / "regression_matrix.json"
MANIFEST = PACKAGE / "manifest.json"
LANGUAGES = {".c": "c", ".cc": "cpp", ".cpp": "cpp", ".h": "cpp", ".hpp": "cpp", ".js": "js"}

EXPECTED_CATEGORIES = {
    "vulnerable",
    "vulnerable_unknown_return",
    "fixed",
    "safe",
    "unrelated",
    "unknown_macro",
    "unknown_template",
    "unknown_exception_destructor",
    "unknown_indirect_call",
    "unknown_cross_function_alias",
    "unknown_failed_parse",
    "not_analyzed_unsupported_language",
}
OBSERVATIONS = {
    "candidate_shape",
    "candidate_with_unknown_obligations",
    "no_candidate_shape",
    "unknown_incomplete_analysis",
    "not_analyzed_no_matching_language",
}
COVERAGES = {"complete", "partial", "failed", "not_analyzed"}
GUARD_RELATIONS = {"none", "dominating", "not_dominating", "unknown", "not_applicable"}
ERROR_PATHS = {
    "not_applicable",
    "early_return",
    "positive_guard_only",
    "error_branch_falls_through",
    "exception_unmodeled",
    "unknown",
}


def digest(data: bytes, algorithm: str = "sha256") -> str:
    return hashlib.new(algorithm, data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return digest(b"blob " + str(len(data)).encode("ascii") + b"\0" + data, "sha1")


def load_matrix() -> dict:
    return json.loads(MATRIX.read_text(encoding="utf-8-sig"))


def source_record(case: dict) -> dict:
    path = FIXTURES / case["fixture"]
    data = path.read_bytes()
    text = data.decode("utf-8")
    suffix = path.suffix.lower()
    language = LANGUAGES.get(suffix)
    if language is None:
        raise ValueError(f"unsupported fixture suffix: {path.name}")
    return {
        "path": f"research/tests/a_null_01/fixtures/{path.name}",
        "language": language,
        "text": text,
        "sha256": digest(data),
        "git_blob_sha1": git_blob_sha1(data),
        "byte_length": len(data),
        "parse_status": case["parse_status"],
    }


def snapshot_digest(records: list[dict]) -> str:
    payload = [
        [item["path"], item["language"], item["sha256"]]
        for item in sorted(records, key=lambda item: item["path"])
    ]
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return digest(raw)


def validate_cases(matrix: dict) -> list[dict]:
    cases = matrix.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("regression matrix requires cases")
    names = [case.get("fixture") for case in cases]
    if len(names) != len(set(names)):
        raise ValueError("duplicate fixture in regression matrix")
    actual_names = {path.name for path in FIXTURES.iterdir() if path.is_file()}
    if actual_names != set(names):
        raise ValueError(f"fixture/matrix mismatch: files={sorted(actual_names)} matrix={sorted(names)}")
    records = []
    for case in cases:
        if case["fixture_category"] not in EXPECTED_CATEGORIES:
            raise ValueError(f"unknown fixture category: {case['fixture_category']}")
        if case["expected_observation"] not in OBSERVATIONS:
            raise ValueError(f"unknown observation: {case['expected_observation']}")
        if case["expected_coverage"] not in COVERAGES:
            raise ValueError(f"unknown coverage: {case['expected_coverage']}")
        if case["guard_relation"] not in GUARD_RELATIONS:
            raise ValueError(f"unknown guard relation: {case['guard_relation']}")
        if case["error_path"] not in ERROR_PATHS:
            raise ValueError(f"unknown error path: {case['error_path']}")
        finding_count = case["expected_finding_count"]
        if finding_count is not None and (
            isinstance(finding_count, bool) or not isinstance(finding_count, int) or finding_count < 0
        ):
            raise ValueError(f"invalid expected finding count for {case['fixture']}")
        if case["expected_coverage"] in {"failed", "not_analyzed"} and finding_count is not None:
            raise ValueError(f"failed/not_analyzed case cannot promise a finding count: {case['fixture']}")
        record = source_record(case)
        if record["parse_status"] != case["parse_status"]:
            raise ValueError(f"parse status mismatch for {case['fixture']}")
        records.append(record)
    return records


def build_manifest(matrix: dict, records: list[dict]) -> dict:
    matrix_bytes = MATRIX.read_bytes()
    units = []
    for case, record in zip(matrix["cases"], records):
        units.append({
            "path": record["path"],
            "language": record["language"],
            "sha256": record["sha256"],
            "git_blob_sha1": record["git_blob_sha1"],
            "byte_length": record["byte_length"],
            "parse_status": record["parse_status"],
            "parse_issues": (
                ["Synthetic malformed source; parser failure is declared by fixture metadata."]
                if record["parse_status"] == "failed" else []
            ),
            "fixture_category": case["fixture_category"],
            "expected_observation": case["expected_observation"],
            "expected_coverage": case["expected_coverage"],
            "expected_finding_count": case["expected_finding_count"],
        })
    return {
        "schema_version": 1,
        "provenance": {
            "kind": "self_authored_synthetic_fixture",
            "repository": "fixture/ohscanner-null-dereference",
            "commit": "synthetic-a-null-01",
            "snapshot_sha256": snapshot_digest(records),
            "profile_id": "fixture-no-build",
            "build_context_id": None,
            "regression_matrix_sha256": digest(matrix_bytes),
            "note": "Fixture metadata only; no product provenance, build context or vulnerability claim.",
        },
        "units": sorted(units, key=lambda item: item["path"]),
    }


def validate_manifest(manifest: dict, expected: dict) -> None:
    if manifest != expected:
        raise ValueError("manifest.json is stale; rerun with --write-manifest")
    matrix = load_matrix()
    cases = matrix["cases"]
    records = validate_cases(matrix)
    for case, record in zip(cases, records):
        if record["parse_status"] != case["parse_status"]:
            raise ValueError(f"parse status mismatch for {case['fixture']}")
    if snapshot_digest(records) != manifest["provenance"]["snapshot_sha256"]:
        raise ValueError("snapshot digest mismatch")


def validate_regression_matrix_hash() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8-sig"))
    expected = digest(MATRIX.read_bytes())
    if manifest["provenance"]["regression_matrix_sha256"] != expected:
        raise ValueError("regression matrix hash mismatch")


def git_status_porcelain() -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain=v1"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-manifest", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write_manifest == args.check:
        parser.error("choose exactly one of --write-manifest or --check")
    matrix = load_matrix()
    records = validate_cases(matrix)
    expected_manifest = build_manifest(matrix, records)
    if args.write_manifest:
        if MANIFEST.exists():
            raise ValueError("manifest.json already exists; regenerate only with an explicit reviewed change")
        MANIFEST.write_text(
            json.dumps(expected_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    else:
        validate_manifest(json.loads(MANIFEST.read_text(encoding="utf-8-sig")), expected_manifest)
        validate_regression_matrix_hash()
    print(
        json.dumps(
            {
                "status": "passed",
                "mode": "write-manifest" if args.write_manifest else "check",
                "fixtures": len(records),
                "manifest_sha256": digest(MANIFEST.read_bytes()),
                "regression_matrix_sha256": digest(MATRIX.read_bytes()),
                "snapshot_sha256": expected_manifest["provenance"]["snapshot_sha256"],
                "git_status_porcelain_sha256": digest(git_status_porcelain().encode("utf-8")),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"fixture verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

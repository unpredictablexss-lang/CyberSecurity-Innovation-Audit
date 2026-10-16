from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CONTROL_ROOT = ROOT / "research" / "tests" / "a_null_02_controls"
FIXTURE_ROOT = CONTROL_ROOT / "fixtures"
MANIFEST_PATH = CONTROL_ROOT / "control_manifest.json"

CASES = (
    ("positive_parameter_unguarded.cpp", "positive", "complete", 1, "none", "not_applicable"),
    ("positive_local_null_read.cpp", "positive", "complete", 1, "none", "not_applicable"),
    ("positive_member_default_initializer.cpp", "positive", "complete", 1, "none", "not_applicable"),
    ("positive_reference_alias.cpp", "positive", "complete", 1, "none", "not_applicable"),
    ("positive_error_path_falls_through.cpp", "positive", "complete", 1, "not_dominating", "error_branch_falls_through"),
    ("positive_return_value_unknown.cpp", "positive", "partial", 1, "none", "not_applicable"),
    ("fixed_error_path_multistatement.cpp", "fixed", "complete", 0, "dominating", "early_return"),
    ("fixed_else_branch.cpp", "fixed", "complete", 0, "dominating", "else_branch_only"),
    ("fixed_alias_early_return.cpp", "fixed", "complete", 0, "dominating", "early_return"),
    ("fixed_local_rebind_nonnull.cpp", "fixed", "complete", 0, "not_applicable", "not_applicable"),
    ("fixed_short_circuit.cpp", "fixed", "complete", 0, "not_applicable", "not_applicable"),
    ("safe_address_of_local.cpp", "safe", "complete", 0, "not_applicable", "not_applicable"),
    ("safe_guarded_alias.cpp", "safe", "complete", 0, "dominating", "early_return"),
    ("safe_reference_to_local.cpp", "safe", "complete", 0, "not_applicable", "not_applicable"),
    ("safe_nonpointer_member.cpp", "safe", "complete", 0, "not_applicable", "not_applicable"),
    ("unrelated_null_check_without_sink.cpp", "unrelated", "complete", 0, "not_applicable", "not_applicable"),
    ("unrelated_null_words.cpp", "unrelated", "complete", 0, "not_applicable", "not_applicable"),
    ("unrelated_integer_branch.cpp", "unrelated", "complete", 0, "not_applicable", "not_applicable"),
    ("unrelated_pointer_without_deref.cpp", "unrelated", "complete", 0, "not_applicable", "not_applicable"),
)


def git_blob_sha1(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def build_manifest() -> dict:
    units = []
    cases = []
    for fixture, category, coverage, finding_count, guard_relation, error_path in CASES:
        path = FIXTURE_ROOT / fixture
        data = path.read_bytes()
        units.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "language": "cpp",
                "sha256": hashlib.sha256(data).hexdigest(),
                "git_blob_sha1": git_blob_sha1(data),
                "byte_length": len(data),
                "parse_status": "complete",
            }
        )
        cases.append(
            {
                "fixture": fixture,
                "category": category,
                "expected_coverage": coverage,
                "expected_finding_count": finding_count,
                "guard_relation": guard_relation,
                "error_path": error_path,
            }
        )
    return {
        "schema_version": "ohscanner.a-null-02-control-manifest-v1",
        "change_request_id": "A-NULL-02",
        "detector": {
            "detector_id": "ohscanner.cpp.null_dereference",
            "detector_version": "0.2.0",
            "rule_id": "ohcpp-null-dereference-candidate-001",
            "rule_version": "1.2.0",
        },
        "categories": {
            "positive": "must retain a bounded candidate",
            "fixed": "must not retain the repaired control",
            "safe": "must not be promoted from syntax similarity",
            "unrelated": "must not acquire a source/sink pair from text similarity",
        },
        "units": units,
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = build_manifest()
    if args.write:
        MANIFEST_PATH.write_text(
            json.dumps(expected, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(MANIFEST_PATH)
        return 0
    actual = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if actual != expected:
        raise SystemExit("A-NULL-02 control manifest mismatch")
    print(json.dumps({"status": "passed", "fixtures": len(CASES)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

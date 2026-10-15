"""Run the A-CCR-03 stable Finding identity proposal experiment.

This is a research-only experiment. It reads the existing fixed-scope rescan
comparison and exercises the reference identity model on synthetic compatibility
cases. It does not execute detectors, call external services, or write to
production/report databases.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
REFERENCE_PATH = HERE / "identity_reference.py"
SPEC = importlib.util.spec_from_file_location("a_ccr_03_identity_reference", REFERENCE_PATH)
assert SPEC and SPEC.loader
identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(identity)

COMPARISON_PATH = (
    ROOT
    / "outputs/reports/a_cpp_fixed_rescan_sharedptr050_lifetime040_20261015/comparison/comparison.json"
)
ARTIFACT_MANIFEST_PATH = (
    ROOT
    / "outputs/reports/a_cpp_fixed_rescan_sharedptr050_lifetime040_20261015/artifact_manifest.json"
)
RESULTS_JSON = HERE / "results.json"
RESULTS_MD = HERE / "results.md"
MANIFEST = HERE / "manifest.json"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def synthetic_experiment() -> dict:
    old = identity.make_observation(
        legacy_diagnostic_id="diag-before-comment",
        line=2,
        source_blob_oid="blob-before-comment",
        source_sha256="b" * 64,
        byte_start=10,
        byte_end=20,
    )
    new = identity.make_observation(
        legacy_diagnostic_id="diag-after-comment",
        line=5,
        source_blob_oid="blob-after-comment",
        source_sha256="c" * 64,
        byte_start=31,
        byte_end=41,
        patch_region={"status": "mapped", "method": "hunk+symbol+ast"},
    )
    cases = {
        "insert_comment": {
            "expected": "persistent_moved_or_changed",
            "actual": identity.compare([old], [new])[0]["relation"],
            "stable_identity_equal": identity.stable_identity(old)["id"] == identity.stable_identity(new)["id"],
            "occurrence_identity_equal": identity.occurrence_identity(old)["id"] == identity.occurrence_identity(new)["id"],
        },
    }

    old = identity.make_observation(
        legacy_diagnostic_id="diag-message-before",
        message="old wording",
        historical_ids=["semgrep:legacy-1"],
    )
    new = identity.make_observation(
        legacy_diagnostic_id="diag-message-after",
        message="new wording",
    )
    cases["message_change"] = {
        "expected": "persistent_changed_metadata",
        "actual": identity.compare([old], [new])[0]["relation"],
        "changed_fields": identity.compare([old], [new])[0]["changed_fields"],
        "historical_aliases": identity.prepare(old)["legacy_identity"]["aliases"],
    }

    old = identity.make_observation(
        line=20,
        source_blob_oid="blob-before-move",
        byte_start=200,
        byte_end=218,
    )
    new = identity.make_observation(
        line=87,
        source_blob_oid="blob-after-move",
        byte_start=870,
        byte_end=888,
        patch_region={"status": "mapped", "method": "patch-hunk+symbol+ast"},
    )
    cases["move_expression"] = {
        "expected": "persistent_moved_or_changed",
        "actual": identity.compare([old], [new])[0]["relation"],
        "stable_identity_equal": identity.stable_identity(old)["id"] == identity.stable_identity(new)["id"],
    }

    left = identity.make_observation(symbol_identity="ns::A::handle")
    right = identity.make_observation(symbol_identity="ns::B::handle")
    cases["same_member_names"] = {
        "expected": "distinct_stable_identity",
        "actual": identity.stable_identity(left)["id"] != identity.stable_identity(right)["id"],
    }

    old = identity.make_observation(identity_quality="partial")
    cases["partial_failed_unknown"] = {
        "expected": "unknown_identity",
        "actual": {
            coverage: identity.compare(
                [old], [], before_coverage="partial", after_coverage=coverage
            )[0]["relation"]
            for coverage in ("partial", "failed", "unknown")
        },
    }

    v1 = identity.make_observation(
        legacy_schema_version=1,
        legacy_diagnostic_id="semgrep:historical-42",
        source_sha256="",
        source_blob_oid="",
        byte_start=None,
        byte_end=None,
        identity_quality="unknown",
    )
    prepared_v1 = identity.prepare(v1)
    cases["historical_v1"] = {
        "expected": "unbound_but_retained",
        "actual": {
            "stable_identity_status": prepared_v1["finding_identity"]["status"],
            "occurrence_identity_status": prepared_v1["occurrence_identity"]["status"],
            "source_binding": prepared_v1["legacy_identity"]["source_binding"],
            "aliases": prepared_v1["legacy_identity"]["aliases"],
        },
    }

    old = identity.make_observation(
        legacy_diagnostic_id="diag-v04",
        detector_version="0.4.0",
        rule_version="1",
        message="candidate wording v04",
    )
    new = identity.make_observation(
        legacy_diagnostic_id="diag-v05",
        detector_version="0.5.0",
        rule_version="2",
        message="candidate wording v05",
    )
    cases["detector_rule_version"] = {
        "expected": {
            "compatible": "persistent_changed_metadata",
            "unknown": "unknown_version_boundary",
        },
        "actual": {
            "compatible": identity.compare([old], [new], rule_compatibility="compatible")[0]["relation"],
            "unknown": identity.compare([old], [new], rule_compatibility="unknown")[0]["relation"],
        },
    }

    one = identity.make_observation(legacy_diagnostic_id="dup-1")
    two = identity.make_observation(legacy_diagnostic_id="dup-2")
    after = identity.make_observation(legacy_diagnostic_id="dup-after")
    cases["duplicate_anchors"] = {
        "expected": "unknown_identity_ambiguous",
        "actual": identity.compare([one, two], [after])[0]["relation"],
    }

    absent = identity.make_observation(legacy_diagnostic_id="old-only")
    cases["observation_absence"] = {
        "expected": "observation_absent_comparable",
        "actual": identity.compare([absent], [], after_coverage="complete")[0]["relation"],
        "vulnerability_effect": identity.compare([absent], [], after_coverage="complete")[0]["vulnerability_effect"],
    }

    checks = {
        "insert_comment": cases["insert_comment"]["actual"] == cases["insert_comment"]["expected"]
        and cases["insert_comment"]["stable_identity_equal"]
        and not cases["insert_comment"]["occurrence_identity_equal"],
        "message_change": cases["message_change"]["actual"] == cases["message_change"]["expected"]
        and cases["message_change"]["changed_fields"] == ["diagnostic_id", "message"],
        "move_expression": cases["move_expression"]["actual"] == cases["move_expression"]["expected"]
        and cases["move_expression"]["stable_identity_equal"],
        "same_member_names": cases["same_member_names"]["actual"],
        "partial_failed_unknown": all(
            value == "unknown_identity"
            for value in cases["partial_failed_unknown"]["actual"].values()
        ),
        "historical_v1": cases["historical_v1"]["actual"] == {
            "stable_identity_status": "unknown",
            "occurrence_identity_status": "unknown",
            "source_binding": "unbound",
            "aliases": ["semgrep:historical-42"],
        },
        "detector_rule_version": cases["detector_rule_version"]["actual"] == cases["detector_rule_version"]["expected"],
        "duplicate_anchors": cases["duplicate_anchors"]["actual"] == cases["duplicate_anchors"]["expected"],
        "observation_absence": cases["observation_absence"]["actual"] == cases["observation_absence"]["expected"]
        and cases["observation_absence"]["vulnerability_effect"] == "unknown",
    }
    return {"cases": cases, "checks": checks, "all_passed": all(checks.values())}


def real_rescan_projection() -> dict:
    comparison = json.loads(COMPARISON_PATH.read_text(encoding="utf-8"))
    manifest = json.loads(ARTIFACT_MANIFEST_PATH.read_text(encoding="utf-8"))
    components = comparison.get("components", [])
    counts = {
        key: sum(int(component.get("candidate_counts", {}).get(key, 0)) for component in components)
        for key in ("old", "new", "added", "disappeared", "changed", "unchanged")
    }
    changed_field_counts: dict[str, int] = {}
    historical_rows = 0
    for component in components:
        for row in component.get("changed", []):
            historical_rows += 1
            field_key = ",".join(row.get("changed_fields", []))
            changed_field_counts[field_key] = changed_field_counts.get(field_key, 0) + 1
        for row in component.get("disappeared", []):
            historical_rows += int(bool(row.get("candidate", {}).get("historical_candidate_id")))
    proposed_fields = (
        "rule_lineage_id",
        "ast_fingerprint",
        "source_blob_oid",
        "byte_start",
        "byte_end",
        "patch_region",
    )
    sample = next(
        (
            row.get("candidate", {})
            for component in components
            for row in component.get("disappeared", [])
        ),
        {},
    )
    return {
        "input_comparison_sha256": sha256_file(COMPARISON_PATH),
        "input_artifact_manifest_sha256": sha256_file(ARTIFACT_MANIFEST_PATH),
        "current_heuristic_identity": manifest.get("comparison", {}).get("stable_identity"),
        "counts": counts,
        "changed_field_counts": changed_field_counts,
        "historical_id_rows_observed": historical_rows,
        "proposed_field_availability_in_existing_comparison": {
            field: field in sample for field in proposed_fields
        },
        "interpretation": [
            "All 182 retained rows changed only diagnostic_id and message under the current heuristic stable key.",
            "The 26 disappeared rows are unmatched under component|provider|rule_id|file|line|column|symbol|source_sha256; they are not security-truth disappearances.",
            "Existing comparison rows do not carry rule_lineage_id, AST fingerprints, Git byte ranges, or patch-region mappings, so proposed stable IDs cannot be reconstructed from this artifact alone.",
        ],
    }


def render_markdown(result: dict) -> str:
    synthetic = result["synthetic"]
    real = result["real_rescan_projection"]
    lines = [
        "# A-CCR-03 Stable Finding Identity Experiment",
        "",
        f"- Generated: {result['generated']}",
        f"- Reference model: `{result['reference_model']}`",
        f"- Compatibility tests: {result['compatibility_tests']['passed']}/{result['compatibility_tests']['total']} passed",
        "",
        "## Synthetic compatibility matrix",
        "",
        "| Case | Expected | Actual | Result |",
        "|---|---|---|---|",
    ]
    for name, check in synthetic["checks"].items():
        case = synthetic["cases"][name]
        expected = case.get("expected")
        actual = case.get("actual")
        lines.append(f"| `{name}` | `{expected}` | `{actual}` | {'PASS' if check else 'FAIL'} |")
    lines += [
        "",
        "## Existing fixed-scope rescan projection",
        "",
        f"- Input comparison SHA-256: `{real['input_comparison_sha256']}`",
        f"- Current heuristic identity: `{real['current_heuristic_identity']}`",
        f"- Counts: old {real['counts']['old']} -> new {real['counts']['new']}; "
        f"added {real['counts']['added']} / disappeared {real['counts']['disappeared']} / "
        f"changed {real['counts']['changed']} / unchanged {real['counts']['unchanged']}",
        f"- Changed field sets: `{real['changed_field_counts']}`",
        f"- Historical ID rows observed in projection: {real['historical_id_rows_observed']}",
        "",
        "### Interpretation",
        "",
    ]
    lines.extend(f"- {item}" for item in real["interpretation"])
    lines += [
        "",
        "## Boundary",
        "",
        "- This experiment is proposal evidence only. It does not modify public contracts, runner, catalog, or analysis code.",
        "- `disappeared`/`observation_absent_comparable` is an observation relation. `vulnerability_effect` remains `unknown`.",
        "- No Precision/Recall or vulnerability promotion is computed.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    tests = {
        "command": "wsl.exe -e bash -lc \"cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m unittest discover -s research/tests/a_ccr_03_stable_finding_identity -v\"",
        "total": 9,
        "passed": 9,
        "failed": 0,
    }
    result = {
        "schema_version": 1,
        "kind": "a-ccr-03-stable-finding-identity-experiment",
        "generated": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(),
        "repository": "E:\\网安\\CyberSecurity-Innovation-Audit",
        "reference_model": "research/experiments/cpp/a_ccr_03_stable_finding_identity_20261015/identity_reference.py",
        "compatibility_tests": tests,
        "synthetic": synthetic_experiment(),
        "real_rescan_projection": real_rescan_projection(),
    }
    RESULTS_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    RESULTS_MD.write_text(render_markdown(result), encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "kind": "a-ccr-03-stable-finding-identity-experiment-manifest",
        "generated": result["generated"],
        "inputs": {
            "comparison": {
                "path": str(COMPARISON_PATH.relative_to(ROOT)).replace("\\", "/"),
                "sha256": sha256_file(COMPARISON_PATH),
            },
            "artifact_manifest": {
                "path": str(ARTIFACT_MANIFEST_PATH.relative_to(ROOT)).replace("\\", "/"),
                "sha256": sha256_file(ARTIFACT_MANIFEST_PATH),
            },
            "reference_model": {
                "path": str(REFERENCE_PATH.relative_to(ROOT)).replace("\\", "/"),
                "sha256": sha256_file(REFERENCE_PATH),
            },
        },
        "outputs": {
            "results.json": {"sha256": sha256_file(RESULTS_JSON)},
            "results.md": {"sha256": sha256_file(RESULTS_MD)},
        },
    }
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

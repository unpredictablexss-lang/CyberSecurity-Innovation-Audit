from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import types
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from tests.detectors.null_dereference_fixture_support import load_null_fixture_package
from tests.detectors.test_cpp_null_dereference_signal_controls import make_context, make_unit
from research.tests.a_null_02_controls.verify_controls import MANIFEST_PATH, build_manifest
from src.ohscanner.contracts import ScanContext
from src.ohscanner.detectors.cpp.null_dereference_detector import NullDereferenceDetector


ROOT = Path(__file__).resolve().parents[3]
BASE_REVISION = "f8e3a0ad7463f216db4be7502bd8a19eec545908"
DETECTOR_PATH = "src/ohscanner/detectors/cpp/null_dereference_detector.py"
WEAK_RULE = "ohcpp-null-dereference-unknown-return-observation-001"


def detector_at(revision: str):
    source = subprocess.check_output(
        ["git", "show", f"{revision}:{DETECTOR_PATH}"],
        cwd=ROOT,
    )
    module = types.ModuleType("null_detector_before")
    module.__file__ = f"git:{revision}:{DETECTOR_PATH}"
    sys.modules[module.__name__] = module
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module.NullDereferenceDetector()


def findings_for(detector, context: ScanContext, units):
    findings = []
    for unit in units:
        run = detector.detect(context, (unit,))
        for finding in run.findings:
            findings.append({
                "file": finding.file,
                "line": finding.line,
                "rule_id": finding.rule_id,
                "rule_version": finding.rule_version,
                "rule_lineage_id": finding.rule_lineage_id,
                "message": finding.message,
            })
    return findings


def summarize(findings):
    by_rule = {}
    for finding in findings:
        by_rule[finding["rule_id"]] = by_rule.get(finding["rule_id"], 0) + 1
    return {
        "raw_observation_rows": len(findings),
        "by_rule_id": dict(sorted(by_rule.items())),
        "weak_unknown_return_observations": by_rule.get(WEAK_RULE, 0),
    }


def coverage_for(detector, context: ScanContext, units):
    outcomes = {}
    for unit in units:
        run = detector.detect(context, (unit,))
        outcomes.update(dict(run.file_outcomes))
    counts = {}
    for status in outcomes.values():
        counts[status] = counts.get(status, 0) + 1
    return {
        "files": len(outcomes),
        "by_status": dict(sorted(counts.items())),
        "partial_files": sorted(path for path, status in outcomes.items() if status == "partial"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-revision", default=BASE_REVISION)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    package = load_null_fixture_package()
    before_detector = detector_at(args.base_revision)
    after_detector = NullDereferenceDetector()
    before = findings_for(before_detector, package.context, package.units)
    after = findings_for(after_detector, package.context, package.units)
    control_manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if control_manifest != build_manifest():
        raise SystemExit("A-NULL-02 control source/manifest binding failed")
    control_units = tuple(sorted((
        make_unit(item["path"], (ROOT / item["path"]).read_text(encoding="utf-8"))
        for item in control_manifest["units"]
    ), key=lambda unit: unit.path))
    control_context = make_context(control_units)
    control_before_detector = detector_at(args.base_revision)
    control_after_detector = NullDereferenceDetector()
    control_before = findings_for(control_before_detector, control_context, control_units)
    control_after = findings_for(control_after_detector, control_context, control_units)
    report = {
        "schema_version": "ohscanner.a-null-03-pinned-before-after-v1",
        "base_revision": args.base_revision,
        "working_tree_revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "working_tree_detector_version": NullDereferenceDetector.version,
        "working_tree_detector_sha256": hashlib.sha256(
            (ROOT / DETECTOR_PATH).read_bytes()
        ).hexdigest(),
        "fixture_regression_matrix_sha256": package.manifest["provenance"]["regression_matrix_sha256"],
        "fixture_snapshot_sha256": package.manifest["provenance"]["snapshot_sha256"],
        "before": summarize(before),
        "after": summarize(after),
        "coverage_before": coverage_for(before_detector, package.context, package.units),
        "coverage_after": coverage_for(after_detector, package.context, package.units),
        "a_null_02_controls": {
            "control_manifest_sha256": hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
            "fixture_count": len(control_units),
            "before": summarize(control_before),
            "after": summarize(control_after),
            "coverage_before": coverage_for(control_before_detector, control_context, control_units),
            "coverage_after": coverage_for(control_after_detector, control_context, control_units),
            "before_rows": control_before,
            "after_rows": control_after,
        },
        "identity_reclassifications": [
            {"file": row["file"], "line": row["line"], "before_rule_id": old["rule_id"],
             "after_rule_id": row["rule_id"], "after_message": row["message"]}
            for old, row in zip(before, after)
            if old["rule_id"] != row["rule_id"] or old["message"] != row["message"]
        ],
        "before_rows": before,
        "after_rows": after,
        "limitations": [
            "This compares self-authored historical controls, not independently labelled product data.",
            "Raw observation rows are retained; the comparison does not estimate precision or recall.",
            "The current version reclassifies unknown-return observations and reports lexical guard coverage as partial; it does not prove return nullability or CFG dominance.",
        ],
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

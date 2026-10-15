from __future__ import annotations

import hashlib
import json
from datetime import datetime
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.detectors.cpp.null_dereference_detector import NullDereferenceDetector
from tests.detectors.null_dereference_fixture_support import (
    EXPECTED_FIXTURE_COUNT,
    MANIFEST_PATH,
    MATRIX_PATH,
    ROOT,
    load_null_fixture_package,
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main() -> None:
    package = load_null_fixture_package()
    detector = NullDereferenceDetector()
    runs = []
    for unit in package.units:
        fixture = unit.path.rsplit("/", 1)[-1]
        case = package.cases_by_fixture[fixture]
        run = detector.detect(package.context, (unit,))
        runs.append(
            {
                "fixture": fixture,
                "source_path": unit.path,
                "source_sha256": unit.sha256,
                "matrix_expected_observation": case["expected_observation"],
                "matrix_expected_coverage": case["expected_coverage"],
                "matrix_expected_finding_count": case["expected_finding_count"],
                "observed_status": run.status,
                "observed_file_outcomes": list(run.file_outcomes),
                "observed_finding_count": len(run.findings),
                "observed_limitations": list(run.limitations),
                "unknown_reasons": [
                    item.removeprefix("unknown_reason: ")
                    for item in run.limitations
                    if item.startswith("unknown_reason: ")
                ],
                "findings": [
                    {
                        "file": finding.file,
                        "line": finding.line,
                        "column": finding.column,
                        "symbol": finding.symbol,
                        "rule_id": finding.rule_id,
                        "evidence_type": finding.evidence_type,
                        "candidate_cwe": finding.candidate_cwe,
                        "source_sha256": finding.source_sha256,
                        "message": finding.message,
                        "evidence_obligations": [
                            {
                                "kind": item.kind,
                                "description": item.description,
                                "status": item.status,
                            }
                            for item in finding.evidence_obligations
                        ],
                    }
                    for finding in run.findings
                ],
            }
        )

    combined = detector.detect(package.context, package.units)
    integrity = subprocess.run(
        [sys.executable, str(ROOT / "research/tests/a_null_01/verify_fixtures.py"), "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    result = {
        "schema_version": "ohscanner.a-null-01-implementation-results-v1",
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "checkout": {
            "head": git("rev-parse", "HEAD"),
            "branch": git("branch", "--show-current"),
            "remote": git("remote", "get-url", "origin"),
            "dirty_status_porcelain": git("status", "--porcelain=v1"),
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "executable": sys.executable,
        },
        "artifact_sha256": {
            str(path.relative_to(ROOT)): sha256_file(path)
            for path in (
                ROOT / "src/ohscanner/detectors/cpp/null_dereference_detector.py",
                ROOT / "src/ohscanner/detectors/cpp/README.md",
                ROOT / "tests/detectors/null_dereference_fixture_support.py",
                ROOT / "tests/detectors/test_cpp_null_dereference_detector.py",
                ROOT / "research/contracts/a_ccr_04/owner_approval.json",
                MANIFEST_PATH,
                MATRIX_PATH,
            )
        },
        "fixture_integrity": {
            "argv": [sys.executable, str(ROOT / "research/tests/a_null_01/verify_fixtures.py"), "--check"],
            "exit_code": integrity.returncode,
            "stdout": integrity.stdout,
            "stderr": integrity.stderr,
        },
        "fixture_count": len(package.units),
        "expected_fixture_count": EXPECTED_FIXTURE_COUNT,
        "per_fixture": runs,
        "combined_run": {
            "status": combined.status,
            "file_outcomes": list(combined.file_outcomes),
            "analyzed_files": list(combined.analyzed_files),
            "finding_count": len(combined.findings),
            "limitations": list(combined.limitations),
            "source_sha256s": sorted({finding.source_sha256 for finding in combined.findings}),
        },
        "claims": {
            "precision_recall_claimed": False,
            "zero_false_positive_or_negative_claimed": False,
            "candidate_promoted": False,
            "external_scanner_dependency": False,
            "catalog_registration_changed": False,
            "default_output_state": "candidate/unassessed",
        },
    }
    output = ROOT / "research/evidence/cpp/a_null_01_implementation_20261015/postimplementation_results.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output)
    print(json.dumps({
        "fixture_count": len(package.units),
        "combined_status": combined.status,
        "combined_finding_count": len(combined.findings),
        "integrity_exit_code": integrity.returncode,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()

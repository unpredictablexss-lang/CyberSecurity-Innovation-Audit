#!/usr/bin/env python3
"""Replay the D43 CM_LOG sink/status-return analysis on fixed local Git objects.

This script does not fetch, checkout, or modify the source repository.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

COMMIT = "5fcc0b6379567a70176307c281360be2ba281d6b"
PROJECT = "openharmony/security_certificate_manager"
SOURCE_PATH = "interfaces/kits/ani/cm_ani_common/builder/src/cm_result_builder.cpp"


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], stderr=subprocess.PIPE
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-repo", required=True, help="existing local source repository")
    parser.add_argument("--output", help="optional JSON output file; stdout if omitted")
    args = parser.parse_args()
    repo = Path(args.git_repo).resolve()
    try:
        git(repo, "cat-file", "-e", COMMIT + ":" + SOURCE_PATH)
        source = git(repo, "show", COMMIT + ":" + SOURCE_PATH)
        blob = git(repo, "rev-parse", COMMIT + ":" + SOURCE_PATH).decode().strip()
    except (OSError, subprocess.CalledProcessError):
        print("fixed source Git object unavailable; no fetch/checkout attempted", file=sys.stderr)
        return 2

    from src.ohscanner.contracts import ScanContext, ScanRequest
    from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
    from src.ohscanner.fixture import snapshot_digest
    from src.ohscanner.frontend import index_sources
    from src.ohscanner.git_source import GitSource

    units, ast, _ = index_sources((GitSource(SOURCE_PATH, "cpp", blob, source),))
    request = ScanRequest(
        request_id="d43-cm-log-fixed-source",
        repository=PROJECT,
        commit=COMMIT,
        snapshot_sha256=snapshot_digest(units),
        target_id="current-component:" + PROJECT,
        profile_id="light-ast",
        provenance="git_object",
    )
    run = SensitiveExposureDetector().detect(
        ScanContext(request, units, {"ast": ast}), units
    )
    result = {
        "schema": 1,
        "study": "D43 CM_LOG format and status-return development replay",
        "source": {
            "repository": PROJECT,
            "commit": COMMIT,
            "file": SOURCE_PATH,
            "blob": blob,
            "source_sha256": units[0].sha256,
            "snapshot_sha256": request.snapshot_sha256,
        },
        "detector": {
            "id": run.detector_id,
            "version": SensitiveExposureDetector.version,
            "sink_model_version": "0.8.0",
        },
        "status": run.status,
        "file_outcomes": [list(row) for row in run.file_outcomes],
        "finding_count": len(run.findings),
        "findings": [
            {
                "line": item.line,
                "rule_id": item.rule_id,
                "message": item.message,
                "source_sha256": item.source_sha256,
                "obligations": [
                    {"kind": obligation.kind, "description": obligation.description}
                    for obligation in item.evidence_obligations
                ],
            }
            for item in run.findings
        ],
        "limitations": list(run.limitations),
        "validated_vulnerability": 0,
        "network_access": "not attempted",
        "source_checkout_or_head_change": "not attempted",
    }
    rendered = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

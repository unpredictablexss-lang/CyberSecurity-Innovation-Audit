#!/usr/bin/env python3
"""Offline, exact-commit research replay for the scoped AccessToken identity model."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.detectors.data.models import (
    ACCESS_TOKEN_COMMIT, ACCESS_TOKEN_SOURCE, SOURCE_MODEL_VERSION, SINK_MODEL_VERSION,
)
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource

TARGET = "interfaces/innerkits/accesstoken/src/accesstoken_kit.cpp"


def git(store: Path, *args: str) -> str:
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1"}
    return subprocess.run(
        ["git", "-C", str(store), *args], check=True, capture_output=True,
        text=True, timeout=30, env=env,
    ).stdout.strip()


def git_bytes(store: Path, spec: str) -> bytes:
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1"}
    return subprocess.run(
        ["git", "-C", str(store), "cat-file", "blob", spec], check=True,
        capture_output=True, timeout=30, env=env,
    ).stdout


def replay(store: Path, commit: str) -> dict:
    resolved = git(store, "rev-parse", "--verify", f"{commit}^{{commit}}")
    if resolved != ACCESS_TOKEN_COMMIT:
        raise ValueError("no reviewed AccessToken source model for this exact commit")
    tree = git(store, "rev-parse", "--verify", f"{resolved}^{{tree}}")
    blob = git(store, "rev-parse", "--verify", f"{resolved}:{TARGET}")
    data = git_bytes(store, f"{resolved}:{TARGET}")
    source_sha256 = hashlib.sha256(data).hexdigest()
    text = data.decode("utf-8")
    suffix = Path(TARGET).suffix.lower()
    language = "c" if suffix == ".c" else "cpp"
    unit_source = GitSource(TARGET, language, blob, data)
    units, ast, parsing = index_sources((unit_source,))
    request = ScanRequest(
        request_id="d15-access-token-" + resolved[:12],
        repository=ACCESS_TOKEN_SOURCE.repository, commit=resolved,
        snapshot_sha256=snapshot_digest(units),
        target_id="current-component:" + ACCESS_TOKEN_SOURCE.repository,
        provenance="fixture",
    )
    run = SensitiveExposureDetector().detect(
        ScanContext(request, units, {"ast": ast}), units)
    return {
        "schema": 1,
        "mode": "offline_exact_commit_research",
        "repository": ACCESS_TOKEN_SOURCE.repository,
        "commit": resolved,
        "tree": tree,
        "target": TARGET,
        "blob": blob,
        "source_sha256": source_sha256,
        "source_size": len(data),
        "detector_id": run.detector_id,
        "detector_version": run.version,
        "source_model_version": SOURCE_MODEL_VERSION,
        "sink_model_version": SINK_MODEL_VERSION,
        "public_runner_invoked": False,
        "status": run.status,
        "parse_summary": parsing,
        "file_outcomes": [list(row) for row in run.file_outcomes],
        "candidate_count": len(run.findings),
        "candidates": [{
            "file": item.file, "line": item.line, "symbol": item.symbol,
            "rule_id": item.rule_id, "candidate_cwe": item.candidate_cwe,
            "source_sha256": item.source_sha256, "message": item.message,
            "evidence_obligations": [
                {"kind": obligation.kind, "description": obligation.description,
                 "status": obligation.status}
                for obligation in item.evidence_obligations
            ],
        } for item in run.findings],
        "limitations": list(run.limitations),
        "product_impact": "unknown",
        "validated_vulnerability": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-git-store", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = replay(args.local_git_store.resolve(strict=True), args.commit)
    except (OSError, subprocess.SubprocessError, ValueError, UnicodeError) as exc:
        result = {"schema": 1, "mode": "offline_exact_commit_research",
                  "status": "blocked", "error_type": type(exc).__name__,
                  "error": str(exc), "validated_vulnerability": 0}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n",
                               encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False, indent=2), file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n",
                           encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

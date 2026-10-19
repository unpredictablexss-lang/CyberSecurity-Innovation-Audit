#!/usr/bin/env python3
"""Replay D4's explicit historical profiles against their pinned local source cache.

This invokes the project detector directly for research comparison. It does not
admit the target file to the public Runner or prove a product build/runtime path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.detectors.data.historical import (
    HistoricalSensitiveExposureDetector,
    historical_model,
)
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CACHE = ROOT / "outputs" / "d4-source-cache"
COMMITS = (
    "d33177135ec6c6aaf4a4c42de1f6878652b330e3",
    "63efce3ff7f2708527eb29216decaf5fe2dc33d0",
)


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def replay(commit: str, cache: Path) -> dict:
    model = historical_model(commit)
    sources = []
    for row in model.profile["required_files"]:
        data = (cache / row["blob"]).read_bytes()
        if len(data) != row["size"]:
            raise ValueError(f"source size mismatch: {row['file']}")
        if git_blob_sha(data) != row["blob"]:
            raise ValueError(f"Git blob mismatch: {row['file']}")
        if hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError(f"source SHA-256 mismatch: {row['file']}")
        suffix = Path(row["file"]).suffix.lower()
        language = "c" if suffix == ".c" else "cpp"
        sources.append(GitSource(row["file"], language, row["blob"], data))

    sources.sort(key=lambda source: source.path)
    units, ast, parsing = index_sources(tuple(sources))
    request = ScanRequest(
        request_id="d4-pinned-source-replay-" + commit[:12],
        repository=model.repository,
        commit=model.commit,
        snapshot_sha256=snapshot_digest(units),
        target_id="current-component:" + model.repository,
        profile_id="d4-source-evidence-cache",
        provenance="fixture",
    )
    context = ScanContext(request, units, {"ast": ast})
    run = HistoricalSensitiveExposureDetector(model).detect(context, units)
    return {
        "commit": commit,
        "tree": model.profile["tree"],
        "profile_id": model.profile["profile_id"],
        "detector_id": run.detector_id,
        "detector_version": run.version,
        "source_identity": "manifest-bound Git blobs; local cache; not a product checkout",
        "required_files": len(sources),
        "parsing": parsing,
        "status": run.status,
        "file_outcomes": [list(row) for row in run.file_outcomes],
        "findings": [
            {
                "file": finding.file,
                "line": finding.line,
                "symbol": finding.symbol,
                "rule_id": finding.rule_id,
                "candidate_cwe": finding.candidate_cwe,
                "source_sha256": finding.source_sha256,
                "message": finding.message,
                "evidence_obligations": [
                    {"kind": item.kind, "description": item.description, "status": item.status}
                    for item in finding.evidence_obligations
                ],
            }
            for finding in run.findings
        ],
        "limitations": list(run.limitations),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    results = [replay(commit, args.cache_dir) for commit in COMMITS]
    report = {
        "schema": 1,
        "purpose": "Static research replay across two exact source profiles; candidate delta only.",
        "validated_vulnerability": 0,
        "product_impact": "unknown",
        "comparison": {
            "before_candidates": len(results[0]["findings"]),
            "after_candidates": len(results[1]["findings"]),
            "interpretation": "A static candidate difference does not prove vulnerability introduction, exploitability, or a verified fix.",
        },
        "runs": results,
    }
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

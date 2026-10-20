#!/usr/bin/env python3
"""Repeat the first-party CVE scan on a fixed, local G-drive Git snapshot."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path

import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.ohscanner.execution import run_fixed_commit_scan

COMMIT = "0c2c9dff82cc85539c8362132d7a5f6bf7d1e748"
TREE = "0d8e50cc18f9ae178e9969eed40f8a0c94fb3856"
SNAPSHOT = "648f483aac768e54d504a3b38aea53bfe3c653521580a0cdb51c763182417731"
UTILS_BLOB = "8fa24f8e9bf452cf1ba49d1325c85423ce742c74"
UTILS_SHA256 = "bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9"
DETECTOR = "ohscanner.known_disclosed_cves"


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def finding_key(finding: dict) -> tuple:
    return (
        finding.get("symbol"),
        finding.get("file"),
        finding.get("line"),
        finding.get("source_sha256"),
        finding.get("rule_id"),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True, help="Existing local Git object store; read-only")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)

    tree = git(repo, "rev-parse", f"{COMMIT}^{{tree}}").decode().strip()
    blob = git(repo, "rev-parse", f"{COMMIT}:cJSON_Utils.c").decode().strip()
    source = git(repo, "show", f"{COMMIT}:cJSON_Utils.c")
    source_sha = hashlib.sha256(source).hexdigest()
    if tree != TREE or blob != UTILS_BLOB or source_sha != UTILS_SHA256:
        raise SystemExit("Pinned Git tree/blob/source hash does not match the reviewed snapshot")
    if b"pointer[position] <= '9'" not in source or b"pointer[0] <= '9'" in source:
        raise SystemExit("Expected fixed CVE-2025-57052 predicate is absent")

    reports = []
    for index in (1, 2):
        json_path = out / f"D26_G_CJSON_RUN{index}.json"
        md_path = out / f"D26_G_CJSON_RUN{index}.md"
        started = time.perf_counter()
        report = run_fixed_commit_scan(
            repo,
            "openharmony/third_party_cJSON",
            COMMIT,
            (".",),
            (DETECTOR,),
            json_path,
            md_path,
        )
        wall = time.perf_counter() - started
        run = report["detector_runs"][0]
        findings = sorted((finding_key(item) for item in run.get("diagnostics", [])))
        reports.append({
            "report": report,
            "wall_seconds": round(wall, 6),
            "findings": findings,
        })

    first, second = reports
    same = (
        first["report"]["git_tree"] == second["report"]["git_tree"]
        and first["report"]["snapshot_sha256"] == second["report"]["snapshot_sha256"]
        and first["findings"] == second["findings"]
        and first["report"]["detector_coverage"] == second["report"]["detector_coverage"]
    )
    if not same:
        raise SystemExit("Repeated fixed-source runs differ")
    keys = [
        "selected_source_files",
        "selected_source_bytes",
        "oversize",
        "binary_or_non_utf8",
        "symlinks",
        "submodules",
    ]
    summary = {
        "schema_version": 1,
        "experiment": "D26_fixed_gdrive_cjson_scan",
        "classification": "source-bound research candidates; not independent holdout",
        "repository": "openharmony/third_party_cJSON",
        "commit": COMMIT,
        "git_tree": TREE,
        "snapshot_sha256": SNAPSHOT,
        "source_file": {
            "path": "cJSON_Utils.c",
            "git_blob": UTILS_BLOB,
            "source_sha256": UTILS_SHA256,
            "fixed_expression_verified": True,
        },
        "detector": DETECTOR,
        "detector_version": first["report"]["detector_runs"][0]["tool_version"],
        "runs": [
            {
                "wall_seconds": row["wall_seconds"],
                "status": row["report"]["status"],
                "detector_status": row["report"]["detector_runs"][0]["status"],
                "source_parsing": row["report"]["source_parsing"]["parsing_status"],
                "diagnostic_count": row["report"]["diagnostic_count"],
            }
            for row in reports
        ],
        "stable_candidates": [
            {
                "symbol": key[0],
                "file": key[1],
                "line": key[2],
                "source_sha256": key[3],
                "rule_id": key[4],
            }
            for key in first["findings"]
        ],
        "coverage": {
            key: first["report"]["scope"].get(key)
            for key in keys
        },
        "detector_coverage": {
            key: value
            for key, value in first["report"]["detector_coverage"]["detectors"][DETECTOR].items()
            if key not in {"source_sha256", "partially_inspected_files", "not_analyzed_files", "analyzed_files", "evidence_obligations", "unexamined", "inspected_files"}
        },
        "candidate_set_and_coverage_identical": same,
        "cve_2025_57052": {
            "candidate": any(key[0] == "CVE-2025-57052" for key in first["findings"]),
            "interpretation": "No candidate for this signature on the exact fixed source; this does not establish product safety or scan completeness.",
        },
        "validated_vulnerability": 0,
        "limitations": [
            "This pinned G-drive snapshot is a real-source replay but is not an independent holdout; the CVE-2025-57052 fix pair was used during rule development.",
            "The whole detector run is blocked because all 99 C/C++ files are partial under current parsing; no-match cannot be read as safe.",
            "Findings remain component-source candidates; product inclusion, caller reachability, attacker control, and impact remain unverified.",
            "Peak RSS was not measured per run.",
        ],
        "raw_reports": [f"D26_G_CJSON_RUN{i}.json" for i in (1, 2)],
    }
    (out / "D26_G_CJSON_REPLAY.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
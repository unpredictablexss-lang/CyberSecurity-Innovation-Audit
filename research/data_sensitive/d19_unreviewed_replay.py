"""Repeatable offline run of D's blocked high-recall fallback on one pinned Git revision."""
from __future__ import annotations

import argparse
import hashlib
import json
import resource
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.execution import run_reviewed_detectors
from src.ohscanner.runner import DetectorRegistry

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp"}
TEST_SEGMENTS = {"test", "tests", "unittest", "mock", "mocks", "fuzztest"}


def pinned_source_paths(repo: Path, commit: str) -> tuple[str, ...]:
    raw = subprocess.check_output(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "-z", commit]
    )
    paths = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        path = item.decode("utf-8")
        parts = path.lower().split("/")
        if Path(path).suffix.lower() not in SOURCE_SUFFIXES or any(x in TEST_SEGMENTS for x in parts):
            continue
        paths.append(path)
    if not paths:
        raise ValueError("pinned revision contains no eligible C/C++ source files")
    if len(paths) > 2_000:
        raise ValueError("scope exceeds the public 2,000-file limit; select a smaller reviewed scope")
    return tuple(sorted(paths))


def signature(report: dict) -> list[tuple]:
    result = []
    for run in report.get("detector_runs", []):
        for finding in run.get("diagnostics", []):
            result.append((
                finding.get("file"), finding.get("line"), finding.get("rule_id"),
                finding.get("source_sha256"), finding.get("diagnostic_id"),
                finding.get("evidence_obligations"),
            ))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-dir", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    repo = args.repo_dir.resolve(strict=True)
    commit = subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "--verify", f"{args.commit}^{{commit}}"],
        text=True,
    ).strip()
    paths = pinned_source_paths(repo, commit)
    registry = DetectorRegistry()
    registry.register(SensitiveExposureDetector())
    start = time.perf_counter()
    first = run_reviewed_detectors(repo, args.repository, commit, paths, registry)
    replay = run_reviewed_detectors(repo, args.repository, commit, paths, registry)
    if (first["git_tree"], first["snapshot_sha256"], signature(first),
            first["detector_coverage"]) != (
            replay["git_tree"], replay["snapshot_sha256"], signature(replay),
            replay["detector_coverage"]):
        raise RuntimeError("same-scope replay drifted; no stable result claimed")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report_hashes = {}
    for name, report in (("first.json", first), ("replay.json", replay)):
        data = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        (args.output_dir / name).write_bytes(data)
        report_hashes[name] = hashlib.sha256(data).hexdigest()
    run = first["detector_runs"][0]
    cov = first["detector_coverage"]["detectors"][run["tool"]]
    summary = {
        "schema": 1,
        "repository": args.repository,
        "commit": commit,
        "tree": first["git_tree"],
        "snapshot_sha256": first["snapshot_sha256"],
        "scope_files": len(paths),
        "scope_paths_sha256": hashlib.sha256("\n".join(paths).encode()).hexdigest(),
        "detector_id": run["tool"],
        "detector_version": run["tool_version"],
        "task_status": first["status"],
        "detector_status": run["status"],
        "candidate_count": run["diagnostic_count"],
        "coverage": cov,
        "same_scope_replay_equal": True,
        "report_hashes": report_hashes,
        "wall_seconds_two_runs": round(time.perf_counter() - start, 4),
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "validated_vulnerability": first["validated_vulnerability"],
        "limitations": [
            "Unreviewed source profile: fallback is candidate-only and reports blocked/partial coverage.",
            "Two identical executions are a stability check, not an independent holdout.",
            "No candidate is not evidence of a clean component or no vulnerability.",
        ],
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({k: v for k, v in summary.items()
                      if k not in ("coverage", "limitations")},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

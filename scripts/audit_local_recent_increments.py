"""Audit the local 15-day increment without fetching external repositories."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
import sys
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.detectors.cpp.bounds_detector import CppBoundsDetector
from src.ohscanner.detectors.cpp.integer_bounds_detector import CppIntegerBoundsDetector
from src.ohscanner.detectors.cpp.resource_lifetime_detector import CppResourceLifetimeDetector
from src.ohscanner.detectors.cpp.unsafe_memory_call_detector import CppUnsafeMemoryCallDetector
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource, SOURCE_LANGUAGES


def git(repo: Path, *args: str) -> bytes:
    env = os.environ.copy()
    env.update({"GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "", "GIT_TERMINAL_PROMPT": "0"})
    return subprocess.check_output(["git", "-C", str(repo), *args], env=env, stderr=subprocess.STDOUT, timeout=30)


def source_language(path: str):
    return SOURCE_LANGUAGES.get(Path(path).suffix.lower())


def run_increment(repo: Path, since: str, until: str) -> Dict[str, Any]:
    started = time.perf_counter()
    raw = git(repo, "log", "--first-parent", f"--since={since}", f"--until={until}", "--format=%H%x09%cI%x09%s")
    commits = []
    detector_counts = {item.detector_id: 0 for item in (
        CppBoundsDetector(), CppIntegerBoundsDetector(), CppResourceLifetimeDetector(), CppUnsafeMemoryCallDetector()
    )}
    selected_files = set()
    parse_counts: Dict[str, int] = {}
    for line in raw.decode("utf-8", "replace").splitlines()[:50]:
        if not line:
            continue
        commit, date, subject = line.split("\t", 2)
        changed = git(repo, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit).decode("utf-8", "replace").splitlines()
        sources = []
        for path in sorted(set(changed))[:50]:
            language = source_language(path)
            if language is None:
                continue
            try:
                data = git(repo, "show", f"{commit}:{path}")
            except subprocess.CalledProcessError:
                continue
            if len(data) > 1024 * 1024:
                continue
            sources.append(GitSource(path, language, "", data))
            selected_files.add(path)
        if not sources:
            commits.append({"commit": commit, "date": date, "subject": subject, "source_files": 0, "candidate_count": 0})
            continue
        units, _ast, coverage = index_sources(tuple(sources))
        for status, count in coverage["parsing_status"].items():
            parse_counts[status] = parse_counts.get(status, 0) + count
        candidate_count = 0
        for detector in (CppBoundsDetector(), CppIntegerBoundsDetector(), CppResourceLifetimeDetector(), CppUnsafeMemoryCallDetector()):
            run = detector.detect(None, units)
            detector_counts[detector.detector_id] += len(run.findings)
            candidate_count += len(run.findings)
        commits.append({"commit": commit, "date": date, "subject": subject, "source_files": len(sources), "candidate_count": candidate_count})
    return {
        "repository": repo.name,
        "path": str(repo),
        "commit_count": len(commits),
        "selected_unique_files": len(selected_files),
        "candidate_counts_by_detector": detector_counts,
        "parse_counts": parse_counts,
        "commits": commits,
        "wall_seconds": time.perf_counter() - started,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--since", default="2026-10-02T00:00:00+08:00")
    parser.add_argument("--until", default="2026-10-18T00:00:00+08:00")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    rows = []
    for repo in sorted(path for path in args.repo_root.iterdir() if (path / ".git").exists()):
        rows.append(run_increment(repo, args.since, args.until))
    report = {
        "schema_version": 1,
        "experiment_kind": "local_recent_15_day_increment",
        "status": "completed_with_limitations",
        "window": {"since": args.since, "until": args.until},
        "scope": {
            "mode": "locally_available_repositories",
            "repository_count": len(rows),
            "all_community_status": "not_executed",
            "reason": "Only locally cloned OpenHarmony repositories were authorized; no additional repositories were fetched.",
        },
        "repositories": rows,
        "totals": {
            "commits": sum(row["commit_count"] for row in rows),
            "selected_unique_files_sum": sum(row["selected_unique_files"] for row in rows),
            "wall_seconds": sum(row["wall_seconds"] for row in rows),
        },
        "limitations": [
            "Increment candidates are not vulnerabilities and no Precision/Recall is computed.",
            "A commit with zero changed supported source files is not evidence of safety.",
            "This is not an 807-repository or whole-community capacity run.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + chr(10), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

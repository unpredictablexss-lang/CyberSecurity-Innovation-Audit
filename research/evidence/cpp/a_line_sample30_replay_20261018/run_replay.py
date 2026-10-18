#!/usr/bin/env python3
"""Replay the delivered sample30 manifest against local pinned source roots.

The 30 pinned repositories are not present in this workspace. This runner is
ready for them: it verifies commit/tree identity, recomputes the snapshot,
runs the current A-line detectors and compares per-rule diagnostics with the
delivered sandbox report. ``--self-check`` validates the machinery on a
synthetic temporary Git repository.

No source is fetched, checked out or modified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.detectors.cpp.bounds_detector import CppBoundsDetector
from src.ohscanner.detectors.cpp.integer_bounds_detector import (
    CppIntegerBoundsDetector,
)
from src.ohscanner.detectors.cpp.resource_lifetime_detector import (
    CppResourceLifetimeDetector,
)
from src.ohscanner.detectors.cpp.unsafe_memory_call_detector import (
    CppUnsafeMemoryCallDetector,
)
from src.ohscanner.git_source import resolve_commit
from src.ohscanner.indexing import prepare_git_context


DEFAULT_MANIFEST = (
    PROJECT_ROOT
    / "research"
    / "deliveries"
    / "a-line-sample30"
    / "20261018"
    / "evidence"
    / "sample_manifest.json"
)

DETECTORS = (
    CppBoundsDetector(),
    CppIntegerBoundsDetector(),
    CppResourceLifetimeDetector(),
    CppUnsafeMemoryCallDetector(),
)


def _resolve_source_root(value: str, mapping: Dict[str, str]) -> Path:
    if value in mapping:
        return Path(mapping[value])
    path = Path(value)
    if path.exists():
        return path
    match = re.fullmatch(r"([A-Za-z]):\\(.*)", value)
    if match and os.name != "nt":
        converted = Path("/mnt") / match.group(1).lower() / match.group(2).replace("\\", "/")
        return converted
    return path


def _baseline_by_rule(record: Dict[str, Any]) -> Dict[str, int]:
    return dict(Counter(item["rule_id"] for item in record.get("diagnostics", [])))


def _current_by_rule(
    context: Any, units: Sequence[Any]
) -> Tuple[Dict[str, int], Dict[str, str]]:
    counts: Counter = Counter()
    statuses: Dict[str, str] = {}
    for detector in DETECTORS:
        run = detector.detect(context, tuple(units))
        statuses[run.detector_id] = run.status
        for finding in run.findings:
            counts[finding.rule_id] += 1
    return dict(sorted(counts.items())), statuses


def replay_record(
    record: Dict[str, Any], mapping: Dict[str, str]
) -> Dict[str, Any]:
    repository = record["repository"]
    result: Dict[str, Any] = {
        "sample_order": record["sample_order"],
        "repository": repository,
        "expected_commit": record["commit"],
        "expected_tree": record["git_tree"],
        "expected_snapshot": record["snapshot_sha256"],
        "baseline_by_rule": _baseline_by_rule(record),
    }
    source_root = _resolve_source_root(record["wsl_repo_dir"], mapping)
    if not source_root.is_dir():
        result["status"] = "source_missing"
        result["source_root"] = str(source_root)
        return result
    started = time.perf_counter()
    try:
        commit, tree = resolve_commit(source_root, record["commit"])
    except Exception as error:  # noqa: BLE001 - reported as unknown identity
        result["status"] = "identity_error"
        result["error"] = str(error)
        return result
    result["resolved_commit"] = commit
    result["resolved_tree"] = tree
    if commit != record["commit"] or tree != record["git_tree"]:
        result["status"] = "identity_mismatch"
        return result
    try:
        context, _tree, inventory, _coverage, _sources = prepare_git_context(
            source_root, repository, commit, (".",)
        )
    except Exception as error:  # noqa: BLE001 - reported as unknown snapshot
        result["status"] = "snapshot_error"
        result["error"] = str(error)
        return result
    result["snapshot_sha256"] = context.request.snapshot_sha256
    result["snapshot_match"] = (
        context.request.snapshot_sha256 == record["snapshot_sha256"]
    )
    result["selected_source_files"] = inventory["selected_source_files"]
    result["selected_source_bytes"] = inventory["selected_source_bytes"]
    current, statuses = _current_by_rule(context, context.units)
    result["current_by_rule"] = current
    result["detector_status"] = statuses
    result["delta_by_rule"] = {
        rule: current.get(rule, 0) - result["baseline_by_rule"].get(rule, 0)
        for rule in sorted(set(current) | set(result["baseline_by_rule"]))
    }
    result["status"] = "replayed"
    result["wall_seconds"] = time.perf_counter() - started
    return result


def _self_check() -> int:
    with tempfile.TemporaryDirectory(prefix="a-line-replay-self-check-") as temp:
        repo = Path(temp) / "repo"
        repo.mkdir()
        (repo / "demo.cpp").write_text(
            "void demo(char *src) {\n    char dst[4];\n    memcpy(dst, src, 8);\n}\n",
            encoding="utf-8",
        )
        env = {
            "GIT_AUTHOR_NAME": "self-check",
            "GIT_AUTHOR_EMAIL": "self-check@example.invalid",
            "GIT_COMMITTER_NAME": "self-check",
            "GIT_COMMITTER_EMAIL": "self-check@example.invalid",
        }
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env={**os.environ, **env})
        subprocess.run(["git", "add", "demo.cpp"], cwd=repo, check=True, env={**os.environ, **env})
        subprocess.run(
            ["git", "commit", "-q", "-m", "self-check"],
            cwd=repo,
            check=True,
            env={**os.environ, **env},
        )
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip()
        commit, tree = resolve_commit(repo, head)
        context, _tree, _inventory, _coverage, _sources = prepare_git_context(
            repo, "self-check/repo", commit, (".",)
        )
        record = {
            "sample_order": 0,
            "repository": "self-check/repo",
            "commit": commit,
            "git_tree": tree,
            "snapshot_sha256": context.request.snapshot_sha256,
            "wsl_repo_dir": str(repo),
            "diagnostics": [],
        }
        result = replay_record(record, {})
        assert result["status"] == "replayed", result
        assert result["snapshot_match"] is True
        assert result["current_by_rule"].get(
            "ohcpp-memory-bounds-copy-candidate-001", 0
        ) >= 1
        missing = replay_record({**record, "wsl_repo_dir": str(repo) + "-absent"}, {})
        assert missing["status"] == "source_missing", missing
    print("self-check=passed")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out-dir", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--source-root-map", type=Path)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)
    if args.self_check:
        return _self_check()
    mapping: Dict[str, str] = {}
    if args.source_root_map:
        mapping = json.loads(args.source_root_map.read_text(encoding="utf-8"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    records = manifest["records"]
    results = [replay_record(record, mapping) for record in records]
    replayed = [item for item in results if item["status"] == "replayed"]
    snapshot_matched = [item for item in replayed if item["snapshot_match"]]
    summary = {
        "schema_version": 1,
        "experiment_kind": "a_line_sample30_pinned_replay",
        "status": "completed" if len(replayed) == len(records) else "blocked_sources_missing",
        "source_manifest": str(args.manifest),
        "source_manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "samples": len(records),
        "replayed": len(replayed),
        "snapshot_matched": len(snapshot_matched),
        "status_counts": dict(sorted(Counter(item["status"] for item in results).items())),
        "results": results,
        "limitations": [
            "No source is fetched or checked out; missing roots stay source_missing.",
            "Snapshot equality is required before claiming the same lexical scope.",
            "Candidate counts are not vulnerability counts and no Precision/Recall is computed.",
        ],
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print("samples=" + str(summary["samples"]))
    print("replayed=" + str(summary["replayed"]))
    print("snapshot_matched=" + str(summary["snapshot_matched"]))
    print("status_counts=" + json.dumps(summary["status_counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

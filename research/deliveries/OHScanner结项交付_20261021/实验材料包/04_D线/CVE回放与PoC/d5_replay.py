#!/usr/bin/env python3
"""Offline, commit-pinned research replay for one reviewed D source model.

The script reads Git objects from an existing local repository only. It never
fetches, checks out, or changes a ref. Its findings are research candidates and
are kept separate from the public Runner and product vulnerability state.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from importlib import metadata
from pathlib import Path

try:
    import resource
except ModuleNotFoundError:  # Windows has no resource module.
    resource = None

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.detectors.data.historical import HistoricalSensitiveExposureDetector, historical_model
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource


def git(store: Path, *args: str, timeout: int) -> str:
    result = subprocess.run(
        ["git", "-C", str(store), *args], check=True, capture_output=True,
        text=True, timeout=timeout, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    )
    return result.stdout.strip()


def git_bytes(store: Path, spec: str, timeout: int) -> bytes:
    return subprocess.run(
        ["git", "-C", str(store), "cat-file", "blob", spec], check=True,
        capture_output=True, timeout=timeout,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
    ).stdout


def canonical_hash(value: object) -> str:
    data = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def peak_rss() -> int | None:
    if resource is None:
        return None
    try:
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (AttributeError, OSError):
        return None


def write_blocked(output: Path, exc: Exception) -> dict:
    record = {"schema": 1, "status": "blocked", "error_type": type(exc).__name__, "error": str(exc),
              "exit_code": 2, "network_access": "not attempted", "head_switch": "not attempted"}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, ensure_ascii=False, indent=2), file=sys.stderr)
    return record


def bounded_child(command: list[str], output: Path, seconds: float) -> int:
    """Enforce a wall budget on platforms without SIGALRM, including Windows."""
    try:
        return subprocess.run(command, timeout=seconds).returncode
    except subprocess.TimeoutExpired:
        write_blocked(output, TimeoutError(f"replay exceeded {seconds}s budget"))
        return 2


def replay(args: argparse.Namespace) -> dict:
    started = time.monotonic()
    store = args.local_git_store.resolve(strict=True)
    if not (store / ".git").exists() and not (store / "HEAD").exists():
        raise ValueError("local_git_store must be an existing Git checkout or bare repository")
    commit = git(store, "rev-parse", "--verify", f"{args.commit}^{{commit}}", timeout=args.git_timeout)
    tree = git(store, "rev-parse", "--verify", f"{commit}^{{tree}}", timeout=args.git_timeout)
    model = historical_model(commit)
    profile = model.profile
    if model.repository != args.repository:
        raise ValueError(f"repository/model mismatch: {model.repository} != {args.repository}")
    if profile["model_version"] != args.model_version:
        raise ValueError(f"model version mismatch: profile={profile['model_version']} requested={args.model_version}")
    if profile["tree"] != tree:
        raise ValueError(f"tree mismatch: source={tree} model={profile['tree']}")
    if len(args.target) != len(set(args.target)):
        raise ValueError("duplicate --target path")
    required = {row["file"]: row for row in profile["required_files"]}
    requested = set(args.target)
    if requested != set(required):
        missing, extra = sorted(set(required)-requested), sorted(requested-set(required))
        raise ValueError(f"target scope mismatch: missing={missing} extra={extra}")

    sources = []
    source_rows = []
    for path in sorted(requested):
        row = required[path]
        blob = git(store, "rev-parse", "--verify", f"{commit}:{path}", timeout=args.git_timeout)
        if blob != row["blob"]:
            raise ValueError(f"blob mismatch for {path}: Git={blob} model={row['blob']}")
        data = git_bytes(store, f"{commit}:{path}", args.git_timeout)
        sha256 = hashlib.sha256(data).hexdigest()
        if len(data) != row["size"] or sha256 != row["sha256"]:
            raise ValueError(f"source bytes mismatch for {path}")
        suffix = Path(path).suffix.lower()
        language = "c" if suffix == ".c" else "cpp"
        sources.append(GitSource(path, language, blob, data))
        source_rows.append({"path": path, "blob": blob, "size": len(data), "sha256": sha256})

    units, ast, parsing = index_sources(tuple(sources))
    request = ScanRequest(
        request_id="d5-offline-replay-" + commit[:12], repository=args.repository,
        commit=commit, snapshot_sha256=snapshot_digest(units),
        target_id="current-component:" + args.repository, profile_id=args.parser_profile,
        provenance="fixture",
    )
    context = ScanContext(request, units, {"ast": ast})
    run = HistoricalSensitiveExposureDetector(model).detect(context, units)
    max_rss = peak_rss()
    return {
        "schema": 1,
        "mode": "offline_research_only",
        "repository": args.repository,
        "commit": commit,
        "tree": tree,
        "model_version": args.model_version,
        "model_profile_id": profile["profile_id"],
        "model_sha256": canonical_hash(profile),
        "parser_profile": args.parser_profile,
        "build_profile": args.build_profile,
        "dependencies": {
            "requirements_web_sha256": hashlib.sha256((ROOT / "requirements-web.txt").read_bytes()).hexdigest(),
            "tree_sitter": metadata.version("tree-sitter"),
            "tree_sitter_c": metadata.version("tree-sitter-c"),
            "tree_sitter_cpp": metadata.version("tree-sitter-cpp"),
        },
        "detector_id": run.detector_id,
        "detector_version": run.version,
        "detector_implementation": {
            "historical.py_sha256": hashlib.sha256(
                (ROOT / "src/ohscanner/detectors/data/historical.py").read_bytes()).hexdigest(),
            "sensitive_exposure.py_sha256": hashlib.sha256(
                (ROOT / "src/ohscanner/detectors/data/sensitive_exposure.py").read_bytes()).hexdigest(),
        },
        "public_runner_invoked": False,
        "validated_vulnerability": 0,
        "product_impact": "unknown",
        "source_files": source_rows,
        "parse_summary": parsing,
        "status": run.status,
        "file_outcomes": [list(row) for row in run.file_outcomes],
        "candidates": [{
            "id": canonical_hash([finding.file, finding.line, finding.rule_id, finding.source_sha256]),
            "file": finding.file, "line": finding.line, "symbol": finding.symbol,
            "rule_id": finding.rule_id, "candidate_cwe": finding.candidate_cwe,
            "source_sha256": finding.source_sha256, "message": finding.message,
            "evidence_obligations": [
                {"kind": item.kind, "description": item.description, "status": item.status}
                for item in finding.evidence_obligations
            ],
        } for finding in run.findings],
        "limitations": list(run.limitations),
        "elapsed_ms": round((time.monotonic()-started)*1000, 3),
        "max_rss_platform_units": max_rss,
        "budget_seconds": args.budget_seconds,
        "git_command_timeout_seconds": args.git_timeout,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--local-git-store", type=Path, required=True)
    parser.add_argument("--target", action="append", required=True, help="repeat once per exact reviewed source path")
    parser.add_argument("--model-version", required=True)
    parser.add_argument("--parser-profile", required=True)
    parser.add_argument("--build-profile", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--git-timeout", type=int, default=30)
    parser.add_argument("--budget-seconds", type=int, default=60)
    parser.add_argument("--_budget-worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.git_timeout < 1 or args.budget_seconds < 1:
        parser.error("--git-timeout and --budget-seconds must be positive")
    def time_budget(_signum, _frame):
        raise TimeoutError(f"replay exceeded {args.budget_seconds}s budget")
    has_alarm = hasattr(signal, "SIGALRM") and hasattr(signal, "alarm")
    if not has_alarm and not args._budget_worker:
        return bounded_child(
            [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], "--_budget-worker"],
            args.output, args.budget_seconds,
        )
    if has_alarm:
        signal.signal(signal.SIGALRM, time_budget)
        signal.alarm(args.budget_seconds)
    try:
        result = replay(args)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TimeoutError) as exc:
        write_blocked(args.output, exc)
        return 2
    finally:
        if has_alarm:
            signal.alarm(0)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

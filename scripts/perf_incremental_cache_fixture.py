#!/usr/bin/env python3
"""Reproducible two-commit fixture for verified per-Blob detector reuse."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.ohscanner.execution import run_fixed_commit_scan


DETECTOR = "ohscanner.example.cpp.copy-calls"
BASE_FILES = {
    "unchanged.cpp": "void stable(){ memcpy(a, b, n); }\n",
    "changed.cpp": "void changing(){ memcpy(a, b, n); }\n",
}


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def commit(repo: Path, message: str) -> str:
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", message], check=True)
    return git(repo, "rev-parse", "HEAD")


def scan(repo: Path, out: Path, commit_id: str, *, cache: Path | None = None,
         base: str | None = None) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    return run_fixed_commit_scan(
        repo, "fixture/incremental-cache", commit_id, (".",), (DETECTOR,),
        out / "report.json", out / "report.md", allow_examples=True,
        base_commit=base, detector_result_cache_dir=cache,
    )


def signature(report: dict) -> dict:
    run = report["detector_runs"][0]
    return {
        "status": report["status"],
        "source_parsing": report["source_parsing"],
        "detector_coverage": report["detector_coverage"],
        "detector_status": run["status"],
        "diagnostics": sorted((item["diagnostic_id"], item["file"], item["line"],
                                item["column"], item["source_sha256"])
                              for item in run["diagnostics"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    out = args.out_dir.resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"Refusing to overwrite non-empty output directory: {out}")
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ohscanner-p2-fixture-") as temporary:
        repo = Path(temporary) / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "OHScanner Fixture"], check=True)
        for name, text in BASE_FILES.items():
            (repo / name).write_text(text, encoding="utf-8")
        base = commit(repo, "fixture base")
        cache = out / "detector-cache"
        base_cold = scan(repo, out / "base-cold", base, cache=cache)
        (repo / "changed.cpp").write_text(
            "void changing(){ memcpy(a, b, n); memcpy(c, d, m); }\n", encoding="utf-8")
        head = commit(repo, "fixture source change")
        head_cached = scan(repo, out / "head-cached", head, cache=cache, base=base)
        head_uncached = scan(repo, out / "head-uncached", head)
        equivalent = signature(head_cached) == signature(head_uncached)
        payload = {
            "schema_version": 1,
            "experiment": "P2 verified single-Git-Blob detector-result reuse fixture",
            "limits": [
                "Two-file synthetic C++ fixture, not a product scan or ABCD vulnerability benchmark.",
                "The source inventory and parsing still run at head; only opted-in per-file result reuse is measured.",
                "The demonstration detector inventories memcpy call sites; no security precision/recall claim.",
            ],
            "repository": "fixture/incremental-cache",
            "base_commit": base,
            "head_commit": head,
            "cold_cache_stats": base_cold["performance"].get("detector_result_cache"),
            "incremental_cache_stats": head_cached["performance"].get("detector_result_cache"),
            "incremental": head_cached.get("incremental"),
            "equivalent_to_uncached": equivalent,
            "cached_result_signature": signature(head_cached),
            "uncached_result_signature": signature(head_uncached),
            "timings": {
                "head_cached": head_cached["performance"],
                "head_uncached": head_uncached["performance"],
            },
        }
        (out / "comparison.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not equivalent:
        raise SystemExit("Cached and uncached result identities/coverage differ; see comparison.json")
    print(f"P2 fixture reports written under {out}; result/coverage equivalence: {equivalent}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Show why changed-files-only E1 is not a complete scan result."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.ohscanner.execution import run_fixed_commit_scan  # noqa: E402

DETECTORS = ("ohscanner.cpp.lifetime", "ohscanner.cpp.shared_ptr_race")
FIXTURES = ROOT / "tests" / "detectors" / "fixtures"


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def commit(repo: Path, message: str) -> str:
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", message], check=True)
    return git(repo, "rev-parse", "HEAD")


def scan(repo: Path, out: Path, commit_id: str, includes: tuple[str, ...]) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    return run_fixed_commit_scan(
        repo, "fixture/e1-changed-only", commit_id, includes, DETECTORS,
        out / "report.json", out / "report.md",
    )


def candidates(report: dict) -> set[tuple[str, str, str, int, int | None, str | None]]:
    return {
        (run["tool"], row["diagnostic_id"], row["file"], row["line"],
         row.get("column"), row.get("source_sha256"))
        for run in report["detector_runs"] for row in run.get("diagnostics", [])
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    out = args.out_dir.resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"Refusing to overwrite non-empty output directory: {out}")
    out.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="ohscanner-e1-fixture-") as temporary:
        repo = Path(temporary) / "repo"
        (repo / "src").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "OHScanner E1 fixture"], check=True)
        sources = {
            "src/lifetime.cpp": FIXTURES / "cpp_lifetime" / "vulnerable_unserialized.cpp",
            "src/race.cpp": FIXTURES / "cpp_shared_ptr_race" / "vulnerable_non_atomic_shared_ptr.cpp",
            "src/safe.cpp": FIXTURES / "cpp_lifetime" / "fixed_alias_rebind.cpp",
        }
        for relative, source in sources.items():
            (repo / relative).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        base = commit(repo, "base fixture")
        safe = repo / "src" / "safe.cpp"
        safe.write_text(safe.read_text(encoding="utf-8") + "\n// harmless edit\n", encoding="utf-8")
        head = commit(repo, "edit safe file only")
        full = scan(repo, out / "full_head", head, (".",))
        e1 = scan(repo, out / "e1_changed_file_only", head, ("src/safe.cpp",))
        full_set, e1_set = candidates(full), candidates(e1)
        omitted = sorted(full_set - e1_set)
        result = {
            "schema_version": 1,
            "experiment": "E1 changed-files-only risk fixture",
            "status": "rejected_changed_files_only_incomplete_coverage",
            "scope": "synthetic three-file C++ Git repository using two M2 research detectors",
            "base_commit": base,
            "head_commit": head,
            "changed_paths": ["src/safe.cpp"],
            "detectors": list(DETECTORS),
            "full_report": "full_head/report.json",
            "e1_report": "e1_changed_file_only/report.json",
            "full_candidate_count": len(full_set),
            "e1_candidate_count": len(e1_set),
            "omitted_unchanged_file_candidate_count": len(omitted),
            "omitted_candidates": [
                {"detector": row[0], "diagnostic_id": row[1], "file": row[2],
                 "line": row[3], "column": row[4], "source_sha256": row[5]}
                for row in omitted
            ],
            "full_status": full["status"],
            "e1_status": e1["status"],
            "full_coverage": full["detector_coverage"],
            "e1_coverage": e1["detector_coverage"],
            "interpretation": "A harmless edit to one file leaves findings in unchanged files; E1 is diagnostic only and cannot be published as a complete scan.",
        }
        (out / "comparison.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in (
        "status", "full_candidate_count", "e1_candidate_count",
        "omitted_unchanged_file_candidate_count", "full_status", "e1_status")},
        ensure_ascii=False))
    return 0 if result["omitted_unchanged_file_candidate_count"] > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

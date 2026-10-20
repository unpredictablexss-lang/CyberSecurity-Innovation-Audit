#!/usr/bin/env python3
"""Verify T5's per-file originating-worktree date provenance inventory."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import sys


DEFAULT_INVENTORY = pathlib.Path(__file__).with_name(
    "t5_pr35_date_provenance_20261020.json"
)
DATE_SUFFIX = re.compile(r"202610(?:2[1-9]|30)")
T3_CORRECTED = {
    "research/evidence/cpp/d54_libpng_lifetime_assessment_20261020.md",
    "research/evidence/cpp/d54_libpng_lifetime_assessment_20261020.json",
    "research/evidence/cpp/d54_libpng33416_vulnerable_cli_20261020.json",
    "research/evidence/cpp/d54_libpng33416_fixed_cli_20261020.json",
    "research/evidence/cpp/d54_libpng46675_vulnerable_cli_20261020.json",
    "research/evidence/cpp/d54_libpng46675_fixed_cli_20261020.json",
    "research/evidence/cpp/verify_d54_libpng_lifetime_20261020.py",
    "research/evidence/cpp/t61_libpng_independent_acceptance_20261020.md",
    "research/evidence/cpp/t61_libpng_independent_acceptance_20261020.json",
    "research/evidence/cpp/t61_libpng_current_replay_20261020.json",
    "research/evidence/cpp/verify_t61_libpng_acceptance_20261020.py",
    "research/evidence/cpp/t62_dsoftbus_cve_2025_26690_independent_acceptance_20261020.md",
    "research/evidence/cpp/t62_dsoftbus_cve_2025_26690_independent_acceptance_20261020.json",
}


def git(root: pathlib.Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def git_file_sha256(root: pathlib.Path, commit: str, rel: str) -> str:
    content = subprocess.check_output(
        ["git", "-C", str(root), "show", f"{commit}:{rel}"],
        stderr=subprocess.STDOUT,
    )
    return hashlib.sha256(content).hexdigest()


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repo_root(start: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(git(start, "rev-parse", "--show-toplevel"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=pathlib.Path, default=DEFAULT_INVENTORY)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    root = repo_root(pathlib.Path(__file__).resolve().parent)
    errors: list[str] = []

    base = inventory["integration_head"]
    try:
        git(root, "cat-file", "-e", f"{base}^{{commit}}")
    except subprocess.CalledProcessError:
        errors.append(f"integration baseline commit is unavailable: {base}")

    expected_by_task = {item["task_id"]: item for item in inventory["date_proven_tasks"]}
    if len(expected_by_task) != len(inventory["date_proven_tasks"]):
        errors.append("duplicate task id in date_proven_tasks")
    seen: set[str] = set()
    for item in inventory["date_proven_files"]:
        rel = item["path"]
        if rel in seen:
            errors.append(f"duplicate date-proven path: {rel}")
            continue
        seen.add(rel)
        if not DATE_SUFFIX.search(pathlib.PurePosixPath(rel).name):
            errors.append(f"date-proven path lacks a 20261021-30 filename date: {rel}")
        source = pathlib.Path(item["origin_worktree"])
        source_file = source / pathlib.Path(rel)
        integration_file = root / pathlib.Path(rel)
        if not source_file.is_file() or not integration_file.is_file():
            errors.append(f"missing source or integration artifact: {rel}")
            continue
        task = expected_by_task.get(item["task_id"])
        if not task or str(source) != task["origin_worktree"]:
            errors.append(f"task/worktree mapping mismatch: {rel}")
        else:
            try:
                actual_head = git(source, "rev-parse", "HEAD")
                if item["task_id"] == "T56" and source.resolve() == pathlib.Path(task["origin_worktree"]).resolve():
                    # T56's origin is the integration checkout itself. It can advance
                    # after T5 is cherry-picked, so require ancestry plus an exact
                    # baseline blob and current-file hash check for every indexed file.
                    ancestor = subprocess.run(
                        ["git", "-C", str(source), "merge-base", "--is-ancestor", task["origin_head"], actual_head],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    if ancestor.returncode != 0:
                        errors.append(
                            f"integration-origin HEAD is not a descendant of recorded T56 origin head for {rel}: {actual_head}"
                        )
                    try:
                        baseline_sha = git_file_sha256(source, task["origin_head"], rel)
                        if baseline_sha != item["sha256"]:
                            errors.append(f"recorded T56 origin-head blob SHA-256 mismatch: {rel}")
                    except subprocess.CalledProcessError as exc:
                        errors.append(f"cannot read T56 artifact at recorded origin head for {rel}: {exc}")
                elif actual_head != task["origin_head"]:
                    errors.append(f"origin worktree HEAD changed for {item['task_id']}: {actual_head}")
            except subprocess.CalledProcessError as exc:
                errors.append(f"origin worktree is not a readable Git checkout for {item['task_id']}: {exc}")
        if sha256(source_file) != item["sha256"]:
            errors.append(f"origin artifact SHA-256 mismatch: {rel}")
        if sha256(integration_file) != item["sha256"]:
            errors.append(f"integration artifact SHA-256 mismatch: {rel}")
        recorded = dt.datetime.fromisoformat(item["origin_last_write_local"])
        actual = dt.datetime.fromtimestamp(source_file.stat().st_mtime).astimezone()
        if recorded.date().isoformat() != inventory["audit_date_local"]:
            errors.append(f"recorded source write time is not audit date: {rel}")
        if abs((actual - recorded).total_seconds()) > 1:
            errors.append(f"origin worktree timestamp changed: {rel}")

    computed_task_counts = {
        task_id: sum(item["task_id"] == task_id for item in inventory["date_proven_files"])
        for task_id in expected_by_task
    }
    for task_id, task in expected_by_task.items():
        if task["artifact_count"] != computed_task_counts[task_id]:
            errors.append(f"artifact count mismatch for {task_id}")
        listed = set(task["artifact_paths"])
        actual = {item["path"] for item in inventory["date_proven_files"] if item["task_id"] == task_id}
        if listed != actual:
            errors.append(f"artifact path list mismatch for {task_id}")

    evidence_dir = root / "research/evidence/cpp"
    current_future = {
        path.relative_to(root).as_posix()
        for path in evidence_dir.iterdir()
        if path.is_file() and DATE_SUFFIX.search(path.name)
    }
    blocked = set(inventory["blocked_paths"])
    t3_excluded = set(inventory["t3_corrected_paths_excluded"])
    if seen & blocked or seen & t3_excluded or blocked & t3_excluded:
        errors.append("date-proven, blocked, and T3-corrected path sets overlap")
    if current_future != seen | blocked:
        missing = sorted(current_future - (seen | blocked))
        stale = sorted((seen | blocked) - current_future)
        errors.append(f"future-path inventory differs (unclassified={missing}, absent={stale})")
    if t3_excluded != T3_CORRECTED:
        errors.append("T3 corrected path reference set differs from the 13-item confirmation set")
    for rel in sorted(blocked | t3_excluded):
        path = root / pathlib.Path(rel)
        if not path.is_file():
            errors.append(f"blocked or T3 reference path missing: {rel}")
        elif rel in t3_excluded and DATE_SUFFIX.search(path.name):
            errors.append(f"T3 corrected path was unexpectedly renamed back to a future date: {rel}")
    if len(seen) != 79 or len(blocked) != 192 or len(t3_excluded) != 13:
        errors.append(
            f"unexpected inventory totals: date-proven={len(seen)}, blocked={len(blocked)}, T3={len(t3_excluded)}"
        )

    print(
        json.dumps(
            {
                "ok": not errors,
                "date_proven_files": len(seen),
                "blocked_files": len(blocked),
                "t3_corrected_files_excluded": len(t3_excluded),
                "errors": errors,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())

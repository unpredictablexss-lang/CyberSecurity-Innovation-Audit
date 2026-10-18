#!/usr/bin/env python3
"""Verify the source-bound JSProxy component case without mutating the target."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_REPO = Path("/mnt/e/网安/audit-sources-20261014/home/audit/openharmony-audit/perf-corpus/distributeddatamgr_kv_store")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pinned-repo", type=Path, default=DEFAULT_REPO)
    args = parser.parse_args()
    manifest = json.loads((ROOT / "case_manifest.json").read_text(encoding="utf-8"))
    errors = []

    if not args.pinned_repo.is_dir():
        errors.append("pinned repository is missing: " + str(args.pinned_repo))
    else:
        commit = manifest["commit"]
        for item in manifest["source_files"]:
            path = item["path"]
            data = subprocess.check_output(
                ["git", "-C", str(args.pinned_repo), "show", commit + ":" + path]
            )
            actual_sha = hashlib.sha256(data).hexdigest()
            actual_blob = git(args.pinned_repo, "rev-parse", commit + ":" + path)
            if actual_sha != item["sha256"]:
                errors.append("source SHA mismatch: " + path)
            if actual_blob != item["git_blob_oid"]:
                errors.append("source blob mismatch: " + path)

    for key in ("vulnerable_header_sha256", "fixed_header_sha256", "results_sha256"):
        if not manifest["harness"].get(key):
            errors.append("missing harness binding: " + key)
    for item in manifest["source_files"]:
        if not item.get("git_blob_oid") or not item.get("sha256"):
            errors.append("missing source binding: " + item.get("path", "unknown"))

    results = json.loads((ROOT / "results.json").read_text(encoding="utf-8"))
    vulnerable = results["variants"]["vulnerable"]["runs"]
    fixed = results["variants"]["fixed"]["runs"]
    if len(vulnerable) != 3 or len(fixed) != 3:
        errors.append("expected three runs per variant")
    if not all(item["tsan_race"] and item["exit_code"] == 66 for item in vulnerable):
        errors.append("vulnerable TSan expectation not met")
    if not all(not item["tsan_race"] and item["exit_code"] == 0 for item in fixed):
        errors.append("fixed TSan expectation not met")
    if sha256(ROOT / "results.json") != manifest["harness"]["results_sha256"]:
        errors.append("results.json hash mismatch")

    patch = ROOT / manifest["patch"]["path"]
    if sha256(patch) != manifest["patch"]["sha256"]:
        errors.append("patch hash mismatch")
    if args.pinned_repo.is_dir():
        check = subprocess.run(
            ["git", "-C", str(args.pinned_repo), "apply", "--cached", "--check", str(patch)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if check.returncode != 0:
            errors.append("patch does not apply to pinned index: " + check.stdout.strip())

    if errors:
        for error in errors:
            print("ERROR: " + error)
        return 1
    print("case_ok")
    print("source_files=" + str(len(manifest["source_files"])))
    print("vulnerable=3/3 race, fixed=3/3 clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

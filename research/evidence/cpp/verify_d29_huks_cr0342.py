#!/usr/bin/env python3
"""Verify D29 HUKS CR-0342 source identity, frozen queue state and M2 replay."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

COMMIT = "4ae4e0db461f137672719d43ffc6c5b1b6c05be8"
TREE = "9c922a60d815a34eb96c060274ed863fd3a6fea8"
PATH = "services/huks_standard/huks_service/extension/ukey_client_service/inc/hks_ukey_async_task.h"
BLOB = "3719b03ef01f215b3188a236503ff973a1cb6e5d"
SHA256 = "6a656b45b3809a77b4fe124cff3c1b0b668ef754640667fcddedf576117a2974"
HERE = Path(__file__).resolve().parent


def git(git_dir: Path, *args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], input=data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", type=Path, required=True)
    parser.add_argument("--queue-json", type=Path, required=True)
    parser.add_argument("--queue-csv", type=Path, required=True)
    parser.add_argument("--cli-json", type=Path, required=True)
    args = parser.parse_args()
    git_dir = args.source_git_dir.resolve()

    if len(COMMIT) != 40:
        raise SystemExit("expected full 40-character A0 commit field")
    resolved = git(git_dir, "rev-parse", "--verify", COMMIT + "^{commit}").decode().strip()
    tree = git(git_dir, "show", "-s", "--format=%T", resolved).decode().strip()
    source = git(git_dir, "show", f"{COMMIT}:{PATH}")
    blob = git(git_dir, "hash-object", "--stdin", data=source).decode().strip()
    sha = hashlib.sha256(source).hexdigest()
    if (resolved, tree, blob, sha) != (COMMIT, TREE, BLOB, SHA256):
        raise SystemExit(f"source identity mismatch: {(resolved, tree, blob, sha)}")

    queue = json.loads(args.queue_json.read_text(encoding="utf-8"))["queue"]
    rows = [r for r in queue if r.get("queue_id") == "CR-0342"]
    if len(rows) != 1:
        raise SystemExit(f"expected exactly one JSON row for CR-0342, got {len(rows)}")
    row = rows[0]
    expected = (COMMIT, TREE, PATH, 48, BLOB, SHA256, "not_testable", "queued_first_batch")
    actual = (row["commit"], row["tree"], row["path"], row["line"], row["blob"],
              row["source_sha256"], row["original_status"], row["queue_status"])
    if actual != expected:
        raise SystemExit(f"JSON source binding/status changed: {actual}")

    with args.queue_csv.open(encoding="utf-8-sig", newline="") as handle:
        csv_rows = [r for r in csv.DictReader(handle) if r.get("queue_id") == "CR-0342"]
    if len(csv_rows) != 1:
        raise SystemExit(f"expected exactly one CSV row for CR-0342, got {len(csv_rows)}")
    csv_row = csv_rows[0]
    if (csv_row["commit"], csv_row["tree"], csv_row["path"], csv_row["line"],
        csv_row["blob"], csv_row["source_sha256"], csv_row["original_status"],
        csv_row["queue_status"]) != (COMMIT, TREE, PATH, "48", BLOB, SHA256,
                                    "not_testable", "queued_first_batch"):
        raise SystemExit("CSV source binding/status changed")

    cli = json.loads(args.cli_json.read_text(encoding="utf-8"))
    if (cli["repository"], cli["commit"], cli["git_tree"]) != (
        "openharmony/security_huks", COMMIT, TREE
    ):
        raise SystemExit("CLI source identity mismatch")
    if cli["scope"]["declared_scope"] != [PATH] or cli["scope"]["selected_source_files"] != 1:
        raise SystemExit("CLI declared scope mismatch")
    if cli["source_parsing"]["parsing_status"] != {"complete": 1}:
        raise SystemExit("CLI parser coverage not complete")
    run = cli["detector_runs"][0]
    if (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"],
        run["diagnostics"]) != ("ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", 0, []):
        raise SystemExit("CLI detector identity/result mismatch")

    print("CR-0342 original queue identities preserved; full commit/tree/blob/SHA-256 match: PASS")
    print("Production M2 CLI identity, single-file scope, complete parse and zero findings: PASS")
    print("Original not_testable / queued_first_batch statuses unchanged: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Verify D52 source bindings, CLI results, and unchanged A0 candidate rows."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path


FILES = {
    "interfaces/ets/ani/i18n/include/simple_number_format_addon.h": "23803c9108c4e4c6b88a92ad366b600108a16317",
    "interfaces/ets/ani/intl/include/number_format_addon.h": "216b68e9e1ba22c1c478b5966ebc713fe00e5bfe",
}


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path, help="Checkout of pinned global_i18n commit")
    parser.add_argument("--queue-csv", required=True, type=Path, help="Frozen A0 candidate CSV")
    parser.add_argument("--evidence-dir", type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    record = json.loads((args.evidence_dir / "d52_global_i18n_sharedptr_assessment_20261029.json").read_text(encoding="utf-8"))
    assert git(args.repo, "rev-parse", "HEAD") == record["commit"]
    assert git(args.repo, "rev-parse", "HEAD^{tree}") == record["tree"]
    for path, expected_blob in FILES.items():
        assert git(args.repo, "rev-parse", f"HEAD:{path}") == expected_blob
        source = subprocess.check_output(["git", "-C", str(args.repo), "show", f"HEAD:{path}"])
        assert hashlib.sha256(source).hexdigest() == next(
            row["sha256"] for row in record["candidates"] if row["file"] == path
        )
    with args.queue_csv.open(encoding="utf-8-sig", newline="") as stream:
        rows = {row["original_review_id"]: row for row in csv.DictReader(stream)}
    for candidate in record["candidates"]:
        row = rows[candidate["review_id"]]
        assert row["repository"] == "openharmony/global_i18n"
        assert row["path"] == candidate["file"]
        assert row["line"] == str(candidate["line"])
        assert row["original_status"] == candidate["original_status"] == "not_testable"
        assert row["queue_status"] == "paused_pending_evidence"
    for run in record["runs"]:
        cli = json.loads((args.evidence_dir / run["cli_json"]).read_text(encoding="utf-8"))
        assert cli["commit"] == record["commit"] and cli["git_tree"] == record["tree"]
        detector = next(item for item in cli["detector_runs"] if item["tool"] == record["detector"])
        assert detector["tool_version"] == record["detector_version"]
        assert detector["status"] == "completed" and detector["diagnostic_count"] == 0
        assert all(item["status"] == "complete" for item in detector["parsing"])
    print("D52 source identity, A0 preservation, and CLI evidence verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

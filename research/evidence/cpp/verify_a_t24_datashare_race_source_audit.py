#!/usr/bin/env python3
"""Verify T24 source provenance and preservation of its original A0 queue rows."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path


AUDIT_PATH = Path(__file__).with_name("a_t24_datashare_race_source_audit_20261020.json")
EXPECTED_REPOSITORY = "openharmony/distributeddatamgr_data_share"
EXPECTED_PROJECT_PATH = "foundation/distributeddatamgr/data_share"
EXPECTED_COMMIT = "560c5cdadf08b4beeb691e93d70ff32cc2dca8bd"
EXPECTED_TREE = "f731230c116c94d7619f5514c828b33ffac69924"
EXPECTED_ROWS = {
    "CR-0005": ("frameworks/ets/ani/include/ani_observer.h", 29),
    "CR-0006": ("frameworks/ets/ani/include/datashare_ani.h", 84),
    "CR-0007": ("frameworks/ets/ani/include/datashare_ani.h", 90),
    "CR-0008": ("frameworks/ets/ani/include/datashare_ani.h", 91),
    "CR-0009": ("frameworks/ets/ani/include/datashare_ani.h", 101),
    "CR-0010": ("frameworks/js/napi/dataShare/include/napi_datashare_observer.h", 27),
    "CR-0011": ("frameworks/native/consumer/include/datashare_helper_impl.h", 34),
    "CR-0012": ("frameworks/native/provider/include/datashare_stub_impl.h", 33),
}


def git(git_dir: Path, *args: str) -> bytes:
    return subprocess.check_output(
        ["git", f"--git-dir={git_dir}", *args], stderr=subprocess.PIPE
    )


def fail(message: str) -> int:
    print(json.dumps({"overall_ok": False, "error": message}, indent=2))
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", required=True, type=Path,
                        help="Path to the complete frozen A0 queue.csv; it is read-only")
    parser.add_argument("--git-dir", required=True, type=Path,
                        help="Git object database for the pinned DataShare source repository")
    parser.add_argument("--audit", type=Path, default=AUDIT_PATH)
    args = parser.parse_args()
    if not args.queue.is_file():
        return fail(f"queue not found: {args.queue}")
    if not args.git_dir.is_dir():
        return fail(f"git object database not found: {args.git_dir}")

    audit = json.loads(args.audit.read_text(encoding="utf-8"))
    with args.queue.open("r", encoding="utf-8-sig", newline="") as stream:
        queue_rows = list(csv.DictReader(stream))
    found = {row.get("queue_id"): row for row in queue_rows
             if row.get("queue_id") in EXPECTED_ROWS}
    expected_tree = git(args.git_dir, "rev-parse", "--verify",
                        f"{EXPECTED_COMMIT}^{{tree}}").decode().strip()
    commit_ok = git(args.git_dir, "cat-file", "-t", EXPECTED_COMMIT).decode().strip() == "commit"

    source_files = {item["path"]: item for item in audit["source_files"]}
    source_checks = {}
    for path, identity in source_files.items():
        listing = git(args.git_dir, "ls-tree", EXPECTED_COMMIT, "--", path).decode().strip()
        fields = listing.split("\t", 1)
        object_id = fields[0].split()[2] if len(fields) == 2 else ""
        content = git(args.git_dir, "cat-file", "blob", identity["blob"])
        source_checks[path] = {
            "tree_blob_matches": object_id == identity["blob"],
            "git_blob_matches": hashlib.sha1(
                b"blob " + str(len(content)).encode("ascii") + b"\0" + content
            ).hexdigest() == identity["blob"],
            "raw_sha256_matches": hashlib.sha256(content).hexdigest() == identity["source_sha256"],
            "byte_count_matches": len(content) == identity["bytes"],
        }

    row_checks = {}
    for row_id, (path, line) in EXPECTED_ROWS.items():
        row = found.get(row_id)
        audit_row = next((item for item in audit["rows"] if item["id"] == row_id), None)
        row_checks[row_id] = bool(
            row and audit_row
            and row.get("repository") == EXPECTED_REPOSITORY
            and row.get("repo_project_path") == EXPECTED_PROJECT_PATH
            and row.get("commit") == EXPECTED_COMMIT
            and row.get("tree") == EXPECTED_TREE
            and row.get("path") == path
            and int(row.get("line", "0")) == line
            and row.get("original_status") == "not_testable"
            and row.get("queue_status") == "paused_pending_evidence"
            and audit_row.get("path") == path and audit_row.get("line") == line
        )
    all_blob_checks = all(all(check.values()) for check in source_checks.values())
    overall_ok = (
        commit_ok and expected_tree == EXPECTED_TREE
        and len(queue_rows) == 345 and len(found) == len(EXPECTED_ROWS)
        and len({row.get("queue_id") for row in queue_rows}) == len(queue_rows)
        and len(audit["rows"]) == len(EXPECTED_ROWS)
        and all_blob_checks and all(row_checks.values())
        and audit["summary"]["source_mapping"] == "PASS"
        and audit["summary"]["race_case_disposition"] == "PARTIAL/BLOCK"
        and audit["summary"]["same_object_cross_thread_unordered_access_evidenced"] is False
        and audit["summary"]["tsan_or_product_runtime_claim"] is False
    )
    print(json.dumps({
        "overall_ok": overall_ok,
        "queue_path": str(args.queue.resolve()),
        "queue_rows": len(queue_rows),
        "queue_unique_ids": len({row.get("queue_id") for row in queue_rows}),
        "target_rows_found": len(found),
        "commit_is_git_commit": commit_ok,
        "observed_tree": expected_tree,
        "expected_tree": EXPECTED_TREE,
        "source_file_checks": source_checks,
        "row_identity_and_state_checks": row_checks,
        "race_case_disposition": audit["summary"]["race_case_disposition"],
        "same_object_cross_thread_unordered_access_evidenced": audit["summary"]["same_object_cross_thread_unordered_access_evidenced"],
    }, indent=2))
    return 0 if overall_ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"overall_ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        raise SystemExit(1)

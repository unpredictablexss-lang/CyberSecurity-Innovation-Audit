#!/usr/bin/env python3
"""Verify T22 pinned source identity and preservation of the four original A0 rows."""
from __future__ import annotations

import csv
import hashlib
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
DATA = HERE / "a_t22_supervisor_race_source_audit_20261020.json"
REPO = pathlib.Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\resourceschedule_resource_schedule_service.git")
CHECKOUT = pathlib.Path(r"D:\openHarmonyScanner\openharmony\foundation\resourceschedule\resource_schedule_service")


def git(*args: str) -> bytes:
    return subprocess.run(
        ["git", f"--git-dir={REPO}", *args], check=True, stdout=subprocess.PIPE
    ).stdout


data = json.loads(DATA.read_text(encoding="utf-8"))
src = data["source"]
commit_text = git("cat-file", "-p", src["commit"]).decode("utf-8", errors="replace")
commit_tree = next(line.split()[1] for line in commit_text.splitlines() if line.startswith("tree "))
tree_entry = git("ls-tree", src["commit"], "--", src["path"]).decode().strip()
blob = git("cat-file", "blob", src["blob"])
local_blob = subprocess.run(
    ["git", "hash-object", str(CHECKOUT / pathlib.PurePosixPath(src["path"]))],
    check=True,
    stdout=subprocess.PIPE,
    text=True,
).stdout.strip()
source_lines = blob.decode("utf-8").splitlines()

with pathlib.Path(data["queue_source"]).open(encoding="utf-8-sig", newline="") as stream:
    queue_rows = {row["queue_id"]: row for row in csv.DictReader(stream)}

expected_lines = {90, 91, 195, 236}
source_line_checks = {str(n): bool(source_lines[n - 1].strip()) for n in expected_lines}
queue_checks = {}
for expected in data["original_rows"]:
    row = queue_rows.get(expected["queue_id"], {})
    queue_checks[expected["queue_id"]] = all(
        row.get(field) == value
        for field, value in (
            ("candidate_id", expected["candidate_id"]),
            ("line", str(expected["line"])),
            ("original_status", expected["original_status"]),
            ("queue_status", expected["queue_status"]),
            ("commit", src["commit"]),
            ("tree", src["tree"]),
            ("path", src["path"]),
            ("blob", src["blob"]),
            ("source_sha256", src["sha256"]),
        )
    )

checks = {
    "commit_tree_matches": commit_tree == src["tree"],
    "tree_path_resolves_to_expected_blob": tree_entry.endswith(f"blob {src['blob']}\t{src['path']}"),
    "pinned_blob_sha256_matches": hashlib.sha256(blob).hexdigest() == src["sha256"],
    "local_checkout_file_matches_pinned_blob": local_blob == src["blob"],
    "source_candidate_lines_exist": all(source_line_checks.values()),
    "four_original_queue_rows_and_states_match": all(queue_checks.values()),
    "queue_rows_remain_not_testable_paused": all(
        row["original_status"] == "not_testable" and row["queue_status"] == "paused_pending_evidence"
        for row in data["original_rows"]
    ),
    "A0_345_identity_and_status_verifier_passed": data["a0_queue_verification"]["overall_ok"]
    and data["a0_queue_verification"]["source_candidates"] == 345
    and data["a0_queue_verification"]["queue_rows"] == 345
    and data["a0_queue_verification"]["original_status_counts"]
    == {"not_reproduced": 9, "not_testable": 336},
    "no_tsan_or_race_confirmation_claimed": not data["validation_limits"]["tsan_run"]
    and not data["validation_limits"]["race_confirmed"],
}
result = {
    "task": "T22",
    "source_commit": src["commit"],
    "source_tree": commit_tree,
    "tree_entry": tree_entry,
    "blob": src["blob"],
    "sha256": hashlib.sha256(blob).hexdigest(),
    "original_queue_rows_checked": queue_checks,
    "checks": checks,
    "overall_ok": all(checks.values()),
}
print(json.dumps(result, ensure_ascii=False, indent=2))
sys.exit(0 if result["overall_ok"] else 1)

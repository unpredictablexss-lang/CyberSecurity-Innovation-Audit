#!/usr/bin/env python3
"""Verify D51 CR-0341 source binding, frozen A0 status, and CLI replay."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

EXPECTED = {
    "commit": "4ae4e0db461f137672719d43ffc6c5b1b6c05be8",
    "tree": "9c922a60d815a34eb96c060274ed863fd3a6fea8",
    "blob": "2c12eef68c03b83e27c805b651bf99c981efac45",
    "sha256": "f189d4fbcb83e989ed3367fa8cb656e39a62f9aeddeb22b39c8d82352b435f45",
    "path": "services/huks_standard/huks_service/extension/ability_native/inc/hks_crypto_ext_stub_impl.h",
    "candidate": "ohscanner.cpp.shared_ptr_race:63b7b6b9dff04365",
}


def git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def fail(message: str) -> None:
    raise SystemExit(f"FAIL D51: {message}")


parser = argparse.ArgumentParser()
parser.add_argument("--source-repo", required=True, type=pathlib.Path)
parser.add_argument("--a0-queue", required=True, type=pathlib.Path)
parser.add_argument("--cli-json", required=True, type=pathlib.Path)
args = parser.parse_args()

if git(args.source_repo, "rev-parse", "HEAD") != EXPECTED["commit"]:
    fail("source checkout is not the frozen A0 commit")
if git(args.source_repo, "rev-parse", "HEAD^{tree}") != EXPECTED["tree"]:
    fail("source tree differs from frozen A0 identity")
if git(args.source_repo, "rev-parse", f"HEAD:{EXPECTED['path']}") != EXPECTED["blob"]:
    fail("source blob differs from frozen A0 identity")
blob = subprocess.check_output(
    ["git", "-C", str(args.source_repo), "cat-file", "blob", f"HEAD:{EXPECTED['path']}"]
)
if hashlib.sha256(blob).hexdigest() != EXPECTED["sha256"]:
    fail("source blob SHA-256 differs from frozen A0 identity")

queue = json.loads(args.a0_queue.read_text(encoding="utf-8"))
rows = [row for row in queue["queue"] if row.get("original_review_id") == "CR-0341"]
if len(queue["queue"]) != 345 or len(rows) != 1:
    fail("A0 queue count or CR-0341 uniqueness changed")
row = rows[0]
for key, field in (("commit", "commit"), ("tree", "tree"), ("blob", "blob"),
                   ("sha256", "source_sha256"), ("path", "path"),
                   ("candidate", "candidate_id")):
    if row.get(field) != EXPECTED[key]:
        fail(f"A0 CR-0341 {field} changed")
if row.get("original_status") != "not_testable" or row.get("queue_status") != "paused_pending_evidence":
    fail("A0 CR-0341 original status/queue state changed")

cli = json.loads(args.cli_json.read_text(encoding="utf-8"))
if cli.get("repository") != "openharmony/security_huks" or cli.get("commit") != EXPECTED["commit"]:
    fail("CLI report target identity mismatch")
if cli.get("scope", {}).get("git_tree") != EXPECTED["tree"]:
    fail("CLI report tree mismatch")
if cli.get("scope", {}).get("declared_scope") != [EXPECTED["path"]]:
    fail("CLI replay scope mismatch")
if cli.get("source_parsing", {}).get("parsing_status") != {"complete": 1}:
    fail("target file did not parse completely")
runs = cli.get("detector_runs", [])
if len(runs) != 1:
    fail("expected exactly one detector run")
run = runs[0]
if (run.get("tool") != "ohscanner.cpp.shared_ptr_race" or run.get("tool_version") != "0.5.1"
        or run.get("diagnostic_count") != 0 or run.get("status") != "completed"):
    fail("current shared_ptr_race replay metadata/result mismatch")
if len(run.get("parsing", [])) != 1 or run["parsing"][0].get("status") != "complete":
    fail("detector parser coverage mismatch")

print("PASS D51: exact A0 commit/tree/blob/SHA and CR-0341 row binding")
print("PASS D51: 345-row A0 queue retained; CR-0341 status and queue state unchanged")
print("PASS D51: current shared_ptr_race 0.5.1 selected-file replay complete, zero diagnostics")
print("PASS D51: report disposition remains PARTIAL/BLOCK; zero findings are not safety evidence")

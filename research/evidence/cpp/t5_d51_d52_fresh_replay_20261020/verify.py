#!/usr/bin/env python3
"""Verify T5 source identities, frozen A0 rows, baseline and fresh CLI outputs."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pathlib
import subprocess


BASELINE = "81dd4aea9bb51522ac912b33504ef0d2ddb79089"
QUEUE_SHA256 = "687d773986910a600e558833515137160ed50037889a2b6cc31c024433c3b45b"
CASES = {
    "CR-0341": {
        "repo": "security_huks",
        "repository": "openharmony/security_huks",
        "commit": "4ae4e0db461f137672719d43ffc6c5b1b6c05be8",
        "tree": "9c922a60d815a34eb96c060274ed863fd3a6fea8",
        "snapshot": "9fc6f1440f14899a71e9d4b99bd343782ad97eae5d1fa66b44c7fe23f4d3992c",
        "candidate": "ohscanner.cpp.shared_ptr_race:63b7b6b9dff04365",
        "path": "services/huks_standard/huks_service/extension/ability_native/inc/hks_crypto_ext_stub_impl.h",
        "blob": "2c12eef68c03b83e27c805b651bf99c981efac45",
        "sha256": "f189d4fbcb83e989ed3367fa8cb656e39a62f9aeddeb22b39c8d82352b435f45",
        "cli": "d51_cli.json",
        "parse_count": 1,
    },
    "CR-0255": {
        "repo": "global_i18n",
        "repository": "openharmony/global_i18n",
        "commit": "d13c698ebb238fa416a711bd3befe871e85721b6",
        "tree": "d667c4f54ca12ef664b3bab9ec80b93653c5a7b7",
        "snapshot": "533c3b8e09bbe318349ff90d92d07e2ea5d13fb2730f5fad2b102f6a0a7c54f8",
        "candidate": "ohscanner.cpp.shared_ptr_race:da71855714407620",
        "path": "interfaces/ets/ani/i18n/include/simple_number_format_addon.h",
        "blob": "23803c9108c4e4c6b88a92ad366b600108a16317",
        "sha256": "588f5783b8be2b3c1b49874e43464dce8c750cb340437f334053b57a665d4289",
        "cli": "d52_cli.json",
        "parse_count": 2,
    },
    "CR-0256": {
        "repo": "global_i18n",
        "repository": "openharmony/global_i18n",
        "commit": "d13c698ebb238fa416a711bd3befe871e85721b6",
        "tree": "d667c4f54ca12ef664b3bab9ec80b93653c5a7b7",
        "snapshot": "533c3b8e09bbe318349ff90d92d07e2ea5d13fb2730f5fad2b102f6a0a7c54f8",
        "candidate": "ohscanner.cpp.shared_ptr_race:d34ea3729a3995d7",
        "path": "interfaces/ets/ani/intl/include/number_format_addon.h",
        "blob": "216b68e9e1ba22c1c478b5966ebc713fe00e5bfe",
        "sha256": "a2548ed27d5e424132a1ed16cde48fdedb1e85dc89f504ab86f7267f57a20389",
        "cli": "d52_cli.json",
        "parse_count": 2,
    },
}


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True, encoding="utf-8").strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--object-db-root", required=True, type=pathlib.Path)
    parser.add_argument("--source-checkout-root", required=True, type=pathlib.Path)
    parser.add_argument("--a0-queue", required=True, type=pathlib.Path)
    parser.add_argument("--scanner-root", required=True, type=pathlib.Path)
    parser.add_argument("--evidence-dir", type=pathlib.Path, default=pathlib.Path(__file__).parent)
    args = parser.parse_args()

    summary = json.loads((args.evidence_dir / "summary.json").read_text(encoding="utf-8"))
    assert run("git", "-C", str(args.scanner_root), "rev-parse", "HEAD") == BASELINE
    assert summary["scanner"]["commit"] == BASELINE
    assert summary["integration_base"] == "6286eabd7b1da2ab83d7b2b03cf26ce5a331846d"

    queue_bytes = args.a0_queue.read_bytes()
    assert hashlib.sha256(queue_bytes).hexdigest() == QUEUE_SHA256 == summary["a0_queue"]["sha256"]
    with args.a0_queue.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = reader.fieldnames or []
        rows = list(reader)
    assert len(rows) == 345 and len({row.get("review_id") for row in rows}) == 345
    by_id = {row["review_id"]: row for row in rows}
    assert "queue_status" not in fields

    for review_id, expected in CASES.items():
        row = by_id[review_id]
        assert row["repository"] == expected["repository"]
        assert row["commit"] == expected["commit"]
        assert row["git_tree"] == expected["tree"]
        assert row["snapshot_sha256"] == expected["snapshot"]
        assert row["candidate_id"] == expected["candidate"]
        assert row["file"] == expected["path"]
        assert row["original_final_status"] == "not_testable"

        bare = args.object_db_root / f"{expected['repo']}.git"
        commit = expected["commit"]
        assert run("git", f"--git-dir={bare}", "rev-parse", f"{commit}^{{commit}}") == commit
        commit_lines = run("git", f"--git-dir={bare}", "cat-file", "-p", commit).splitlines()
        assert commit_lines[0] == f"tree {expected['tree']}"
        assert run("git", f"--git-dir={bare}", "rev-parse", f"{commit}:{expected['path']}") == expected["blob"]
        source = subprocess.check_output(["git", f"--git-dir={bare}", "show", f"{commit}:{expected['path']}"])
        assert hashlib.sha256(source).hexdigest() == expected["sha256"]

        checkout = args.source_checkout_root / expected["repo"]
        assert run("git", "-C", str(checkout), "rev-parse", "HEAD") == commit
        assert run("git", "-C", str(checkout), "rev-parse", "HEAD^{tree}") == expected["tree"]
        checkout_source = subprocess.check_output(["git", "-C", str(checkout), "show", f"HEAD:{expected['path']}"])
        assert hashlib.sha256(checkout_source).hexdigest() == expected["sha256"]

    for cli_name, expected_commit, expected_tree, expected_repo, parse_count, source_files in (
        ("d51_cli.json", CASES["CR-0341"]["commit"], CASES["CR-0341"]["tree"], "openharmony/security_huks", 1, 1),
        ("d52_cli.json", CASES["CR-0255"]["commit"], CASES["CR-0255"]["tree"], "openharmony/global_i18n", 2, 2),
    ):
        result = json.loads((args.evidence_dir / cli_name).read_text(encoding="utf-8"))
        assert result["repository"] == expected_repo
        assert result["commit"] == expected_commit
        assert result["git_tree"] == expected_tree
        assert result["scope"]["selected_source_files"] == source_files
        assert result["source_parsing"]["parsing_status"] == {"complete": parse_count}
        assert result["diagnostic_count"] == 0
        assert result["detector_count"] == 1
        detector = result["detector_runs"][0]
        assert detector["tool"] == "ohscanner.cpp.shared_ptr_race"
        assert detector["tool_version"] == "0.5.1"
        assert detector["status"] == "completed" and detector["diagnostic_count"] == 0
        coverage = result["detector_coverage"]["detectors"]["ohscanner.cpp.shared_ptr_race"]
        assert coverage["status"] == "complete"
        assert coverage["coverage_counts"]["complete"] == parse_count
        md_name = cli_name.replace(".json", ".md")
        assert (args.evidence_dir / md_name).is_file()

    assert summary["a0_queue"]["modified"] is False
    assert summary["historical_artifacts"]["modified"] is False
    print("PASS T5: source bare object commits/trees/blobs/file SHA-256 match all three frozen A0 rows")
    print("PASS T5: detached source checkouts and CLI commit/scope/parse/coverage/rule identities match")
    print("PASS T5: frozen A0 queue has 345 unique IDs; the three original statuses remain not_testable")
    print("RESULT T5: all three current replays have 0 findings; retain PARTIAL/BLOCK, not safe")
    print("LIMIT T5: historical 2026-10-29 run dates remain BLOCK; fresh replay does not authenticate old execution")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

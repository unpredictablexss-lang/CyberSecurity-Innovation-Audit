#!/usr/bin/env python3
"""Verify T4 source bindings, frozen A0 rows, and exact-source CLI replays."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pathlib
import subprocess


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
        "cli": "d52_a0_pin_cli.json",
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
        "cli": "d52_a0_pin_cli.json",
        "parse_count": 2,
    },
}


def git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.check_output(["git", "--git-dir", str(repo), *args], text=True, encoding="utf-8").strip()


def git_cwd(checkout: pathlib.Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(checkout), *args], text=True, encoding="utf-8").strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--object-db-root", required=True, type=pathlib.Path,
                        help="OpenHarmony .repo/project-objects directory")
    parser.add_argument("--d52-source-checkout", required=True, type=pathlib.Path,
                        help="Read-only exact A0 global_i18n checkout, used only as fallback evidence")
    parser.add_argument("--a0-queue", required=True, type=pathlib.Path,
                        help="Read-only frozen candidate_triage_queue.csv")
    parser.add_argument("--evidence-dir", type=pathlib.Path, default=pathlib.Path(__file__).parent)
    args = parser.parse_args()
    data = json.loads((args.evidence_dir / "t4_d51_d52_source_sha_20261020.json").read_text(encoding="utf-8"))

    with args.a0_queue.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = reader.fieldnames or []
        rows = list(reader)
    ids = [row.get("review_id") for row in rows]
    assert len(rows) == data["a0_queue"]["row_count"] == 345
    assert len(set(ids)) == len(ids) == 345
    counts: dict[str, int] = {}
    for row in rows:
        status = row.get("original_final_status", "")
        counts[status] = counts.get(status, 0) + 1
    assert counts == data["a0_queue"]["original_final_status_counts"]
    assert ("queue_status" in fields) == data["a0_queue"]["queue_status_column_present"]
    by_id = {row["review_id"]: row for row in rows}

    for review_id, expected in CASES.items():
        repo = args.object_db_root / f"{expected['repo']}.git"
        commit = expected["commit"]
        bare_has_commit = subprocess.run(
            ["git", "--git-dir", str(repo), "cat-file", "-e", f"{commit}^{{commit}}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        ).returncode == 0
        checkout = args.d52_source_checkout
        if bare_has_commit:
            assert git(repo, "rev-parse", commit) == commit
            tree_line = subprocess.check_output(["git", "--git-dir", str(repo), "cat-file", "-p", commit], text=True, encoding="utf-8").splitlines()[0]
            assert tree_line == f"tree {expected['tree']}"
            blob = git(repo, "rev-parse", f"{commit}:{expected['path']}")
            source = subprocess.check_output(["git", "--git-dir", str(repo), "show", f"{commit}:{expected['path']}"])
        else:
            # Keep checkout evidence explicitly separate from bare-object provenance.
            assert review_id in {"CR-0255", "CR-0256"}
            assert git_cwd(checkout, "rev-parse", "HEAD") == commit
            tree_line = subprocess.check_output(["git", "-C", str(checkout), "cat-file", "-p", "HEAD"], text=True, encoding="utf-8").splitlines()[0]
            assert tree_line == f"tree {expected['tree']}"
            blob = git(checkout, "rev-parse", f"HEAD:{expected['path']}")
            source = subprocess.check_output(["git", "-C", str(checkout), "show", f"HEAD:{expected['path']}"])
        assert blob == expected["blob"]
        assert hashlib.sha256(source).hexdigest() == expected["sha256"]

        row = by_id[review_id]
        assert row["repository"] == expected["repository"]
        assert row["commit"] == commit and row["git_tree"] == expected["tree"]
        assert row["snapshot_sha256"] == expected["snapshot"]
        assert row["candidate_id"] == expected["candidate"] and row["file"] == expected["path"]
        assert row["original_final_status"] == "not_testable"

    for cli_name, expected in (("d51_cli.json", CASES["CR-0341"]), ("d52_a0_pin_cli.json", CASES["CR-0255"])):
        cli = json.loads((args.evidence_dir / cli_name).read_text(encoding="utf-8"))
        assert cli["repository"] == expected["repository"]
        assert cli["commit"] == expected["commit"]
        assert cli.get("git_tree", cli.get("scope", {}).get("git_tree")) == expected["tree"]
        assert cli["source_parsing"]["parsing_status"] == {"complete": expected["parse_count"]}
        runs = [run for run in cli["detector_runs"] if run["tool"] == data["detector"]]
        assert len(runs) == 1
        run = runs[0]
        assert run["tool_version"] == data["detector_version"]
        assert run["status"] == "completed" and run["diagnostic_count"] == 0
        assert all(item["status"] == "complete" for item in run["parsing"])

    print("PASS T4: D51 A0 commit/tree/blob/SHA-256 verified from local bare object DB")
    print("BLOCK T4: D52 exact A0 commit absent from local bare object DB; checkout Git context independently resolves commit/tree/blob/SHA-256")
    print("PASS T4: exact-A0 current shared_ptr_race CLI replays complete with 0 diagnostics")
    print("PASS T4: A0 queue has 345 unique IDs; original status distribution is 336 not_testable / 9 not_reproduced")
    print("LIMIT T4: queue_status column absent; 345-row paired queue-state preservation cannot be independently verified from this CSV")
    print("LIMIT T4: historical D52 exact-A0 commit/tree binding is stale/mismatched; historical run date remains unverified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

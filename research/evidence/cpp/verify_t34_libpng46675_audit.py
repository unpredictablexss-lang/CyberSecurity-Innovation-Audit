"""Independent integrity checks for T34 libpng CVE-2026-46675 evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
EXPECTED = {
    "vulnerable": {
        "commit": "c3e304954a9cfd154bc0dfbfea2b01cd61d6546d",
        "tree": "e01f5780f93eaa6d74cca003bb39b427c8f1e910",
        "blob": "a4eda54c8cb3d36cf1651dba159067b65030e3aa",
        "sha256": "b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e",
        "bytes": 153112,
        "cli": "t34_libpng46675_vulnerable_cli_20261023.json",
    },
    "fixed": {
        "commit": "aa77ef38c17ab2fc1b41bec09fb973c6a386641d",
        "tree": "4c64b5f18cef7d129adee3b403fc4be93f82e30d",
        "blob": "482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a",
        "sha256": "a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e",
        "bytes": 152477,
        "cli": "t34_libpng46675_fixed_cli_20261023.json",
    },
}
EXPECTED_FUNCTIONS = {
    "png_inflate_claim", "png_inflate", "png_decompress_chunk", "png_inflate_read",
    "png_handle_iCCP", "png_handle_zTXt", "png_read_IDAT_data",
}


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def git(git_dir: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", f"--git-dir={git_dir}", *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return result.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-dir", type=Path, required=True)
    args = parser.parse_args()
    git_dir = args.git_dir.resolve()
    evidence = ROOT / "research/evidence/cpp"
    report = read_json(evidence / "t34_libpng46675_independent_audit_20261023.json")
    checks: dict[str, bool] = {}

    for variant, expected in EXPECTED.items():
        commit_line = git(git_dir, "show", "-s", "--format=%H %T %P", expected["commit"])
        fields = commit_line.split()
        checks[f"{variant}_commit_tree_identity"] = (
            len(fields) >= 2 and fields[0] == expected["commit"] and fields[1] == expected["tree"]
        )
        if variant == "fixed":
            checks["fixed_commit_parent_identity"] = len(fields) >= 3 and fields[2] == "4eeb825ab26605ed34cd74495d4cce920939fe9f"
        ls_tree = git(git_dir, "ls-tree", expected["commit"], "pngrutil.c")
        checks[f"{variant}_path_blob_identity"] = ls_tree.endswith("\tpngrutil.c") and expected["blob"] in ls_tree
        source = subprocess.run(
            ["git", f"--git-dir={git_dir}", "show", f"{expected['commit']}:pngrutil.c"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        checks[f"{variant}_source_sha_and_size"] = (
            hashlib.sha256(source).hexdigest() == expected["sha256"]
            and len(source) == expected["bytes"]
        )
        cli = read_json(evidence / expected["cli"])
        run = cli["detector_runs"][0]
        checks[f"{variant}_cli_source_binding"] = (
            cli["commit"] == expected["commit"]
            and cli["git_tree"] == expected["tree"]
            and cli["scope"]["declared_scope"] == ["pngrutil.c"]
            and cli["scope"]["selected_source_files"] == 1
            and cli["scope"]["selected_source_bytes"] == expected["bytes"]
        )
        checks[f"{variant}_cli_detector_and_partial_outcome"] = (
            run["tool"] == "ohscanner.cpp.resource_lifetime"
            and run["tool_version"] == "0.4.2"
            and run["status"] == "blocked"
            and run["diagnostic_count"] == 0
            and cli["diagnostic_count"] == 0
            and cli["source_parsing"]["parsing_status"] == {"partial": 1}
            and len(run["parsing"]) == 1
            and run["parsing"][0]["file"] == "pngrutil.c"
            and run["parsing"][0]["status"] == "partial"
            and len(run["parsing"][0]["issues"]) == 72
        )

    fragments = read_json(evidence / "t34_libpng46675_d12_fragment_replay_20261023.json")
    case_runs = [r for r in fragments["runs"] if r["case"] == "CVE-2026-46675"]
    checks["fragment_replay_has_both_exact_variants"] = {r["variant"] for r in case_runs} == {"vulnerable", "fixed"}
    for run in case_runs:
        names = {item["function"] for item in run["files"]}
        checks[f"{run['variant']}_fragment_function_set"] = names == EXPECTED_FUNCTIONS
        checks[f"{run['variant']}_fragment_coverage_and_quietness"] = (
            len(run["files"]) == 7
            and sum(item["fragment_parse_status"] == "complete" for item in run["files"]) == 6
            and sum(item["fragment_parse_status"] == "partial" for item in run["files"]) == 1
            and next(item for item in run["files"] if item["function"] == "png_handle_iCCP")["fragment_parse_status"] == "partial"
            and all(item["whole_translation_unit_parse_status"] == "partial" for item in run["files"])
            and all(item["finding_count"] == 0 for item in run["files"])
        )
        checks[f"{run['variant']}_fragment_source_binding"] = all(
            item["source_sha256"] == EXPECTED[run["variant"]]["sha256"]
            and item["detector_version"] == "0.4.2"
            for item in run["files"]
        )

    checks["audit_preserves_partial_block"] = report["status"] == "PARTIAL/BLOCK"
    checks["audit_does_not_claim_full_lifecycle_closure"] = (
        not report["candidate_positions"]
        and report["a0_queue"]["changed"] is False
        and "not a validated fixed differential" in report["full_file_cli"]["interpretation"]
    )
    failed = [name for name, ok in checks.items() if not ok]
    print(json.dumps({"checks": checks, "failed": failed, "overall_ok": not failed}, indent=2))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

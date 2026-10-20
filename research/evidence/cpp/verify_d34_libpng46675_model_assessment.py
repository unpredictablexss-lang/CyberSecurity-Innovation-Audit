"""Validate D34's pinned-source identities, CLI states, and fragment controls."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp/d34_libpng46675_model_assessment_20261024.json"
EXPECTED = {
    "vulnerable": ("c3e304954a9cfd154bc0dfbfea2b01cd61d6546d", "e01f5780f93eaa6d74cca003bb39b427c8f1e910", "a4eda54c8cb3d36cf1651dba159067b65030e3aa", "b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e"),
    "fixed": ("aa77ef38c17ab2fc1b41bec09fb973c6a386641d", "4c64b5f18cef7d129adee3b403fc4be93f82e30d", "482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a", "a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e"),
}


def git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-c", "remote.origin.promisor=false", "-C", str(repo), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                            env={**__import__("os").environ, "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": ""})
    if result.returncode:
        raise AssertionError(result.stderr.decode("utf-8", "replace")[:400])
    return result.stdout


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print("PASS", message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    check(report["baseline"] == "1cb2178c88715b6c8f908ac7826cb684a35730f7", "D34 baseline is the requested integration base")
    check(report["detector"] == "ohscanner.cpp.resource_lifetime" and report["detector_version"] == "0.4.2", "current resource-lifetime detector identity is recorded")
    for variant, (commit, tree, blob, digest) in EXPECTED.items():
        identity = report["source_identities"][variant]
        check(identity["commit"] == commit and identity["tree"] == tree, f"{variant} commit and tree match pinned D14 identity")
        check(git(args.source_git_dir, "rev-parse", f"{commit}^{{tree}}").decode().strip() == tree, f"{variant} tree exists in source mirror")
        source = identity["files"]["pngrutil.c"]
        content = git(args.source_git_dir, "show", f"{commit}:pngrutil.c")
        actual_blob = git(args.source_git_dir, "rev-parse", f"{commit}:pngrutil.c").decode().strip()
        check(source["blob"] == blob and source["sha256"] == digest and actual_blob == blob and hashlib.sha256(content).hexdigest() == digest, f"{variant} pngrutil blob and SHA-256 match")
        cli = report["production_cli"][variant]
        check(cli["commit"] == commit and cli["tree"] == tree and cli["source_sha256"] == digest, f"{variant} production CLI is bound to exact source")
        check(cli["detector_version"] == "0.4.2" and cli["detector_status"] == "blocked" and cli["coverage_status"] == "partial" and cli["finding_count"] == 0, f"{variant} CLI remains blocked/partial with zero findings")
        rows = report["fragments"][variant]
        check(len(rows) == 7 and sum(row["fragment_parse_status"] == "complete" for row in rows) == 6 and sum(row["fragment_parse_status"] == "partial" for row in rows) == 1, f"{variant} has six complete and one partial target fragments")
        check(all(row["finding_count"] == 0 for row in rows) and next(row for row in rows if row["function"] == "png_handle_iCCP")["fragment_parse_status"] == "partial", f"{variant} fragment results preserve iCCP partial and zero findings")
    model = report["source_model_assessment"]
    check(model["current_parser_proves_interprocedural_same_object_field_reuse"] is False, "parser model does not claim interprocedural same-object proof")
    check(model["decision"] == "NO_RULE_CHANGE_PARTIAL_BLOCK", "no detector change and PARTIAL/BLOCK disposition are explicit")
    print("D34 libpng 46675 model assessment: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

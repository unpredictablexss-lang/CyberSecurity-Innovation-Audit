from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


SOURCE = "arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc"
CASES = {
    "vulnerable": {
        "commit": "a15cbf4ef20673cfcf1856bf40a723b3ce026564",
        "tree": "03e16f6f4f2c33c2cd08e31c14e00be689230c39",
        "blob": "78e83fea67a2db3297cc59f07566a0c0b6153e7a",
        "sha256": "aa401c305ed30b70007917d97b726986a26aff2d00fb49649466533f4a48a920",
    },
    "fixed": {
        "commit": "fa0d92ccbf47b7cdc7efb727c79cbdfc168469eb",
        "tree": "9873e4146e4a521b80f05a61c24d9c6047f696a7",
        "blob": "27e93e338ced03aeed6e7d892e29d4d0740f3653",
        "sha256": "332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483",
    },
}
EVIDENCE = Path(__file__).parent / "webview_exact_a0_20261020"


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True, encoding="utf-8").strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", required=True, type=Path)
    args = parser.parse_args()
    errors: list[str] = []
    for side, expected in CASES.items():
        commit = expected["commit"]
        tree = git(args.source_git_dir, "rev-parse", f"{commit}^{{tree}}")
        blob = git(args.source_git_dir, "rev-parse", f"{commit}:{SOURCE}")
        source = subprocess.check_output(["git", "-C", str(args.source_git_dir), "show", f"{commit}:{SOURCE}"])
        source_sha = hashlib.sha256(source).hexdigest()
        if (tree, blob, source_sha) != (expected["tree"], expected["blob"], expected["sha256"]):
            errors.append(f"{side}: Git tree/blob/source SHA mismatch")

        report = json.loads((EVIDENCE / f"{side}.json").read_text(encoding="utf-8"))
        if (report.get("repository"), report.get("commit"), report.get("git_tree")) != (
            "openharmony/web_webview", commit, tree
        ):
            errors.append(f"{side}: CLI repository/commit/tree mismatch")
        if report.get("scope", {}).get("declared_scope") != [SOURCE]:
            errors.append(f"{side}: CLI scope mismatch")
        if report.get("source_parsing", {}).get("parsing_status") != {"partial": 1}:
            errors.append(f"{side}: expected one partial target file")
        runs = [r for r in report.get("detector_runs", []) if r.get("tool") == "ohscanner.cpp.bounds"]
        if len(runs) != 1:
            errors.append(f"{side}: expected one bounds detector run")
            continue
        run = runs[0]
        if run.get("tool_version") != "0.3.0" or run.get("status") != "blocked":
            errors.append(f"{side}: detector identity/status mismatch")
        if run.get("diagnostic_count") != 0 or run.get("parsing", [{}])[0].get("status") != "partial":
            errors.append(f"{side}: expected partial parse and zero findings")
        if report.get("status") != "completed_with_limitations":
            errors.append(f"{side}: expected completed_with_limitations aggregate status")

    result = {"source_pair_identity": "PASS" if not errors else "FAIL", "current_cli_outcome": "PARTIAL_BLOCK", "errors": errors}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())

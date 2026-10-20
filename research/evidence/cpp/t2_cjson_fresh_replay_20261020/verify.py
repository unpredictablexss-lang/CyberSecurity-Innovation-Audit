from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


SCANNER_HEAD = "81dd4aea9bb51522ac912b33504ef0d2ddb79089"
SOURCE_COMMIT = "0c2c9dff82cc85539c8362132d7a5f6bf7d1e748"
SOURCE_TREE = "0d8e50cc18f9ae178e9969eed40f8a0c94fb3856"
EXPECTED = {
    "cJSON.c": {
        "blob": "152b2caa479c9f448001652913c980a6dafb82e0",
        "sha256": "427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb",
        "parse": "partial",
    },
    "cJSON_Utils.c": {
        "blob": "8fa24f8e9bf452cf1ba49d1325c85423ce742c74",
        "sha256": "bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9",
        "parse": "complete",
    },
}


def git(git_dir: str, *args: str) -> str:
    return subprocess.check_output(
        ["git", f"--git-dir={git_dir}", *args], text=True, encoding="utf-8"
    ).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", required=True)
    parser.add_argument("--evidence-dir", type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    errors: list[str] = []

    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if head != SCANNER_HEAD:
        errors.append(f"scanner HEAD {head} != frozen {SCANNER_HEAD}")

    commit_line = git(args.source_git_dir, "show", "-s", "--format=%H %T", SOURCE_COMMIT)
    if commit_line != f"{SOURCE_COMMIT} {SOURCE_TREE}":
        errors.append(f"source commit/tree mismatch: {commit_line}")

    report_path = args.evidence_dir / "cli.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("commit") != SOURCE_COMMIT or report.get("repository") != "openharmony/third_party_cJSON":
        errors.append("CLI source repository/commit mismatch")
    scope = report.get("scope", {})
    if scope.get("git_tree") != SOURCE_TREE or scope.get("declared_scope") != ["cJSON.c", "cJSON_Utils.c"]:
        errors.append("CLI tree or exact scope mismatch")
    if scope.get("selected_source_files") != 2 or scope.get("selected_source_bytes") != 121265:
        errors.append("CLI selected source file/byte count mismatch")

    for name, expected in EXPECTED.items():
        blob = git(args.source_git_dir, "rev-parse", f"{SOURCE_COMMIT}:{name}")
        source = subprocess.check_output(
            ["git", f"--git-dir={args.source_git_dir}", "show", f"{SOURCE_COMMIT}:{name}"]
        )
        digest = hashlib.sha256(source).hexdigest()
        if blob != expected["blob"] or digest != expected["sha256"]:
            errors.append(f"source identity mismatch for {name}: {blob} / {digest}")

    run = report.get("detector_runs", [{}])[0]
    if (run.get("tool"), run.get("tool_version"), run.get("status"), run.get("diagnostic_count")) != (
        "ohscanner.cpp.resource_lifetime", "0.4.2", "blocked", 3
    ):
        errors.append("detector/version/status/count mismatch")
    actual = sorted(
        (d.get("file"), d.get("line"), d.get("rule_id")) for d in run.get("diagnostics", [])
    )
    expected_findings = sorted(
        [
            ("cJSON.c", 3161, "ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005"),
            ("cJSON_Utils.c", 932, "ohcpp-resource-exhaustion-tree-amplification-candidate-004"),
            ("cJSON_Utils.c", 950, "ohcpp-resource-exhaustion-tree-amplification-candidate-004"),
        ]
    )
    if actual != expected_findings:
        errors.append(f"finding tuples mismatch: {actual}")
    parse = {item["file"]: item["status"] for item in run.get("parsing", [])}
    if parse != {name: item["parse"] for name, item in EXPECTED.items()}:
        errors.append(f"parse states mismatch: {parse}")
    coverage = report.get("detector_coverage", {}).get("detectors", {}).get("ohscanner.cpp.resource_lifetime", {})
    if coverage.get("status") != "partial" or coverage.get("analyzed_files") != []:
        errors.append("detector coverage is not the recorded partial state")

    if errors:
        print(json.dumps({"status": "FAIL", "errors": errors}, indent=2))
        return 1
    print(json.dumps({"status": "PASS_SOURCE_BOUND_FRESH_REPLAY", "scanner_head": head,
                      "source_commit": SOURCE_COMMIT, "findings": actual,
                      "parse": parse, "disposition": "PARTIAL/BLOCK"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

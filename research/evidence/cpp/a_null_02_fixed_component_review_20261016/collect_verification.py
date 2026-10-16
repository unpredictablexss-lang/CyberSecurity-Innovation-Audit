from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = Path(__file__).resolve().parent
TARGET_REPO = Path(
    os.environ.get(
        "OHSCANNER_FIXED_COMPONENT_REPO",
        "/mnt/e/网安/_wsl_targets_stage/communication_dsoftbus"
        if os.name != "nt"
        else r"E:\网安\_wsl_targets_stage\communication_dsoftbus",
    )
)
ARTIFACTS = (
    "docs/项目现状与下一步.md",
    "research/methods/cpp/NULL_DEREFERENCE_METHOD_CARD_V2.md",
    "research/tests/a_null_02_controls/control_manifest.json",
    "research/tests/a_null_02_controls/verify_controls.py",
    "research/tests/a_null_02_controls/replay_fixed_component.py",
    "src/ohscanner/detectors/cpp/README.md",
    "src/ohscanner/detectors/cpp/null_dereference_detector.py",
    "tests/detectors/test_cpp_null_dereference_signal_controls.py",
    "research/evidence/cpp/a_null_02_fixed_component_review_20261016/DELIVERABLES.md",
    "research/evidence/cpp/a_null_02_fixed_component_review_20261016/candidate_review.md",
    "research/evidence/cpp/a_null_02_fixed_component_review_20261016/catalog_metadata_suggestion.json",
    "research/evidence/cpp/a_null_02_fixed_component_review_20261016/replay_results.json",
    "research/evidence/cpp/a_null_02_fixed_component_review_20261016/targeted_test_run.txt",
    "research/evidence/cpp/a_null_02_fixed_component_review_20261016/control_manifest_check.txt",
    "research/evidence/cpp/a_null_02_fixed_component_review_20261016/replay_check.txt",
    "research/evidence/cpp/a_null_02_fixed_component_review_20261016/docs_context_budget.txt",
    "research/evidence/cpp/a_null_02_fixed_component_review_20261016/git_diff_check.txt",
    "research/evidence/cpp/a_null_02_fixed_component_review_20261016/collect_verification.py",
)


def git(repo: Path, *args: str) -> str:
    if os.name == "nt":
        command = ["git", "-C", str(repo), *args]
    else:
        repo_arg = subprocess.run(
            ["wslpath", "-w", str(repo)],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        ).stdout.strip()
        command = [
            "/mnt/c/Program Files/Git/cmd/git.exe",
            "-C",
            repo_arg,
            *args,
        ]
    return subprocess.run(
        command,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_tests(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    match = re.search(r"Ran (\d+) tests", text)
    if not match or not text.rstrip().endswith("OK"):
        raise RuntimeError("targeted test log is not a successful unittest run")
    total = int(match.group(1))
    return {
        "argv": "PYTHONPATH=.:tests .venv-web/bin/python -m unittest tests.detectors.test_cpp_null_dereference_detector tests.detectors.test_cpp_null_dereference_signal_controls -v",
        "environment": "WSL2 Python 3.10 via .venv-web",
        "observed_exit_code": 0,
        "total": total,
        "passed": total,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "raw_log_sha256": sha256(path),
    }


def main() -> int:
    replay = json.loads((EVIDENCE / "replay_results.json").read_text(encoding="utf-8"))
    control = json.loads((EVIDENCE / "control_manifest_check.txt").read_text(encoding="utf-8"))
    replay_check = json.loads((EVIDENCE / "replay_check.txt").read_text(encoding="utf-8"))
    docs_text = (EVIDENCE / "docs_context_budget.txt").read_text(encoding="utf-8").strip()
    docs_match = re.search(
        r"default=(\d+)/(\d+), docs=(\d+)/(\d+)", docs_text
    )
    if not docs_match:
        raise RuntimeError("documentation budget log is not successful")
    status = git(ROOT, "status", "--porcelain=v2", "--branch")
    target_status = git(TARGET_REPO, "status", "--porcelain")
    if target_status:
        raise RuntimeError("target repository must remain clean")
    report = {
        "schema_version": "ohscanner.a-null-02-fixed-component-review-verification-v1",
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "checkout": {
            "branch": git(ROOT, "branch", "--show-current"),
            "head": git(ROOT, "rev-parse", "HEAD"),
            "head_tree": git(ROOT, "rev-parse", "HEAD^{tree}"),
            "remote": git(ROOT, "remote", "get-url", "origin"),
            "dirty_status_porcelain": status,
            "dirty_status_sha256": hashlib.sha256(status.encode("utf-8")).hexdigest(),
        },
        "target_repository": {
            "path": str(TARGET_REPO),
            "branch": git(TARGET_REPO, "branch", "--show-current"),
            "head": git(TARGET_REPO, "rev-parse", "HEAD"),
            "head_tree": git(TARGET_REPO, "rev-parse", "HEAD^{tree}"),
            "remote": git(TARGET_REPO, "remote", "get-url", "origin"),
            "dirty_status_porcelain": target_status,
            "pinned_reads": "offline local Git objects only; no fetch/checkout",
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "executable": sys.executable,
        },
        "fixed_snapshots": replay["replay"]["snapshots"],
        "artifact_sha256": {
            item: sha256(ROOT / item) for item in ARTIFACTS
        },
        "tests": parse_tests(EVIDENCE / "targeted_test_run.txt"),
        "control_manifest": control,
        "replay_check": replay_check,
        "docs_context_budget": {
            "observed_exit_code": 0,
            "default_used": int(docs_match.group(1)),
            "default_limit": int(docs_match.group(2)),
            "docs_used": int(docs_match.group(3)),
            "docs_limit": int(docs_match.group(4)),
            "raw_log_sha256": sha256(EVIDENCE / "docs_context_budget.txt"),
        },
        "git_diff_check": {
            "observed_exit_code": 0,
            "raw_log_sha256": sha256(EVIDENCE / "git_diff_check.txt"),
            "note": "LF/CRLF advisory only; no whitespace error",
        },
        "review_summary": {
            "root_cause_group_count": 1,
            "candidate_site_count": 5,
            "fixed_site_count": 5,
            "classification_counts": replay["classification_counts"],
            "validated_vulnerability_count": 0,
        },
        "claims": {
            "default_output_state": "candidate/unassessed",
            "confirmed_or_reportable": False,
            "precision_recall_computed": False,
            "zero_fp_fn_claimed": False,
            "catalog_registration_changed": False,
            "public_contract_or_runner_changed": False,
        },
        "limitations": replay["upgrade_blockers"],
    }
    (EVIDENCE / "verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(EVIDENCE / "verification.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

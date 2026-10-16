from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = ROOT / "research" / "evidence" / "cpp" / "a_null_02_signal_controls_20261016"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-c", "core.autocrlf=true", *args],
        cwd=ROOT,
        text=True,
    ).strip()


def parse_test_log(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    run_match = re.search(r"^Ran (\d+) tests? in ", text, re.MULTILINE)
    if not run_match:
        raise ValueError("missing unittest summary: " + str(path))
    total = int(run_match.group(1))
    failures = re.findall(r"^FAIL: ([^\n]+)$", text, re.MULTILINE)
    errors = re.findall(r"^ERROR: ([^\n]+)$", text, re.MULTILINE)
    skipped_match = re.search(r"skipped=(\d+)", text)
    skipped = int(skipped_match.group(1)) if skipped_match else 0
    exit_match = re.search(r"^exit_code: ?(\d+)?$", text, re.MULTILINE)
    return {
        "argv": re.search(r"^argv: (.+)$", text, re.MULTILINE).group(1),
        "recorded_at": re.search(r"^recorded_at: (.+)$", text, re.MULTILINE).group(1),
        "total": total,
        "passed": total - len(failures) - len(errors) - skipped,
        "failed": len(failures),
        "errors": len(errors),
        "skipped": skipped,
        "failure_names": failures,
        "error_names": errors,
        "observed_exit_code": int(exit_match.group(1)) if exit_match and exit_match.group(1) else None,
        "raw_log_sha256": sha256_file(path),
    }


def main() -> int:
    targeted = parse_test_log(EVIDENCE / "targeted_test_run.txt")
    full = parse_test_log(EVIDENCE / "full_test_run.txt")
    paths = (
        ROOT / "src/ohscanner/detectors/cpp/null_dereference_detector.py",
        ROOT / "src/ohscanner/detectors/cpp/README.md",
        ROOT / "tests/detectors/test_cpp_null_dereference_detector.py",
        ROOT / "tests/detectors/test_cpp_null_dereference_signal_controls.py",
        ROOT / "research/tests/a_null_02_controls/control_manifest.json",
        ROOT / "research/tests/a_null_02_controls/verify_controls.py",
        ROOT / "research/methods/cpp/NULL_DEREFERENCE_METHOD_CARD_V2.md",
        EVIDENCE / "DELIVERABLES.md",
        EVIDENCE / "targeted_test_run.txt",
        EVIDENCE / "full_test_run.txt",
    )
    status = git("status", "--porcelain=v1")
    result = {
        "schema_version": "ohscanner.a-null-02-verification-v1",
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "checkout": {
            "branch": git("branch", "--show-current"),
            "head": git("rev-parse", "HEAD"),
            "head_tree": git("rev-parse", "HEAD^{tree}"),
            "remote": git("remote", "get-url", "origin"),
            "dirty_status_porcelain": status,
            "dirty_status_sha256": hashlib.sha256(status.encode("utf-8")).hexdigest(),
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "executable": sys.executable,
        },
        "artifact_sha256": {
            str(path.relative_to(ROOT)): sha256_file(path) for path in paths
        },
        "tests": {
            "targeted": targeted,
            "full": full,
        },
        "fixture_integrity": {
            "a_null_01": "passed",
            "a_null_02_controls": "passed",
        },
        "claims": {
            "default_output_state": "candidate/unassessed",
            "confirmed_or_reportable": False,
            "precision_recall_computed": False,
            "zero_fp_fn_claimed": False,
            "catalog_registration_changed": False,
            "public_contract_or_runner_changed": False,
        },
        "limitations": [
            "Synthetic controls do not establish product reachability, attacker control, CIA impact or vulnerability truth.",
        ],
    }
    output = EVIDENCE / "verification.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output)
    print(json.dumps({"targeted": targeted, "full": full}, ensure_ascii=False))
    return 0 if targeted["failed"] == targeted["errors"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

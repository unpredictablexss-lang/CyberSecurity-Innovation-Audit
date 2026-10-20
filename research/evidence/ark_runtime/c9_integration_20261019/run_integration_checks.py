#!/usr/bin/env python3
"""Run bounded integration checks and record exact argv/env, wall time and child RSS."""
from __future__ import annotations

import json
import os
import resource
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit-c-line-opt-20261019")
OUT = REPO / "research/evidence/ark_runtime/c9_integration_20261019"
LOGS = OUT / "logs"
PY = "/usr/bin/python3"
BASE_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": str(OUT / ".home"),
    "TMPDIR": str(OUT / ".tmp"),
    "PYTHONPATH": "src",
    "PYTHONPYCACHEPREFIX": str(OUT / ".pycache"),
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
    "TZ": "Asia/Shanghai",
    "SOURCE_DATE_EPOCH": "0",
}
GIT_ENV = dict(BASE_ENV)
GIT_ENV.update({
    "GIT_DIR": "/mnt/e/网安/CyberSecurity-Innovation-Audit/.git/worktrees/CyberSecurity-Innovation-Audit-c-line-opt-20261019",
    "GIT_WORK_TREE": str(REPO),
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "safe.directory",
    "GIT_CONFIG_VALUE_0": str(REPO),
})


def tracked(pattern: str) -> list[str]:
    argv = ["/usr/bin/git", "-C", str(REPO), "ls-files", "-z", "--", pattern]
    raw = subprocess.check_output(argv, env=GIT_ENV)
    return [item.decode("utf-8") for item in raw.split(b"\0") if item]


def run(name: str, argv: list[str], *, expected: tuple[int, ...] = (0,), env: dict[str, str] | None = None) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    t0 = time.perf_counter()
    proc = subprocess.run(
        argv,
        cwd=REPO,
        env=env or BASE_ENV,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    wall = time.perf_counter() - t0
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    log = LOGS / f"{name}.log"
    log.write_bytes(
        b"--- stdout ---\n" + proc.stdout + b"\n--- stderr ---\n" + proc.stderr
    )
    observed_expected = proc.returncode in expected
    return {
        "name": name,
        "argv": argv,
        "cwd": str(REPO),
        "env": env or BASE_ENV,
        "expected_exit_codes": list(expected),
        "exit_code": proc.returncode,
        "expected_exit_observed": observed_expected,
        "status": "pass" if observed_expected else "fail",
        "started_at": started,
        "wall_seconds": wall,
        "child_max_rss_kib": after.ru_maxrss,
        "rss_measurement": "resource.getrusage(RUSAGE_CHILDREN).ru_maxrss after subprocess; Linux KiB; wrapper RSS excluded",
        "log": str(log.relative_to(REPO)),
        "stdout_bytes": len(proc.stdout),
        "stderr_bytes": len(proc.stderr),
    }


def main() -> int:
    LOGS.mkdir(parents=True, exist_ok=True)
    py_files = tracked("*.py")
    json_files = tracked("*.json")
    (OUT / "tracked_python_files.txt").write_text("\n".join(py_files) + "\n", encoding="utf-8")
    (OUT / "tracked_json_files.txt").write_text("\n".join(json_files) + "\n", encoding="utf-8")

    records = []
    records.append(run(
        "ark_runtime_full_unittest",
        [PY, "-B", "-m", "unittest", "discover", "-s", "tests/detectors/ark_runtime", "-t", ".", "-v"],
    ))
    records.append(run(
        "runner_catalog_contract_compat",
        [PY, "-B", "-m", "unittest", "-v",
         "tests.test_contract_v2_source_binding",
         "tests.test_ohscanner_contract",
         "tests.test_runner_applicability",
         "tests.test_ohscanner_m2",
         "tests.test_ohscanner_m2_a_integration"],
    ))
    records.append(run(
        "cpp_runner_integration",
        [PY, "-B", "-m", "unittest", "-v", "tests.detectors.test_cpp_runner_integration"],
    ))
    records.append(run(
        "python_py_compile",
        [PY, "-B", "-m", "py_compile", *py_files],
    ))
    records.append(run(
        "tracked_json_validation",
        [PY, "-B", str(OUT / "validate_json.py"), "--root", str(REPO),
         "--files-from", str(OUT / "tracked_json_files.txt"),
         "--output", str(OUT / "json_validation.json")],
    ))
    records.append(run(
        "docs_context_budget",
        [PY, "-B", "scripts/check_docs_context_budget.py"],
    ))
    records.append(run(
        "git_diff_check",
        ["/usr/bin/git", "-C", str(REPO), "diff", "--check"],
        env=GIT_ENV,
    ))
    records.append(run(
        "source_audit_reconciliation_default",
        [PY, "-B", "research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/reconcile.py"],
    ))
    records.append(run(
        "source_audit_reconciliation_strict",
        [PY, "-B", "research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/reconcile.py", "--strict-input"],
        expected=(3,),
    ))

    payload = {
        "schema": "c9-integration-check-records/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "checkout": str(REPO),
        "tracked_python_count": len(py_files),
        "tracked_json_count": len(json_files),
        "checks": records,
    }
    (OUT / "check-records.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if all(item["status"] == "pass" for item in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())



#!/usr/bin/env python3
"""C9 bounded acceptance runner. Writes only under c9_integration_20261019."""
from __future__ import annotations
import json, os, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit-c-line-opt-20261019")
OUT = REPO / "research/evidence/ark_runtime/c9_integration_20261019"
LOGS = OUT / "logs-c9-acceptance"
PY = "/usr/bin/python3"
BASE_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": str(OUT / ".home"),
    "TMPDIR": str(OUT / ".tmp"),
    "PYTHONPATH": "src",
    "PYTHONPYCACHEPREFIX": str(OUT / ".pycache-c9-acceptance"),
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
    "TZ": "Asia/Shanghai",
    "SOURCE_DATE_EPOCH": "0",
}
GIT_DIRS = {
    "/mnt/e/网安/CyberSecurity-Innovation-Audit-c-line-opt-20261019": "/mnt/e/网安/CyberSecurity-Innovation-Audit/.git/worktrees/CyberSecurity-Innovation-Audit-c-line-opt-20261019",
    "/mnt/e/网安/CyberSecurity-Innovation-Audit-c-line-latest-20261019": "/mnt/e/网安/CyberSecurity-Innovation-Audit/.git/worktrees/CyberSecurity-Innovation-Audit-c-line-latest-20261019",
    "/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard": "/mnt/e/网安/CyberSecurity-Innovation-Audit/.git/worktrees/exception-guard",
    "/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/partial-owner": "/mnt/e/网安/CyberSecurity-Innovation-Audit/.git/worktrees/partial-owner",
    "/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/type-origin": "/mnt/e/网安/CyberSecurity-Innovation-Audit/.git/worktrees/type-origin",
}

def git_env(path):
    env = dict(BASE_ENV)
    env.update({
        "GIT_DIR": GIT_DIRS[str(path)],
        "GIT_WORK_TREE": str(path),
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": "*",
    })
    return env

WORKTREES = {
    "local_7af": REPO,
    "remote_e4e": Path("/mnt/e/网安/CyberSecurity-Innovation-Audit-c-line-latest-20261019"),
    "parallel_exception_guard": Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard"),
    "parallel_partial_owner": Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/partial-owner"),
    "parallel_type_origin": Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/type-origin"),
}

def run(name, argv, cwd, expected=(0,), env=None):
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()
    p = subprocess.run(argv, cwd=cwd, env=env or BASE_ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    wall = time.perf_counter() - t0
    LOGS.mkdir(parents=True, exist_ok=True)
    log = LOGS / f"{name}.log"
    log.write_bytes(b"--- stdout ---\n" + p.stdout + b"\n--- stderr ---\n" + p.stderr)
    ok = p.returncode in expected
    return {
        "name": name, "argv": argv, "cwd": str(cwd), "env": env or BASE_ENV,
        "expected_exit_codes": list(expected), "exit_code": p.returncode,
        "expected_exit_observed": ok, "status": "pass" if ok else "fail",
        "started_at": started, "wall_seconds": wall,
        "log": str(log.relative_to(REPO)), "stdout_bytes": len(p.stdout), "stderr_bytes": len(p.stderr),
    }

def git_status(name, path):
    return run(name, ["/usr/bin/git", "-C", str(path), "status", "--short"], path, env=git_env(path))

def main():
    checks = []
    checks.append(run("local_7af_ark_focused", [PY, "-B", "-m", "unittest", "-v",
        "tests.detectors.ark_runtime.test_type_origin",
        "tests.detectors.ark_runtime.test_exception_guard",
        "tests.detectors.ark_runtime.test_parser_owner",
        "tests.detectors.ark_runtime.test_detector_cases",
        "tests.detectors.ark_runtime.test_historical"], WORKTREES["local_7af"]))
    checks.append(run("remote_e4e_ark_focused", [PY, "-B", "-m", "unittest", "discover", "-s", "tests/detectors/ark_runtime", "-t", ".", "-v"], WORKTREES["remote_e4e"]))
    checks.append(run("parallel_exception_guard_focused", [PY, "-B", "-m", "unittest", "-v",
        "tests.detectors.ark_runtime.test_exception_guard"], WORKTREES["parallel_exception_guard"]))
    checks.append(run("parallel_partial_owner_focused", [PY, "-B", "-m", "unittest", "-v",
        "tests.detectors.ark_runtime.test_parser_owner"], WORKTREES["parallel_partial_owner"]))
    checks.append(run("parallel_type_origin_focused", [PY, "-B", "-m", "unittest", "-v",
        "tests.detectors.ark_runtime.test_type_origin"], WORKTREES["parallel_type_origin"]))
    checks.append(run("runner_applicability", [PY, "-B", "-m", "unittest", "-v",
        "tests.test_runner_applicability"], REPO))
    checks.append(run("schema_legacy_compatibility", [PY, "-B", "-m", "unittest", "-v",
        "tests.test_contract_v2_source_binding",
        "tests.test_a_ccr_03_finding_identity",
        "tests.test_ohscanner_contract"], REPO))
    tracked_py = subprocess.check_output(["/usr/bin/git", "-C", str(REPO), "ls-files", "-z", "--", "*.py"], env=git_env(REPO)).decode("utf-8").split("\0")
    tracked_py = [p for p in tracked_py if p]
    checks.append(run("compileall_tracked_python", [PY, "-B", "-m", "compileall", "-q", "-f", *tracked_py], REPO))
    tracked_json = subprocess.check_output(["/usr/bin/git", "-C", str(REPO), "ls-files", "-z", "--", "*.json"], env=git_env(REPO)).decode("utf-8").split("\0")
    tracked_json = [p for p in tracked_json if p]
    (OUT / "tracked_json_files_c9_acceptance.txt").write_text("\n".join(tracked_json) + "\n", encoding="utf-8")
    checks.append(run("tracked_json_validation", [PY, "-B", str(OUT / "validate_json.py"), "--root", str(REPO),
        "--files-from", str(OUT / "tracked_json_files_c9_acceptance.txt"),
        "--output", str(OUT / "json_validation_c9_acceptance.json")], REPO))
    for key, path in WORKTREES.items():
        checks.append(run(f"{key}_git_diff_check", ["/usr/bin/git", "-C", str(path), "diff", "--check"], path, env=git_env(path)))
        checks.append(git_status(f"{key}_status_snapshot", path))
    payload = {
        "schema": "c9-acceptance-check-records/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "platform": " ".join(os.uname()),
        "tracked_python_count": len(tracked_py),
        "tracked_json_count": len(tracked_json),
        "write_scope": str(OUT),
        "checks": checks,
    }
    (OUT / "c9-acceptance-check-records.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"generated_at": payload["generated_at"], "checks": [{k:c[k] for k in ("name","exit_code","status","wall_seconds","log")} for c in checks]}, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())



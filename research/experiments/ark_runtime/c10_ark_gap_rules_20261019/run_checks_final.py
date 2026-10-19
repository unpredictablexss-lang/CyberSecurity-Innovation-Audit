from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
OUT = Path(__file__).resolve().parent
LOGS = OUT / "logs-win-final"
LOGS.mkdir(exist_ok=True)
PYCACHE = Path(r"C:\Users\work_work\AppData\Local\Temp\ohscanner-c10-gap-pycache")
PYCACHE.mkdir(exist_ok=True)
PY = r"C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
env = dict(os.environ)
env["PYTHONPYCACHEPREFIX"] = str(PYCACHE)
env["PYTHONDONTWRITEBYTECODE"] = "1"
commands = [
    ("ark_discover", [PY, "-B", "-m", "unittest", "discover", "-s", "tests/detectors/ark_runtime", "-t", ".", "-v"]),
    ("gap_focused", [PY, "-B", "-m", "unittest", "-v", "tests.detectors.ark_runtime.test_c10_ark_gap_rules"]),
    ("known_cves", [PY, "-B", "-m", "unittest", "-v", "tests.detectors.test_known_disclosed_cves"]),
    ("compileall", [PY, "-B", "-m", "compileall", "-q", "src", "tests"]),
    ("git_diff_check", ["git", "diff", "--check"]),
]
records = []
for name, argv in commands:
    started = datetime.now(timezone.utc).isoformat()
    result = subprocess.run(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    finished = datetime.now(timezone.utc).isoformat()
    stdout = result.stdout.decode("utf-8", "replace")
    stderr = result.stderr.decode("utf-8", "replace")
    (LOGS / f"{name}.stdout.txt").write_text(stdout, encoding="utf-8")
    (LOGS / f"{name}.stderr.txt").write_text(stderr, encoding="utf-8")
    combined = stdout + "\n" + stderr
    ran = re.search(r"Ran (\d+) tests?", combined)
    skipped = re.search(r"skipped=(\d+)", combined)
    failures = len(re.findall(r"^(?:FAIL|ERROR): ", combined, re.M))
    record = {
        "name": name,
        "argv": argv,
        "cwd": str(ROOT),
        "started_utc": started,
        "finished_utc": finished,
        "exit_code": result.returncode,
        "stdout_path": str(LOGS / f"{name}.stdout.txt"),
        "stderr_path": str(LOGS / f"{name}.stderr.txt"),
        "stdout_sha256": sha256(result.stdout).hexdigest(),
        "stderr_sha256": sha256(result.stderr).hexdigest(),
        "summary": {
            "tests_run": int(ran.group(1)) if ran else None,
            "skipped": int(skipped.group(1)) if skipped else 0,
            "failure_or_error_headers": failures,
            "status": "pass" if result.returncode == 0 else "fail",
        },
    }
    records.append(record)
payload = {
    "environment_mode": "inherited environment plus explicit overrides; full environment not persisted to avoid secret duplication",
    "python_executable": PY,
    "env_overrides": {k: env[k] for k in ("PYTHONPYCACHEPREFIX", "PYTHONDONTWRITEBYTECODE")},
    "relevant_inherited_env": {k: os.environ.get(k) for k in ("PYTHONPATH", "TEMP", "TMP")},
    "environment_keys_sha256": sha256("\n".join(sorted(env)).encode()).hexdigest(),
    "records": records,
}
(OUT / "check-records-win-final.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(payload, ensure_ascii=False, indent=2))
raise SystemExit(0 if all(x["exit_code"] == 0 for x in records) else 1)


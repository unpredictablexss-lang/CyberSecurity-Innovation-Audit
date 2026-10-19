from __future__ import annotations
import json, os, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[3]
IS_WSL = os.name != "nt"
TAG = "wsl" if IS_WSL else "win"
LOGS = OUT / ("logs-wsl" if IS_WSL else "logs-win")
TMP = OUT / (".tmp-wsl" if IS_WSL else ".tmp-win")
HOME = OUT / ".home-wsl"
CACHE = OUT / (".pycache-wsl" if IS_WSL else ".pycache-win")
for directory in (LOGS, TMP, CACHE):
    directory.mkdir(parents=True, exist_ok=True)
if IS_WSL:
    HOME.mkdir(parents=True, exist_ok=True)

BASE_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "PYTHONPATH": str(ROOT),
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONPYCACHEPREFIX": str(CACHE),
    "SOURCE_DATE_EPOCH": "0",
    "TZ": "Asia/Shanghai",
}
if IS_WSL:
    BASE_ENV.update({
        "HOME": str(HOME),
        "TMPDIR": str(TMP),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
    })
else:
    BASE_ENV.update({
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "TEMP": str(TMP),
        "TMP": str(TMP),
    })

CHECKS = [
    ("known_disclosed_cves", [sys.executable, "-B", "-m", "unittest", "-v", "tests.detectors.test_known_disclosed_cves"]),
    ("ark_discover", [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/detectors/ark_runtime", "-t", ".", "-v"]),
    ("type_origin", [sys.executable, "-B", "-m", "unittest", "-v", "tests.detectors.ark_runtime.test_type_origin"]),
    ("c3_mechanisms", [sys.executable, "-B", "-m", "unittest", "-v", "tests.detectors.ark_runtime.test_c3_mechanisms"]),
    ("runtime_exception", [sys.executable, "-B", "-m", "unittest", "-v", "tests.detectors.ark_runtime.test_runtime_exception"]),
    ("receiver_guard", [sys.executable, "-B", "-m", "unittest", "-v", "tests.detectors.ark_runtime.test_receiver_guard"]),
    ("exception_guard", [sys.executable, "-B", "-m", "unittest", "-v", "tests.detectors.ark_runtime.test_exception_guard"]),
    ("c10_known_case_controls", [sys.executable, "-B", "-m", "unittest", "-v", "tests.detectors.ark_runtime.test_c10_known_case_controls"]),
]

records = []
for name, argv in CHECKS:
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.perf_counter()
    proc = subprocess.run(argv, cwd=ROOT, env=BASE_ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    wall = time.perf_counter() - t0
    log = LOGS / f"{name}.log"
    log.write_bytes(b"--- stdout ---\n" + proc.stdout + b"\n--- stderr ---\n" + proc.stderr)
    records.append({
        "name": name, "argv": argv, "cwd": str(ROOT), "env": BASE_ENV,
        "exit_code": proc.returncode, "status": "pass" if proc.returncode == 0 else "fail",
        "started_at": started, "wall_seconds": wall, "log": str(log),
        "stdout_bytes": len(proc.stdout), "stderr_bytes": len(proc.stderr),
        "stdout_tail": proc.stdout.decode("utf-8", "replace").splitlines()[-12:],
        "stderr_tail": proc.stderr.decode("utf-8", "replace").splitlines()[-12:],
    })

payload = {
    "schema": "c10-ark-latest-semantics-checks/v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "runtime": sys.version,
    "executable": sys.executable,
    "checkout": str(ROOT),
    "environment_contract": "explicit subprocess env recorded in each check; no inherited secrets copied",
    "checks": records,
}
(OUT / f"check-records-{TAG}.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"tag": TAG, "generated_at": payload["generated_at"], "checks": [
    {key: row[key] for key in ("name", "exit_code", "status", "wall_seconds", "log", "stdout_tail", "stderr_tail")}
    for row in records]}, ensure_ascii=False, indent=2))
raise SystemExit(0 if all(row["status"] == "pass" for row in records) else 1)


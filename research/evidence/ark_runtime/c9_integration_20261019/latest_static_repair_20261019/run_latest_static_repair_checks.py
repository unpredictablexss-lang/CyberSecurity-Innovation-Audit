from __future__ import annotations
import json, os, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path
REPO = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c-line-static-20261019")
OUT = Path(r"E:\网安\CyberSecurity-Innovation-Audit-c-line-opt-20261019\research\evidence\ark_runtime\c9_integration_20261019\latest_static_repair_20261019")
LOGS = OUT / "logs"
BASE_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
    "TEMP": str(OUT / ".tmp"),
    "TMP": str(OUT / ".tmp"),
    "HOME": str(OUT / ".home"),
    "PYTHONPATH": str(REPO),
    "PYTHONPYCACHEPREFIX": str(OUT / ".pycache"),
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "TZ": "Asia/Shanghai",
}
CHECKS = [
    ("known_disclosed_cves", [sys.executable, "-B", "-m", "unittest", "-v", "tests.detectors.test_known_disclosed_cves"]),
    ("ark_discover", [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/detectors/ark_runtime", "-t", ".", "-v"]),
    ("owner_cd_admission", [sys.executable, "-B", "-m", "unittest", "-v", "tests.test_owner_cd_admission"]),
]
def main():
    LOGS.mkdir(parents=True, exist_ok=True)
    (OUT / ".tmp").mkdir(exist_ok=True)
    (OUT / ".home").mkdir(exist_ok=True)
    records=[]
    for name, argv in CHECKS:
        started=datetime.now(timezone.utc).isoformat()
        t0=time.perf_counter()
        p=subprocess.run(argv, cwd=REPO, env=BASE_ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        wall=time.perf_counter()-t0
        log=LOGS / f"{name}.log"
        log.write_bytes(b"--- stdout ---\n"+p.stdout+b"\n--- stderr ---\n"+p.stderr)
        records.append({
            "name":name, "argv":argv, "cwd":str(REPO), "env":BASE_ENV,
            "exit_code":p.returncode, "status":"pass" if p.returncode==0 else "fail",
            "started_at":started, "wall_seconds":wall,
            "log":str(log), "stdout_bytes":len(p.stdout), "stderr_bytes":len(p.stderr),
            "stdout_tail":p.stdout.decode("utf-8","replace").splitlines()[-8:],
            "stderr_tail":p.stderr.decode("utf-8","replace").splitlines()[-8:],
        })
    payload={"schema":"c9-latest-static-repair-checks/v1","generated_at":datetime.now(timezone.utc).isoformat(),
             "python":sys.version,"executable":sys.executable,"checkout":str(REPO),"checks":records}
    (OUT/"check-records.json").write_text(json.dumps(payload,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(payload,ensure_ascii=False,indent=2))
    return 0 if all(r["status"]=="pass" for r in records) else 1
if __name__ == "__main__":
    raise SystemExit(main())

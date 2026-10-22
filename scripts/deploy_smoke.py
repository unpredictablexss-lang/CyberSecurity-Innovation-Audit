"""Exercise a real server/Worker on an isolated synthetic Git fixture, then stop it.

No model calls, Docker, target code execution, or existing database access.
Logs and report are retained under .deploy/smoke-*/ for troubleshooting.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--hold-seconds", type=int, default=0)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    # Refuse to mistake another healthy server for the process started below.
    with socket.socket() as check:
        check.bind(("127.0.0.1", args.port))
    state = Path(os.environ.get("OHSCANNER_DEPLOY_HOME", root / ".deploy"))
    state.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="smoke-", dir=state)).resolve()
    repo = run / "targets" / "fixture"
    repo.mkdir(parents=True)
    (repo / "sample.cpp").write_text(
        '#include <cstring>\nvoid copy(char *out, const char *in) { strcpy(out, in); }\n',
        encoding="utf-8",
    )
    def git(*argv):
        return subprocess.check_output(["git", "-C", str(repo), *argv], text=True).strip()
    git("init", "-q")
    git("add", "sample.cpp")
    git("-c", "user.name=Deployment smoke", "-c", "user.email=smoke@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-qm", "Synthetic deployment fixture")
    commit = git("rev-parse", "HEAD")
    config = run / "config.json"
    config.write_text(json.dumps({"data_dir": str(run / "data"),
                                  "target_roots": [str(repo.parent)]}), encoding="utf-8")
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("OHSCANNER_") and k not in {"OPENAI_API_KEY"}}
    env["OHSCANNER_CONFIG"] = str(config)
    base = f"http://127.0.0.1:{args.port}"
    # Loopback checks must bypass system HTTP proxies.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def request(path, data=None):
        body = None if data is None else json.dumps(data).encode()
        req = urllib.request.Request(base + path, data=body, headers={
            "Content-Type": "application/json", "x-ohscanner-client": "workbench-v1"})
        with opener.open(req, timeout=10) as response:
            raw = response.read()
            return json.loads(raw) if "application/json" in response.headers.get("content-type", "") else raw
    log_path = run / "server.log"
    result = {"status": "failed", "run_dir": str(run), "commit": commit}
    process = None
    try:
        with log_path.open("w") as log:
            process = subprocess.Popen([sys.executable, "-m", "src.workbench", "serve",
                                        "--port", str(args.port)], cwd=root, env=env,
                                       stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 60
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"Server exited; see {log_path}")
                try:
                    health = request("/api/v1/health")
                    if health["status"] == "ok" and health["worker_running"]:
                        break
                except (OSError, ValueError):
                    pass
                if time.monotonic() > deadline:
                    raise TimeoutError(f"Server/Worker readiness timeout; see {log_path}")
                time.sleep(0.3)
            assert b"OHScanner" in request("/")
            assert len(request("/assets/app.js")) > 1000
            repository = request("/api/v1/repositories", {"name": "smoke/fixture", "path": str(repo)})
            job = request("/api/v1/scans", {"repository_id": repository["id"],
                          "revision": commit, "detector_ids": ["ohscanner.cpp.unsafe_memory_call"]})
            deadline = time.monotonic() + 90
            while job["status"] in {"queued", "running"} and time.monotonic() < deadline:
                time.sleep(0.3)
                job = request("/api/v1/scans/" + job["id"])
            assert job["status"] in {"completed", "completed_with_limitations"}, job
            assert job["report_sha256"], job
            report = request("/api/v1/scans/" + job["id"] + "/report")
            assert report["commit"] == commit, report
            runs = report["detector_runs"]
            assert runs and all(item["status"] == "completed" for item in runs), runs
            candidates = sum(len(item["diagnostics"]) for item in runs)
            assert candidates >= 1, "Expected a synthetic strcpy candidate"
            (run / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            result.update(status="passed", worker_running=True, homepage=True, static_asset=True,
                          job_status=job["status"], candidates=candidates,
                          report_sha256=job["report_sha256"])
            time.sleep(max(0, min(args.hold_seconds, 30)))
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        result["server_exit_code"] = None if process is None else process.returncode
        (run / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()

"""Single leased queue consumer with process-group cancellation and hard deadlines."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from .settings import Settings
from .store import Store
from .service import artifact_dir, sha, check_repository

class Worker:
    def __init__(self, settings):
        self.settings = settings
        settings.initialize()
        self.store = Store(settings.data_dir)

    @staticmethod
    def terminate(process):
        try:
            os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)

    def execute(self, job):
        key = job["id"]
        out = artifact_dir(self.settings,key)
        out.mkdir(parents=True,exist_ok=False)
        process = None
        start = time.monotonic()
        status, error, digest = "failed",None,None
        try:
            check_repository(self.settings,self.store.repository(job["repository_id"])["path"])
            with (out/"worker.log").open("wb") as log:
                process = subprocess.Popen(
                    [sys.executable,"-m","src.workbench.child",str(self.settings.data_dir),key,str(os.getpid())],
                    cwd=Path(__file__).resolve().parents[2],stdin=subprocess.DEVNULL,
                    stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                with self.store.connect() as db:
                    db.execute("UPDATE jobs SET worker_pid=? WHERE id=?", (process.pid,key))
                while process.poll() is None:
                    if self.store.job(key)["cancel_requested"]:
                        status,error = "cancelled","Cancelled by user; incomplete analysis remains unknown"
                        self.terminate(process)
                        break
                    if time.monotonic()-start > job["spec"]["timeout_seconds"]:
                        status,error = "timed_out","Hard task deadline exceeded; no complete result"
                        self.terminate(process)
                        break
                    if (out/"worker.log").stat().st_size > 10*1024*1024:
                        status,error = "failed","Worker log quota exceeded"
                        self.terminate(process)
                        break
                    time.sleep(0.1)
                else:
                    if self.store.job(key)["cancel_requested"]:
                        status,error = "cancelled","Cancellation arrived before result publication"
                    elif process.returncode != 0:
                        error = f"Scanner exited {process.returncode}; inspect worker log"
                    else:
                        data = (out/"report.json").read_bytes()
                        report = json.loads(data)
                        if (report["commit"] != job["spec"]["commit"]
                                or report["git_tree"] != job["spec"]["git_tree"]
                                or report["repository"] != job["spec"]["repository"]):
                            raise ValueError("scanner report binding mismatch")
                        if report["status"] not in {"completed","completed_with_limitations"}:
                            raise ValueError("invalid scanner task status")
                        status,digest = report["status"],sha(data)
                        manifest = {"schema_version":1,"job_id":key,"spec":job["spec"],
                                    "artifacts":{"report.json":digest,"report.md":sha((out/"report.md").read_bytes())}}
                        (out/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
        except Exception as exc:
            error = type(exc).__name__+": "+str(exc)[:1000]
        finally:
            if process is not None and process.poll() is None:
                self.terminate(process)
            elapsed = time.monotonic()-start
            self.store.finish(key,status,error,digest,elapsed)
            final = self.store.job(key)
            self.store.event(key,final["status"],final["error"] or "Verified result published")

    def run(self, once=False):
        with (self.settings.data_dir/"worker.lock").open("a") as lock:
            try:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("another Worker already owns this data directory")
            self.store.recover()
            while True:
                job = self.store.claim()
                if job:
                    self.execute(job)
                elif once:
                    return
                else:
                    time.sleep(0.3)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once",action="store_true",help="drain queue and exit")
    args = parser.parse_args()
    Worker(Settings.from_env()).run(args.once)

if __name__ == "__main__":
    main()

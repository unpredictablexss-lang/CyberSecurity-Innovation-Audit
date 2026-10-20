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
from .worker_env import remove_agent_provider_environment, worker_child_environment


class Worker:
    def __init__(self, settings):
        self.settings = settings
        settings.initialize()
        self.store = Store(settings.data_dir)

    @staticmethod
    def terminate(process):
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)

    def execute(self, job):
        key = job["id"]
        out = artifact_dir(self.settings, key)
        out.mkdir(parents=True, exist_ok=False)
        process = None
        start = time.monotonic()
        status, error, digest = "failed", None, None
        try:
            check_repository(
                self.settings, self.store.repository(job["repository_id"])["path"]
            )
            with (out / "worker.log").open("wb") as log:
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "src.workbench.child",
                        str(self.settings.data_dir),
                        key,
                        str(os.getpid()),
                    ],
                    cwd=Path(__file__).resolve().parents[2],
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    env=worker_child_environment(os.environ),
                )
                with self.store.connect() as db:
                    db.execute(
                        "UPDATE jobs SET worker_pid=? WHERE id=?", (process.pid, key)
                    )
                while process.poll() is None:
                    if self.store.job(key)["cancel_requested"]:
                        status, error = (
                            "cancelled",
                            "Cancelled by user; incomplete analysis remains unknown",
                        )
                        self.terminate(process)
                        break
                    if time.monotonic() - start > job["spec"]["timeout_seconds"]:
                        status, error = (
                            "timed_out",
                            "Hard task deadline exceeded; no complete result",
                        )
                        self.terminate(process)
                        break
                    if (out / "worker.log").stat().st_size > 10 * 1024 * 1024:
                        status, error = "failed", "Worker log quota exceeded"
                        self.terminate(process)
                        break
                    time.sleep(0.1)
                else:
                    if self.store.job(key)["cancel_requested"]:
                        status, error = (
                            "cancelled",
                            "Cancellation arrived before result publication",
                        )
                    elif process.returncode != 0:
                        error = (
                            f"Scanner exited {process.returncode}; inspect worker log"
                        )
                    else:
                        data = (out / "report.json").read_bytes()
                        report = json.loads(data)
                        if (
                            report["commit"] != job["spec"]["commit"]
                            or report["git_tree"] != job["spec"]["git_tree"]
                            or report["repository"] != job["spec"]["repository"]
                        ):
                            raise ValueError("scanner report binding mismatch")
                        if report["status"] not in {
                            "completed",
                            "completed_with_limitations",
                        }:
                            raise ValueError("invalid scanner task status")
                        if job["spec"].get("audit_plan") is not None:
                            if report.get("audit_plan") != job["spec"]["audit_plan"]:
                                raise ValueError("published audit plan differs from queued plan")
                        status, digest = report["status"], sha(data)
                        manifest = {
                            "schema_version": 1,
                            "job_id": key,
                            "spec": job["spec"],
                            "artifacts": {
                                "report.json": digest,
                                "report.md": sha((out / "report.md").read_bytes()),
                            },
                        }
                        (out / "manifest.json").write_text(
                            json.dumps(manifest, indent=2) + "\n"
                        )
        except Exception as exc:
            error = type(exc).__name__ + ": " + str(exc)[:1000]
        finally:
            if process is not None and process.poll() is None:
                self.terminate(process)
            elapsed = time.monotonic() - start
            self.store.finish(key, status, error, digest, elapsed)
            final = self.store.job(key)
            self.store.event(
                key, final["status"], final["error"] or "Verified result published"
            )
            if final["status"] in {"completed", "completed_with_limitations"} and final["report_sha256"]:
                # Only explicit task-level consent can create executable bounded triage.
                # Do not add the legacy candidate_review_batch pointer: no Worker claims it.
                self._enqueue_authorized_triage(final)

    def _enqueue_authorized_triage(self, job):
        if not self.store.triage_authorization(job["id"]):
            return
        try:
            from .operations_store import Operations
            from .smart_audit import enqueue_authorized_triage
            ops = Operations(self.store)
            batch = enqueue_authorized_triage(self.settings, self.store, ops, job)
            if batch:
                self.store.event(
                    job["id"], "triage_batch_" + batch["status"],
                    "Authorized R1 triage batch " + batch["id"] + ": "
                    + str(batch["selected_count"]) + "/" + str(batch["candidate_count"])
                    + " candidates selected; unselected remain unassessed",
                )
        except Exception as exc:
            self.store.event(
                job["id"], "triage_batch_enqueue_failed",
                "Static report remains valid; automatic triage did not start: "
                + type(exc).__name__ + ": " + str(exc)[:1000],
            )

    def run(self, once=False):
        with (self.settings.data_dir / "worker.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("another Worker already owns this data directory")
            # Apply additive operation/triage schema migrations under their backup lock
            # before inspecting older job rows for optional task-level consent.
            from .operations_store import Operations
            Operations(self.store)
            self.store.recover()
            # Recover the transition after a committed scan if the process stopped
            # before writing its idempotent triage batch. Old tasks have no consent row.
            for completed in self.store.authorized_completed_jobs_missing_batch():
                self._enqueue_authorized_triage(completed)
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
    parser.add_argument("--once", action="store_true", help="drain queue and exit")
    args = parser.parse_args()
    settings = Settings.from_env()
    remove_agent_provider_environment(os.environ)
    Worker(settings).run(args.once)


if __name__ == "__main__":
    main()

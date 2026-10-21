"""Dedicated operation consumers; validation uses its own lease and Docker boundary."""
import argparse
import ctypes
import fcntl
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time
from .settings import Settings
from .store import Store
from .operations_store import Operations
from .worker import Worker
from .worker_env import remove_agent_provider_environment, worker_child_environment


class OperationWorker:
    def __init__(self, settings, validation=False):
        self.settings = settings
        self.store = Store(settings.data_dir)
        self.ops = Operations(self.store)
        self.validation = validation

    def execute(self, task):
        folder = self.ops.directory(task["id"])
        folder.mkdir(parents=True, exist_ok=True)
        proc = None
        start = time.monotonic()
        try:
            with (folder / "worker.log").open("wb") as log:
                proc = subprocess.Popen([sys.executable, "-m", "src.workbench.operation_worker",
                    "--child", task["id"], "--parent", str(os.getpid())],
                    cwd=Path(__file__).resolve().parents[2], stdout=log, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL, start_new_session=True,
                    env={**worker_child_environment(os.environ,
                            allow_agent_provider=(not self.validation and task.get("kind") == "agent_investigation")),
                         "OHSCANNER_DATA": str(self.settings.data_dir),
                         "OHSCANNER_TARGET_ROOTS": os.pathsep.join(map(str, self.settings.target_roots)),
                         "OHSCANNER_REPOSITORY_CACHE_ROOTS": os.pathsep.join(map(str, self.settings.repository_cache_roots)),
                         "OHSCANNER_REPOSITORY_CACHE_MAX_BYTES": str(self.settings.repository_cache_max_bytes),
                         "OHSCANNER_REPOSITORY_CACHE_MIN_FREE_BYTES": str(self.settings.repository_cache_min_free_bytes)})
                while proc.poll() is None:
                    if self.ops.get(task["id"])["cancel_requested"]:
                        self.ops.cancel(task["id"])
                        Worker.terminate(proc)
                        self.ops.finish(task["id"], state="cancelled")
                        return
                    if time.monotonic() - start > task["spec"].get("timeout_seconds", 600):
                        Worker.terminate(proc)
                        for key in task["spec"].get("scan_ids", []):
                            self.store.cancel(key)
                        self.ops.finish(task["id"], state="timed_out", error="Operation hard deadline exceeded")
                        return
                    if (folder / "worker.log").stat().st_size > 10 * 1024 * 1024:
                        raise ValueError("operation log quota exceeded")
                    time.sleep(.1)
            if proc.returncode:
                raise RuntimeError("Operation child exited " + str(proc.returncode) + "; inspect log")
            data = (folder / "child-result.json").read_bytes()
            if len(data) > 16 * 1024 * 1024:
                raise ValueError("operation result quota exceeded")
            self.ops.finish(task["id"], json.loads(data))
        except Exception as exc:
            self.ops.finish(task["id"], error=type(exc).__name__ + ": " + str(exc)[:1500], state="failed")
        finally:
            if proc is not None and proc.poll() is None:
                Worker.terminate(proc)
            if task["kind"] == "validation":
                from .validation import cleanup_container
                cleanup_container(task["id"])
            if (task["kind"] == "agent_investigation"
                    and task.get("spec", {}).get("smart_triage_batch_id")):
                try:
                    from .smart_audit import enqueue_authorized_r2_followups
                    enqueue_authorized_r2_followups(
                        self.settings, self.store, self.ops,
                        task["spec"]["smart_triage_batch_id"])
                except Exception as exc:
                    self.store.event(
                        task["spec"].get("job_id", ""), "triage_r2_enqueue_failed",
                        "R1 result remains available; conditional R2 scheduling failed closed: "
                        + type(exc).__name__ + ": " + str(exc)[:600],
                    )

    def run(self, once=False):
        name = "validation-worker.lock" if self.validation else "operations-worker.lock"
        with (self.settings.data_dir / name).open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("another operation Worker owns this lane")
            self.ops.recover(self.validation)
            if not self.validation:
                from .smart_audit import enqueue_authorized_r2_followups
                for batch in self.ops.triage_batches_pending_r2():
                    try:
                        enqueue_authorized_r2_followups(
                            self.settings, self.store, self.ops, batch["id"])
                    except Exception:
                        # The durable R1 result is preserved; a later worker start retries
                        # this idempotent decision until the R2 batch is committed.
                        continue
            if self.validation:
                from .validation import cleanup_stale_containers
                cleanup_stale_containers()
            while True:
                task = self.ops.claim(self.validation)
                if task:
                    self.execute(task)
                elif once:
                    return
                else:
                    time.sleep(.3)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--validation", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--child")
    parser.add_argument("--parent", type=int)
    args = parser.parse_args()
    settings = Settings.from_env()
    if args.child:
        if ctypes.CDLL(None).prctl(1, signal.SIGKILL) != 0 or os.getppid() != args.parent:
            raise RuntimeError("operation parent unavailable")
        store = Store(settings.data_dir)
        ops = Operations(store)
        task = ops.get(args.child)
        if task.get("kind") != "agent_investigation":
            remove_agent_provider_environment(os.environ)
        memory = task["spec"].get("memory_mb", 2048) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024,) * 2)
        from .operations import execute
        child_started = time.monotonic()
        result = execute(settings, store, ops, task)
        if task.get("kind") == "agent_investigation" and isinstance(result, dict):
            peak_rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            result["execution_telemetry"] = {
                "wall_seconds": round(time.monotonic() - child_started, 3),
                "process_peak_rss_bytes": int(peak_rss_kib * 1024),
                "rss_measurement": "Linux resource.getrusage(RUSAGE_SELF).ru_maxrss converted from KiB to bytes",
                "docker_container_peak_rss_bytes": None,
                "docker_container_metrics": "not_measured",
            }
        (ops.directory(args.child) / "child-result.json").write_text(json.dumps(result, ensure_ascii=False))
    else:
        if args.validation:
            remove_agent_provider_environment(os.environ)
        OperationWorker(settings, args.validation).run(args.once)


if __name__ == "__main__":
    main()

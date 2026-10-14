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
                    env={**os.environ, "OHSCANNER_DATA": str(self.settings.data_dir),
                         "OHSCANNER_TARGET_ROOTS": os.pathsep.join(map(str, self.settings.target_roots))})
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

    def run(self, once=False):
        name = "validation-worker.lock" if self.validation else "operations-worker.lock"
        with (self.settings.data_dir / name).open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("another operation Worker owns this lane")
            self.ops.recover(self.validation)
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
        memory = task["spec"].get("memory_mb", 2048) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024,) * 2)
        from .operations import execute
        result = execute(settings, store, ops, task)
        (ops.directory(args.child) / "child-result.json").write_text(json.dumps(result, ensure_ascii=False))
    else:
        OperationWorker(settings, args.validation).run(args.once)


if __name__ == "__main__":
    main()

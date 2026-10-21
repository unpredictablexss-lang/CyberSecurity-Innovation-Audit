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


def _is_consented_joint_comparison(task, ops=None):
    spec = task.get("spec") if isinstance(task.get("spec"), dict) else {}
    return (task.get("kind") == "version_candidate_comparison"
            and spec.get("source_submission_approved") is True
            and isinstance(spec.get("consent_sha256"), str)
            and len(spec["consent_sha256"]) == 64
            and all(ch in "0123456789abcdef" for ch in spec["consent_sha256"])
            and isinstance(spec.get("consent_nonce"), str)
            and len(spec["consent_nonce"]) == 32
            and all(ch in "0123456789abcdef" for ch in spec["consent_nonce"])
            and isinstance(spec.get("joint_binding_snapshot"), dict)
            and ops is not None
            and ops.joint_comparison_ticket_allows_worker(
                task.get("id"), spec["consent_nonce"], spec["consent_sha256"]))


def _is_continuous_tool_agent(task):
    spec = task.get("spec") if isinstance(task.get("spec"), dict) else {}
    return (task.get("kind") == "agent_investigation"
            and spec.get("continuous_investigation") is True)


def _hard_deadline_seconds(task):
    """Bound Agent runtime, allowing ten seconds for child cleanup."""
    spec = task.get("spec") if isinstance(task.get("spec"), dict) else {}
    if task.get("kind") == "agent_investigation":
        from .agent import bounded_agent_spec
        return bounded_agent_spec(spec)["timeout_seconds"] + 10
    return spec.get("timeout_seconds", 600)


def _provider_quota_failure(exc):
    from .agent import ProviderQuotaError
    if isinstance(exc, ProviderQuotaError):
        return {"status": "failed", "_operation_error": {
            "code": exc.error_code, "message": str(exc)}}
    return None


def _commit_provider_quota_failure(ops, task, result):
    failure = result.get("_operation_error") if isinstance(result, dict) else None
    if (task.get("kind") == "agent_investigation"
            and isinstance(failure, dict)
            and failure.get("code") == "provider_quota_exhausted"
            and isinstance(failure.get("message"), str)):
        ops.finish(task["id"], error=failure["code"] + ": " + failure["message"],
                   state="failed")
        return True
    return False


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
        spec = task.get("spec") if isinstance(task.get("spec"), dict) else {}
        uncapped_smart = _authorized_smart_batch(self.store, self.ops, task)
        try:
            with (folder / "worker.log").open("wb") as log:
                proc = subprocess.Popen([sys.executable, "-m", "src.workbench.operation_worker",
                    "--child", task["id"], "--parent", str(os.getpid())],
                    cwd=Path(__file__).resolve().parents[2], stdout=log, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL, start_new_session=True,
                    env={**worker_child_environment(os.environ,
                            allow_agent_provider=(not self.validation and (
                                task.get("kind") == "agent_investigation"
                                or _is_consented_joint_comparison(task, self.ops)))),
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
                    hard_deadline = _hard_deadline_seconds(task)
                    if hard_deadline is not None and time.monotonic() - start > hard_deadline:
                        Worker.terminate(proc)
                        for key in spec.get("scan_ids", []):
                            self.store.cancel(key)
                        self.ops.finish(task["id"], state="timed_out", error="Operation hard deadline exceeded")
                        return
                    log_path = folder / "worker.log"
                    if log_path.stat().st_size > 10 * 1024 * 1024:
                        if not uncapped_smart:
                            raise ValueError("operation log quota exceeded")
                        # Retain a bounded diagnostic tail without stopping a
                        # source-authorized smart investigation on cumulative log bytes.
                        with log_path.open("r+b") as log:
                            log.seek(-1024 * 1024, os.SEEK_END)
                            tail = log.read()
                            log.seek(0)
                            log.write(b"[older diagnostic output trimmed]\n" + tail)
                            log.truncate()
                    time.sleep(.1)
            if proc.returncode:
                raise RuntimeError("Operation child exited " + str(proc.returncode) + "; inspect log")
            data = (folder / "child-result.json").read_bytes()
            if len(data) > 16 * 1024 * 1024 and not uncapped_smart:
                raise ValueError("operation result quota exceeded")
            result = json.loads(data)
            if _commit_provider_quota_failure(self.ops, task, result):
                return
            self.ops.finish(task["id"], result)
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
        if (task.get("kind") != "agent_investigation"
                and not _is_consented_joint_comparison(task, ops)):
            remove_agent_provider_environment(os.environ)
        memory = task["spec"].get("memory_mb", 2048) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        if _authorized_smart_batch(store, ops, task):
            # Result size follows the finite fixed-source investigation; do not
            # apply an aggregate output-file quota to the explicitly authorized path.
            resource.setrlimit(resource.RLIMIT_FSIZE,
                               (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        else:
            resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024,) * 2)
        from .operations import execute
        child_started = time.monotonic()
        try:
            result = execute(settings, store, ops, task)
        except Exception as exc:
            if task.get("kind") == "agent_investigation":
                result = _provider_quota_failure(exc)
                if result is None:
                    raise
            else:
                raise
        if (task.get("kind") in {"revision_range", "recent_window_comparison",
                                  "branch_comparison", "version_matrix"}
                and isinstance(task.get("spec", {}).get("progressive_triage_policy"), dict)
                and isinstance(result, dict)):
            from .progressive_triage.runtime import build_operation_plan
            result["progressive_triage"] = build_operation_plan(settings, store, task)
        if task.get("kind") == "agent_investigation" and not result.get("_operation_error"):
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





def _authorized_smart_batch(store, ops, task):
    spec = task.get("spec") if isinstance(task.get("spec"), dict) else {}
    job_id = spec.get("job_id")
    report_sha256 = spec.get("report_sha256")
    authorization_sha256 = spec.get("triage_authorization_sha256")
    batch_id = spec.get("smart_triage_batch_id")
    if (task.get("kind") != "agent_investigation"
            or spec.get("no_cumulative_token_ceiling") is not True
            or not all(isinstance(value, str) and value for value in
                       (job_id, report_sha256, authorization_sha256, batch_id))):
        return False
    try:
        authorization = store.triage_authorization(job_id)
        job = store.job(job_id)
        if (not authorization or authorization.get("revoked")
                or authorization.get("consent_sha256") != authorization_sha256
                or job.get("report_sha256") != report_sha256):
            return False
        return any(batch.get("id") == batch_id
                   and batch.get("authorization_sha256") == authorization_sha256
                   and task["id"] in (batch.get("operation_ids", [])
                                      + batch.get("r2_operation_ids", []))
                   for batch in ops.triage_batches_for_job(job_id, report_sha256))
    except (KeyError, ValueError):
        return False


if __name__ == "__main__":
    main()

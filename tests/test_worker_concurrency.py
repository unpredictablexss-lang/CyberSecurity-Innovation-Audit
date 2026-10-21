import threading
import time
import tempfile
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from src.workbench.worker import Worker
    from src.workbench.settings import Settings
except ModuleNotFoundError as error:
    if error.name == "fcntl":
        Worker = None
    else:
        raise


@unittest.skipIf(Worker is None, "Worker process locking requires POSIX fcntl")
class WorkerConcurrencyTests(unittest.TestCase):
    def _running_job_with_checkpoint(self, directory, *, manifest=True, tamper=False,
                                     cancel=False, status="completed_with_limitations"):
        root = Path(directory)
        settings = Settings(root / "data", (root,), "low")
        settings.initialize()
        worker = Worker(settings)
        repository = worker.store.add_repository("fixture/checkpoint", str(root))
        spec = {"repository": "fixture/checkpoint", "commit": "a" * 40,
                "git_tree": "b" * 40, "audit_plan": None}
        queued = worker.store.create_job(repository["id"], spec)
        job = worker.store.claim()
        self.assertEqual(job["id"], queued["id"])
        out = settings.data_dir / "artifacts" / job["id"]
        out.mkdir(parents=True)
        report = {"status": status, "repository": spec["repository"],
                  "commit": spec["commit"], "git_tree": spec["git_tree"]}
        report_bytes = json.dumps(report, sort_keys=True).encode("utf-8")
        markdown_bytes = b"completed scan report\n"
        (out / "report.json").write_bytes(report_bytes)
        (out / "report.md").write_bytes(markdown_bytes)
        if manifest:
            report_hash = hashlib.sha256(report_bytes).hexdigest()
            markdown_hash = hashlib.sha256(markdown_bytes).hexdigest()
            checkpoint = {"schema_version": 1, "job_id": job["id"], "spec": spec,
                          "artifacts": {"report.json": report_hash,
                                        "report.md": markdown_hash}}
            Worker.write_final_checkpoint(out / "manifest.json", checkpoint)
        if tamper:
            (out / "report.json").write_text(json.dumps({**report, "candidate_count": 99}))
        if cancel:
            worker.store.cancel(job["id"])
        return worker, job, out, report_bytes

    def test_recover_promotes_only_fully_verified_final_report_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            worker, job, _, report_bytes = self._running_job_with_checkpoint(directory)
            recovered = worker.store.recover()
            final = worker.store.job(job["id"])
            self.assertEqual(recovered, {"published": 1, "interrupted": 0, "cancelled": 0})
            self.assertEqual(final["status"], "completed_with_limitations")
            self.assertEqual(final["report_sha256"], hashlib.sha256(report_bytes).hexdigest())
            self.assertEqual(worker.store.events(job["id"])[-1]["stage"], "result_recovered")

    def test_recover_never_promotes_missing_or_tampered_checkpoint(self):
        for kwargs in ({"manifest": False}, {"tamper": True}):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as directory:
                worker, job, _, _ = self._running_job_with_checkpoint(directory, **kwargs)
                recovered = worker.store.recover()
                final = worker.store.job(job["id"])
                self.assertEqual(recovered["interrupted"], 1)
                self.assertEqual(final["status"], "interrupted")
                self.assertIsNone(final["report_sha256"])

    def test_pending_cancel_wins_over_a_complete_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            worker, job, _, _ = self._running_job_with_checkpoint(directory, cancel=True)
            recovered = worker.store.recover()
            final = worker.store.job(job["id"])
            self.assertEqual(recovered["cancelled"], 1)
            self.assertEqual(final["status"], "cancelled")
            self.assertIsNone(final["report_sha256"])

    def test_real_worker_claim_loop_obeys_profile_slots(self):
        for mode, expected in (("low", 1), ("balanced", 2), ("high", 4)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                settings = Settings(root / "data", (root,), mode)
                settings.initialize()
                worker = Worker(settings)
                repository = worker.store.add_repository("fixture/sample", str(root))
                jobs = [worker.store.create_job(repository["id"], {"test": True})
                        for _ in range(expected * 2)]
                lock = threading.Lock()
                active = 0
                observed = 0

                def execute(instance, job):
                    nonlocal active, observed
                    with lock:
                        active += 1
                        observed = max(observed, active)
                    time.sleep(0.05)
                    instance.store.finish(job["id"], "completed")
                    with lock:
                        active -= 1

                with patch.object(Worker, "execute", execute):
                    Worker(settings).run(once=True)
                self.assertEqual(observed, expected)
                self.assertEqual({worker.store.job(job["id"])["status"] for job in jobs}, {"completed"})


if __name__ == "__main__":
    unittest.main()

"""Offline tests for bounded source-sync batches.

The transport seam rewrites only approved HTTPS URLs to temporary bare Git
fixtures. Tests exercise the handler and cancellation behavior, not HTTPS,
redirects, or the real remote-network boundary.
"""
import os
from concurrent.futures import ThreadPoolExecutor
import threading
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from src.workbench import operations
from src.workbench.operations_api import SyncBatchRequest, SyncRequest, install_routes
from src.workbench.operations import execute
from src.workbench.operations_store import Operations
from src.workbench.settings import Settings
from src.workbench.store import Store

DETECTOR_ID = "ohscanner.cpp.lifetime"

def git(path, *args):
    result = subprocess.run(
        ["git", "-C", str(path), *args], check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull,
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"},
    )
    return result.stdout.strip()

class SourceSyncBatchIntegrationTests(unittest.TestCase):
    """Run the batch handler with local bare repositories and no service ports."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.upstreams = {}
        self.data = self.root / "data"
        self.cache = self.data / "repo-cache"
        self.settings = Settings(self.data, (self.cache,))
        self.settings.initialize()
        self.store = Store(self.data)
        self.ops = Operations(self.store)

    def _repository(self, name, value="1"):
        slug = name.split("/", 1)[1]
        bare, work = self.root / (slug + ".git"), self.root / (slug + "-author")
        work.mkdir()
        subprocess.run(["git", "init", "-q", "--bare", "--initial-branch=main", str(bare)], check=True)
        subprocess.run(["git", "init", "-q", "--initial-branch=main"], cwd=work, check=True)
        git(work, "config", "user.name", "OHScanner batch fixture")
        git(work, "config", "user.email", "batch@example.invalid")
        git(work, "remote", "add", "origin", str(bare))
        (work / "sample.cpp").write_text(f"int sample() {{ return {value}; }}\n", encoding="utf-8")
        git(work, "add", "sample.cpp")
        git(work, "commit", "-q", "-m", "fixture version one")
        git(work, "push", "-u", "origin", "main")
        self.upstreams[name] = bare
        return bare, work

    def _entry(self, name, scan=False):
        return {
            "name": name, "url": "https://github.com/" + name + ".git",
            "timeout_seconds": 60, "scan_after_sync": scan,
            "revision": "refs/remotes/origin/main", "include_paths": ["."],
            "detector_ids": [DETECTOR_ID], "audit_mode": "static_only",
            "scan_timeout_seconds": 60, "memory_mb": 512,
        }

    def _task(self, entries):
        self.ops.create("source_sync_batch", {
            "repositories": entries,
            "timeout_seconds": sum(row["timeout_seconds"] for row in entries) + 60,
            "max_repositories": operations.MAX_SOURCE_SYNC_BATCH_REPOSITORIES,
        })
        return self.ops.claim()

    def _transport(self, calls, cancel_before=None, operation_id=None):
        def start(command, env):
            command = list(command)
            for policy in ("http.followRedirects=false", "fetch.recurseSubmodules=false",
                           "core.hooksPath=/dev/null", "credential.helper=",
                           "protocol.file.allow=never", "protocol.ext.allow=never"):
                self.assertIn(policy, command)
            self.assertIn("--no-recurse-submodules", command)
            self.assertEqual(env.get("GIT_ALLOW_PROTOCOL"), "https")
            if "clone" in command:
                self.assertIn("--no-checkout", command)
            remote = next((value for value in command
                           if value.startswith("https://github.com/openharmony/")), None)
            if remote is None:
                raise AssertionError("Git transfer lost the approved HTTPS URL")
            name = remote.removeprefix("https://github.com/").removesuffix(".git")
            action = "fetch" if "fetch" in command else "clone"
            calls.append((action, name))
            command[command.index(remote)] = str(self.upstreams.get(name, self.root / "missing.git"))
            index = 0
            while index < len(command) - 1:
                if command[index:index + 2] == ["-c", "protocol.file.allow=never"]:
                    del command[index:index + 2]
                else:
                    index += 1
            local_env = dict(env)
            local_env["GIT_ALLOW_PROTOCOL"] = "file"
            if cancel_before == name:
                wrapped = ["bash", "-lc", 'sleep 5; exec "$@"',
                           "batch-cancel-wrapper", *command]
                process = subprocess.Popen(wrapped, env=local_env, start_new_session=True)
                self.ops.cancel(operation_id)
                return process
            return subprocess.Popen(command, env=local_env, start_new_session=True)
        return start

    def _run(self, entries, cancel_before=None):
        task = self._task(entries)
        calls = []
        with patch.object(operations, "_start_source_sync_process",
                          side_effect=self._transport(calls, cancel_before, task["id"])):
            result = execute(self.settings, self.store, self.ops, task)
        self.ops.finish(task["id"], result)
        return task, result, calls

    def test_fetch_clone_duplicates_and_optional_fixed_static_scan(self):
        first, second = "openharmony/batch-existing", "openharmony/batch-new"
        bare, work = self._repository(first)
        self._repository(second, "2")
        target = self.cache / first.split("/", 1)[1]
        subprocess.run(["git", "clone", "-q", "--no-checkout", str(bare), str(target)],
                       check=True, capture_output=True,
                       env={**os.environ, "GIT_ALLOW_PROTOCOL": "file"})
        registered = self.store.add_repository(first, str(target))
        (work / "sample.cpp").write_text("int sample() { return 3; }\n", encoding="utf-8")
        git(work, "add", "sample.cpp")
        git(work, "commit", "-q", "-m", "fixture version two")
        expected_commit = git(work, "rev-parse", "HEAD")
        git(work, "push", "origin", "main")

        first_entry = self._entry(first, scan=True)
        task, result, calls = self._run([first_entry, self._entry(second), dict(first_entry)])

        self.assertEqual(calls, [("fetch", first), ("clone", second)])
        self.assertEqual(result["status"], "completed")
        self.assertEqual([row["status"] for row in result["repositories"]],
                         ["completed", "completed", "skipped_duplicate"])
        self.assertEqual(result["repositories"][0]["repository_id"], registered["id"])
        self.assertEqual(result["summary"]["unique"], 2)
        self.assertEqual(result["summary"]["duplicates_skipped"], 1)
        self.assertEqual(result["summary"]["static_scans_enqueued"], 1)
        self.assertIsNone(result["repositories"][1]["scan_job_id"])

        scan_id = result["repositories"][0]["scan_job_id"]
        scan = self.store.job(scan_id)
        self.assertEqual(scan["status"], "queued")
        self.assertEqual(scan["repository_id"], registered["id"])
        self.assertEqual(scan["spec"]["repository"], first)
        self.assertEqual(scan["spec"]["commit"], expected_commit)
        self.assertEqual(scan["spec"]["git_tree"], git(work, "rev-parse", "HEAD^{tree}"))
        self.assertEqual(scan["spec"]["audit_mode"], "static_only")
        self.assertNotIn("triage_authorization", scan["spec"])
        self.assertIsNone(self.store.triage_authorization(scan_id))
        self.assertEqual(self.ops.get(task["id"])["status"], "completed")

    def test_concurrent_same_repository_sync_serializes_clone_fetch_and_registration(self):
        name = "openharmony/concurrent-same-repository"
        self._repository(name)
        entry = self._entry(name)
        spec = {
            "repositories": [entry], "timeout_seconds": 120,
            "max_repositories": operations.MAX_SOURCE_SYNC_BATCH_REPOSITORIES,
        }
        tasks = [self.ops.create("source_sync_batch", dict(spec)) for _ in range(2)]
        rendezvous = threading.Barrier(2)
        real_acquire = operations._acquire_source_sync_lock

        def synchronized_acquire(*args):
            # Both handlers have computed their initial state before either
            # acquires the per-repository lock; the handler must recheck under lock.
            rendezvous.wait(timeout=10)
            return real_acquire(*args)

        calls = []
        with patch.object(operations, "_start_source_sync_process",
                          side_effect=self._transport(calls)), \
             patch.object(operations, "_acquire_source_sync_lock",
                          side_effect=synchronized_acquire):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [
                    pool.submit(operations._sync_source_batch_item,
                                self.settings, self.store, self.ops, task, entry, 1, 1)
                    for task in tasks
                ]
                results = [future.result(timeout=20) for future in futures]

        self.assertCountEqual([action for action, _ in calls], ["clone", "fetch"])
        self.assertEqual(len(calls), 2)
        self.assertEqual({result["sync_action"] for result in results}, {"clone", "fetch"})
        self.assertEqual(results[0]["repository_id"], results[1]["repository_id"])
        registered = [row for row in self.store.repositories() if row["name"] == name]
        self.assertEqual(len(registered), 1)

    def test_batch_rejects_cache_symlink_escape_before_git_transfer(self):
        name = "openharmony/cache-path-escape"
        self._repository(name)
        target = self.cache / name.split("/", 1)[1]
        outside = self.root / "outside-cache-target"
        outside.mkdir()
        sentinel = outside / "keep.txt"
        sentinel.write_text("leave intact", encoding="utf-8")
        target.symlink_to(outside, target_is_directory=True)

        task, result, calls = self._run([self._entry(name)])

        self.assertEqual(calls, [])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["repositories"][0]["status"], "failed")
        self.assertIn("unsafe repository cache path", result["repositories"][0]["error"])
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "leave intact")
        self.assertFalse(any(row["name"] == name for row in self.store.repositories()))

    def test_batch_continues_after_one_repository_transfer_fails(self):
        first, failed, last = ("openharmony/batch-first", "openharmony/batch-missing",
                               "openharmony/batch-last")
        self._repository(first)
        self._repository(last, "3")
        task, result, calls = self._run([self._entry(first), self._entry(failed), self._entry(last)])

        self.assertEqual([name for _, name in calls], [first, failed, last])
        self.assertEqual(result["status"], "completed_with_limitations")
        self.assertEqual([row["status"] for row in result["repositories"]],
                         ["completed", "failed", "completed"])
        self.assertIn("exit status", result["repositories"][1]["error"])
        self.assertEqual(result["summary"]["succeeded"], 2)
        self.assertEqual(result["summary"]["failed"], 1)
        self.assertEqual([repo["name"] for repo in self.store.repositories()], [first, last])
        self.assertEqual(self.ops.get(task["id"])["status"], "completed_with_limitations")

    def test_cancel_stops_active_transfer_remaining_items_and_owned_scan(self):
        first, second, third = ("openharmony/batch-before-cancel", "openharmony/batch-cancel-now",
                               "openharmony/batch-after-cancel")
        self._repository(first)
        self._repository(second)
        self._repository(third)
        task, result, calls = self._run(
            [self._entry(first, scan=True), self._entry(second), self._entry(third)],
            cancel_before=second,
        )

        self.assertEqual([name for _, name in calls], [first, second])
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual([row["status"] for row in result["repositories"]],
                         ["completed", "cancelled", "not_started"])
        scan_id = result["repositories"][0]["scan_job_id"]
        self.assertEqual(result["repositories"][0]["scan_status"], "cancelled")
        self.assertEqual(self.store.job(scan_id)["status"], "cancelled")
        self.assertTrue(result["summary"]["cancellation_requested"])
        self.assertEqual(self.ops.get(task["id"])["status"], "cancelled")
        persisted = self.ops.result(task["id"])
        self.assertEqual(persisted["repositories"][0]["repository"], first)
        self.assertEqual(persisted["repositories"][2]["status"], "not_started")

    def test_disk_safety_failure_terminates_active_git_and_persists_failed_row(self):
        name = "openharmony/batch-disk-guard"
        self._repository(name)
        task = self._task([self._entry(name)])
        processes = []

        def start_sleeping_process(command, env):
            process = subprocess.Popen(["sleep", "30"], start_new_session=True)
            processes.append(process)
            return process

        guard = operations.SourceSyncSafetyLimit("disk guard test")
        with patch.object(operations, "_start_source_sync_process", side_effect=start_sleeping_process), \
             patch.object(operations, "_ensure_source_sync_free_space",
                          side_effect=[None, None, guard]):
            result = execute(self.settings, self.store, self.ops, task)
        self.ops.finish(task["id"], result)

        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll(), "active Git process must stop before cleanup")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["repositories"][0]["status"], "failed")
        self.assertIn("disk guard test", result["repositories"][0]["error"])
        persisted = self.ops.result(task["id"])
        self.assertEqual(persisted["repositories"][0]["status"], "failed")
        self.assertTrue(persisted["summary"]["disk_safety_stop"])

    def test_batch_api_caps_selection_and_counts_duplicate_timeout_once(self):
        request = SyncRequest(
            repository="openharmony/api-batch-fixture",
            url="https://github.com/openharmony/api-batch-fixture.git",
            timeout_seconds=3600,
        )
        with self.assertRaises(ValidationError):
            SyncBatchRequest(repositories=[request.model_copy(deep=True) for _ in range(9)])

        app = FastAPI()
        install_routes(app, self.settings, self.store)
        response = TestClient(app).post(
            "/api/v1/operations/source-sync/batch",
            json={"repositories": [request.model_dump() for _ in range(8)]},
        )
        self.assertEqual(response.status_code, 201, response.text)
        created = self.ops.get(response.json()["id"])
        self.assertEqual(created["kind"], "source_sync_batch")
        self.assertEqual(created["spec"]["timeout_seconds"], 3660)
        self.assertEqual(len(created["spec"]["repositories"]), 8)

if __name__ == "__main__":
    unittest.main()

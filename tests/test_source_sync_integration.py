"""Offline integration tests for the source-sync operation handler.

The production handler still validates the approved HTTPS URL. A narrow test
transport shim maps only that already-approved URL to a temporary bare Git
fixture and permits Git's local file transport for the clone/fetch command.
These tests exercise the shared production command builder through a narrow local
transport seam. They verify clone/fetch orchestration, cleanup and cancellation;
they do not test HTTPS, redirects, or network security.
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from src.workbench import operations
from src.workbench.operations import execute
from src.workbench.operations_store import Operations
from src.workbench.settings import Settings
from src.workbench.store import Store


APPROVED_URL = "https://github.com/openharmony/source-sync-fixture.git"
REPOSITORY_NAME = "openharmony/source-sync-fixture"
REVISION = "refs/remotes/origin/main"
DETECTOR_ID = "ohscanner.cpp.lifetime"


def git(path, *args):
    result = subprocess.run(
        ["git", "-C", str(path), *args],
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    return result.stdout.strip()


class SourceSyncHandlerIntegrationTests(unittest.TestCase):
    """Use the real operation handler without starting a server or Worker port."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bare = self.root / "upstream.git"
        self.work = self.root / "author"
        self.work.mkdir()
        subprocess.run(
            ["git", "init", "-q", "--bare", "--initial-branch=main", str(self.bare)],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["git", "init", "-q", "--initial-branch=main"],
            cwd=self.work,
            check=True,
            capture_output=True,
            text=True,
        )
        git(self.work, "config", "user.name", "OHScanner source-sync fixture")
        git(self.work, "config", "user.email", "source-sync@example.invalid")
        git(self.work, "remote", "add", "origin", str(self.bare))
        self._commit("fixture version one")
        git(self.work, "push", "-u", "origin", "main")

        self.data = self.root / "data"
        self.cache = self.data / "repo-cache"
        self.settings = Settings(self.data, (self.cache,))
        self.settings.initialize()
        self.store = Store(self.data)
        self.ops = Operations(self.store)

    def _commit(self, text):
        (self.work / "sample.cpp").write_text(
            "int sample() { return " + ("1" if text.endswith("one") else "2") + "; }\n",
            encoding="utf-8",
        )
        git(self.work, "add", "sample.cpp")
        git(self.work, "commit", "-q", "-m", text)
        return git(self.work, "rev-parse", "HEAD")

    def _transport_shim(self, calls, commands):
        def start(command, environment):
            command = list(command)
            operation = next((item for item in ("clone", "fetch") if item in command), None)
            if command and command[0] == "git" and operation and APPROVED_URL in command:
                calls.append((operation, APPROVED_URL))
                commands.append((operation, list(command), dict(environment)))
                command[command.index(APPROVED_URL)] = str(self.bare)

                # The handler rejects file URLs in production. This fixture seam
                # maps the approved HTTPS URL to a local bare repository.
                index = 0
                while index < len(command) - 1:
                    if command[index:index + 2] == ["-c", "protocol.file.allow=never"]:
                        del command[index:index + 2]
                    else:
                        index += 1
                environment = dict(environment)
                environment["GIT_ALLOW_PROTOCOL"] = "file"
            return subprocess.Popen(
                command, env=environment, start_new_session=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

        return start

    def _queue_scan_after_sync(self, *, expected_operation, pre_register=False):
        target = self.cache / "source-sync-fixture"
        registered = None
        if pre_register:
            # Seed the cache as an existing clone, then advance the fixture remote
            # so the handler must take its fetch path to see the new commit.
            subprocess.run(
                ["git", "clone", "-q", "--no-checkout", str(self.bare), str(target)],
                check=True,
                capture_output=True,
                text=True,
                env={**os.environ, "GIT_ALLOW_PROTOCOL": "file"},
            )
            registered = self.store.add_repository(REPOSITORY_NAME, str(target))
            expected_commit = self._commit("fixture version two")
            git(self.work, "push", "origin", "main")
        else:
            expected_commit = git(self.bare, "rev-parse", "refs/heads/main")

        task = self.ops.create("source_sync", {
            "name": REPOSITORY_NAME,
            "url": APPROVED_URL,
            "timeout_seconds": 60,
            "scan_after_sync": True,
            "revision": "HEAD" if pre_register else REVISION,
            "include_paths": ["."],
            "detector_ids": [DETECTOR_ID],
            "audit_mode": "static_only",
            "scan_timeout_seconds": 60,
            "memory_mb": 512,
        })
        claimed = self.ops.claim()
        self.assertEqual(claimed["id"], task["id"])
        calls = []
        commands = []

        # execute() is the operation Worker's child handler. We invoke it directly
        # with a temporary local-Git transport shim; no HTTP server, port, or
        # outbound network request is created by this test.
        with patch.object(operations, "_start_source_sync_process",
                          side_effect=self._transport_shim(calls, commands)):
            result = execute(self.settings, self.store, self.ops, claimed)
        self.ops.finish(task["id"], result)

        self.assertEqual(calls, [(expected_operation, APPROVED_URL)])
        self.assertEqual(len(commands), 1)
        command = commands[0][1]
        environment = commands[0][2]
        for policy in ("http.followRedirects=false", "fetch.recurseSubmodules=false",
                       "core.hooksPath=/dev/null", "credential.helper=",
                       "protocol.file.allow=never", "protocol.ext.allow=never"):
            self.assertIn(policy, command)
        self.assertIn("--no-recurse-submodules", command)
        self.assertEqual(environment.get("GIT_ALLOW_PROTOCOL"), "https")
        if expected_operation == "clone":
            self.assertIn("--no-checkout", command)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["repository"]["name"], REPOSITORY_NAME)
        self.assertEqual(Path(result["repository"]["path"]), target)

        repositories = [row for row in self.store.repositories() if row["name"] == REPOSITORY_NAME]
        self.assertEqual(len(repositories), 1)
        repository = repositories[0]
        if registered:
            self.assertEqual(repository["id"], registered["id"])
        self.assertEqual(result["repository"]["id"], repository["id"])

        scan_id = result["scan_job_id"]
        self.assertTrue(scan_id)
        scan = self.store.job(scan_id)
        self.assertEqual(scan["status"], "queued")
        self.assertEqual(scan["repository_id"], repository["id"])
        self.assertEqual(scan["spec"]["repository"], REPOSITORY_NAME)
        self.assertEqual(scan["spec"]["commit"], expected_commit)
        expected_tree = git(self.bare, "rev-parse", expected_commit + "^{tree}")
        self.assertEqual(scan["spec"]["git_tree"], expected_tree)
        local_head = git(target, "rev-parse", "HEAD")
        local_tree = git(target, "rev-parse", local_head + "^{tree}")
        self.assertEqual(result["local_head_after_sync"], local_head)
        self.assertEqual(result["git_tree_after_sync"], local_tree)
        self.assertEqual(result["scan_tree"], expected_tree)
        self.assertEqual(result["scan_commit"], expected_commit)
        self.assertEqual(result["scan_status"], "queued")

        # The handoff creates a static scan only. No model egress consent is
        # implicitly minted by syncing and queueing source analysis.
        self.assertEqual(scan["spec"]["audit_mode"], "static_only")
        self.assertNotIn("triage_authorization", scan["spec"])
        self.assertIsNone(self.store.triage_authorization(scan_id))
        self.assertEqual(self.ops.get(task["id"])["status"], "completed")
        self.assertEqual(self.ops.result(task["id"])["scan_job_id"], scan_id)

    def test_source_sync_handler_local_transport_shim_clones_and_queues_fixed_static_scan(self):
        self._queue_scan_after_sync(expected_operation="clone")

    def test_source_sync_handler_local_transport_shim_fetches_existing_repo_before_queueing(self):
        self._queue_scan_after_sync(expected_operation="fetch", pre_register=True)

    def _task(self):
        task = self.ops.create("source_sync", {
            "name": REPOSITORY_NAME, "url": APPROVED_URL, "timeout_seconds": 60,
            "scan_after_sync": True, "revision": REVISION, "include_paths": ["."],
            "detector_ids": [DETECTOR_ID], "audit_mode": "static_only",
            "scan_timeout_seconds": 60, "memory_mb": 512,
        })
        claimed = self.ops.claim()
        self.assertEqual(claimed["id"], task["id"])
        return task, claimed

    def test_single_sync_cancel_stops_git_and_removes_partial_clone(self):
        task, claimed = self._task()
        target = self.cache / "source-sync-fixture"
        started = threading.Event()
        processes = []

        def start(_command, _environment):
            target.mkdir(parents=True, exist_ok=True)
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            processes.append(process)
            started.set()
            return process

        cancel_thread = threading.Thread(target=lambda: (
            started.wait(5), time.sleep(0.15), self.ops.cancel(task["id"])
        ))
        cancel_thread.start()
        with patch.object(operations, "_start_source_sync_process", side_effect=start):
            result = execute(self.settings, self.store, self.ops, claimed)
        cancel_thread.join(timeout=5)
        self.ops.finish(task["id"], result)
        self.assertEqual(result["status"], "cancelled")
        self.assertFalse(target.exists())
        self.assertTrue(processes)
        self.assertIsNotNone(processes[0].poll())
        self.assertEqual(self.ops.get(task["id"])["status"], "cancelled")
        self.assertIsNone(result["scan_job_id"])

    def test_failed_single_sync_removes_partial_clone(self):
        task, claimed = self._task()
        target = self.cache / "source-sync-fixture"

        def fail_after_partial_clone(_command, _environment):
            target.mkdir(parents=True, exist_ok=True)
            return subprocess.Popen(
                [sys.executable, "-c", "raise SystemExit(7)"],
                start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

        with patch.object(operations, "_start_source_sync_process",
                          side_effect=fail_after_partial_clone):
            result = execute(self.settings, self.store, self.ops, claimed)
        self.ops.finish(task["id"], result)
        self.assertEqual(result["status"], "failed")
        self.assertIn("exit status 7", result["error"])
        self.assertFalse(target.exists())
        self.assertEqual(self.store.repositories(), [])
        self.assertEqual(self.ops.get(task["id"])["status"], "failed")


if __name__ == "__main__":
    unittest.main()

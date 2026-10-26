import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.workbench import repository_import
from src.workbench.api import create_app
from src.workbench.operations_store import Operations
from src.workbench.operations import execute as execute_operation
from src.workbench.settings import Settings
from src.workbench.store import Store


HEADERS = {"x-ohscanner-client": "workbench-v1"}
DOTTED_GITCODE_REPOSITORIES = (
    "kernel_linux_4.19",
    "kernel_linux_5.10",
    "third_party_rust_lazy-static.rs",
    "kernel_linux_6.6",
    "third_party_decimal.js",
    ".gitcode",
)


def git(path, *args):
    return subprocess.check_output(["git", "-C", str(path), *args], text=True,
                                   stderr=subprocess.PIPE).strip()


def init_repo(path, *, submodule=False):
    path.mkdir(parents=True)
    (path / "sample.cpp").write_text("int sample() { return 1; }\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    git(path, "config", "user.name", "test")
    git(path, "config", "user.email", "test@example.invalid")
    git(path, "add", ".")
    git(path, "commit", "-qm", "fixture")
    branch = git(path, "branch", "--show-current")
    if submodule:
        (path / "sample.cpp").write_text("int sample() { return 2; }\n", encoding="utf-8")
        git(path, "add", "sample.cpp")
        git(path, "update-index", "--add", "--cacheinfo", "160000," + "a" * 40 + ",vendor/child")
        git(path, "commit", "-qm", "submodule gitlink")
    return branch, git(path, "rev-parse", "HEAD"), git(path, "rev-parse", "HEAD^{tree}")


class RepositoryImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.data = self.base / "data"
        self.cache = self.base / "cache"
        self.cache.mkdir()
        self.source = self.base / "source"
        self.branch, self.commit, self.tree = init_repo(self.source)
        self.settings = Settings(self.data, (), repository_cache_roots=(self.cache,),
                                 repository_cache_min_free_bytes=0)
        self.settings.initialize()
        self.store = Store(self.data)
        self.spec = {"slug": "fixture", "name": "openharmony/fixture", "branch": self.branch,
                     "commit": self.commit, "preview_sha256": "b" * 64,
                     "clone_url": "https://gitcode.com/openharmony/fixture.git",
                     "include_paths": ["."], "detector_ids": None, "timeout_seconds": 30,
                     "scan_timeout_seconds": 30, "memory_mb": 256, "estimated_size_kib": 64}
        self.make_spec_patch = patch.object(
            repository_import.service,
            "make_spec",
            return_value={"commit": self.commit, "git_tree": self.tree, "timeout_seconds": 30},
        )
        self.make_spec_mock = self.make_spec_patch.start()
        self.addCleanup(self.make_spec_patch.stop)

    def fake_fetch(self, stage, slug, branch, commit, timeout, **_limits):
        subprocess.run(["git", "clone", "--no-checkout", "--no-recurse-submodules", "--depth=1",
                        "--single-branch", "--no-tags", "--branch", branch, "--",
                        str(self.source), str(stage)], check=True, capture_output=True)
        return git(stage, "rev-parse", commit + "^{tree}")

    def run_import(self, progress=None):
        return repository_import.import_and_queue_scan(self.settings, self.store, self.spec,
                                                        progress=progress)

    def test_git_progress_output_is_normalized_for_the_operation_api(self):
        parsed = repository_import._parse_git_progress(
            "Receiving objects: 42% (123/456), 1.25 MiB | 512.00 KiB/s")
        self.assertEqual(parsed, {
            "phase": "receiving_objects", "percent": 42,
            "completed_objects": 123, "total_objects": 456,
            "received_bytes": 1310720, "bytes_per_second": 524288,
        })
        self.assertIsNone(repository_import._parse_git_progress("fatal: repository unavailable"))

    def test_clone_progress_pipe_is_drained_and_forwarded(self):
        stage = self.cache / "openharmony" / "fixture" / ("." + self.commit + ".progress-test")
        stage.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--no-checkout", str(self.source), str(stage)],
                       check=True, capture_output=True)
        original_popen = subprocess.Popen
        progress = []

        class ProgressProcess:
            def __init__(self):
                read_fd, write_fd = os.pipe()
                self.stderr = os.fdopen(read_fd, "rb", buffering=0)
                self.returncode = None
                self.pid = 12345

                def write_progress():
                    os.write(write_fd, b"Receiving objects: 42% (123/456), 1.25 MiB | 512.00 KiB/s\r")
                    os.close(write_fd)
                    self.returncode = 0

                self.thread = threading.Thread(target=write_progress)
                self.thread.start()

            def poll(self):
                return self.returncode

            def communicate(self):
                self.thread.join(timeout=2)
                self.stderr.close()
                return b"", b""

        def popen(command, **kwargs):
            return ProgressProcess() if "clone" in command else original_popen(command, **kwargs)

        with patch.object(repository_import, "approved_clone_url",
                          return_value="https://gitcode.com/openharmony/fixture.git"), patch.object(
                repository_import.subprocess, "Popen", side_effect=popen):
            tree = repository_import._fetch_to_stage(stage, "fixture", self.branch, self.commit,
                                                      5, progress=progress.append)
        self.assertEqual(tree, self.tree)
        self.assertEqual(progress[0]["phase"], "receiving_objects")
        self.assertEqual(progress[0]["percent"], 42)
        self.assertEqual(progress[0]["received_bytes"], 1310720)

    def test_success_downloads_fixed_commit_and_queues_static_job_without_checkout(self):
        with patch.object(repository_import, "_fetch_to_stage", side_effect=self.fake_fetch) as fetch:
            result = self.run_import()
        target = self.cache / "openharmony" / "fixture" / self.commit
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(result["commit"], self.commit)
        self.assertEqual(result["git_tree"], self.tree)
        self.assertEqual(result["scan_job"]["status"], "queued")
        self.assertEqual(result["cache"], "downloaded")
        self.assertFalse((target / "sample.cpp").exists(), "source was not checked out")
        self.assertEqual(self.store.job(result["scan_job"]["id"])["spec"]["commit"], self.commit)
        self.assertEqual(result["source_provenance"].startswith("GitCode public"), True)

    def test_selected_destination_is_used_and_registered_for_the_queued_scan(self):
        destination = self.base / "chosen-downloads"
        spec = {**self.spec, "destination_dir": str(destination)}
        with patch.object(repository_import, "_fetch_to_stage", side_effect=self.fake_fetch):
            result = repository_import.import_and_queue_scan(self.settings, self.store, spec)
        target = destination / "openharmony" / "fixture" / self.commit
        self.assertTrue(target.is_dir())
        self.assertEqual(result["destination_dir"], str(destination))
        self.assertEqual(self.store.job(result["scan_job"]["id"])["repository_id"],
                         result["repository"]["id"])
        self.assertIn(destination, self.settings.target_roots)
        self.assertEqual(result["scan_job"]["status"], "queued")

    def test_exact_cache_hit_queues_scan_without_fetch(self):
        with patch.object(repository_import, "_fetch_to_stage", side_effect=self.fake_fetch):
            first = self.run_import()
        with patch.object(repository_import, "_fetch_to_stage", side_effect=AssertionError("network fetch on cache hit")):
            second = self.run_import()
        self.assertEqual(second["cache"], "hit")
        self.assertNotEqual(first["scan_job"]["id"], second["scan_job"]["id"])

    def test_same_repository_concurrent_import_only_fetches_once(self):
        count = 0
        guard = threading.Lock()
        def delayed_fetch(*args, **kwargs):
            nonlocal count
            with guard:
                count += 1
            time.sleep(.1)
            return self.fake_fetch(*args, **kwargs)
        results, failures = [], []
        def invoke():
            try:
                results.append(self.run_import())
            except Exception as exc:
                failures.append(exc)
        with patch.object(repository_import, "_fetch_to_stage", side_effect=delayed_fetch):
            threads = [threading.Thread(target=invoke) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join(10)
        self.assertFalse(failures, failures)
        self.assertEqual(count, 1)
        self.assertEqual(len(results), 2)
        self.assertEqual({item["cache"] for item in results}, {"downloaded", "hit"})
        self.assertIs(repository_import.service.make_spec, self.make_spec_mock)

    def test_disk_reserve_failure_is_fail_closed_before_fetch(self):
        settings = Settings(self.data, (), repository_cache_roots=(self.cache,),
                            repository_cache_min_free_bytes=10 ** 30)
        with patch.object(repository_import, "_fetch_to_stage", side_effect=AssertionError("fetch called")):
            with self.assertRaisesRegex(OSError, "capacity"):
                repository_import.import_and_queue_scan(settings, self.store, self.spec)
        self.assertFalse((self.cache / "openharmony" / "fixture" / self.commit).exists())

    def test_git_disk_full_error_cleans_staging_and_preserves_scan_queue(self):
        def disk_full(*args, **kwargs):
            raise OSError("repository cache disk is full")
        with patch.object(repository_import, "_fetch_to_stage", side_effect=disk_full):
            with self.assertRaisesRegex(OSError, "disk is full"):
                self.run_import()
        self.assertEqual(list((self.cache / "openharmony" / "fixture").glob("." + self.commit + ".import-*")), [])
        self.assertEqual(self.store.jobs(), [])

    def test_symlink_cache_root_and_path_escape_are_rejected(self):
        link = self.base / "cache-link"
        link.symlink_to(self.cache, target_is_directory=True)
        unsafe = Settings(self.data, (), repository_cache_roots=(link,), repository_cache_min_free_bytes=0)
        with self.assertRaisesRegex(OSError, "safe paths"):
            repository_import.import_and_queue_scan(unsafe, self.store, self.spec)
        escaped = {**self.spec, "slug": "../outside", "clone_url": "https://gitcode.com/openharmony/../outside.git"}
        with self.assertRaisesRegex(ValueError, "repository name"):
            repository_import.import_and_queue_scan(self.settings, self.store, escaped)

    def test_timeout_cleans_only_owned_staging_directory(self):
        def timeout_after_stage(stage, *args, **kwargs):
            stage.mkdir()
            (stage / "partial.pack").write_bytes(b"partial")
            raise subprocess.TimeoutExpired("git", 1)
        with patch.object(repository_import, "_fetch_to_stage", side_effect=timeout_after_stage):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.run_import()
        self.assertEqual(list((self.cache / "openharmony" / "fixture").glob("." + self.commit + ".import-*")), [])

    def test_git_redirect_is_disabled_and_rejected(self):
        observed = {}
        class RedirectedGit:
            returncode = 1
            pid = None
            def poll(self): return 1
            def communicate(self): return b"", b"fatal: redirect refused"
        def fail_redirect(command, **kwargs):
            observed["command"] = command
            observed["env"] = kwargs["env"]
            return RedirectedGit()
        stage = self.cache / "openharmony" / "fixture" / ".redirect-stage"
        (stage.parent).mkdir(parents=True, exist_ok=True)
        with patch.object(repository_import.subprocess, "Popen", side_effect=fail_redirect):
            with self.assertRaisesRegex(ValueError, "redirect refused"):
                repository_import._fetch_to_stage(stage, "fixture", self.branch, self.commit, 3)
        self.assertIn("http.followRedirects=false", observed["command"])
        self.assertIn("--no-recurse-submodules", observed["command"])
        self.assertNotIn("--recurse-submodules", observed["command"])
        self.assertEqual(observed["env"]["GIT_ALLOW_PROTOCOL"], "https")

    def test_cache_quota_stops_an_in_progress_clone(self):
        stage = self.cache / "openharmony" / "fixture" / ".quota-stage"
        def start_limited(command, **kwargs):
            stage.mkdir(parents=True)
            (stage / "partial.pack").write_bytes(b"more than quota")
            class RunningGit:
                pid = 987654321
                returncode = None
                def poll(self): return self.returncode
                def terminate(self): self.returncode = -15
                def communicate(self, timeout=None): return b"", b""
                def kill(self): self.returncode = -9
            return RunningGit()
        with patch.object(repository_import.subprocess, "Popen", side_effect=start_limited), patch.object(
                repository_import.os, "killpg", side_effect=ProcessLookupError):
            with self.assertRaisesRegex(OSError, "quota would be exceeded"):
                repository_import._fetch_to_stage(stage, "fixture", self.branch, self.commit, 5,
                                                  cache_root=self.cache, cache_max_bytes=1)

    def test_submodule_gitlink_is_rejected_without_recursing(self):
        sub_source = self.base / "subsource"
        _, sub_commit, _ = init_repo(sub_source)
        bad_source = self.base / "submodule-root"
        branch, commit, _tree = init_repo(bad_source, submodule=True)
        git(bad_source, "update-index", "--cacheinfo", "160000," + sub_commit + ",vendor/child")
        git(bad_source, "commit", "-qm", "point at an existing gitlink")
        commit = git(bad_source, "rev-parse", "HEAD")
        stage = self.cache / "openharmony" / "fixture" / ".submodule-stage"
        original = repository_import.subprocess.Popen
        def clone_local(command, **kwargs):
            # Preserve and assert the production command's protocol/redirect/submodule
            # policy, then substitute only the fixture URL for a local test repository.
            if "clone" not in command:
                return original(command, **kwargs)
            self.assertIn("--no-recurse-submodules", command)
            self.assertIn("http.followRedirects=false", command)
            altered = list(command)
            separator = altered.index("--")
            altered[separator + 1] = str(bad_source)
            env = dict(kwargs["env"], GIT_ALLOW_PROTOCOL="file:https")
            return original(altered, **{**kwargs, "env": env})
        with patch.object(repository_import, "approved_clone_url", return_value="https://gitcode.com/openharmony/fixture.git"), patch.object(
                repository_import.subprocess, "Popen", side_effect=clone_local):
            with self.assertRaisesRegex(ValueError, "submodules"):
                repository_import._fetch_to_stage(stage, "fixture", branch, commit, 30)

    def test_real_dotted_names_are_valid_import_cache_paths_and_reuse(self):
        for slug in DOTTED_GITCODE_REPOSITORIES:
            with self.subTest(slug=slug):
                spec = {**self.spec, "slug": slug, "name": "openharmony/" + slug,
                        "clone_url": repository_import.approved_clone_url(slug)}
                with patch.object(repository_import.service, "make_spec", return_value={
                        "commit": self.commit, "git_tree": self.tree, "timeout_seconds": 30}), patch.object(
                        repository_import, "_fetch_to_stage", side_effect=self.fake_fetch) as fetch:
                    first = repository_import.import_and_queue_scan(self.settings, self.store, spec)
                target = self.cache / "openharmony" / slug / self.commit
                self.assertTrue(target.is_dir())
                self.assertEqual(first["cache"], "downloaded")
                self.assertEqual(fetch.call_count, 1)
                with patch.object(repository_import.service, "make_spec", return_value={
                        "commit": self.commit, "git_tree": self.tree, "timeout_seconds": 30}), patch.object(
                        repository_import, "_fetch_to_stage",
                        side_effect=AssertionError("cache hit must not fetch")):
                    second = repository_import.import_and_queue_scan(self.settings, self.store, spec)
                self.assertEqual(second["cache"], "hit")
                self.assertNotEqual(first["scan_job"]["id"], second["scan_job"]["id"])

    def test_api_accepts_real_dotted_names_and_returns_422_for_unsafe_slugs(self):
        from src.workbench.operations import approved_url
        from src.workbench.source_catalog import approved_clone_url
        for unsafe_url in (
            "https://gitcode.com/openharmony/bad%2Fslug.git",
            "https://gitcode.com/openharmony/%2E%2E.git",
            "https://gitcode.com/openharmony/bad%5Cslug.git",
            "https://gitcode.com/openharmony/bad%0Aslug.git",
        ):
            with self.subTest(unsafe_url=unsafe_url), self.assertRaises(ValueError):
                approved_url(unsafe_url)
        client = TestClient(create_app(self.settings))
        self.addCleanup(client.close)
        commit = "1" * 40
        preview_hash = "2" * 64
        for slug in DOTTED_GITCODE_REPOSITORIES:
            with self.subTest(slug=slug), patch(
                    "src.workbench.operations_api.repository_preview", return_value={"slug": slug}):
                response = client.post("/api/v1/repositories/official-catalog/preview",
                                       headers=HEADERS, json={"slug": slug})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["slug"], slug)
            fixed_preview = {"name": "openharmony/" + slug, "catalog_sha256": "3" * 64, "size_kib": 64}
            with self.subTest(import_slug=slug), patch(
                    "src.workbench.operations_api.validate_preview", return_value=fixed_preview):
                imported = client.post("/api/v1/operations/repository-import-scans", headers=HEADERS,
                                       json={"slug": slug, "branch": "master", "commit": commit,
                                             "preview_sha256": preview_hash})
            self.assertEqual(imported.status_code, 201, imported.text)
            self.assertEqual(Operations(self.store).get(imported.json()["id"])["spec"]["clone_url"],
                             approved_clone_url(slug))
            legacy = client.post("/api/v1/operations/source-sync", headers=HEADERS,
                                 json={"repository": "openharmony/" + slug,
                                       "url": approved_clone_url(slug)})
            self.assertEqual(legacy.status_code, 201, legacy.text)

        invalid = ("", ".", "..", "../escape", "nested/repo", "bad" + chr(10) + "slug")
        for slug in invalid:
            with self.subTest(unsafe_preview=slug):
                rejected_preview = client.post("/api/v1/repositories/official-catalog/preview",
                                               headers=HEADERS, json={"slug": slug})
            self.assertEqual(rejected_preview.status_code, 422)
            with self.subTest(unsafe_import=slug):
                rejected_import = client.post(
                    "/api/v1/operations/repository-import-scans", headers=HEADERS,
                    json={"slug": slug, "branch": "master", "commit": commit,
                          "preview_sha256": preview_hash})
            self.assertEqual(rejected_import.status_code, 422)
            with self.subTest(unsafe_legacy=slug):
                rejected_legacy = client.post(
                    "/api/v1/operations/source-sync", headers=HEADERS,
                    json={"repository": "openharmony/" + slug,
                          "url": "https://gitcode.com/openharmony/" + slug + ".git"})
            self.assertEqual(rejected_legacy.status_code, 422)

    def test_durable_operation_worker_dispatches_repository_import_scan(self):
        ops = Operations(self.store)
        task = ops.create("repository_import_scan", self.spec)
        def successful_import(settings, store, spec, progress=None):
            progress({"state": "running", "phase": "receiving_objects", "percent": 42,
                      "completed_objects": 123, "total_objects": 456,
                      "message": "Git 正在接收固定版本对象"})
            return {"status": "completed", "cache": "hit"}
        with patch.object(repository_import, "import_and_queue_scan",
                          side_effect=successful_import) as run_import:
            result = execute_operation(self.settings, self.store, ops, task)
        self.assertEqual(run_import.call_args.args, (self.settings, self.store, self.spec))
        self.assertTrue(callable(run_import.call_args.kwargs["progress"]))
        self.assertEqual(result, {"status": "completed", "cache": "hit"})
        self.assertIn("repository_import", [event["stage"] for event in ops.events(task["id"])])
        client = TestClient(create_app(self.settings))
        self.addCleanup(client.close)
        detail = client.get("/api/v1/operations/" + task["id"])
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertEqual(detail.json()["download_progress"]["phase"], "receiving_objects")
        self.assertEqual(detail.json()["download_progress"]["percent"], 42)

    def test_failed_repository_import_can_be_explicitly_retried_once_per_attempt(self):
        ops = Operations(self.store)
        original = ops.create("repository_import_scan", self.spec)
        claimed = ops.claim()
        self.assertEqual(claimed["id"], original["id"])
        ops.finish(original["id"], error="GitCode temporarily unavailable", state="failed")
        client = TestClient(create_app(self.settings))
        self.addCleanup(client.close)

        response = client.post("/api/v1/operations/" + original["id"] + "/retry", headers=HEADERS)
        self.assertEqual(response.status_code, 201, response.text)
        retried = response.json()
        self.assertEqual(retried["kind"], "repository_import_scan")
        self.assertEqual(retried["status"], "queued")
        self.assertEqual(retried["spec"]["commit"], self.commit)
        self.assertEqual(retried["spec"]["preview_sha256"], self.spec["preview_sha256"])
        self.assertEqual(retried["spec"]["retry_of"], original["id"])
        self.assertEqual(ops.get(original["id"])["status"], "failed")
        self.assertEqual(ops.events(retried["id"])[0]["stage"], "retry_queued")

        repeated = client.post("/api/v1/operations/" + original["id"] + "/retry", headers=HEADERS)
        self.assertEqual(repeated.status_code, 200, repeated.text)
        self.assertEqual(repeated.json()["id"], retried["id"])
        self.assertEqual(len([item for item in ops.list()
                              if item["spec"].get("retry_of") == original["id"]]), 1)

    def test_repository_import_retry_rejects_active_completed_and_other_operation(self):
        ops = Operations(self.store)
        client = TestClient(create_app(self.settings))
        self.addCleanup(client.close)
        active = ops.create("repository_import_scan", self.spec)
        response = client.post("/api/v1/operations/" + active["id"] + "/retry", headers=HEADERS)
        self.assertEqual(response.status_code, 409, response.text)
        ops.cancel(active["id"])

        completed = ops.create("repository_import_scan", {**self.spec, "slug": "completed"})
        self.assertEqual(ops.claim()["id"], completed["id"])
        ops.finish(completed["id"], {"status": "completed"})
        response = client.post("/api/v1/operations/" + completed["id"] + "/retry", headers=HEADERS)
        self.assertEqual(response.status_code, 409, response.text)

        other = ops.create("source_sync", {"name": "openharmony/fixture", "url": "https://gitcode.com/openharmony/fixture.git"})
        self.assertEqual(ops.claim()["id"], other["id"])
        ops.finish(other["id"], error="failed", state="failed")
        response = client.post("/api/v1/operations/" + other["id"] + "/retry", headers=HEADERS)
        self.assertEqual(response.status_code, 409, response.text)

        missing = client.post("/api/v1/operations/" + "f" * 32 + "/retry", headers=HEADERS)
        self.assertEqual(missing.status_code, 404, missing.text)

    def test_repository_import_retry_accepts_interrupted_and_timed_out_attempts_only(self):
        ops = Operations(self.store)
        client = TestClient(create_app(self.settings))
        self.addCleanup(client.close)
        for index, state in enumerate(("interrupted", "timed_out")):
            task = ops.create("repository_import_scan", {**self.spec, "slug": "retryable-" + str(index)})
            self.assertEqual(ops.claim()["id"], task["id"])
            ops.finish(task["id"], error="worker ended", state=state)
            response = client.post("/api/v1/operations/" + task["id"] + "/retry", headers=HEADERS)
            self.assertEqual(response.status_code, 201, response.text)
            self.assertEqual(response.json()["spec"]["retry_of"], task["id"])
            ops.cancel(response.json()["id"])

        cancelled = ops.create("repository_import_scan", {**self.spec, "slug": "cancelled"})
        ops.cancel(cancelled["id"])
        response = client.post("/api/v1/operations/" + cancelled["id"] + "/retry", headers=HEADERS)
        self.assertEqual(response.status_code, 409, response.text)

    def test_import_api_and_legacy_source_sync_route_both_remain_available(self):
        client = TestClient(create_app(self.settings))
        self.addCleanup(client.close)
        catalog_result = {"items": [{"slug": "fixture"}], "total": 1, "page": 1,
                          "per_page": 30, "catalog_total_count": 808,
                          "provenance": {"source": "GitCode public organization repository API",
                                         "identity_note": "Not independent identity verification"}}
        with patch("src.workbench.operations_api.public_repository_catalog", return_value=catalog_result) as listing:
            listed = client.get("/api/v1/repositories/official-catalog?q=fixture&page=1&per_page=30")
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(listed.json()["items"], [{"slug": "fixture"}])
        self.assertIn("identity_note", listed.json()["provenance"])
        self.assertEqual(listing.call_args.kwargs["query"], "fixture")
        preview = {"name": "openharmony/fixture", "slug": "fixture", "default_branch": "main",
                   "commit": "1" * 40, "preview_sha256": "2" * 64, "catalog_sha256": "3" * 64,
                   "size_kib": 64}
        selected_destination = self.base / "api-selected-downloads"
        with patch("src.workbench.operations_api.validate_preview", return_value=preview):
            response = client.post("/api/v1/operations/repository-import-scans", headers=HEADERS,
                                   json={"slug": "fixture", "branch": "main", "commit": "1" * 40,
                                         "preview_sha256": "2" * 64,
                                         "destination_dir": str(selected_destination)})
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["kind"], "repository_import_scan")
        imported = Operations(self.store).get(response.json()["id"])
        self.assertEqual(imported["spec"]["destination_dir"], str(selected_destination))
        self.assertFalse(selected_destination.exists(), "API preview/queue must not create the selected directory")
        legacy = client.post("/api/v1/operations/source-sync", headers=HEADERS,
                             json={"repository": "openharmony/fixture",
                                   "url": "https://gitcode.com/openharmony/fixture.git"})
        self.assertEqual(legacy.status_code, 201, legacy.text)
        self.assertEqual(legacy.json()["kind"], "source_sync")
        self.assertEqual(Operations(self.store).get(response.json()["id"])["kind"], "repository_import_scan")


if __name__ == "__main__":
    unittest.main()

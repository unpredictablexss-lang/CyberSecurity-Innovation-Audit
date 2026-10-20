import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.workbench.api import create_app
from src.workbench import repository_management
from src.workbench.settings import Settings


HEADERS = {"x-ohscanner-client": "workbench-v1"}


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL, text=True
    ).strip()


def init_repo(path):
    path.mkdir(parents=True, exist_ok=True)
    (path / "sample.cpp").write_text("int sample() { return 1; }\n", encoding="utf-8")
    git(path, "init", "-q")
    git(path, "config", "user.name", "test")
    git(path, "config", "user.email", "test@example.invalid")
    git(path, "add", ".")
    git(path, "commit", "-qm", "fixed")
    return path


class RepositoryManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "trusted"
        self.root.mkdir()
        self.settings = Settings(self.base / "data", (self.root,))
        self.client = TestClient(create_app(self.settings))
        self.addCleanup(self.client.close)

    def register(self, name, path):
        response = self.client.post(
            "/api/v1/repositories",
            json={"name": name, "path": str(path)},
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_online_catalog_discovers_only_openharmony_org_and_caches_page(self):
        class Response:
            headers = {"Link": '<https://api.github.com/orgs/openharmony/repos?per_page=100&page=2>; rel="next"'}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return json.dumps([
                    {"name": "commonlibrary", "full_name": "openharmony/commonlibrary",
                     "owner": {"login": "openharmony"}, "default_branch": "master",
                     "description": "public source", "stargazers_count": 12,
                     "updated_at": "2026-10-01T00:00:00Z", "archived": False, "fork": False},
                    {"name": "spoof", "full_name": "attacker/spoof",
                     "owner": {"login": "attacker"}, "default_branch": "main"},
                    {"name": "bad/name", "full_name": "openharmony/bad/name",
                     "owner": {"login": "openharmony"}, "default_branch": "main"},
                ]).encode()

        repository_management._ONLINE_CATALOG_CACHE.clear()
        with patch("src.workbench.repository_management.urlopen", return_value=Response()) as open_url:
            response = self.client.get("/api/v1/repositories/online-catalog?page=1")
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()
            self.assertEqual(result["next_page"], 2)
            self.assertFalse(result["identity_verified"])
            self.assertEqual([row["name"] for row in result["repositories"]],
                             ["openharmony/commonlibrary"])
            self.assertEqual(result["repositories"][0]["url"],
                             "https://github.com/openharmony/commonlibrary.git")
            self.assertEqual(self.client.get("/api/v1/repositories/online-catalog?page=1").status_code, 200)
            self.assertEqual(open_url.call_count, 1)

    def test_online_catalog_rejects_out_of_bound_page(self):
        with self.assertRaisesRegex(ValueError, "between 1 and 20"):
            repository_management.online_repository_catalog(21)
        response = self.client.get("/api/v1/repositories/online-catalog?page=21")
        self.assertEqual(response.status_code, 422, response.text)

    def test_catalog_hides_paths_and_disambiguates_duplicate_names(self):
        first = init_repo(self.root / "first")
        second = init_repo(self.root / "second")
        self.register("local/sample", first)
        self.register("local/sample", second)

        response = self.client.get("/api/v1/repositories/catalog")
        self.assertEqual(response.status_code, 200, response.text)
        rows = response.json()
        self.assertEqual([row["display_name"] for row in rows],
                         ["local/sample（trusted · 副本 1）", "local/sample（trusted · 副本 2）"])
        self.assertEqual([row["root_alias"] for row in rows], ["trusted", "trusted"])
        self.assertTrue(all(row["status"] == "available" for row in rows))
        self.assertTrue(all(row["head_commit"] for row in rows))
        self.assertNotIn(str(first), response.text)
        self.assertNotIn(str(second), response.text)
        self.assertNotIn('"path"', response.text)

        ordinary = self.client.get("/api/v1/repositories/list")
        self.assertEqual(ordinary.status_code, 200, ordinary.text)
        self.assertNotIn(str(first), ordinary.text)
        self.assertNotIn('"path"', ordinary.text)
        legacy_ordinary = self.client.get("/api/v1/repositories")
        self.assertEqual(legacy_ordinary.status_code, 200, legacy_ordinary.text)
        self.assertNotIn(str(first), legacy_ordinary.text)
        self.assertNotIn('"path"', legacy_ordinary.text)
        managed = self.client.get("/api/v1/repositories/managed")
        self.assertEqual(managed.status_code, 200, managed.text)
        self.assertIn(str(first), managed.text)
        roots = self.client.get("/api/v1/repositories/roots")
        self.assertEqual(roots.status_code, 200, roots.text)
        self.assertEqual(roots.json()[0]["repository_count"], 2)
        self.assertEqual(roots.json()[0]["path"], str(self.root))
        health = self.client.get("/api/v1/health")
        self.assertEqual(health.status_code, 200, health.text)
        self.assertNotIn(str(self.root), health.text)
        self.assertNotIn("target_roots", health.json())

    def test_catalog_accepts_bare_repository_with_resolvable_head(self):
        source = init_repo(self.root / "source")
        bare = self.root / "mirror.git"
        git(source, "clone", "--bare", str(source), str(bare))
        self.register("local/mirror", bare)

        response = self.client.get("/api/v1/repositories/catalog")
        self.assertEqual(response.status_code, 200, response.text)
        row = response.json()[0]
        self.assertEqual(row["status"], "available")
        self.assertEqual(row["head_commit"], git(bare, "rev-parse", "HEAD"))

    def test_revisions_mark_the_repository_default_ref(self):
        path = init_repo(self.root / "default-branch")
        registered = self.register("local/default-branch", path)
        expected = git(path, "symbolic-ref", "--quiet", "HEAD")

        response = self.client.get(
            "/api/v1/repositories/" + registered["id"] + "/revisions"
        )
        self.assertEqual(response.status_code, 200, response.text)
        rows = response.json()
        defaults = [row["ref"] for row in rows if row.get("is_default")]
        self.assertEqual(defaults, [expected])
        self.assertTrue(all("path" not in row for row in rows))

    def test_catalog_rejects_git_metadata_outside_trusted_roots(self):
        outside = init_repo(self.base / "outside")
        candidate = self.root / "redirected"
        candidate.mkdir()
        (candidate / ".git").write_text(
            "gitdir: " + str(outside / ".git") + "\n", encoding="utf-8"
        )
        self.settings.data_dir.mkdir(parents=True, exist_ok=True)
        app = self.client.app
        app.state.store.add_repository("local/redirected", candidate)

        response = self.client.get("/api/v1/repositories/catalog")
        self.assertEqual(response.status_code, 200, response.text)
        row = next(item for item in response.json() if item["name"] == "local/redirected")
        self.assertEqual(row["status"], "unavailable")
        self.assertIn("已批准", row["reason"])
        self.assertNotIn(str(outside), response.text)

    def test_discovery_is_bounded_and_does_not_follow_symlinks(self):
        registered_path = init_repo(self.root / "registered")
        discoverable_path = init_repo(self.root / "discoverable")
        outside_path = init_repo(self.base / "outside-link-target")
        self.register("local/registered", registered_path)
        (self.root / "linked-outside").symlink_to(outside_path, target_is_directory=True)

        response = self.client.get("/api/v1/repositories/discover?root_index=0")
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["registered_count"], 1)
        self.assertEqual([row["path"] for row in result["repositories"]], [str(discoverable_path)])
        self.assertEqual(result["repositories"][0]["name_guess"], "local/discoverable")
        self.assertFalse(result["truncated"])
        self.assertNotIn(str(outside_path), response.text)

    def test_discovery_skips_repository_without_a_commit(self):
        committed = init_repo(self.root / "committed")
        unborn = self.root / "unborn"
        unborn.mkdir()
        git(unborn, "init", "-q")

        response = self.client.get("/api/v1/repositories/discover?root_index=0")
        self.assertEqual(response.status_code, 200, response.text)
        rows = response.json()["repositories"]
        self.assertEqual([row["path"] for row in rows], [str(committed)])

    def test_managed_source_root_is_persisted_and_used_for_discovery_and_registration(self):
        managed = self.base / "managed-source"
        managed.mkdir()
        repo = init_repo(managed / "communication_dsoftbus")

        response = self.client.post(
            "/api/v1/repositories/roots",
            json={"alias": "G盘 OpenHarmony 镜像", "path": str(managed)},
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 201, response.text)
        root = response.json()
        self.assertTrue(root["managed"])
        self.assertNotIn("inode", root)
        self.assertEqual(root["path"], str(managed.resolve()))
        self.assertIn(managed.resolve(), self.settings.target_roots)
        self.assertEqual((self.settings.data_dir / "managed-source-roots.json").stat().st_mode & 0o777, 0o600)

        # A fresh Settings instance (as used by worker processes) sees the same allowlist.
        from src.workbench.settings import Settings
        child_settings = Settings(self.settings.data_dir, self.settings._configured_target_roots)
        self.assertIn(managed.resolve(), child_settings.target_roots)
        from src.workbench.service import check_repository
        self.assertEqual(check_repository(child_settings, repo), repo.resolve())

        listed = self.client.get("/api/v1/repositories/roots")
        row = next(item for item in listed.json() if item["id"] == root["id"])
        self.assertEqual(row["alias"], "G盘 OpenHarmony 镜像")
        self.assertTrue(row["managed"])

        discovered = self.client.get("/api/v1/repositories/discover", params={"root_id": root["id"]})
        self.assertEqual(discovered.status_code, 200, discovered.text)
        self.assertEqual(discovered.json()["root_name"], "G盘 OpenHarmony 镜像")
        self.assertEqual(discovered.json()["repositories"][0]["path"], str(repo))

        registered = self.register("local/managed", repo)
        self.assertEqual(registered["path"], str(repo))
        self.assertEqual(self.client.get("/api/v1/repositories/catalog").json()[0]["status"], "available")

    def test_managed_source_root_rejects_symlinks_broad_paths_and_world_writable_paths(self):
        target = self.base / "real-root"
        target.mkdir()
        symlink = self.base / "root-link"
        symlink.symlink_to(target, target_is_directory=True)

        linked = self.client.post(
            "/api/v1/repositories/roots",
            json={"alias": "linked", "path": str(symlink)},
            headers=HEADERS,
        )
        self.assertEqual(linked.status_code, 409)
        self.assertIn("符号链接", linked.json()["detail"])

        data_root = self.client.post(
            "/api/v1/repositories/roots",
            json={"alias": "data", "path": str(self.settings.data_dir)},
            headers=HEADERS,
        )
        self.assertEqual(data_root.status_code, 409)
        self.assertIn("工作台", data_root.json()["detail"])

        broad = self.client.post(
            "/api/v1/repositories/roots",
            json={"alias": "temporary", "path": "/tmp"},
            headers=HEADERS,
        )
        self.assertEqual(broad.status_code, 409)

        world_writable = self.base / "world-writable"
        world_writable.mkdir()
        world_writable.chmod(0o777)
        unsafe = self.client.post(
            "/api/v1/repositories/roots",
            json={"alias": "unsafe", "path": str(world_writable)},
            headers=HEADERS,
        )
        self.assertEqual(unsafe.status_code, 409)
        self.assertIn("其他用户或共享组写入", unsafe.json()["detail"])

    def test_removing_managed_root_disables_repository_without_erasing_history(self):
        managed = self.base / "removable-source"
        repo = init_repo(managed / "project")
        response = self.client.post(
            "/api/v1/repositories/roots",
            json={"alias": "removable", "path": str(managed)},
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.register("local/removable", repo)

        removed = self.client.delete(
            "/api/v1/repositories/roots/" + response.json()["id"],
            headers=HEADERS,
        )
        self.assertEqual(removed.status_code, 200, removed.text)
        self.assertNotIn(managed.resolve(), self.settings.target_roots)
        catalog = self.client.get("/api/v1/repositories/catalog").json()
        self.assertEqual(catalog[0]["status"], "unavailable")
        rejected = self.client.post(
            "/api/v1/repositories",
            json={"name": "local/outside", "path": str(repo)},
            headers=HEADERS,
        )
        self.assertEqual(rejected.status_code, 409)
        self.assertIn("outside configured target roots", rejected.json()["detail"])

    def test_moving_repository_requires_registration_at_its_new_path(self):
        original = init_repo(self.root / "before-move")
        registered = self.register("local/moved", original)
        moved = self.root / "after-move"
        original.rename(moved)

        catalog = self.client.get("/api/v1/repositories/catalog").json()
        self.assertEqual(catalog[0]["status"], "unavailable")

        replacement = self.register("local/moved", moved)
        self.assertNotEqual(replacement["id"], registered["id"])
        catalog = self.client.get("/api/v1/repositories/catalog").json()
        self.assertEqual([row["status"] for row in catalog], ["unavailable", "available"])
        self.assertEqual(catalog[0]["id"], registered["id"])
        self.assertEqual(catalog[1]["id"], replacement["id"])

    def test_managed_root_symlink_swap_invalidates_existing_repository(self):
        managed = self.base / "movable-source"
        repo = init_repo(managed / "project")
        response = self.client.post(
            "/api/v1/repositories/roots",
            json={"alias": "movable", "path": str(managed)},
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.register("local/movable", repo)

        outside = self.base / "replacement"
        outside.mkdir()
        (managed / "project").rename(outside / "project")
        managed.rename(self.base / "original-source")
        managed.symlink_to(outside, target_is_directory=True)

        catalog = self.client.get("/api/v1/repositories/catalog").json()
        self.assertEqual(catalog[0]["status"], "unavailable")
        self.assertIn("已批准", catalog[0]["reason"])

    def test_plan_digest_binds_execution_budget(self):
        repo = init_repo(self.root / "budgeted")
        registered = self.register("local/budgeted", repo)
        common = {
            "repository_id": registered["id"],
            "revision": "HEAD",
            "include_paths": ["."],
            "detector_ids": ["ohscanner.cpp.lifetime"],
            "timeout_seconds": 60,
            "memory_mb": 512,
        }
        first = self.client.post("/api/v1/audit-plans", json=common, headers=HEADERS)
        self.assertEqual(first.status_code, 200, first.text)
        plan = first.json()
        self.assertEqual(plan["execution_budget"], {"timeout_seconds": 60, "memory_mb": 512})

        second = self.client.post(
            "/api/v1/audit-plans", json={**common, "timeout_seconds": 61}, headers=HEADERS
        )
        self.assertEqual(second.status_code, 200, second.text)
        self.assertNotEqual(plan["plan_sha256"], second.json()["plan_sha256"])

        accepted = self.client.post(
            "/api/v1/scans",
            json={**common, "expected_plan_sha256": plan["plan_sha256"]},
            headers=HEADERS,
        )
        self.assertEqual(accepted.status_code, 201, accepted.text)
        changed = self.client.post(
            "/api/v1/scans",
            json={
                **common,
                "timeout_seconds": 61,
                "expected_plan_sha256": plan["plan_sha256"],
            },
            headers=HEADERS,
        )
        self.assertEqual(changed.status_code, 409)
        self.assertIn("plan", changed.json()["detail"].lower())

    def test_workflow_mode_is_frozen_separately_from_static_scan_plan(self):
        repo = init_repo(self.root / "workflow")
        registered = self.register("local/workflow", repo)
        common = {
            "repository_id": registered["id"],
            "revision": "HEAD",
            "include_paths": ["."],
            "detector_ids": ["ohscanner.cpp.lifetime"],
            "timeout_seconds": 60,
            "memory_mb": 512,
        }
        standard = self.client.post("/api/v1/audit-plans",
            json={**common, "audit_mode": "standard_review"}, headers=HEADERS)
        static = self.client.post("/api/v1/audit-plans",
            json={**common, "audit_mode": "static_only"}, headers=HEADERS)
        self.assertEqual(standard.status_code, 200, standard.text)
        self.assertEqual(static.status_code, 200, static.text)
        self.assertEqual(standard.json()["plan_sha256"], static.json()["plan_sha256"])
        self.assertNotEqual(standard.json()["workflow_sha256"], static.json()["workflow_sha256"])
        self.assertFalse(standard.json()["workflow"]["automatic_model_calls"])
        self.assertTrue(standard.json()["workflow"]["source_consent_required"])

        stale = self.client.post("/api/v1/scans",
            json={**common, "audit_mode": "static_only",
                  "expected_plan_sha256": standard.json()["plan_sha256"],
                  "expected_workflow_sha256": standard.json()["workflow_sha256"]},
            headers=HEADERS)
        self.assertEqual(stale.status_code, 409, stale.text)
        self.assertEqual(self.client.get("/api/v1/scans").json(), [])

        created = self.client.post("/api/v1/scans",
            json={**common, "audit_mode": "static_only",
                  "expected_plan_sha256": static.json()["plan_sha256"],
                  "expected_workflow_sha256": static.json()["workflow_sha256"]},
            headers=HEADERS)
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(created.json()["spec"]["audit_mode"], "static_only")
        self.assertEqual(created.json()["spec"]["workflow_sha256"], static.json()["workflow_sha256"])

    def test_discovery_rejects_unconfigured_root_index(self):
        response = self.client.get("/api/v1/repositories/discover?root_index=1")
        self.assertEqual(response.status_code, 409)
        self.assertIn("invalid", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()

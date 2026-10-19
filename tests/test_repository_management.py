import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from fastapi.testclient import TestClient

from src.workbench.api import create_app
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

    def test_catalog_hides_paths_and_disambiguates_duplicate_names(self):
        first = init_repo(self.root / "first")
        second = init_repo(self.root / "second")
        self.register("local/sample", first)
        self.register("local/sample", second)

        response = self.client.get("/api/v1/repositories/catalog")
        self.assertEqual(response.status_code, 200, response.text)
        rows = response.json()
        self.assertEqual([row["display_name"] for row in rows],
                         ["local/sample（副本 1）", "local/sample（副本 2）"])
        self.assertTrue(all(row["status"] == "available" for row in rows))
        self.assertTrue(all(row["head_commit"] for row in rows))
        self.assertNotIn(str(first), response.text)
        self.assertNotIn(str(second), response.text)
        self.assertNotIn('"path"', response.text)

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

    def test_discovery_rejects_unconfigured_root_index(self):
        response = self.client.get("/api/v1/repositories/discover?root_index=1")
        self.assertEqual(response.status_code, 409)
        self.assertIn("invalid", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()

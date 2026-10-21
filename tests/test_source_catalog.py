import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

from src.workbench import source_catalog as catalog
from src.workbench.settings import Settings


DOTTED_GITCODE_REPOSITORIES = (
    "kernel_linux_4.19",
    "kernel_linux_5.10",
    "third_party_rust_lazy-static.rs",
    "kernel_linux_6.6",
    "third_party_decimal.js",
    ".gitcode",
)


def api_row(slug):
    return {
        "path": slug,
        "namespace": {"path": "openharmony"},
        "repo_type": "code",
        "public": True,
        "private": False,
        "default_branch": "master",
        "description": "fixture",
        "language": "C++",
        "pushed_at": "2026-10-21",
        "size": 128,
    }


class SourceCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.settings = Settings(Path(self.temp.name) / "data", ())
        self.settings.initialize()
        catalog._MEMORY_CACHE.clear()

    def test_catalog_persists_and_reuses_fresh_cache_without_network(self):
        rows = [{"slug": "demo", "name": "openharmony/demo", "description": "a", "language": "C++"}]
        with patch.object(catalog, "_fetch_catalog_pages", return_value=(rows, 808)) as fetch:
            first = catalog.repository_catalog(self.settings, query="DEMO")
            second = catalog.repository_catalog(self.settings, query="demo")
        self.assertEqual(first["items"], second["items"])
        self.assertEqual(first["catalog_total_count"], 808)
        self.assertEqual(fetch.call_count, 1)
        saved = json.loads((self.settings.data_dir / "catalog-cache" / "gitcode-openharmony-public.json").read_text())
        self.assertEqual(saved["items"], rows)

    def test_offline_uses_stale_listing_but_blocks_commit_preview(self):
        row = {"slug": "demo", "name": "openharmony/demo"}
        catalog._MEMORY_CACHE[str(self.settings.data_dir.resolve())] = {
            "items": [row], "total_count": 1, "saved_epoch": 1,
            "catalog_sha256": "a" * 64,
        }
        with patch.object(catalog, "_fetch_catalog_pages", side_effect=catalog.CatalogUnavailable("timeout")):
            result = catalog.repository_catalog(self.settings)
            self.assertTrue(result["stale"])
            self.assertEqual(result["items"], [row])
            with self.assertRaisesRegex(catalog.CatalogUnavailable, "stale"):
                catalog.repository_preview(self.settings, "demo")

    def test_timeout_does_not_claim_fresh_catalog(self):
        with patch.object(catalog, "_fetch_catalog_pages", side_effect=catalog.CatalogUnavailable("timeout")):
            with self.assertRaisesRegex(catalog.CatalogUnavailable, "timeout"):
                catalog.repository_catalog(self.settings, refresh=True)

    def test_catalog_skips_redirect_and_limits_requested_host(self):
        class Redirecting:
            def open(self, request, timeout):
                self.request = request
                raise catalog.HTTPError(request.full_url, 302, "redirect", {}, None)

        redirect = Redirecting()
        with patch.object(catalog, "build_opener", return_value=redirect):
            with self.assertRaisesRegex(catalog.CatalogUnavailable, "redirected"):
                catalog._request_json("/repos/openharmony/demo/branches/main")
        self.assertTrue(redirect.request.full_url.startswith(catalog.API_ROOT + "/"))

    def test_preview_binds_default_branch_full_commit_and_catalog_digest(self):
        sha = "1" * 40
        entry = {"slug": "demo", "name": "openharmony/demo", "default_branch": "main",
                 "clone_url": "https://gitcode.com/openharmony/demo.git",
                 "catalog_source": "GitCode public listing"}
        snapshot = {"items": [entry], "catalog_sha256": "2" * 64, "stale": False}
        with patch.object(catalog, "catalog_snapshot", return_value=snapshot), patch.object(
                catalog, "_request_json", side_effect=[({"name": "main", "commit": {"id": sha}}, {}),
                                                       ({"sha": sha, "tree": [{"path": "src", "type": "tree", "sha": "4" * 40}]}, {})]):
            preview = catalog.repository_preview(self.settings, "demo")
        self.assertEqual(preview["commit"], sha)
        self.assertIsNone(preview["tree"])
        self.assertEqual(preview["catalog_sha256"], "2" * 64)
        self.assertEqual(preview["tree_preview"][0]["path"], "src")
        self.assertIn("尚未独立验证", preview["tree_note"])
        self.assertEqual(len(preview["preview_sha256"]), 64)
        self.assertIn("独立身份认证", preview["provenance"]["identity_note"])

    def test_real_dotted_names_survive_catalog_cache_and_preview_parameters(self):
        records = catalog._normalize_page([api_row(slug) for slug in DOTTED_GITCODE_REPOSITORIES])
        self.assertEqual({row["slug"] for row in records}, set(DOTTED_GITCODE_REPOSITORIES))
        for row in records:
            encoded = quote(row["slug"], safe="")
            self.assertEqual(row["web_url"], "https://gitcode.com/openharmony/" + encoded)
            self.assertEqual(row["clone_url"], "https://gitcode.com/openharmony/" + encoded + ".git")

        saved = {"items": records, "total_count": 808, "saved_epoch": time.time(),
                 "catalog_sha256": "a" * 64}
        catalog._save_cache(self.settings, saved)
        catalog._MEMORY_CACHE.clear()
        with patch.object(catalog, "_fetch_catalog_pages",
                          side_effect=AssertionError("fresh catalog cache should avoid network")):
            listing = catalog.repository_catalog(self.settings, per_page=100)
        self.assertEqual({row["slug"] for row in listing["items"]}, set(DOTTED_GITCODE_REPOSITORIES))
        self.assertFalse(listing["stale"])
        self.assertEqual(catalog._read_saved_cache(self.settings)["items"], records)

        commit = "1" * 40
        tree_sha = "2" * 40
        for slug in DOTTED_GITCODE_REPOSITORIES:
            row = next(item for item in records if item["slug"] == slug)
            snapshot = {"items": [row], "catalog_sha256": "a" * 64, "stale": False}
            with self.subTest(slug=slug), patch.object(
                    catalog, "catalog_snapshot", return_value=snapshot), patch.object(
                    catalog, "_request_json", side_effect=[
                        ({"name": "master", "commit": {"id": commit}}, {}),
                        ({"tree": [{"path": "src", "type": "tree", "sha": tree_sha}]}, {}),
                    ]) as request:
                preview = catalog.repository_preview(self.settings, slug)
            encoded = quote(slug, safe="")
            self.assertEqual(preview["slug"], slug)
            self.assertEqual(preview["clone_url"], "https://gitcode.com/openharmony/" + encoded + ".git")
            self.assertEqual(request.call_args_list[0].args[0],
                             "/repos/openharmony/" + encoded + "/branches/master")
            self.assertEqual(request.call_args_list[1].args[0],
                             "/repos/openharmony/" + encoded + "/git/trees/" + commit)

    def test_slug_rejects_only_empty_traversal_separators_and_controls(self):
        invalid = ("", ".", "..", "../repo", "repo/sub", "repo" + chr(92) + "sub",
                   "repo" + chr(10) + "name", "repo" + chr(0x85) + "name", "x" * 101)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                catalog.validate_repository_slug(value)
        self.assertEqual(catalog._normalize_page([api_row("../bad"), api_row("bad/name")]), [])

    def test_clone_url_rejects_path_escape_and_branch_traversal(self):
        with self.assertRaisesRegex(ValueError, "repository name"):
            catalog.approved_clone_url("../secret")
        with self.assertRaisesRegex(ValueError, "branch"):
            catalog.validate_branch("../main")


if __name__ == "__main__":
    unittest.main()

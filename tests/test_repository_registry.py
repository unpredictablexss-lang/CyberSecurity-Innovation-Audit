from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from src.ohscanner.repository_registry import parse_repository_registry, verify_registry


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REGISTRY = PROJECT_ROOT / "research/evidence/platform/openharmony_repository_registry_20261017.json"


def write_manifest(directory: str, xml: str) -> Path:
    path = Path(directory) / "manifest.xml"
    path.write_text(xml, encoding="utf-8")
    return path


class RepositoryRegistryTests(unittest.TestCase):
    def test_official_registry_is_complete_and_verifiable(self):
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        verify_registry(registry)
        self.assertGreaterEqual(len(registry["repositories"]), 500)
        self.assertTrue(any(item["name"] == "window_window_manager" for item in registry["repositories"]))
        self.assertTrue(all(item["mirror_urls"].keys() == {"gitcode", "gitee"} for item in registry["repositories"]))
        self.assertEqual(registry["policy"]["repository_count_is_dynamic"], True)

    def test_manifest_produces_dynamic_registry(self):
        xml = """<manifest>
          <remote name='gitcode' fetch='https://gitcode.com/openharmony'/>
          <default remote='gitcode' revision='master'/>
          <project name='a' path='a' revision='master'/>
          <project name='b' path='vendor/b' revision='release'/>
        </manifest>"""
        with tempfile.TemporaryDirectory() as directory:
            registry = parse_repository_registry(write_manifest(directory, xml))
            verify_registry(registry)
            self.assertEqual(len(registry["repositories"]), 2)
            self.assertEqual(registry["repositories"][0]["name"], "a")
            self.assertEqual(registry["repositories"][1]["name"], "b")
            self.assertEqual(registry["repositories"][1]["revision"], "release")

    def test_invalid_duplicate_manifest_is_rejected(self):
        xml = """<manifest>
          <remote name='gitcode' fetch='https://gitcode.com/openharmony'/>
          <default remote='gitcode' revision='master'/>
          <project name='a' path='a' revision='master'/>
          <project name='a' path='b' revision='master'/>
        </manifest>"""
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "duplicate repository name/path"):
                parse_repository_registry(write_manifest(directory, xml))

    def test_invalid_remote_is_rejected(self):
        xml = """<manifest>
          <remote name='gitcode' fetch='not a URL'/>
          <default remote='gitcode' revision='master'/>
          <project name='a' path='a'/>
        </manifest>"""
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "invalid manifest remote"):
                parse_repository_registry(write_manifest(directory, xml))

    def test_unsafe_project_path_is_rejected(self):
        xml = """<manifest>
          <remote name='gitcode' fetch='https://gitcode.com/openharmony'/>
          <default remote='gitcode' revision='master'/>
          <project name='a' path='../escape'/>
        </manifest>"""
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "invalid manifest project path"):
                parse_repository_registry(write_manifest(directory, xml))

    @unittest.skipUnless(os.environ.get("OHOS_MANIFEST_PATH"), "OHOS_MANIFEST_PATH is not configured")
    def test_current_official_manifest_matches_policy(self):
        registry = parse_repository_registry(Path(os.environ["OHOS_MANIFEST_PATH"]))
        verify_registry(registry)
        self.assertGreaterEqual(len(registry["repositories"]), 500)


if __name__ == "__main__":
    unittest.main()

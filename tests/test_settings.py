import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.workbench.settings import Settings


class SettingsPortabilityTests(unittest.TestCase):
    def test_json_paths_are_relative_to_config_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "portable.json"
            config.write_text(json.dumps({
                "data_dir": "./state",
                "target_roots": ["./targets", "../shared-targets"],
            }), encoding="utf-8")
            with patch.dict(os.environ, {"OHSCANNER_CONFIG": str(config)}, clear=True):
                settings = Settings.from_env()

            self.assertEqual(settings.data_dir, (root / "state").resolve())
            self.assertEqual(settings.target_roots[:2], (
                (root / "targets").resolve(),
                (root.parent / "shared-targets").resolve(),
            ))
            self.assertEqual(settings.target_roots[2], settings.data_dir / "repo-cache")

    def test_environment_paths_override_portable_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "portable.json"
            config.write_text(json.dumps({
                "data_dir": "./config-state",
                "target_roots": ["./config-targets"],
            }), encoding="utf-8")
            data = root / "env-state"
            targets = [root / "env-target-a", root / "env-target-b"]
            env = {
                "OHSCANNER_CONFIG": str(config),
                "OHSCANNER_DATA": str(data),
                "OHSCANNER_TARGET_ROOTS": os.pathsep.join(map(str, targets)),
            }
            with patch.dict(os.environ, env, clear=True):
                settings = Settings.from_env()

            self.assertEqual(settings.data_dir, data.resolve())
            self.assertEqual(settings.target_roots[:2], tuple(path.resolve() for path in targets))

    def test_empty_target_roots_remains_an_empty_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "portable.json"
            config.write_text(json.dumps({"data_dir": "./state", "target_roots": []}), encoding="utf-8")
            with patch.dict(os.environ, {"OHSCANNER_CONFIG": str(config)}, clear=True):
                settings = Settings.from_env()

            self.assertEqual(settings.target_roots, (settings.data_dir / "repo-cache",))

    def test_invalid_data_path_is_reported_as_configuration_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "portable.json"
            config.write_text(json.dumps({"data_dir": 7, "target_roots": []}), encoding="utf-8")
            with patch.dict(os.environ, {"OHSCANNER_CONFIG": str(config)}, clear=True):
                with self.assertRaisesRegex(ValueError, "data_dir"):
                    Settings.from_env()

    def test_repository_cache_configuration_is_portable_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "portable.json"
            config.write_text(json.dumps({
                "data_dir": "./state",
                "target_roots": [],
                "repository_cache": {"roots": ["./cache-a", "./cache-b"],
                                     "max_bytes": 4096, "minimum_free_bytes": 1024},
            }), encoding="utf-8")
            with patch.dict(os.environ, {"OHSCANNER_CONFIG": str(config)}, clear=True):
                settings = Settings.from_env()
            self.assertEqual(settings.repository_cache_roots,
                             ((root / "cache-a").resolve(), (root / "cache-b").resolve()))
            self.assertEqual(settings.repository_cache_max_bytes, 4096)
            self.assertEqual(settings.repository_cache_min_free_bytes, 1024)
            settings.initialize()
            self.assertTrue((root / "cache-a").is_dir())
            self.assertTrue((root / "cache-b").is_dir())

    def test_repository_cache_config_rejects_symlink_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "real-cache"
            target.mkdir()
            link = root / "cache-link"
            link.symlink_to(target, target_is_directory=True)
            config = root / "portable.json"
            config.write_text(json.dumps({
                "data_dir": "./state", "target_roots": [],
                "repository_cache": {"roots": [str(link)]},
            }), encoding="utf-8")
            with patch.dict(os.environ, {"OHSCANNER_CONFIG": str(config)}, clear=True):
                with self.assertRaisesRegex(ValueError, "symbolic links"):
                    Settings.from_env()

    def test_negative_repository_cache_limit_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "portable.json"
            config.write_text(json.dumps({"data_dir": "./state", "target_roots": [],
                                          "repository_cache": {"max_bytes": -1}}), encoding="utf-8")
            with patch.dict(os.environ, {"OHSCANNER_CONFIG": str(config)}, clear=True):
                with self.assertRaisesRegex(ValueError, "non-negative"):
                    Settings.from_env()


if __name__ == "__main__":
    unittest.main()

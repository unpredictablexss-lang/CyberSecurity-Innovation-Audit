import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.workbench import download_locations
from src.workbench.settings import Settings


class DownloadLocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.cache = self.data / "repo-cache"
        self.settings = Settings(self.data, (), repository_cache_roots=(self.cache,))
        self.settings.initialize()

    def test_empty_path_uses_default_cache_without_creating_another_directory(self):
        result = download_locations.normalize_download_dir(self.settings, "")
        self.assertEqual(Path(result), self.cache)
        self.assertTrue(self.cache.is_dir())
        self.assertFalse((self.data / download_locations.REGISTRY_FILENAME).exists())

    def test_custom_directory_preview_is_canonical_and_read_only(self):
        selected = self.root / "chosen" / "OpenHarmony"
        result = download_locations.normalize_download_dir(self.settings, str(selected))
        self.assertEqual(Path(result), selected)
        self.assertFalse(selected.exists())
        self.assertFalse((self.data / download_locations.REGISTRY_FILENAME).exists())

    def test_wsl_accepts_windows_drive_paths_and_maps_them_to_mnt(self):
        original_is_dir = Path.is_dir
        def is_dir(path):
            if path == Path("/mnt/g"):
                return True  # Simulate a mounted drive on CI hosts without G:.
            return original_is_dir(path)

        with patch.object(download_locations, "_is_wsl", return_value=True),              patch.object(Path, "is_dir", autospec=True, side_effect=is_dir):
            result = download_locations.normalize_download_dir(self.settings, r"G:\OpenHarmony")
        self.assertEqual(Path(result), Path("/mnt/g/OpenHarmony"))

    def test_linux_rejects_windows_drive_path_outside_wsl(self):
        with patch.object(download_locations, "_is_wsl", return_value=False):
            with self.assertRaisesRegex(ValueError, "仅能在 WSL"):
                download_locations.normalize_download_dir(self.settings, r"G:\OpenHarmony")

    def test_rejects_relative_traversal_and_workbench_overlap(self):
        with self.assertRaisesRegex(ValueError, "绝对路径"):
            download_locations.normalize_download_dir(self.settings, "OpenHarmony")
        with self.assertRaisesRegex(ValueError, r"\.\."):
            download_locations.normalize_download_dir(self.settings, "/tmp/../data")
        with self.assertRaisesRegex(ValueError, "工作台数据库"):
            download_locations.normalize_download_dir(self.settings, str(self.data))

    def test_confirmed_custom_directory_is_persistently_allowed_for_repository_checks(self):
        selected = self.root / "chosen"
        result = download_locations.ensure_download_dir(self.settings, str(selected))
        self.assertEqual(Path(result), selected)
        self.assertIn(selected, self.settings.target_roots)
        rows = download_locations.load_download_locations(self.data)
        self.assertEqual(len(rows), 1)
        self.assertTrue(download_locations.download_location_is_current(rows[0]))

    def test_rejects_symlink_component(self):
        actual = self.root / "actual"
        actual.mkdir()
        link = self.root / "link"
        link.symlink_to(actual, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "符号链接"):
            download_locations.normalize_download_dir(self.settings, str(link / "repos"))


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from research.data_sensitive import d10_manifest_bound_replay as replay


class ManifestReplayNetworkPolicyTests(unittest.TestCase):
    def test_missing_source_cache_fails_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(replay, "fetch") as fetch:
                with self.assertRaises(FileNotFoundError):
                    replay.fetch_cached("openharmony/example", "a" * 40, "src/a.c", Path(directory))
                fetch.assert_not_called()

    def test_cached_source_is_read_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "openharmony__example" / ("a" * 40) / "src/a.c"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"fixed source")
            with patch.object(replay, "fetch") as fetch:
                self.assertEqual(replay.fetch_cached("openharmony/example", "a" * 40, "src/a.c", Path(directory)), b"fixed source")
                fetch.assert_not_called()

    def test_missing_api_cache_fails_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(replay, "urlopen") as urlopen:
                with self.assertRaises(FileNotFoundError):
                    replay.github_json("https://api.github.com/example", Path(directory))
                urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()

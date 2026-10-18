import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from research.data_sensitive.d11_d4_historical_replay import verify_source_rows


class HistoricalReplaySourceIntegrityTests(unittest.TestCase):
    def build_cache(self, root, corrupt_source=False):
        commit = "a" * 40
        tree = "b" * 40
        repository = "openharmony/test"
        rows = []
        entries = []
        contents = {}
        for index in range(11):
            path = f"src/file_{index}.c"
            data = f"static int value_{index}(void) {{ return {index}; }}\n".encode()
            blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            rows.append({"commit": commit, "tree": tree, "file": path, "blob": blob,
                         "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
            entries.append({"path": path, "type": "blob", "sha": blob, "size": len(data)})
            contents[path] = data
        cache = Path(root)
        (cache / ".api").mkdir(parents=True)
        (cache / ".api" / f"commit-{commit}.json").write_text(
            json.dumps({"sha": commit, "tree": {"sha": tree}}), encoding="utf-8")
        (cache / ".api" / f"tree-{tree}.json").write_text(
            json.dumps({"sha": tree, "tree": entries}), encoding="utf-8")
        for path, data in contents.items():
            target = cache / commit / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        if corrupt_source:
            target = cache / commit / "src/file_0.c"
            target.write_bytes(target.read_bytes() + b"/* changed */")
        manifest = {"repository": repository, "files": rows}
        return manifest, commit, cache

    def test_cached_commit_tree_and_sources_verify_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, commit, cache = self.build_cache(directory)
            with patch("research.data_sensitive.d11_d4_historical_replay.urlopen") as urlopen:
                sources, evidence, tree, entry_count = verify_source_rows(
                    manifest, commit, cache, allow_network=False)
            urlopen.assert_not_called()
            self.assertEqual(len(sources), 11)
            self.assertEqual(len(evidence), 11)
            self.assertEqual(tree, "b" * 40)
            self.assertEqual(entry_count, 11)

    def test_missing_api_cache_fails_closed_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, commit, cache = self.build_cache(directory)
            (cache / ".api" / f"commit-{commit}.json").unlink()
            with patch("research.data_sensitive.d11_d4_historical_replay.urlopen") as urlopen:
                with self.assertRaises(FileNotFoundError):
                    verify_source_rows(manifest, commit, cache, allow_network=False)
            urlopen.assert_not_called()

    def test_changed_cached_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, commit, cache = self.build_cache(directory, corrupt_source=True)
            with self.assertRaisesRegex(ValueError, "source byte verification failed"):
                verify_source_rows(manifest, commit, cache, allow_network=False)


if __name__ == "__main__":
    unittest.main()

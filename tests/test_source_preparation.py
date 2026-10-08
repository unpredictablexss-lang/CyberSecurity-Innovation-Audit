import hashlib
import io
import json
import unittest
from dataclasses import asdict
from unittest.mock import patch

import test_ast_coverage_mapping as fixtures
from scripts.prepare_historical_sources import prepare


class SourcePreparationTests(unittest.TestCase):
    setUp = fixtures.SnapshotMappingTests.setUp
    git = fixtures.SnapshotMappingTests.git
    commit = fixtures.SnapshotMappingTests.commit

    def remove_source_blob(self):
        path = self.root / "seed.json"
        path.write_text(json.dumps(asdict(self.seed)), encoding="utf-8")
        content = self.code.encode()
        expected = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        object_path = self.repo / ".git" / "objects" / expected[:2] / expected[2:]
        object_path.unlink()
        return path, expected, object_path

    def test_raw_recovery_verifies_blob_and_preserves_target_head(self):
        path, expected, _ = self.remove_source_blob()
        with patch("scripts.prepare_historical_sources.urlopen", return_value=io.BytesIO(self.code.encode())):
            result = prepare(path, self.root, raw_only=True)
        self.assertEqual(result["status"], "prepared")
        self.assertEqual(result["fetches"][0]["verified_blob"], expected)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.fixed)
        self.assertEqual(self.git("show", f"{self.vulnerable}:src/f.cpp"), self.code.strip())

    def test_raw_recovery_rejects_source_that_differs_from_git_tree(self):
        path, _, object_path = self.remove_source_blob()
        with patch("scripts.prepare_historical_sources.urlopen", return_value=io.BytesIO(b"different source")):
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                prepare(path, self.root, raw_only=True)
        self.assertFalse(object_path.exists())

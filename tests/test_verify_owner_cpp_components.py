import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_owner_cpp_components import (
    ValidationError,
    plan_digest,
    shard_digest,
    validate_manifest_data,
)


class SameScopeManifestTests(unittest.TestCase):
    def setUp(self):
        self.tree = {
            "a.cpp": ("a" * 40, 10),
            "b.h": ("b" * 40, 20),
        }
        shard = {
            "shard_id": 0,
            "files": 2,
            "bytes": 30,
            "shard_sha256": shard_digest([("a.cpp", "a" * 40), ("b.h", "b" * 40)]),
            "paths": ["a.cpp", "b.h"],
        }
        self.manifest = {
            "component": "update_updateservice",
            "repository": "openharmony/update_updateservice",
            "source_repo_path": "/tmp/source",
            "commit": "1" * 40,
            "git_tree": "2" * 40,
            "counts": {"selected_files": 2, "selected_bytes": 30, "shards": 1},
            "plan_sha256": plan_digest("1" * 40, [shard["shard_sha256"]]),
            "shards": [shard],
        }

    def test_valid_manifest(self):
        result = validate_manifest_data(self.manifest, self.tree, {"update_updateservice": (2, 2)})
        self.assertTrue(result["scope_equivalent"])
        self.assertEqual(result["selected_files"], 2)

    def test_duplicate_paths_across_shards_rejected(self):
        self.manifest["counts"] = {"selected_files": 3, "selected_bytes": 40, "shards": 2}
        self.manifest["shards"].append({
            "shard_id": 1,
            "files": 1,
            "bytes": 10,
            "shard_sha256": shard_digest([("a.cpp", "a" * 40)]),
            "paths": ["a.cpp"],
        })
        with self.assertRaises(ValidationError):
            validate_manifest_data(self.manifest, self.tree)

    def test_unsorted_paths_rejected(self):
        self.manifest["shards"][0]["paths"] = ["b.h", "a.cpp"]
        with self.assertRaises(ValidationError):
            validate_manifest_data(self.manifest, self.tree)

    def test_plan_digest_mismatch_rejected(self):
        self.manifest["plan_sha256"] = "0" * 64
        with self.assertRaises(ValidationError):
            validate_manifest_data(self.manifest, self.tree)

    def test_expected_component_count_mismatch_rejected(self):
        self.manifest["counts"]["selected_files"] = 3
        with self.assertRaises(ValidationError):
            validate_manifest_data(self.manifest, self.tree)

    def test_source_size_mismatch_rejected(self):
        self.manifest["counts"]["selected_bytes"] = 31
        with self.assertRaises(ValidationError):
            validate_manifest_data(self.manifest, self.tree)

    def test_tree_blob_identity_is_in_digest(self):
        changed = dict(self.tree)
        changed["a.cpp"] = ("c" * 40, 10)
        self.manifest["shards"][0]["shard_sha256"] = shard_digest(
            [("a.cpp", "c" * 40), ("b.h", "b" * 40)]
        )
        self.manifest["plan_sha256"] = plan_digest(
            self.manifest["commit"], [self.manifest["shards"][0]["shard_sha256"]]
        )
        with self.assertRaises(ValidationError):
            validate_manifest_data(self.manifest, changed)


if __name__ == "__main__":
    unittest.main()

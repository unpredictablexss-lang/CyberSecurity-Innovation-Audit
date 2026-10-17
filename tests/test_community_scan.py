from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from src.ohscanner.community import (
    git_blob_oid,
    load_source_units,
    plan_repository_shards,
    scan_shard,
    select_first_parent_increment,
)


def row(path: str, data: bytes) -> dict:
    return {
        "path": path,
        "blob_oid": git_blob_oid(data),
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "lines": len(data.splitlines()),
        "language": "cpp" if path.endswith((".c", ".h", ".cpp")) else "js",
    }


def run(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class CommunityPlanningTests(unittest.TestCase):
    def test_shards_respect_file_and_byte_limits(self):
        files = [
            row("a.cpp", b"int a;\n"),
            row("b.cpp", b"int b;\n"),
            row("c.cpp", b"int c;\n"),
            row("d.js", b"let d = 1;\n"),
        ]
        plan = plan_repository_shards(
            repository="openharmony/demo",
            commit="a" * 40,
            tree="b" * 40,
            files=files,
            max_files=2,
            max_bytes=1000,
        )
        self.assertEqual(plan["counts"]["shards"], 2)
        self.assertEqual([shard["files"] for shard in plan["shards"]], [2, 2])
        self.assertEqual(len({shard["shard_sha256"] for shard in plan["shards"]}), 2)

    def test_source_hash_drift_is_rejected(self):
        data = b"int main(){return 0;}\n"
        item = row("main.cpp", data)
        item["source_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.cpp").write_bytes(data)
            with self.assertRaisesRegex(ValueError, "source SHA-256 drift"):
                load_source_units(root, "openharmony/demo", "a" * 40, [item])

    def test_offline_shard_scan_is_deterministic(self):
        data = b"void f(int *p) { *p = 1; }\n"
        item = row("f.cpp", data)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "f.cpp").write_bytes(data)
            first = scan_shard(
                source_root=root,
                repository="openharmony/demo",
                commit="a" * 40,
                rows=[item],
                detector_ids=("ohscanner.cpp.null_dereference",),
            )
            second = scan_shard(
                source_root=root,
                repository="openharmony/demo",
                commit="a" * 40,
                rows=[item],
                detector_ids=("ohscanner.cpp.null_dereference",),
            )
        self.assertEqual(first["identity"], second["identity"])
        self.assertEqual(first["coverage"], second["coverage"])
        self.assertEqual(
            [item["diagnostic_count"] for item in first["detector_reports"]],
            [item["diagnostic_count"] for item in second["detector_reports"]],
        )


class CommunityIncrementTests(unittest.TestCase):
    def test_first_parent_increment_records_patch_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            run(repo, "init", "-q")
            run(repo, "config", "user.email", "test@example.invalid")
            run(repo, "config", "user.name", "Test")
            (repo / "a.cpp").write_text("int a = 0;\n", encoding="utf-8")
            run(repo, "add", "a.cpp")
            run(repo, "commit", "-q", "-m", "first")
            (repo / "a.cpp").write_text("int a = 1;\n", encoding="utf-8")
            run(repo, "add", "a.cpp")
            run(repo, "commit", "-q", "-m", "second")
            endpoint = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            result = select_first_parent_increment(
                repo, endpoint, since="2000-01-01T00:00:00Z", until="2100-01-01T00:00:00Z"
            )
        self.assertGreaterEqual(result["counts"]["commits"], 2)
        self.assertTrue(all(row["stable_patch_id"] for row in result["commits"] if row["parents"]))
        self.assertTrue(all(row["first_parent_diff"] for row in result["commits"]))


if __name__ == "__main__":
    unittest.main()

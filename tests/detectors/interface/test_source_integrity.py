import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from research.experiments.interface.verify_sources import verify


class SourceIntegrityTests(unittest.TestCase):
    def test_invalid_manifest_metadata(self):
        mutations = [
            {"files": []}, {"commit": "short"}, {"commit": None},
            {"repository": ""}, {"files": [None]},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = self.make_manifest(root)
            baseline = json.loads(path.read_text())
            for change in mutations:
                with self.subTest(change=change):
                    path.write_text(json.dumps({**baseline, **change}))
                    with self.assertRaises(ValueError):
                        verify(path, root)

    def test_duplicate_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = self.make_manifest(root)
            manifest = json.loads(path.read_text())
            manifest["files"].append(dict(manifest["files"][0]))
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                verify(path, root)

    def test_invalid_hash_and_byte_fields(self):
        mutations = [{"git_blob_sha1": ""}, {"sha256": None}, {"bytes": True}, {"bytes": -1}]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = self.make_manifest(root)
            baseline = path.read_text()
            for change in mutations:
                with self.subTest(change=change):
                    manifest = json.loads(baseline)
                    manifest["files"][0].update(change)
                    path.write_text(json.dumps(manifest))
                    with self.assertRaises(ValueError):
                        verify(path, root)

    def make_manifest(self, root):
        data = b"synthetic source\n"
        (root / "demo.cpp").write_bytes(data)
        manifest = {"repository": "synthetic/demo", "commit": "a" * 40, "files": [
            {"path": "demo.cpp", "bytes": len(data),
             "git_blob_sha1": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(),
             "sha256": hashlib.sha256(data).hexdigest()}]}
        path = root / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def test_valid_blob(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertTrue(verify(self.make_manifest(root), root)["verified_files"][0]["git_blob_verified"])

    def test_tampered_source_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = self.make_manifest(root)
            (root / "demo.cpp").write_text("changed", encoding="utf-8")
            with self.assertRaises(ValueError):
                verify(manifest, root)

    def test_missing_source_is_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = self.make_manifest(root)
            (root / "demo.cpp").unlink()
            with self.assertRaises(FileNotFoundError):
                verify(manifest, root)

    def test_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = self.make_manifest(root)
            manifest = json.loads(path.read_text())
            manifest["files"][0]["path"] = "../demo.cpp"
            path.write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                verify(path, root)

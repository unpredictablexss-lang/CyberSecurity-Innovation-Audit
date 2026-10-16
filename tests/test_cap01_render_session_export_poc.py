from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "research/evidence/interface/cap01_render_session_export_20261016"
MANIFEST = PACKAGE / "source-manifest.json"
EVIDENCE = PACKAGE / "evidence.json"
RUNNER = PACKAGE / "poc/run_poc.py"
PATCH = PACKAGE / "patch/minimal.patch"
TARGET = Path(r"E:\网安\audit-sources-20261014\home\audit\openharmony-audit\perf-corpus\window_window_manager")
if not TARGET.exists():
    TARGET = Path("/mnt/e/网安/audit-sources-20261014/home/audit/openharmony-audit/perf-corpus/window_window_manager")


class Cap01RenderSessionEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    def test_fail_closed_status_and_cve(self) -> None:
        self.assertEqual(self.evidence["candidate_status"], "candidate/unknown")
        self.assertEqual(self.evidence["validated_vulnerability"], 0)
        self.assertFalse(self.evidence["promotion"]["confirmed"])
        self.assertFalse(self.evidence["promotion"]["reportable"])
        self.assertEqual(self.evidence["cve"]["status"], "not_assigned")
        self.assertEqual(self.evidence["cia"]["confidentiality"], "unknown")
        self.assertEqual(self.evidence["cia"]["integrity"], "unknown")
        self.assertEqual(self.evidence["cia"]["availability"], "unknown")

    def test_pinned_source_objects_match_manifest(self) -> None:
        if not TARGET.exists():
            self.skipTest("pinned window_window_manager Git object store is unavailable")
        identity = self.manifest["repository_identity"]
        head = subprocess.check_output(["git", "-C", str(TARGET), "rev-parse", "HEAD"], text=True).strip()
        tree = subprocess.check_output(
            ["git", "-C", str(TARGET), "rev-parse", "HEAD^{tree}"], text=True
        ).strip()
        self.assertEqual(head, identity["commit"])
        self.assertEqual(tree, identity["tree"])
        for item in self.manifest["sources"]:
            blob = subprocess.check_output(
                ["git", "-C", str(TARGET), "rev-parse", f"{head}:{item['path']}"], text=True
            ).strip()
            data = subprocess.check_output(["git", "-C", str(TARGET), "cat-file", "blob", blob])
            self.assertEqual(blob, item["blob"], item["path"])
            self.assertEqual(len(data), item["bytes"], item["path"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"], item["path"])

    def test_relations_match_exact_pinned_lines(self) -> None:
        if not TARGET.exists():
            self.skipTest("pinned window_window_manager Git object store is unavailable")
        source_lines = {
            item["path"]: subprocess.check_output(
                ["git", "-C", str(TARGET), "cat-file", "blob", item["blob"]], text=True
            ).splitlines()
            for item in self.manifest["sources"]
        }
        for relation in self.manifest["relations"]:
            line = source_lines[relation["path"]][relation["line"] - 1]
            self.assertIn(relation["contains"], line, relation)

    def test_minimal_patch_applies_to_exact_primary_blob(self) -> None:
        if not TARGET.exists():
            self.skipTest("pinned window_window_manager Git object store is unavailable")
        primary = self.manifest["source_observation"]
        data = subprocess.check_output(
            ["git", "-C", str(TARGET), "cat-file", "blob", primary["blob"]]
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / primary["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            subprocess.run(["git", "apply", "--check", str(PATCH)], cwd=root, check=True)
            subprocess.run(["git", "apply", str(PATCH)], cwd=root, check=True)
            patched = target.read_bytes()
        self.assertIn(b"if (!SessionPermission::IsSystemCalling())", patched)
        self.assertEqual(
            hashlib.sha256(patched).hexdigest(),
            "2b379e4427071b3536583c9f0e16ccd90d7389953a534be87dae087ec74b9295",
        )

    def test_runner_refuses_host_build_and_run(self) -> None:
        if not TARGET.exists():
            self.skipTest("pinned window_window_manager Git object store is unavailable")
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "result.json"
            env = dict(__import__("os").environ)
            env.pop("OHSCANNER_VALIDATION_CONTAINER", None)
            done = subprocess.run(
                [sys.executable, str(RUNNER), "--target", str(TARGET), "--out", str(output)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("container_required", done.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

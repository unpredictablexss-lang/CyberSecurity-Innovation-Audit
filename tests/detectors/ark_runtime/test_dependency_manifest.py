import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
WORKSPACE_ROOT = REPO_ROOT.parent
MANIFEST_PATH = REPO_ROOT / "research/experiments/ark_runtime/c4_20261018/exact_snapshot_manifest.v1.json"
MODULE_PATH = REPO_ROOT / "research/experiments/ark_runtime/c4_20261018/dependency_manifest.py"
SPEC = importlib.util.spec_from_file_location("dependency_manifest", MODULE_PATH)
dependency_manifest = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(dependency_manifest)


class ExactSnapshotDependencyManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def _copy_inputs(self, destination: Path) -> None:
        for entry in self.manifest["inputs"]:
            relative = Path(*entry["workspace_path"].split("/"))
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((WORKSPACE_ROOT / relative).read_bytes())

    def test_recomputation_is_stable_and_incomplete_profile_blocks(self):
        first = dependency_manifest.verify_manifest(self.manifest, WORKSPACE_ROOT)
        second = dependency_manifest.verify_manifest(self.manifest, WORKSPACE_ROOT)
        self.assertEqual(first["observed_summary_sha256"], second["observed_summary_sha256"])
        self.assertEqual(first["status"], "blocked")
        self.assertIn("unresolved_dependency:ACTUAL_INCLUDE_CLOSURE", first["errors"])

    def test_every_declared_file_byte_is_in_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._copy_inputs(root)
            baseline = dependency_manifest.verify_manifest(self.manifest, root)
            for entry in self.manifest["inputs"]:
                with self.subTest(input_id=entry["id"]):
                    relative = Path(*entry["workspace_path"].split("/"))
                    target = root / relative
                    original = target.read_bytes()
                    target.write_bytes(original + b"\x00")
                    changed = dependency_manifest.verify_manifest(self.manifest, root)
                    self.assertNotEqual(baseline["observed_summary_sha256"], changed["observed_summary_sha256"])
                    self.assertIn(f"sha256_mismatch:{entry['id']}", changed["errors"])
                    target.write_bytes(original)

    def test_profile_command_macro_tool_and_profile_changes_change_digest(self):
        original = dependency_manifest.calculate_summary(self.manifest)
        mutations = (
            ("command_argv", lambda m: m["profile"]["command_argv"].append("-DTEST=1")),
            ("macro", lambda m: m["profile"]["macros"]["definitions"].append("TEST=1")),
            ("tool_version", lambda m: m["profile"]["tools"].__setitem__("tree-sitter-cpp", "changed")),
            ("profile", lambda m: m["profile"].__setitem__("replay_profile", "changed-profile")),
            ("target_platform", lambda m: m["profile"].__setitem__("target_platform", "changed-platform")),
            ("include_search_path", lambda m: m["profile"]["include_search_paths"]["ordered_paths"].append("/new/include")),
        )
        for label, mutate in mutations:
            with self.subTest(field=label):
                changed = copy.deepcopy(self.manifest)
                mutate(changed)
                self.assertNotEqual(original, dependency_manifest.calculate_summary(changed))

    def test_missing_dependency_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            result = dependency_manifest.verify_manifest(self.manifest, Path(temp))
        self.assertEqual(result["status"], "blocked")
        self.assertIn("missing_dependency:src-target", result["errors"])
        self.assertNotEqual(result["expected_summary_sha256"], result["observed_summary_sha256"])


if __name__ == "__main__":
    unittest.main()

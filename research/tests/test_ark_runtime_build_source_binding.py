from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.ohscanner.indexing import prepare_git_context


class BuildSourceBindingTests(unittest.TestCase):
    def test_gn_blob_is_bound_from_git_tree_without_fake_cpp_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)

            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()

            subprocess.check_call(["git", "init", "-q", str(repo)])
            git("config", "user.name", "Build Pin Test")
            git("config", "user.email", "build-pin@example.invalid")
            (repo / "target.cpp").write_text("int target() { return 0; }\n", encoding="utf-8")
            build = repo / "ecmascript/compiler/BUILD.gn"
            build.parent.mkdir(parents=True)
            build.write_text("sources += [ 'target.cpp' ]\n", encoding="utf-8")
            git("add", ".")
            git("commit", "-qm", "pin build graph")
            commit = git("rev-parse", "HEAD")
            expected = git("rev-parse", commit + ":ecmascript/compiler/BUILD.gn")

            context, _tree, inventory, _coverage, _sources = prepare_git_context(
                repo, "test/build-pin", commit
            )
            self.assertEqual(
                context.shared_facts["build_config_blob_oid"]["ecmascript/compiler/BUILD.gn"], expected
            )
            self.assertEqual(inventory["build_config_blob_oids"]["ecmascript/compiler/BUILD.gn"], expected)
            self.assertNotIn("ecmascript/compiler/BUILD.gn", {unit.path for unit in context.units})


if __name__ == "__main__":
    unittest.main()

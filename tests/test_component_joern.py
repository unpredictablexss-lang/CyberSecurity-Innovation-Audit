import tempfile
import unittest
from pathlib import Path

from scripts.run_component_joern import (
    analysis_interpretation,
    component_joern_coverage_issues,
    cpp_scope,
    relative_findings,
)


class ComponentJoernTests(unittest.TestCase):
    def setUp(self):
        self.record = dict(path="base/src/a.cpp", sha256="a" * 64, blob="b" * 40,
                           language_scope="cpp")
        self.manifest = dict(files=[
            self.record,
            dict(path="base/test/unit.cpp", sha256="c" * 64, blob="d" * 40,
                 language_scope="cpp"),
            dict(path="README.md", sha256="e" * 64, blob="f" * 40,
                 language_scope="other"),
        ])

    def test_cpp_scope_is_exact_and_hash_bound(self):
        scope = cpp_scope(self.manifest)
        self.assertEqual([item["path"] for item in scope],
                         ["base/src/a.cpp", "base/test/unit.cpp"])
        self.assertEqual(scope[0]["sha256"], "a" * 64)
        self.assertNotIn("README.md", [item["path"] for item in scope])

    def test_parse_problem_or_missing_coverage_is_unknown(self):
        good = "| 1 | base/src/a.cpp | 20 | yes | yes | 5 ms |"
        self.assertEqual(component_joern_coverage_issues(good, ["base/src/a.cpp"]), [])
        absolute = "| 1 | /root/source/base/src/a.cpp | 20 | yes | yes | 5 ms |"
        self.assertEqual(component_joern_coverage_issues(absolute, ["base/src/a.cpp"]), [])
        incomplete = "| 1 | base/src/a.cpp | 20 | yes | no | 5 ms |"
        self.assertIn("Incomplete parsed/CPG coverage row: base/src/a.cpp",
                      component_joern_coverage_issues(incomplete, ["base/src/a.cpp"]))
        self.assertIn("Joern parser reported problems",
                      component_joern_coverage_issues(good + "\nFailed to parse method",
                                                      ["base/src/a.cpp"]))

    def test_native_absolute_paths_are_normalized_without_losing_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "base/src/a.cpp"
            source.parent.mkdir(parents=True)
            source.write_text("int a;\n")
            payload = {"joern_version": "4.0", "findings": [
                {"rule_id": "r", "file": str(source), "line": 1}
            ]}
            result = relative_findings(payload, root)
        self.assertEqual(result["findings"][0]["file"], "base/src/a.cpp")
        self.assertEqual(result["findings"][0]["native_file"], str(source))

    def test_coverage_failure_always_interprets_unknown(self):
        self.assertEqual(analysis_interpretation(True, []), "candidate_query_completed")
        self.assertEqual(analysis_interpretation(True, ["partial"]), "unknown")
        self.assertEqual(analysis_interpretation(False, []), "unknown")

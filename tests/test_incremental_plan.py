import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from src.ohscanner.incremental import plan_fixed_commit_diff


class IncrementalPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Test"], check=True)
        (self.repo / "src").mkdir()
        (self.repo / "src" / "main.cpp").write_text('#include "api.h"\nint main(){return call();}\n')
        (self.repo / "src" / "api.h").write_text("int call();\n")
        (self.repo / "src" / "common.cpp").write_text("int shared_value = 1;\n")
        self.base = self.commit("base")

    def tearDown(self):
        self.temp.cleanup()

    def commit(self, message):
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", message], check=True)
        return subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()

    def test_tracks_add_modify_delete_and_rename_and_falls_back(self):
        (self.repo / "src" / "common.cpp").write_text("int shared_value = 2;\n")
        (self.repo / "src" / "main.cpp").rename(self.repo / "src" / "renamed_main.cpp")
        (self.repo / "src" / "extra.cpp").write_text("int extra;\n")
        (self.repo / "src" / "api.h").unlink()
        head = self.commit("changes")
        plan = plan_fixed_commit_diff(self.repo, self.base, head)
        statuses = {row["status"][0] for row in plan["changed_paths"]}
        self.assertTrue({"A", "M", "D", "R"}.issubset(statuses))
        self.assertTrue(plan["fallback"])
        self.assertEqual(plan["reused_files"], 0)
        self.assertEqual(plan["execution"], "full_scan_required")

    def test_build_or_macro_config_change_is_explicit(self):
        (self.repo / "src" / "BUILD.gn").write_text('defines = ["FEATURE_X"]\n')
        head = self.commit("build config")
        plan = plan_fixed_commit_diff(self.repo, self.base, head)
        self.assertEqual(plan["fallback_reason"], "build_or_analysis_configuration_changed")
        self.assertEqual(plan["config_changed_paths"], ["src/BUILD.gn"])

    def test_header_edit_expands_to_its_translation_unit(self):
        (self.repo / "src" / "api.h").write_text("int call();\n#define FEATURE 2\n")
        head = self.commit("header macro change")
        plan = plan_fixed_commit_diff(self.repo, self.base, head)
        self.assertIn("src/main.cpp", plan["impact_paths"])
        self.assertEqual(plan["include_index"]["status"], "tracked_quoted_includes_indexed")
        self.assertGreater(plan["include_index"]["head_dependency_edges"], 0)
        self.assertTrue(plan["fallback"])

    def test_changed_function_expands_to_syntax_callers_on_both_endpoints(self):
        (self.repo / "src" / "impl.cpp").write_text("int call() { return 1; }\n")
        self.base = self.commit("add implementation")
        (self.repo / "src" / "impl.cpp").write_text("int call() { return 2; }\n")
        head = self.commit("modify implementation")
        plan = plan_fixed_commit_diff(self.repo, self.base, head)
        self.assertIn("src/main.cpp", plan["impact_paths"])
        self.assertEqual(plan["call_symbol_index"]["status"], "conservative_syntax_candidates")
        self.assertGreater(plan["call_symbol_index"]["candidate_edges"], 0)
        self.assertTrue(plan["fallback"])
        self.assertEqual(plan["execution"], "full_scan_required")

    def test_ambiguous_callee_keeps_expanded_scope_but_marks_dependency_incomplete(self):
        (self.repo / "src" / "one.cpp").write_text("int target() { return 1; }\n")
        (self.repo / "src" / "two.cpp").write_text("int target() { return 2; }\n")
        (self.repo / "src" / "target_caller.cpp").write_text("int invoke() { return target(); }\n")
        self.base = self.commit("add ambiguous definitions")
        (self.repo / "src" / "one.cpp").write_text("int target() { return 3; }\n")
        head = self.commit("change one overload candidate")
        plan = plan_fixed_commit_diff(self.repo, self.base, head)
        self.assertIn("src/target_caller.cpp", plan["impact_paths"])
        self.assertIn("target", plan["call_symbol_index"]["ambiguous_unqualified_symbols"])
        self.assertEqual(plan["call_symbol_index"]["status"], "incomplete")
        self.assertTrue(plan["fallback"])

    def test_unindexed_cross_language_scope_marks_call_graph_incomplete(self):
        (self.repo / "src" / "impl.cpp").write_text("int call() { return 1; }\n")
        (self.repo / "src" / "bridge.ets").write_text("function bridge() { call(); }\n")
        self.base = self.commit("add C++ and ArkTS sources")
        (self.repo / "src" / "impl.cpp").write_text("int call() { return 2; }\n")
        head = self.commit("change C++ implementation")
        plan = plan_fixed_commit_diff(self.repo, self.base, head)
        self.assertEqual(plan["call_symbol_index"]["status"], "incomplete")
        self.assertEqual(plan["call_symbol_index"]["unindexed_languages"], ["arkts"])
        self.assertTrue(plan["fallback"])

    def test_base_call_index_reuses_versioned_ast_cache(self):
        from src.ohscanner.ast_cache import AstSummaryCache
        (self.repo / "src" / "impl.cpp").write_text("int call() { return 1; }\n")
        self.base = self.commit("add implementation")
        (self.repo / "src" / "impl.cpp").write_text("int call() { return 2; }\n")
        head = self.commit("modify implementation")
        cache = AstSummaryCache(self.repo / "ast-cache")
        cold = plan_fixed_commit_diff(self.repo, self.base, head, ast_cache=cache)
        hot = plan_fixed_commit_diff(self.repo, self.base, head, ast_cache=cache)
        self.assertTrue(cold["fallback"] and hot["fallback"])
        self.assertGreater(hot["call_symbol_index"]["base_ast_indexing"]
                           ["cache_counter_delta"]["hits"], 0)
        self.assertEqual(hot["call_symbol_index"]["base_ast_indexing"]["parse_files"], 0)

    def test_unresolved_project_include_is_reported_as_incomplete(self):
        (self.repo / "src" / "main.cpp").write_text('#include "missing_local.h"\nint main(){return 0;}\n')
        head = self.commit("unresolved dependency")
        plan = plan_fixed_commit_diff(self.repo, self.base, head)
        self.assertEqual(plan["include_index"]["status"], "incomplete")
        self.assertGreater(plan["include_index"]["unresolved_include_count"], 0)
        self.assertTrue(plan["fallback"])

    def test_baseline_dependency_read_error_falls_back_instead_of_aborting_head_scan(self):
        (self.repo / "src" / "main.cpp").write_text("int main(){return 1;}\n")
        head = self.commit("head without includes")
        from src.ohscanner.git_source import load_git_sources
        _, _, head_sources, head_inventory = load_git_sources(self.repo, head, (".",))
        with patch("src.ohscanner.git_source.load_git_sources", side_effect=ValueError("missing old blob")):
            plan = plan_fixed_commit_diff(self.repo, self.base, head, head_sources=head_sources,
                                          head_inventory=head_inventory)
        self.assertEqual(plan["fallback_reason"], "base_dependency_inventory_unavailable")
        self.assertEqual(plan["include_index"]["status"], "incomplete")
        self.assertEqual(plan["execution"], "full_scan_required")

    def test_baseline_dependency_read_error_falls_back_instead_of_aborting_head_scan(self):
        (self.repo / "src" / "main.cpp").write_text("int main(){return 1;}\n")
        head = self.commit("head without includes")
        from src.ohscanner.git_source import load_git_sources
        _, _, head_sources, head_inventory = load_git_sources(self.repo, head, (".",))
        with patch("src.ohscanner.git_source.load_git_sources", side_effect=ValueError("missing old blob")):
            plan = plan_fixed_commit_diff(self.repo, self.base, head, head_sources=head_sources,
                                          head_inventory=head_inventory)
        self.assertEqual(plan["fallback_reason"], "base_dependency_inventory_unavailable")
        self.assertEqual(plan["include_index"]["status"], "incomplete")
        self.assertEqual(plan["execution"], "full_scan_required")

    def test_honors_include_scope(self):
        (self.repo / "outside.cpp").write_text("int outside;\n")
        head = self.commit("outside")
        plan = plan_fixed_commit_diff(self.repo, self.base, head, includes=("src",))
        self.assertEqual(plan["changed_path_count"], 0)
        self.assertTrue(plan["fallback"])

    def test_rejects_non_ancestor_endpoints(self):
        tree = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", self.base + "^{tree}"], text=True).strip()
        unrelated = subprocess.check_output(
            ["git", "-C", str(self.repo), "commit-tree", tree, "-m", "unrelated root"], text=True
        ).strip()
        with self.assertRaisesRegex(ValueError, "ancestor"):
            plan_fixed_commit_diff(self.repo, self.base, unrelated)


if __name__ == "__main__":
    unittest.main()

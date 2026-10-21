import unittest
from pathlib import Path

from src.workbench.settings import Settings
from src.workbench.agent import _rank_source_actions, _remember_tool_result, _tool_result_cache_key
from src.workbench.smart_audit import _root_cause_group_id


class ResourceProfileTests(unittest.TestCase):
    def test_profiles_have_bounded_defaults(self):
        roots = (Path("/tmp/targets"),)
        self.assertEqual(Settings("/tmp/data", roots, "low").max_concurrent_scans, 1)
        self.assertEqual(Settings("/tmp/data", roots, "balanced").max_concurrent_scans, 2)
        self.assertEqual(Settings("/tmp/data", roots, "high").max_concurrent_scans, 4)

    def test_profile_cannot_exceed_its_limit(self):
        with self.assertRaises(ValueError):
            Settings("/tmp/data", (), "balanced", 3)
        with self.assertRaises(ValueError):
            Settings("/tmp/data", (), "unknown")

    def test_agent_tool_memo_key_is_bound_to_commit_report_candidate_and_policy(self):
        args = {"file": "src/a.cpp", "start_line": 1, "line_count": 5}
        key = _tool_result_cache_key("a" * 40, "b" * 64, "candidate-1", "read_fixed_source_range", args)
        self.assertEqual(key, _tool_result_cache_key("a" * 40, "b" * 64, "candidate-1", "read_fixed_source_range", args))
        self.assertNotEqual(key, _tool_result_cache_key("c" * 40, "b" * 64, "candidate-1", "read_fixed_source_range", args))
        self.assertNotEqual(key, _tool_result_cache_key("a" * 40, "d" * 64, "candidate-1", "read_fixed_source_range", args))
        self.assertNotEqual(key, _tool_result_cache_key("a" * 40, "b" * 64, "candidate-2", "read_fixed_source_range", args))
        self.assertNotEqual(key, _tool_result_cache_key("a" * 40, "b" * 64, "candidate-1", "read_fixed_source_range", args, "new-policy"))

    def test_root_cause_grouping_requires_exact_source_identity(self):
        candidate = {"detector_id": "d", "detector_version": "1", "rule_id": "r",
                     "file": "src/a.cpp", "line": 8, "symbol": "f", "source_sha256": "a" * 64}
        group = _root_cause_group_id(candidate, "b" * 64)
        self.assertEqual(group, _root_cause_group_id(dict(candidate), "b" * 64))
        self.assertNotEqual(group, _root_cause_group_id({**candidate, "line": 9}, "b" * 64))
        self.assertNotEqual(group, _root_cause_group_id({**candidate, "source_sha256": "c" * 64}, "b" * 64))
        self.assertNotEqual(group, _root_cause_group_id(candidate, "d" * 64))

    def test_agent_tool_cache_stores_only_bounded_nontruncated_results(self):
        cache = {}
        self.assertTrue(_remember_tool_result(cache, "ok", {"text": "fixed source excerpt"}))
        self.assertEqual(cache["ok"], {"text": "fixed source excerpt"})
        self.assertFalse(_remember_tool_result(cache, "truncated", {"truncated": True}))
        self.assertFalse(_remember_tool_result(cache, "large", {"text": "x" * (24 * 1024 + 1)}))
        self.assertNotIn("truncated", cache)
        self.assertNotIn("large", cache)

    def test_agent_action_ranking_uses_only_recognized_source_obligations(self):
        obligations = [
            {"kind": "attacker_control"},
            {"kind": "guard_dominance"},
            {"kind": "product_build"},
            {"kind": "cross_function_alias"},
        ]
        actions = _rank_source_actions(obligations, [0, 1, 2, 3])
        self.assertEqual([item["obligation_index"] for item in actions], [1, 0, 3])
        self.assertEqual(actions[0]["tool"], "read_candidate_enclosing_function")
        self.assertEqual(actions[1]["tool"], "lookup_symbol_in_fixed_commit")
        self.assertNotIn(2, [item["obligation_index"] for item in actions])
        self.assertEqual(_rank_source_actions(obligations, [2]), [])


if __name__ == "__main__":
    unittest.main()

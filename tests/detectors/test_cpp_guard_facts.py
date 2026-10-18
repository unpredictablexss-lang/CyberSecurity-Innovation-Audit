from __future__ import annotations

import unittest

from src.ohscanner.detectors.cpp.memory_safety import (
    build_guard_facts,
    function_shapes,
    mask_comments_and_literals,
)


class GuardFactTests(unittest.TestCase):
    def test_lower_and_upper_guards_produce_range_facts(self) -> None:
        text = """
void bounded(int n) {
    if (n <= 0) return;
    if (n > 4) return;
    char dst[4];
    dst[n - 1] = 0;
}
"""
        masked = mask_comments_and_literals(text)
        facts = build_guard_facts(masked, function_shapes(masked))
        bounded = [item for item in facts if item.symbol == "n"]
        self.assertTrue(any(item.lower == 1 for item in bounded))
        self.assertTrue(any(item.upper == 4 for item in bounded))
        self.assertTrue(all(item.error_path == "return" for item in bounded))

    def test_null_check_produces_a_null_fact(self) -> None:
        text = """
void nullable(int *value) {
    if (value == nullptr) return;
    *value = 1;
}
"""
        masked = mask_comments_and_literals(text)
        facts = build_guard_facts(masked, function_shapes(masked))
        value_facts = [item for item in facts if item.symbol == "value"]
        self.assertTrue(value_facts)
        self.assertEqual(value_facts[-1].kind, "null_check")

    def test_inclusive_upper_guard_produces_an_upper_bound(self) -> None:
        text = """
void bounded(unsigned int n) {
    if (n >= 4) return;
    char dst[4];
    dst[n] = 0;
}
"""
        masked = mask_comments_and_literals(text)
        facts = build_guard_facts(masked, function_shapes(masked))
        bounded = [item for item in facts if item.symbol == "n"]
        self.assertTrue(bounded)
        self.assertEqual(bounded[-1].upper, 3)
        self.assertEqual(bounded[-1].kind, "upper_bound")

    def test_zero_exit_produces_an_exact_zero_fact(self) -> None:
        text = """
int Prepare();
void checked() {
    int ret = Prepare();
    if (ret != 0) return;
    char dst[4];
    dst[0] = 0;
}
"""
        masked = mask_comments_and_literals(text)
        facts = build_guard_facts(masked, function_shapes(masked))
        ret_facts = [item for item in facts if item.symbol == "ret"]
        self.assertTrue(ret_facts)
        self.assertEqual(ret_facts[-1].lower, 0)
        self.assertEqual(ret_facts[-1].upper, 0)
        self.assertEqual(ret_facts[-1].kind, "zero_check")
        self.assertEqual(ret_facts[-1].error_path, "return")

    def test_zero_guard_is_recorded_without_overriding_a_range(self) -> None:
        text = """
void checked(unsigned int n) {
    if (n <= 0) return;
    if (n != 0) return;
    char dst[8];
    dst[n] = 0;
}
"""
        masked = mask_comments_and_literals(text)
        facts = build_guard_facts(masked, function_shapes(masked))
        n_facts = [item for item in facts if item.symbol == "n"]
        self.assertEqual(len(n_facts), 2)
        self.assertEqual(n_facts[0].lower, 1)
        self.assertEqual(n_facts[1].kind, "zero_check")
        self.assertEqual((n_facts[1].lower, n_facts[1].upper), (0, 0))


if __name__ == "__main__":
    unittest.main()

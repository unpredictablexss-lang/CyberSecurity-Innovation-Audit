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


if __name__ == "__main__":
    unittest.main()

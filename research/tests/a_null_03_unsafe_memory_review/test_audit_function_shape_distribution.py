from __future__ import annotations

import unittest

from audit_function_shape_distribution import function_shapes_by_line


class FunctionShapeDistributionTests(unittest.TestCase):
    source = """\
void free_fn() {
    printf("x");
}
struct S {
    void member() {
        printf("x");
    }
};
#define WRAP(x) printf(x)
"""

    def test_free_and_member_function_shapes(self) -> None:
        self.assertEqual(function_shapes_by_line(self.source, {2, 6}), {
            2: "free_function",
            6: "member_method",
        })

    def test_macro_and_outside_function_shapes(self) -> None:
        self.assertEqual(function_shapes_by_line(self.source, {4, 9}), {
            4: "outside_named_function",
            9: "macro_definition_body",
        })


if __name__ == "__main__":
    unittest.main()

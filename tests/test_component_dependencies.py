import unittest
from src.benchmark.component_dependencies import inventory_dependencies


def bundle(name, deps):
    return ({'commit': 'fixed'}, {'component': {'name': name, 'deps': {'components': deps}}})


class ComponentDependencyTests(unittest.TestCase):
    def test_cycle_does_not_hide_missing_transitive_dependency(self):
        result = inventory_dependencies([bundle('c_utils', ['hilog']), bundle('hilog', ['c_utils', 'init'])], 'c_utils')
        self.assertEqual(result['unresolved_components'], ['init'])
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(len(result['edges']), 3)
        self.assertEqual(result['build_status'], 'not_run')

    def test_duplicate_identity_is_rejected(self):
        with self.assertRaises(ValueError):
            inventory_dependencies([bundle('c_utils', []), bundle('c_utils', ['other'])], 'c_utils')

    def test_present_declarations_do_not_claim_build_closure(self):
        result = inventory_dependencies([bundle('c_utils', [])], 'c_utils')
        self.assertEqual(result['status'], 'declared_inputs_present')
        self.assertFalse(result['full_product_lock'])
        self.assertEqual(result['compile_commands_status'], 'not_generated')

    def test_unknown_dependency_shape_is_rejected(self):
        with self.assertRaises(ValueError):
            inventory_dependencies([bundle('c_utils', {'init': 'latest'})], 'c_utils')

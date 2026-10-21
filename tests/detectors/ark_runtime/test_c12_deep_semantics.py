import unittest
from pathlib import Path

from src.ohscanner.detectors.ark_runtime.cross_helper import (
    build_helper_contracts, build_identity_helpers, effectful_helper_problem,
)
from src.ohscanner.detectors.ark_runtime.model import AnalysisBudget
from src.ohscanner.detectors.ark_runtime.runtime_ir import build_graph
from src.ohscanner.detectors.ark_runtime.size_overflow import analyze_size_overflow, analyze_size_flows
from src.ohscanner.detectors.ark_runtime.syntax import parse_functions, walk


FIXTURES = Path(__file__).parent / 'fixtures' / 'c12_deep_semantics'


def source(name):
    return (FIXTURES / name).read_text(encoding='utf-8')


def functions(name):
    return parse_functions(source(name).encode('utf-8'))[1]


def first_call(function):
    return next(node for node in walk(function.body) if node.type == 'call_expression')


class HelperContractControls(unittest.TestCase):
    def test_effectful_helper_has_explicit_contract_and_is_not_identity(self):
        fns = functions('effectful_positive.cpp')
        contracts = build_helper_contracts(fns)
        wrapper = next(item for item in contracts if item.name == 'wrapper')
        self.assertTrue(wrapper.effects)
        self.assertFalse(wrapper.returns_parameter)
        self.assertFalse(any(item.name == 'wrapper' for item in build_identity_helpers(fns)))
        caller = next(item for item in fns if item.qualified_name == 'caller')
        self.assertTrue(effectful_helper_problem(caller, first_call(caller), contracts))

    def test_fixed_identity_helper_is_effect_free(self):
        fns = functions('effectful_fixed.cpp')
        contracts = build_helper_contracts(fns)
        wrapper = next(item for item in contracts if item.name == 'wrapper')
        self.assertEqual(wrapper.effects, ())
        self.assertTrue(wrapper.returns_parameter)
        self.assertTrue(any(item.name == 'wrapper' for item in build_identity_helpers(fns)))

    def test_safe_local_identity_is_not_a_security_verdict(self):
        fns = functions('effectful_safe.cpp')
        self.assertTrue(build_helper_contracts(fns)[0].returns_parameter)

    def test_unrelated_helper_has_no_applicable_contract(self):
        fns = functions('effectful_unrelated.cpp')
        self.assertFalse(any(item.name == 'log_event' and item.effects for item in build_helper_contracts(fns)))

    def test_unknown_helper_is_explicitly_effectful(self):
        fns = functions('effectful_unknown.cpp')
        contracts = build_helper_contracts(fns)
        wrapper = next(item for item in contracts if item.name == 'wrapper')
        self.assertIn('call:Opaque', wrapper.effects)
        self.assertFalse(wrapper.returns_parameter)


class CrossFunctionSummaryControls(unittest.TestCase):
    def test_forwarding_chain_is_bounded_identity_summary(self):
        fns = functions('summary_positive.cpp')
        contracts = build_helper_contracts(fns)
        self.assertTrue(all(next(item for item in contracts if item.name == name).returns_parameter
                            for name in ('inner', 'outer', 'caller')))
        self.assertEqual({item.name for item in build_identity_helpers(fns)},
                         {'inner', 'outer', 'caller'})

    def test_direct_identity_is_still_supported(self):
        self.assertTrue(build_identity_helpers(functions('summary_fixed.cpp')))

    def test_constant_helper_is_not_identity(self):
        self.assertFalse(build_identity_helpers(functions('summary_safe.cpp')))

    def test_unrelated_type_helper_is_not_promoted(self):
        self.assertFalse(build_identity_helpers(functions('summary_unrelated.cpp')))

    def test_unknown_forwarding_helper_remains_unknown(self):
        contracts = build_helper_contracts(functions('summary_unknown.cpp'))
        self.assertFalse(next(item for item in contracts if item.name == 'outer').returns_parameter)


class NumericCastSignWidthControls(unittest.TestCase):
    def analyze(self, name):
        return analyze_size_flows(source(name))

    def test_positive_signed_narrowing_is_candidate(self):
        flows, limitations = self.analyze('numeric_positive.cpp')
        self.assertEqual(len(analyze_size_overflow(source('numeric_positive.cpp'))[0]), 1)
        self.assertTrue(flows[0].sign_width_loss)
        self.assertEqual(limitations, ())

    def test_fixed_unsigned_width_control_has_no_candidate(self):
        flows, limitations = self.analyze('numeric_fixed.cpp')
        self.assertEqual(analyze_size_overflow(source('numeric_fixed.cpp'))[0], ())
        self.assertEqual(limitations, ())

    def test_safe_local_zero_product_is_not_security_verdict(self):
        flows, limitations = self.analyze('numeric_safe.cpp')
        self.assertEqual(analyze_size_overflow(source('numeric_safe.cpp'))[0], ())
        self.assertEqual(limitations, ())

    def test_unrelated_conversion_without_allocation_is_not_applicable(self):
        flows, limitations = self.analyze('numeric_unrelated.cpp')
        self.assertEqual(flows, ())
        self.assertEqual(limitations, ())

    def test_unknown_conversion_is_explicitly_partial(self):
        flows, limitations = self.analyze('numeric_unknown.cpp')
        self.assertEqual(flows, ())
        self.assertTrue(any(item.startswith('numeric_conversion_semantics_unmodeled:')
                            for item in limitations))


class MinimalLoopBackedgeControls(unittest.TestCase):
    def graph(self, name):
        fn = functions(name)[0]
        return fn, build_graph(fn, AnalysisBudget())

    def test_positive_loop_end_backedge_is_audited(self):
        _, graph = self.graph('loop_positive.cpp')
        self.assertEqual(len(graph.loop_backedges), 1)
        self.assertFalse(any('loop_backedge' in item for item in graph.limitations))

    def test_fixed_exit_has_no_backedge(self):
        _, graph = self.graph('loop_fixed.cpp')
        self.assertEqual(graph.loop_backedges, ())
        self.assertFalse(any('loop_backedge' in item for item in graph.limitations))

    def test_safe_zero_iteration_shape_is_not_a_security_verdict(self):
        _, graph = self.graph('loop_safe.cpp')
        self.assertEqual(graph.loop_backedges, ())
        self.assertFalse(any('loop_backedge' in item for item in graph.limitations))

    def test_host_loop_is_unrelated_to_generated_cfg(self):
        _, graph = self.graph('loop_unrelated.cpp')
        self.assertEqual(graph.loop_backedges, ())
        self.assertTrue(any('unsupported_host_control' in item for item in graph.limitations))

    def test_unknown_loop_target_is_fail_closed(self):
        _, graph = self.graph('loop_unknown.cpp')
        self.assertEqual(graph.loop_backedges, ())
        self.assertTrue(any('loop_backedge' in item or 'unresolved_label_target' in item
                            for item in graph.limitations))


if __name__ == '__main__':
    unittest.main()

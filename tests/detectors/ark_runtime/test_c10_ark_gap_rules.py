from dataclasses import replace
from hashlib import sha1
from pathlib import Path
import unittest

from src.ohscanner.detectors.ark_runtime.detector import ArkRuntimeTypeSafetyDetector
from src.ohscanner.detectors.ark_runtime.model import (
    INDEX_BOUNDS_RULE_ID, LENGTH_NARROWING_RULE_ID, NATIVE_EXCEPTION_RULE_ID,
    GAP_RULE_VERSIONS, RuntimeTypeModel,
)
from src.ohscanner.detectors.ark_runtime.runtime_exception import (
    analyze_native_inline_exception_propagation,
)
from src.ohscanner.detectors.ark_runtime.size_overflow import (
    analyze_index_bounds_flows, analyze_length_narrowing_flows,
    index_bounds_result, length_narrowing_result,
)
from .support import context, unit

FIXTURES = Path(__file__).parent / 'fixtures' / 'c10_gap_rules'


def fixture(name):
    return unit((FIXTURES / name).read_text(encoding='utf-8'), 'ecmascript/' + name)


class NativeInlineExceptionGapTests(unittest.TestCase):
    def analyze(self, name):
        return analyze_native_inline_exception_propagation(fixture(name))

    def test_positive_is_source_bound_candidate(self):
        result = self.analyze('ia_positive.cpp')
        self.assertEqual(result.file_outcome, 'partial')
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].kind, 'candidate')
        self.assertIn('sentinel_comparison', result.observations[0].reason)

    def test_fixed_pending_exception_control_has_no_same_root_candidate(self):
        result = self.analyze('ia_fixed.cpp')
        self.assertFalse(any(item.kind == 'candidate' for item in result.observations))
        self.assertTrue(any('fixed_pending_exception_check_control' in x
                            for x in result.limitations))

    def test_safe_local_guard_control_is_not_a_security_verdict(self):
        result = self.analyze('ia_safe.cpp')
        self.assertEqual(result.observations, ())

    def test_unrelated_owner_is_not_analyzed(self):
        result = self.analyze('ia_unrelated.cpp')
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertEqual(result.observations, ())

    def test_missing_helper_is_explicit_unknown(self):
        result = self.analyze('ia_unknown.cpp')
        self.assertEqual(result.file_outcome, 'partial')
        self.assertEqual(result.observations, ())
        self.assertTrue(any('helper_summary_missing' in x for x in result.limitations))

    def test_native_inline_lowering_path_is_selected(self):
        source = fixture('ia_positive.cpp')
        raw = source.text.encode('utf-8')
        blob = sha1(b'blob ' + str(len(raw)).encode('ascii') + bytes((0)) + raw).hexdigest()
        model = replace(RuntimeTypeModel(), source_repository='fixture/ark-runtime',
                        target_bindings=(), exception_guard_bindings=(),
                        receiver_guard_bindings=(), size_overflow_bindings=(),
                        length_narrowing_bindings=(), index_bounds_bindings=(),
                        native_exception_bindings=(('a' * 40, source.path, blob, source.sha256),))
        selected = ArkRuntimeTypeSafetyDetector(model=model).select_applicable_units(
            context((source,)), (source,))
        self.assertEqual(selected, (source,))

    def test_rule_versions_are_stable(self):
        self.assertEqual(GAP_RULE_VERSIONS[NATIVE_EXCEPTION_RULE_ID], '1.1.0')


class TypedArrayLengthGapTests(unittest.TestCase):
    def analyze_flows(self, name):
        source = fixture(name)
        return source, analyze_length_narrowing_flows(source.text)

    def analyze(self, name):
        source = fixture(name)
        return length_narrowing_result(source, 'model-digest')

    def test_positive_signed_narrowing_to_allocation_is_candidate(self):
        source, (candidates, limitations) = self.analyze_flows('length_positive.cpp')
        self.assertEqual(len(candidates), 1)
        self.assertEqual(limitations, ())
        self.assertEqual(candidates[0].result_name, 'elementLength')

    def test_fixed_unsigned_conversion_has_no_same_root_candidate(self):
        result = self.analyze('length_fixed.cpp')
        self.assertEqual(result.observations, ())
        self.assertTrue(any('no_local_length_narrowing_candidate' in x
                            for x in result.limitations))
        # RangeError/fixed semantics are not a product-safety verdict.
        self.assertNotIn('safe', result.file_outcome)

    def test_safe_local_zero_length_control_is_not_security_verdict(self):
        result = self.analyze('length_safe.cpp')
        self.assertEqual(result.observations, ())
        self.assertEqual(result.file_outcome, 'complete')

    def test_unrelated_signed_conversion_is_not_applicable(self):
        result = self.analyze('length_unrelated.cpp')
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertTrue(any('not_applicable' in x for x in result.limitations))

    def test_unknown_conversion_helper_is_explicit_unknown(self):
        result = self.analyze('length_unknown.cpp')
        self.assertEqual(result.file_outcome, 'partial')
        self.assertEqual(result.observations, ())
        self.assertTrue(any('conversion_semantics_unmodeled' in x
                            for x in result.limitations))

    def test_rule_version_is_stable(self):
        self.assertEqual(GAP_RULE_VERSIONS[LENGTH_NARROWING_RULE_ID], '1.1.0')


class DataViewIndexBoundsGapTests(unittest.TestCase):
    def analyze_flows(self, name):
        source = fixture(name)
        return source, analyze_index_bounds_flows(source.text)

    def analyze(self, name):
        source = fixture(name)
        return index_bounds_result(source, 'model-digest')

    def test_positive_32_bit_index_arithmetic_is_candidate(self):
        source, (candidates, limitations) = self.analyze_flows('index_positive.cpp')
        self.assertEqual(len(candidates), 1)
        self.assertEqual(limitations, ())
        self.assertEqual(candidates[0].function, 'DataViewGet')

    def test_fixed_64_bit_bounds_control_remains_explicitly_unproven(self):
        result = self.analyze('index_fixed.cpp')
        self.assertFalse(any(item.kind == 'candidate' for item in result.observations))
        self.assertEqual(result.file_outcome, 'partial')
        self.assertTrue(any('not_fully_proven' in x for x in result.limitations))

    def test_subtraction_safe_local_control_is_not_security_verdict(self):
        result = self.analyze('index_safe.cpp')
        self.assertEqual(result.observations, ())
        self.assertEqual(result.file_outcome, 'complete')

    def test_unrelated_integer_addition_is_not_applicable(self):
        result = self.analyze('index_unrelated.cpp')
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertTrue(any('not_applicable' in x for x in result.limitations))

    def test_unknown_bounds_helper_is_explicit_unknown(self):
        result = self.analyze('index_unknown.cpp')
        self.assertEqual(result.file_outcome, 'partial')
        self.assertTrue(any('semantics_unmodeled' in x for x in result.limitations))
        self.assertFalse(any(item.kind == 'candidate' for item in result.observations))

    def test_rule_version_is_stable(self):
        self.assertEqual(GAP_RULE_VERSIONS[INDEX_BOUNDS_RULE_ID], '1.1.0')


if __name__ == '__main__':
    unittest.main()

import unittest
from dataclasses import replace

from src.ohscanner.detectors.ark_runtime.negative_double_length import (
    _double_guard_block, _PINNED_ROWS, analyze_negative_double_length,
)
from src.ohscanner.detectors.ark_runtime.model import (
    NEGATIVE_DOUBLE_LENGTH_RULE_ID, c_line_static_model,
)
from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest


class NegativeDoubleLengthRuleTests(unittest.TestCase):
    def test_rule_is_registered_in_the_exact_c_line_model(self):
        model = c_line_static_model()
        self.assertEqual(NEGATIVE_DOUBLE_LENGTH_RULE_ID,
                         'ark.runtime.float32array-negative-double-length')
        self.assertEqual([row[1] for row in model.negative_double_length_bindings], [
            'ecmascript/compiler/common_stubs.cpp',
            'ecmascript/compiler/typed_hcr_lowering.cpp',
            'ecmascript/compiler/new_object_stub_builder.cpp',
        ])
        self.assertTrue(all(row[0] == 'a65a2853ccae13da167d9aa4720ab8b11ec16656'
                            and len(row[2]) == 40 and len(row[3]) == 64
                            for row in model.negative_double_length_bindings))
        self.assertEqual(model.negative_double_length_bindings, _PINNED_ROWS)
        changed = list(model.negative_double_length_bindings)
        changed[2] = (changed[2][0], changed[2][1], '0' * 40, changed[2][3])
        changed_model = replace(model, negative_double_length_bindings=tuple(changed))
        context = ScanContext(
            ScanRequest('test', 'openharmony/arkcompiler_ets_runtime',
                        'a65a2853ccae13da167d9aa4720ab8b11ec16656', snapshot_digest(()),
                        'current-component:openharmony/arkcompiler_ets_runtime',
                        'light-ast', 'git_object'), (), {})
        result = analyze_negative_double_length(context, changed_model)
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertFalse(result.observations)
        self.assertIn('negative_double_length_profile_incomplete', result.limitations)

    def test_missing_double_lower_bound_is_the_only_positive_predicate(self):
        block = '''
            GateRef doubleLength = GetDoubleOfTDouble(arg0);
            GateRef doubleToInt = DoubleToInt(glue, doubleLength, base::INT32_BITS);
            GateRef doubleEqual = DoubleEqual(doubleLength, intToDouble);
            GateRef doubleLEMaxLen = DoubleLessThanOrEqual(doubleLength, Double(JSObject::MAX_GAP));
            BRANCH(BitAnd(doubleEqual, doubleLEMaxLen), &validDoubleLength, &slowPath);
            arrayLength = SExtInt32ToInt64(doubleToInt);
        '''
        self.assertIsNotNone(_double_guard_block(
            block, 'DoubleToInt(glue, doubleLength, base::INT32_BITS)',
            'DoubleLessThanOrEqual(doubleLength, Double(JSObject::MAX_GAP))'))

    def test_fixed_double_lower_bound_is_not_a_candidate(self):
        fixed = '''
            GateRef doubleLength = GetDoubleOfTDouble(arg0);
            GateRef doubleToInt = DoubleToInt(glue, doubleLength, base::INT32_BITS);
            GateRef nonNegative = DoubleGreaterThanOrEqual(doubleLength, Double(0));
            GateRef doubleEqual = DoubleEqual(doubleLength, intToDouble);
            GateRef doubleLEMaxLen = DoubleLessThanOrEqual(doubleLength, Double(JSObject::MAX_GAP));
            BRANCH(BitAnd(nonNegative, BitAnd(doubleEqual, doubleLEMaxLen)), &validDoubleLength, &slowPath);
            arrayLength = SExtInt32ToInt64(doubleToInt);
        '''
        self.assertIsNone(_double_guard_block(
            fixed, 'DoubleToInt(glue, doubleLength, base::INT32_BITS)',
            'DoubleLessThanOrEqual(doubleLength, Double(JSObject::MAX_GAP))'))

    def test_tagged_int_lower_bound_is_not_mistaken_for_double_guard(self):
        tagged_int_only = '''
            GateRef intLen = GetInt32OfTInt(arg0);
            GateRef isGEZero = Int64GreaterThanOrEqual(intLen, Int64(0));
            BRANCH(BitAnd(isGEZero, isLEMaxLen), &validIntLength, &slowPath);
        '''
        self.assertIsNone(_double_guard_block(
            tagged_int_only, 'DoubleToInt(glue, doubleLength, base::INT32_BITS)',
            'DoubleLessThanOrEqual(doubleLength, Double(JSObject::MAX_GAP))'))

    def test_wrong_upper_bound_or_unrelated_block_does_not_match(self):
        unrelated = '''
            GateRef doubleLength = GetDoubleOfTDouble(arg0);
            GateRef doubleToInt = DoubleToInt(glue, doubleLength, base::INT32_BITS);
            GateRef doubleEqual = DoubleEqual(doubleLength, intToDouble);
            GateRef unrelated = DoubleLessThanOrEqual(doubleLength, Double(99));
            BRANCH(BitAnd(doubleEqual, unrelated), &yes, &no);
            arrayLength = SExtInt32ToInt64(doubleToInt);
        '''
        self.assertIsNone(_double_guard_block(
            unrelated, 'DoubleToInt(glue, doubleLength, base::INT32_BITS)',
            'DoubleLessThanOrEqual(doubleLength, Double(JSObject::MAX_GAP))'))


if __name__ == '__main__':
    unittest.main()

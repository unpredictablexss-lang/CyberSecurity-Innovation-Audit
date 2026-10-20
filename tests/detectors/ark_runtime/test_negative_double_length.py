import unittest

from src.ohscanner.detectors.ark_runtime.negative_double_length import _double_guard_block
from src.ohscanner.detectors.ark_runtime.model import (
    NEGATIVE_DOUBLE_LENGTH_RULE_ID, c_line_static_model,
)


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

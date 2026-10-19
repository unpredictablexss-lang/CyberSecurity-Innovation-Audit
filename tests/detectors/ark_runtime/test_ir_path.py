import unittest
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.model import AnalysisBudget
from .support import case, unit, wrap, PREFIX


class GeneratedPathTests(unittest.TestCase):
    def test_C09_host_branch_merge_is_unknown(self):
        result = analyze_unit(case('C09'))
        self.assertTrue(any(o.kind == 'unknown' for o in result.observations))
        self.assertFalse(any(o.kind == 'candidate' for o in result.observations))

    def test_C10_unmodelled_control_stops_inference(self):
        result = analyze_unit(case('C10'))
        self.assertTrue(any(o.kind == 'unknown' for o in result.observations))
        self.assertFalse(any(o.kind == 'candidate' for o in result.observations))

    def test_C11_damaged_target_is_not_analyzed(self):
        result = analyze_unit(case('C11'), research_partial=True)
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertFalse(any(o.kind == 'candidate' for o in result.observations))

    def test_C12_detached_label_has_no_runtime_predecessor(self):
        result = analyze_unit(case('C12'))
        self.assertEqual([o.kind for o in result.observations], ['unreachable'])

    def test_false_generated_branch_prunes_sink(self):
        code = wrap(PREFIX + 'Label write(GetEnvironment());\nBRANCH(false, &write, exit);\n'
                    'Bind(&write);\nStoreTypedArrayElement(glue, output, count, input, inputTag);\nJump(exit);')
        self.assertEqual([o.kind for o in analyze_unit(unit(code)).observations], ['unreachable'])

    def test_type_equality_guard_is_narrow_suppression(self):
        code = wrap(PREFIX + 'GateRef t = GetObjectType(LoadHClass(output));\n'
                    'Label write(GetEnvironment());\nBRANCH(Int32Equal(inputTag, t), &write, exit);\n'
                    'Bind(&write);\nStoreTypedArrayElement(glue, output, count, input, inputTag);\nJump(exit);')
        self.assertEqual([o.kind for o in analyze_unit(unit(code)).observations], ['matched'])

    def test_unknown_label_is_not_a_reachable_path(self):
        code = wrap(PREFIX + 'Jump(&missing);\nStoreTypedArrayElement(glue, output, count, input, inputTag);')
        result = analyze_unit(unit(code))
        self.assertTrue(any(o.kind == 'unknown' for o in result.observations))
        self.assertFalse(any(o.kind == 'candidate' for o in result.observations))

    def test_repeated_immutable_predicate_cannot_be_true_and_false(self):
        code = wrap(PREFIX + 'Label first(GetEnvironment());\nLabel write(GetEnvironment());\n'
                    'BRANCH(count, &first, exit);\nBind(&first);\nBRANCH(count, exit, &write);\n'
                    'Bind(&write);\nStoreTypedArrayElement(glue, output, count, input, inputTag);\nJump(exit);')
        self.assertEqual([o.kind for o in analyze_unit(unit(code)).observations], ['unreachable'])

    def test_type_equality_is_not_valid_after_unknown_mutation(self):
        code = wrap(PREFIX + 'GateRef t = GetObjectType(LoadHClass(output));\n'
                    'Label write(GetEnvironment());\nBRANCH(Int32Equal(inputTag, t), &write, exit);\n'
                    'Bind(&write);\nMutate(input);\n'
                    'StoreTypedArrayElement(glue, output, count, input, inputTag);\nJump(exit);')
        self.assertEqual([o.kind for o in analyze_unit(unit(code)).observations], ['candidate'])

    def test_state_budget_does_not_publish_partial_candidates(self):
        result = analyze_unit(case('C03'), budget=AnalysisBudget(max_states=1))
        self.assertEqual(result.status, 'limited')
        self.assertFalse(result.observations)

    def test_time_budget_does_not_publish_partial_candidates(self):
        result = analyze_unit(case('C03'), budget=AnalysisBudget(max_seconds=0))
        self.assertEqual(result.status, 'timed_out')
        self.assertFalse(result.observations)

    def test_budget_expiry_after_a_candidate_does_not_publish_it(self):
        code = wrap(PREFIX + 'StoreTypedArrayElement(glue, output, count, input, inputTag);\n'
                    'Label next(GetEnvironment());\nJump(&next);\nBind(&next);\nJump(exit);')
        result = analyze_unit(unit(code), budget=AnalysisBudget(max_steps=4))
        self.assertEqual(result.status, 'limited')
        self.assertFalse(result.observations)

    def test_scope_depth_budget_is_bounded(self):
        code = wrap('{' * 20 + PREFIX + '}' * 20)
        result = analyze_unit(unit(code), budget=AnalysisBudget(max_scope_depth=4))
        self.assertIn('scope_depth_budget_exhausted', result.limitations)


if __name__ == '__main__':
    unittest.main()

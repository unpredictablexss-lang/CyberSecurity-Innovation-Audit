import unittest
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.model import AnalysisBudget
from .support import case, unit, wrap, PREFIX


class TypeOriginTests(unittest.TestCase):
    def test_C03_renamed_variables_still_form_candidate(self):
        result = analyze_unit(case('C03'))
        self.assertEqual([o.kind for o in result.observations], ['candidate'])
        self.assertNotEqual(result.observations[0].target_identity, result.observations[0].token_origin)

    def test_C04_target_type_has_same_identity(self):
        self.assertEqual([o.kind for o in analyze_unit(case('C04')).observations], ['matched'])

    def test_C05_local_object_alias_preserves_identity(self):
        self.assertEqual([o.kind for o in analyze_unit(case('C05')).observations], ['matched'])

    def test_C06_token_copy_preserves_origin(self):
        self.assertEqual([o.kind for o in analyze_unit(case('C06')).observations], ['matched'])

    def test_C07_reassignment_kills_old_object_fact(self):
        self.assertEqual([o.kind for o in analyze_unit(case('C07')).observations], ['unknown'])

    def test_C08_other_owner_is_not_a_modelled_call(self):
        result = analyze_unit(case('C08'))
        self.assertFalse(result.observations)
        self.assertIn('not_applicable_to_rule', result.limitations)

    def test_namespace_homonym_is_not_bound(self):
        code = wrap(PREFIX + 'StoreTypedArrayElement(glue, output, count, input, inputTag);', namespace='unrelated')
        self.assertFalse(analyze_unit(unit(code)).observations)

    def test_reassignment_of_type_token_uses_new_definition(self):
        code = wrap(PREFIX + 'inputTag = GetObjectType(LoadHClass(output));\n'
                    'StoreTypedArrayElement(glue, output, count, input, inputTag);')
        self.assertEqual([o.kind for o in analyze_unit(unit(code)).observations], ['matched'])

    def test_unknown_escape_invalidates_same_object_guarantee(self):
        code = wrap(PREFIX + 'GateRef t = GetObjectType(LoadHClass(output));\nMutate(output);\n'
                    'StoreTypedArrayElement(glue, output, count, input, t);')
        self.assertEqual([o.kind for o in analyze_unit(unit(code)).observations], ['unknown'])

    def test_local_shadow_is_not_the_outer_object(self):
        code = wrap(PREFIX + '{ GateRef output = input;\n'
                    'StoreTypedArrayElement(glue, output, count, input, inputTag); }')
        self.assertEqual([o.kind for o in analyze_unit(unit(code)).observations], ['matched'])

    def test_wrong_sink_arity_stays_unknown(self):
        code = wrap(PREFIX + 'StoreTypedArrayElement(glue, output, inputTag);')
        self.assertEqual([o.kind for o in analyze_unit(unit(code)).observations], ['unknown'])

    def test_byte_budget_does_not_produce_empty_safe_result(self):
        result = analyze_unit(case('C03'), budget=AnalysisBudget(max_source_bytes=1))
        self.assertEqual(result.status, 'limited')
        self.assertEqual(result.file_outcome, 'not_analyzed')

    def test_relevant_macro_redefinition_is_not_silently_ignored(self):
        code = '#define StoreTypedArrayElement(a,b,c,d,e) something_else(a,b,c,d,e)\n' + case('C03').text
        result = analyze_unit(unit(code))
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertIn('model_symbol_macro_redefined', result.limitations)

    def test_conditional_compilation_needs_build_context(self):
        code = '#ifdef UNKNOWN_BUILD\n' + case('C03').text + '\n#endif\n'
        result = analyze_unit(unit(code))
        self.assertFalse(any(o.kind == 'candidate' for o in result.observations))
        self.assertIn('target_conditional_compilation_unresolved', result.limitations)

    def test_unresolved_receiver_is_unknown_not_silently_matched(self):
        code = wrap(PREFIX + 'foreign.StoreTypedArrayElement(glue, output, count, input, inputTag);')
        self.assertEqual([o.kind for o in analyze_unit(unit(code)).observations], ['unknown'])

    def test_unmodeled_lambda_is_not_expanded_as_current_function(self):
        code = wrap(PREFIX + 'auto later = [&]() { StoreTypedArrayElement(glue, output, count, input, inputTag); };\nlater();')
        result = analyze_unit(unit(code))
        self.assertTrue(any(o.kind == 'unknown' for o in result.observations))
        self.assertFalse(any(o.kind == 'candidate' for o in result.observations))


if __name__ == '__main__':
    unittest.main()

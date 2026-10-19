"""C3 development controls, authored before algorithm changes; not holdout."""
from dataclasses import replace
import unittest
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.model import AnalysisBudget, RuntimeTypeModel
from .support import PREFIX, unit, wrap

STORE = 'StoreTypedArrayElement(glue, output, count, input, inputTag);\n'
FRESH = 'GateRef tag = GetObjectType(LoadHClass(output));\n'
SAFE_STORE = 'StoreTypedArrayElement(glue, output, count, input, tag);\n'
GUARD = ('GateRef tag = GetObjectType(LoadHClass(output));\n'
         'Label write(GetEnvironment());\n'
         'BRANCH(Int32Equal(inputTag, tag), &write, exit);\nBind(&write);\n')

# expected describes local rule evidence, not product safety or exploitability.
CASES = (
    ('G01', PREFIX + 'GateRef resultAlias = output; GateRef x = inputTag; GateRef y = x;\n'
     'StoreTypedArrayElement(glue, resultAlias, count, input, y);', 'candidate',
     'Destination alias and two token copies preserve distinct origins.'),
    ('G02', PREFIX + FRESH + 'GateRef x = tag; GateRef y = x;\n'
     'StoreTypedArrayElement(glue, output, count, input, y);', 'matched',
     'Two copies of a fresh destination token retain the same origin.'),
    ('G03', PREFIX + FRESH + 'GateRef ignored = Mutate(output);\n' + SAFE_STORE, 'unknown',
     'Unknown effects inside declaration initializers invalidate stale tokens.'),
    ('G04', PREFIX + FRESH + 'ignored = Mutate(output);\n' + SAFE_STORE, 'unknown',
     'Unknown effects in assignment RHS invalidate stale tokens.'),
    ('G05', PREFIX + FRESH + 'foreign.Mutate(output);\n' + SAFE_STORE, 'unknown',
     'Unknown member-call arguments may escape the destination.'),
    ('G06', PREFIX + FRESH + 'Observe(Mutate(output));\n' + SAFE_STORE, 'unknown',
     'Nested calls cannot retain old type observations.'),
    ('G07', PREFIX + FRESH + 'UnknownGlobalEffect();\n' + SAFE_STORE, 'unknown',
     'Unmodelled global effects cannot prove type stability.'),
    ('G08', PREFIX + FRESH + 'Label write(GetEnvironment());\n'
     'BRANCH(Mutate(output), &write, exit);\nBind(&write);\n' + SAFE_STORE, 'unknown',
     'Condition evaluation can have effects before either generated successor.'),
    ('G09', PREFIX + FRESH +
     'StoreTypedArrayElement(glue, output, count, Mutate(output), tag);', 'unknown',
     'Sink argument effects must be applied before checking type evidence.'),
    ('G10', PREFIX + 'Mutate(output);\n' + STORE, 'unknown',
     'An invalidated destination cannot support an old mismatch candidate.'),
    ('G11', PREFIX + GUARD + 'GateRef ignored = Mutate(input);\n' + STORE, 'unknown',
     'A successful type guard must not survive an unknown effect.'),
    ('G12', PREFIX + 'GateRef tag = GetObjectType(LoadHClass(input));\n'
     'Label write(GetEnvironment());\nBRANCH(Int32Equal(inputTag, tag), &write, exit);\n'
     'Bind(&write);\n' + STORE, 'candidate',
     'A guard comparing two source tokens says nothing about the destination.'),
    ('G13', PREFIX + FRESH + 'GateRef Int32Equal = foreign;\n'
     'Label write(GetEnvironment());\nBRANCH(Int32Equal(inputTag, tag), &write, exit);\n'
     'Bind(&write);\n' + STORE, 'unknown',
     'A shadowed equality operation cannot justify a same-type guarantee.'),
    ('G14', PREFIX + 'UNMODELED_IR();\n' + STORE, 'unknown',
     'A sink beyond unknown generated control is unknown, not proven unreachable.'),
    ('G15', PREFIX + 'return StoreTypedArrayElement(glue, output, count, input, inputTag);', 'unknown',
     'Return expressions must not hide unanalysed effectful calls.'),
    ('G16', PREFIX + 'Label detached(GetEnvironment()); Jump(exit); Bind(&detached);\n' + STORE,
     'not_analyzed', 'A detached generated block without a predecessor has no analysed sink path.'),
    ('G17', PREFIX + 'Jump(&missing);\n' + STORE, 'unknown',
     'An unresolved jump is an unknown edge, not proof of absence.'),
    ('G18', PREFIX + FRESH + 'GateRef alias = output; alias = input;\n'
     'StoreTypedArrayElement(glue, alias, count, input, tag);', 'unknown',
     'Rebinding alias to the source does not make the old destination token match.'),
    ('G19', PREFIX + 'GateRef old = inputTag; inputTag = GetObjectType(LoadHClass(output));\n'
     'StoreTypedArrayElement(glue, output, count, input, old);', 'candidate',
     'Token redefinition does not retroactively change a prior copied token.'),
    ('G20', PREFIX + 'if (count) { output = input; }\n' + STORE, 'unknown',
     'Unmodelled host-C++ merge does not justify either origin.'),
    ('G21', PREFIX + FRESH + 'foreign.StoreTypedArrayElement(glue, output, count, input, tag);',
     'unknown', 'The same sink spelling on another receiver is not a model binding.'),
    ('G22', PREFIX + 'Label again(GetEnvironment()); Jump(&again); LoopBegin(&again);\n'
     'output = builder.NewTypedArray(glue, input, inputTag, count);\n' + STORE + 'LoopEnd(&again);',
     'unknown', 'Repeated allocation sites require iteration-sensitive identity; retain unknown.'),
    ('G23', PREFIX + FRESH + 'GateRef tag2 = GetObjectType(LoadHClass(input));\n'
     'tag = tag2;\n' + SAFE_STORE, 'candidate',
     'Reassigning a token must use its new source origin.'),
    ('G24', PREFIX + 'GateRef tag = GetObjectType(LoadHClass(output));\n'
     'Label write(GetEnvironment()); BRANCH(Int32Equal(inputTag, tag), &write, exit);\n'
     'Bind(&write);\n' + STORE, 'matched',
     'A bound, uninvalidated equality guard is a narrow same-type proof.'),
)


def classify(result):
    kinds = {o.kind for o in result.observations}
    if 'candidate' in kinds:
        return 'candidate'
    if 'unknown' in kinds:
        return 'unknown'
    if 'matched' in kinds:
        return 'matched'
    return 'not_analyzed'


class C3MechanismTests(unittest.TestCase):
    def test_copywithin_reviewed_reads_preserve_same_object_type(self):
        text = ('auto env = GetEnvironment();\n'
                'GateRef inputTag = GetObjectType(LoadHClass(input));\n'
                'Label write(GetEnvironment()); Label more(GetEnvironment());\n'
                'BRANCH(IsFastTypeArray(inputTag), &write, exit);\nBind(&write);\n'
                'GateRef offset = CalculatePositionWithLength(count, count);\n'
                'BRANCH(LogicAndBuilder(env).And(Int64LessThan(offset, count))'
                '.And(Int64GreaterThan(count, Int64(0))).Done(), &more, exit);\nBind(&more);\n'
                'GateRef value = FastGetPropertyByIndex(glue, input, count, inputTag);\n'
                'StoreTypedArrayElement(glue, input, count, value, inputTag);')
        result = analyze_unit(unit(wrap(text, owner='BuiltinsTypedArrayStubBuilder').replace(
            '::Filter(', '::CopyWithin(')))
        self.assertEqual([o.kind for o in result.observations], ['matched'])

    def test_same_type_creator_and_exact_buffer_copy_preserve_origin(self):
        text = ('GateRef inputTag = GetObjectType(LoadHClass(input));\n'
                'NewObjectStubBuilder builder(this);\n'
                'GateRef output = builder.NewTypedArraySameType(glue, input, inputTag, count);\n'
                'CallNGCRuntime(glue, RTSTUB_ID(CopyTypedArrayBuffer), '
                '{glue, input, output, Int32(0), Int32(0), count});\n'
                'StoreTypedArrayElement(glue, output, count, input, inputTag);')
        result = analyze_unit(unit(wrap(text)))
        self.assertEqual([o.kind for o in result.observations], ['matched'])

    def test_same_type_creator_requires_token_from_its_exact_exemplar(self):
        text = ('GateRef inputTag = GetObjectType(LoadHClass(input));\n'
                'GateRef unrelatedTag = GetObjectType(LoadHClass(count));\n'
                'NewObjectStubBuilder builder(this);\n'
                'GateRef output = builder.NewTypedArraySameType(glue, input, unrelatedTag, count);\n'
                'StoreTypedArrayElement(glue, output, count, input, inputTag);')
        result = analyze_unit(unit(wrap(text)))
        self.assertEqual([o.kind for o in result.observations], ['unknown'])

    def test_unknown_runtime_call_still_invalidates_same_type_relation(self):
        text = ('GateRef inputTag = GetObjectType(LoadHClass(input));\n'
                'NewObjectStubBuilder builder(this);\n'
                'GateRef output = builder.NewTypedArraySameType(glue, input, inputTag, count);\n'
                'UnknownRuntime(glue, input);\n'
                'StoreTypedArrayElement(glue, output, count, input, inputTag);')
        result = analyze_unit(unit(wrap(text)))
        self.assertEqual([o.kind for o in result.observations], ['unknown'])

    def test_host_gate_ref_rebinding_is_not_a_runtime_phi(self):
        text = PREFIX + FRESH + 'Label change(GetEnvironment()); Label write(GetEnvironment());\n'
        text += 'BRANCH(count, &change, &write); Bind(&change); output = input; Jump(exit);\n'
        text += 'Bind(&write);\n' + SAFE_STORE
        result = analyze_unit(unit(wrap(text)))
        self.assertEqual(classify(result), 'unknown')
        self.assertFalse(any(o.kind == 'matched' for o in result.observations))

    def test_later_function_budget_retains_only_completed_function_evidence(self):
        first = wrap(PREFIX + STORE)
        second = wrap(PREFIX + STORE).replace('::Filter(', '::CopyWithin(')
        result = analyze_unit(unit(first + second), budget=AnalysisBudget(max_steps=6))
        self.assertEqual(result.status, 'limited')
        self.assertEqual(result.file_outcome, 'partial')
        self.assertEqual([(o.symbol.split('::')[-1], o.kind) for o in result.observations], [('Filter', 'candidate')])

    def test_unmodelled_cpp_expression_writes_cannot_leave_type_facts_live(self):
        writes = (
            'tag++;', '++tag;',
            'GateRef scratch = Int32Add((tag = inputTag), Int32(0));',
            'GateRef scratch = Int32Add((output = input), Int32(0));',
            'GateRef other = GetObjectType(LoadHClass(output)), changed = (tag = inputTag);',
            'Label write(GetEnvironment()); BRANCH((tag = inputTag), &write, exit); Bind(&write);',
            'GateRef &alias = tag; alias = inputTag;',
            'GateRef &alias = output; alias = input;',
            'GateRef *address = &tag; *address = inputTag;',
            '(void)(tag = inputTag);', '*(&tag) = inputTag;',
            'Mutator m(tag);', 'Mutator m{tag};', 'auto m = new Mutator(tag);',
            'delete external;',
        )
        for write in writes:
            with self.subTest(expression=write):
                result = analyze_unit(unit(wrap(PREFIX + FRESH + write + '\n' + SAFE_STORE)))
                self.assertEqual(classify(result), 'unknown')
                self.assertFalse(any(o.kind == 'matched' for o in result.observations))

    def test_arrow_allocation_inside_cycle_is_not_a_fresh_identity(self):
        text = PREFIX + 'Label again(GetEnvironment()); Jump(&again); LoopBegin(&again);\n'
        text += 'output = builder->NewTypedArray(glue, input, inputTag, count);\n' + STORE + 'LoopEnd(&again);'
        self.assertEqual(classify(analyze_unit(unit(wrap(text)))), 'unknown')

    def test_unreviewed_constructor_in_detached_block_still_blocks_host_proof(self):
        text = PREFIX + 'Label write(GetEnvironment()); Label detached(GetEnvironment());\n'
        text += 'Jump(&write); Bind(&detached); Mutator m(inputTag); Jump(exit); Bind(&write);\n' + STORE
        result = analyze_unit(unit(wrap(text)))
        self.assertEqual(classify(result), 'unknown')
        self.assertFalse(any(o.kind == 'candidate' for o in result.observations))

    def test_species_creation_invalidates_current_type_but_not_token_origin(self):
        # Source same-object matching needs a fresh sample after species code;
        # distinct-origin candidate evidence retains the immutable token origin.
        code = wrap(PREFIX + 'StoreTypedArrayElement(glue, input, count, input, inputTag);')
        self.assertEqual(classify(analyze_unit(unit(code))), 'unknown')
        self.assertEqual(classify(analyze_unit(unit(wrap(PREFIX + STORE)))), 'candidate')

    def test_two_stale_snapshots_cannot_prove_current_destination_type(self):
        code = PREFIX + FRESH + 'UnknownGlobalEffect();\n'
        code += 'Label write(GetEnvironment()); BRANCH(Int32Equal(inputTag, tag), &write, exit);\n'
        code += 'Bind(&write);\n' + STORE
        self.assertEqual(classify(analyze_unit(unit(wrap(code)))), 'unknown')

    def test_verified_by_value_call_does_not_refresh_old_token(self):
        text = wrap(PREFIX + FRESH + 'GetViewedArrayBuffer(output);\n' + SAFE_STORE +
                    'tag = GetObjectType(LoadHClass(output));\n' + SAFE_STORE)
        result = analyze_unit(unit(text))
        self.assertEqual([o.kind for o in sorted(result.observations, key=lambda o: o.line)], ['unknown', 'matched'])

    def test_readonly_summary_requires_exact_builder_receiver(self):
        text = PREFIX + FRESH + 'BuiltinsArrayStubBuilder helper(this);\n'
        text += 'helper.GetTaggedValueWithElementsKind(glue, input, count);\n' + SAFE_STORE
        self.assertEqual(classify(analyze_unit(unit(wrap(text)))), 'matched')
        foreign = text.replace('helper.GetTaggedValueWithElementsKind', 'foreign.GetTaggedValueWithElementsKind')
        self.assertEqual(classify(analyze_unit(unit(wrap(foreign)))), 'unknown')

    def test_host_builder_write_does_not_mutate_runtime_type(self):
        text = wrap(PREFIX + FRESH + 'builder.SetParameters(glue, count);\n' + SAFE_STORE)
        self.assertEqual(classify(analyze_unit(unit(text))), 'matched')
        self.assertEqual(classify(analyze_unit(unit(text.replace('builder.SetParameters', 'foreign.SetParameters')))), 'unknown')

    def test_unknown_build_profile_does_not_silently_drop_assertions(self):
        result = analyze_unit(unit(wrap(PREFIX + STORE)), model=replace(RuntimeTypeModel(), build_profile='unknown'))
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertIn('model_build_profile_unresolved', result.limitations)

    def test_deleted_special_member_has_no_body_and_cannot_crash_parser(self):
        text = 'struct Unrelated { Unrelated() = default; Unrelated(const Unrelated&) = delete; };\n'
        result = analyze_unit(unit(text + wrap(PREFIX + STORE)))
        self.assertEqual(classify(result), 'candidate')

    def test_global_creator_type_homonym_is_not_a_reviewed_builder(self):
        source = unit('namespace panda::ecmascript::kungfu { struct NewObjectStubBuilder {}; }\n' + wrap(PREFIX + STORE))
        result = analyze_unit(source)
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertFalse(result.observations)

    def test_visible_type_helper_definition_requires_review(self):
        source = unit('GateRef GetObjectType(GateRef x) { return x; }\n' + wrap(PREFIX + STORE))
        result = analyze_unit(source)
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertFalse(result.observations)

    def test_compound_assignment_is_not_token_copy(self):
        result = analyze_unit(unit(wrap(PREFIX +
            'inputTag += GetObjectType(LoadHClass(output));\n' + STORE)))
        self.assertEqual(classify(result), 'unknown')

    def test_fresh_read_does_not_revalidate_an_old_copy(self):
        text = wrap(PREFIX + FRESH + 'GateRef old = tag;\nUnknownGlobalEffect();\n'
                    'tag = GetObjectType(LoadHClass(output));\n' + SAFE_STORE +
                    'StoreTypedArrayElement(glue, output, count, input, old);')
        result = analyze_unit(unit(text))
        self.assertEqual([o.kind for o in result.observations], ['matched', 'unknown'])

    def test_unknown_reference_parameter_cannot_reuse_pre_call_alias(self):
        text = wrap(PREFIX + 'GateRef prior = output; Mutate(output);\n'
                    'GateRef tag = GetObjectType(LoadHClass(output));\n'
                    'StoreTypedArrayElement(glue, prior, count, input, tag);')
        self.assertEqual(classify(analyze_unit(unit(text))), 'unknown')

    def test_host_return_cannot_emit_future_label(self):
        text = wrap(PREFIX + 'Label write(GetEnvironment()); BRANCH(count, &write, exit);\n'
                    'return; Bind(&write);\n' + STORE)
        result = analyze_unit(unit(text))
        self.assertEqual(classify(result), 'unknown')
        self.assertFalse(any(o.kind == 'candidate' for o in result.observations))

    def test_unmodelled_generated_return_does_not_fall_through(self):
        result = analyze_unit(unit(wrap(PREFIX + 'Return(input);\n' + STORE)))
        self.assertEqual(classify(result), 'unknown')
        self.assertFalse(any(o.kind == 'candidate' for o in result.observations))

    def test_other_reviewed_owner_function_uses_actual_symbol(self):
        text = wrap(PREFIX + STORE).replace('::Filter(', '::Set(')
        result = analyze_unit(unit(text))
        self.assertEqual(classify(result), 'candidate')
        self.assertTrue(result.observations[0].symbol.endswith('::Set'))

    def test_multiple_supported_functions_keep_independent_states(self):
        text = wrap(PREFIX + STORE) + wrap(PREFIX + FRESH + SAFE_STORE).replace('::Filter(', '::CopyWithin(')
        result = analyze_unit(unit(text))
        self.assertEqual({(o.symbol.split('::')[-1], o.kind) for o in result.observations},
                         {('Filter', 'candidate'), ('CopyWithin', 'matched')})

    def test_mechanism_matrix(self):
        for case_id, body, expected, why in CASES:
            with self.subTest(case=case_id, reason=why):
                actual = analyze_unit(unit(wrap(body)))
                self.assertEqual(classify(actual), expected, actual.to_dict())
                if expected == 'unknown':
                    self.assertFalse(any(o.kind in ('matched', 'unreachable') for o in actual.observations),
                                     'Unknown control/effects must not imply safe or unreachable.')

    def test_shadowed_equality_macro_is_not_admitted(self):
        text = '#define Int32Equal(a,b) true\n' + wrap(PREFIX + GUARD + STORE)
        result = analyze_unit(unit(text))
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertFalse(result.observations)

    def test_unknown_loop_never_upgrades_file_coverage(self):
        _, body, _, _ = next(c for c in CASES if c[0] == 'G22')
        result = analyze_unit(unit(wrap(body)))
        self.assertNotEqual(result.file_outcome, 'complete')

    def test_budget_after_multiple_paths_discards_truncated_candidates(self):
        text = wrap(PREFIX + STORE + 'Label next(GetEnvironment()); Jump(&next); Bind(&next); Jump(exit);')
        result = analyze_unit(unit(text), budget=AnalysisBudget(max_steps=4))
        self.assertEqual(result.status, 'limited')
        self.assertFalse(result.observations)


if __name__ == '__main__':
    unittest.main()

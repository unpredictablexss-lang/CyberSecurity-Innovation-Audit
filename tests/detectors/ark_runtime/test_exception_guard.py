"""Boundary and pinned-source tests for the bounded allocation exception guard."""
from dataclasses import replace
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import subprocess
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.ark_runtime.detector import ArkRuntimeTypeSafetyDetector
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from src.ohscanner.detectors.ark_runtime.exception_guard import analyze_exception_guard
from src.ohscanner.detectors.ark_runtime.model import (
    EXCEPTION_GUARD_RULE_ID, RuntimeTypeModel, OWNER,
)
from src.ohscanner.fixture import snapshot_digest
from src.parser.ast import parse_source
from .support import case, unit, wrap, PREFIX


class ExceptionGuardSyntheticTests(unittest.TestCase):
    def test_missing_exception_guard_is_candidate(self):
        source = unit(wrap(PREFIX + 'GateRef klass = GetObjectType(LoadHClass(glue, output));'))
        result = analyze_exception_guard(source)
        self.assertEqual(result.file_outcome, 'complete')
        self.assertEqual([item.kind for item in result.observations], ['candidate'])
        self.assertEqual(result.observations[0].reason,
                         'allocation_result_hclass_read_on_pending_exception_path')

    def test_exception_return_before_use_suppresses_candidate(self):
        body = (PREFIX +
                'Label exception(GetEnvironment()); Label normal(GetEnvironment()); Label exit(GetEnvironment());\n'
                'BRANCH(HasPendingException(glue), &exception, &normal);\n'
                'Bind(&exception); result->WriteVariable(Exception()); Jump(&exit);\n'
                'Bind(&normal); GateRef klass = GetObjectType(LoadHClass(glue, output)); Jump(&exit);\n'
                'Bind(&exit);')
        result = analyze_exception_guard(unit(wrap(body)))
        self.assertEqual(result.file_outcome, 'complete')
        self.assertEqual([item.kind for item in result.observations], ['matched'])

    def test_pending_exception_check_on_other_glue_is_not_accepted(self):
        body = (PREFIX +
                'Label exception(GetEnvironment()); Label normal(GetEnvironment()); Label exit(GetEnvironment());\n'
                'BRANCH(HasPendingException(input), &exception, &normal);\n'
                'Bind(&exception); result->WriteVariable(Exception()); Jump(&exit);\n'
                'Bind(&normal); GateRef klass = GetObjectType(LoadHClass(glue, output)); Jump(&exit);\n'
                'Bind(&exit);')
        result = analyze_exception_guard(unit(wrap(body)))
        self.assertFalse(any(item.kind == 'matched' for item in result.observations))
        self.assertTrue(result.limitations)

    def test_reassigned_gate_ref_is_not_treated_as_allocation_result(self):
        source = unit(wrap(PREFIX + 'output = input;\nGateRef klass = GetObjectType(LoadHClass(glue, output));'))
        result = analyze_exception_guard(source)
        self.assertEqual([item.kind for item in result.observations], ['unknown'])
        self.assertIn('allocation_result_gate_ref_reassigned', result.limitations)

    def test_load_hclass_signature_mismatch_is_unknown(self):
        source = unit(wrap(PREFIX + 'GateRef klass = GetObjectType(LoadHClass(output));'))
        result = analyze_exception_guard(source)
        self.assertEqual([item.kind for item in result.observations], ['unknown'])
        self.assertIn('load_hclass_signature_or_binding_mismatch', result.limitations)

    def test_unmodeled_effect_fails_closed_as_unknown(self):
        body = PREFIX + 'UnreviewedOperation(glue);\nGateRef klass = GetObjectType(LoadHClass(glue, output));'
        result = analyze_exception_guard(unit(wrap(body)))
        self.assertFalse(any(item.kind == 'candidate' for item in result.observations))
        self.assertTrue(result.limitations)

    def test_sensitive_read_requires_exact_wrapper_expression(self):
        for expression in (
            'Wrap(GetObjectType(LoadHClass(glue, output)))',
            'GetObjectType(LoadHClass(glue, output) + MaybeRaise(glue))',
        ):
            with self.subTest(expression=expression):
                body = PREFIX + 'GateRef klass = ' + expression + ';'
                result = analyze_exception_guard(unit(wrap(body)))
                self.assertEqual([item.kind for item in result.observations], ['unknown'])
                self.assertIn('load_hclass_signature_or_binding_mismatch', result.limitations)

    def test_nested_call_in_declaration_fails_closed_as_unknown(self):
        body = PREFIX + 'GateRef side = MaybeRaise(glue);\nGateRef klass = GetObjectType(LoadHClass(glue, output));'
        result = analyze_exception_guard(unit(wrap(body)))
        self.assertEqual([item.kind for item in result.observations], ['unknown'])
        self.assertIn('unmodeled_effect_before_exception_guard', result.limitations)

    def test_nested_call_in_expression_fails_closed_as_unknown(self):
        body = PREFIX + 'Consume(MaybeRaise(glue));\nGateRef klass = GetObjectType(LoadHClass(glue, output));'
        result = analyze_exception_guard(unit(wrap(body)))
        self.assertEqual([item.kind for item in result.observations], ['unknown'])
        self.assertIn('unmodeled_effect_before_exception_guard', result.limitations)

    def test_missing_expected_caller_keeps_candidate_partial(self):
        source = unit(wrap(PREFIX + 'GateRef klass = GetObjectType(LoadHClass(glue, output));'))
        result = analyze_exception_guard(
            source, caller_names=(OWNER + '::Filter', OWNER + '::Map'))
        self.assertEqual([item.kind for item in result.observations], ['candidate'])
        self.assertEqual(result.file_outcome, 'partial')
        self.assertIn('expected_exception_guard_caller_missing:Map', result.limitations)

    def test_budget_exhaustion_does_not_emit_candidate(self):
        from src.ohscanner.detectors.ark_runtime.model import AnalysisBudget
        source = unit(wrap(PREFIX + 'GateRef klass = GetObjectType(LoadHClass(glue, output));'))
        result = analyze_exception_guard(source, budget=AnalysisBudget(max_steps=0))
        self.assertNotEqual(result.file_outcome, 'complete')
        self.assertFalse(any(item.kind == 'candidate' for item in result.observations))


    def test_fixture_control_matrix_positive_fixed_safe_unrelated_unknown(self):
        source = case('EXC01')
        controls = (
            ('Positive', ('NewTypedArray', 4), ('LoadHClass',), (), 'candidate', 'complete'),
            ('Fixed', ('NewTypedArray', 4), ('LoadHClass',), (), 'matched', 'complete'),
            ('Safe', ('NewTypedArraySameType', 4), ('CopyTypedArrayBuffer',), (), 'matched', 'complete'),
            ('Unrelated', ('NewTypedArray', 4), ('CopyTypedArrayBuffer',), (), None, 'complete'),
            ('Unknown', ('NewTypedArraySameType', 4), ('CopyTypedArrayBuffer',), (), 'unknown', 'partial'),
        )
        for name, creator, effects, throwing, expected, outcome in controls:
            with self.subTest(control=name):
                result = analyze_exception_guard(
                    source, caller_names=(OWNER + '::' + name,),
                    creator_specs=(creator,), effect_names=effects,
                    throwing_names=throwing)
                kinds = [item.kind for item in result.observations]
                if expected is None:
                    self.assertEqual(kinds, [])
                elif expected == 'unknown':
                    self.assertIn('unknown', kinds)
                else:
                    self.assertEqual(kinds, [expected])
                self.assertEqual(result.file_outcome, outcome)

    def test_guard_before_effect_is_matched_and_guard_after_effect_is_candidate(self):
        before = unit(wrap(PREFIX +
            'Label exception(GetEnvironment()); Label normal(GetEnvironment()); Label exit(GetEnvironment());\n'
            'BRANCH(HasPendingException(glue), &exception, &normal);\n'
            'Bind(&exception); result->WriteVariable(Exception()); Jump(&exit);\n'
            'Bind(&normal); GateRef klass = GetObjectType(LoadHClass(glue, output)); Jump(&exit);\n'
            'Bind(&exit);'))
        after = unit(wrap(PREFIX +
            'GateRef klass = GetObjectType(LoadHClass(glue, output));\n'
            'Label exception(GetEnvironment()); Label normal(GetEnvironment()); Label exit(GetEnvironment());\n'
            'BRANCH(HasPendingException(glue), &exception, &normal);\n'
            'Bind(&exception); result->WriteVariable(Exception()); Jump(&exit);\n'
            'Bind(&normal); Jump(&exit);\n'
            'Bind(&exit);'))
        self.assertEqual([item.kind for item in analyze_exception_guard(before).observations], ['matched'])
        self.assertEqual([item.kind for item in analyze_exception_guard(after).observations], ['candidate'])

    def test_potential_throw_helper_requires_guard_before_external_effect(self):
        body = PREFIX + 'MaybeRaise(glue);\nresult->WriteVariable(output);'
        result = analyze_exception_guard(
            unit(wrap(body)), creator_specs=(), effect_names=('WriteVariable',),
            throwing_names=('MaybeRaise',))
        self.assertEqual([item.kind for item in result.observations], ['candidate'])

        fixed = PREFIX + (
            'MaybeRaise(glue);\n'
            'Label exception(GetEnvironment()); Label normal(GetEnvironment()); Label exit(GetEnvironment());\n'
            'BRANCH(HasPendingException(glue), &exception, &normal);\n'
            'Bind(&exception); result->WriteVariable(Exception()); Jump(&exit);\n'
            'Bind(&normal); result->WriteVariable(output); Jump(&exit);\n'
            'Bind(&exit);')
        result = analyze_exception_guard(
            unit(wrap(fixed)), creator_specs=(), effect_names=('WriteVariable',),
            throwing_names=('MaybeRaise',))
        self.assertEqual([item.kind for item in result.observations], ['matched'])

    def test_unknown_effect_fails_closed_for_potential_throw_helper(self):
        body = PREFIX + 'MaybeRaise(glue);\nUnreviewedOperation(glue);\nresult->WriteVariable(output);'
        result = analyze_exception_guard(
            unit(wrap(body)), creator_specs=(), effect_names=('WriteVariable',),
            throwing_names=('MaybeRaise',))
        self.assertEqual([item.kind for item in result.observations], ['unknown'])
        self.assertIn('unmodeled_effect_before_exception_guard', result.limitations)

    def test_branch_and_loop_paths_keep_local_candidate_or_guard_match(self):
        branch = unit(wrap(PREFIX +
            'Label guarded(GetEnvironment()); Label unguarded(GetEnvironment()); Label exit(GetEnvironment());\n'
            'BRANCH(count, &guarded, &unguarded);\n'
            'Bind(&guarded); Label exception(GetEnvironment()); Label normal(GetEnvironment());\n'
            'BRANCH(HasPendingException(glue), &exception, &normal);\n'
            'Bind(&exception); result->WriteVariable(Exception()); Jump(&exit);\n'
            'Bind(&normal); GateRef klass = GetObjectType(LoadHClass(glue, output)); Jump(&exit);\n'
            'Bind(&unguarded); GateRef other = GetObjectType(LoadHClass(glue, output)); Jump(&exit);\n'
            'Bind(&exit);'))
        self.assertEqual([item.kind for item in analyze_exception_guard(branch).observations], ['candidate'])

        loop = unit(wrap(PREFIX +
            'Label loop(GetEnvironment()); Label body(GetEnvironment()); Label done(GetEnvironment());\n'
            'Label exception(GetEnvironment()); Label normal(GetEnvironment());\n'
            'LoopBegin(&loop); BRANCH(count, &body, &done);\n'
            'Bind(&body); BRANCH(HasPendingException(glue), &exception, &normal);\n'
            'Bind(&exception); result->WriteVariable(Exception()); Jump(&done);\n'
            'Bind(&normal); GateRef klass = GetObjectType(LoadHClass(glue, output)); Jump(&loop);\n'
            'Bind(&done);'))
        self.assertEqual([item.kind for item in analyze_exception_guard(loop).observations], ['matched'])

    def test_zero_length_return_path_is_unknown_not_safe(self):
        source = case('EXC01')
        result = analyze_exception_guard(
            source, caller_names=(OWNER + '::Unknown',),
            creator_specs=(('NewTypedArraySameType', 4),),
            effect_names=('CopyTypedArrayBuffer',))
        self.assertIn('unknown', [item.kind for item in result.observations])
        self.assertIn('result_return_before_modeled_effect_order_unknown', result.limitations)
        self.assertEqual(result.file_outcome, 'partial')

    def test_historical_missing_guard_mechanism_regression(self):
        for caller in ('Filter', 'Map'):
            with self.subTest(caller=caller):
                body = PREFIX + 'GateRef klass = GetObjectType(LoadHClass(glue, output));'
                source = unit(wrap(body).replace('::Filter(', '::' + caller + '('))
                result = analyze_exception_guard(source, caller_names=(OWNER + '::' + caller,))
                self.assertEqual([item.kind for item in result.observations], ['candidate'])
                fixed = unit(wrap(PREFIX +
                    'Label exception(GetEnvironment()); Label normal(GetEnvironment()); Label exit(GetEnvironment());\n'
                    'BRANCH(HasPendingException(glue), &exception, &normal);\n'
                    'Bind(&exception); result->WriteVariable(Exception()); Jump(&exit);\n'
                    'Bind(&normal); GateRef klass = GetObjectType(LoadHClass(glue, output)); Jump(&exit);\n'
                    'Bind(&exit);').replace('::Filter(', '::' + caller + '('))
                fixed_result = analyze_exception_guard(fixed, caller_names=(OWNER + '::' + caller,))
                self.assertEqual([item.kind for item in fixed_result.observations], ['matched'])


@unittest.skipUnless(os.environ.get('OHSCANNER_ARK_REPO'),
                     'Pinned Ark Git store not supplied; no implicit fetch')
class ExceptionGuardHistoricalTests(unittest.TestCase):
    commits = (
        ('c758818dbfd0b146a908d43d21f6ca1706c33783',
         '857ad416bc102fcd5d462e9702d2ba7c51f29b6d',
         '984e45f2b6ea652c412437be03dda4189549afe4cf77c95713cf0d0c5d361db9',
         'candidate'),
        ('81ca57487d04ea30cd11c271e86494a4e130f43e',
         '3b9de9d915d767d7a67316145451da2446162884',
         '4684a1587519e7d141f181b595317db489991a3908e1f1b4ef67513c25d9efd0',
         'matched'),
    )
    path = 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp'

    @classmethod
    def setUpClass(cls):
        repo = os.environ.get('OHSCANNER_ARK_REPO')
        if repo:
            for commit, *_ in cls.commits:
                if subprocess.run(['git', '-C', repo, 'cat-file', '-e', commit + '^{commit}'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
                    raise unittest.SkipTest('Historical exception-guard Git objects are absent from supplied component store')

    def test_exact_parent_and_fixed_source_through_registered_adapter(self):
        repo_path = os.environ['OHSCANNER_ARK_REPO']
        for commit, expected_blob, expected_sha, expected_kind in self.commits:
            with self.subTest(commit=commit):
                content = subprocess.check_output(
                    ['git', '-C', repo_path, 'show', commit + ':' + self.path])
                blob = sha1(b'blob ' + str(len(content)).encode('ascii') + bytes((0,)) + content).hexdigest()
                source_sha = sha256(content).hexdigest()
                self.assertEqual(blob, expected_blob)
                self.assertEqual(source_sha, expected_sha)
                text = content.decode('utf-8')
                index = parse_source(text, 'cpp')
                source = SourceUnit(self.path, 'cpp', text, source_sha, index.parse_status,
                                    tuple(json.dumps(item, sort_keys=True) for item in index.parse_issues))
                model = RuntimeTypeModel()
                units = (source,)
                request = ScanRequest(
                    'ark-runtime-historical', model.source_repository, commit,
                    snapshot_digest(units), 'current-component:' + model.source_repository,
                    provenance='git_object', profile_id='light-ast')
                context = ScanContext(request, units, {
                    'ast': {self.path: dict(index.to_dict(), parse_status=index.parse_status)},
                    'source_blob_oid': {self.path: blob},
                })
                registry = DetectorRegistry()
                registry.register(ArkRuntimeTypeSafetyDetector(model=model))
                reports, coverage = run_all_with_coverage(context, registry)
                run = reports[0]
                findings = [item for item in run.diagnostics if item.rule_id == EXCEPTION_GUARD_RULE_ID]
                self.assertEqual([item.message.split(':', 1)[0] for item in findings],
                                 ['Candidate only', 'Candidate only'] if expected_kind == 'candidate' else [])
                if expected_kind == 'candidate':
                    self.assertEqual(run.status, 'blocked')
                    self.assertEqual(findings[0].source_sha256, expected_sha)
                    self.assertEqual(coverage['detectors']['ohscanner.ark.runtime.type_safety']['coverage_counts']['partial'], 1)
                    self.assertEqual(findings[0].candidate_cwe, None)
                else:
                    self.assertFalse(findings)
                    self.assertEqual(run.status, 'blocked')
                    self.assertEqual(coverage['detectors']['ohscanner.ark.runtime.type_safety']['coverage_counts']['partial'], 1)


if __name__ == '__main__':
    unittest.main()

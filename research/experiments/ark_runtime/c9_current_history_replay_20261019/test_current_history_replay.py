from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

WORKTREE = Path(__file__).resolve().parents[4]
if str(WORKTREE) not in sys.path:
    sys.path.insert(0, str(WORKTREE))

from research.experiments.ark_runtime.c9_current_history_replay_20261019.replay import (
    CASES,
    classify,
    dependency_inventory,
    raw_rule_result,
    read_bound_source,
)
from src.ohscanner.contracts import SourceUnit
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.exception_guard import analyze_exception_guard
from src.ohscanner.detectors.ark_runtime.model import AnalysisBudget, RuntimeTypeModel
from src.parser.ast import parse_source

TARGET = 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp'
OWNER = 'BuiltinsTypedArrayStubBuilder'
NAMESPACE = 'panda::ecmascript::kungfu'

PREFIX = (
    'GateRef inputTag = GetObjectType(LoadHClass(input));\n'
    'NewObjectStubBuilder builder(this);\n'
    'GateRef output = builder.NewTypedArray(glue, input, inputTag, count);\n'
)


def unit(text: str) -> SourceUnit:
    index = parse_source(text, 'cpp')
    return SourceUnit(
        'src/typedarray.cpp',
        'cpp',
        text,
        hashlib.sha256(text.encode()).hexdigest(),
        index.parse_status,
        tuple(json.dumps(item, sort_keys=True) for item in index.parse_issues),
    )


def wrap(body: str, owner: str = OWNER, namespace: str = NAMESPACE) -> str:
    return (
        'namespace ' + namespace + ' {\nvoid ' + owner + '::Filter('
        'GateRef glue, GateRef input, GateRef count, Variable *result, '
        'Label *exit, Label *slowPath) {\n' + body + '\n}\n}\n'
    )


@unittest.skipUnless(os.environ.get('OHSCANNER_ARK_REPO'),
                     'Pinned Ark Git store not supplied; no implicit fetch')
class ExactHistoryReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(os.environ['OHSCANNER_ARK_REPO'])

    def result_for(self, case):
        identity, source, _ = read_bound_source(
            self.repo,
            case['commit'],
            TARGET,
            case['expected_blob'],
            case['expected_sha256'],
        )
        from research.experiments.ark_runtime.c9_current_history_replay_20261019.replay import source_unit

        parsed, _ = source_unit(source)
        return identity, raw_rule_result(
            case['rule_id'], parsed, RuntimeTypeModel(), AnalysisBudget())

    def test_exact_source_identities_match_model_bindings(self):
        for case in CASES:
            with self.subTest(case=case['case_id']):
                identity, _, _ = read_bound_source(
                    self.repo,
                    case['commit'],
                    TARGET,
                    case['expected_blob'],
                    case['expected_sha256'],
                )
                self.assertEqual(identity['tree'], case['expected_tree'])
                self.assertEqual(identity['blob_oid'], case['expected_blob'])
                self.assertEqual(identity['source_sha256'], case['expected_sha256'])

    def test_type_origin_known_parent_gap_is_minimized_as_unknown_not_hit(self):
        _, result = self.result_for(CASES[0])
        self.assertEqual(classify(result), 'unknown')
        self.assertFalse(any(item['kind'] == 'candidate' for item in result['observations']))
        self.assertTrue(any(
            item['symbol'].endswith('::Filter')
            and item['reason'] == 'type_fact_invalidated_by_call'
            for item in result['observations']
        ))

    def test_type_origin_fixed_source_is_also_unknown_not_a_clean_miss(self):
        _, result = self.result_for(CASES[1])
        self.assertEqual(classify(result), 'unknown')
        self.assertFalse(any(item['kind'] == 'candidate' for item in result['observations']))

    def test_exception_guard_known_parent_hits_filter_and_map(self):
        _, result = self.result_for(CASES[2])
        self.assertEqual(classify(result), 'hit')
        self.assertEqual(
            {item['symbol'].split('::')[-1] for item in result['observations']},
            {'Filter', 'Map'},
        )
        self.assertTrue(all(item['kind'] == 'candidate' for item in result['observations']))

    def test_exception_guard_fixed_source_is_miss_with_two_guard_matches(self):
        _, result = self.result_for(CASES[3])
        self.assertEqual(classify(result), 'miss')
        self.assertEqual([item['kind'] for item in result['observations']], ['matched', 'matched'])

    def test_required_missing_dependency_fails_closed(self):
        inventory = dependency_inventory(self.repo, RuntimeTypeModel())
        self.assertEqual(inventory['required_gate'], 'blocked_missing_or_mismatched_dependency')
        missing = [
            item for item in inventory['required_execution_dependencies']
            if item['status'] != 'available'
        ]
        self.assertTrue(missing)
        self.assertTrue(all(
            item['expected_blob'] == '05dda56de74949f07a241942be6465beaf94b52a'
            for item in missing
        ))


class PositiveFixedSafeUnrelatedUnknownControls(unittest.TestCase):
    def test_type_origin_positive_fixed_safe_unrelated_unknown(self):
        positive = analyze_unit(unit(wrap(PREFIX + (
            'StoreTypedArrayElement(glue, output, count, input, inputTag);'
        ))))
        self.assertEqual(classify(positive), 'hit')

        fixed = analyze_unit(unit(wrap(PREFIX + (
            'GateRef outputTag = GetObjectType(LoadHClass(output));\n'
            'StoreTypedArrayElement(glue, output, count, input, outputTag);'
        ))))
        self.assertEqual(classify(fixed), 'miss')
        self.assertEqual([item.kind for item in fixed.observations], ['matched'])

        safe = analyze_unit(unit(wrap(PREFIX + (
            'GateRef outputTag = GetObjectType(LoadHClass(output));\n'
            'StoreTypedArrayElement(glue, output, count, input, outputTag);'
        ))))
        self.assertEqual(classify(safe), 'miss')

        unrelated = analyze_unit(unit(wrap(
            PREFIX + 'StoreTypedArrayElement(glue, output, count, input, inputTag);',
            namespace='unrelated',
        )))
        self.assertEqual(classify(unrelated), 'not_analyzed')

        unknown = analyze_unit(unit(wrap(PREFIX + (
            'UnreviewedOperation(glue);\n'
            'StoreTypedArrayElement(glue, output, count, input, inputTag);'
        ))))
        self.assertEqual(classify(unknown), 'unknown')
        self.assertFalse(any(item.kind == 'candidate' for item in unknown.observations))

    def test_exception_guard_positive_fixed_safe_unrelated_unknown(self):
        positive = analyze_exception_guard(unit(wrap(
            PREFIX + 'GateRef klass = GetObjectType(LoadHClass(glue, output));'
        )))
        self.assertEqual(classify(positive), 'hit')

        guarded_body = (
            PREFIX +
            'Label exception(GetEnvironment()); Label normal(GetEnvironment()); Label exit(GetEnvironment());\n'
            'BRANCH(HasPendingException(glue), &exception, &normal);\n'
            'Bind(&exception); result->WriteVariable(Exception()); Jump(&exit);\n'
            'Bind(&normal); GateRef klass = GetObjectType(LoadHClass(glue, output)); Jump(&exit);\n'
            'Bind(&exit);'
        )
        fixed = analyze_exception_guard(unit(wrap(guarded_body)))
        safe = analyze_exception_guard(unit(wrap(guarded_body)))
        self.assertEqual(classify(fixed), 'miss')
        self.assertEqual(classify(safe), 'miss')

        unrelated = analyze_exception_guard(unit(wrap(
            PREFIX + 'GateRef klass = GetObjectType(LoadHClass(glue, output));',
            owner='Unrelated',
        )))
        self.assertEqual(classify(unrelated), 'not_analyzed')

        unknown = analyze_exception_guard(unit(wrap(
            PREFIX + 'output = input;\nGateRef klass = GetObjectType(LoadHClass(glue, output));'
        )))
        self.assertEqual(classify(unknown), 'unknown')
        self.assertFalse(any(item.kind == 'candidate' for item in unknown.observations))

    def test_status_vocabulary_is_explicit(self):
        observed = set()
        samples = (
            analyze_unit(unit(wrap(PREFIX + (
                'StoreTypedArrayElement(glue, output, count, input, inputTag);'
            )))),
            analyze_unit(unit(wrap(PREFIX + (
                'GateRef outputTag = GetObjectType(LoadHClass(output));\n'
                'StoreTypedArrayElement(glue, output, count, input, outputTag);'
            )))),
            analyze_unit(unit(wrap(PREFIX + (
                'UnreviewedOperation(glue);\n'
                'StoreTypedArrayElement(glue, output, count, input, inputTag);'
            )))),
            analyze_unit(unit(wrap(
                PREFIX + 'StoreTypedArrayElement(glue, output, count, input, inputTag);',
                namespace='unrelated',
            ))),
        )
        observed.update(classify(item) for item in samples)
        self.assertEqual(observed, {'hit', 'miss', 'unknown', 'not_analyzed'})


if __name__ == '__main__':
    unittest.main()

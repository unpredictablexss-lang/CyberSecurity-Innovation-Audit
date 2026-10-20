"""Same-receiver type validation must dominate backing-buffer access."""
import os
import subprocess
import unittest

from src.ohscanner.detectors.ark_runtime.receiver_guard import analyze_receiver_guard
from src.ohscanner.detectors.ark_runtime.model import OWNER
from .support import unit, wrap


class ReceiverGuardTests(unittest.TestCase):
    def test_buffer_read_before_typedarray_guard_is_candidate(self):
        body = ("Label exists(GetEnvironment()); Label typed(GetEnvironment());\n"
                "BRANCH(TaggedIsUndefinedOrNull(input), slowPath, &exists); Bind(&exists);\n"
                "GateRef buffer = GetViewedArrayBuffer(input);\n"
                "GateRef inputTag = GetObjectType(LoadHClass(input));\n"
                "BRANCH(IsFastTypeArray(inputTag), &typed, slowPath); Bind(&typed);")
        result = analyze_receiver_guard(unit(wrap(body)))
        self.assertEqual([item.kind for item in result.observations], ['candidate'])
        self.assertEqual(result.observations[0].reason,
                         'backing_buffer_read_not_dominated_by_receiver_type_guard')

    def test_successful_same_receiver_guard_dominates_buffer_read(self):
        body = ("Label exists(GetEnvironment()); Label typed(GetEnvironment());\n"
                "BRANCH(TaggedIsUndefinedOrNull(input), slowPath, &exists); Bind(&exists);\n"
                "GateRef inputTag = GetObjectType(LoadHClass(input));\n"
                "BRANCH(IsFastTypeArray(inputTag), &typed, slowPath); Bind(&typed);\n"
                "GateRef buffer = GetViewedArrayBuffer(input);")
        result = analyze_receiver_guard(unit(wrap(body)))
        self.assertEqual([item.kind for item in result.observations], ['matched'])

    def test_negated_typedarray_predicate_does_not_protect_true_branch(self):
        body = ("Label typed(GetEnvironment());\n"
                "BRANCH(!IsTypedArray(input), &typed, slowPath); Bind(&typed);\n"
                "GateRef buffer = GetViewedArrayBuffer(input);")
        result = analyze_receiver_guard(unit(wrap(body)))
        self.assertEqual([item.kind for item in result.observations], ['unknown'])
        self.assertIn('receiver_type_guard_not_resolved', result.limitations)

    def test_direct_positive_typedarray_predicate_is_supported(self):
        body = ("Label typed(GetEnvironment());\n"
                "BRANCH(IsTypedArray(input), &typed, slowPath); Bind(&typed);\n"
                "GateRef buffer = GetViewedArrayBuffer(input);")
        result = analyze_receiver_guard(unit(wrap(body)))
        self.assertEqual([item.kind for item in result.observations], ['matched'])

    def test_compound_predicate_is_not_assumed_to_protect_receiver(self):
        body = ("Label typed(GetEnvironment());\n"
                "BRANCH(IsTypedArray(input) || count, &typed, slowPath); Bind(&typed);\n"
                "GateRef buffer = GetViewedArrayBuffer(input);")
        result = analyze_receiver_guard(unit(wrap(body)))
        self.assertEqual([item.kind for item in result.observations], ['unknown'])

    def test_other_object_guard_does_not_protect_receiver(self):
        body = ("Label typed(GetEnvironment());\n"
                "GateRef inputTag = GetObjectType(LoadHClass(input));\n"
                "BRANCH(IsFastTypeArray(inputTag), &typed, slowPath); Bind(&typed);\n"
                "GateRef buffer = GetViewedArrayBuffer(count);")
        result = analyze_receiver_guard(unit(wrap(body)))
        self.assertEqual([item.kind for item in result.observations], ['unknown'])

    def test_unrenamed_identifier_is_not_a_rule_requirement(self):
        source = wrap(
            "Label checked(GetEnvironment());\n"
            "GateRef runtimeType = GetObjectType(LoadHClass(input));\n"
            "BRANCH(IsFastTypeArray(runtimeType), &checked, slowPath); Bind(&checked);\n"
            "GateRef backing = GetViewedArrayBuffer(input);")
        result = analyze_receiver_guard(unit(source))
        self.assertEqual([item.kind for item in result.observations], ['matched'])


@unittest.skipUnless(os.environ.get('OHSCANNER_ARK_OFFICIAL_GIT'),
                     'Pinned official Ark Git store not supplied; no implicit fetch')
class ReceiverGuardHistoricalTests(unittest.TestCase):
    repo = 'D:/openHarmonyScanner/tmp/cve-2025-arkruntime-official.git'
    path = 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp'
    pairs = (
        ('c4c52fb57b6e204128e1520340c8e66c8e708981', 'candidate'),
        ('2a70904be0e21a37a666eb00cab49d02068260ea', 'matched'),
    )

    def test_exact_historical_pair(self):
        for commit, expected in self.pairs:
            with self.subTest(commit=commit):
                source = subprocess.check_output(
                    ['git', '--git-dir=' + self.repo, 'show', commit + ':' + self.path]).decode()
                result = analyze_receiver_guard(unit(source, self.path), caller_name=OWNER + '::Filter')
                self.assertEqual(len(result.observations), 1)
                self.assertEqual(result.observations[0].kind, expected)
                # A neighboring historical method is an independent safe
                # variant: it guards thisValue with IsTypedArray before access.
                safe = analyze_receiver_guard(
                    unit(source, self.path), caller_name=OWNER + '::LastIndexOf')
                self.assertEqual([item.kind for item in safe.observations], ['matched'])


if __name__ == '__main__':
    unittest.main()

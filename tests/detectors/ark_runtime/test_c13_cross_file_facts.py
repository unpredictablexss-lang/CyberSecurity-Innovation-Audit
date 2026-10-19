from dataclasses import replace
from hashlib import sha1, sha256
import unittest

from src.ohscanner.detectors.ark_runtime.cross_file_facts import build_cross_file_facts
from src.ohscanner.detectors.ark_runtime.detector import ArkRuntimeTypeSafetyDetector
from src.ohscanner.detectors.ark_runtime.model import (
    EXCEPTION_GUARD_RULE_ID, INDEX_BOUNDS_RULE_ID, LENGTH_NARROWING_RULE_ID,
    NATIVE_EXCEPTION_RULE_ID, RECEIVER_TYPE_GUARD_RULE_ID, RULE_ID,
    RUNTIME_EXCEPTION_RULE_ID, SIZE_OVERFLOW_RULE_ID, RuntimeTypeModel,
)
from src.ohscanner.detectors.ark_runtime.syntax import parse_functions
from .support import context, unit, wrap, PREFIX


ROOT = 'tests/detectors/ark_runtime/fixtures/c13_cross_file_facts'


def source(text, path):
    return unit(text, path)


def first_function(text):
    return parse_functions(text.encode('utf-8'))[1][0]


def blob(text):
    raw = text.encode('utf-8')
    return sha1(b'blob ' + str(len(raw)).encode('ascii') + bytes((0)) + raw).hexdigest()


def bound_context(units, rule_id, target_path):
    units = tuple(sorted(units, key=lambda item: item.path))
    target = next(item for item in units if item.path == target_path)
    ctx = context(units)
    binding = ('a' * 40, target.path, blob(target.text), target.sha256)
    field = {
        RULE_ID: 'target_bindings',
        EXCEPTION_GUARD_RULE_ID: 'exception_guard_bindings',
        RECEIVER_TYPE_GUARD_RULE_ID: 'receiver_guard_bindings',
        SIZE_OVERFLOW_RULE_ID: 'size_overflow_bindings',
        LENGTH_NARROWING_RULE_ID: 'length_narrowing_bindings',
        INDEX_BOUNDS_RULE_ID: 'index_bounds_bindings',
        RUNTIME_EXCEPTION_RULE_ID: 'runtime_exception_bindings',
        NATIVE_EXCEPTION_RULE_ID: 'native_exception_bindings',
    }[rule_id]
    overrides = {
        'source_repository': 'fixture/ark-runtime',
        'target_bindings': (), 'exception_guard_bindings': (), 'receiver_guard_bindings': (),
        'size_overflow_bindings': (), 'length_narrowing_bindings': (),
        'index_bounds_bindings': (), 'runtime_exception_bindings': (),
        'native_exception_bindings': (), 'source_dependencies': (),
        field: (binding,),
    }
    model = replace(RuntimeTypeModel(), **overrides)
    request = replace(
        ctx.request,
        repository='fixture/ark-runtime',
        commit='a' * 40,
        target_id='current-component:fixture/ark-runtime',
        profile_id='light-ast',
        provenance='git_object',
    )
    facts = dict(ctx.shared_facts)
    facts['source_blob_oid'] = {item.path: blob(item.text) for item in units}
    facts['ast'] = {item.path: __import__('src.parser.ast', fromlist=['parse_source']).parse_source(item.text, 'cpp').to_dict()
                    for item in units}
    return replace(ctx, request=request, shared_facts=facts), model


def production_run(units, rule_id, target_path):
    ctx, model = bound_context(units, rule_id, target_path)
    detector = ArkRuntimeTypeSafetyDetector(model=model)
    selected = detector.select_applicable_units(ctx, ctx.units)
    return detector.detect(ctx, selected)


def candidates(result):
    return tuple(item for item in result.findings if item.rule_id)


class CrossFileFactControls(unittest.TestCase):
    def test_positive_alias_cast_helper_summary_loop_and_include_are_bound(self):
        root = source('#include "ecma_macros.h"\nvoid f(GateRef value) { GateRef alias = (GateRef)value; }\n', ROOT + '/positive.cpp')
        header = source('#define GUARD(x) do { (void)(x); } while (false)\n', ROOT + '/ecma_macros.h')
        helper = source('GateRef Pass(GateRef value) { return value; }\n', ROOT + '/helper.h')
        loop = source('void Generated() { Label head(GetEnvironment()); Label tail(GetEnvironment()); LoopBegin(&head); LoopEnd(&head); }\n', ROOT + '/loop.cpp')
        bundle = build_cross_file_facts((root, header, helper, loop))
        self.assertTrue(bundle.alias_facts)
        self.assertTrue(bundle.cast_facts)
        self.assertTrue(any(item.status == 'identity' for item in bundle.helper_facts))
        self.assertTrue(bundle.loop_backedges)
        self.assertEqual(bundle.include_edges[0].status, 'resolved')
        self.assertTrue(bundle.macro_facts)
        self.assertIn(root.path, [item.path for item in bundle.source_units_for(root.path)])

    def test_fixed_identity_summary_is_bound_without_effect_contract(self):
        fixed = source('GateRef Pass(GateRef value) { return value; }\nvoid Use(GateRef x) { GateRef y = x; }\n', ROOT + '/fixed.cpp')
        bundle = build_cross_file_facts((fixed,))
        self.assertTrue(bundle.alias_facts)
        self.assertTrue(any(item.status == 'identity' for item in bundle.helper_facts))
        self.assertFalse(any(item.status == 'effectful' for item in bundle.helper_facts))

    def test_safe_local_shape_is_not_a_security_verdict(self):
        safe = source('void Safe() { int x = 0; int y = x; }\n', ROOT + '/safe.cpp')
        bundle = build_cross_file_facts((safe,))
        self.assertFalse(bundle.loop_backedges)
        self.assertTrue(bundle.alias_facts)

    def test_unrelated_source_is_not_promoted_to_a_cross_file_fact(self):
        unrelated = source('int Add(int x, int y) { return x + y; }\n', ROOT + '/unrelated.cpp')
        bundle = build_cross_file_facts((unrelated,))
        self.assertFalse(any(item.status in ('identity', 'effectful') for item in bundle.helper_facts))
        self.assertFalse(bundle.loop_backedges)
        self.assertFalse(bundle.include_edges)

    def test_missing_include_and_unresolved_loop_are_explicit_unknown(self):
        root = source('#include "missing.h"\nvoid Generated() { Label head(GetEnvironment()); LoopBegin(&head); LoopEnd(other); }\n', ROOT + '/unknown.cpp')
        bundle = build_cross_file_facts((root,))
        self.assertTrue(any('include_source_unavailable' in item for item in bundle.limitations))
        self.assertTrue(any('loop_backedge' in item or 'unresolved_label' in item for item in bundle.limitations))

    def test_non_canonical_path_is_rejected(self):
        with self.assertRaises(ValueError):
            build_cross_file_facts((source('int x;\n', '../escape.cpp'),))


class ProductionNineShapeRegression(unittest.TestCase):
    def type_origin_units(self, name):
        path = ROOT + '/' + name
        return (source((name and open('tests/detectors/ark_runtime/fixtures/c10_semantics/' + name, encoding='utf-8').read()), path),)

    def run_rule(self, rule_id, units, path):
        return production_run(units, rule_id, path)

    def assert_candidate(self, result):
        self.assertTrue(result.findings, msg=result.to_dict() if hasattr(result, 'to_dict') else result)
        self.assertTrue(any(item.rule_id for item in result.findings))

    def assert_no_candidate(self, result):
        self.assertFalse(result.findings)

    def test_nine_known_ark_shapes_have_production_candidate_and_fixed_controls(self):
        cases = []
        for name in ('cve_2025_24304_parent.cpp', 'ibs5yg_parent.cpp'):
            path = ROOT + '/' + name
            text = open('tests/detectors/ark_runtime/fixtures/c10_semantics/' + name, encoding='utf-8').read()
            fixed = text.replace('NewTypedArray(', 'NewTypedArraySameType(')
            cases.append((RULE_ID, (source(text, path),), path, (source(fixed, path),), path))
        loop_positive = open('tests/detectors/ark_runtime/fixtures/c11_alias_cross_helper/loop_positive.cpp', encoding='utf-8').read()
        loop_fixed = loop_positive.replace('uint32_t byteCount = stride * count;', 'uint64_t byteCount = static_cast<uint64_t>(stride) * count;')
        cases.append((SIZE_OVERFLOW_RULE_ID, (source(loop_positive, ROOT + '/loop_positive.cpp'),), ROOT + '/loop_positive.cpp',
                      (source(loop_fixed, ROOT + '/loop_fixed.cpp'),), ROOT + '/loop_fixed.cpp'))
        exception_parent = wrap(PREFIX + 'GateRef klass = GetObjectType(LoadHClass(glue, output));')
        exception_fixed = wrap(PREFIX + 'Label exception(GetEnvironment()); Label normal(GetEnvironment()); Label exit(GetEnvironment());\nBRANCH(HasPendingException(glue), &exception, &normal);\nBind(&exception); result->WriteVariable(Exception()); Jump(&exit);\nBind(&normal); GateRef klass = GetObjectType(LoadHClass(glue, output)); Jump(&exit);\nBind(&exit);')
        cases.append((EXCEPTION_GUARD_RULE_ID, (source(exception_parent, ROOT + '/exception_parent.cpp'),), ROOT + '/exception_parent.cpp',
                      (source(exception_fixed, ROOT + '/exception_fixed.cpp'),), ROOT + '/exception_fixed.cpp'))
        runtime_parent = '#include "ecma_macros.h"\nclass BuiltinsTypedArray {\nJSTaggedValue Filter(EcmaRuntimeCallInfo *argv) {\nJSThread *thread = argv->GetThread();\nEcmaRuntimeCallInfo *info = EcmaInterpreter::NewRuntimeCallInfo(thread, callback, thisArg, undefined, 3);\nJSTaggedValue callbackOutcome = JSFunction::Call(info);\nbool accepted = callbackOutcome.ToBoolean();\nreturn accepted ? JSTaggedValue::True() : JSTaggedValue::False();\n}\n};\n'
        runtime_fixed = runtime_parent.replace('bool accepted = callbackOutcome.ToBoolean();', 'RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread);\nbool accepted = callbackOutcome.ToBoolean();')
        macro = '#define RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread) do { if ((thread)->HasPendingException()) { return JSTaggedValue::Exception(); } } while (false)\n'
        cases.append((RUNTIME_EXCEPTION_RULE_ID,
                      (source(runtime_parent, ROOT + '/runtime_parent.cpp'), source(macro, ROOT + '/ecma_macros.h')),
                      ROOT + '/runtime_parent.cpp',
                      (source(runtime_fixed, ROOT + '/runtime_fixed.cpp'), source(macro, ROOT + '/ecma_macros.h')),
                      ROOT + '/runtime_fixed.cpp'))
        for rule_id, parent_name, fixed_name in (
                (NATIVE_EXCEPTION_RULE_ID, 'ia_positive.cpp', 'ia_fixed.cpp'),
                (LENGTH_NARROWING_RULE_ID, 'length_positive.cpp', 'length_fixed.cpp'),
                (INDEX_BOUNDS_RULE_ID, 'index_positive.cpp', 'index_fixed.cpp')):
            parent_path = ROOT + '/' + parent_name
            fixed_path = ROOT + '/' + fixed_name
            cases.append((rule_id,
                          (source(open('tests/detectors/ark_runtime/fixtures/c10_gap_rules/' + parent_name, encoding='utf-8').read(), parent_path),),
                          parent_path,
                          (source(open('tests/detectors/ark_runtime/fixtures/c10_gap_rules/' + fixed_name, encoding='utf-8').read(), fixed_path),),
                          fixed_path))
        receiver_parent = wrap('Label exists(GetEnvironment()); Label typed(GetEnvironment());\nBRANCH(TaggedIsUndefinedOrNull(input), slowPath, &exists); Bind(&exists);\nGateRef buffer = GetViewedArrayBuffer(input);\nGateRef inputTag = GetObjectType(LoadHClass(input));\nBRANCH(IsFastTypeArray(inputTag), &typed, slowPath); Bind(&typed);')
        receiver_fixed = wrap('Label exists(GetEnvironment()); Label typed(GetEnvironment());\nBRANCH(TaggedIsUndefinedOrNull(input), slowPath, &exists); Bind(&exists);\nGateRef inputTag = GetObjectType(LoadHClass(input));\nBRANCH(IsFastTypeArray(inputTag), &typed, slowPath); Bind(&typed);\nGateRef buffer = GetViewedArrayBuffer(input);')
        cases.append((RECEIVER_TYPE_GUARD_RULE_ID, (source(receiver_parent, ROOT + '/receiver_parent.cpp'),), ROOT + '/receiver_parent.cpp',
                      (source(receiver_fixed, ROOT + '/receiver_fixed.cpp'),), ROOT + '/receiver_fixed.cpp'))
        self.assertEqual(len(cases), 9)
        for rule_id, parent_units, parent_path, fixed_units, fixed_path in cases:
            with self.subTest(rule=rule_id, parent=parent_path):
                self.assert_candidate(self.run_rule(rule_id, parent_units, parent_path))
            with self.subTest(rule=rule_id, fixed=fixed_path):
                self.assert_no_candidate(self.run_rule(rule_id, fixed_units, fixed_path))


if __name__ == '__main__':
    unittest.main()

"""Bounded macro expansion: its refusal semantics, and what it does to findings.

The expander is ported from the round1 interface line, and the semantics tests are
ported with it, keeping their original expectations.

The integration tests at the bottom answer a different question, and answer it
against the corpus rather than by assumption: does putting a macro-hidden guard
into the interpreted control flow actually change a candidate? The measurement in
`research/experiments/interface/ipc/measure_macro_expansion.py` says that on ten
real components it does not -- none of 12,716 expansions introduced a call the
policy models as an authorization guard, and none of the 314 refused definitions
mentions one either, so the pattern is absent from the corpus rather than hidden
behind a refusal. These tests are what keeps that negative result meaningful: they
prove the mechanism works when the pattern is present, so the corpus result is
"the pattern is absent", not "the wiring is broken".
"""
import hashlib
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface.analysis import Interpreter
from src.ohscanner.detectors.interface.cpp_macros import (catalog_for_units, expand,
                                                          expand_with_catalog, macro_catalog)
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.detectors.interface.models import IpcPolicy

GUARD_HEADER = ('#pragma once\n'
                '#define REQUIRE_PERMISSION(who) if (AccessTokenKit::VerifyAccessToken(who, '
                '"ohos.permission.TEST") != PERMISSION_GRANTED) return -1;\n')

UNGUARDED = '''#define Stub Fixture_macro_guard
#include "common_types.h"

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
StartAbility();
return 0;
}
'''

GUARDED_BY_MACRO = UNGUARDED.replace(
    'StartAbility();',
    'REQUIRE_PERMISSION(IPCSkeleton::GetCallingTokenID());\nStartAbility();')

# `CHECK_ALLOWED` does not use its parameter, so the two-line invocation collapses
# to one line and everything below it shifts up by one in the expanded text. The
# finding must still name the line it was written on.
LINE_SHIFT_SOURCE = '''#define Stub Fixture_line_map
#include "common_types.h"
#define CHECK_ALLOWED(unused) if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), "ohos.permission.TEST") != PERMISSION_GRANTED) return -1;

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
CHECK_ALLOWED(
    0);
StartAbility();
return 0;
}
'''
SHIFTED_CALL_ORIGINAL_LINE = 9


class Unit:
    """Stand-in for a scan unit: the expander and the index read only these fields."""

    def __init__(self, path, text, language='cpp', parse_status='complete'):
        self.path = path
        self.language = language
        self.text = text
        self.parse_status = parse_status


def context(sources):
    units, facts = [], {}
    for path, text in sources:
        index = parse_source(text, language='cpp')
        units.append(SourceUnit(path, 'cpp', text, hashlib.sha256(text.encode()).hexdigest(),
                                index.parse_status))
        facts[path] = index.to_dict()
    units = tuple(units)
    request = ScanRequest('ipc-test', 'fixture/ipc', 'synthetic-ipc-v1', snapshot_digest(units),
                          'current-component:fixture/ipc')
    return ScanContext(request, units, {'ast': facts})


def rules(expand_macros, source=GUARDED_BY_MACRO, policy=None):
    ctx = context((('guard.h', GUARD_HEADER), ('sample.cpp', source)))
    run = IpcInterfaceDetector(policy or IpcPolicy(expand_macros=expand_macros)).detect(ctx, ctx.units)
    return {finding.rule_id for finding in run.findings}


class ExpanderSemanticsTests(unittest.TestCase):
    """Ported expectations: what the expander does, and what it refuses to do."""

    def test_permission_macro_from_header_expands_with_its_source(self):
        result = expand(b"void Handle(int caller) { REQUIRE(caller); Sensitive(); }",
                        {"guard.h": b"#define REQUIRE(who) do { if (!Allowed(who)) return; } while(0)\n"})
        self.assertTrue(result.applied)
        self.assertIn(b"if (!Allowed(caller)) return;", result.source)
        self.assertNotIn(b"REQUIRE", result.source)
        self.assertEqual(result.expansions[0]["definition_locations"][0]["file"], "guard.h")
        self.assertTrue(result.expansions[0]["carries_control_flow"])

    def test_comments_and_strings_are_not_invocations_and_lines_map_back(self):
        source = (b'void Handle(int caller) {\n // REQUIRE(caller);\n'
                  b' const char *s = "REQUIRE(caller)";\n REQUIRE(caller);\n Sensitive();\n}')
        result = expand(source, {"guard.h": b"#define REQUIRE(who) if (!Allowed(who)) {return;}\n"})
        self.assertEqual(len(result.expansions), 1)
        self.assertEqual(result.expansions[0]["original_line"], 4)
        self.assertIn(b"// REQUIRE(caller);", result.source)
        self.assertIn(b'"REQUIRE(caller)"', result.source)

    def test_nested_macros_expand_through_the_round_budget(self):
        result = expand(b"FIRST(x);", {"guard.h": b"#define FIRST(a) SECOND(a)\n#define SECOND(a) Allowed(a)\n"})
        self.assertIn(b"Allowed(x)", result.source)
        self.assertEqual(len(result.expansions), 2)

    def test_a_self_referential_macro_is_refused_not_looped(self):
        result = expand(b"LOOP(x);", {"guard.h": b"#define LOOP(x) LOOP(x)\n"})
        self.assertFalse(result.applied)
        self.assertEqual(result.source, b"LOOP(x);")
        self.assertIn("self_referential_definition", result.unknown)

    def test_a_recursion_that_never_settles_leaves_the_file_as_written(self):
        # A(a) -> B(a) -> A(a). One arbitrary step of an infinite expansion is
        # neither the source nor its expansion, so nothing may be applied.
        result = expand(b"A(x);", {"guard.h": b"#define A(a) B(a)\n#define B(a) A(a)\n"})
        self.assertFalse(result.applied)
        self.assertEqual(result.source, b"A(x);")
        self.assertEqual(result.expansions, ())
        self.assertIn("macro_recursion_or_round_budget_exceeded", result.unknown)

    def test_variadic_and_token_paste_definitions_are_refused(self):
        for definition in (b"#define BAD(x, ...) Allowed(x, __VA_ARGS__)\n", b"#define BAD(x) prefix##x\n"):
            with self.subTest(definition=definition):
                result = expand(b"BAD(x);", {"guard.h": definition})
                self.assertFalse(result.applied)
                self.assertEqual(result.refused[0][1], "variadic_stringify_or_token_paste")

    def test_conflicting_definition_variants_are_refused(self):
        result = expand(b"BAD(x);", {"guard.h": b"#define BAD(x) Allowed(x)\n#define BAD(x) Other(x)\n"})
        self.assertFalse(result.applied)
        self.assertEqual(result.refused[0][1], "ambiguous_definition_variants")

    def test_a_source_local_undef_refuses_the_file(self):
        result = expand(b"#undef BAD\nBAD(x);", {"guard.h": b"#define BAD(x) Allowed(x)\n"})
        self.assertEqual(result.fatal, ("source_local_undef_not_supported",))
        self.assertEqual(result.source, b"#undef BAD\nBAD(x);")

    def test_a_missing_header_does_not_invent_a_guard(self):
        result = expand(b"void Handle(int caller) { REQUIRE(caller); Sensitive(); }", {})
        self.assertFalse(result.applied)
        self.assertEqual(result.expansions, ())

    def test_a_conditional_definition_is_not_assumed_enabled(self):
        result = expand(b"CHECK(x);", {"guard.h": b"#ifdef FEATURE\n#define CHECK(x) Allowed(x)\n#endif\n"})
        self.assertFalse(result.applied)
        self.assertEqual(result.refused[0][1], "conditional_definition_requires_build_profile")

    def test_a_commented_out_define_defines_nothing(self):
        result = expand(b"CHECK(x);", {"guard.h": b"/*\n#define CHECK(x) Allowed(x)\n*/\n"})
        self.assertEqual(result.expansions, ())

    def test_raw_strings_are_an_explicit_refusal(self):
        result = expand(b'const char *p = R"(CHECK(x))";', {})
        self.assertEqual(result.fatal, ("raw_string_tokenization_not_supported",))


class CatalogueTests(unittest.TestCase):
    def test_an_include_guard_is_not_a_build_profile_condition(self):
        catalog = macro_catalog({"guard.h": b"#ifndef GUARD_H\n#define GUARD_H\n"
                                           b"#define CHECK(x) Allowed(x)\n#endif\n"})
        self.assertEqual(catalog["CHECK"][0]["conditional_context"], [])
        self.assertEqual(catalog["GUARD_H"][0]["conditional_context"], [])
        self.assertTrue(expand_with_catalog(b"CHECK(x);", catalog).applied)

    def test_a_feature_flag_inside_an_include_guard_is_still_recorded(self):
        catalog = macro_catalog({"guard.h": b"#ifndef GUARD_H\n#define GUARD_H\n"
                                           b"#ifdef FEATURE\n#define CHECK(x) Allowed(x)\n#endif\n#endif\n"})
        self.assertEqual(catalog["CHECK"][0]["conditional_context"], ["ifdefFEATURE"])
        self.assertFalse(expand_with_catalog(b"CHECK(x);", catalog).applied)

    def test_a_scan_catalogue_tolerates_a_source_local_define(self):
        catalog = macro_catalog({"s.cpp": b"#define LOCAL if (!ok) return;\nvoid f(){ LOCAL DoThing(); }"})
        expansion = expand_with_catalog(b"#define LOCAL if (!ok) return;\nvoid f(){ LOCAL DoThing(); }", catalog)
        self.assertTrue(expansion.applied)
        self.assertIn(b"if (!ok) return;", expansion.source)

    def test_headers_are_catalogued_before_translation_units(self):
        units = [Unit("z.cpp", "#define LATE 1\n"), Unit("a.h", "#define EARLY 1\n")]
        catalog, used, _, truncated = catalog_for_units(units, max_sources=1, max_bytes=1 << 20)
        self.assertEqual(sorted(catalog), ["EARLY"])
        self.assertEqual(used, 1)
        self.assertTrue(truncated)

    def test_the_catalogue_does_not_depend_on_unit_order(self):
        units = [Unit("z.cpp", "#define Z 1\n"), Unit("a.h", "#define A 1\n")]
        self.assertEqual(catalog_for_units(units, 10, 1 << 20)[0],
                         catalog_for_units(list(reversed(units)), 10, 1 << 20)[0])


class IntegrationTests(unittest.TestCase):
    """Does a macro-hidden guard change the candidate set? Prove it does."""

    def test_a_guard_inside_a_macro_suppresses_the_candidate(self):
        self.assertIn("ipc.auth.missing", rules(expand_macros=False))
        self.assertNotIn("ipc.auth.missing", rules(expand_macros=True))

    def test_the_same_source_without_the_macro_still_reports(self):
        # The control for the test above: the header and the expansion are present,
        # the guard is not, and the candidate comes back. Without this, a detector
        # that simply stopped reporting would pass the test above.
        self.assertIn("ipc.auth.missing", rules(expand_macros=True, source=UNGUARDED))

    def test_expansion_does_not_invent_findings(self):
        unguarded = rules(expand_macros=True, source=UNGUARDED)
        baseline = rules(expand_macros=False, source=UNGUARDED)
        self.assertEqual(unguarded, baseline)

    def test_a_finding_names_the_line_it_was_written_on(self):
        policy = IpcPolicy(expand_macros=True,
                           expected_permissions=(('StartAbility', '"ohos.permission.OTHER"'),))
        ctx = context((('sample.cpp', LINE_SHIFT_SOURCE),))
        run = IpcInterfaceDetector(policy).detect(ctx, ctx.units)
        missing = [f for f in run.findings if f.rule_id == "ipc.auth.missing"]
        self.assertEqual([f.line for f in missing], [SHIFTED_CALL_ORIGINAL_LINE])

    def test_expansion_never_turns_a_parseable_file_into_a_partial_one(self):
        for source in (UNGUARDED, GUARDED_BY_MACRO, LINE_SHIFT_SOURCE):
            with self.subTest(source=source[:20]):
                ctx = context((('guard.h', GUARD_HEADER), ('sample.cpp', source)))
                off = Interpreter(ctx.units, IpcPolicy(expand_macros=False))
                on = Interpreter(ctx.units, IpcPolicy(expand_macros=True))
                self.assertLessEqual(sum("Partial source" in s for s in on.limitations),
                                     sum("Partial source" in s for s in off.limitations))

    def test_the_scan_catalogue_never_applies_across_a_conflicting_definition(self):
        # Two headers define the same guard differently. Nothing may be chosen.
        ctx = context((('a.h', '#define CHECK(x) Guard(x)\n'),
                       ('b.h', '#define CHECK(x) Other(x)\n'),
                       ('sample.cpp', 'void f(){ CHECK(1); }')))
        interpreter = Interpreter(ctx.units, IpcPolicy(expand_macros=True))
        self.assertEqual(interpreter.macro_expanded, 0)
        self.assertEqual(interpreter.macro_refusal_reasons.get("ambiguous_definition_variants"), 1)


if __name__ == "__main__":
    unittest.main()

import unittest

from src.ohscanner.detectors.interface.cpp_macros import analyze_with_macros, expand
from tests.detectors.interface.test_cpp_permission import model_for


class CppMacroTests(unittest.TestCase):
    def test_permission_macro_from_header(self):
        source = b"void Handle(int caller) { REQUIRE(caller); Sensitive(); }"
        headers = {"guard.h": b"#define REQUIRE(who) do { if (!Allowed(who)) return; } while(0)\n"}
        result = analyze_with_macros(source, model_for(source), headers)
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["assessment"], "no_uncovered_sink_in_supported_syntax")
        self.assertEqual(result["macro_expansions"][0]["definition_locations"][0]["file"], "guard.h")

    def test_comments_strings_and_line_mapping(self):
        source = b'void Handle(int caller) {\n // REQUIRE(caller);\n const char *s = "REQUIRE(caller)";\n REQUIRE(caller);\n Sensitive();\n}'
        headers = {"guard.h": b"#define REQUIRE(who) if (!Allowed(who)) {return;}\n"}
        result = analyze_with_macros(source, model_for(source), headers)
        self.assertEqual(len(result["macro_expansions"]), 1)
        self.assertEqual(result["macro_expansions"][0]["original_line"], 4)
        self.assertEqual(result["calls"][-1]["line"], 5)

    def test_nested_macros(self):
        result = expand(b"FIRST(x);", {"guard.h": b"#define FIRST(a) SECOND(a)\n#define SECOND(a) Allowed(a)\n"})
        self.assertIn(b"Allowed(x)", result["source"])
        self.assertEqual(len(result["expansions"]), 2)

    def test_recursive_macro_unknown(self):
        self.assertTrue(expand(b"LOOP(x);", {"guard.h": b"#define LOOP(x) LOOP(x)\n"})["unknown"])

    def test_variadic_and_token_paste_unknown(self):
        for definition in (b"#define BAD(x, ...) Allowed(x, __VA_ARGS__)\n", b"#define BAD(x) prefix##x\n"):
            result = expand(b"BAD(x);", {"guard.h": definition})
            self.assertTrue(result["unknown"])

    def test_conflicting_variants_unknown(self):
        self.assertTrue(expand(b"BAD(x);", {"guard.h": b"#define BAD(x) Allowed(x)\n#define BAD(x) Other(x)\n"})["unknown"])

    def test_local_macro_changes_unknown(self):
        self.assertTrue(expand(b"#undef BAD\nBAD(x);", {"guard.h": b"#define BAD(x) Allowed(x)\n"})["unknown"])

    def test_header_missing_does_not_invent_guard(self):
        source = b"void Handle(int caller) { REQUIRE(caller); Sensitive(); }"
        self.assertEqual(analyze_with_macros(source, model_for(source), {})["assessment"], "unknown")

    def test_inactive_conditional_macro_not_assumed_enabled(self):
        self.assertTrue(expand(b"CHECK(x);", {"guard.h": b"#ifdef FEATURE\n#define CHECK(x) Allowed(x)\n#endif\n"})["unknown"])

    def test_comment_cannot_define_macro(self):
        result = expand(b"CHECK(x);", {"guard.h": b"/*\n#define CHECK(x) Allowed(x)\n*/\n"})
        self.assertEqual(result["expansions"], [])

    def test_raw_strings_are_explicit_unknown(self):
        self.assertTrue(expand(b'const char *p = R"(CHECK(x))";', {})["unknown"])

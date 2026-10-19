"""Counterexamples for candidate suppression; no product exploit assertions."""
import unittest

from tests.test_ipc_arkts_js import native_run, needs_grammars, rules, run


@needs_grammars
class GuardSuppressionRegressions(unittest.TestCase):
    def test_path_predicates_that_do_not_cover_the_sink_keep_the_candidate(self):
        cases = (
            "fileIo.openSync(path); if (path.startsWith('/safe/')) {}",
            "if (path.startsWith('/safe/')) console.log(path); fileIo.openSync(path);",
            "if (!path.startsWith('/safe/')) { fileIo.openSync(path); }",
            "if (path.startsWith('/safe/') || enabled) { fileIo.openSync(path); }",
            "// if (path.startsWith('/safe/'))\nfileIo.openSync(path);",
            "const text = \"if (path.startsWith('/safe/'))\"; fileIo.openSync(path);",
            "function other() { if (path.startsWith('/safe/')) return; } fileIo.openSync(path);",
        )
        for body in cases:
            with self.subTest(body=body):
                result = run(("a.js", "function handle(want, enabled) { const path = want.parameters.path; " + body + " }"))
                self.assertIn("ohscanner.js.path_taint", rules(result))

    def test_same_subject_positive_branch_and_early_rejection_are_structural_controls(self):
        for body in (
            "if (path.startsWith('/safe/')) { fileIo.openSync(path); }",
            "if (!path.startsWith('/safe/')) return; fileIo.openSync(path);",
        ):
            with self.subTest(body=body):
                result = run(("a.js", "function handle(want) { const path = want.parameters.path; " + body + " }"))
                self.assertNotIn("ohscanner.js.path_taint", rules(result))

    def test_numeric_guard_on_another_value_does_not_cover_the_native_argument(self):
        body = """import foo from 'libfoo.so';
function handle(want) {
 const size = want.parameters.size;
 const count = want.parameters.count;
 if (count > 0 && count <= 4096) { return foo.setSize(size); }
}"""
        self.assertIn("ohscanner.oh.native_bridge", rules(native_run(body)))

    def test_late_numeric_predicate_does_not_cover_native_call(self):
        body = """import foo from 'libfoo.so';
function handle(want) {
 const size = want.parameters.size;
 foo.setSize(size);
 if (size > 0 && size <= 4096) return;
}"""
        self.assertIn("ohscanner.oh.native_bridge", rules(native_run(body)))

    def test_origin_predicate_that_only_logs_does_not_cover_registration(self):
        body = """function init(url, controller) {
 if (url.startsWith('https://trusted.example/')) console.log(url);
 controller.registerJavaScriptProxy({object: this, name: 'bridge'});
}"""
        self.assertIn("ohscanner.oh.arkts.webview_bridge", rules(run(("a.js", body))))

    def test_predicate_in_another_ability_method_does_not_cover_lifecycle(self):
        body = """export default class EntryAbility extends UIAbility {
 onNewWant(want: Want) { const path = want.parameters.path; fileIo.openSync(path); }
 unrelated(path: string) { if (path.startsWith('/safe/')) return; }
}"""
        result = run(("ability.ts", body))
        self.assertIn("ohscanner.js.path_taint", rules(result))
        self.assertIn("ohscanner.oh.arkts.component_exposure", rules(result))

    def test_reassignment_after_a_guard_keeps_path_candidate(self):
        for body in (
            "if (!path.startsWith('/safe/')) return; path = want.parameters.other; fileIo.openSync(path);",
            "if (path.startsWith('/safe/')) { path = want.parameters.other; fileIo.openSync(path); }",
            "if (path.startsWith('/safe/')) { path = want.parameters.other; } else { return; } fileIo.openSync(path);",
        ):
            with self.subTest(body=body):
                result = run(("a.js", "function f(want) { let path = want.parameters.path; " + body + " }"))
                self.assertIn("ohscanner.js.path_taint", rules(result))

    def test_a_guard_for_one_numeric_parameter_does_not_cover_another(self):
        declaration = "declare module 'libfoo.so' { export function pair(size:number, count:number):void; }"
        body = """import foo from 'libfoo.so';
function handle(want) {
 const size = want.parameters.size;
 const count = want.parameters.count;
 if (size > 0 && size <= 4096) { return foo.pair(size, count); }
}"""
        self.assertIn("ohscanner.oh.native_bridge", rules(native_run(body, declaration)))

    def test_a_nested_function_does_not_inherit_the_outer_guard(self):
        body = """function handle(want) {
 const path = want.parameters.path;
 if (path.startsWith('/safe/')) { function deferred() { fileIo.openSync(want.parameters.path); } }
}"""
        self.assertIn("ohscanner.js.path_taint", rules(run(("a.js", body))))

    def test_an_ability_other_method_sink_is_not_a_lifecycle_candidate(self):
        body = """export default class EntryAbility extends UIAbility {
 onNewWant(want: Want) { console.log(want.parameters); }
 unrelated(want: Want) { fileIo.openSync(want.parameters.path); }
}"""
        result = run(("ability.ts", body))
        self.assertIn("ohscanner.js.path_taint", rules(result))
        self.assertNotIn("ohscanner.oh.arkts.component_exposure", rules(result))

    def test_runner_keeps_candidates_when_shared_frontend_has_not_parsed_js(self):
        from tests.test_ipc_arkts_js import units
        from src.ohscanner.contracts import ScanContext, ScanRequest
        from src.ohscanner.fixture import snapshot_digest
        from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
        from src.ohscanner.detectors.interface.arkts_js import ArkTsJsInterfaceDetector
        source = units(("a.js", "function f(code) { eval(code); }"))
        ctx = ScanContext(ScanRequest("review", "fixture/ipc", "synthetic-ipc-v3",
                          snapshot_digest(source), "current-component:fixture/ipc"), source, {})
        registry = DetectorRegistry()
        registry.register(ArkTsJsInterfaceDetector())
        reports, sidecar = run_all_with_coverage(ctx, registry)
        self.assertEqual(reports[0].status, "completed")
        self.assertEqual(len(reports[0].diagnostics), 1)
        self.assertEqual(reports[0].diagnostics[0].confidence, "unassessed")
        self.assertEqual(reports[0].diagnostics[0].source_sha256, source[0].sha256)
        coverage = sidecar["detectors"]["ohscanner.oh.arkts_js"]
        self.assertEqual(coverage["coverage_counts"]["partial"], 1)
        self.assertEqual(coverage["coverage_counts"]["complete"], 0)
        self.assertTrue(coverage["evidence_obligations"])

    def test_complete_requires_shared_and_private_parse_agreement(self):
        from dataclasses import replace
        from tests.test_ipc_arkts_js import units
        from src.ohscanner.contracts import ScanContext, ScanRequest
        from src.ohscanner.fixture import snapshot_digest
        from src.ohscanner.detectors.interface.arkts_js import ArkTsJsInterfaceDetector
        for text, expected in (
            ("function f(code) { eval(code); }", "complete"),
            ("@Entry\n@Component\nstruct Index { build() { Text('x'); } }", "partial"),
        ):
            with self.subTest(text=text):
                # This control explicitly supplies a shared complete parse;
                # the private grammar still cannot upgrade its own partial tree.
                source = tuple(replace(u, parse_status="complete") for u in units(("a.ts", text)))
                request = ScanRequest("review", "fixture/ipc", "synthetic-ipc-v3",
                                      snapshot_digest(source), "current-component:fixture/ipc")
                result = ArkTsJsInterfaceDetector().detect(ScanContext(request, source, {}), source)
                self.assertEqual(result.file_outcomes, (("a.ts", expected),))

    def test_typescript_grammar_does_not_depend_on_javascript_wheel(self):
        import subprocess
        import sys
        code = """
import sys
sys.modules['tree_sitter_javascript'] = None
from src.ohscanner.detectors.interface.arkts_js import LANGUAGE_MODULE_STATUS, frontend
from src.ohscanner.contracts import SourceUnit
import hashlib
assert LANGUAGE_MODULE_STATUS['js'] == 'missing'
assert LANGUAGE_MODULE_STATUS['ts'] == 'available'
text = 'function f(x: number) { return x; }'
u = SourceUnit('a.ts','ts',text,hashlib.sha256(text.encode()).hexdigest())
assert frontend(u).status == 'complete'
"""
        subprocess.run([sys.executable, "-c", code], check=True)

    def test_string_concatenation_is_not_a_literal_eval_body(self):
        for body in ("eval('prefix' + code + 'suffix');", "new Function('prefix' + code + 'suffix');"):
            with self.subTest(body=body):
                self.assertIn("ohscanner.js.dangerous_eval", rules(run(("a.js", "function f(code) { " + body + " }"))))

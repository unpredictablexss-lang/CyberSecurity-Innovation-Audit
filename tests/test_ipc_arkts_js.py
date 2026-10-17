"""ArkTS/JS frontend: report what parsed, then only claim what was read.

The gap review's B-3 asks for an auditable frontend first. These tests pin the
frontend contract (complete / partial / unsupported) and the paired controls of
the first rule batch. ArkTS `struct` is outside the TypeScript grammar; the
partial status is the honest answer and the tests require it to be reported
rather than hidden.
"""
import hashlib
import unittest

from src.ohscanner.contracts import SourceUnit, ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface.arkts_js import (
    ArkTsJsInterfaceDetector, LANGUAGE_MODULE_STATUS)

# The grammars are optional in the shared environment (requirements are
# owner-managed); without them the detector reports `blocked`, and these tests
# would only restate that. Skip rather than fail CI.
needs_grammars = unittest.skipUnless(
    all(status == "available" for status in LANGUAGE_MODULE_STATUS.values()),
    "tree-sitter javascript/typescript grammars not installed")


def units(*pairs):
    result = []
    for path, text in pairs:
        language = {"js": "js", "ts": "ts", "ets": "arkts"}[path.rsplit(".", 1)[1]]
        result.append(SourceUnit(path, language, text,
                                 hashlib.sha256(text.encode()).hexdigest()))
    return tuple(sorted(result, key=lambda unit: unit.path))


def run(*pairs):
    source_units = units(*pairs)
    request = ScanRequest("ipc-test", "fixture/ipc", "synthetic-ipc-v2",
                          snapshot_digest(source_units), "current-component:fixture/ipc")
    ctx = ScanContext(request, source_units, {})
    result = ArkTsJsInterfaceDetector().detect(ctx, ctx.units)
    assert result.status == "completed", (result.status, result.limitations)
    return result


def rules(result):
    return [finding.rule_id for finding in result.findings]


def note(result, prefix):
    matched = [line for line in result.limitations if line.startswith(prefix)]
    assert len(matched) == 1, result.limitations
    return matched[0]


@needs_grammars
class FrontendTests(unittest.TestCase):
    def test_a_plain_javascript_file_parses_completely(self):
        result = run(("a.js", "function f(x) { return x + 1; }\n"))
        self.assertEqual(result.file_outcomes, (("a.js", "complete"),))

    def test_arkts_struct_is_reported_partial_not_claimed_as_semantics(self):
        text = ("@Entry\n@Component\nstruct Index {\n"
                "  build() { Text('x'); }\n}\n")
        result = run(("page.ets", text))
        self.assertEqual(result.file_outcomes, (("page.ets", "partial"),))
        line = note(result, "ArkTS/JS frontend:")
        self.assertIn("1 partial", line)
        self.assertIn("struct", note(result, "ArkTS `struct`"))

    def test_an_unsupported_language_is_not_silently_zero(self):
        c_unit = SourceUnit("a.c", "c", "int main(void) { return 0; }\n",
                            hashlib.sha256(b"int main(void) { return 0; }\n").hexdigest())
        request = ScanRequest("ipc-test", "fixture/ipc", "synthetic-ipc-v2",
                              snapshot_digest((c_unit,)), "current-component:fixture/ipc")
        result = ArkTsJsInterfaceDetector().detect(
            ScanContext(request, (c_unit,), {}), (c_unit,))
        self.assertEqual(result.status, "blocked")
        self.assertTrue(any("No .js/.ts/.ets unit" in line for line in result.limitations))


@needs_grammars
class DangerousEvalTests(unittest.TestCase):
    def test_eval_with_a_dynamic_argument_is_a_candidate(self):
        result = run(("a.js", "function f(code) { eval(code); }\n"))
        self.assertIn("ohscanner.js.dangerous_eval", rules(result))
        self.assertEqual(result.findings[0].candidate_cwe, "CWE-95")

    def test_eval_with_a_literal_is_not_a_candidate(self):
        result = run(("a.js", "function f() { eval('1 + 1'); }\n"))
        self.assertNotIn("ohscanner.js.dangerous_eval", rules(result))

    def test_new_function_with_a_variable_body_is_a_candidate(self):
        result = run(("a.js", "function f(body) { return new Function(body); }\n"))
        self.assertIn("ohscanner.js.dangerous_eval", rules(result))


@needs_grammars
class PathTaintTests(unittest.TestCase):
    def test_want_parameters_reaching_a_path_sink_is_a_candidate(self):
        text = ("function openFromWant(want) {\n"
                "  const path = want.parameters.path;\n"
                "  return fileIo.openSync(path);\n}\n")
        result = run(("a.js", text))
        self.assertIn("ohscanner.js.path_taint", rules(result))
        self.assertIn("Taint coverage:", note(result, "Taint coverage:"))

    def test_an_inline_want_parameter_argument_is_still_a_candidate(self):
        text = ("function openFromWant(want) {\n"
                "  return fileIo.openSync(want.parameters?.path);\n}\n")
        result = run(("a.js", text))
        self.assertIn("ohscanner.js.path_taint", rules(result))

    def test_a_one_hop_helper_receiving_want_parameters_is_a_candidate(self):
        text = ("function openPath(path) {\n"
                "  return fileIo.openSync(path);\n}\n"
                "function handle(want) {\n"
                "  return openPath(want.parameters.path);\n}\n")
        result = run(("a.js", text))
        self.assertIn("ohscanner.js.path_taint", rules(result))
        self.assertIn("<- openPath", result.findings[0].symbol)

    def test_a_helper_called_with_a_literal_is_not_a_candidate(self):
        text = ("function openPath(path) {\n"
                "  return fileIo.openSync(path);\n}\n"
                "function handle() {\n"
                "  return openPath('/data/storage/el2/base/a.txt');\n}\n")
        result = run(("a.js", text))
        self.assertNotIn("ohscanner.js.path_taint", rules(result))

    def test_a_path_predicate_inside_the_helper_suppresses_it(self):
        text = ("function openPath(path) {\n"
                "  if (!path.startsWith('/data/storage/el2/base/')) { return; }\n"
                "  return fileIo.openSync(path);\n}\n"
                "function handle(want) {\n"
                "  return openPath(want.parameters.path);\n}\n")
        result = run(("a.js", text))
        self.assertNotIn("ohscanner.js.path_taint", rules(result))

    def test_a_same_function_path_predicate_suppresses_the_candidate(self):
        text = ("function openFromWant(want) {\n"
                "  const path = want.parameters.path;\n"
                "  if (path.startsWith('/data/storage/el2/base/')) {\n"
                "    return fileIo.openSync(path);\n  }\n}\n")
        result = run(("a.js", text))
        self.assertNotIn("ohscanner.js.path_taint", rules(result))
        self.assertIn("1 behind a same-function path predicate",
                      note(result, "Taint coverage:"))


@needs_grammars
class WebViewBridgeTests(unittest.TestCase):
    def test_an_unguarded_bridge_registration_is_a_candidate(self):
        text = ("function init(controller) {\n"
                "  controller.registerJavaScriptProxy({ object: this, "
                "name: 'bridge', methodList: ['run'] });\n}\n")
        result = run(("a.js", text))
        self.assertIn("ohscanner.oh.arkts.webview_bridge", rules(result))

    def test_an_origin_predicate_in_the_same_function_suppresses_it(self):
        text = ("function init(url, controller) {\n"
                "  if (url.startsWith('https://trusted.example/')) {\n"
                "    controller.registerJavaScriptProxy({ object: this, "
                "name: 'bridge' });\n  }\n}\n")
        result = run(("a.js", text))
        self.assertNotIn("ohscanner.oh.arkts.webview_bridge", rules(result))
        self.assertIn("1 with an origin predicate",
                      note(result, "WebView bridge coverage:"))


@needs_grammars
class ComponentExposureTests(unittest.TestCase):
    def test_an_exported_ability_reading_want_parameters_reaches_a_sink(self):
        text = ("export default class EntryAbility extends UIAbility {\n"
                "  onNewWant(want: Want) {\n"
                "    const path = want.parameters.path as string;\n"
                "    fileIo.openSync(path);\n  }\n}\n")
        result = run(("ability.ts", text))
        self.assertIn("ohscanner.oh.arkts.component_exposure", rules(result))
        self.assertIn("module.json5", " ".join(
            finding.message for finding in result.findings))
        self.assertIn("export/permission state", note(result, "Ability surface:"))

    def test_an_inline_want_parameter_argument_in_a_lifecycle_is_a_candidate(self):
        text = ("export default class EntryAbility extends UIAbility {\n"
                "  onNewWant(want: Want) {\n"
                "    fileIo.openSync(want.parameters?.path);\n  }\n}\n")
        result = run(("ability.ts", text))
        self.assertIn("ohscanner.oh.arkts.component_exposure", rules(result))

    def test_a_path_predicate_inside_the_ability_suppresses_both_candidates(self):
        text = ("export default class EntryAbility extends UIAbility {\n"
                "  onNewWant(want: Want) {\n"
                "    const path = want.parameters.path as string;\n"
                "    if (path.startsWith('/data/storage/el2/base/')) {\n"
                "      fileIo.openSync(path);\n    }\n  }\n}\n")
        result = run(("ability.ts", text))
        self.assertNotIn("ohscanner.oh.arkts.component_exposure", rules(result))
        self.assertNotIn("ohscanner.js.path_taint", rules(result))

    def test_a_non_ability_class_is_not_a_component_candidate(self):
        text = ("export default class Helper extends Base {\n"
                "  run(want) {\n"
                "    const path = want.parameters.path;\n"
                "    fileIo.openSync(path);\n  }\n}\n")
        result = run(("helper.ts", text))
        self.assertNotIn("ohscanner.oh.arkts.component_exposure", rules(result))
        # The path rule is about the call, not the class kind.
        self.assertIn("ohscanner.js.path_taint", rules(result))


if __name__ == "__main__":
    unittest.main()

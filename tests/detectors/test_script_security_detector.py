from __future__ import annotations

import hashlib
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.script_security_detector import ScriptSecurityDetector
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.language import parse_script_text


def unit(name: str, text: str, language: str = "arkts", parse_status: str | None = None) -> SourceUnit:
    parsed = parse_script_text(text, language)
    return SourceUnit(
        path="tests/fixtures/script/" + name,
        language=language,
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        parse_status=parse_status or parsed["parse_status"],
    )


def context_for(*units: SourceUnit) -> ScanContext:
    return ScanContext(
        request=ScanRequest(
            request_id="test:b-ark-01",
            repository="fixture/script-security",
            commit="5" * 40,
            snapshot_sha256=snapshot_digest(units),
            target_id="current-component:fixture/script-security",
            profile_id="fixture-no-build",
            provenance="fixture",
        ),
        units=tuple(sorted(units, key=lambda item: item.path)),
    )


class ScriptSecurityDetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = ScriptSecurityDetector()

    def test_language_frontend_reports_syntax_not_semantics(self):
        parsed = parse_script_text("export default class Main extends Ability { onCreate() {} }", "arkts")
        self.assertEqual(parsed["parse_status"], "complete")
        self.assertTrue(any(item["name"] == "Main" for item in parsed["functions"]))
        broken = parse_script_text("function broken( {", "js")
        self.assertEqual(broken["parse_status"], "failed")

    def test_positive_rules_and_source_binding(self):
        source = unit("positive.ets", """
export default class Main extends Ability {
  onCreate(want) {
    const path = want.parameters.path;
    eval(path);
    this.webview.javaScriptProxy = {};
    this.webview.loadUrl('https://remote.invalid');
    napi_create_function(env, cb);
    memcpy(dst, data.ReadBuffer(), n);
    readFile(path);
  }
}
""")
        run = self.detector.detect(context_for(source), (source,))
        rules = {item.rule_id for item in run.findings}
        self.assertEqual(rules, {
            "ohscanner.js.dangerous-eval-candidate-001",
            "ohscanner.js.path-taint-candidate-002",
            "ohscanner.oh.arkts.component-exposure-candidate-003",
            "ohscanner.oh.arkts.webview-bridge-candidate-004",
            "ohscanner.oh.native-bridge-candidate-005",
        })
        for finding in run.findings:
            self.assertEqual(finding.source_sha256, source.sha256)
            self.assertEqual(finding.rule_lineage_id, "B-ARK-01:script-security-candidate")

    def test_fixed_safe_unrelated_and_unknown(self) -> None:
        fixed = unit("fixed.ts", """
function read(path) {
  const normalized = validatePath(path);
  return fs.readFileSync(normalized);
}
""")
        safe = unit("safe.js", "const result = compute(1); console.log(result);", "js")
        unknown = unit("unknown.ets", "function broken( {", "arkts", "partial")
        for source in (fixed, safe):
            run = self.detector.detect(context_for(source), (source,))
            self.assertEqual(run.findings, ())
        run = self.detector.detect(context_for(unknown), (unknown,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())

    def test_deterministic_and_not_applicable(self) -> None:
        source = unit("positive.ts", "eval('x');", "ts")
        first = self.detector.detect(context_for(source), (source,))
        second = self.detector.detect(context_for(source), (source,))
        self.assertEqual(first, second)
        c_source = unit("not_script.cpp", "int main(){}", "cpp", "complete")
        run = self.detector.detect(context_for(c_source), (c_source,))
        self.assertEqual(run.status, "blocked")


if __name__ == "__main__":
    unittest.main()

import hashlib
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.path_safety_detector import CppPathSafetyDetector, RULE_ID
from src.ohscanner.runner import _normalized


def make_context(source: str, parse_status: str = "complete") -> ScanContext:
    unit = SourceUnit("src/sample.cpp", "cpp", source, hashlib.sha256(source.encode()).hexdigest(), parse_status)
    request = ScanRequest("path-test", "fixture/path", "a" * 40, hashlib.sha256(source.encode()).hexdigest(),
                          "current-component:fixture/path", "fixture-no-build", "fixture")
    return ScanContext(request, (unit,))


class CppPathSafetyDetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = CppPathSafetyDetector()

    def test_external_field_may_flow_through_ref_summary_and_path_concat_to_delete(self):
        source = r'''#include <string>
std::string GetStringValueFromDataShareValue(const Values &v, const char *key, bool &ok);
void GetPhotoName(const Values &v, std::string &photo) {
    bool ok = false;
    photo = GetStringValueFromDataShareValue(v, "PortraitFileName", ok);
}
void Handle(const Values &v, std::string root) {
    std::string photo;
    GetPhotoName(v, photo);
    std::string srcFilePath = root + photo;
    unlink(srcFilePath.c_str());
}
'''
        run = self.detector.detect(make_context(source), make_context(source).units)
        self.assertEqual("completed", run.status)
        self.assertEqual(1, len(run.findings))
        finding = run.findings[0]
        self.assertEqual(RULE_ID, finding.rule_id)
        self.assertEqual("CWE-22", finding.candidate_cwe)
        self.assertIn("PortraitFileName", finding.message)
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), finding.source_sha256)
        self.assertEqual("unknown", finding.evidence_obligations[1].status)

    def test_path_concatenation_without_file_sink_is_not_reported(self):
        source = '''void f(Values &v, std::string root) {
 std::string name = GetStringValueFromDataShareValue(v, "avatar", ok);
 std::string path = root + name;
 log(path);
}'''
        run = self.detector.detect(make_context(source), make_context(source).units)
        self.assertEqual((), run.findings)

    def test_literal_basename_allowlist_guard_before_sink_is_safe(self):
        source = '''void f(Values &v, std::string root) {
 std::string name = GetStringValueFromDataShareValue(v, "avatar", ok);
 if (name != "front.png" && name != "back.png") return;
 std::string path = root + name;
 unlink(path.c_str());
}'''
        run = self.detector.detect(make_context(source), make_context(source).units)
        self.assertEqual((), run.findings)

    def test_conditional_predicate_does_not_complete_allowlist(self):
        source = '''void f(Values &v, std::string root, bool gate) {
 std::string name = GetStringValueFromDataShareValue(v, "avatar", ok);
 if (name != "front.png" && gate) return;
 std::string path = root + name;
 unlink(path.c_str());
}'''
        run = self.detector.detect(make_context(source), make_context(source).units)
        self.assertEqual(1, len(run.findings))
        self.assertEqual("completed", run.status)

    def test_contacts_fileutils_deletefile_is_a_typed_member_sink(self):
        source = '''namespace Contacts { class FileUtils {}; }
void f(Values &v) {
 Contacts::FileUtils fileUtils;
 std::string name = GetStringValueFromDataShareValue(v, "PortraitFileName", ok);
 fileUtils.DeleteFile(name);
}'''
        run = self.detector.detect(make_context(source), make_context(source).units)
        self.assertEqual(1, len(run.findings))
        self.assertEqual("DeleteFile", run.findings[0].symbol)

    def test_unrelated_same_name_deletefile_method_is_not_a_file_sink(self):
        source = '''struct Logger { void DeleteFile(const std::string &); };
void f(Logger &log) {
 std::string path = GetStringParam("ui", "theme");
 log.DeleteFile(path);
}'''
        run = self.detector.detect(make_context(source), make_context(source).units)
        self.assertEqual((), run.findings)

    def test_partial_conditional_allowlist_keeps_candidate_and_unknown_coverage(self):
        source = '''void f(Values &v, std::string root, bool gate) {
 std::string name = GetStringValueFromDataShareValue(v, "avatar", ok);
 if (name != "front.png" && gate) return;
 unlink((root + name).c_str());
}'''
        context = make_context(source, "partial")
        run = self.detector.detect(context, context.units)
        self.assertEqual("blocked", run.status)
        self.assertEqual(1, len(run.findings))
        self.assertEqual(("src/sample.cpp",), run.analyzed_files)
        self.assertEqual((("src/sample.cpp", "partial"),), run.file_outcomes)

    def test_allowlisted_variable_reassigned_after_guard_is_not_safe(self):
        source = '''void f(Values &v, Values &other, std::string root) {
 std::string name = GetStringValueFromDataShareValue(v, "avatar", ok);
 if (name != "front.png" && name != "back.png") return;
 name = GetStringValueFromDataShareValue(other, "path", ok);
 std::string path = root + name;
 unlink(path.c_str());
}'''
        run = self.detector.detect(make_context(source), make_context(source).units)
        self.assertEqual(1, len(run.findings))

    def test_canonical_path_and_separator_bounded_root_guard_is_safe(self):
        source = '''void f(Values &v, std::string root) {
 std::string name = GetStringValueFromDataShareValue(v, "avatar", ok);
 auto canonicalRoot = std::filesystem::weakly_canonical(root).string();
 auto resolved = std::filesystem::weakly_canonical(root + name).string();
 if (!resolved.starts_with(canonicalRoot + "/")) return;
 unlink(resolved.c_str());
}'''
        run = self.detector.detect(make_context(source), make_context(source).units)
        self.assertEqual((), run.findings)

    def test_canonical_path_prefix_without_separator_boundary_is_not_accepted(self):
        source = '''void f(Values &v, std::string root) {
 std::string name = GetStringValueFromDataShareValue(v, "avatar", ok);
 auto canonicalRoot = std::filesystem::weakly_canonical(root).string();
 auto resolved = std::filesystem::weakly_canonical(root + name).string();
 if (!resolved.starts_with(canonicalRoot)) return;
 unlink(resolved.c_str());
}'''
        run = self.detector.detect(make_context(source), make_context(source).units)
        self.assertEqual(1, len(run.findings))

    def test_unrelated_same_name_source_and_file_calls_are_not_crossed(self):
        source = '''void f() {
 auto text = ReadConfigString(config, "display", ok);
 unlink("/tmp/fixed.log");
}'''
        run = self.detector.detect(make_context(source), make_context(source).units)
        self.assertEqual((), run.findings)

    def test_partial_parse_retains_candidate_and_blocked_coverage(self):
        source = '''void f(Values &v) {
 auto p = GetStringValueFromDataShareValue(v, "filename", ok);
 unlink(p.c_str());
}'''
        context = make_context(source, "partial")
        run = self.detector.detect(context, context.units)
        self.assertEqual("blocked", run.status)
        self.assertEqual(1, len(run.findings))
        self.assertEqual(("src/sample.cpp",), run.analyzed_files)
        self.assertEqual((("src/sample.cpp", "partial"),), run.file_outcomes)
        normalized = _normalized(context, self.detector, context.units, run, 0.0)
        self.assertEqual(1, len(normalized.diagnostics))
        self.assertEqual("partial", normalized.parsing[0]["analysis_status"])

    def test_path_sink_without_source_is_not_reported(self):
        source = '''void f(std::string root, std::string fixedName) {
 std::string path = root + fixedName;
 unlink(path.c_str());
}'''
        run = self.detector.detect(make_context(source), make_context(source).units)
        self.assertEqual((), run.findings)

    def test_call_budget_exhaustion_is_unknown_not_safe(self):
        source = "void f() {\n" + "  helper();\n" * 12001 + "}\n"
        context = make_context(source)
        run = self.detector.detect(context, context.units)
        self.assertEqual("blocked", run.status)
        self.assertFalse(run.findings)
        self.assertEqual((("src/sample.cpp", "not_analyzed"),), run.file_outcomes)
        self.assertIn("coverage unknown", " ".join(run.limitations))


if __name__ == "__main__":
    unittest.main()

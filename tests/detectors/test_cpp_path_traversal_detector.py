from __future__ import annotations

import hashlib
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.path_traversal_detector import (
    CppPathTraversalDetector, RULE_ID, RULE_VERSION,
)
from src.ohscanner.fixture import snapshot_digest


def _unit(text: str, path: str = "fixture.cpp", parse_status: str = "complete") -> SourceUnit:
    return SourceUnit(path, "cpp", text, hashlib.sha256(text.encode()).hexdigest(), parse_status)


def _context(*units: SourceUnit) -> ScanContext:
    ordered = tuple(sorted(units, key=lambda item: item.path))
    return ScanContext(ScanRequest(
        request_id="test:path-traversal", repository="fixture/path-traversal",
        commit="1" * 40, snapshot_sha256=snapshot_digest(ordered),
        target_id="current-component:fixture/path-traversal", profile_id="fixture-no-build",
    ), ordered)


SOURCE_AND_FILE_FLOW = r'''
struct Bucket { Value Get(const std::string &key) const; };
std::string ReadTextField(const Bucket &bucket, const std::string &key) {
    Value valueObject = bucket.Get(key);
    std::string value;
    if (const auto *stringPtr = std::get_if<std::string>(&valueObject.value)) value = *stringPtr;
    return value;
}
void ExtractFilename(const Bucket &bucket, std::string &filename) {
    filename = ReadTextField(bucket, "input");
}
void OpenPath(const std::string &path) { open(path.c_str(), O_RDONLY); }
void RemovePath(const std::string &path) { unlink(path.c_str()); }
void Handle(const Bucket &bucket) {
    std::string filename;
    ExtractFilename(bucket, filename);
    std::string root = GetStorageRoot();
    std::string sourcePath = root + filename;
    OpenPath(sourcePath);
    RemovePath(sourcePath);
}
'''


class CppPathTraversalDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = CppPathTraversalDetector()

    def test_cross_function_field_to_open_and_delete_candidate(self) -> None:
        unit = _unit(SOURCE_AND_FILE_FLOW)
        run = self.detector.detect(_context(unit), (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.file_outcomes, ((unit.path, "complete"),))
        self.assertEqual([item.rule_id for item in run.findings], [RULE_ID, RULE_ID])
        self.assertEqual({item.line for item in run.findings}, {12, 13})
        self.assertTrue(all(item.candidate_cwe == "CWE-22" for item in run.findings))
        self.assertTrue(all(item.source_sha256 == unit.sha256 for item in run.findings))
        self.assertTrue(all(item.rule_version == RULE_VERSION for item in run.findings))
        self.assertTrue(all(item.identity_quality == "complete" for item in run.findings))
        self.assertTrue(all(item.ast_fingerprint for item in run.findings))

    def test_synthetic_fixed_shaped_basename_control_is_safe(self) -> None:
        source = SOURCE_AND_FILE_FLOW.replace(
            "std::string sourcePath = root + filename;",
            "std::string safeName = std::filesystem::path(filename).filename().string();\n"
            "    std::string sourcePath = root + safeName;",
        )
        unit = _unit(source, "basename.cpp")
        run = self.detector.detect(_context(unit), (unit,))
        self.assertEqual(run.findings, ())

    def test_explicit_containment_guard_is_safe_control(self) -> None:
        source = SOURCE_AND_FILE_FLOW.replace(
            "OpenPath(sourcePath);\n    RemovePath(sourcePath);",
            "if (sourcePath.starts_with(root)) { OpenPath(sourcePath); RemovePath(sourcePath); }",
        )
        unit = _unit(source, "contained.cpp")
        run = self.detector.detect(_context(unit), (unit,))
        self.assertEqual(run.findings, ())

    def test_unrelated_api_and_missing_sink_are_quiet(self) -> None:
        no_sink = SOURCE_AND_FILE_FLOW.replace("OpenPath(sourcePath);", "LogPath(sourcePath);")
        no_sink = no_sink.replace("RemovePath(sourcePath);", "RecordPath(sourcePath);")
        unit = _unit(no_sink, "no_sink.cpp")
        run = self.detector.detect(_context(unit), (unit,))
        self.assertEqual(run.findings, ())

    def test_partial_parse_candidate_stays_partial(self) -> None:
        unit = _unit(SOURCE_AND_FILE_FLOW, parse_status="partial")
        run = self.detector.detect(_context(unit), (unit,))
        self.assertEqual(len(run.findings), 2)
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.file_outcomes, ((unit.path, "partial"),))
        self.assertTrue(any("parser status is partial" in item for item in run.limitations))

    def test_unrelated_field_getter_without_file_flow_is_quiet(self) -> None:
        unit = _unit(SOURCE_AND_FILE_FLOW.split("void Handle")[0] + "void Handle(const Bucket &bucket) {\n"
                     " std::string title = ReadTextField(bucket, \"title\");\n"
                     " LogText(title);\n}\n", "unrelated.cpp")
        run = self.detector.detect(_context(unit), (unit,))
        self.assertEqual(run.findings, ())

    def test_bucket_component_separator_rejection_is_safe(self) -> None:
        source = SOURCE_AND_FILE_FLOW.replace(
            'void OpenPath(const std::string &path) { open(path.c_str(), O_RDONLY); }',
            'void OpenPath(const std::string &path) { if (path.find_first_of("/\\\\") != std::string::npos) return; open(path.c_str(), O_RDONLY); }'
        ).replace(
            'void RemovePath(const std::string &path) { unlink(path.c_str()); }',
            'void RemovePath(const std::string &path) { if (path.find_first_of("/\\\\") != std::string::npos) return; unlink(path.c_str()); }'
        )
        unit = _unit(source, "validated_component.cpp")
        run = self.detector.detect(_context(unit), (unit,))
        self.assertEqual(run.findings, ())

    def test_bucket_presence_and_nonempty_checks_do_not_validate_path_component(self) -> None:
        unit = _unit(SOURCE_AND_FILE_FLOW.replace(
            'ExtractFilename(bucket, filename);',
            'ExtractFilename(bucket, filename);\n'
            '    if (filename.empty()) return;'
        ), "nonempty_only.cpp")
        run = self.detector.detect(_context(unit), (unit,))
        self.assertEqual(len(run.findings), 2)

    def test_reversed_separator_condition_does_not_suppress_candidate(self) -> None:
        source = SOURCE_AND_FILE_FLOW.replace(
            'void OpenPath(const std::string &path) { open(path.c_str(), O_RDONLY); }',
            'void OpenPath(const std::string &path) { if (path.find_first_of("/\\\\") == std::string::npos) return; open(path.c_str(), O_RDONLY); }'
        )
        unit = _unit(source, "reversed_guard.cpp")
        run = self.detector.detect(_context(unit), (unit,))
        self.assertEqual(len(run.findings), 2)


if __name__ == "__main__":
    unittest.main()

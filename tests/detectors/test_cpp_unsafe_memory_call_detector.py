from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.unsafe_memory_call_detector import CppUnsafeMemoryCallDetector
from src.ohscanner.fixture import snapshot_digest


ROOT = Path(__file__).parent / "fixtures" / "cpp_unsafe_calls"


def unit(path: Path, parse_status: str = "complete") -> SourceUnit:
    text = path.read_text(encoding="utf-8")
    return SourceUnit(
        path="tests/detectors/fixtures/cpp_unsafe_calls/" + path.name,
        language="cpp",
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        parse_status=parse_status,
    )


def context_for(*units: SourceUnit) -> ScanContext:
    return ScanContext(
        request=ScanRequest(
            request_id="test:a-unsafe-calls",
            repository="fixture/ohscanner-unsafe-calls",
            commit="3" * 40,
            snapshot_sha256=snapshot_digest(units),
            target_id="current-component:fixture/ohscanner-unsafe-calls",
            profile_id="fixture-no-build",
            provenance="fixture",
        ),
        units=tuple(sorted(units, key=lambda item: item.path)),
    )


class UnsafeMemoryCallDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.detector = CppUnsafeMemoryCallDetector()
        cls.manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))

    def run_case(self, name: str, parse_status: str = "complete"):
        source = unit(ROOT / name, parse_status)
        return self.detector.detect(context_for(source), (source,)), source

    def test_manifest_is_hash_bound_and_covers_control_classes(self) -> None:
        self.assertEqual(
            {item["category"] for item in self.manifest["cases"]},
            {"positive", "fixed", "safe", "unrelated", "unknown", "format_api_signature", "format_signature_unknown", "format_literal_conditional", "format_long_concatenated_literals", "format_arguments_with_delimiters", "format_literal_prefix_macro", "format_raw_string_controls"},
        )
        for item in self.manifest["cases"]:
            path = ROOT / item["fixture"]
            self.assertEqual(path.stat().st_size, item["byte_length"])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])

    def test_positive_and_source_binding(self) -> None:
        run, source = self.run_case("positive_unsafe.cpp")
        self.assertEqual(self.detector.detector_id, "ohscanner.cpp.unsafe_memory_call")
        self.assertEqual(self.detector.version, "0.5.0")
        self.assertGreaterEqual(len(run.findings), 5)
        self.assertIn("ohcpp-unsafe-memory-call-candidate-001", {item.rule_id for item in run.findings})
        self.assertIn("ohcpp-format-string-candidate-002", {item.rule_id for item in run.findings})
        for finding in run.findings:
            self.assertEqual(finding.source_sha256, source.sha256)
            self.assertEqual(finding.rule_lineage_id, "A-UNSAFE-01:ohcpp-unsafe-call-candidate")

    def test_fixed_safe_unrelated_and_unknown(self) -> None:
        for name in ("fixed_bounded.cpp", "safe_literal.cpp", "unrelated.cpp"):
            run, _ = self.run_case(name)
            self.assertEqual(run.findings, ())
        unknown, _ = self.run_case("unknown_partial.cpp", "partial")
        self.assertEqual(unknown.status, "blocked")
        self.assertEqual(unknown.findings, ())

    def test_format_calls_use_the_api_format_parameter_position(self) -> None:
        run, source = self.run_case("format_api_argument_positions.cpp")
        findings = [item for item in run.findings if item.rule_id == "ohcpp-format-string-candidate-002"]
        self.assertEqual(len(findings), 5)
        self.assertEqual({item.symbol for item in findings}, {"format"})
        self.assertEqual({item.line for item in findings}, {6, 8, 10, 12, 14})
        self.assertTrue(all(item.source_sha256 == source.sha256 for item in findings))

    def test_shadowed_or_qualified_format_calls_remain_unknown(self) -> None:
        run, _ = self.run_case("format_api_shadow_unknown.cpp")
        self.assertEqual(run.findings, ())
        self.assertEqual(dict(run.file_outcomes)["tests/detectors/fixtures/cpp_unsafe_calls/format_api_shadow_unknown.cpp"], "partial")
        self.assertTrue(any("format_call_signature_unknown" in item for item in run.limitations))

    def test_literal_format_conditionals_are_suppressed_but_dynamic_arms_remain(self) -> None:
        run, source = self.run_case("format_literal_conditional.cpp")
        findings = [item for item in run.findings if item.rule_id == "ohcpp-format-string-candidate-002"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 3)
        self.assertEqual(findings[0].symbol, 'condition ? dynamic : "fixed"')
        self.assertEqual(findings[0].source_sha256, source.sha256)

    def test_long_concatenated_literal_format_is_classified_without_regex_backtracking(self) -> None:
        run, _ = self.run_case("format_long_concatenated_literals.cpp")
        self.assertEqual(run.findings, ())
        self.assertEqual(run.status, "completed")

    def test_delimiters_inside_string_arguments_do_not_shift_format_argument(self) -> None:
        run, source = self.run_case("format_arguments_with_delimiters.cpp")
        findings = [item for item in run.findings if item.rule_id == "ohcpp-format-string-candidate-002"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 3)
        self.assertEqual(findings[0].symbol, "dynamic_format")
        self.assertEqual(findings[0].source_sha256, source.sha256)

    def test_literal_prefix_followed_by_macro_token_remains_a_candidate(self) -> None:
        run, source = self.run_case("format_literal_prefix_macro.cpp")
        findings = [item for item in run.findings if item.rule_id == "ohcpp-format-string-candidate-002"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 4)
        self.assertEqual(findings[0].source_sha256, source.sha256)

    def test_raw_string_literals_are_constant_and_mask_their_delimiters(self) -> None:
        run, source = self.run_case("format_raw_string_controls.cpp")
        findings = [item for item in run.findings if item.rule_id == "ohcpp-format-string-candidate-002"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 3)
        self.assertEqual(findings[0].symbol, "dynamic_format")
        self.assertEqual(findings[0].source_sha256, source.sha256)

    def test_long_format_signature_line_fails_closed(self) -> None:
        text = (" " * 17000) + "fprintf(stream, format);\n"
        source = SourceUnit(
            path="tests/detectors/fixtures/cpp_unsafe_calls/long_format_signature.cpp",
            language="cpp",
            text=text,
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            parse_status="complete",
        )
        run = self.detector.detect(context_for(source), (source,))
        self.assertEqual(run.findings, ())
        self.assertEqual(dict(run.file_outcomes)[source.path], "partial")
        self.assertTrue(any("format_call_signature_unknown" in item for item in run.limitations))

    def test_deterministic_and_budget(self) -> None:
        first, _ = self.run_case("positive_unsafe.cpp")
        second, _ = self.run_case("positive_unsafe.cpp")
        self.assertEqual(first, second)
        oversized = SourceUnit(
            path="tests/detectors/fixtures/cpp_unsafe_calls/oversized.cpp",
            language="cpp",
            text="int x;" + " " * (1024 * 1024),
            sha256=hashlib.sha256(("int x;" + " " * (1024 * 1024)).encode("utf-8")).hexdigest(),
            parse_status="complete",
        )
        run = self.detector.detect(context_for(oversized), (oversized,))
        self.assertEqual(run.status, "failed")


if __name__ == "__main__":
    unittest.main()

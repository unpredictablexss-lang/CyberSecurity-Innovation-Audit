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

    def test_manifest_is_hash_bound_and_has_four_control_classes(self) -> None:
        self.assertEqual(
            {item["category"] for item in self.manifest["cases"]},
            {"positive", "fixed", "safe", "unrelated", "unknown"},
        )
        for item in self.manifest["cases"]:
            path = ROOT / item["fixture"]
            self.assertEqual(path.stat().st_size, item["byte_length"])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])

    def test_positive_and_source_binding(self) -> None:
        run, source = self.run_case("positive_unsafe.cpp")
        self.assertEqual(self.detector.detector_id, "ohscanner.cpp.unsafe_memory_call")
        self.assertEqual(self.detector.version, "0.1.2")
        self.assertGreaterEqual(len(run.findings), 5)
        self.assertIn("ohcpp-unsafe-memory-call-candidate-001", {item.rule_id for item in run.findings})
        self.assertIn("ohcpp-format-string-candidate-002", {item.rule_id for item in run.findings})
        for finding in run.findings:
            self.assertEqual(finding.source_sha256, source.sha256)
            self.assertEqual(finding.rule_lineage_id, "A-UNSAFE-01:ohcpp-unsafe-call-candidate")

    def test_fixed_safe_unrelated_and_unknown(self) -> None:
        for name in (
            "fixed_bounded.cpp",
            "safe_literal.cpp",
            "safe_macro_format.cpp",
            "safe_fprintf_literal.cpp",
            "unrelated.cpp",
        ):
            run, _ = self.run_case(name)
            self.assertEqual(run.findings, ())
        unknown, _ = self.run_case("unknown_partial.cpp", "partial")
        self.assertEqual(unknown.status, "blocked")
        self.assertEqual(unknown.findings, ())

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

    def test_macro_format_is_quiet_but_nonliteral_format_remains_candidate(self) -> None:
        macro_run, _ = self.run_case("safe_macro_format.cpp")
        self.assertEqual(macro_run.findings, ())

        real_run, _ = self.run_case("positive_nonliteral_format.cpp")
        self.assertEqual(
            {item.rule_id for item in real_run.findings},
            {"ohcpp-format-string-candidate-002"},
        )
        self.assertEqual(real_run.findings[0].symbol, "user_format")

    def test_fprintf_uses_the_format_argument_not_the_stream(self) -> None:
        safe_run, _ = self.run_case("safe_fprintf_literal.cpp")
        self.assertEqual(safe_run.findings, ())

        real_run, _ = self.run_case("positive_fprintf_format.cpp")
        self.assertEqual(
            {item.rule_id for item in real_run.findings},
            {"ohcpp-format-string-candidate-002"},
        )
        self.assertEqual(real_run.findings[0].symbol, "user_format")


if __name__ == "__main__":
    unittest.main()

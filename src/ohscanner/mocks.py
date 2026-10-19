"""Synthetic-only detector examples used to validate the shared plugin contract."""

from .contracts import DetectorFinding, DetectorRun, ScanContext, SourceUnit
from typing import Tuple


class MockCppDetector:
    detector_id = "ohscanner.mock.cpp"
    version = "0.1.0"
    supported_languages = ("c", "cpp")
    required_facts = ()

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        findings = []
        for unit in units:
            for number, line in enumerate(unit.text.splitlines(), start=1):
                if "OH_MOCK_CPP_MARKER" in line:
                    findings.append(DetectorFinding(
                        file=unit.path, line=number, rule_id="mock.cpp.marker",
                        message="Synthetic C/C++ contract marker (not a vulnerability)."))
        return DetectorRun(self.detector_id, self.version, "completed",
                           analyzed_files=tuple(unit.path for unit in units),
                           findings=tuple(findings),
                           limitations=("M0 synthetic marker matching only; no semantic analysis.",))


class MockInterfaceDetector:
    detector_id = "ohscanner.mock.interface"
    version = "0.1.0"
    supported_languages = ("js", "ts", "arkts")
    required_facts = ()

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        findings = []
        for unit in units:
            for number, line in enumerate(unit.text.splitlines(), start=1):
                if "OH_MOCK_INTERFACE_MARKER" in line:
                    findings.append(DetectorFinding(
                        file=unit.path, line=number, rule_id="mock.interface.marker",
                        message="Synthetic interface contract marker (not a vulnerability)."))
        return DetectorRun(self.detector_id, self.version, "completed",
                           analyzed_files=tuple(unit.path for unit in units),
                           findings=tuple(findings),
                           limitations=("M0 synthetic marker matching only; no taint or permission analysis.",))

"""IPC coverage sidecar contract for complete, partial, and out-of-scope sources."""

import hashlib
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.m2_adapter import M2IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from src.parser.ast import parse_source


def source(path, language, text, parse_status, ast=None):
    unit = SourceUnit(
        path, language, text, hashlib.sha256(text.encode("utf-8")).hexdigest(),
        parse_status,
    )
    if ast is not None:
        ast[path] = parse_source(text, language=language).to_dict()
    return unit


class IpcCoverageContractTests(unittest.TestCase):
    def test_ipc_sidecar_keeps_applicability_and_analysis_states_distinct(self):
        ast = {}
        units = (
            source("src/a_complete.cpp", "cpp", "int ready() { return 0; }\n",
                   "complete", ast),
            source("src/b_partial.cpp", "cpp", "int broken( {\n", "partial", ast),
            source("src/bridge.js", "js", "export function bridge() {}\n",
                   "not_run"),
            source("src/c_no_ast.cpp", "cpp", "int no_ast() { return 1; }\n",
                   "complete"),
        )
        request = ScanRequest(
            "ipc-coverage-contract", "fixture/ipc-coverage", "synthetic-ipc-v1",
            snapshot_digest(units), "current-component:fixture/ipc-coverage",
        )
        context = ScanContext(request, units, {"ast": ast})
        registry = DetectorRegistry()
        registry.register(M2IpcInterfaceDetector())

        _, coverage = run_all_with_coverage(context, registry)
        ipc = coverage["detectors"][M2IpcInterfaceDetector.detector_id]

        self.assertEqual(ipc["status"], "partial")
        self.assertEqual(ipc["applicable_files"], 3)
        self.assertEqual(ipc["analyzed_files"], ["src/a_complete.cpp"])
        self.assertEqual(ipc["partially_inspected_files"], ["src/b_partial.cpp"])
        self.assertEqual(ipc["not_analyzed_files"], ["src/c_no_ast.cpp"])
        self.assertEqual(ipc["coverage_counts"], {
            "complete": 1, "partial": 1, "not_analyzed": 1, "failed": 0,
        })
        self.assertEqual(sum(ipc["coverage_counts"].values()), ipc["applicable_files"])

        analyzed = set(ipc["analyzed_files"])
        partial = set(ipc["partially_inspected_files"])
        not_analyzed = set(ipc["not_analyzed_files"])
        self.assertFalse(analyzed & partial or analyzed & not_analyzed or partial & not_analyzed)
        self.assertEqual(ipc["inspected_files"], sorted(analyzed | partial))
        self.assertEqual(ipc["source_sha256"], {
            unit.path: unit.sha256 for unit in units
            if unit.language in ("c", "cpp")
        })
        self.assertEqual(ipc["unexamined"], [{
            "file": "src/b_partial.cpp",
            "parse_status": "partial",
            "reason": "detector_model_incomplete",
            "analysis_status": "partial",
        }, {
            "file": "src/c_no_ast.cpp",
            "parse_status": "complete",
            "reason": "not_analyzed",
            "analysis_status": "not_analyzed",
        }])
        self.assertNotIn("src/bridge.js", ipc["source_sha256"])
        self.assertNotIn("src/bridge.js", ipc["inspected_files"])


if __name__ == "__main__":
    unittest.main()

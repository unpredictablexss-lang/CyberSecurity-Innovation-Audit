import hashlib
import importlib.util
import unittest

from src.ohscanner.detectors.interface.detector import IpcPermissionDetector
from tests.detectors.interface.test_ipc_repository import HEADER, DISPATCH, HELPER

CORE_PRESENT = importlib.util.find_spec("src.ohscanner.contracts") is not None


@unittest.skipUnless(CORE_PRESENT, "Core contract exists on feat/ohscanner-core, not main yet")
class CoreAdapterTests(unittest.TestCase):
    def context(self, body, partial=False):
        from dataclasses import replace
        from src.ohscanner.contracts import ScanContext, ScanRequest
        from src.ohscanner.fixture import snapshot_digest
        from src.ohscanner.frontend import index_sources
        from src.ohscanner.git_source import GitSource
        sources = {"stub.h": HEADER, "stub.cpp": DISPATCH.replace(b"return Helper(token);", body), "helper.cpp": HELPER}
        git_sources = tuple(GitSource(path, "cpp", hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest(), data)
                            for path, data in sorted(sources.items()))
        units, ast, _ = index_sources(git_sources)
        if partial:
            units = tuple(replace(u, parse_status="partial") if u.path == "stub.cpp" else u for u in units)
            ast["stub.cpp"]["parse_status"] = "partial"
        request = ScanRequest("interface-adapter-fixture", "fixture/interface", "d"*40,
                              snapshot_digest(units), "current-component:fixture/interface")
        facts = {"ast": ast}
        return ScanContext(request, units, facts)

    def run_detector(self, context):
        from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
        registry = DetectorRegistry()
        registry.register(IpcPermissionDetector())
        return run_all_with_coverage(context, registry)

    def test_candidate_uses_real_core_bridge_and_obligations(self):
        reports, sidecar = self.run_detector(self.context(b"if (!Helper(token)) { int ignored=0; } return 0;"))
        report = reports[0]
        self.assertEqual(report.status, "completed")
        self.assertEqual(len(report.diagnostics), 1)
        self.assertEqual(report.diagnostics[0].evidence_type, "syntax")
        self.assertEqual(report.diagnostics[0].confidence, "unassessed")
        self.assertTrue(sidecar["detectors"][IpcPermissionDetector.detector_id]["evidence_obligations"])

    def test_guarded_control_has_no_candidate(self):
        reports, _ = self.run_detector(self.context(b"if (!Helper(token)) return -1; return 0;"))
        self.assertEqual(reports[0].diagnostics, [])

    def test_whole_scope_partial_is_blocked(self):
        reports, sidecar = self.run_detector(self.context(b"return 0;", partial=True))
        self.assertEqual(reports[0].status, "blocked")
        self.assertEqual(reports[0].scope_files, 0)
        self.assertEqual(sidecar["detectors"][IpcPermissionDetector.detector_id]["status"], "blocked")

    def test_snapshot_drift_rejected_by_core_runner(self):
        from dataclasses import replace
        context = self.context(b"return 0;")
        request = replace(context.request, snapshot_sha256="0"*64)
        with self.assertRaises(ValueError):
            self.run_detector(replace(context, request=request))

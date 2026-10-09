import hashlib
import importlib.util
import unittest
from src.ohscanner.detectors.interface.web_patterns import BridgeInjectionDetector, WebUrlDetector, SensitiveDisclosureDetector, WebEngineDetector

@unittest.skipUnless(importlib.util.find_spec('src.ohscanner.contracts'), 'Actual core is not merged on main')
class WebCoreTests(unittest.TestCase):
    def run_case(self, detector, text, language='arkts', status='not_run'):
        from src.ohscanner.contracts import SourceUnit, ScanContext, ScanRequest
        from src.ohscanner.fixture import snapshot_digest
        from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
        u=SourceUnit('fixture.ets' if language=='arkts' else 'engine.cpp', language, text, hashlib.sha256(text.encode()).hexdigest(), status)
        units=(u,)
        request=ScanRequest('web-fixture', 'fixture/web', 'd'*40, snapshot_digest(units), 'current-component:fixture/web')
        registry=DetectorRegistry()
        registry.register(detector)
        return run_all_with_coverage(ScanContext(request, units), registry)
    def test_three_candidates_and_obligations(self):
        for detector, source in [(BridgeInjectionDetector(), 'c.runJavaScript(input)'), (WebUrlDetector(), 'url.startsWith("https://a.example")'), (SensitiveDisclosureDetector(), 'Web({}).fileAccess(true)')]:
            with self.subTest(detector=detector.detector_id):
                reports, sidecar=self.run_case(detector, source)
                self.assertEqual(reports[0].status, 'completed')
                self.assertEqual(len(reports[0].diagnostics), 1)
                self.assertEqual(reports[0].diagnostics[0].evidence_type, 'pattern')
                self.assertEqual(reports[0].diagnostics[0].confidence, 'unassessed')
                self.assertTrue(sidecar['detectors'][detector.detector_id]['evidence_obligations'])
                self.assertEqual(reports[0].parsing[0]['status'], 'not_run')
    def test_failed_source_withheld(self):
        reports, _=self.run_case(BridgeInjectionDetector(), 'c.runJavaScript(input)', status='failed')
        self.assertEqual(reports[0].status, 'blocked')
        self.assertEqual(reports[0].diagnostics, [])
    def test_engine_unimplemented_is_blocked(self):
        reports, _=self.run_case(WebEngineDetector(), 'void f() {}', language='cpp', status='complete')
        self.assertEqual(reports[0].status, 'blocked')
        self.assertEqual(reports[0].diagnostics, [])
    def test_deterministic(self):
        first, _=self.run_case(BridgeInjectionDetector(), 'c.runJavaScript(input)')
        second, _=self.run_case(BridgeInjectionDetector(), 'c.runJavaScript(input)')
        self.assertEqual(first[0].diagnostics, second[0].diagnostics)

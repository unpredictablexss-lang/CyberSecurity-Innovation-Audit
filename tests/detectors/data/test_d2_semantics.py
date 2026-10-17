import hashlib
import json
from pathlib import Path
import unittest
from tests.detectors.data import test_sensitive_exposure as support
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector

ROOT=Path(__file__).resolve().parents[3]

class D2SemanticsTests(unittest.TestCase):
    def test_d2_control_groups(self):
        cases=json.loads((ROOT/'tests/fixtures/data_sensitive/d2_cases.json').read_text())
        for case in cases:
            with self.subTest(case=case['id']):
                text=(ROOT/'tests/fixtures/data_sensitive'/case['file']).read_text()
                context=support.SensitiveTests().context(text)
                run=SensitiveExposureDetector(support.MODEL).detect(context,context.units)
                self.assertEqual(len(run.findings),case['expected_candidates'])
                if case['requires_partial']:
                    self.assertNotEqual(dict(run.file_outcomes)['service.cpp'],'complete')
    def test_d1_fixtures_and_expectations_unchanged(self):
        record=json.loads((ROOT/'research/data_sensitive/D2_BASELINE.json').read_text())
        for path,digest in record['d1_fixture_sha256'].items():
            with self.subTest(path=path):self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),digest)

    def test_explicit_exit_evidence_has_no_fallthrough(self):
        from src.ohscanner.detectors.data.sensitive_exposure import LocalFlow
        context=support.SensitiveTests().context('void Callback(const char *s,int c){if(c){return;}else{return;} AUTH_LOGI(0,"%{public}s",s);}')
        probe=LocalFlow(context.units[0],support.MODEL)
        self.assertEqual(probe.run(),[])
        self.assertFalse(probe.function_audits[0]['fallthrough'])
        self.assertEqual([x['kind'] for x in probe.function_audits[0]['exits']],['return_statement','return_statement'])

    def test_live_else_preserved_by_real_runner(self):
        from src.ohscanner.runner import DetectorRegistry,run_all_with_coverage
        text='void Callback(const char *s,int c){const char *a="safe";if(c){return;}else{a=s;}AUTH_LOGI(0,"%{public}s",a);}'
        context=support.SensitiveTests().context(text)
        registry=DetectorRegistry();registry.register(SensitiveExposureDetector(support.MODEL))
        reports,sidecar=run_all_with_coverage(context,registry)
        self.assertEqual(len(reports[0].diagnostics),1)
        self.assertEqual(reports[0].diagnostics[0].source_sha256,context.units[0].sha256)
        self.assertEqual(reports[0].diagnostics[0].confidence,'unassessed')
        self.assertTrue(sidecar['detectors'][SensitiveExposureDetector.detector_id]['evidence_obligations'])

    def test_other_repository_never_reuses_source_model(self):
        from dataclasses import replace
        c=support.SensitiveTests().context('void Callback(const char *s){AUTH_LOGI(0,"%{public}s",s);}')
        c=replace(c,request=replace(c.request,repository='other/project',target_id='current-component:other/project'))
        run=SensitiveExposureDetector(support.MODEL).detect(c,c.units)
        self.assertEqual(run.status,'blocked');self.assertEqual(run.findings,())

    def test_same_named_copy_definition_not_assumed(self):
        text='int strcpy_s(char *d,int n,const char *s){return 0;} void Callback(const char *s){char out[64];strcpy_s(out,64,s);AUTH_LOGI(0,"%{public}s",out);}'
        c=support.SensitiveTests().context(text)
        run=SensitiveExposureDetector(support.MODEL).detect(c,c.units)
        self.assertEqual(run.findings,());self.assertEqual(run.status,'blocked')

import hashlib
import json
from pathlib import Path
import unittest
from dataclasses import replace
from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from src.ohscanner.detectors.data.models import SensitiveSourceModel
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector, formats

MODEL=SensitiveSourceModel('fixture/d-sensitive','d'*40,parameters=(('service.cpp','Callback',0),),provenance='Synthetic model for regression only; no real vulnerability')
ROOT=Path(__file__).resolve().parents[2]

class SensitiveTests(unittest.TestCase):
    def context(self, source, path='service.cpp', partial=None):
        b=source.encode()
        units,ast,_=index_sources((GitSource(path,'cpp',hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),b),))
        if partial:
            units=(replace(units[0],parse_status=partial),);ast[path]['parse_status']=partial
        request=ScanRequest('d-regression',MODEL.repository,MODEL.commit,snapshot_digest(units),'current-component:'+MODEL.repository)
        return ScanContext(request,units,{'ast':ast})
    def analyze(self,source,**kwargs):
        c=self.context(source,**kwargs)
        return SensitiveExposureDetector(MODEL).detect(c,c.units)
    def test_controls_from_manifest(self):
        cases=json.loads((ROOT/'fixtures/data_sensitive/cases.json').read_text())
        for case in cases:
            with self.subTest(case=case['id']):
                text=(ROOT/'fixtures/data_sensitive'/case['file']).read_text()
                run=self.analyze(text,path=case.get('path','service.cpp'))
                self.assertEqual(len(run.findings),case['expected_candidates'])
                if case.get('partial'):
                    self.assertNotEqual(dict(run.file_outcomes).get(case.get('path','service.cpp')),'complete')
    def test_model_binding_rejects_other_commit(self):
        c=self.context('void f() {}')
        c=replace(c,request=replace(c.request,commit='e'*40))
        self.assertEqual(SensitiveExposureDetector(MODEL).detect(c,c.units).status,'blocked')
    def test_parse_failed_no_clean_scan(self):
        run=self.analyze('void f() {}',partial='failed')
        self.assertEqual(run.status,'blocked');self.assertEqual(run.file_outcomes,(('service.cpp','failed'),))
    def test_parse_partial_preserves_tentative(self):
        run=self.analyze('void f(SessionKey *x){ AUTH_LOGE(0,"%{public}s",x->value); }',partial='partial')
        self.assertEqual(len(run.findings),1);self.assertEqual(run.status,'blocked')
        self.assertEqual(run.file_outcomes,(('service.cpp','partial'),))
    def test_real_runner_v2_and_obligations(self):
        c=self.context('void f(SessionKey *x){ const char *alias = (const char*)x->value; AUTH_LOGE(0,"%{public}s",alias); }')
        registry=DetectorRegistry();registry.register(SensitiveExposureDetector(MODEL))
        reports,sidecar=run_all_with_coverage(c,registry)
        self.assertEqual(len(reports[0].diagnostics),1)
        d=reports[0].diagnostics[0]
        self.assertEqual(d.source_sha256,c.units[0].sha256)
        self.assertEqual(d.confidence,'unassessed')
        self.assertEqual(d.candidate_cwe,'CWE-532')
        obligations=sidecar['detectors'][SensitiveExposureDetector.detector_id]['evidence_obligations']
        self.assertTrue(obligations)
        self.assertIn('assign alias',d.message)
    def test_snapshot_drift_rejected(self):
        c=self.context('void f() {}');c=replace(c,request=replace(c.request,snapshot_sha256='0'*64))
        reg=DetectorRegistry();reg.register(SensitiveExposureDetector(MODEL))
        with self.assertRaises(ValueError):run_all_with_coverage(c,reg)
    def test_format_stars_and_percent(self):
        slots,count=formats('%% %{public}*.*s %{private}u')
        self.assertEqual(count,4);self.assertEqual(slots[0][1],(0,1,2))
    def test_format_positional_rejected(self):
        with self.assertRaises(ValueError):formats('%2$s')
    def test_default_private(self):
        self.assertEqual(formats('%s')[0][0][0],'private')
    def test_repeat_stable(self):
        text='void Callback(const char *x){ const char *b=x; AUTH_LOGI(0,"%{public}s",b); }'
        self.assertEqual(self.analyze(text),self.analyze(text))

if __name__=='__main__':unittest.main()

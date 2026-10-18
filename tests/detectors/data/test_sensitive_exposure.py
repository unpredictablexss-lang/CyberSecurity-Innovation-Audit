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
        d5=json.loads((ROOT/'fixtures/data_sensitive/d5_cases.json').read_text())
        overrides={case['id']:case for case in d5}
        for case in cases:
            with self.subTest(case=case['id']):
                text=(ROOT/'fixtures/data_sensitive'/case['file']).read_text()
                run=self.analyze(text,path=case.get('path','service.cpp'))
                self.assertEqual(len(run.findings),overrides.get(case['id'],case)['expected_candidates'])
                if case.get('partial'):
                    self.assertNotEqual(dict(run.file_outcomes).get(case.get('path','service.cpp')),'complete')
    def test_d5_loop_controls_preserve_uncertainty(self):
        cases=json.loads((ROOT/'fixtures/data_sensitive/d5_cases.json').read_text())
        for case in cases:
            with self.subTest(case=case['id']):
                run=self.analyze((ROOT/'fixtures/data_sensitive'/case['file']).read_text())
                self.assertEqual(len(run.findings),case['expected_candidates'])
                if run.findings:self.assertTrue(run.findings[0].evidence_obligations)
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
    def test_dsoftbus_trans_and_comm_log_macros_are_modeled_sinks(self):
        cases=(
            ('TRANS_LOGE(TRANS_CTRL,"%{public}s",secret->value);',1),
            ('COMM_LOGW(COMM_ADAPTER,"%{public}s",secret->value);',1),
            ('TRANS_CHECK_AND_RETURN_RET_LOGE(false,0,TRANS_CTRL,"%{public}s",secret->value);',1),
            ('COMM_CHECK_AND_RETURN_LOGE(false,COMM_ADAPTER,"%{public}s",secret->value);',1),
            ('TRANS_LOGI(TRANS_CTRL,"%{private}s",secret->value);',0),
        )
        for call,expected in cases:
            with self.subTest(call=call):
                run=self.analyze('void Callback(SessionKey *secret){'+call+'}')
                self.assertEqual(len(run.findings),expected)
                if expected:
                    self.assertEqual(run.findings[0].rule_id,'data.log.sensitive-value')
                    self.assertEqual(run.findings[0].candidate_cwe,'CWE-532')
                    self.assertTrue(run.findings[0].evidence_obligations)
    def test_hilog_native_macro_families_are_source_bound_sinks(self):
        public_calls=(
            'HILOG_DEBUG(HILOG_MODULE_SOFTBUS,"%{public}s",secret->value);',
            'HILOG_INFO(HILOG_MODULE_SOFTBUS,"%{public}s",secret->value);',
            'HILOG_WARN(HILOG_MODULE_SOFTBUS,"%{public}s",secret->value);',
            'HILOG_ERROR(HILOG_MODULE_SOFTBUS,"%{public}s",secret->value);',
            'HILOG_FATAL(HILOG_MODULE_SOFTBUS,"%{public}s",secret->value);',
            'HILOG_COMM_INFO("%{public}s",secret->value);',
            'HILOG_COMM_WARN("%{public}s",secret->value);',
            'HILOG_COMM_ERROR("%{public}s",secret->value);',
            'HILOG_COMM_FATAL("%{public}s",secret->value);',
            'HiLogDebug(label,"%{public}s",secret->value);',
            'HiLogInfo(label,"%{public}s",secret->value);',
            'HiLogWarn(label,"%{public}s",secret->value);',
            'HiLogError(label,"%{public}s",secret->value);',
            'HiLogFatal(label,"%{public}s",secret->value);',
        )
        for call in public_calls:
            with self.subTest(call=call):
                run=self.analyze('void Callback(SessionKey *secret){'+call+'}')
                self.assertEqual(len(run.findings),1)
                self.assertEqual(run.findings[0].rule_id,'data.log.sensitive-value')
                self.assertEqual(run.findings[0].candidate_cwe,'CWE-532')
                self.assertTrue(run.findings[0].evidence_obligations)
        private_calls=(
            'HILOG_INFO(HILOG_MODULE_SOFTBUS,"%{private}s",secret->value);',
            'HILOG_INFO(HILOG_MODULE_SOFTBUS,"%s",secret->value);',
            'HILOG_COMM_INFO("%{private}s",secret->value);',
            'HiLogInfo(label,"%s",secret->value);',
            'HILOG_INFO(HILOG_MODULE_SOFTBUS,"literal only");',
        )
        for call in private_calls:
            with self.subTest(call=call):
                self.assertEqual(self.analyze('void Callback(SessionKey *secret){'+call+'}').findings,())

    def test_d9_hilog_cases_from_additive_manifest(self):
        cases=json.loads((ROOT/"fixtures/data_sensitive/d9_hilog_cases.json").read_text())
        for case in cases:
            with self.subTest(case=case["id"]):
                text=(ROOT/"fixtures/data_sensitive"/case["file"]).read_text()
                run=self.analyze(text)
                self.assertEqual(len(run.findings),case["expected_candidates"])
                if case["expected_candidates"]:
                    self.assertEqual(run.findings[0].rule_id,"data.log.sensitive-value")
                    self.assertEqual(run.findings[0].candidate_cwe,"CWE-532")
                    self.assertTrue(run.findings[0].evidence_obligations)

    def test_repeat_stable(self):
        text='void Callback(const char *x){ const char *b=x; AUTH_LOGI(0,"%{public}s",b); }'
        self.assertEqual(self.analyze(text),self.analyze(text))

    def test_sensitive_copy_into_modeled_local_member_reaches_public_log(self):
        text='''void Callback(SessionKey *secret) {
            AesGcmCipherKey cipher = {0};
            memcpy_s(cipher.key, sizeof(cipher.key), secret->value, 32);
            HILOG_INFO(HILOG_MODULE_SOFTBUS, "key=%{public}s", cipher.key);
        }'''
        run=self.analyze(text)
        self.assertEqual(len(run.findings),1)
        finding=run.findings[0]
        self.assertEqual(finding.rule_id,'data.log.sensitive-value')
        self.assertIn('memcpy_s -> cipher.key',finding.message)
        self.assertIn('HILOG_INFO public operand 0',finding.message)

    def test_sensitive_copy_to_modeled_local_member_without_log_stays_safe(self):
        text='''void Callback(SessionKey *secret) {
            AesGcmCipherKey cipher = {0};
            memcpy_s(cipher.key, sizeof(cipher.key), secret->value, 32);
            return;
        }'''
        self.assertEqual(self.analyze(text).findings,())

    def test_aliased_pointer_member_copy_retains_unresolved_candidate(self):
        text='''void Callback(SessionKey *secret, AesGcmCipherKey *out) {
            memcpy_s(out->key, sizeof(out->key), secret->value, 32);
        }'''
        run=self.analyze(text)
        self.assertEqual(len(run.findings),1)
        self.assertEqual(run.findings[0].rule_id,'data.sensitive.unresolved-escape')
        self.assertIn('destination whose identity is unresolved',run.findings[0].message)

if __name__=='__main__':unittest.main()

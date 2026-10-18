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
from src.ohscanner.detectors.data.models import ACCESS_TOKEN_SOURCE, SensitiveSourceModel
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
    def test_modeled_sensitive_record_parameters_seed_flow_outside_callback_names(self):
        public = self.analyze('void UnreviewedName(SessionKey *secret){ HILOG_INFO(HILOG_MODULE_SOFTBUS,"%{public}s",secret->value); }')
        self.assertEqual(len(public.findings), 1)
        self.assertIn('SessionKey.value', public.findings[0].message)
        self.assertTrue(any(item.kind == 'source_semantics' for item in public.findings[0].evidence_obligations))

        private = self.analyze('void UnreviewedName(SessionKey *secret){ HILOG_INFO(HILOG_MODULE_SOFTBUS,"%{private}s",secret->value); }')
        self.assertEqual(len(private.findings), 1)
        self.assertTrue(any(item.kind == 'sink_privacy' for item in private.findings[0].evidence_obligations))
        self.assertIn('private operand', private.findings[0].message)
        unrelated = self.analyze('void UnreviewedName(const char *ordinary){ HILOG_INFO(HILOG_MODULE_SOFTBUS,"%{public}s",ordinary); }')
        self.assertEqual(unrelated.findings, ())

    def test_same_named_sensitive_type_conflict_keeps_only_a_candidate(self):
        source = '''typedef struct SessionKey { char value[64]; } SessionKey;
void UnreviewedName(SessionKey *maybe){ HILOG_INFO(HILOG_MODULE_SOFTBUS,"%{public}s",maybe->value); }'''
        run = self.analyze(source)
        self.assertEqual(len(run.findings), 1)
        self.assertTrue(any(item.kind == 'source_semantics' for item in run.findings[0].evidence_obligations))
        self.assertTrue(any(item.kind == 'type_identity' for item in run.findings[0].evidence_obligations))
        self.assertIn('shadowed sensitive record type identity unresolved', ' '.join(run.limitations))
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
            ('TRANS_LOGI(TRANS_CTRL,"%{private}s",secret->value);',1),
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
        privacy_calls=(
            ('HILOG_INFO(HILOG_MODULE_SOFTBUS,"%{private}s",secret->value);',1),
            ('HILOG_INFO(HILOG_MODULE_SOFTBUS,"%s",secret->value);',1),
            ('HILOG_COMM_INFO("%{private}s",secret->value);',1),
            ('HiLogInfo(label,"%s",secret->value);',1),
            ('HILOG_INFO(HILOG_MODULE_SOFTBUS,"literal only");',0),
            ('HILOG_INFO(HILOG_MODULE_SOFTBUS,"%{private}p",secret->value);',0),
        )
        for call,expected in privacy_calls:
            with self.subTest(call=call):
                run=self.analyze('void Callback(SessionKey *secret){'+call+'}')
                self.assertEqual(len(run.findings),expected)
                if expected:
                    self.assertTrue(any(item.kind == 'sink_privacy' for item in run.findings[0].evidence_obligations))

    def test_access_token_profile_is_revision_and_path_bound(self):
        path = 'interfaces/innerkits/accesstoken/src/accesstoken_kit.cpp'
        cases = (
            ('public_sensitive', 'void AccessTokenKit::GetKernelPermissions(AccessTokenID tokenID) {\n'
             ' LOGI(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}u", tokenID);\n}', 1),
            ('private_conditional', 'void AccessTokenKit::GetKernelPermissions(AccessTokenID tokenID) {\n'
             ' LOGI(ATM_DOMAIN, ATM_TAG, "TokenID=%{private}u", tokenID);\n}', 1),
            ('removed_sensitive_log', 'void AccessTokenKit::GetKernelPermissions(AccessTokenID tokenID) {\n'
             ' LOGI(ATM_DOMAIN, ATM_TAG, "operation completed");\n}', 0),
            ('unrelated_value', 'void AccessTokenKit::GetKernelPermissions(AccessTokenID tokenID) {\n'
             ' uint32_t count = 7; LOGI(ATM_DOMAIN, ATM_TAG, "count=%{public}u", count);\n}', 0),
        )

        def analyze_access_token(source, source_path=path, commit=ACCESS_TOKEN_SOURCE.commit):
            data = source.encode()
            units, ast, _ = index_sources((GitSource(
                source_path, 'cpp',
                hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(), data),))
            request = ScanRequest(
                'd-access-token-model', ACCESS_TOKEN_SOURCE.repository, commit,
                snapshot_digest(units), 'current-component:'+ACCESS_TOKEN_SOURCE.repository)
            context = ScanContext(request, units, {'ast': ast})
            return SensitiveExposureDetector(ACCESS_TOKEN_SOURCE).detect(context, units)

        for label, source, expected in cases:
            with self.subTest(label=label):
                run = analyze_access_token(source)
                self.assertEqual(len(run.findings), expected)
                if label in ('public_sensitive', 'private_conditional'):
                    self.assertTrue(run.findings[0].evidence_obligations)
                if label == 'private_conditional':
                    self.assertTrue(any(
                        item.kind == 'sink_privacy'
                        for item in run.findings[0].evidence_obligations))

        self.assertIn('authorization principals', ACCESS_TOKEN_SOURCE.provenance)
        unrelated = analyze_access_token(cases[0][1], source_path='unrelated.cpp')
        self.assertEqual(unrelated.findings, ())
        wrong_commit = analyze_access_token(cases[0][1], commit='f'*40)
        self.assertEqual(wrong_commit.status, 'blocked')

    def test_dsoftbus_reviewed_log_header_families_are_modeled_sinks(self):
        # Format operand positions checked against dfx/interface/include/*_log.h
        # and the nested nstackx/fillp log.h wrappers in the downloaded source.
        calls = (
            ('LNN_LOGE(LNN_LABEL,"key=%{public}s",secret->value);', 1),
            ('CONN_LOGW(CONN_LABEL,"key=%{private}s",secret->value);', 1),
            ('DISC_LOGI(DISC_LABEL,"key=%s",secret->value);', 1),
            ('CONN_CHECK_AND_RETURN_RET_LOGI(false,-1,CONN_LABEL,"key=%{public}s",secret->value);', 1),
            ('DISC_CHECK_AND_RETURN_LOGD(false,DISC_LABEL,"key=%{public}s",secret->value);', 1),
            ('DFILE_LOGE(MODULE,"key=%{public}s",secret->value);', 1),
            ('DFINDER_LOGI(MODULE,"key=%{public}s",secret->value);', 1),
            ('FILLP_LOGERR("key=%{public}s",secret->value);', 1),
        )
        for call, expected in calls:
            with self.subTest(call=call):
                run = self.analyze('void Callback(SessionKey *secret){'+call+'}')
                self.assertEqual(len(run.findings), expected)
                if expected:
                    self.assertEqual(run.findings[0].rule_id, 'data.log.sensitive-value')
                    self.assertTrue(run.findings[0].evidence_obligations)

    def test_hilog_base_header_interfaces_are_modeled_sinks(self):
        # Signatures and macro argument positions verified against hiviewdfx_hilog
        # interfaces/native/innerkits/include/hilog_base/log_base.h.
        calls = (
            ('HILOG_BASE_DEBUG(LOG_CORE,"%{public}s",secret->value);', 1),
            ('HILOG_BASE_INFO(LOG_CORE,"%s",secret->value);', 1),
            ('HILOG_BASE_WARN(LOG_CORE,"%{private}s",secret->value);', 1),
            ('HILOG_BASE_ERROR(LOG_CORE,"%{public}s",secret->value);', 1),
            ('HILOG_BASE_FATAL(LOG_CORE,"%{public}s",secret->value);', 1),
            ('HiLogBasePrint(LOG_CORE,LOG_ERROR,0,"tag","%{public}s",secret->value);', 1),
            ('HiLogBasePrint(LOG_CORE,LOG_ERROR,0,"tag","literal only");', 0),
        )
        for call, expected in calls:
            with self.subTest(call=call):
                run = self.analyze('void Callback(SessionKey *secret){'+call+'}')
                self.assertEqual(len(run.findings), expected)
                if expected:
                    self.assertEqual(run.findings[0].rule_id, 'data.log.sensitive-value')
                    self.assertTrue(run.findings[0].evidence_obligations)

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

    def test_same_named_sensitive_type_known_length_metadata_is_not_secret_material(self):
        source = '''typedef struct SessionKey { char value[64]; unsigned int len; } SessionKey;
void UnreviewedName(SessionKey *maybe){ HILOG_INFO(HILOG_MODULE_SOFTBUS,"%{public}u",maybe->len); }'''
        run = self.analyze(source)
        self.assertEqual(run.findings, ())
        self.assertIn('shadowed sensitive record type identity unresolved', ' '.join(run.limitations))
if __name__=='__main__':unittest.main()

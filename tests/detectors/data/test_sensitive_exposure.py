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
from src.ohscanner.detectors.data.models import (
    ACCESS_TOKEN_SOURCE, DEFAULT_SOURCE, DSOFTBUS_CURRENT_SOURCE, IOTC_LOCAL_CONTROL_SOURCE, SUPPORTED_SOURCE_MODELS, SensitiveSourceModel)
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector, formats, looks_sensitive_name

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

    def analyze_many(self, sources):
        git_sources=[]
        for path,source in sources:
            data=source.encode()
            git_sources.append(GitSource(
                path,'cpp',
                hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),
                data))
        units,ast,_=index_sources(tuple(git_sources))
        units=tuple(sorted(units,key=lambda unit:unit.path))
        request=ScanRequest('d-interfile',MODEL.repository,MODEL.commit,
                            snapshot_digest(units),'current-component:'+MODEL.repository)
        context=ScanContext(request,units,{'ast':ast})
        return SensitiveExposureDetector(MODEL).detect(context,units)
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
    def test_default_detector_dispatches_only_exact_reviewed_profiles(self):
        def analyze(repository, commit, path, source):
            data = source.encode()
            units, ast, _ = index_sources((GitSource(
                path, 'cpp',
                hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(), data),))
            request = ScanRequest(repository, repository, commit, snapshot_digest(units),
                                  'current-component:'+repository)
            context = ScanContext(request, units, {'ast': ast})
            return SensitiveExposureDetector().detect(context, units)

        dsoftbus = analyze(
            DEFAULT_SOURCE.repository, DEFAULT_SOURCE.commit,
            'core/authentication/src/auth_hichain.c',
            'void OnSessionKeyReturned(int64_t authSeq, const uint8_t *sessionKey, uint32_t len) { '
            'HILOG_INFO(HILOG_MODULE_SOFTBUS,"%{public}s",sessionKey); }')
        access_token = analyze(
            ACCESS_TOKEN_SOURCE.repository, ACCESS_TOKEN_SOURCE.commit,
            'interfaces/innerkits/accesstoken/src/accesstoken_kit.cpp',
            'void AccessTokenKit::GetKernelPermissions(AccessTokenID tokenID) { '
            'LOGI(ATM_DOMAIN, ATM_TAG, "TokenID=%{public}u", tokenID); }')
        dsoftbus_current = analyze(
            DSOFTBUS_CURRENT_SOURCE.repository, DSOFTBUS_CURRENT_SOURCE.commit,
            'core/authentication/src/auth_hichain.c',
            'void OnSessionKeyReturned(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen) { '
            'AUTH_LOGI(AUTH_HICHAIN, "key=%{public}s", sessionKey); }')
        dsoftbus_current_safe = analyze(
            DSOFTBUS_CURRENT_SOURCE.repository, DSOFTBUS_CURRENT_SOURCE.commit,
            'core/authentication/src/auth_hichain.c',
            'void OnSessionKeyReturned(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen) { '
            'AUTH_LOGI(AUTH_HICHAIN, "len=%{public}u", sessionKeyLen); }')
        self.assertEqual(len(dsoftbus.findings), 1)
        self.assertEqual(len(access_token.findings), 1)
        self.assertEqual(len(dsoftbus_current.findings), 1)
        self.assertEqual(len(dsoftbus_current_safe.findings), 0)
        self.assertEqual(len(dsoftbus.findings[0].source_sha256), 64)
        self.assertEqual(len(access_token.findings[0].source_sha256), 64)
        self.assertNotEqual(dsoftbus.findings[0].source_sha256,
                            access_token.findings[0].source_sha256)
        self.assertTrue(any(model.repository == DEFAULT_SOURCE.repository for model in SUPPORTED_SOURCE_MODELS))
        self.assertTrue(any(model.repository == ACCESS_TOKEN_SOURCE.repository for model in SUPPORTED_SOURCE_MODELS))
        self.assertTrue(any(model.repository == DSOFTBUS_CURRENT_SOURCE.repository and
                            model.commit == DSOFTBUS_CURRENT_SOURCE.commit
                            for model in SUPPORTED_SOURCE_MODELS))

        unknown = analyze(DEFAULT_SOURCE.repository, 'f'*40,
                          'core/authentication/src/auth_hichain.c',
                          'void OnSessionKeyReturned(int64_t authSeq, const uint8_t *sessionKey, uint32_t len) { '
                          'HILOG_INFO(HILOG_MODULE_SOFTBUS,"%{public}s",sessionKey); }')
        self.assertEqual(unknown.status, 'blocked')
        self.assertEqual(len(unknown.findings), 1)
        self.assertIn('heuristic suspected sensitive identifier sessionKey', unknown.findings[0].message)
        self.assertIn('No reviewed sensitive-source model', ' '.join(unknown.limitations))

    def test_unknown_revision_keeps_name_based_sensitive_log_candidate_without_confirmation(self):
        source = '''void dump(const char *sessionKey) {
            HILOG_INFO(HILOG_MODULE_SOFTBUS, "%{public}s", sessionKey);
        }'''
        c = self.context(source)
        run = SensitiveExposureDetector().detect(c, c.units)
        self.assertEqual(run.status, 'blocked')
        self.assertEqual(dict(run.file_outcomes)['service.cpp'], 'partial')
        self.assertEqual(len(run.findings), 1)
        finding = run.findings[0]
        self.assertEqual(finding.rule_id, 'data.log.sensitive-value')
        self.assertEqual(finding.candidate_cwe, 'CWE-532')
        self.assertEqual(finding.source_sha256, c.units[0].sha256)
        self.assertIn('heuristic suspected sensitive identifier sessionKey', finding.message)
        self.assertTrue(any(item.kind == 'source_semantics' and 'Unreviewed' in item.description
                            for item in finding.evidence_obligations))
        self.assertIn('heuristic candidates are incomplete', ' '.join(run.limitations))

    def test_cross_file_unique_helper_reaches_public_log_sink(self):
        run=self.analyze_many((
            ('service.cpp','void Callback(const char *key) { relay(key); }'),
            ('logging.cpp','void relay(const char *value) { HILOG_INFO(1,"%{public}s",value); }'),
        ))
        self.assertEqual(len(run.findings),1)
        finding=run.findings[0]
        self.assertEqual(finding.file,'logging.cpp')
        self.assertEqual(finding.rule_id,'data.log.sensitive-value')
        self.assertIn('service.cpp:1 source Callback parameter 0',finding.message)
        self.assertIn('call relay argument 0',finding.message)
        self.assertIn('HILOG_INFO public operand 0',finding.message)
        self.assertEqual(run.status,'blocked')
        self.assertTrue(all(state=='partial' for _,state in run.file_outcomes))

    def test_cross_file_helper_return_reaches_caller_sink(self):
        run=self.analyze_many((
            ('service.cpp','void Callback(const char *key) { const char *copy = relay(key); HILOG_INFO(1,"%{public}s",copy); }'),
            ('relay.cpp','const char *relay(const char *value) { return value; }'),
        ))
        self.assertEqual(len(run.findings),1)
        self.assertEqual(run.findings[0].file,'service.cpp')
        self.assertEqual(run.findings[0].rule_id,'data.log.sensitive-value')
        self.assertIn('call relay argument 0',run.findings[0].message)
        self.assertIn('return from relay',run.findings[0].message)
        self.assertEqual(run.status,'blocked')

    def test_cross_file_local_sink_name_is_not_credited_without_body_binding(self):
        run=self.analyze_many((
            ('service.cpp','void Callback(const char *key) { HILOG_INFO(1,"%{public}s",key); }'),
            ('logger.cpp','void HILOG_INFO(int tag, const char *format, const char *value) { (void)tag; (void)format; (void)value; }'),
        ))
        self.assertEqual(len(run.findings),1)
        self.assertEqual(run.findings[0].rule_id,'data.sensitive.unresolved-escape')
        self.assertNotIn('data.log.sensitive-value',
                         {finding.rule_id for finding in run.findings})
        self.assertIn('helper body did not establish',run.findings[0].message)
        self.assertEqual(run.status,'blocked')

    def test_cross_file_ambiguous_helper_preserves_candidate_without_crediting_sink(self):
        run=self.analyze_many((
            ('service.cpp','void Callback(const char *key) { relay(key); }'),
            ('a.cpp','void relay(const char *value) { HILOG_INFO(1,"%{public}s",value); }'),
            ('b.cpp','void relay(const char *value) { (void)value; }'),
        ))
        self.assertEqual(len(run.findings),1)
        self.assertEqual(run.findings[0].rule_id,'data.sensitive.unresolved-escape')
        self.assertNotIn('data.log.sensitive-value',
                         {finding.rule_id for finding in run.findings})
        self.assertIn('ambiguous',run.findings[0].message)
        self.assertEqual(run.status,'blocked')

    def test_wifi_log_macro_detects_preshared_key_candidate(self):
        source = 'void dump(const char *preSharedKey) { WIFI_LOGI("%{public}s", preSharedKey); }'
        c = self.context(source)
        run = SensitiveExposureDetector().detect(c, c.units)
        findings = [item for item in run.findings if item.rule_id == 'data.log.sensitive-value']
        self.assertEqual(1, len(findings))
        self.assertIn('WIFI_LOGI public operand', findings[0].message)
        self.assertEqual('CWE-532', findings[0].candidate_cwe)
        self.assertEqual(run.status, 'blocked')

    def test_switch_subtree_preserves_sensitive_wifi_log_candidate(self):
        source = '''void parse(int mode, const char *preSharedKey) {
            switch (mode) {
                case 1:
                    WIFI_LOGI("PreSharedKey is %{public}s", preSharedKey);
                    break;
                default:
                    break;
            }
        }'''
        c = self.context(source)
        run = SensitiveExposureDetector().detect(c, c.units)
        findings = [item for item in run.findings if item.rule_id == 'data.log.sensitive-value']
        self.assertEqual(1, len(findings))
        self.assertEqual(4, findings[0].line)
        self.assertEqual('CWE-532', findings[0].candidate_cwe)
        self.assertEqual(run.status, 'blocked')
        self.assertTrue(any('switch_statement' in gap and 'may-flow' in gap
                            for gap in run.limitations))

    def test_unknown_revision_heuristic_fixed_safe_and_identifier_controls(self):
        cases = (
            ('positive', 'void f(const char *password) { HILOG_ERROR(1,"%{public}s",password); }', 1),
            ('removed_log', 'void f(const char *password) { (void)password; }', 0),
            ('ordinary', 'void f(unsigned keyCount) { HILOG_INFO(1,"%{public}u",keyCount); }', 0),
            ('principal_id', 'void f(unsigned accessTokenID) { HILOG_INFO(1,"%{public}u",accessTokenID); }', 0),
        )
        for label, source, expected in cases:
            with self.subTest(label=label):
                c = self.context(source)
                run = SensitiveExposureDetector().detect(c, c.units)
                self.assertEqual(run.status, 'blocked')
                self.assertEqual(len(run.findings), expected)
                self.assertEqual(dict(run.file_outcomes)['service.cpp'], 'partial')

    def test_unknown_revision_heuristic_tracks_secret_field_and_api_return(self):
        cases = (
            'void f(User *user) { HILOG_INFO(1,"%{public}s",user->password); }',
            'void f() { const char *credential = getCredential(); HILOG_INFO(1,"%{public}s",credential); }',
        )
        for source in cases:
            with self.subTest(source=source):
                c = self.context(source)
                run = SensitiveExposureDetector().detect(c, c.units)
                self.assertEqual(run.status, 'blocked')
                self.assertEqual(len(run.findings), 1)
                self.assertEqual(dict(run.file_outcomes)['service.cpp'], 'partial')

    def test_heuristic_name_classifier_avoids_token_id_but_keeps_secret_shapes(self):
        for value in ('sessionKey', 'private_key', 'password', 'clientSecret', 'accessToken', 'API_KEY'):
            with self.subTest(value=value):
                self.assertTrue(looks_sensitive_name(value))
        for value in ('accessTokenID', 'FullTokenIdentifier', 'keyCount', 'keyboard', 'ordinary',
                      'HTTP_API_KEY_FETCH', 'WSI_TOKEN_HTTP', 'token'):
            with self.subTest(value=value):
                self.assertFalse(looks_sensitive_name(value))
        for value in ('passwordId', 'encryptedPassword.length', 'PASSWORD_NO_HIDDEN_LEN',
                      'PASSWORD_ALLOWED_SPECIAL', 'SEC_ASSET_TAG_SECRET', 'keyBytes.size',
                      'passwordCount', 'passwordType'):
            with self.subTest(value=value):
                self.assertFalse(looks_sensitive_name(value))
        for value in ('PreSharedKey', 'pre_shared_key', 'PassWordAnonymize', 'PSK'):
            with self.subTest(value=value):
                self.assertTrue(looks_sensitive_name(value))

    def test_unknown_profile_recognizes_preshared_key_with_password_casing(self):
        source = '\n'.join((
            'std::string PassWordAnonymize(const std::string value) { return value; }',
            'void dump(Config config) {',
            '    HILOG_INFO(1, "%{public}s", PassWordAnonymize(config.preSharedKey).c_str());',
            '}',
        ))
        c = self.context(source)
        run = SensitiveExposureDetector().detect(c, c.units)
        findings = [item for item in run.findings if item.rule_id == 'data.log.sensitive-value']
        self.assertEqual(1, len(findings))
        self.assertIn('PassWordAnonymize', findings[0].message)
        self.assertEqual(run.status, 'blocked')

    def test_partial_unknown_revision_retains_heuristic_candidate_as_blocked(self):
        source = 'void f(const char *secret) { HILOG_INFO(1,"%{public}s",secret); }'
        c = self.context(source, partial='partial')
        run = SensitiveExposureDetector().detect(c, c.units)
        self.assertEqual(run.status, 'blocked')
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(dict(run.file_outcomes)['service.cpp'], 'partial')

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

    def test_hilog_public_c_macros_and_message_apis_are_modeled_sinks(self):
        for level in ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'):
            with self.subTest(sink='OH_LOG_' + level):
                run = self.analyze(
                    'void f(SessionKey *secret) { '
                    'OH_LOG_' + level + '(LOG_APP, "%{public}s", secret->value); }')
                self.assertEqual(len(run.findings), 1)
                self.assertEqual(run.findings[0].rule_id, 'data.log.sensitive-value')

        message = self.analyze(
            'void f(SessionKey *secret) { '
            'OH_LOG_PrintMsg(LOG_APP, LOG_INFO, 1, "tag", secret->value); }')
        self.assertEqual(len(message.findings), 1)

        message_by_len = self.analyze(
            'void f(SessionKey *secret, size_t n) { '
            'OH_LOG_PrintMsgByLen(LOG_APP, LOG_INFO, 1, "tag", 3, secret->value, n); }')
        self.assertEqual(len(message_by_len.findings), 1)

        unrelated = self.analyze(
            'void f(const char *ordinary) { '
            'OH_LOG_DEBUG(LOG_APP, "%{public}s", ordinary); '
            'OH_LOG_PrintMsg(LOG_APP, LOG_INFO, 1, "tag", ordinary); }')
        self.assertEqual(unrelated.findings, ())
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
    def test_iotc_pinned_derived_key_to_public_log_and_controls(self):
        path = 'core/wifi/application/local_control/local_ctl_coap_api.c'
        repository = IOTC_LOCAL_CONTROL_SOURCE.repository
        commit = IOTC_LOCAL_CONTROL_SOURCE.commit
        vulnerable = '''
int32_t localCtlSessKeyGen(void *param) {
    IotcPkcs5Pbkdf2Hmac(param, localCtlKey, 16);
    UtilsHexify(localCtlKey, sizeof(localCtlKey), localCtlKeyStr, sizeof(localCtlKeyStr));
    IOTC_LOGI("%s localCtlKey:[%s]", __func__, localCtlKeyStr);
    return 0;
}
'''
        def run(source, revision=commit):
            data = source.encode()
            units, ast, _ = index_sources((GitSource(
                path, 'c',
                hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(),
                data),))
            request = ScanRequest(repository, repository, revision,
                                  snapshot_digest(units), 'current-component:' + repository)
            return SensitiveExposureDetector().detect(
                ScanContext(request, units, {'ast': ast}), units)

        finding_run = run(vulnerable)
        self.assertEqual(len(finding_run.findings), 1)
        finding = finding_run.findings[0]
        self.assertEqual(finding.rule_id, 'data.log.sensitive-value')
        self.assertEqual(finding.symbol, 'localCtlSessKeyGen')
        self.assertIn('IotcPkcs5Pbkdf2Hmac output argument 1', finding.message)
        self.assertIn('UtilsHexify -> localCtlKeyStr', finding.message)
        self.assertIn('IOTC_LOGI', finding.message)
        self.assertEqual(finding.message.count('Candidate local sensitive-material dependency:'), 1)
        self.assertTrue(any(item.kind == 'security_impact'
                            for item in finding.evidence_obligations))

        fixed = vulnerable.replace(
            '    IOTC_LOGI("%s localCtlKey:[%s]", __func__, localCtlKeyStr);\n',
            '')
        self.assertEqual(run(fixed).findings, ())
        unrelated = '''
int32_t localCtlSessKeyGen(void *param) {
    IotcPkcs5Pbkdf2Hmac(param, localCtlKey, 16);
    UtilsHexify(publicIdentifier, sizeof(publicIdentifier), publicHex, sizeof(publicHex));
    IOTC_LOGI("%s id:[%s]", __func__, publicHex);
    return 0;
}
'''
        self.assertEqual(run(unrelated).findings, ())
        self.assertEqual(run(vulnerable, revision='f' * 40).findings, ())
        mismatch = run(vulnerable.replace(
            'IotcPkcs5Pbkdf2Hmac(param, localCtlKey, 16);',
            'IotcPkcs5Pbkdf2Hmac(param, localCtlKey);'))
        self.assertEqual(mismatch.findings, ())
        self.assertTrue(any('source API argument count unresolved' in item
                            for item in mismatch.limitations))

if __name__=='__main__':unittest.main()

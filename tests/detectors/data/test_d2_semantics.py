import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tests.detectors.data import test_sensitive_exposure as support
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector

ROOT=Path(__file__).resolve().parents[3]

class D2SemanticsTests(unittest.TestCase):
    def test_d2_control_groups(self):
        cases=json.loads((ROOT/'tests/fixtures/data_sensitive/d2_cases.json').read_text())
        d5=json.loads((ROOT/'tests/fixtures/data_sensitive/d5_cases.json').read_text())
        overrides={case['id']:case for case in d5}
        for case in cases:
            with self.subTest(case=case['id']):
                text=(ROOT/'tests/fixtures/data_sensitive'/case['file']).read_text()
                context=support.SensitiveTests().context(text)
                run=SensitiveExposureDetector(support.MODEL).detect(context,context.units)
                self.assertEqual(len(run.findings),overrides.get(case['id'],case)['expected_candidates'])
                if case['requires_partial']:
                    self.assertNotEqual(dict(run.file_outcomes)['service.cpp'],'complete')
    def test_same_file_helper_expansion_preserves_argument_return_and_out_flows(self):
        cases=(
            ('argument to helper sink',
             'void emit(const char *v){AUTH_LOGI(0,"%{public}s",v);} '
             'void Callback(const char *s){emit(s);}',1),
            ('returned sensitive argument',
             'const char *identity(const char *v){return v;} '
             'void Callback(const char *s){AUTH_LOGI(0,"%{public}s",identity(s));}',1),
            ('pointer output from sensitive argument',
             'void format(char *out,const char *v){snprintf(out,64,"%{public}s",v);} '
             'void Callback(const char *s){char out[64];format(out,s);AUTH_LOGI(0,"%{public}s",out);}',1),
            ('modeled source through pointer output',
             'void create(char *out){SoftBusGenerateSessionKey(out,32);} '
             'void Callback(const char *unused){char out[64];create(out);AUTH_LOGI(0,"%{public}s",out);}',1),
            ('modeled output through address-of local',
             'void Callback(const char *unused){char out[64];SoftBusGenerateSessionKey(&out,32);AUTH_LOGI(0,"%{public}s",out);}',1),
            ('constant helper argument remains safe',
             'void emit(const char *v){AUTH_LOGI(0,"%{public}s",v);} '
             'void Callback(const char *s){emit("literal");}',0),
        )
        for label,source,expected in cases:
            with self.subTest(case=label):
                run=support.SensitiveTests().analyze(source)
                self.assertEqual(len(run.findings),expected)
                if expected:
                    self.assertTrue(any('return from' in finding.message
                                        or 'may write through argument' in finding.message
                                        or 'output argument' in finding.message
                                        or 'call emit argument' in finding.message
                                        for finding in run.findings))

    def test_unresolved_sensitive_boundaries_remain_candidates_for_agent_review(self):
        cases=(
            ('external helper escape',
             'void Callback(const char *secret){ForwardToLog(secret);}',
             'data.sensitive.unresolved-escape','callee_binding'),
            ('dynamic logging format',
             'void Callback(const char *secret){AUTH_LOGI(0,GetFormat(),secret);}',
             'data.log.sensitive-value','format_resolution'),
            ('ambiguous same-file overload',
             'void emit(const char *v){AUTH_LOGI(0,"%{public}s",v);} '
             'void emit(char *v){} '
             'void Callback(const char *secret){emit(secret);}',
             'data.log.sensitive-value',None),
            ('recursive same-file helper',
             'void relay(const char *v){relay(v);} '
             'void Callback(const char *secret){relay(secret);}',
             'data.sensitive.unresolved-escape','callee_binding'),
            ('sensitive copy into unresolved member destination',
             'struct State { char *out; }; '
             'void Callback(SessionKey *secret,State *state){memcpy_s(state->out,64,secret->value,32);}',
             'data.sensitive.unresolved-escape','destination_binding'),
            ('sensitive formatting into unresolved member destination',
             'struct State { char *out; }; '
             'void Callback(SessionKey *secret,State *state){snprintf(state->out,64,"%{public}s",secret->value);}',
             'data.sensitive.unresolved-escape','destination_binding'),
            ('modeled source with unresolved member destination',
             'struct State { char *out; }; '
             'void Callback(State *state){SoftBusGenerateSessionKey(state->out,32);}',
             'data.sensitive.unresolved-escape','destination_binding'),
            ('sensitive formatting with unresolved runtime format',
             'void Callback(SessionKey *secret){char out[64];snprintf(out,64,GetFormat(),secret->value);}',
             'data.sensitive.unresolved-escape','format_resolution'),
        )
        for label,source,rule,obligation in cases:
            with self.subTest(case=label):
                run=support.SensitiveTests().analyze(source)
                matches=[finding for finding in run.findings if finding.rule_id==rule]
                self.assertTrue(matches)
                if obligation:
                    self.assertTrue(any(any(item.kind==obligation
                                            for item in finding.evidence_obligations)
                                        for finding in matches))
                if rule=='data.sensitive.unresolved-escape':
                    self.assertTrue(all(finding.candidate_cwe is None for finding in matches))
                    from src.ohscanner.runner import DetectorRegistry,run_all_with_coverage
                    context=support.SensitiveTests().context(source)
                    registry=DetectorRegistry()
                    registry.register(SensitiveExposureDetector(support.MODEL))
                    reports,sidecar=run_all_with_coverage(context,registry)
                    public=[item for item in reports[0].diagnostics
                            if item.rule_id==rule]
                    self.assertTrue(public)
                    self.assertTrue(all(item.confidence=='unassessed'
                                        and item.source_sha256==context.units[0].sha256
                                        for item in public))
                    self.assertTrue(sidecar['detectors'][SensitiveExposureDetector.detector_id]
                                    ['evidence_obligations'])

    def test_cm_log_macro_family_models_format_operands_and_same_file_shadow(self):
        public = support.SensitiveTests().analyze(
            'void Callback(SessionKey *s){CM_LOG_E("%s",s->value);}')
        self.assertEqual(len(public.findings), 1)
        self.assertEqual(public.findings[0].rule_id, 'data.log.sensitive-value')
        self.assertIn('CM_LOG_E', public.findings[0].message)
        self.assertIn('public operand', public.findings[0].message)

        private = support.SensitiveTests().analyze(
            'void Callback(SessionKey *s){CM_LOG_W("%{private}s",s->value);}')
        self.assertEqual(len(private.findings), 1)
        self.assertEqual(private.findings[0].rule_id, 'data.log.sensitive-value')
        self.assertTrue(any(item.kind == 'format_resolution'
                            for item in private.findings[0].evidence_obligations))
        self.assertIn('formatting prevents privacy-slot resolution', private.findings[0].message)

        debug = support.SensitiveTests().analyze(
            'void Callback(SessionKey *s){CM_LOG_D("%s",s->value);}')
        self.assertEqual(len(debug.findings), 1)
        self.assertEqual(debug.findings[0].rule_id, 'data.log.sensitive-value')
        self.assertTrue(any(item.kind == 'runtime_log_visibility'
                            for item in debug.findings[0].evidence_obligations))

        metadata = support.SensitiveTests().analyze(
            'void Callback(SessionKey *s){CM_LOG_I("%{public}u",s->len);}')
        self.assertEqual(metadata.findings, ())

        shadowed = support.SensitiveTests().analyze(
            'void CM_LOG_E(const char *message) { } '
            'void Callback(SessionKey *s){CM_LOG_E(s->value);}')
        self.assertEqual(shadowed.findings, ())
        self.assertTrue(any('visible empty body' in item
                            for item in shadowed.limitations))

    def test_object_property_escape_keeps_candidate_but_not_status_taint(self):
        source = (
            'struct Env { int Object_SetPropertyByName_Ref(const char *, const char *); }; '
            'void Callback(SessionKey *s, Env *env){ '
            'int status = env->Object_SetPropertyByName_Ref("credential", s->value); '
            'CM_LOG_E("%d", status); }')
        run = support.SensitiveTests().analyze(source)
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].rule_id, 'data.sensitive.unresolved-escape')
        self.assertIn('Object_SetPropertyByName_Ref', run.findings[0].message)
        self.assertNotIn('CM_LOG_E', run.findings[0].message)

    def test_modeled_status_return_does_not_retaint_logged_status(self):
        source = (
            'void Callback(SessionKey *s){ '
            'int status = AniUtils::GenerateCredentialObj(env, s->value); '
            'CM_LOG_E("%d", status); }')
        run = support.SensitiveTests().analyze(source)
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].rule_id, 'data.sensitive.unresolved-escape')
        self.assertIn('GenerateCredentialObj', run.findings[0].message)
        self.assertNotIn('CM_LOG_E', run.findings[0].message)

    def test_same_owner_unqualified_method_uses_its_body_before_tainting_return(self):
        source = (
            'struct SessionKey { const char *value; }; '
            'class Builder { public: int helper(const char *); int run(SessionKey *); }; '
            'int Builder::helper(const char *secret) { return 0; } '
            'int Builder::run(SessionKey *s) { int status = helper(s->value); '
            'CM_LOG_E("%d", status); return status; }')
        run = support.SensitiveTests().analyze(source)
        self.assertEqual(run.findings, ())
        self.assertFalse(any('same-owner unqualified method call is ambiguous'
                             in item for item in run.limitations))

    def test_unrelated_member_write_does_not_create_sensitive_candidate(self):
        source=('struct State { char *out; }; '
                'void Callback(State *state){const char *ordinary="safe";memcpy_s(state->out,64,ordinary,32);}')
        run=support.SensitiveTests().analyze(source)
        self.assertEqual(run.findings,())

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
        samples=(
            ('int strcpy_s(char *d,int n,const char *s){return 0;} void Callback(const char *s){char out[64];strcpy_s(out,64,s);AUTH_LOGI(0,"%{public}s",out);}', 'strcpy_s'),
            ('int memcpy_s(char *d,int n,const char *s,int count){return 0;} void Callback(const char *s){char out[64];memcpy_s(out,64,s,8);AUTH_LOGI(0,"%{public}s",out);}', 'memcpy_s'),
        )
        for text,name in samples:
            with self.subTest(name=name):
                c=support.SensitiveTests().context(text)
                run=SensitiveExposureDetector(support.MODEL).detect(c,c.units)
                self.assertEqual(len(run.findings),1);self.assertEqual(run.status,'blocked')
                self.assertIn('unresolved '+name+' may write',run.findings[0].message)

    def test_d5_replay_missing_local_object_fails_closed_offline(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'blocked.json'
            command=[sys.executable,str(ROOT/'research/data_sensitive/d5_replay.py'),
                '--repository','openharmony/communication_dsoftbus','--commit','f'*40,
                '--local-git-store',str(ROOT),'--model-version','0.2.0-historical.1',
                '--parser-profile','offline-test','--build-profile','source-only',
                '--target','core/transmission/trans_channel/tcp_direct/src/trans_tcp_direct_message.c',
                '--output',str(output)]
            result=subprocess.run(command,capture_output=True,text=True,timeout=10)
            record=json.loads(output.read_text())
            self.assertEqual(result.returncode,2)
            self.assertEqual(record['status'],'blocked')
            self.assertEqual(record['network_access'],'not attempted')
            self.assertEqual(record['head_switch'],'not attempted')

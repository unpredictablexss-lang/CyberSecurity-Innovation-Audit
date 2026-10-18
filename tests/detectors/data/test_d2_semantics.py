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

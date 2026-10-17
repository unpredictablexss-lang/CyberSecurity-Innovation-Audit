"""D3 design controls, never claimed as independent holdout or upstream code."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from src.ohscanner.detectors.data.historical import (
    HistoricalSourceModel, HistoricalLocalFlow, HistoricalSensitiveExposureDetector, historical_model)

ROOT=Path(__file__).resolve().parents[3]
HEADER='static int DecryptMessage(int channelId, int flags, MsgCryptInfo *p) { return SOFTBUS_OK; }\n'
PREFIX='MsgCryptInfo info = {0}; info.out = (char *)SoftBusCalloc(128); if (info.out == NULL) { return; } '
SUCCESS='if (DecryptMessage(1, 0, &info) != SOFTBUS_OK) { return; } '
SINK='SoftBusLog(0, 3, "%s", info.out);'

def context(source):
    data=source.encode(); blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
    units,ast,_=index_sources((GitSource('service.c','c',blob,data),))
    p=dict(historical_model('d33177135ec6c6aaf4a4c42de1f6878652b330e3').profile)
    p.update(profile_id='synthetic-D3-controls',repository='fixture/d3',commit='d'*40,target_file='service.c',
        required_files=[{'file':'service.c','sha256':hashlib.sha256(data).hexdigest()}],
        source_semantics='Synthetic source summary for design controls, not a real vulnerability')
    model=HistoricalSourceModel('fixture/d3','d'*40,fields=(),output_calls=(),parameters=(),provenance=p['source_semantics'],profile=p)
    req=ScanRequest('d3-control',model.repository,model.commit,snapshot_digest(units),'current-component:'+model.repository)
    return ScanContext(req,units,{'ast':ast}),model

def analyze(body, header=HEADER):
    c,m=context(header+'void ProcessReceivedData(void) { '+body+' }')
    return HistoricalSensitiveExposureDetector(m).detect(c,c.units)

class D3HistoricalTests(unittest.TestCase):
    def test_design_control_matrix(self):
        for case in json.loads((ROOT/'tests/fixtures/data_sensitive/d3_cases.json').read_text()):
            with self.subTest(case=case['id']):
                run=analyze(case['body'],case.get('header',HEADER))
                self.assertEqual(len(run.findings),case['expected_candidates'])

    def test_wrong_version_never_auto_selected(self):
        with self.assertRaises(ValueError):historical_model('f'*40)

    def test_old_default_model_and_controls_unchanged(self):
        from src.ohscanner.detectors.data.models import DSOFTBUS_COMMIT, SOURCE_MODEL_VERSION
        self.assertEqual(DSOFTBUS_COMMIT,'0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132')
        self.assertEqual(SOURCE_MODEL_VERSION,'0.1.0')
        frozen=json.loads((ROOT/'research/data_sensitive/D3_BASELINE.json').read_text())
        for path,digest in frozen['existing_control_sha256'].items():
            self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),digest,path)

    def test_missing_dependency_blocks_real_model(self):
        c,_=context('void ProcessReceivedData(void) {}')
        model=historical_model('d33177135ec6c6aaf4a4c42de1f6878652b330e3')
        c=replace(c,request=replace(c.request,repository=model.repository,commit=model.commit,target_id='current-component:'+model.repository))
        result=HistoricalSensitiveExposureDetector(model).detect(c,c.units)
        self.assertEqual(result.findings,());self.assertIn('missing or mismatched',result.limitations[0])

    def test_source_bytes_mismatch_cannot_use_claimed_hash(self):
        c,m=context(HEADER+'void ProcessReceivedData(void) { '+PREFIX+SUCCESS+SINK+' }')
        text=c.units[0].text+'\n// modified bytes'
        with self.assertRaises(ValueError):
            replace(c.units[0],text=text)
        bad=replace(c.units[0],text=text,sha256=hashlib.sha256(text.encode()).hexdigest())
        c=replace(c,units=(bad,))
        self.assertEqual(HistoricalSensitiveExposureDetector(m).detect(c,c.units).findings,())

    def test_public_runner_retains_partial_candidate_and_obligations(self):
        c,m=context(HEADER+'void ProcessReceivedData(void) { '+PREFIX+SUCCESS+SINK+' }')
        reg=DetectorRegistry();reg.register(HistoricalSensitiveExposureDetector(m))
        reports,coverage=run_all_with_coverage(c,reg)
        self.assertEqual(len(reports[0].diagnostics),1)
        d=reports[0].diagnostics[0]
        self.assertEqual(d.source_sha256,c.units[0].sha256);self.assertEqual(d.confidence,'unassessed')
        side=coverage['detectors'][HistoricalSensitiveExposureDetector.detector_id]
        self.assertTrue(side['evidence_obligations'])
        self.assertEqual(side['coverage_counts']['partial'],1)

    def test_public_runner_does_not_admit_parse_partial(self):
        c,m=context(HEADER+'void ProcessReceivedData(void) { '+PREFIX+SUCCESS+SINK+' }')
        bad=replace(c.units[0],parse_status='partial')
        facts={'ast':{'service.c':dict(c.shared_facts['ast']['service.c'],parse_status='partial')}}
        c=replace(c,units=(bad,),shared_facts=facts)
        reg=DetectorRegistry();reg.register(HistoricalSensitiveExposureDetector(m))
        reports,coverage=run_all_with_coverage(c,reg)
        self.assertEqual(len(reports[0].diagnostics),0)
        self.assertEqual(coverage['detectors'][HistoricalSensitiveExposureDetector.detector_id]['coverage_counts']['not_analyzed'],1)

    def test_private_default_format_semantics_remain_distinct(self):
        from src.ohscanner.detectors.data.sensitive_exposure import formats
        self.assertEqual(formats('%s')[0][0][0],'private')
        self.assertEqual(formats('%s','public')[0][0][0],'public')

    def test_repeat_identity_stable(self):
        body=PREFIX+SUCCESS+SINK
        self.assertEqual(analyze(body),analyze(body))

if __name__=='__main__':unittest.main()

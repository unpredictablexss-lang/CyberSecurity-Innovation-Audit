"""Synthetic semantic regressions, not historical recall claims."""
import hashlib
import json
from pathlib import Path
import unittest
from src.parser.ast import parse_source
from src.ohscanner.contracts import SourceUnit, ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.detectors.interface.models import IpcPolicy

BASE=Path(__file__).parent/'fixtures/ipc'

def context(text, path='sample.cpp'):
    index=parse_source(text,language='cpp')
    unit=SourceUnit(path,'cpp',text,hashlib.sha256(text.encode()).hexdigest(),index.parse_status)
    request=ScanRequest('ipc-test','fixture/ipc','synthetic-ipc-v1',snapshot_digest((unit,)),'current-component:fixture/ipc')
    return ScanContext(request,(unit,),{'ast':{path:index.to_dict()}})

class IpcDetectorTests(unittest.TestCase):
    def test_synthetic_semantic_matrix(self):
        for item in json.loads((BASE/'manifest.json').read_text()):
            with self.subTest(sample=item['sample_id']):
                ctx=context((BASE/item['file']).read_text())
                run=IpcInterfaceDetector().detect(ctx,ctx.units)
                self.assertEqual(run.status,'completed')
                rules={f.rule_id for f in run.findings}
                if item['expected_rule']:
                    self.assertIn(item['expected_rule'],rules)
                else:
                    self.assertEqual(rules,set())

    def test_contract_bridge_and_obligations(self):
        ctx=context((BASE/'auth_positive.cpp').read_text())
        registry=DetectorRegistry();registry.register(IpcInterfaceDetector())
        reports,sidecar=run_all_with_coverage(ctx,registry)
        self.assertEqual(reports[0].status,'completed')
        self.assertTrue(reports[0].diagnostics)
        self.assertEqual(reports[0].diagnostics[0].confidence,'unassessed')
        self.assertTrue(sidecar['detectors']['ohscanner.interface.ipc']['evidence_obligations'])

    def test_partial_is_blocked_not_empty_success(self):
        ctx=context('int Stub::OnRemoteRequest( {')
        registry=DetectorRegistry();registry.register(IpcInterfaceDetector())
        reports,sidecar=run_all_with_coverage(ctx,registry)
        self.assertEqual(reports[0].status,'blocked')
        self.assertEqual(sidecar['detectors']['ohscanner.interface.ipc']['status'],'partial')

    def test_missing_shared_ast_blocks_direct_use(self):
        ctx=context((BASE/'auth_positive.cpp').read_text())
        ctx=ScanContext(ctx.request,ctx.units,{})
        self.assertEqual(IpcInterfaceDetector().detect(ctx,ctx.units).status,'blocked')

    def test_permission_binding_policy(self):
        ctx=context((BASE/'auth_fixed.cpp').read_text())
        policy=IpcPolicy(expected_permissions=(('StartAbility','"ohos.permission.OTHER"'),))
        run=IpcInterfaceDetector(policy).detect(ctx,ctx.units)
        self.assertIn('ipc.auth.missing',{f.rule_id for f in run.findings})

    def test_format_models_preserve_original_offsets(self):
        from src.ohscanner.detectors.interface.analysis import normalize_syntax
        raw=b'LOG("id=%" PRIu64 "", id); (this->*handler)(data,reply); // PRIu64\n'
        normalized=normalize_syntax(raw)
        self.assertEqual(len(raw),len(normalized))
        self.assertEqual(raw.count(b'\n'),normalized.count(b'\n'))
        self.assertIn(b'// PRIu64',normalized)
        self.assertIn(b'(this-> handler)',normalized)

    def test_transport_position_bound_pair(self):
        before='bool HitraceInvoker::TraceServerReceieve(int h, uint32_t c, Parcel &data, uint32_t &flags){ data.RewindRead(data.GetDataSize()-PAD); auto n=data.ReadUint8(); data.RewindRead(data.GetDataSize()-PAD-n); return true; }'
        after=before.replace('data.RewindRead(data.GetDataSize()-PAD);','if(data.GetDataSize()<PAD)return false; data.RewindRead(data.GetDataSize()-PAD);').replace('data.RewindRead(data.GetDataSize()-PAD-n);','if(n<=data.GetDataSize()-PAD) data.RewindRead(data.GetDataSize()-PAD-n);')
        for text,expected in [(before,True),(after,False)]:
            ctx=context(text);run=IpcInterfaceDetector().detect(ctx,ctx.units)
            self.assertEqual(any(f.rule_id=='ipc.parcel.position-underflow' for f in run.findings),expected)

    def test_caller_class_beyond_permission(self):
        before='void PrivacyManagerStub::RemovePermissionUsedRecordsInner(MessageParcel &data,MessageParcel &reply){ RemovePermissionUsedRecords(data.ReadUint32()); }'
        after=before.replace('{ Remove','{ auto caller=IPCSkeleton::GetCallingTokenID(); if(AccessTokenKit::GetTokenTypeFlag(caller)==TOKEN_HAP && !IsSystemAppCalling()) return; Remove')
        for text,expected in [(before,True),(after,False)]:
            ctx=context(text);run=IpcInterfaceDetector().detect(ctx,ctx.units)
            self.assertEqual(any(f.rule_id=='ipc.auth.caller-class' for f in run.findings),expected)

    def test_service_uid_binding(self):
        before='int BgContinuousTaskMgr::RequestBackgroundRunningForInner(Task *task){ return StartBackgroundRunningForInner(task); }'
        after=before.replace('{ return','{ auto uid=IPCSkeleton::GetCallingUid(); if(uid!=task->uid_)return -1; return')
        for text,expected in [(before,True),(after,False)]:
            ctx=context(text);run=IpcInterfaceDetector().detect(ctx,ctx.units)
            self.assertEqual(any(f.rule_id=='ipc.auth.object-owner' for f in run.findings),expected)

    def test_permission_result_without_sensitive_effect_is_not_identity_alarm(self):
        ctx=context((BASE/'request_identity_positive.cpp').read_text().replace('StartAbility();',''))
        run=IpcInterfaceDetector().detect(ctx,ctx.units)
        self.assertNotIn('ipc.auth.request-identity',{f.rule_id for f in run.findings})

    def test_negative_one_is_not_nonnegative(self):
        text=(BASE/'parcel_fixed.cpp').read_text().replace('n<0','n<-1')
        ctx=context(text);run=IpcInterfaceDetector().detect(ctx,ctx.units)
        self.assertIn('ipc.parcel.copy-range',{f.rule_id for f in run.findings})

    def test_broken_function_does_not_hide_intact_function_candidates(self):
        ctx=context((BASE/'auth_positive.cpp').read_text()+'\nint broken( {')
        registry=DetectorRegistry();registry.register(IpcInterfaceDetector())
        reports,sidecar=run_all_with_coverage(ctx,registry)
        self.assertEqual(reports[0].status,'blocked')
        self.assertTrue(any(d.rule_id=='ipc.auth.missing' for d in reports[0].diagnostics))
        self.assertEqual(sidecar['detectors']['ohscanner.interface.ipc']['status'],'partial')

    def test_uid_cannot_substitute_for_access_token(self):
        ctx=context((BASE/'auth_fixed.cpp').read_text().replace('GetCallingTokenID()','GetCallingUid()'))
        run=IpcInterfaceDetector().detect(ctx,ctx.units)
        self.assertIn('ipc.auth.identity-domain',{f.rule_id for f in run.findings})
        self.assertIn('ipc.auth.missing',{f.rule_id for f in run.findings})

    def test_token_number_cannot_substitute_for_trusted_uid(self):
        ctx=context((BASE/'auth_positive.cpp').read_text().replace('StartAbility();','if(IPCSkeleton::GetCallingTokenID()!=1000)return -1; StartAbility();'))
        run=IpcInterfaceDetector().detect(ctx,ctx.units)
        self.assertIn('ipc.auth.missing',{f.rule_id for f in run.findings})

    def test_deterministic_findings(self):
        ctx=context((BASE/'switch_positive.cpp').read_text());d=IpcInterfaceDetector()
        self.assertEqual(d.detect(ctx,ctx.units),d.detect(ctx,ctx.units))

    def test_budget_conservative(self):
        text=(BASE/'coverage_positive.cpp').read_text().replace('StartAbility();','if(code==2){} if(code==3){} if(code==4){} StartAbility();')
        ctx=context(text);run=IpcInterfaceDetector(IpcPolicy(max_paths=2)).detect(ctx,ctx.units)
        self.assertIn('ipc.auth.missing',{f.rule_id for f in run.findings})
        self.assertTrue(any('budget' in s for s in run.limitations))

    def test_no_cross_entry_permission_leak(self):
        text=(BASE/'auth_positive.cpp').read_text()+'\nint Other::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option){'+(BASE/'common_types.h').read_text().split('constexpr')[0][:0]+'AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(),"p"); return 0;}'
        ctx=context(text);run=IpcInterfaceDetector().detect(ctx,ctx.units)
        self.assertNotIn('ipc.auth.guard-coverage',{f.rule_id for f in run.findings if f.symbol=='Stub::OnRemoteRequest'})

if __name__=='__main__':unittest.main()

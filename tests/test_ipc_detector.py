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
from src.ohscanner.detectors.interface.m2_adapter import M2IpcInterfaceDetector
from src.ohscanner.detectors.interface.models import IpcPolicy, ServiceAccountRole

BASE=Path(__file__).parent/'fixtures/ipc'

def context(text, path='sample.cpp', repository='fixture/ipc'):
    index=parse_source(text,language='cpp')
    unit=SourceUnit(path,'cpp',text,hashlib.sha256(text.encode()).hexdigest(),index.parse_status)
    request=ScanRequest('ipc-test',repository,'synthetic-ipc-v1',snapshot_digest((unit,)),'current-component:'+repository)
    return ScanContext(request,(unit,),{'ast':{path:index.to_dict()}})

def parses_raw(text, grammar):
    """The bytes as written, with no normalization. `parses_clean` cannot serve
    here: it normalizes first, so it can only state the after condition."""
    from tree_sitter import Language, Parser
    return not Parser(Language(grammar)).parse(text).root_node.has_error

def context_sources(items, repository="fixture/ipc"):
    units=[]
    ast={}
    for path,text in sorted(items):
        parsed=parse_source(text,language='cpp')
        unit=SourceUnit(path,'cpp',text,hashlib.sha256(text.encode()).hexdigest(),
                        parsed.parse_status)
        units.append(unit)
        ast[path]=parsed.to_dict()
    request=ScanRequest('ipc-test',repository,'synthetic-ipc-multifile-v1',
                        snapshot_digest(tuple(units)),'current-component:' + repository)
    return ScanContext(request,tuple(units),{'ast':ast})

def fixture_account_policy():
    return IpcPolicy(service_account_roles=(ServiceAccountRole(
        "ACCESSTOKEN_UID", "3020", "<caller-account:access-token-service>",
        ("GetRemoteHapTokenInfo", "DeleteRemoteHapTokenInfo", "UpdateRemoteHapTokenInfo"),
        "synthetic fixture-only assumption; not product account evidence",
    ),))

class IpcDetectorTests(unittest.TestCase):
    def test_hcamera_deferred_session_requires_system_app_guard(self):
        entry = """
int32_t HCameraService::CreateDeferredVideoProcessingSession(int32_t userId,
    Callback &callback, Session &session)
{
    CAMERA_SYNC_TRACE;
    DeferredProcessingService::GetInstance().CreateDeferredVideoProcessingSession(userId, callback);
    return CAMERA_OK;
}
"""
        fixed = entry.replace(
            "    CAMERA_SYNC_TRACE;\n",
            "    CAMERA_SYNC_TRACE;\n"
            '    CHECK_ERROR_RETURN_RET_LOG(!CheckSystemApp(), CAMERA_NO_PERMISSION, "denied");\n',
        )
        macro_header = """
#define CHECK_ERROR_RETURN_RET_LOG(cond, ret, fmt, ...) \\
    do { \\
        if (cond) { \\
            MEDIA_ERR_LOG(fmt, ##__VA_ARGS__); \\
            return ret; \\
        } \\
    } while (0)
"""
        file = "services/camera_service/src/hcamera_service.cpp"
        header = "common/utils/camera_log.h"
        repository = "openharmony/multimedia_camera_framework"
        vulnerable_ctx = context_sources(((file, entry), (header, macro_header)), repository)
        fixed_ctx = context_sources(((file, fixed), (header, macro_header)), repository)
        wrong_guard = fixed.replace("!CheckSystemApp()", "CheckSystemApp()")
        wrong_ctx = context_sources(((file, wrong_guard), (header, macro_header)), repository)
        unrelated = entry.replace("HCameraService::", "UnrelatedService::")
        unrelated_ctx = context_sources(((file, unrelated), (header, macro_header)), repository)
        vulnerable = IpcInterfaceDetector().detect(vulnerable_ctx, vulnerable_ctx.units)
        remediated = IpcInterfaceDetector().detect(fixed_ctx, fixed_ctx.units)
        wrong = IpcInterfaceDetector().detect(wrong_ctx, wrong_ctx.units)
        unrelated_run = IpcInterfaceDetector().detect(unrelated_ctx, unrelated_ctx.units)
        self.assertIn("ipc.auth.missing", {item.rule_id for item in vulnerable.findings})
        self.assertNotIn("ipc.auth.missing", {item.rule_id for item in remediated.findings})
        self.assertIn("ipc.auth.missing", {item.rule_id for item in wrong.findings})
        self.assertEqual(unrelated_run.findings, ())
    def test_auth07_does_not_assume_unauthorized_effect(self):
        text=(BASE / "auth07" / "denial_transport_success_positive.cpp").read_text()
        run=IpcInterfaceDetector().detect(context(text),context(text).units)
        finding=next(item for item in run.findings
                     if item.rule_id == "ipc.auth.denial-transport-success")
        self.assertIsNone(finding.consequence_impact)
        self.assertIsNone(finding.consequence_cwe)

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

    def test_fuzz_wrapper_name_alone_is_not_an_ipc_entry(self):
        # Fuzz drivers often expose a free OnRemoteRequest with only the input
        # parcel. Name plus Parcel must not create an IPC root.
        text = """
#include "common_types.h"
int OnRemoteRequest(uint32_t code, MessageParcel &data) {
    StartAbility();
    return 0;
}
"""
        text += """
class FuzzWrapper {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data) {
        StartAbility();
        return 0;
    }
};
"""
        ctx = context(text, "services/ability/test/fuzztest/ability_fuzzer.cpp")
        run = IpcInterfaceDetector().detect(ctx, ctx.units)
        self.assertEqual(run.findings, ())

    def test_findings_bind_entry_source_and_test_build_membership(self):

        text=(BASE/'auth_positive.cpp').read_text()
        product=context(text,'services/ability/ability_stub.cpp')
        product_findings=IpcInterfaceDetector().detect(product,product.units).findings
        self.assertTrue(product_findings)
        self.assertTrue(all('[entry-source=services/ability/ability_stub.cpp]' in f.message
                            for f in product_findings))
        self.assertFalse(any(o.kind=='entry_build_membership'
                             for f in product_findings for o in f.evidence_obligations))

        harness=context(text,'services/ability/test/fuzztest/ability_stub_fuzzer.cpp')
        harness_run=IpcInterfaceDetector().detect(harness,harness.units)
        self.assertFalse(harness_run.findings)
        self.assertTrue(any('Excluded 1 test/fuzz/mock entry root' in note
                            for note in harness_run.limitations))

        # Exact path components prevent incidental names from being mistaken
        # for test-only build evidence.
        from src.ohscanner.detectors.interface.detector import _test_source_path
        self.assertFalse(_test_source_path('services/contest/mockery/ability_stub.cpp'))
        self.assertTrue(_test_source_path(r'services\ability\tests\ability_stub.cpp'))

        fixed=context((BASE/'auth_fixed.cpp').read_text(),
                      'services/ability/test/fuzztest/ability_stub_fuzzer.cpp')
        self.assertFalse(IpcInterfaceDetector().detect(fixed,fixed.units).findings)

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
        # runner.py:253 turns a blocked run with inspected files into 'partial'.
        self.assertEqual(sidecar['detectors']['ohscanner.interface.ipc']['status'],'partial')

    def test_missing_shared_ast_blocks_direct_use(self):
        ctx=context((BASE/'auth_positive.cpp').read_text())
        ctx=ScanContext(ctx.request,ctx.units,{})
        self.assertEqual(IpcInterfaceDetector().detect(ctx,ctx.units).status,'blocked')

    def test_permission_binding_policy(self):
        ctx=context((BASE/'auth_fixed.cpp').read_text())
        policy=IpcPolicy(expected_permissions=(('StartAbility','"ohos.permission.OTHER"'),))
        run=IpcInterfaceDetector(policy).detect(ctx,ctx.units)
        mismatch = next(f for f in run.findings if f.rule_id == 'ipc.auth.missing')
        self.assertIn('permission mismatch', mismatch.message)
        self.assertIn('ohos.permission.OTHER', mismatch.message)
        self.assertEqual(sum(f.rule_id == 'ipc.auth.missing' for f in run.findings), 1)

    def test_a_correct_expected_permission_is_a_safe_control(self):
        ctx=context((BASE/'auth_fixed.cpp').read_text())
        policy=IpcPolicy(expected_permissions=(('StartAbility','"ohos.permission.TEST"'),))
        run=IpcInterfaceDetector(policy).detect(ctx,ctx.units)
        self.assertNotIn('ipc.auth.missing',{f.rule_id for f in run.findings})

    def test_reviewed_telephony_permission_contract_is_component_qualified(self):
        expected = {(repo, method): permission
                    for repo, method, permission in IpcPolicy().repository_expected_permissions}
        self.assertEqual(expected[('openharmony/telephony_call_manager',
                                   'CallManagerService::SetCameraZoom')],
                         'OHOS_PERMISSION_SET_TELEPHONY_STATE')
        self.assertEqual(expected[('openharmony/telephony_call_manager',
                                   'CallManagerService::GetImsConfig')],
                         'OHOS_PERMISSION_GET_TELEPHONY_STATE')
        self.assertFalse(IpcPolicy().expected_permissions)

    def test_disclosed_permission_contract_is_repository_scoped(self):
        from src.ohscanner.detectors.interface.analysis import Interpreter
        source = "class CallManagerService {};"

        same = context(source, repository='openharmony/telephony_call_manager')
        foreign = context(source, repository='example/forked_component')
        method = 'CallManagerService::GetImsConfig'
        expected = 'OHOS_PERMISSION_GET_TELEPHONY_STATE'
        same_interpreter = Interpreter(same.units, IpcPolicy(), same.request)
        foreign_interpreter = Interpreter(foreign.units, IpcPolicy(), foreign.request)
        self.assertEqual(same_interpreter.expected_permission('GetImsConfig', method),
                         expected)
        self.assertIsNone(foreign_interpreter.expected_permission('GetImsConfig', method))

    def test_visibility_annotations_are_blank_only_in_private_parse_copy(self):
        import tree_sitter_cpp
        from src.ohscanner.detectors.interface.analysis import normalize_syntax, parses_clean
        grammar=tree_sitter_cpp.language()
        raw=(b"EXPORT static void ThrowError(int32_t err);\n"
             b"FFI_EXPORT int64_t FfiContactDelete(int64_t id);\n"
             b"FFI_EXPORT OHOS::ContactsFfi::ContactData* FfiQuery();\n")
        normalized=normalize_syntax(raw)
        self.assertFalse(parses_raw(raw,grammar))
        self.assertTrue(parses_clean(raw,grammar))
        self.assertEqual(len(raw),len(normalized))
        self.assertEqual([i for i,b in enumerate(raw) if b==10],
                         [i for i,b in enumerate(normalized) if b==10])
        self.assertIn(b"       static void ThrowError",normalized)
        self.assertIn(b"          int64_t FfiContactDelete",normalized)
        self.assertIn(b"          OHOS::ContactsFfi::ContactData* FfiQuery",normalized)

    def test_visibility_annotation_normalizer_leaves_non_prefix_tokens_alone(self):
        from src.ohscanner.detectors.interface.analysis import normalize_syntax
        controls=(
            b"int EXPORT = 1;\n",
            b"void EXPORT_call();\n",
            b"// EXPORT void hidden();\n",
            b"#define EXPORT __attribute__((visibility(\"default\")))\n",
        )
        for raw in controls:
            with self.subTest(shape=raw):
                self.assertEqual(normalize_syntax(raw),raw)

    def test_descriptor_macro_literal_is_preserved_outside_private_parse_copy(self):
        import tree_sitter_cpp
        from src.ohscanner.detectors.interface.analysis import normalize_syntax, parses_clean
        grammar=tree_sitter_cpp.language()
        raw=(b"class IFixture : public IRemoteBroker {\n"
             b"public:\n"
             b"    DECLARE_INTERFACE_DESCRIPTOR(u\"ohos.test.IFixture\");\n"
             b"    virtual int Invoke() = 0;\n"
             b"};\n")
        normalized=normalize_syntax(raw)
        self.assertFalse(parses_raw(raw,grammar))
        self.assertTrue(parses_clean(raw,grammar))
        self.assertEqual(len(raw),len(normalized))
        self.assertEqual([i for i,b in enumerate(raw) if b==10],
                         [i for i,b in enumerate(normalized) if b==10])
        self.assertIn(b'DECLARE_INTERFACE_DESCRIPTOR(u\"ohos.test.IFixture\")',raw)
        self.assertNotIn(b'DECLARE_INTERFACE_DESCRIPTOR',normalized)

    def test_nonliteral_descriptor_macro_arguments_remain_unparsed(self):
        from src.ohscanner.detectors.interface.analysis import normalize_syntax
        raw=b'class IFixture { DECLARE_INTERFACE_DESCRIPTOR(to_utf16(DESCRIPTOR)); };\n'
        self.assertEqual(normalize_syntax(raw),raw)

    def test_format_models_preserve_original_offsets(self):
        from src.ohscanner.detectors.interface.analysis import normalize_syntax
        raw=b'LOG("id=%" PRIu64 "", id); (this->*handler)(data,reply); // PRIu64\n'
        normalized=normalize_syntax(raw)
        self.assertEqual(len(raw),len(normalized))
        self.assertEqual(raw.count(b'\n'),normalized.count(b'\n'))
        self.assertIn(b'// PRIu64',normalized)
        self.assertIn(b'(this-> handler)',normalized)

    def test_format_macro_that_ends_a_literal_sequence_parses(self):
        """The dominant OpenHarmony spelling: the width macro is the last token
        of the literal sequence, because the next thing is the comma.

        Requiring a string literal on both sides left `"count=%{public}" PRIu32,`
        -- and every `SCNd64`, whose width family was not matched at all -- as a
        bare identifier between literals. tree-sitter then dropped the whole
        translation unit to `partial`, and the complete-ast pass skips partial
        files, so no obligation was ever recorded for candidates carried by them.
        """
        import tree_sitter_cpp
        from src.ohscanner.detectors.interface.analysis import normalize_syntax, parses_clean
        grammar=tree_sitter_cpp.language()
        shapes=(
            b'void f(MessageParcel& data, uint32_t n){ COMM_LOGE(TAG, "count=%{public}" PRIu32, n); }\n',
            b'void g(void){ if (sscanf_s(p, "pkg_%" SCNd64 "_%" SCNd64, &pid, &uid) != 2) { return; } }\n',
            b'void h(intmax_t n){ char buf[32]; sprintf_s(buf, 32, "%" PRIdMAX "\n", n); }\n',
        )
        for raw in shapes:
            with self.subTest(shape=raw[:44]):
                self.assertFalse(parses_raw(raw,grammar),
                                 'this shape must not already parse, or the test proves nothing')
                self.assertTrue(parses_clean(raw,grammar),
                                'normalization must make this shape parse')

    def test_format_rule_leaves_non_format_identifiers_alone(self):
        """Controls. The rule must only fire on a real width macro that follows a
        string literal; anything else is returned byte-identical."""
        from src.ohscanner.detectors.interface.analysis import normalize_syntax
        untouched=(
            b'#include <inttypes.h>\n',              # a directive, no literal
            b'int x = (int)PRIu32;\n',               # no literal before it
            b'void f(void){ g("a" PRIORITY); }\n',   # PRI-prefixed, not a width macro
            b'void f(void){ g(SCANNER); }\n',        # SCN-prefixed, not a width macro
        )
        for raw in untouched:
            with self.subTest(shape=raw[:32]):
                self.assertEqual(normalize_syntax(raw),raw)

    def test_format_extension_preserves_offsets(self):
        from src.ohscanner.detectors.interface.analysis import normalize_syntax
        raw=(b'if (sscanf_s(pkgName, "pkg_%" SCNd64 "_%" SCNd64, &pid, &uid) != '
             b'GET_UID_PID_CNT) {\n    COMM_LOGE(COMM_SVC, "read invalid qosCount=%{public}" PRIu32, '
             b'param.qosCount);\n}\n')
        normalized=normalize_syntax(raw)
        self.assertEqual(len(raw),len(normalized))
        self.assertEqual(raw.count(b'\n'),normalized.count(b'\n'))

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
        # runner.py:253 turns a blocked run with inspected files into 'partial'.
        self.assertEqual(sidecar['detectors']['ohscanner.interface.ipc']['status'],'partial')

    def test_ipc_adapter_recovers_only_exact_include_trailing_space(self):
        text = '#include "contacts_common_event.h" \n' + (BASE / 'auth_positive.cpp').read_text()
        ctx = context(text, 'dataBusiness/poster/src/poster_call_stub.cpp')
        self.assertEqual(ctx.units[0].parse_status, 'partial')

        run = M2IpcInterfaceDetector().detect(ctx, ctx.units)
        self.assertEqual(run.file_outcomes, ((ctx.units[0].path, 'partial'),))
        self.assertTrue(any('B IPC private syntax copy recovered one exact include-line ending' in item
                            for item in run.limitations))
        findings = [item for item in run.findings if item.rule_id == 'ipc.auth.missing']
        self.assertTrue(findings, 'candidate must survive parser recovery')
        self.assertTrue(all(any(ob.kind == 'parse_completeness_impact'
                             for ob in finding.evidence_obligations) for finding in findings))

        from src.ohscanner.detectors.interface.analysis import normalize_include_trailing_space
        original = b'#include "x.h" \nint f() { return 0; }\n'
        normalized = normalize_include_trailing_space(original)
        self.assertEqual(len(normalized), len(original))
        self.assertEqual([i for i, byte in enumerate(normalized) if byte == 10],
                         [i for i, byte in enumerate(original) if byte == 10])
        self.assertIn(b'#include "x.h"\r\n', normalized)
        self.assertEqual(normalize_include_trailing_space(b'#include "x.h"  \n'),
                         b'#include "x.h"  \n')

    def test_ipc_adapter_keeps_partial_when_other_recovery_is_needed(self):
        text = '#include "contacts_common_event.h" \n' + (BASE / 'auth_positive.cpp').read_text()
        text += '\nuint32_t value; auto label = "n=%{public}" PRIu32;\n'
        ctx = context(text, 'contacts/needs-another-recovery.cpp')
        run = M2IpcInterfaceDetector().detect(ctx, ctx.units)
        self.assertEqual(run.file_outcomes, ((ctx.units[0].path, 'partial'),))
        self.assertTrue(any(item.rule_id == 'ipc.auth.missing' for item in run.findings))
        self.assertTrue(any(ob.kind == 'parse_completeness_impact'
                            for finding in run.findings if finding.rule_id == 'ipc.auth.missing'
                            for ob in finding.evidence_obligations))

    def test_partial_source_candidate_keeps_its_parse_obligation_in_public_adapter(self):
        """A useful partial-tree finding must still reach review as a candidate.

        The default catalog uses the owner M2 adapter, which records file-level
        partial coverage while retaining findings from syntax it did inspect.
        This is an evidence-preservation contract, not a claim that parsing the
        intact function proves the rest of the file was understood.
        """
        ctx=context((BASE/'auth_positive.cpp').read_text()+'\nint broken( {')
        run=M2IpcInterfaceDetector().detect(ctx,ctx.units)

        self.assertEqual(run.status,'completed')
        self.assertEqual(run.file_outcomes,((ctx.units[0].path,'partial'),))
        candidates=[finding for finding in run.findings
                    if finding.rule_id=='ipc.auth.missing']
        self.assertTrue(candidates)
        self.assertTrue(all(any(item.kind=='parse_completeness_impact'
                                for item in finding.evidence_obligations)
                            for finding in candidates))
        self.assertTrue(all(any(item.status=='unknown'
                                for item in finding.evidence_obligations)
                            for finding in candidates))

        registry=DetectorRegistry()
        registry.register(M2IpcInterfaceDetector())
        reports,_=run_all_with_coverage(ctx,registry)
        public_candidates=[item for item in reports[0].diagnostics
                           if item.rule_id=='ipc.auth.missing']
        self.assertTrue(public_candidates)
        self.assertTrue(all(item.confidence=='unassessed'
                            for item in public_candidates))

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

    def test_relay_lookahead_does_not_report_a_call_it_could_not_reach(self):
        """A relay look-ahead reads a handler body, but is not a walk of it.

        Finding the descriptor comparison means running `relay_guard` over the
        callee's statements from the state at the call site, which is the state
        before the callee's own guard. A sensitive call bound to a local met on
        that way was reported as unauthorized, with the guard that reaches it
        missing from the path. The relay candidate itself must survive: the
        interface token comparison is genuinely not accepted here, and dropping
        the rule would hide that instead of fixing this.
        """
        ctx=context((BASE/'relay_lookahead_declaration_fixed.cpp').read_text())
        run=IpcInterfaceDetector().detect(ctx,ctx.units)
        rules={f.rule_id for f in run.findings}
        self.assertNotIn('ipc.auth.missing',rules)
        self.assertNotIn('ipc.auth.guard-coverage',rules)
        self.assertIn('ipc.relay.descriptor-boundary',rules)

    def test_no_cross_entry_permission_leak(self):
        text=(BASE/'auth_positive.cpp').read_text()+'\nint Other::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option){'+(BASE/'common_types.h').read_text().split('constexpr')[0][:0]+'AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(),"p"); return 0;}'
        ctx=context(text);run=IpcInterfaceDetector().detect(ctx,ctx.units)
        self.assertNotIn('ipc.auth.guard-coverage',{f.rule_id for f in run.findings if f.symbol=='Stub::OnRemoteRequest'})

    def test_one_hop_implementer_guard_suppresses_the_export(self):
        """M6: the method the handler calls is not defined by the stub class.

        OpenHarmony implements an IPC stub by inheritance -- the concrete service
        derives from it and supplies the body in another translation unit -- so
        `GetUIContent(persistentId, object)` inside the handler reaches a body
        this file never read. Where that body's opening gate turns away every
        caller holding no privileged role, the `WriteRemoteObject` behind the
        call is not an export to an unauthorized caller. The provenance of the
        credit is asserted, not only the suppression: which caller dispatched to
        which implementer, and the role the gate was read to admit.
        """
        ctx=context((BASE/'onehop_guard_fixed.cpp').read_text())
        run=IpcInterfaceDetector().detect(ctx,ctx.units)
        self.assertEqual({f.rule_id for f in run.findings},set())
        credited=[s for s in run.limitations if s.startswith('Cross-TU one-hop guard credited:')]
        self.assertEqual(len(credited),1)
        self.assertIn('OneHopGuardStub::HandleGetUIContent',credited[0])
        self.assertIn('OneHopGuardService::GetUIContent',credited[0])
        self.assertIn('admits <sa-caller>',credited[0])

    def test_one_hop_gates_that_do_not_answer_about_the_caller_leave_the_export(self):
        """Controls for the credit rule, one failure shape each.

        `onehop_unguarded_positive` has no gate at all; `onehop_open_conjunct`
        gates on a conjunction whose second conjunct is not a reviewed caller-role
        predicate, so a caller it established nothing about continues;
        `onehop_late_gate` checks the caller only after a modelled operation, and
        a gate covers what follows it and nothing before; `onehop_property_gate`
        asks about the request rather than about the caller. None of the four may
        be credited, and the export must survive in each.
        """
        for name in ('onehop_unguarded_positive','onehop_open_conjunct_positive',
                     'onehop_late_gate_positive','onehop_property_gate_positive'):
            with self.subTest(sample=name):
                ctx=context((BASE/(name+'.cpp')).read_text())
                run=IpcInterfaceDetector().detect(ctx,ctx.units)
                self.assertIn('ipc.capability.export',{f.rule_id for f in run.findings})
                self.assertEqual([s for s in run.limitations
                                  if s.startswith('Cross-TU one-hop guard credited:')],[])

    def test_unresolved_hop_is_recorded_rather_than_read_as_a_guard(self):
        """Two implementers define the method, so neither body is the answer.

        Both of them gate, and the analysis still may not use either: which one
        runs depends on the object the caller reached. `is not established` is
        the answer, and it has to be written down where the reviewer reads it --
        a refusal that only exists inside the index is indistinguishable from a
        hop that was never attempted.
        """
        ctx=context((BASE/'onehop_not_unique_positive.cpp').read_text())
        run=IpcInterfaceDetector().detect(ctx,ctx.units)
        self.assertIn('ipc.capability.export',{f.rule_id for f in run.findings})
        self.assertTrue(any('not unique' in s and 'stays a candidate' in s
                            for s in run.limitations))

    def test_a_reviewed_role_name_defined_here_is_read_as_the_body_it_is(self):
        """The reviewed fact does not travel to a file that defines the name.

        `role_predicate_shadowed_positive` gates its handler with a reviewed
        caller-role name and writes its own definition of that name, which answers
        with a UID the reviewed set carries no role for. The credit is a fact about
        the reviewed function, and a local function of the same name is not it, so
        the operation stays a candidate. The shadowing has to be written down: a
        candidate produced by an uncredited local body reads as "no guard here"
        otherwise, which is the wrong thing to hand a reviewer.
        `helper_preproc_guard_fixed` is the other half -- same-file bodies, a
        reviewed fact, and the operation suppressed -- and it must stay that way.
        """
        ctx=context((BASE/'role_predicate_shadowed_positive.cpp').read_text())
        run=IpcInterfaceDetector().detect(ctx,ctx.units)
        self.assertIn('ipc.auth.missing',{f.rule_id for f in run.findings})
        shadowed=[s for s in run.limitations if 'IsAccessTokenCalling' in s]
        self.assertEqual(len(shadowed),1)
        self.assertIn('Reviewed caller-role predicate IsAccessTokenCalling',shadowed[0])
        # The definition's line, not a placeholder: the frame comes from the
        # sources rather than from the index, so `Function.line` is 0 and the
        # citation has to be the definition node's own line.
        self.assertIn('defined in the scanned sources at sample.cpp:27 (',shadowed[0])
        self.assertIn('ShadowedRoleStub::IsAccessTokenCalling',shadowed[0])
        self.assertIn('not credited',shadowed[0])
        fixed=context((BASE/'helper_preproc_guard_fixed.cpp').read_text())
        fixed_run=IpcInterfaceDetector().detect(fixed,fixed.units)
        self.assertEqual({f.rule_id for f in fixed_run.findings},set())

    def test_service_account_role_is_credited_only_where_the_source_binds_it(self):
        """M8: a caller UID compared with a reviewed account constant -- and the
        binding of that constant comes from the scanned sources, not the model.

        `account_role_authorized_fixed` gates its three handlers with a caller-UID
        comparison against `ACCESSTOKEN_UID`, which its own file binds to the
        reviewed 3020, and each call is one of the three operations the reviewed
        record lists. The credit is asserted with its provenance: the guard's
        function and line, the definition's own file and line, the declaration
        text, the accepted-operation list, the scan target and the policy origin.
        A credit that cannot be checked line by line is not reviewable.
        """
        ctx=context((BASE/'account_role_authorized_fixed.cpp').read_text())
        run=IpcInterfaceDetector(fixture_account_policy()).detect(ctx,ctx.units)
        self.assertEqual({f.rule_id for f in run.findings},set())
        credited=[s for s in run.limitations if s.startswith('Service-account role credited:')]
        self.assertEqual(len(credited),1)
        note=credited[0]
        self.assertIn('AccountRoleStub::IsAccessTokenCalling',note)
        self.assertIn('compares the calling UID with ACCESSTOKEN_UID',note)
        # The definition's line, not a placeholder: the binding is read from the
        # sources this run scanned, and the note has to say which line it read.
        self.assertIn('bind to 3020 at sample.cpp:11',note)
        self.assertIn('ACCESSTOKEN_UID, "static const int32_t ACCESSTOKEN_UID = 3020;"',note)
        self.assertIn('The role <caller-account:access-token-service> is accepted for '
                      'GetRemoteHapTokenInfo, DeleteRemoteHapTokenInfo, '
                      'UpdateRemoteHapTokenInfo and for nothing else',note)
        self.assertIn('target fixture/ipc@synthetic-ipc-v1',note)
        self.assertIn('policy origin: ',note)
        self.assertTrue(any(s.startswith('Service-account model: ') and 'not a permission' in s
                            for s in run.limitations))

    def test_service_account_controls_that_must_not_supply_the_guard(self):
        """One control per condition the account model is allowed to rely on.

        `account_role_wrong_value_positive` writes the reviewed constant name and
        binds it to 4096, so the guard is not the reviewed one;
        `account_role_tokenid_positive` compares a caller TokenID against the
        right constant in the right value, which asks about a different identity
        domain; `account_role_request_value_positive` compares a value out of the
        parcel, which the caller writes itself. None of the three may be read as
        a caller-identity fact, and each has to say which condition failed rather
        than staying silent -- a candidate produced by a guard that did not line
        up must not read as a candidate produced by no guard.
        `account_role_unrelated_call_positive` is the scope control: the account
        *is* credited, and the operation behind it is `SetPermission`, which the
        record does not list, so an account that is not a permission must not
        carry the call. The credit naming only its own three operations is what
        keeps the model from becoming a general authorization injection.
        """
        for name,phrase in (('account_role_wrong_value_positive','bind to 4096'),
                            ('account_role_tokenid_positive','against a caller TokenID'),
                            ('account_role_request_value_positive',
                             'against a request-derived value')):
            with self.subTest(sample=name):
                ctx=context((BASE/(name+'.cpp')).read_text())
                run=IpcInterfaceDetector(fixture_account_policy()).detect(ctx,ctx.units)
                self.assertIn('ipc.auth.missing',{f.rule_id for f in run.findings})
                self.assertTrue(any(phrase in s for s in run.limitations),
                                'the failing condition is not recorded: '+phrase)
                self.assertEqual([s for s in run.limitations
                                  if s.startswith('Service-account role credited:')],[])
        # The scope control: the account is credited and the call still survives,
        # so the three credits above cannot be read as "credited means covered".
        ctx=context((BASE/'account_role_unrelated_call_positive.cpp').read_text())
        run=IpcInterfaceDetector(fixture_account_policy()).detect(ctx,ctx.units)
        self.assertIn('ipc.auth.missing',{f.rule_id for f in run.findings})
        credited=[s for s in run.limitations if s.startswith('Service-account role credited:')]
        self.assertEqual(len(credited),1)
        self.assertIn('<caller-account:access-token-service> is accepted for '
                      'GetRemoteHapTokenInfo, DeleteRemoteHapTokenInfo, '
                      'UpdateRemoteHapTokenInfo and for nothing else',credited[0])

    def test_member_delegation_chain_credits_only_source_bound_terminal_guard(self):
        header=(BASE/'member_delegation'/'service.h').read_text()
        fixed=(BASE/'member_delegation'/'service.cpp').read_text()
        guard_start=fixed.index('    if (!PermissionVerification::GetInstance()->IsSACall()) {')
        guard_end=fixed.index('    }',guard_start)+len('    }')
        guard_end=fixed.index(chr(10),guard_end)+1
        vulnerable=fixed[:guard_start]+fixed[guard_end:]
        delegated='    return appMgrServiceInner_->GetAppRunningStateByBundleName(bundleName);'
        unrelated=fixed.replace(delegated,'    StartAbility();'+chr(10)+delegated)
        reset=fixed.replace('    if (!IsReady()) {',
                            '    IPCSkeleton::ResetCallingIdentity();'+chr(10)
                            +'    if (!IsReady()) {')
        self.assertNotEqual(vulnerable,fixed)
        for name,source,expected in (
            ('vulnerable',vulnerable,True),
            ('fixed',fixed,False),
            ('unrelated-effect-before-delegate',unrelated,True),
            ('caller-identity-reset-before-delegate',reset,True),
        ):
            with self.subTest(case=name):
                ctx=context_sources((('service.h',header),('service.cpp',source)))
                run=IpcInterfaceDetector().detect(ctx,ctx.units)
                auth02={f.rule_id for f in run.findings if f.rule_id=='ipc.auth.missing'}
                self.assertEqual(bool(auth02),expected)
                data04 = {f.rule_id for f in run.findings if f.rule_id == 'ipc.data.sensitive-flow'}
                self.assertEqual(bool(data04), expected)
                if not expected:
                    note=next((item for item in run.limitations
                               if item.startswith('Cross-TU one-hop guard credited:')), '')
                    self.assertIn('AppMgrServiceInner::GetAppRunningStateByBundleName',note)
                    self.assertIn('in AppMgrServiceInner::GetAppRunningStateByBundleName',note)
                    self.assertIn('admits <sa-caller>',note)
        # Without the class field declaration in the scanned units, the same
        # spelling is insufficient to resolve the delegate or inherit its guard.
        ctx=context_sources((('service.cpp',fixed),))
        run=IpcInterfaceDetector().detect(ctx,ctx.units)
        self.assertIn('ipc.auth.missing',{f.rule_id for f in run.findings})

if __name__=='__main__':unittest.main()

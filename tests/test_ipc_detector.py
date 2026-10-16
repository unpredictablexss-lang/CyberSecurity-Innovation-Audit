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

def parses_raw(text, grammar):
    """The bytes as written, with no normalization. `parses_clean` cannot serve
    here: it normalizes first, so it can only state the after condition."""
    from tree_sitter import Language, Parser
    return not Parser(Language(grammar)).parse(text).root_node.has_error

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
        self.assertEqual(sidecar['detectors']['ohscanner.interface.ipc']['status'],'blocked')

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
            b'void h(intmax_t n){ char buf[32]; sprintf_s(buf, 32, "%" PRIdMAX "\\n", n); }\n',
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
        self.assertEqual(sidecar['detectors']['ohscanner.interface.ipc']['status'],'blocked')

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
        run=IpcInterfaceDetector().detect(ctx,ctx.units)
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
                run=IpcInterfaceDetector().detect(ctx,ctx.units)
                self.assertIn('ipc.auth.missing',{f.rule_id for f in run.findings})
                self.assertTrue(any(phrase in s for s in run.limitations),
                                'the failing condition is not recorded: '+phrase)
                self.assertEqual([s for s in run.limitations
                                  if s.startswith('Service-account role credited:')],[])
        # The scope control: the account is credited and the call still survives,
        # so the three credits above cannot be read as "credited means covered".
        ctx=context((BASE/'account_role_unrelated_call_positive.cpp').read_text())
        run=IpcInterfaceDetector().detect(ctx,ctx.units)
        self.assertIn('ipc.auth.missing',{f.rule_id for f in run.findings})
        credited=[s for s in run.limitations if s.startswith('Service-account role credited:')]
        self.assertEqual(len(credited),1)
        self.assertIn('<caller-account:access-token-service> is accepted for '
                      'GetRemoteHapTokenInfo, DeleteRemoteHapTokenInfo, '
                      'UpdateRemoteHapTokenInfo and for nothing else',credited[0])

if __name__=='__main__':unittest.main()

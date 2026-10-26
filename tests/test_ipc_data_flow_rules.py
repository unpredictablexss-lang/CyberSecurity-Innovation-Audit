"""Focused regressions for the parcel-bounds, view-lifetime and flow rules.

The fixture matrix establishes one positive/fixed/safe control per family. These
tests pin the *semantics* those controls rely on, because each of them is a way
the rule could quietly stop meaning what its message says:

* the parcel read API is positional -- `ReadRawData(dst, size)` is not memcpy;
* a bound has to name the destination that is actually indexed or written;
* a view is only invalidated by an operation on the parcel that produced it;
* disclosure data is a candidate only when it reaches the reply parcel;
* an identity reset is only a flow candidate when the returned identity was
  discarded, and a guard has to have been established for the caller first.

They are written as detection results, not as claims about product code.
"""
import hashlib
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import SourceUnit, ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.detectors.interface.models import consequence_for

HEADER = '#define Stub Fixture_flow\n#include "common_types.h"\n'
SIGNATURE = ('int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,'
             'MessageParcel &reply,MessageOption &option) {\n')
DESCRIPTOR = 'if (data.ReadInterfaceToken() != GetDescriptor()) return -1;\n'
GUARD = ('if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(), '
         '"ohos.permission.TEST") != PERMISSION_GRANTED) return -1;\n')


def context(text, path='sample.cpp'):
    index = parse_source(text, language='cpp')
    unit = SourceUnit(path, 'cpp', text, hashlib.sha256(text.encode()).hexdigest(),
                      index.parse_status)
    request = ScanRequest('ipc-test', 'fixture/ipc', 'synthetic-ipc-v1',
                          snapshot_digest((unit,)), 'current-component:fixture/ipc')
    return ScanContext(request, (unit,), {'ast': {path: index.to_dict()}})


def rules_for(body, path='sample.cpp'):
    text = HEADER + SIGNATURE + DESCRIPTOR + body + '\nreturn 0;\n}\n'
    ctx = context(text, path)
    run = IpcInterfaceDetector().detect(ctx, ctx.units)
    assert run.status == 'completed', run.status
    return {finding.rule_id for finding in run.findings}


def findings_for(text, path='sample.cpp'):
    ctx = context(text, path)
    run = IpcInterfaceDetector().detect(ctx, ctx.units)
    assert run.status == 'completed', run.status
    return run.findings


class ParcelArgumentPositionTests(unittest.TestCase):
    def test_readrawdata_size_is_the_second_argument(self):
        rules = rules_for('char dst[64]; int n=data.ReadInt32(); data.ReadRawData(dst,n);')
        self.assertIn('ipc.parcel.write-bounds', rules)
        # ReadRawData is not a memcpy: reporting it through the copy rule would
        # claim a length position the API does not have.
        self.assertNotIn('ipc.parcel.copy-range', rules)

    def test_readrawdata_with_matching_bound_is_not_a_candidate(self):
        rules = rules_for('char dst[64]; int n=data.ReadInt32(); '
                          'if (n<0 || n>=sizeof(dst)) return -1; data.ReadRawData(dst,n);')
        self.assertEqual(rules, set())

    def test_memcpy_still_uses_its_own_position(self):
        rules = rules_for('char dst[64]; int n=data.ReadInt32(); '
                          'memcpy(dst,data.ReadBuffer(64),n);')
        self.assertIn('ipc.parcel.copy-range', rules)
        self.assertNotIn('ipc.parcel.write-bounds', rules)


class ParcelAllocatedDestinationTests(unittest.TestCase):
    def test_exact_new_array_capacity_and_nonnegative_fail_fast_are_safe(self):
        rules = rules_for('int n=data.ReadInt32(); if(n<=0) return -1; '
                          'char *dst=new char[n]; '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertNotIn('ipc.parcel.copy-range', rules)

    def test_dynamic_array_without_nonnegative_guard_stays_a_candidate(self):
        rules = rules_for('int n=data.ReadInt32(); char *dst=new char[n]; '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_non_exiting_nonnegative_check_does_not_guard_the_copy(self):
        rules = rules_for('int n=data.ReadInt32(); if(n<=0) { Log("bad length"); } '
                          'char *dst=new char[n]; '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_rebinding_the_allocation_length_invalidates_capacity(self):
        rules = rules_for('int n=data.ReadInt32(); if(n<=0) return -1; '
                          'char *dst=new char[n]; n=data.ReadInt32(); '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_incrementing_the_allocation_length_invalidates_capacity(self):
        rules = rules_for('int n=data.ReadInt32(); if(n<=0) return -1; '
                          'char *dst=new char[n]; n++; '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_prefix_decrement_invalidates_the_nonnegative_fact(self):
        rules = rules_for('int n=data.ReadInt32(); if(n<=0) return -1; '
                          'char *dst=new char[n]; --n; '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_compound_increment_preserves_request_taint_and_invalidates_facts(self):
        rules = rules_for('int n=data.ReadInt32(); if(n<=0) return -1; '
                          'char *dst=new char[n]; n+=1; '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_compound_decrement_preserves_request_taint_and_invalidates_facts(self):
        rules = rules_for('int n=data.ReadInt32(); if(n<=0) return -1; '
                          'char *dst=new char[n]; n-=1; '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_unresolved_call_may_mutate_a_request_length_by_reference(self):
        rules = rules_for('int n=data.ReadInt32(); if(n<=0) return -1; '
                          'char *dst=new char[n]; Bump(n); '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_unresolved_explicit_address_call_invalidates_length_facts(self):
        rules = rules_for('int n=data.ReadInt32(); if(n<=0) return -1; '
                          'char *dst=new char[n]; Bump(&n); '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_resolved_nonconst_reference_mutator_invalidates_length_facts(self):
        text = (HEADER + 'void Fixture_flow::Bump(int &value) { value++; }\n'
                + SIGNATURE + DESCRIPTOR
                + 'int n=data.ReadInt32(); if(n<=0) return -1; '
                  'char *dst=new char[n]; Bump(n); '
                  'const char *src=data.ReadBuffer(n); memcpy(dst,src,n); return 0;\n}\n')
        rules = {finding.rule_id for finding in findings_for(text)}
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_resolved_pointer_mutator_invalidates_explicit_address_argument(self):
        text = (HEADER + 'void Fixture_flow::Bump(int *value) { (*value)++; }\n'
                + SIGNATURE + DESCRIPTOR
                + 'int n=data.ReadInt32(); if(n<=0) return -1; '
                  'char *dst=new char[n]; Bump(&n); '
                  'const char *src=data.ReadBuffer(n); memcpy(dst,src,n); return 0;\n}\n')
        rules = {finding.rule_id for finding in findings_for(text)}
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_local_nonconst_reference_alias_invalidates_origin_facts(self):
        rules = rules_for('int n=data.ReadInt32(); if(n<=0) return -1; '
                          'char *dst=new char[n]; int& alias=n; alias++; '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_local_pointer_alias_invalidates_origin_facts(self):
        text = (HEADER + 'void Fixture_flow::Bump(int *value) { (*value)++; }\n'
                + SIGNATURE + DESCRIPTOR
                + 'int n=data.ReadInt32(); if(n<=0) return -1; '
                  'char *dst=new char[n]; int *alias=&n; Bump(alias); '
                  'const char *src=data.ReadBuffer(n); memcpy(dst,src,n); return 0;\n}\n')
        rules = {finding.rule_id for finding in findings_for(text)}
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_reference_alias_passed_to_reference_mutator_keeps_candidate(self):
        text = (HEADER + 'void Fixture_flow::Bump(int &value) { value++; }\n'
                + SIGNATURE + DESCRIPTOR
                + 'int n=data.ReadInt32(); if(n<=0) return -1; '
                  'char *dst=new char[n]; int& alias=n; Bump(alias); '
                  'const char *src=data.ReadBuffer(n); memcpy(dst,src,n); return 0;\n}\n')
        rules = {finding.rule_id for finding in findings_for(text)}
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_reference_alias_mutated_after_facts_are_established(self):
        rules = rules_for('int n=data.ReadInt32(); int& alias=n; '
                          'if(n<=0) return -1; char *dst=new char[n]; alias++; '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_pointer_alias_passed_after_facts_are_established(self):
        text = (HEADER + 'void Fixture_flow::Bump(int *value) { (*value)++; }\n'
                + SIGNATURE + DESCRIPTOR
                + 'int n=data.ReadInt32(); int *alias=&n; '
                  'if(n<=0) return -1; char *dst=new char[n]; Bump(alias); '
                  'const char *src=data.ReadBuffer(n); memcpy(dst,src,n); return 0;\n}\n')
        rules = {finding.rule_id for finding in findings_for(text)}
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_unused_const_pointer_alias_does_not_drop_proven_capacity(self):
        rules = rules_for('int n=data.ReadInt32(); if(n<=0) return -1; '
                          'char *dst=new char[n]; const int *alias=&n; '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertNotIn('ipc.parcel.copy-range', rules)

    def test_pointer_alias_rebind_updates_origin_before_mutating_helper(self):
        text = (HEADER + 'void Fixture_flow::Bump(int *value) { (*value)++; }\n'
                + SIGNATURE + DESCRIPTOR
                + 'int n=data.ReadInt32(); if(n<=0) return -1; char *first=new char[n]; '
                  'int m=data.ReadInt32(); if(m<=0) return -1; char *dst=new char[m]; '
                  'int *alias=&n; alias=&m; Bump(alias); '
                  'const char *src=data.ReadBuffer(m); memcpy(dst,src,m); return 0;\n}\n')
        rules = {finding.rule_id for finding in findings_for(text)}
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_reference_alias_assignment_invalidates_origin_facts(self):
        rules = rules_for('int n=data.ReadInt32(); int& alias=n; '
                          'if(n<=0) return -1; char *dst=new char[n]; '
                          'alias=data.ReadInt32(); '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_pointer_declared_before_assignment_tracks_request_origin(self):
        text = (HEADER + 'void Fixture_flow::Bump(int *value) { (*value)++; }\n'
                + SIGNATURE + DESCRIPTOR
                + 'int n=data.ReadInt32(); if(n<=0) return -1; char *dst=new char[n]; '
                  'int *alias; alias=&n; Bump(alias); '
                  'const char *src=data.ReadBuffer(n); memcpy(dst,src,n); return 0;\n}\n')
        rules = {finding.rule_id for finding in findings_for(text)}
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_write_through_request_pointer_invalidates_origin_facts(self):
        rules = rules_for('int n=data.ReadInt32(); int *p=&n; '
                          'if(n<=0) return -1; char *dst=new char[n]; '
                          '*p=data.ReadInt32(); '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_indexed_write_through_request_pointer_invalidates_origin_facts(self):
        rules = rules_for('int n=data.ReadInt32(); int *p=&n; '
                          'if(n<=0) return -1; char *dst=new char[n]; '
                          'p[0]=data.ReadInt32(); '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_compound_write_through_request_pointer_invalidates_origin_facts(self):
        rules = rules_for('int n=data.ReadInt32(); int *p=&n; '
                          'if(n<=0) return -1; char *dst=new char[n]; '
                          '*p+=1; '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_compound_indexed_write_invalidates_request_pointer_origin(self):
        rules = rules_for('int n=data.ReadInt32(); int *p=&n; '
                          'if(n<=0) return -1; char *dst=new char[n]; '
                          'p[0]+=1; '
                          'const char *src=data.ReadBuffer(n); memcpy(dst,src,n);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_shadowed_pointer_alias_keeps_outer_origin_in_candidate_state(self):
        text = (HEADER + 'void Fixture_flow::Bump(int *value) { (*value)++; }\n'
                + SIGNATURE + DESCRIPTOR
                + 'int n=data.ReadInt32(); int *alias=&n; if(n<=0) return -1; '
                  'char *dst=new char[n]; int m=data.ReadInt32(); '
                  'if(m<=0) return -1; char *other=new char[m]; '
                  '{ int *alias=&m; } Bump(alias); '
                  'const char *src=data.ReadBuffer(n); memcpy(dst,src,n); return 0;\n}\n')
        rules = {finding.rule_id for finding in findings_for(text)}
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_different_copy_length_does_not_match_allocation_capacity(self):
        rules = rules_for('int n=data.ReadInt32(); if(n<=0) return -1; '
                          'char *dst=new char[n]; '
                          'const char *src=data.ReadBuffer(n+1); memcpy(dst,src,n+1);')
        self.assertIn('ipc.parcel.copy-range', rules)

    def test_new_array_capacity_does_not_apply_to_an_unrelated_destination(self):
        rules = rules_for('int n=data.ReadInt32(); if(n<=0) return -1; '
                          'char *owned=new char[n]; char *dst=data.ReadBuffer(n); '
                          'memcpy(dst,data.ReadBuffer(n),n);')
        self.assertIn('ipc.parcel.copy-range', rules)


class ParcelIndexBoundTests(unittest.TestCase):
    def test_index_bound_against_another_buffer_does_not_match(self):
        rules = rules_for('char dst[64]; int idx=data.ReadInt32(); '
                          'if (idx>4096) return -1; dst[idx]=0;')
        self.assertIn('ipc.parcel.bounds', rules)

    def test_index_bound_against_its_own_capacity_matches(self):
        rules = rules_for('char dst[64]; int idx=data.ReadInt32(); '
                          'if (idx<0 || idx>=sizeof(dst)) return -1; dst[idx]=0;')
        self.assertEqual(rules, set())

    def test_unknown_capacity_is_left_open(self):
        # The destination is a pointer whose capacity this function never states.
        # The question is undecidable here, so the rule must not answer it.
        rules = rules_for('char *dst=(char *)data.ReadBuffer(64); int idx=data.ReadInt32(); '
                          'dst[idx]=0;')
        self.assertNotIn('ipc.parcel.bounds', rules)


class ParcelViewLifetimeTests(unittest.TestCase):
    def test_reuse_on_the_owning_parcel_invalidates_the_view(self):
        rules = rules_for('const char *view=data.ReadBuffer(8); data.Reuse(); char c=view[0];')
        self.assertIn('ipc.parcel.lifecycle', rules)

    def test_rewind_read_on_the_owning_parcel_invalidates_the_view(self):
        rules = rules_for('const char *view=data.ReadBuffer(8); data.RewindRead(0); char c=view[0];')
        self.assertIn('ipc.parcel.lifecycle', rules)

    def test_reuse_on_another_parcel_does_not_invalidate(self):
        # The reply is a different parcel; its reuse says nothing about the
        # request buffer the view points into.
        rules = rules_for('const char *view=data.ReadBuffer(8); reply.Reuse(); char c=view[0];')
        self.assertEqual(rules, set())

    def test_copying_before_reuse_is_the_control(self):
        rules = rules_for('const char *view=data.ReadBuffer(8); char c=view[0]; data.Reuse();')
        self.assertEqual(rules, set())


class SensitiveReplyFlowTests(unittest.TestCase):
    def test_disclosure_result_written_to_reply_without_a_guard(self):
        rules = rules_for('auto blob=ReadUserData(IPCSkeleton::GetCallingUid()); '
                          'reply.WriteString(blob);')
        self.assertIn('ipc.data.sensitive-flow', rules)

    def test_same_value_written_back_into_the_request_is_not_a_reply(self):
        rules = rules_for('auto blob=ReadUserData(IPCSkeleton::GetCallingUid()); '
                          'data.WriteString(blob);')
        self.assertNotIn('ipc.data.sensitive-flow', rules)

    def test_guarded_write_is_the_control(self):
        rules = rules_for(GUARD + 'auto blob=ReadUserData(IPCSkeleton::GetCallingUid()); '
                          'reply.WriteString(blob);')
        self.assertEqual(rules, set())


class UnresolvedGuardTests(unittest.TestCase):
    """A guard the scan can see but cannot read is not an absent guard."""

    HELPER = ('bool Stub::IsTrustedCalling() const {\n'
              'int uid=IPCSkeleton::GetCallingUid();\n'
              'return uid == ACCESS_TOKEN_UID;\n}\n')

    def test_the_candidate_keeps_the_comparison_it_could_not_read(self):
        text = (HEADER + self.HELPER + SIGNATURE + DESCRIPTOR
                + 'if (!IsTrustedCalling()) return -1;\nStartAbility();\nreturn 0;\n}\n')
        findings = [f for f in findings_for(text) if f.rule_id == 'ipc.auth.missing']
        self.assertEqual(len(findings), 1, findings)
        # The comparison is present, so "without a recognized caller
        # authorization" must say which symbol it could not resolve.
        self.assertIn('Guard seen, not accepted', findings[0].message)
        self.assertIn('ACCESS_TOKEN_UID', findings[0].message)

    def test_a_recognized_guard_needs_no_note(self):
        rules = rules_for(GUARD + 'StartAbility();')
        self.assertEqual(rules, set())

    def test_a_local_helper_with_a_reviewed_name_is_still_read_from_its_body(self):
        # `IsAccessTokenCalling` is a name the role model knows. When this file
        # defines it, the definition wins: a body that proves nothing must not
        # inherit the name's meaning.
        text = (HEADER + 'bool Stub::IsAccessTokenCalling() const {\nreturn true;\n}\n'
                + SIGNATURE + DESCRIPTOR
                + 'if (!IsAccessTokenCalling()) return -1;\nStartAbility();\nreturn 0;\n}\n')
        rules = {f.rule_id for f in findings_for(text)}
        self.assertIn('ipc.auth.missing', rules)

    def test_a_resolved_constant_without_a_reviewed_account_says_so(self):
        # The symbol has a value; the policy has no reviewed account assignment
        # for that value. Saying "does not resolve" here would be a claim about
        # the source that a reviewer can check, and it would be false.
        text = (HEADER + 'static const int32_t ACCESS_TOKEN_UID = 3020;\n' + self.HELPER
                + SIGNATURE + DESCRIPTOR
                + 'if (!IsTrustedCalling()) return -1;\nStartAbility();\nreturn 0;\n}\n')
        findings = [f for f in findings_for(text) if f.rule_id == 'ipc.auth.missing']
        self.assertEqual(len(findings), 1, findings)
        message = findings[0].message
        self.assertIn('these sources bind to 3020', message)
        self.assertIn('no reviewed account assignment', message)
        self.assertNotIn('does not resolve', message)

    def test_the_note_does_not_credit_the_guard(self):
        # Reporting the comparison must not turn it into authorization: the
        # symbol is still unresolved, so the candidate stays.
        text = (HEADER + self.HELPER + SIGNATURE + DESCRIPTOR
                + 'if (!IsTrustedCalling()) return -1;\nStartAbility();\nreturn 0;\n}\n')
        rules = {f.rule_id for f in findings_for(text)}
        self.assertIn('ipc.auth.missing', rules)


class IdentityFlowTests(unittest.TestCase):
    def test_discarded_identity_after_authorization_is_a_candidate(self):
        rules = rules_for(GUARD + 'IPCSkeleton::ResetCallingIdentity(); StartAbility();')
        self.assertIn('ipc.auth.flow', rules)

    def test_saved_and_restored_identity_is_the_control(self):
        rules = rules_for(GUARD + 'auto saved=IPCSkeleton::ResetCallingIdentity(); '
                          'IPCSkeleton::SetCallingIdentity(saved); StartAbility();')
        self.assertEqual(rules, set())

    def test_discarded_identity_without_a_guard_is_missing_authorization_not_flow(self):
        # AUTH-02 already says there is no guard; claiming an identity flow would
        # report the same path twice under a mechanism it does not have.
        rules = rules_for('IPCSkeleton::ResetCallingIdentity(); StartAbility();')
        self.assertNotIn('ipc.auth.flow', rules)
        self.assertIn('ipc.auth.missing', rules)


class ConsequenceTests(unittest.TestCase):
    def test_lifecycle_reports_use_after_release_not_oob_read(self):
        impact, cwe, basis = consequence_for('ipc.parcel.lifecycle')
        self.assertEqual((impact, cwe, basis), ('use_after_release', 'CWE-416', ''))

    def test_write_bounds_is_distinguished_from_read_bounds(self):
        self.assertEqual(consequence_for('ipc.parcel.bounds')[0], 'out_of_bounds_read')
        self.assertEqual(consequence_for('ipc.parcel.write-bounds')[0], 'out_of_bounds_write')

    def test_a_disclosure_call_promotes_any_rule_to_information_disclosure(self):
        impact, cwe, basis = consequence_for('ipc.auth.missing', ('GetTokenInfo',))
        self.assertEqual((impact, cwe, basis), ('information_disclosure', 'CWE-200', 'GetTokenInfo'))


if __name__ == '__main__':
    unittest.main()

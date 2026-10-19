"""Integration counterexamples; synthetic controls are not product evidence."""
from pathlib import Path
import unittest
from unittest.mock import patch

from tests.test_ipc_detector import context
from src.ohscanner.detectors.interface.analysis import Interpreter
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.detectors.interface.families import merge_policy
from src.ohscanner.detectors.interface.models import IpcPolicy, ServiceAccountRole

BASE = Path(__file__).parent / "fixtures/ipc"


class IpcIntegrationSafetyTests(unittest.TestCase):
    def run_text(self, text):
        ctx = context(text)
        return IpcInterfaceDetector().detect(ctx, ctx.units)

    def test_a_uid_literal_does_not_enable_an_unreviewed_account_by_default(self):
        run = self.run_text((BASE / "account_role_authorized_fixed.cpp").read_text())
        self.assertIn("ipc.auth.missing", {f.rule_id for f in run.findings})
        self.assertEqual(IpcInterfaceDetector().policy.service_account_roles, ())
        self.assertFalse(any(s.startswith("Service-account role credited:") for s in run.limitations))

    def test_access_token_role_is_limited_to_reviewed_repo_and_operation(self):
        text = """
static const int32_t ACCESSTOKEN_UID = 3020;
class PrivacyManagerStub {
public:
 bool IsAccessTokenCalling() const;
 int RemovePermissionUsedRecords();
 int StartAbility();
 void RemoveInner(MessageParcel &data, MessageParcel &reply);
 void StartInner(MessageParcel &data, MessageParcel &reply);
};
bool PrivacyManagerStub::IsAccessTokenCalling() const {
 return IPCSkeleton::GetCallingUid() == ACCESSTOKEN_UID;
}
void PrivacyManagerStub::RemoveInner(MessageParcel &data, MessageParcel &reply) {
 if (!IsAccessTokenCalling()) { reply.WriteInt32(-1); return; }
 this->RemovePermissionUsedRecords();
}
void PrivacyManagerStub::StartInner(MessageParcel &data, MessageParcel &reply) {
 if (!IsAccessTokenCalling()) { reply.WriteInt32(-1); return; }
 this->StartAbility();
}
"""
        product = context(text, "privacy_manager_stub.cpp",
                          "openharmony/security_access_token")
        product_run = IpcInterfaceDetector().detect(product, product.units)
        product_missing = {f.symbol for f in product_run.findings
                           if f.rule_id == "ipc.auth.missing"}
        self.assertNotIn("PrivacyManagerStub::RemoveInner", product_missing)
        self.assertTrue(any(s.startswith("Service-account role credited:")
                            for s in product_run.limitations))
        # A repo string does not make the same account a global trust rule.
        unrelated = context(text, "privacy_manager_stub.cpp", "fixture/unrelated")
        unrelated_run = IpcInterfaceDetector().detect(unrelated, unrelated.units)
        self.assertIn("ipc.auth.missing", {f.rule_id for f in unrelated_run.findings})
        # Even inside the reviewed repository, the role answers only for the
        # explicitly listed privacy operation, not a different sensitive call.
        self.assertIn("PrivacyManagerStub::StartInner", product_missing)

    def test_onehop_reject_branch_effect_is_not_a_guard(self):
        fixed = (BASE / "onehop_guard_fixed.cpp").read_text()
        positive = fixed.replace("if (!IsSACalling()) {", "if (!IsSACalling()) { StartAbility();")
        self.assertEqual(self.run_text(fixed).findings, ())
        run = self.run_text(positive)
        self.assertIn("ipc.capability.export", {f.rule_id for f in run.findings})
        self.assertFalse(any(s.startswith("Cross-TU one-hop guard credited:") for s in run.limitations))

    def test_onehop_out_parameter_write_before_reject_is_not_guarded(self):
        fixed = (BASE / "onehop_guard_fixed.cpp").read_text()
        controls = (
            fixed.replace("if (!IsSACalling()) {", "object = PrivilegedObject(); if (!IsSACalling()) {"),
            fixed.replace("if (!IsSACalling()) {", "if (!IsSACalling()) { object = PrivilegedObject();"),
        )
        for positive in controls:
            with self.subTest(source=positive):
                run = self.run_text(positive)
                self.assertIn("ipc.capability.export", {f.rule_id for f in run.findings})
                self.assertFalse(any(s.startswith("Cross-TU one-hop guard credited:") for s in run.limitations))

    def test_ambiguous_local_role_overloads_do_not_fall_back_to_name_credit(self):
        text = """
class PrivacyManagerStub {
public:
 bool IsAccessTokenCalling() { return false; }
 bool IsAccessTokenCalling(int other) { return false; }
 void GetRemoteHapTokenInfoInner(MessageParcel &data, MessageParcel &reply) {
   if (!IsAccessTokenCalling()) return;
   GetRemoteHapTokenInfo(1, 2);
 }
};
"""
        run = self.run_text(text)
        self.assertIn("ipc.auth.missing", {f.rule_id for f in run.findings})
        self.assertTrue(any("Local caller-role definition is unresolved" in s for s in run.limitations))

    def test_interpreter_uses_effective_policy_for_its_account_maps(self):
        role = ServiceAccountRole("FIXTURE_UID", "4096", "<fixture-only>", ("TestCall",),
                                  "synthetic test assumption, not a reviewed product account")
        effective = IpcPolicy(service_account_roles=(role,))
        ctx = context("int ordinary() { return 0; }")
        with patch("src.ohscanner.detectors.interface.analysis.merge_policy", return_value=effective):
            walk = Interpreter(ctx.units, IpcPolicy(), ctx.request)
        self.assertEqual(walk.account_roles, {"FIXTURE_UID": role})
        self.assertEqual(walk.account_accepts, {"<fixture-only>": frozenset({"TestCall"})})

    def test_repository_scope_on_explicit_account_policy_is_enforced(self):
        role = ServiceAccountRole(
            "FIXTURE_UID", "4096", "<fixture-only>", ("TestCall",),
            "synthetic repository-scoped test policy", repository="fixture/trusted")
        effective = IpcPolicy(service_account_roles=(role,))
        unrelated = context("int ordinary() { return 0; }", repository="fixture/unrelated")
        trusted = context("int ordinary() { return 0; }", repository="fixture/trusted")
        with patch("src.ohscanner.detectors.interface.analysis.merge_policy",
                   return_value=effective):
            unrelated_walk = Interpreter(unrelated.units, IpcPolicy(), unrelated.request)
            trusted_walk = Interpreter(trusted.units, IpcPolicy(), trusted.request)
        self.assertEqual(unrelated_walk.account_roles, {})
        self.assertEqual(trusted_walk.account_roles, {"FIXTURE_UID": role})

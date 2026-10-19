"""Regression coverage for source-bounded IPC observer and permission candidates."""
import hashlib
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest


STUB = """
class PasteStub {
  int OnSubscribeObserver(Parcel &data) {
    auto callback = ReadObserver(data);
    SubscribeObserver(callback);
    return 0;
  }
  int OnGetPasteData(Parcel &data) {
    return GetPasteData(data);
  }
};
"""
SERVICE = """
class PasteService : public PasteStub {
  bool IsDefaultIME(AppInfo info) {
    if (bundles_.empty()) { return true; }
    return false;
  }
  void SubscribeObserver(Observer *observer) {
    AddObserver(observer);
  }
  void AddObserver(Observer *observer) {
    observers.insert(observer);
  }
  bool VerifyPermission(uint32_t tokenId) {
    bool isReadGrant = HasReadPermission(tokenId);
    bool isPrivilegeApp = IsDefaultIME(GetAppInfo(tokenId));
    auto isGrant = isReadGrant || isPrivilegeApp;
    return isGrant;
  }
  int GetPasteData(Parcel &data) {
    if (!VerifyPermission(GetCallingTokenID())) return -1;
    return GetData(data);
  }
};
"""


def run(sources):
    units = []
    for path, text in sorted(sources.items()):
        index = parse_source(text, language="cpp")
        units.append(SourceUnit(path, "cpp", text,
                                hashlib.sha256(text.encode()).hexdigest(),
                                index.parse_status))
    units = tuple(units)
    request = ScanRequest("ipc-test", "fixture/pasteboard", "synthetic-v1",
                          snapshot_digest(units), "current-component:fixture/pasteboard")
    context = ScanContext(request, units, {
        "ast": {unit.path: parse_source(unit.text, language="cpp").to_dict()
                for unit in units}
    })
    return IpcInterfaceDetector().detect(context, units)


def finding_rule(result, rule):
    return [finding for finding in result.findings if finding.rule_id == rule]


def run_service(service):
    return run({"stub.cpp": STUB, "service.cpp": service})


class UnboundedObserverTests(unittest.TestCase):
    def test_ipc_observer_registration_without_cap_is_candidate(self):
        result = run_service(SERVICE)
        findings = finding_rule(result, "ipc.resource.unbounded-observer-registration")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].candidate_cwe, "CWE-400")
        self.assertEqual(findings[0].symbol, "AddObserver")
        self.assertIn("Source-derived path within the scanned scope", findings[0].message)
        self.assertIn("PasteStub::OnSubscribeObserver", findings[0].message)
        self.assertIn("PasteService::SubscribeObserver", findings[0].message)
        self.assertIn("PasteService::AddObserver", findings[0].message)
        self.assertEqual({item.kind for item in findings[0].evidence_obligations},
                         {"call_path_binding", "entry_reachability", "resource_bound", "product_impact"})

    def test_observer_candidate_kept_without_hierarchy_but_path_stays_unknown(self):
        unlinked = SERVICE.replace("class PasteService : public PasteStub {", "class PasteService {")
        findings = finding_rule(run_service(unlinked),
                                "ipc.resource.unbounded-observer-registration")
        self.assertEqual(len(findings), 1)
        self.assertIn("No unique direct-argument path", findings[0].message)
        self.assertNotIn("Source-derived path within the scanned scope", findings[0].message)

    def test_ambiguous_observer_implementations_receive_no_path_credit(self):
        alternate = SERVICE.replace("class PasteService : public PasteStub {",
                                    "class AlternatePasteService : public PasteStub {")
        findings = finding_rule(run_service(SERVICE + "\n" + alternate),
                                "ipc.resource.unbounded-observer-registration")
        self.assertEqual(len(findings), 2)
        self.assertTrue(all("No unique direct-argument path" in finding.message
                            for finding in findings))

    def test_per_process_cap_before_insert_suppresses_candidate(self):
        bounded = SERVICE.replace(
            "    observers.insert(observer);",
            "    auto allObserverCount = GetAllObserversSize(userId, callingPid);\n"
            "    if (allObserverCount >= MAX_OBSERVER_COUNT) { return; }\n"
            "    observers.insert(observer);",
        )
        self.assertEqual(finding_rule(run_service(bounded),
                                      "ipc.resource.unbounded-observer-registration"), [])

    def test_unrelated_collection_insert_without_ipc_subscription_is_not_candidate(self):
        unrelated = SERVICE.replace(
            "  void SubscribeObserver(Observer *observer) {\n"
            "    AddObserver(observer);\n  }\n", "")
        self.assertEqual(finding_rule(run({"service.cpp": unrelated}),
                                      "ipc.resource.unbounded-observer-registration"), [])

    def test_unrelated_add_observer_owner_is_not_joined_by_name_only(self):
        unrelated_owner = SERVICE + "\nclass OtherService {\n"
        unrelated_owner += "  void AddObserver(Observer *observer) {\n"
        unrelated_owner += "    unrelated.insert(observer);\n  }\n};\n"
        findings = finding_rule(run_service(unrelated_owner),
                                "ipc.resource.unbounded-observer-registration")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].symbol, "AddObserver")

    def test_unrelated_limit_return_does_not_hide_unbounded_insert(self):
        decoy = SERVICE.replace(
            "    observers.insert(observer);",
            "    if (unrelatedCount >= MAX_OBSERVER_COUNT) { return; }\n"
            "    observers.insert(observer);",
        )
        self.assertEqual(len(finding_rule(run_service(decoy),
                                          "ipc.resource.unbounded-observer-registration")), 1)

    def test_unowned_free_functions_are_not_joined_by_name_only(self):
        free_functions = """
        void OnChangedObserver() { SubscribeObserver(); }
        void SubscribeObserver() { AddObserver(); }
        void AddObserver() { observers.insert(observer); }
        """
        self.assertEqual(finding_rule(run({"service.cpp": free_functions}),
                                      "ipc.resource.unbounded-observer-registration"), [])

    def test_nested_conditional_return_is_not_treated_as_unconditional_cap(self):
        decoy = SERVICE.replace(
            "    observers.insert(observer);",
            "    auto allObserverCount = GetAllObserversSize(userId, callingPid);\n"
            "    if (allObserverCount >= MAX_OBSERVER_COUNT) { if (ready) return; }\n"
            "    observers.insert(observer);",
        )
        self.assertEqual(len(finding_rule(run_service(decoy),
                                          "ipc.resource.unbounded-observer-registration")), 1)

    def test_limit_token_and_return_in_separate_branches_do_not_suppress(self):
        decoy = SERVICE.replace(
            "    observers.insert(observer);",
            "    if (ready) { return; }\n"
            "    auto threshold = MAX_OBSERVER_COUNT;\n"
            "    auto count = GetAllObserversSize(callingPid);\n"
            "    if (count >= threshold) { LogLimit(); }\n"
            "    observers.insert(observer);",
        )
        self.assertEqual(len(finding_rule(run_service(decoy),
                                          "ipc.resource.unbounded-observer-registration")), 1)

    def test_default_ime_grant_on_sensitive_ipc_path_is_source_bound_candidate(self):
        findings = finding_rule(run_service(SERVICE), "ipc.auth.privileged-app-bypass")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].candidate_cwe, "CWE-862")
        self.assertEqual(findings[0].symbol, "VerifyPermission")
        self.assertIn("Source-derived path within the scanned scope", findings[0].message)
        self.assertIn("PasteStub::OnGetPasteData", findings[0].message)
        self.assertIn("PasteService::GetPasteData", findings[0].message)
        self.assertIn("product registration, dispatch and any overrides", " ".join(
            item.description for item in findings[0].evidence_obligations
            if item.kind == "call_path_binding"))
        self.assertEqual({item.kind for item in findings[0].evidence_obligations},
                         {"call_path_binding", "grant_policy", "entry_reachability", "disclosure_impact"})

    def test_empty_bundle_true_branch_is_reported_as_source_evidence(self):
        findings = finding_rule(run_service(SERVICE), "ipc.auth.privileged-app-bypass")
        self.assertEqual(len(findings), 1)
        self.assertIn("IsDefaultIME returns true when bundles_ is empty", findings[0].message)
        self.assertIn("empty configuration can contribute to the verifier grant", findings[0].message)
        self.assertIn("Configuration state is unknown", findings[0].message)

    def test_empty_bundle_false_branch_does_not_claim_fail_open_evidence(self):
        safe = SERVICE.replace(
            "if (bundles_.empty()) { return true; }",
            "if (bundles_.empty()) { return false; }",
        )
        findings = finding_rule(run_service(safe), "ipc.auth.privileged-app-bypass")
        self.assertEqual(len(findings), 1)
        self.assertNotIn("bundles_ is empty", findings[0].message)

    def test_missing_hierarchy_keeps_candidate_without_claiming_a_call_path(self):
        unlinked = SERVICE.replace("class PasteService : public PasteStub {", "class PasteService {")
        findings = finding_rule(run_service(unlinked), "ipc.auth.privileged-app-bypass")
        self.assertEqual(len(findings), 1)
        self.assertIn("No unique source-derived entry-to-implementation path was established",
                      findings[0].message)
        self.assertNotIn("Source-derived path within the scanned scope", findings[0].message)

    def test_ambiguous_implementers_keep_candidate_without_path_credit(self):
        alternate = SERVICE.replace("class PasteService : public PasteStub {",
                                    "class AlternatePasteService : public PasteStub {")
        findings = finding_rule(run_service(SERVICE + "\n" + alternate),
                                "ipc.auth.privileged-app-bypass")
        self.assertEqual(len(findings), 2)
        self.assertTrue(all("No unique source-derived entry-to-implementation path was established"
                            in finding.message for finding in findings))

    def test_removing_default_ime_grant_suppresses_candidate(self):
        fixed = SERVICE.replace(
            "    bool isPrivilegeApp = IsDefaultIME(GetAppInfo(tokenId));\n"
            "    auto isGrant = isReadGrant || isPrivilegeApp;",
            "    auto isGrant = isReadGrant;",
        )
        self.assertEqual(finding_rule(run_service(fixed), "ipc.auth.privileged-app-bypass"), [])

    def test_default_ime_predicate_not_used_in_permission_grant_is_safe_control(self):
        safe = SERVICE.replace(
            "    auto isGrant = isReadGrant || isPrivilegeApp;",
            "    auto isGrant = isReadGrant;",
        )
        self.assertEqual(finding_rule(run_service(safe), "ipc.auth.privileged-app-bypass"), [])

    def test_verify_permission_without_sensitive_get_data_path_is_not_candidate(self):
        no_sensitive_path = SERVICE.replace(
            "  int GetPasteData(Parcel &data) {\n"
            "    if (!VerifyPermission(GetCallingTokenID())) return -1;\n"
            "    return GetData(data);\n  }\n", "")
        self.assertEqual(finding_rule(run({"stub.cpp": STUB.replace(
            "  int OnGetPasteData(Parcel &data) {\n"
            "    return GetPasteData(data);\n  }\n", ""),
            "service.cpp": no_sensitive_path}),
            "ipc.auth.privileged-app-bypass"), [])


if __name__ == "__main__":
    unittest.main()

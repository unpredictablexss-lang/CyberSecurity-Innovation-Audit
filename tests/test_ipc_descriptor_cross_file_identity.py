"""Descriptor identity can be established from declarations in other scoped source units.

This models the CVE-2025-26693 scope experiment: scanning only the dispatcher
implementation leaves interface identity unresolved, while adding the stub and
interface declarations lets the scanner accept the valid descriptor guard.
A wrong interface must remain a candidate.
"""
import hashlib
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest

RULE = "ipc.relay.descriptor-boundary"

INTERFACE = """
class IAccessTokenManager {
public:
    static const char *GetDescriptor();
};
class IWrongInterface {
public:
    static const char *GetDescriptor();
};
"""

STUB = """
template <class T> class IRemoteStub {};
class MessageParcel {};
class MessageOption {};
class AccessTokenManagerStub : public IRemoteStub<IAccessTokenManager> {
public:
    using RequestFuncType = void (AccessTokenManagerStub::*)(MessageParcel &, MessageParcel &);
    RequestFuncType requestFunc;
    int OnRemoteRequest(unsigned code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void Handle(MessageParcel &, MessageParcel &);
};
"""

def dispatcher(descriptor):
    return f"""
int AccessTokenManagerStub::OnRemoteRequest(unsigned code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{{
    auto token = data.ReadInterfaceToken();
    if (token != {descriptor}::GetDescriptor()) return -1;
    auto requestFunc = this->requestFunc;
    if (requestFunc != nullptr) {{
        (this->*requestFunc)(data, reply);
        return 0;
    }}
    return -1;
}}
"""

def run_sources(sources):
    units = []
    ast = {}
    for path, text in sources.items():
        index = parse_source(text, language="cpp")
        units.append(SourceUnit(path, "cpp", text, hashlib.sha256(text.encode()).hexdigest(),
                                index.parse_status))
        ast[path] = index.to_dict()
    units = tuple(sorted(units, key=lambda unit: unit.path))
    request = ScanRequest("descriptor-cross-file-test", "fixture/ipc",
                          "descriptor-cross-file-v1", snapshot_digest(units),
                          "current-component:fixture/ipc")
    context = ScanContext(request, units, {"ast": ast})
    return IpcInterfaceDetector().detect(context, context.units)

def auth01(run):
    return [finding for finding in run.findings if finding.rule_id == RULE]

class CrossFileDescriptorIdentityTests(unittest.TestCase):
    def test_correct_interface_guard_is_recognized_from_other_source_units(self):
        run = run_sources({
            "interfaces/i_access_token_manager.h": INTERFACE,
            "service/access_token_manager_stub.h": STUB,
            "service/access_token_manager_stub.cpp": dispatcher("IAccessTokenManager"),
        })
        self.assertEqual(auth01(run), [])

    def test_comparison_to_a_different_declared_interface_remains_a_candidate(self):
        run = run_sources({
            "interfaces/i_access_token_manager.h": INTERFACE,
            "service/access_token_manager_stub.h": STUB,
            "service/access_token_manager_stub.cpp": dispatcher("IWrongInterface"),
        })
        findings = auth01(run)
        self.assertEqual(len(findings), 1, [finding.message for finding in findings])
        self.assertIn("descriptor_identity_mismatch",
                      {obligation.kind for obligation in findings[0].evidence_obligations})

    def test_missing_class_and_interface_context_stays_unresolved_not_suppressed(self):
        run = run_sources({
            "service/access_token_manager_stub.cpp": dispatcher("IAccessTokenManager"),
        })
        findings = auth01(run)
        self.assertEqual(len(findings), 1, [finding.message for finding in findings])
        self.assertIn("descriptor_identity_unresolved",
                      {obligation.kind for obligation in findings[0].evidence_obligations})

if __name__ == "__main__":
    unittest.main()

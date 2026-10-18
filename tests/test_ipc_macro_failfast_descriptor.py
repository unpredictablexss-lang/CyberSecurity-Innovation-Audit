"""Source-defined fail-fast macros preserve descriptor guard facts."""
import hashlib
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest


PREFIX = '''#include "common_types.h"
class IFixture { public: static const char *GetDescriptor(); };
#define FALSE_RETURN_V(exec, ret) do { bool returnValue = (exec); if (!returnValue) { LOG("guard " #exec); return ret; } } while (0)
class Stub : public IRemoteStub<IFixture> {
public:
  std::map<int, Handler> handlers;
  int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};
'''


def run(body, macro=PREFIX):
    text = macro + body
    index = parse_source(text, language="cpp")
    unit = SourceUnit("sample.cpp", "cpp", text,
                      hashlib.sha256(text.encode()).hexdigest(), index.parse_status)
    request = ScanRequest("ipc-test", "fixture/ipc", "synthetic-ipc-v1",
                          snapshot_digest((unit,)), "current-component:fixture/ipc")
    context = ScanContext(request, (unit,), {"ast": {"sample.cpp": index.to_dict()}})
    return IpcInterfaceDetector().detect(context, context.units)


ENTRY = '''int Stub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option) {
  auto it = handlers.find(code);
  if (it == handlers.end()) return -1;
  FALSE_RETURN_V(GetDescriptor() == data.ReadInterfaceToken(), -1);
  return (this->*(it->second))(data, reply, option);
}
'''


def relay_candidates(result):
    return [item for item in result.findings
            if item.rule_id == "ipc.relay.descriptor-boundary"]


class MacroFailFastDescriptorTests(unittest.TestCase):
    def test_source_proven_false_return_macro_guards_member_pointer_dispatch(self):
        self.assertEqual(relay_candidates(run(ENTRY)), [])

    def test_wrong_parcel_does_not_guard_the_request_parcel(self):
        body = ENTRY.replace("data.ReadInterfaceToken()", "reply.ReadInterfaceToken()")
        self.assertTrue(relay_candidates(run(body)))

    def test_logging_only_macro_does_not_credit_a_guard(self):
        macro = PREFIX.replace("return ret;", "LOG(\"continue\");")
        self.assertTrue(relay_candidates(run(ENTRY, macro)))

    def test_conditional_definition_does_not_credit_a_guard(self):
        macro = PREFIX.replace(
            "#define FALSE_RETURN_V(exec, ret)",
            "#if FEATURE_X\n#define FALSE_RETURN_V(exec, ret)",
        ).replace("} while (0)\nclass Stub", "} while (0)\n#endif\nclass Stub")
        self.assertTrue(relay_candidates(run(ENTRY, macro)))

    def test_local_token_compare_zero_guards_member_pointer_dispatch(self):
        body = ENTRY.replace(
            "FALSE_RETURN_V(GetDescriptor() == data.ReadInterfaceToken(), -1);",
            "std::u16string token = data.ReadInterfaceToken();\n"
            "  if (token.compare(IFixture::GetDescriptor()) != 0) return -1;",
        )
        self.assertEqual(relay_candidates(run(body)), [])

    def test_compare_against_a_different_interface_stays_a_candidate(self):
        body = ENTRY.replace(
            "FALSE_RETURN_V(GetDescriptor() == data.ReadInterfaceToken(), -1);",
            "std::u16string token = data.ReadInterfaceToken();\n"
            "  if (token.compare(IUnrelated::GetDescriptor()) != 0) return -1;",
        )
        self.assertTrue(relay_candidates(run(body)))

    def test_compare_on_the_wrong_parcel_stays_a_candidate(self):
        body = ENTRY.replace(
            "FALSE_RETURN_V(GetDescriptor() == data.ReadInterfaceToken(), -1);",
            "std::u16string token = reply.ReadInterfaceToken();\n"
            "  if (token.compare(IFixture::GetDescriptor()) != 0) return -1;",
        )
        self.assertTrue(relay_candidates(run(body)))

    def test_ignored_compare_result_is_not_a_guard(self):
        body = ENTRY.replace(
            "FALSE_RETURN_V(GetDescriptor() == data.ReadInterfaceToken(), -1);",
            "std::u16string token = data.ReadInterfaceToken();\n"
            "  token.compare(IFixture::GetDescriptor());",
        )
        self.assertTrue(relay_candidates(run(body)))


if __name__ == "__main__":
    unittest.main()

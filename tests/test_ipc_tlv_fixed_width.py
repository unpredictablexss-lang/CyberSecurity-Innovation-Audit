import hashlib
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.detectors.interface.tlv_fixed_width import find_fixed_width_tlv_overreads
from src.ohscanner.fixture import snapshot_digest


VULNERABLE = """
template<typename T> bool ReadBasicValue(const std::vector<uint8_t> &buffer,
    T &value, const TLVHead &head) {
    if (head.len == 0) return false;
    if (!HasExpectBuffer(buffer, head.len)) return false;
    auto ret = memcpy_s(&value, sizeof(T), buffer.data() + cursor_, sizeof(T));
    return ret == EOK;
}
"""

FIXED = VULNERABLE.replace(
    "if (head.len == 0) return false;",
    "if (head.len == 0 || head.len != sizeof(T)) return false;",
)


def run(source):
    path = "framework/tlv/tlv_object.h"
    unit = SourceUnit(path, "cpp", source, hashlib.sha256(source.encode()).hexdigest(), "complete")
    request = ScanRequest("tlv-test", "fixture/tlv", "synthetic-tlv-v1",
                          snapshot_digest((unit,)), "current-component:fixture/tlv")
    tree = parse_source(source, language="cpp")
    context = ScanContext(request, (unit,), {"ast": {path: tree.to_dict()}})
    return IpcInterfaceDetector().detect(context, (unit,))


class TlvFixedWidthTests(unittest.TestCase):
    def test_vulnerable_fixed_width_tlv_copy_is_candidate(self):
        self.assertEqual(len(find_fixed_width_tlv_overreads(VULNERABLE)), 1)
        findings = [f for f in run(VULNERABLE).findings
                    if f.rule_id == "ipc.tlv.fixed-width-length"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].candidate_cwe, "CWE-125")
        self.assertEqual(findings[0].consequence_impact, "out_of_bounds_read")
        self.assertEqual({item.kind for item in findings[0].evidence_obligations},
                         {"serialized_input_binding", "source_extent", "entry_reachability", "security_impact"})

    def test_fixed_width_guard_removes_candidate(self):
        self.assertEqual(find_fixed_width_tlv_overreads(FIXED), ())
        self.assertFalse(any(f.rule_id == "ipc.tlv.fixed-width-length" for f in run(FIXED).findings))

    def test_similar_copy_without_tlv_contract_is_not_candidate(self):
        source = VULNERABLE.replace("const TLVHead &head", "const Header &head")
        self.assertEqual(find_fixed_width_tlv_overreads(source), ())

    def test_late_width_check_does_not_suppress_candidate(self):
        source = VULNERABLE.replace(
            "if (head.len == 0) return false;",
            "if (head.len == 0) return false;",
        ).replace(
            "    return ret == EOK;",
            "    if (head.len != sizeof(T)) return false;\n    return ret == EOK;",
        )
        self.assertEqual(len(find_fixed_width_tlv_overreads(source)), 1)

    def test_nested_conditional_width_check_does_not_suppress_candidate(self):
        source = VULNERABLE.replace(
            "if (head.len == 0) return false;",
            "if (head.len == 0) return false;\n    if (condition) { if (head.len != sizeof(T)) return false; }",
        )
        self.assertEqual(len(find_fixed_width_tlv_overreads(source)), 1)


if __name__ == "__main__":
    unittest.main()

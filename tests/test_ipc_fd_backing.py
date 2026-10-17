"""Controls for same-receiver Parcel fd backing checks."""
import hashlib
import unittest

from src.ohscanner.contracts import SourceUnit
from src.ohscanner.detectors.interface.fd_backing import detect_fd_backing_findings


CALLER = """
class MessageParcelWarp { public: const void *ReadRawData(MessageParcel &, size_t); };
int OnGetRecordValueByType(MessageParcel &data, int64_t rawDataSize) {
    MessageParcelWarp messageData;
    return messageData.ReadRawData(data, rawDataSize) != nullptr;
}
"""


def implementation(check="", fd="fd", size="size"):
    return f"""
const void *MessageParcelWarp::ReadRawData(MessageParcel &parcelPata, size_t size) {{
    int {fd} = parcelPata.ReadFileDescriptor();
    {check}
    return ::mmap(nullptr, {size}, PROT_READ, MAP_SHARED, {fd}, 0);
}}
"""


def units(body, caller=CALLER):
    values = []
    for path, text in (("stub.cpp", caller), ("message_parcel_warp.cpp", body)):
        values.append(SourceUnit(path, "cpp", text,
            hashlib.sha256(text.encode()).hexdigest(), "complete"))
    return tuple(values)


class FdBackingTests(unittest.TestCase):
    def test_unsafe_same_fd_and_size_is_candidate(self):
        found, limitations = detect_fd_backing_findings(units(implementation()))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].file, "stub.cpp")
        self.assertEqual(found[0].rule_id, "ipc.parcel.fd-backing-size")
        self.assertIn("unique ReadRawData body", found[0].message)
        self.assertEqual(limitations, ())

    def test_same_fd_explicit_reject_before_mmap_suppresses(self):
        check = "auto actualSize = AshmemGetSize(fd); if (actualSize < 0 || size > actualSize) { return nullptr; }"
        found, _ = detect_fd_backing_findings(units(implementation(check)))
        self.assertEqual(found, ())

    def test_unbound_macro_return_on_valid_path_and_partial_return_keep_candidate(self):
        for check in (
            "auto actualSize = AshmemGetSize(fd); CHECK_AND_RETURN_RET_LOGE(actualSize >= 0 && size <= actualSize, nullptr);",
            "auto actualSize = AshmemGetSize(fd); if (actualSize >= 0 && size <= actualSize) { return nullptr; }",
            "auto actualSize = AshmemGetSize(fd); if (actualSize >= 0 && size > actualSize) { if (flag) return nullptr; }",
            "auto actualSize = AshmemGetSize(fd); actualSize = 1000000; if (actualSize < 0 || size > actualSize) return nullptr;",
            "auto actualSize = AshmemGetSize(fd); if (actualSize < 0 || size > actualSize) return nullptr; size += 1;",
            "auto actualSize = AshmemGetSize(fd); if (actualSize < 0 || size > actualSize) return nullptr; fd = otherFd;",
        ):
            with self.subTest(check=check):
                found, _ = detect_fd_backing_findings(units(implementation(check)))
                self.assertEqual(len(found), 1)
                self.assertTrue(any(o.kind == "receiver_and_guard_binding" for o in found[0].evidence_obligations))

    def test_checking_a_different_fd_does_not_suppress(self):
        check = ("auto actualSize = AshmemGetSize(otherFd);\n"
                 "    CHECK_AND_RETURN_RET_LOGE(actualSize >= 0 && "
                 "static_cast<int64_t>(size) <= actualSize, nullptr);")
        found, _ = detect_fd_backing_findings(units(implementation(check)))
        self.assertEqual(len(found), 1)

    def test_late_capacity_check_does_not_suppress(self):
        check = ("auto actualSize = AshmemGetSize(fd);\n"
                 "    CHECK_AND_RETURN_RET_LOGE(actualSize >= 0 && "
                 "static_cast<int64_t>(size) <= actualSize, nullptr);")
        body = implementation().replace("return ::mmap", "auto *mapped = ::mmap").replace(
            "fd, 0);", "fd, 0);\n    " + check + "\n    return mapped;")
        found, _ = detect_fd_backing_findings(units(body))
        self.assertEqual(len(found), 1)

    def test_log_only_capacity_comparison_does_not_suppress(self):
        check = ("auto actualSize = AshmemGetSize(fd);\n"
                 "    if (actualSize < 0 || size > actualSize) { LOG_ERROR(); }")
        found, _ = detect_fd_backing_findings(units(implementation(check)))
        self.assertEqual(len(found), 1)

    def test_untyped_receiver_is_not_resolved_by_method_name(self):
        caller = ("int handler(MessageParcel &data, size_t size) { "
                  "unknown.ReadRawData(data, size); return 0; }")
        found, _ = detect_fd_backing_findings(units(implementation(), caller))
        self.assertEqual(found, ())

    def test_ambiguous_implementation_is_not_guessed(self):
        body = implementation()
        duplicate = SourceUnit("second.cpp", "cpp", body,
            hashlib.sha256(body.encode()).hexdigest(), "complete")
        found, limitations = detect_fd_backing_findings(units(body) + (duplicate,))
        self.assertEqual(found, ())
        self.assertTrue(any("absent or ambiguous" in item for item in limitations))


if __name__ == "__main__":
    unittest.main()

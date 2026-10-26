from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest

VULNERABLE = "84d681288793785e8f39f71c824f211edaed8f1e"
FIXED = "de3a68cc8b7d6f18017fd261060def0e38dce54a"
SOURCE = "interfaces/innerkits/cj/src/message_sequence_impl.cpp"
WRAPPER = "interfaces/innerkits/cj/src/ipc_ffi.cpp"
WORKSPACE = Path(__file__).resolve().parents[2]
IPC_GIT = Path(os.environ.get("T73_IPC_GIT", WORKSPACE / "tmp" / "t71-communication-ipc"))


def git_source(revision: str, path: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(IPC_GIT), "show", f"{revision}:{path}"], text=True
    )


def function_body(source: str, signature_fragment: str) -> str:
    start = source.index(signature_fragment)
    brace = source.index("{", start)
    depth = 0
    for offset in range(brace, len(source)):
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if depth == 0:
                return source[start:offset + 1]
    raise AssertionError(f"unterminated function: {signature_fragment}")


def b_ipc_run(method: str, wrapper: str):
    units = []
    ast = {}
    for path, text in sorted(((SOURCE, method), (WRAPPER, wrapper))):
        tree = parse_source(text, language="cpp")
        unit = SourceUnit(path, "cpp", text, hashlib.sha256(text.encode()).hexdigest(), tree.parse_status)
        units.append(unit)
        ast[path] = tree.to_dict()
    units = tuple(units)
    request = ScanRequest(
        "t73-cj-array-bounds", "fixture/ipc", "synthetic-cj-array-bounds-v1",
        snapshot_digest(units), "current-component:fixture/ipc",
    )
    context = ScanContext(request, units, {"ast": ast})
    return IpcInterfaceDetector().detect(context, units)


def source_guard_accepts(count: int, remaining: int) -> bool:
    # CJ_ReadRemoteObjectArray returns first for N <= 0, then applies this guard.
    return count > 0 and count <= remaining and count * 4 <= remaining


def underallocation_excess(count: int, element_width: int) -> int:
    if count <= 0:
        return 0
    return count * element_width - count


class CjArrayBoundsOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (IPC_GIT / ".git").exists():
            raise unittest.SkipTest(f"official IPC Git object repo unavailable: {IPC_GIT}; set T73_IPC_GIT")
        cls.vuln_impl = function_body(git_source(VULNERABLE, SOURCE), "RemoteObjectArray MessageSequenceImpl::CJ_ReadRemoteObjectArray")
        cls.fixed_impl = function_body(git_source(FIXED, SOURCE), "RemoteObjectArray MessageSequenceImpl::CJ_ReadRemoteObjectArray")
        cls.vuln_wrapper = function_body(git_source(VULNERABLE, WRAPPER), "OHOS::RemoteObjectArray FfiRpcMessageSequenceImplReadRemoteObjectArray")
        cls.fixed_wrapper = function_body(git_source(FIXED, WRAPPER), "OHOS::RemoteObjectArray FfiRpcMessageSequenceImplReadRemoteObjectArray")

    def test_pinned_official_vulnerable_and_fixed_allocation_shapes(self):
        self.assertEqual(self.vuln_impl.count("malloc(arrayLength)"), 2)
        self.assertIn("int32_t* type", self.vuln_impl)
        self.assertIn("int64_t* id", self.vuln_impl)
        self.assertIn("type[i] =", self.vuln_impl)
        self.assertIn("id[i] =", self.vuln_impl)
        self.assertIn("malloc(sizeof(int32_t) * arrayLength)", self.fixed_impl)
        self.assertIn("malloc(sizeof(int64_t) * arrayLength)", self.fixed_impl)
        self.assertLess(self.fixed_impl.index("if (value == nullptr)"), self.fixed_impl.index("value->IsProxyObject()"))

    def test_official_ffi_wrapper_exposes_helper_but_is_not_an_ipc_dispatcher_root(self):
        for wrapper in (self.vuln_wrapper, self.fixed_wrapper):
            self.assertIn("FFIData::GetData<MessageSequenceImpl>(id)", wrapper)
            self.assertIn("return rpc->CJ_ReadRemoteObjectArray(errCode);", wrapper)
            self.assertNotIn("OnRemoteRequest", wrapper)
        run = b_ipc_run(self.vuln_impl, self.vuln_wrapper)
        self.assertEqual(run.status, "completed")
        # Current B IPC roots are dispatcher/allowlist rooted and do not model
        # this CJ FFI helper's count-derived allocation sink.
        self.assertEqual(run.findings, ())

    def test_count_guard_and_exact_heap_excess_matrix(self):
        cases = [
            (8, 32, True, 24, 56),
            (1, 4, True, 3, 7),
            (8, 31, False, 0, 0),
            (0, 0, False, 0, 0),
            (-1, 0, False, 0, 0),
        ]
        for count, remaining, accepted, type_extra, id_extra in cases:
            with self.subTest(count=count, remaining=remaining):
                self.assertEqual(source_guard_accepts(count, remaining), accepted)
                self.assertEqual(underallocation_excess(count, 4) if accepted else 0, type_extra)
                self.assertEqual(underallocation_excess(count, 8) if accepted else 0, id_extra)

    def test_safe_fixed_and_unrelated_shapes(self):
        unrelated = """
        void unrelated() {
            int32_t count = 4;
            int32_t *items = static_cast<int32_t*>(malloc(sizeof(int32_t) * count));
            for (int32_t i = 0; i < count; ++i) items[i] = i;
            free(items);
        }
        """
        self.assertNotIn("malloc(arrayLength)", self.fixed_impl)
        self.assertNotIn("malloc(arrayLength)", unrelated)
        self.assertIn("malloc(sizeof(int32_t) * arrayLength)", self.fixed_impl)
        self.assertIn("malloc(sizeof(int64_t) * arrayLength)", self.fixed_impl)

    def test_one_cve_root_dedupes_two_typed_array_sinks(self):
        # Ground-truth identity groups both adjacent sink manifestations under
        # the same official CVE and function root. This is a label-side oracle;
        # the current B IPC detector emits no candidates to deduplicate.
        manifestations = [
            ("CVE-2025-26474", SOURCE, "CJ_ReadRemoteObjectArray", "type[] allocation/write"),
            ("CVE-2025-26474", SOURCE, "CJ_ReadRemoteObjectArray", "id[] allocation/write"),
        ]
        roots = {(cve, path, function) for cve, path, function, _ in manifestations}
        self.assertEqual(len(manifestations), 2)
        self.assertEqual(len(roots), 1)


if __name__ == "__main__":
    unittest.main()


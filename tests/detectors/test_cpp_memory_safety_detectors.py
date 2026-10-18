from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.bounds_detector import CppBoundsDetector
from src.ohscanner.detectors.cpp.integer_bounds_detector import CppIntegerBoundsDetector
from src.ohscanner.fixture import snapshot_digest


def unit(path: str, text: str, parse_status: str = "complete") -> SourceUnit:
    return SourceUnit(
        path=path,
        language="cpp",
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        parse_status=parse_status,
    )


def context_for(*units: SourceUnit) -> ScanContext:
    return ScanContext(
        request=ScanRequest(
            request_id="test:a-memory-safety-controls",
            repository="fixture/ohscanner-memory-safety",
            commit="1" * 40,
            snapshot_sha256=snapshot_digest(units),
            target_id="current-component:fixture/ohscanner-memory-safety",
            profile_id="fixture-no-build",
            provenance="fixture",
        ),
        units=tuple(sorted(units, key=lambda item: item.path)),
    )


class BoundsDetectorControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = CppBoundsDetector()

    def test_identity_and_candidate_source_binding(self) -> None:
        source = unit("positive/overflow_copy.cpp", """
void positive(char *src, unsigned int n) {
    char dst[8];
    memcpy(dst, src, n);
    dst[16] = 1;
}
""")
        run = self.detector.detect(context_for(source), (source,))
        self.assertEqual(self.detector.detector_id, "ohscanner.cpp.bounds")
        self.assertEqual(self.detector.version, "0.2.3")
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 2)
        self.assertEqual({item.rule_id for item in run.findings}, {
            "ohcpp-memory-bounds-copy-candidate-001",
            "ohcpp-memory-bounds-index-candidate-002",
        })
        for finding in run.findings:
            self.assertEqual(finding.source_sha256, source.sha256)
            self.assertEqual(finding.rule_version, "0.2.3")
            self.assertEqual(finding.rule_lineage_id, "A-BOF-01:ohcpp-memory-bounds-candidate")
            self.assertEqual(finding.identity_quality, "partial")
            self.assertGreaterEqual(len(finding.evidence_obligations), 7)

    def test_fixed_guard_and_exact_capacity_are_quiet(self) -> None:
        fixed = unit("fixed/copy_guard.cpp", """
void fixed(char *src, unsigned int n) {
    char dst[8];
    if (n >= 8) return;
    memcpy(dst, src, n);
    if (n > 7) return;
    dst[n] = 1;
}
""")
        exact = unit("safe/exact_copy.cpp", """
void exact(char *src) {
    char dst[8];
    memcpy(dst, src, sizeof(dst));
    dst[7] = 1;
}
""")
        run = self.detector.detect(context_for(fixed, exact), (fixed, exact))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())

    def test_direct_sort_element_access_without_stability_guard_is_candidate(self) -> None:
        source = unit("positive/sort_element_access.cpp", """
struct Handle {};
struct Value {};
namespace ElementAccessor {
Value Get(Handle, unsigned int);
void Set(Handle, unsigned int, Value, bool);
}
void SortElementsByObject(Handle h, Value v, unsigned int len) {
    for (unsigned int i = 1; i < len; i++) {
        Value x = ElementAccessor::Get(h, i);
        ElementAccessor::Set(h, i, x, false);
    }
}
""")
        run = self.detector.detect(context_for(source), (source,))
        self.assertGreaterEqual(len(run.findings), 2)
        self.assertIn("ohcpp-memory-bounds-element-access-candidate-003", {item.rule_id for item in run.findings})

    def test_stable_array_wrapper_and_unrelated_accessor_are_quiet(self) -> None:
        source = unit("fixed/stable_element_access.cpp", """
struct Handle {};
struct Value {};
namespace ElementAccessor {
Value Get(Handle, unsigned int);
void Set(Handle, unsigned int, Value, bool);
unsigned int GetElementsLength(Handle);
}
Value CheckStableArrayAndGet(Handle h, unsigned int index) {
    if (index < ElementAccessor::GetElementsLength(h)) return ElementAccessor::Get(h, index);
    return Value();
}
void Unrelated(Handle h) { ElementAccessor::Set(h, 0, Value(), false); }
""")
        run = self.detector.detect(context_for(source), (source,))
        self.assertEqual(run.findings, ())
    def test_unrelated_dynamic_destination_is_unknown_not_candidate(self) -> None:
        source = unit("unrelated/dynamic.cpp", """
void unrelated(char *dst, char *src, unsigned int n) {
    memcpy(dst, src, n);
}
""")
        run = self.detector.detect(context_for(source), (source,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())

    def test_partial_parse_and_budget_fail_closed(self) -> None:
        partial = unit("unknown/partial.cpp", "void f(char *p) { memcpy(p, p, 8);", "partial")
        run = self.detector.detect(context_for(partial), (partial,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.analyzed_files, ())
        self.assertEqual(run.findings, ())

        oversized = unit("unknown/oversized.cpp", "char x[1];" + " " * (1024 * 1024))
        run = self.detector.detect(context_for(oversized), (oversized,))
        self.assertEqual(run.status, "failed")
        self.assertTrue(any("1MiB" in item for item in run.limitations))

    def test_output_is_deterministic(self) -> None:
        source = unit("positive/deterministic.cpp", """
void positive(char *src, unsigned int n) {
    char dst[4];
    memcpy(dst, src, n);
}
""")
        first = self.detector.detect(context_for(source), (source,))
        second = self.detector.detect(context_for(source), (source,))
        self.assertEqual(first, second)


class IntegerBoundsDetectorControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = CppIntegerBoundsDetector()

    def test_positive_multiplication_and_truncation(self) -> None:
        source = unit("positive/integer.cpp", """
#include <cstdlib>
#include <cstring>
void positive(char *src, size_t count, size_t size) {
    size_t bytes = count * size;
    void *dst = malloc(bytes);
    memcpy(dst, src, bytes);
    uint8_t total = 255 + 1;
}
""")
        run = self.detector.detect(context_for(source), (source,))
        self.assertEqual(self.detector.detector_id, "ohscanner.cpp.integer_bounds")
        self.assertEqual(run.status, "completed")
        self.assertGreaterEqual(len(run.findings), 2)
        self.assertIn("ohcpp-integer-bounds-arithmetic-candidate-001", {item.rule_id for item in run.findings})
        self.assertIn("ohcpp-integer-bounds-truncation-candidate-002", {item.rule_id for item in run.findings})
        for finding in run.findings:
            self.assertEqual(finding.source_sha256, source.sha256)
            self.assertEqual(finding.rule_lineage_id, "A-INT-01:ohcpp-integer-bounds-candidate")

    def test_checked_multiplication_and_exact_guard_are_quiet(self) -> None:
        checked = unit("fixed/checked_mul.cpp", """
#include <cstdlib>
void checked(size_t count, size_t size) {
    if (count > SIZE_MAX / size) return;
    size_t bytes = count * size;
    void *dst = malloc(bytes);
}
""")
        intrinsic = unit("safe/mul_overflow.cpp", """
#include <cstdlib>
void intrinsic(size_t count, size_t size) {
    size_t bytes = 0;
    if (__builtin_mul_overflow(count, size, &bytes)) return;
    void *dst = malloc(bytes);
}
""")
        run = self.detector.detect(context_for(checked, intrinsic), (checked, intrinsic))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())

    def test_macro_only_allocation_size_remains_unknown_not_alert(self) -> None:
        source = unit("unknown/macro_alloc.cpp", """
#define MAX_ITEMS 32
void unknown_macro() {
    void *dst = malloc(MAX_ITEMS + 1);
}
""")
        run = self.detector.detect(context_for(source), (source,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())

    def test_narrow_integer_index_before_bounds_check_is_candidate(self) -> None:
        source = unit("positive/narrow_atomic_index.cpp", """
#include <cstdint>
double DoubleInRangeInt32(double value);
unsigned int GetArrayLength();
unsigned int GetSizeFromType();
void Validate(unsigned int offset, double request) {
    int32_t length = static_cast<int32_t>(GetArrayLength());
    int32_t index = DoubleInRangeInt32(request);
    if (index >= length) return;
    unsigned int elementSize = GetSizeFromType();
    unsigned int allOffset = static_cast<uint32_t>(index) * elementSize + offset;
    (void)allOffset;
}
""")
        run = self.detector.detect(context_for(source), (source,))
        self.assertIn("ohcpp-integer-bounds-narrow-index-candidate-003", {item.rule_id for item in run.findings})
    def test_reviewed_false_positive_shapes_are_quiet(self) -> None:
        source = unit("fixed/reviewed_fp_shapes.cpp", """
#include <cstdlib>
#include <cstring>
#define MAX_KEY_LEN 32
struct Header {};
void reviewed(char *key, char *value, char *pos, ssize_t offset, ssize_t size) {
    size_t keyLen = strnlen(key, MAX_KEY_LEN);
    if (keyLen >= MAX_KEY_LEN) return;
    char *copy = (char *)malloc(keyLen + 1);
    uint16_t small = 7;
    char *smallCopy = (char *)malloc(small + 1);
    auto start = reinterpret_cast<uint32_t *>(new (pos + offset) char[size]);
    (void)copy; (void)smallCopy; (void)start;
}
""")
        run = self.detector.detect(context_for(source), (source,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())

    def test_calloc_and_new_array_element_multiplication(self) -> None:
        positive = unit("positive/calloc_new_multiply.cpp", """
#include <cstdint>
#include <cstdlib>
void positive(size_t count) {
    void *buffer = calloc(count, 4);
    uint32_t *items = new uint32_t[count];
    (void)buffer;
    (void)items;
}
""")
        run = self.detector.detect(context_for(positive), (positive,))
        self.assertEqual(run.status, "completed")
        self.assertGreaterEqual(len(run.findings), 2)
        self.assertEqual(
            {item.rule_id for item in run.findings},
            {"ohcpp-integer-bounds-arithmetic-candidate-001"},
        )

        safe = unit("safe/calloc_new_multiply.cpp", """
#include <cstdint>
#include <cstdlib>
void safe(size_t count) {
    void *buffer = calloc(count, 1);
    char *items = new char[count];
    (void)buffer;
    (void)items;
}
""")
        safe_run = self.detector.detect(context_for(safe), (safe,))
        self.assertEqual(safe_run.findings, ())

        fixed = unit("fixed/calloc_new_multiply.cpp", """
#include <cstdint>
#include <cstdlib>
void fixed(size_t count) {
    if (count > SIZE_MAX / 4) return;
    void *buffer = calloc(count, 4);
    uint32_t *items = new uint32_t[count];
    (void)buffer;
    (void)items;
}
""")
        fixed_run = self.detector.detect(context_for(fixed), (fixed,))
        self.assertEqual(fixed_run.findings, ())

    def test_subtraction_without_lower_bound_is_candidate(self) -> None:
        source = unit("positive/subtraction.cpp", """
void positive(char *src, size_t len) {
    size_t payload = len - 4;
    memcpy(src, src, payload);
}
""")
        run = self.detector.detect(context_for(source), (source,))
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].candidate_cwe, "CWE-191")

    def test_unrelated_addition_is_not_an_every_operator_alert(self) -> None:
        source = unit("unrelated/add.cpp", """
int unrelated(int a, int b) {
    int sum = a + b;
    return sum;
}
""")
        run = self.detector.detect(context_for(source), (source,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())

    def test_partial_parse_and_budget_fail_closed(self) -> None:
        partial = unit("unknown/partial.cpp", "void f(size_t n) { size_t x = n * n;", "failed")
        run = self.detector.detect(context_for(partial), (partial,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        oversized = unit("unknown/oversized.cpp", "int x;" + " " * (1024 * 1024))
        run = self.detector.detect(context_for(oversized), (oversized,))
        self.assertEqual(run.status, "failed")
        self.assertTrue(any("1MiB" in item for item in run.limitations))


class MemorySafetyControlManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).parent / "fixtures" / "cpp_memory_safety"
        cls.manifest = json.loads((cls.root / "manifest.json").read_text(encoding="utf-8"))

    def test_manifest_is_hash_bound_and_covers_four_control_classes(self) -> None:
        self.assertEqual(self.manifest["schema_version"], 1)
        self.assertEqual(
            {item["category"] for item in self.manifest["cases"]},
            {"positive", "fixed", "safe", "unrelated", "unknown"},
        )
        for item in self.manifest["cases"]:
            path = self.root / item["fixture"]
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_size, item["byte_length"])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])

    def test_fixture_matrix_matches_expected_detector_signal(self) -> None:
        bounds = CppBoundsDetector()
        integer = CppIntegerBoundsDetector()
        for item in self.manifest["cases"]:
            path = self.root / item["fixture"]
            text = path.read_text(encoding="utf-8")
            source = unit(f"fixtures/cpp_memory_safety/{item['fixture']}", text, "partial" if item["category"] == "unknown" else "complete")
            detector = bounds if item["detector"] == "ohscanner.cpp.bounds" else integer
            run = detector.detect(context_for(source), (source,))
            if item["category"] == "unknown":
                self.assertEqual(run.status, item["expected_status"])
                self.assertEqual(run.findings, ())
                continue
            if "expected_min" in item:
                self.assertGreaterEqual(len(run.findings), item["expected_min"])
            if "expected_max" in item:
                self.assertLessEqual(len(run.findings), item["expected_max"])

    def test_malloc_symbolic_capacity_is_candidate_unknown(self) -> None:
        path = self.root / "bounds_malloc_symbolic.cpp"
        source = unit(
            "fixtures/cpp_memory_safety/bounds_malloc_symbolic.cpp",
            path.read_text(encoding="utf-8"),
        )
        run = CppBoundsDetector().detect(context_for(source), (source,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("allocation capacity", run.findings[0].message)
        self.assertIn("CWE-119", run.findings[0].candidate_cwe)

if __name__ == "__main__":
    unittest.main()

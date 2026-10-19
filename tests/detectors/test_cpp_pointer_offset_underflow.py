from __future__ import annotations

import hashlib
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.integer_bounds_detector import (
    CppIntegerBoundsDetector,
    RULE_POINTER_OFFSET,
)
from src.ohscanner.fixture import snapshot_digest


def unit(path: str, text: str, language: str = "c", parse_status: str = "complete") -> SourceUnit:
    return SourceUnit(
        path=path,
        language=language,
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        parse_status=parse_status,
    )


def context_for(*units: SourceUnit) -> ScanContext:
    return ScanContext(
        request=ScanRequest(
            request_id="test:a-pointer-offset-underflow",
            repository="fixture/ohscanner-pointer-offset-underflow",
            commit="2" * 40,
            snapshot_sha256=snapshot_digest(units),
            target_id="current-component:fixture/ohscanner-pointer-offset-underflow",
            profile_id="fixture-no-build",
            provenance="fixture",
        ),
        units=tuple(sorted(units, key=lambda item: item.path)),
    )


class PointerOffsetUnderflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = CppIntegerBoundsDetector()
        self.header = unit("include/image_info.h", """
typedef struct ImageInfo ImageInfo;
struct ImageInfo {
    uint32_t height;
};
""")

    def test_unsigned_member_difference_into_scaled_pointer_offset(self) -> None:
        source = unit("src/decode.c", """
#include <stdint.h>
#include "image_info.h"
void decode(uint32_t *pixels, uint32_t raster_rows, uint32_t stride, ImageInfo image) {
    consume(pixels + (raster_rows - image.height) * stride);
}
""")
        run = self.detector.detect(context_for(self.header, source), (self.header, source))
        findings = [item for item in run.findings if item.rule_id == RULE_POINTER_OFFSET]
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file, source.path)
        self.assertEqual(findings[0].candidate_cwe, "CWE-191")
        self.assertEqual(findings[0].source_sha256, source.sha256)

    def test_renamed_member_pointer_and_compound_cast_variant(self) -> None:
        source = unit("src/copy_rows.c", """
#include <stdint.h>
#include "image_info.h"
void copy_rows(uint32_t *destination, uint32_t capacity, uint32_t row_size, ImageInfo *metadata) {
    destination += (size_t)(capacity - metadata->height) * row_size;
}
""")
        run = self.detector.detect(context_for(self.header, source), (self.header, source))
        self.assertEqual(len([item for item in run.findings if item.rule_id == RULE_POINTER_OFFSET]), 1)

    def test_strict_positive_guard_matches_fixed_expression(self) -> None:
        fixed = unit("safe/fixed.c", """
#include <stdint.h>
#include "image_info.h"
void copy(uint32_t *raster, uint32_t height, uint32_t width, ImageInfo *image) {
    if (height > image->height) {
        raster += (size_t)(height - image->height) * width;
        consume(raster);
    }
}
""")
        run = self.detector.detect(context_for(self.header, fixed), (self.header, fixed))
        self.assertEqual([item for item in run.findings if item.rule_id == RULE_POINTER_OFFSET], [])

    def test_early_return_guard_and_unrelated_scalar_offset_are_quiet(self) -> None:
        guarded = unit("safe/early_return.c", """
#include <stdint.h>
#include "image_info.h"
void copy(uint32_t *raster, uint32_t height, uint32_t width, ImageInfo image) {
    if (height < image.height) return;
    consume(raster + (height - image.height) * width);
}
""")
        unrelated = unit("unrelated/scalar.c", """
#include <stdint.h>
void count_rows(uint32_t count, uint32_t capacity, uint32_t stride) {
    consume(count + (capacity - 1) * stride);
}
""")
        run = self.detector.detect(context_for(self.header, guarded, unrelated), (self.header, guarded, unrelated))
        self.assertEqual([item for item in run.findings if item.rule_id == RULE_POINTER_OFFSET], [])

    def test_partial_file_keeps_narrow_candidate_and_blocks_coverage(self) -> None:
        source = unit("src/partial.c", """
#include <stdint.h>
#include "image_info.h"
void decode(uint32_t *pixels, uint32_t rows, uint32_t stride, ImageInfo image) {
    consume(pixels + (rows - image.height) * stride);
}
""", parse_status="partial")
        run = self.detector.detect(context_for(self.header, source), (self.header, source))
        self.assertEqual(run.status, "blocked")
        findings = [item for item in run.findings if item.rule_id == RULE_POINTER_OFFSET]
        self.assertEqual(len(findings), 1)
        self.assertIn(source.path, run.analyzed_files)

    def test_signed_dimension_and_incomplete_source_are_not_positive(self) -> None:
        signed = unit("unrelated/signed.c", """
#include <stdint.h>
void decode(uint32_t *pixels, int rows, int stride) {
    consume(pixels + (rows - 1) * stride);
}
""")
        incomplete = unit("unknown/unparsed.c", "void decode({", parse_status="failed")
        run = self.detector.detect(context_for(signed, incomplete), (signed, incomplete))
        self.assertEqual(run.status, "blocked")
        self.assertEqual([item for item in run.findings if item.rule_id == RULE_POINTER_OFFSET], [])

    def test_partial_without_candidate_remains_unknown_and_blocked(self) -> None:
        partial = unit("unknown/partial_no_shape.c", """
#include <stdint.h>
void decode(uint32_t *pixels, uint32_t rows) {
    consume(pixels + rows);
}
""", parse_status="partial")
        run = self.detector.detect(context_for(partial), (partial,))
        self.assertEqual(run.status, "blocked")
        self.assertIn(partial.path, run.analyzed_files)
        self.assertEqual(run.findings, ())
        self.assertTrue(any("parser reported partial syntax" in item for item in run.limitations))


if __name__ == "__main__":
    unittest.main()

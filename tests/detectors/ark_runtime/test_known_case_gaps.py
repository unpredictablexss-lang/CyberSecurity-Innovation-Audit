from dataclasses import replace
from hashlib import sha1, sha256
import unittest

from src.ohscanner.detectors.ark_runtime.analysis import known_case_gap_ids_for_unit
from src.ohscanner.detectors.ark_runtime.detector import (
    ABRUPT_EXCEPTION_RULE_ID, ArkRuntimeTypeSafetyDetector)
from src.ohscanner.detectors.ark_runtime.size_overflow import analyze_size_overflow
from src.ohscanner.detectors.ark_runtime.unseen_detector import ArkRuntimeUnseenTypeSafetyDetector
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import run_all_with_coverage
from .support import case, context, unit


class KnownCaseGapTests(unittest.TestCase):
    def git_context(self, source):
        from src.parser.ast import parse_source
        base = context((source,))
        raw = source.text.encode("utf-8")
        blob = sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        request = replace(
            base.request,
            repository="openharmony/arkcompiler_ets_runtime",
            commit="e4e0761501a83ac25cc67d04c527eefe9f4a1b50",
            snapshot_sha256=snapshot_digest((source,)),
            target_id="current-component:openharmony/arkcompiler_ets_runtime",
            profile_id="light-ast",
            provenance="git_object",
        )
        return replace(base, request=request, shared_facts={
            "ast": {source.path: parse_source(source.text, "cpp").to_dict()},
            "source_blob_oid": {source.path: blob},
        })

    def scan(self, fixture):
        source = case(fixture)
        scan_context = self.git_context(source)
        detector = ArkRuntimeTypeSafetyDetector()
        selected = detector.select_applicable_units(scan_context, scan_context.units)
        return source, detector.detect(scan_context, selected), selected

    def test_iao7go_parent_is_applicable_and_conservatively_reported(self):
        source, result, selected = self.scan("C9_IAO7GO_parent")
        self.assertEqual(len(selected), 1)
        findings = [item for item in result.findings if item.rule_id == ABRUPT_EXCEPTION_RULE_ID]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].candidate_cwe, "CWE-755")
        self.assertEqual(findings[0].source_sha256, source.sha256)
        self.assertEqual(result.file_outcomes, ((source.path, "partial"),))

    def test_iao7go_fixed_and_safe_controls_do_not_repeat_root_cause(self):
        for fixture in ("C9_IAO7GO_fixed", "C9_IAO7GO_safe"):
            with self.subTest(fixture=fixture):
                source, result, selected = self.scan(fixture)
                self.assertEqual(len(selected), 1)
                self.assertFalse(any(item.rule_id == ABRUPT_EXCEPTION_RULE_ID
                                     for item in result.findings))

    def test_i7w51d_missing_rule_is_explicit_and_distinguished_from_boundary_fix(self):
        parent, parent_result, _ = self.scan("C9_I7W51D_parent")
        fixed, fixed_result, _ = self.scan("C9_I7W51D_fixed")
        self.assertEqual(parent_result.findings, ())
        self.assertEqual(fixed_result.findings, ())
        self.assertIn(parent.path + ": known_case_gap:I7W51D:signed_int32_length_narrowing_unmodeled",
                      parent_result.limitations)
        self.assertIn(fixed.path + ": known_case_gap:I7W51D:fixed_unsigned_length_boundary_unassessed_not_security",
                      fixed_result.limitations)

    def test_ib8bca_missing_rule_is_explicit_and_distinguished_from_boundary_fix(self):
        parent, parent_result, _ = self.scan("C9_IB8BCA_parent")
        fixed, fixed_result, _ = self.scan("C9_IB8BCA_fixed")
        self.assertEqual(parent_result.findings, ())
        self.assertEqual(fixed_result.findings, ())
        self.assertIn(parent.path + ": known_case_gap:IB8BCA:dataview_atomics_index_width_bounds_unmodeled",
                      parent_result.limitations)
        self.assertIn(fixed.path + ": known_case_gap:IB8BCA:fixed_index_width_boundary_unassessed_not_security",
                      fixed_result.limitations)

    def test_unrelated_control_is_not_applicable(self):
        source = case("C9_unrelated")
        self.assertEqual(known_case_gap_ids_for_unit(source), ())
        scan_context = self.git_context(source)
        detector = ArkRuntimeTypeSafetyDetector()
        self.assertEqual(detector.select_applicable_units(scan_context, scan_context.units), ())

    def test_catalog_selector_exposes_gap_files_as_auditable_unknown(self):
        expectations = {
            "C9_IAO7GO_parent": "IAO7GO:candidate_rule_routing_requires_strict_adapter",
            "C9_I7W51D_parent": "known_case_gap:I7W51D:signed_int32_length_narrowing_unmodeled",
            "C9_IB8BCA_parent": "known_case_gap:IB8BCA:dataview_atomics_index_width_bounds_unmodeled",
        }
        for fixture, limitation in expectations.items():
            with self.subTest(fixture=fixture):
                source = case(fixture)
                scan_context = self.git_context(source)
                detector = ArkRuntimeUnseenTypeSafetyDetector()
                selected = detector.select_applicable_units(scan_context, scan_context.units)
                self.assertEqual(len(selected), 1)
                result = detector.detect(scan_context, selected)
                self.assertIn(source.path + ": " + limitation, result.limitations)
                self.assertFalse(any("RangeError" in item.message for item in result.findings))

    def test_existing_size_positive_fixed_safe_unrelated_controls(self):
        positive = unit(r'''
void convert(uint32_t stride, uint32_t count) {
    uint32_t byteCount = stride * count;
    auto temporary = AllocateArrayBuffer(byteCount);
    BufferHandle destination;
    destination.Update(temporary);
    for (uint32_t i = count; i > 0; --i) {
        SetValueInBuffer(thread, destination.GetTaggedValue(), cursor, value);
        cursor += stride;
    }
}
''')
        fixed = unit(positive.text.replace("uint32_t byteCount = stride * count",
                                          "uint64_t byteCount = static_cast<uint64_t>(stride) * count"))
        safe = unit(positive.text.replace("uint32_t byteCount = stride * count",
                                         "uint64_t byteCount = static_cast<uint64_t>(stride) * count")
                    .replace("AllocateArrayBuffer", "AllocateSendableArrayBuffer"))
        unrelated = case("C9_unrelated")
        self.assertEqual(len(analyze_size_overflow(positive.text)[0]), 1)
        self.assertEqual(analyze_size_overflow(fixed.text)[0], ())
        self.assertEqual(analyze_size_overflow(safe.text)[0], ())
        self.assertEqual(analyze_size_overflow(unrelated.text)[0], ())


if __name__ == "__main__":
    unittest.main()

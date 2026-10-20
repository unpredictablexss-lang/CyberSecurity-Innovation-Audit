import unittest
from dataclasses import replace
from hashlib import sha256

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.ark_runtime.arraylike_set_bounds import (
    _DEPENDENCIES, _bytes_match, _has_wrap_shape, analyze_arraylike_set_bounds,
)
from src.ohscanner.detectors.ark_runtime.model import c_line_static_model
from src.ohscanner.fixture import snapshot_digest


_METHOD = '''
void method() {
    if (!argArray->IsTypedArray()) {
        if (argArray->IsStableJSArray(thread)) {
            return JSStableArray::FastCopyFromArrayToTypedArray(thread, targetObj, targetType,
                                                                targetOffset, length, argObj);
        }
        uint64_t srcLen = static_cast<uint64_t>(tSrcLen.GetNumber());
        if (srcLen + targetOffset > targetLength) {
            throwRangeError();
        }
        uint32_t targetByteIndex = static_cast<uint32_t>(targetOffset * targetElementSize + targetByteOffset);
        uint32_t limit = targetByteIndex + targetElementSize * srcLen;
        while (targetByteIndex < limit) {
            BuiltinsArrayBuffer::SetValueInBuffer(thread, targetBuffer.GetTaggedValue(),
                                                  targetByteIndex, targetType, kNumberHandle, true);
        }
    }
}
'''


def _wrapped_index_values(offset, src_len, target_byte_offset, element_size=1):
    mask64 = (1 << 64) - 1
    mask32 = (1 << 32) - 1
    accepted_sum = (offset + src_len) & mask64
    target_index = (offset * element_size + target_byte_offset) & mask32
    limit = (target_index + element_size * src_len) & mask32
    return accepted_sum, target_index, limit


def _source_range_check_accepts(offset, src_len, target_length):
    return ((offset + src_len) & ((1 << 64) - 1)) <= target_length


def _empty_context(repository='openharmony/arkcompiler_ets_runtime',
                   commit='a65a2853ccae13da167d9aa4720ab8b11ec16656',
                   provenance='git_object'):
    return ScanContext(
        ScanRequest('set-bounds-control', repository, commit, snapshot_digest(()),
                    'current-component:' + repository, 'light-ast', provenance),
        (), {})


class ArrayLikeSetBoundsTests(unittest.TestCase):
    def test_exact_ordinary_arraylike_path_is_candidate_shape(self):
        self.assertTrue(_has_wrap_shape(_METHOD))

    def test_subtraction_guard_fixes_wrapped_range_sum(self):
        fixed = _METHOD.replace(
            'if (srcLen + targetOffset > targetLength)',
            'if (targetOffset > targetLength || srcLen > targetLength - targetOffset)')
        self.assertFalse(_has_wrap_shape(fixed))

    def test_stable_array_fast_path_alone_is_not_the_candidate(self):
        stable_only = _METHOD.replace(
            '        uint64_t srcLen = static_cast<uint64_t>(tSrcLen.GetNumber());',
            '        return JSStableArray::FastCopyFromArrayToTypedArray(thread, targetObj, targetType, targetOffset, length, argObj);')
        self.assertFalse(_has_wrap_shape(stable_only))

    def test_unrelated_sink_or_missing_loop_fails_closed(self):
        self.assertFalse(_has_wrap_shape(_METHOD.replace(
            'BuiltinsArrayBuffer::SetValueInBuffer(thread, targetBuffer.GetTaggedValue(),\n'
            '                                                  targetByteIndex, targetType, kNumberHandle, true)',
            'UnrelatedStore(targetBuffer, targetByteIndex, targetType, kNumberHandle, true)')))
        self.assertFalse(_has_wrap_shape(_METHOD.replace('while (targetByteIndex < limit)',
                                                        'while (targetByteIndex > limit)')))

    def test_source_derived_wrap_indices_hit_before_nonzero_view(self):
        offset = (1 << 64) - 2048
        wrapped_sum, first, end = _wrapped_index_values(offset, 2049, 4096)
        self.assertEqual(wrapped_sum, 1)
        self.assertEqual((first, end), (2048, 4097))
        self.assertEqual(first < 4096, True)
        self.assertEqual(end <= 6145, True)

    def test_small_in_range_and_one_past_lengths_are_not_wrap_witnesses(self):
        self.assertEqual(_wrapped_index_values(0, 4, 0), (4, 0, 4))
        self.assertTrue(_source_range_check_accepts(0, 4, 4))
        # The ordinary source sum rejects a non-overflowing one-past length.
        self.assertFalse(_source_range_check_accepts(1, 4, 4))
        # The candidate combination wraps and is therefore accepted.
        self.assertTrue(_source_range_check_accepts((1 << 64) - 2048, 2049, 2049))

    def test_wrong_repository_provenance_stays_not_analyzed(self):
        result = analyze_arraylike_set_bounds(
            _empty_context(repository='openharmony/arkcompiler_ets_runtime_copy'),
            c_line_static_model())
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertFalse(result.observations)
        self.assertIn('arraylike_set_bounds_requires_exact_git_profile', result.limitations)

    def test_wrong_commit_provenance_stays_not_analyzed(self):
        result = analyze_arraylike_set_bounds(
            _empty_context(commit='0000000000000000000000000000000000000000'),
            c_line_static_model())
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertFalse(result.observations)
        self.assertIn('arraylike_set_bounds_requires_exact_git_profile', result.limitations)

    def test_mutated_helper_bytes_do_not_match_exact_helper_pin(self):
        row = _DEPENDENCIES[0]
        text = 'void SetValueInBuffer() { /* changed helper */ }\n'
        unit = SourceUnit(row[1], 'cpp', text, sha256(text.encode()).hexdigest(), 'complete')
        ast = {row[1]: {'parse_status': 'complete'}}
        self.assertFalse(_bytes_match(unit, row, ast))

    def test_missing_target_evidence_stays_not_analyzed(self):
        result = analyze_arraylike_set_bounds(_empty_context(), c_line_static_model())
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertFalse(result.observations)
        self.assertIn('arraylike_set_bounds_missing_target', result.limitations)

    def test_incomplete_exact_binding_profile_fails_closed(self):
        model = replace(c_line_static_model(), arraylike_set_bounds_dependencies=())
        result = analyze_arraylike_set_bounds(_empty_context(), model)
        self.assertEqual(result.file_outcome, 'not_analyzed')
        self.assertFalse(result.observations)
        self.assertIn('arraylike_set_bounds_profile_incomplete', result.limitations)


if __name__ == '__main__':
    unittest.main()

import unittest

from src.ohscanner.detectors.ark_runtime.size_overflow import analyze_size_overflow


class TypedArraySizeOverflowTests(unittest.TestCase):
    def test_unsigned_product_to_allocation_and_copy_loop_is_reported(self):
        source = r'''
#include <cstdint>
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
'''
        candidates, limitations = analyze_size_overflow(source)
        self.assertEqual(limitations, ())
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].result_name, 'byteCount')
        self.assertEqual(candidates[0].factor_names, ('stride', 'count'))

    def test_variable_renaming_does_not_change_the_result(self):
        source = r'''
void convert(uint32_t width, uint32_t items) {
    uint32_t needed = width * items;
    auto staging = AllocateArrayBuffer(needed);
    BufferHandle output;
    output.Update(staging);
    for (uint32_t remaining = items; remaining > 0; --remaining) {
        SetValueInBuffer(thread, output.GetTaggedValue(), offset, value);
        offset += width;
    }
}
'''
        candidates, _ = analyze_size_overflow(source)
        self.assertEqual(len(candidates), 1)

    def test_cast_before_multiplication_preserves_full_operand_product(self):
        source = r'''
void convert(uint32_t stride, uint32_t count) {
    uint64_t byteCount = stride * static_cast<uint64_t>(count);
    auto temporary = AllocateArrayBuffer(byteCount);
    BufferHandle destination;
    destination.Update(temporary);
    for (uint32_t i = count; i > 0; --i) {
        SetValueInBuffer(thread, destination.GetTaggedValue(), cursor, value);
        cursor += stride;
    }
}
'''
        candidates, _ = analyze_size_overflow(source)
        self.assertEqual(candidates, ())

    def test_widening_only_the_destination_does_not_hide_narrow_multiply(self):
        source = r'''
void convert(uint32_t stride, uint32_t count) {
    uint64_t byteCount = stride * count;
    auto temporary = AllocateArrayBuffer(byteCount);
    BufferHandle destination;
    destination.Update(temporary);
    for (uint32_t i = count; i > 0; --i) {
        SetValueInBuffer(thread, destination.GetTaggedValue(), cursor, value);
        cursor += stride;
    }
}
'''
        candidates, _ = analyze_size_overflow(source)
        self.assertEqual(len(candidates), 1)

    def test_unrelated_product_without_allocation_copy_flow_is_ignored(self):
        source = r'''
void calculate(uint32_t x, uint32_t y) {
    uint32_t product = x * y;
    print(product);
}
'''
        candidates, _ = analyze_size_overflow(source)
        self.assertEqual(candidates, ())

    def test_sendable_allocator_with_pre_multiply_widening_is_safe(self):
        source = r'''
void convert(uint32_t stride, uint32_t count) {
    uint64_t byteCount = static_cast<uint64_t>(stride) * count;
    auto temporary = AllocateSendableArrayBuffer(byteCount);
    BufferHandle destination;
    destination.Update(temporary);
    for (uint32_t i = count; i > 0; --i) {
        SetValueInBuffer(thread, destination.GetTaggedValue(), cursor, value);
        cursor += stride;
    }
}
'''
        candidates, _ = analyze_size_overflow(source)
        self.assertEqual(candidates, ())

if __name__ == '__main__':
    unittest.main()

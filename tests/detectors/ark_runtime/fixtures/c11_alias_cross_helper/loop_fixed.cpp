void convert(uint32_t stride, uint32_t count) {
    uint64_t byteCount = static_cast<uint64_t>(stride) * count;
    auto temporary = AllocateArrayBuffer(byteCount);
    BufferHandle destination;
    destination.Update(temporary);
    for (uint32_t remaining = count; remaining > 0; --remaining) {
        SetValueInBuffer(thread, destination.GetTaggedValue(), cursor, value);
        cursor += stride;
    }
}

void convert(uint32_t stride, uint32_t count) {
    uint32_t byteCount = stride * count;
    print(byteCount);
    BufferHandle destination;

    for (uint32_t remaining = count; remaining > 0; --remaining) {
        SetValueInBuffer(thread, destination.GetTaggedValue(), cursor, value);
        cursor += stride;
    }
}

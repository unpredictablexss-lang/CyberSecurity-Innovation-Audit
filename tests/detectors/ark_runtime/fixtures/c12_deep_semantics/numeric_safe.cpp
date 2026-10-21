void Copy() {
    uint16_t count = 0;
    uint32_t byteCount = count * count;
    auto temporary = AllocateArrayBuffer(byteCount);
    BufferHandle destination;
    destination.Update(temporary);
    for (uint16_t i = count; i > 0; --i) {
        SetValueInBuffer(thread, destination.GetTaggedValue(), cursor, value);
        cursor += 1;
    }
}

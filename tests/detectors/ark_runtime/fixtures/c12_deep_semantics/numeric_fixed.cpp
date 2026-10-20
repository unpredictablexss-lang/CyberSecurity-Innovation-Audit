void Copy(uint16_t length, uint16_t count) {
    uint32_t byteCount = length * count;
    auto temporary = AllocateArrayBuffer(byteCount);
    BufferHandle destination;
    destination.Update(temporary);
    for (uint16_t i = count; i > 0; --i) {
        SetValueInBuffer(thread, destination.GetTaggedValue(), cursor, value);
        cursor += 1;
    }
}

void Copy(int32_t signedLength, uint16_t count) {
    uint32_t byteCount = OpaqueConvert(signedLength) * count;
    auto temporary = AllocateArrayBuffer(byteCount);
    BufferHandle destination;
    destination.Update(temporary);
    for (uint16_t i = count; i > 0; --i) {
        SetValueInBuffer(thread, destination.GetTaggedValue(), cursor, value);
        cursor += 1;
    }
}

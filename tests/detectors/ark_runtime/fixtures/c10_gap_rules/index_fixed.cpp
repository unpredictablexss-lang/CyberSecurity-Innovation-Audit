JSTaggedValue DataViewGet(JSThread *thread, JSTaggedValue requestIndex) {
    JSTaggedNumber numberIndex = JSTaggedValue::ToIndex(thread, requestIndex);
    uint64_t index = base::NumberHelper::DoubleToUInt64(numberIndex.GetNumber());
    uint64_t elementSize = 4;
    if (index + elementSize > size) {
        THROW_RANGE_ERROR_AND_RETURN(thread, "bounds", JSTaggedValue::Exception());
    }
    uint32_t bufferIndex = static_cast<uint32_t>(index + offset);
    return GetValueFromBuffer(thread, buffer, bufferIndex, type, littleEndian);
}

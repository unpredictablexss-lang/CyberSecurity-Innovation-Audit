JSTaggedValue DataViewGet(JSThread *thread, JSTaggedValue requestIndex) {
    JSTaggedNumber numberIndex = JSTaggedValue::ToIndex(thread, requestIndex);
    int32_t indexInt = base::NumberHelper::DoubleInRangeInt32(numberIndex.GetNumber());
    uint32_t index = static_cast<uint32_t>(indexInt);
    uint32_t elementSize = 4;
    if (static_cast<uint32_t>(index) + elementSize > size) {
        THROW_RANGE_ERROR_AND_RETURN(thread, "bounds", JSTaggedValue::Exception());
    }
    return GetValueFromBuffer(thread, buffer, index, type, littleEndian);
}

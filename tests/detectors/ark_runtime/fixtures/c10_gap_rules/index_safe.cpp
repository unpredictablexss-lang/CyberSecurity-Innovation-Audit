JSTaggedValue DataViewGetSafe(JSThread *thread, JSTaggedValue requestIndex) {
    JSTaggedNumber numberIndex = JSTaggedValue::ToIndex(thread, requestIndex);
    uint64_t index = base::NumberHelper::DoubleToUInt64(numberIndex.GetNumber());
    uint64_t elementSize = 4;
    if (index > size || elementSize > size - index) {
        THROW_RANGE_ERROR_AND_RETURN(thread, "bounds", JSTaggedValue::Exception());
    }
    return GetValueFromBuffer(thread, buffer, static_cast<uint32_t>(index + offset), type, littleEndian);
}

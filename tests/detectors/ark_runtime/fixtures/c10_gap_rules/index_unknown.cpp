JSTaggedValue DataViewUnknown(JSThread *thread, JSTaggedValue requestIndex) {
    JSTaggedNumber numberIndex = JSTaggedValue::ToIndex(thread, requestIndex);
    uint64_t index = UnknownIndexConversion(numberIndex.GetNumber());
    if (CheckIndexBounds(index, size, elementSize)) {
        return GetValueFromBuffer(thread, buffer, index, type, littleEndian);
    }
    return JSTaggedValue::Undefined();
}

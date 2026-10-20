void *BuildTypedArray(int64_t length) {
    if (length > MAX_ARRAY_LENGTH) {
        ThrowRangeError();
    }
    uint32_t allocationLength = static_cast<uint32_t>(length);
    return AllocateArrayBuffer(allocationLength);
}

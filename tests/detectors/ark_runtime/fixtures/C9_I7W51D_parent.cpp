void *BuildTypedArray(int64_t length) {
    int32_t allocationLength = static_cast<int32_t>(length);
    return AllocateArrayBuffer(allocationLength);
}

template<typename T> bool ReadBasicValue(const std::vector<uint8_t> &buffer,
    T &value, const TLVHead &head) {
    if (head.len == 0) return false;
    if (!HasExpectBuffer(buffer, head.len)) return false;
    auto ret = memcpy_s(&value, sizeof(T), buffer.data() + cursor_, head.len);
    return ret == EOK;
}

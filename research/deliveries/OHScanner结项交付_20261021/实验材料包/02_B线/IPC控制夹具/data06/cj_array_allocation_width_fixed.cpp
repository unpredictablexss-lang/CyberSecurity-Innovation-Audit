class MessageSequenceImpl {
    NativeParcel *nativeParcel_;
public:
    void CJ_ReadRemoteObjectArray();
};
void MessageSequenceImpl::CJ_ReadRemoteObjectArray() {
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) { return; }
    if (CheckReadLength(static_cast<size_t>(arrayLength), BYTE_SIZE_32)) { return; }
    int32_t *type = static_cast<int32_t *>(malloc(sizeof(int32_t) * arrayLength));
    int64_t *id = static_cast<int64_t *>(malloc(sizeof(int64_t) * arrayLength));
    for (uint32_t i = 0; i < (uint32_t)arrayLength; i++) {
        type[i] = ReadType();
        id[i] = ReadId();
    }
}

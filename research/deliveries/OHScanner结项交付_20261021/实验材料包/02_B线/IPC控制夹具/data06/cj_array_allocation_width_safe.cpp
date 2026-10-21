class MessageSequenceImpl {
    NativeParcel *nativeParcel_;
public:
    void CJ_ReadRemoteObjectArray();
};
void MessageSequenceImpl::CJ_ReadRemoteObjectArray() {
    int32_t arrayLength = nativeParcel_->ReadInt32();
    if (arrayLength <= 0) { return; }
    if (CheckReadLength(static_cast<size_t>(arrayLength), BYTE_SIZE_32)) { return; }
    if (!IsSupportedArrayLength(arrayLength)) { return; }
    return;
}

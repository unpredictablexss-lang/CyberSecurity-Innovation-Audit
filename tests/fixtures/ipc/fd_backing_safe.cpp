#include <cstddef>
class MessageParcel {};
class MessageParcelWarp { public: const void *ReadRawData(MessageParcel &, size_t); };
int Stub::OnGetRecordValueByType(MessageParcel &data, int64_t rawDataSize) {
    MessageParcelWarp messageData;
    return messageData.ReadRawData(data, static_cast<size_t>(rawDataSize)) != nullptr;
}
const void *MessageParcelWarp::ReadRawData(MessageParcel &parcelPata, size_t size) {
    if (size <= MIN_RAW_SIZE) return parcelPata.ReadUnpadBuffer(size);
    int fd = parcelPata.ReadFileDescriptor();
    auto actualSize = AshmemGetSize(fd);
    if (actualSize < 0 || static_cast<int64_t>(size) > actualSize) { return nullptr; }
    return ::mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
}

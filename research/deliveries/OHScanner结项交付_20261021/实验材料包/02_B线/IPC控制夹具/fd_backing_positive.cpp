#include <cstddef>
class MessageParcel {};
class MessageParcelWarp { public: const void *ReadRawData(MessageParcel &, size_t); };
int Stub::OnGetRecordValueByType(MessageParcel &data, int64_t rawDataSize) {
    MessageParcelWarp messageData;
    return messageData.ReadRawData(data, static_cast<size_t>(rawDataSize)) != nullptr;
}
const void *MessageParcelWarp::ReadRawData(MessageParcel &parcelPata, size_t size) {
    int fd = parcelPata.ReadFileDescriptor();
    return ::mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
}

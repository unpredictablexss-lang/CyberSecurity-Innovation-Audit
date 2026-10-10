#include <cstdint>
#include <cstring>

struct Parcel {
    uint32_t ReadUint32();
    const uint8_t* ReadBuffer() const;
};

int vulnerable_unbounded_length(Parcel& parcel, uint8_t* dst, size_t capacity) {
    uint32_t length = parcel.ReadUint32();
    std::memcpy(dst, parcel.ReadBuffer(), length);
    return 0;
}

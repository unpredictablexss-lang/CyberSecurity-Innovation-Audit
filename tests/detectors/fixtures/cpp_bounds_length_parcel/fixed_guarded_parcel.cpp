#include <cstdint>
#include <cstring>

struct Parcel {
    uint32_t ReadUint32();
    const uint8_t* ReadBuffer() const;
};

int fixed_guarded_length(Parcel& parcel, uint8_t* dst, size_t capacity) {
    uint32_t length = parcel.ReadUint32();
    if (length > capacity) {
        return -1;
    }
    std::memcpy(dst, parcel.ReadBuffer(), length);
    return 0;
}

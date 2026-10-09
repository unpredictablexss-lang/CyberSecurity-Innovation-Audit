#include <cstdint>
#include <cstring>

struct Parcel {
    uint32_t ReadUint32();
    const uint8_t* ReadBuffer() const;
};

int partial_macro_guard(Parcel& parcel, uint8_t* dst, size_t capacity) {
    uint32_t length = parcel.ReadUint32();
#ifdef OH_LENGTH_GUARD_PRESENT
    if (length > capacity) {
        return -1;
    }
#endif
    std::memcpy(dst, parcel.ReadBuffer(), length);
    return 0;
}

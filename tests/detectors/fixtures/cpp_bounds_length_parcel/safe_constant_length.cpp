#include <cstdint>
#include <cstring>

int safe_constant_length(uint8_t* dst, size_t capacity) {
    uint32_t length = 4;
    if (length > capacity) {
        return -1;
    }
    std::memcpy(dst, nullptr, length);
    return 0;
}

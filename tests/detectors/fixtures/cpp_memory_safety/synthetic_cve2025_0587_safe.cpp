// SYNTHETIC SAFE CONTROL for the integer narrowing root cause in CVE-2025-0587.
// The original wide value is range-checked before conversion; offset arithmetic
// uses a wider unsigned type and is checked before the final narrowing.
#include <cstdint>

uint32_t safe_typed_array_offset(double request_index,
                                 uint32_t length,
                                 uint32_t element_size,
                                 uint32_t byte_offset) {
    if (request_index < 0.0 || request_index >= static_cast<double>(length)) {
        return 0;
    }
    const uint64_t index = static_cast<uint64_t>(request_index);
    const uint64_t result = index * static_cast<uint64_t>(element_size) + byte_offset;
    if (result > UINT32_MAX) {
        return 0;
    }
    return static_cast<uint32_t>(result);
}

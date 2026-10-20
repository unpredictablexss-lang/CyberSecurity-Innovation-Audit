// SYNTHETIC UNRELATED CONTROL for the mutable-array sort root cause in CVE-2025-23420.
// Direct ElementAccessor operations occur in a copy routine, not a sorting routine.
#include <cstdint>

namespace ElementAccessor {
int Get(int* values, uint32_t index) { return values[index]; }
void Set(int* values, uint32_t index, int value) { values[index] = value; }
}

void CopyElementsByObject(int* source, int* destination, uint32_t length) {
    for (uint32_t index = 0; index < length; ++index) {
        const int value = ElementAccessor::Get(source, index);
        ElementAccessor::Set(destination, index, value);
    }
}

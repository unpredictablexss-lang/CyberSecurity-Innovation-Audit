// SYNTHETIC SAFE CONTROL for the mutable-array sort root cause in CVE-2025-23420.
// Every element read/write goes through helpers that re-check stability and length.
#include <cstdint>

struct StableArray {
    int values[16];
    uint32_t length;
    bool stable;
};

int CheckStableArrayAndGet(StableArray& array, uint32_t index) {
    if (!array.stable || index >= array.length || index >= 16) {
        return 0;
    }
    return array.values[index];
}

void CheckStableArrayAndSet(StableArray& array, uint32_t index, int value) {
    if (!array.stable || index >= array.length || index >= 16) {
        return;
    }
    array.values[index] = value;
}

void SortElementsByObject(StableArray& array) {
    for (uint32_t index = 1; index < array.length; ++index) {
        const int value = CheckStableArrayAndGet(array, index);
        if (value > 0) {
            CheckStableArrayAndSet(array, index, value);
        }
    }
}

#include <cstdint>
#include <iostream>
int main(int argc, char **argv) {
    volatile double request = argc > 1 ? std::strtod(argv[1], nullptr) : 4294967295.0;
    uint64_t length = 1;
    uint64_t index = static_cast<uint64_t>(request);
    if (index >= length) {
        std::cout << "rejected overflowing index\n";
        return 0;
    }
    char buffer[4] = {};
    volatile uint32_t offset = static_cast<uint32_t>(index) * 4U;
    buffer[offset] = 1;
    std::cout << "fixed index path completed\n";
    return 0;
}

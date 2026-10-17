#include <cstdint>
#include <iostream>
int main(int argc, char **argv) {
    volatile double request = argc > 1 ? std::strtod(argv[1], nullptr) : 4294967295.0;
    uint32_t length = 1;
    int32_t index = static_cast<int32_t>(request);
    if (index >= static_cast<int32_t>(length)) {
        std::cout << "rejected\n";
        return 0;
    }
    char buffer[4] = {};
    volatile uint32_t offset = static_cast<uint32_t>(index) * 4U;
    buffer[offset] = 1;
    std::cout << "unexpected completion\n";
    return 0;
}

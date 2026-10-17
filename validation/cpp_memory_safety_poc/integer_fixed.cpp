#include <cstdint>
#include <cstdlib>
#include <iostream>
int main(int argc, char **argv) {
    volatile uint32_t input = argc > 1 ? static_cast<uint32_t>(std::strtoul(argv[1], nullptr, 0)) : UINT32_MAX;
    if (input == UINT32_MAX) {
        std::cout << "rejected overflowing addition\n";
        return 0;
    }
    uint32_t bytes = input + 1;
    char *buffer = static_cast<char *>(std::malloc(bytes));
    if (buffer == nullptr) {
        return 2;
    }
    buffer[0] = 1;
    std::cout << "allocated=" << bytes << "\n";
    std::free(buffer);
    return 0;
}

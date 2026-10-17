#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <iostream>
int main(int argc, char **argv) {
    volatile uint32_t input = argc > 1 ? static_cast<uint32_t>(std::strtoul(argv[1], nullptr, 0)) : UINT32_MAX;
    uint32_t bytes = input + 1;
    char *buffer = new char[bytes];
    if (buffer == nullptr) {
        return 2;
    }
    std::memset(buffer, 0, 256);
    std::cout << "allocated=" << bytes << "\n";
    delete[] buffer;
    return 0;
}


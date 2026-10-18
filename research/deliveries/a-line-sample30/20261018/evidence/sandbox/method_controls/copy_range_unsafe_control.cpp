// Deliberately unsafe sanitizer positive control. Not derived as a vulnerability claim.
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
constexpr int32_t MAX_LEN = 1024;
int main(int argc, char **argv) {
    int32_t cfgLen = argc > 1 ? std::strtoll(argv[1], nullptr, 10) : 2048;
    if (cfgLen <= 0) return 2;
    std::vector<char> source(static_cast<size_t>(cfgLen), 0x42);
    char *dest = new char[MAX_LEN];
    for (size_t i = 0; i < static_cast<size_t>(cfgLen); ++i) dest[i] = source[i];
    delete[] dest;
    std::cout << "unsafe_control_copy_len=" << cfgLen << "\n";
    return 0;
}

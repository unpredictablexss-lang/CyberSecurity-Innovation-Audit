// Safe control with matched source and destination capacities.
#include <cstddef>
#include <iostream>
int main() {
    constexpr size_t n = 1024;
    char source[n];
    char dest[n];
    for (size_t i = 0; i < n; ++i) source[i] = static_cast<char>(i);
    if (sizeof(dest) < sizeof(source)) return 2;
    for (size_t i = 0; i < n; ++i) dest[i] = source[i];
    std::cout << "safe_control_bytes=" << sizeof(dest) << "\n";
    return 0;
}

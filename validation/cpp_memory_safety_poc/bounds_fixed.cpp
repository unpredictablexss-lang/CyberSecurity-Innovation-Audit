#include <cstring>
#include <iostream>
int main() {
    char source[16] = {};
    char destination[8] = {};
    const size_t length = sizeof(source);
    if (length > sizeof(destination)) {
        std::cout << "rejected oversized copy\n";
        return 0;
    }
    std::memcpy(destination, source, length);
    std::cout << "safe copy completed\n";
    return 0;
}

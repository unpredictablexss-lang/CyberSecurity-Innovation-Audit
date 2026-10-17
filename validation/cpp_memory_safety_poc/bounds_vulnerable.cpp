#include <cstring>
#include <iostream>
int main() {
    char source[16] = {};
    char destination[8] = {};
    std::memcpy(destination, source, sizeof(source));
    std::cout << "unexpected completion\n";
    return 0;
}

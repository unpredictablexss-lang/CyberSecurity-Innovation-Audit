#include <cstdlib>
#include <iostream>
int main() {
    char *p = static_cast<char *>(std::malloc(16));
    if (p == nullptr) {
        return 2;
    }
    std::free(p);
    std::free(p);
    std::cout << "unexpected completion\n";
    return 0;
}

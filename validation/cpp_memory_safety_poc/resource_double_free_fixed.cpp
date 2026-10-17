#include <cstdlib>
#include <iostream>
int main() {
    char *p = static_cast<char *>(std::malloc(16));
    if (p == nullptr) {
        return 2;
    }
    std::free(p);
    p = nullptr;
    if (p != nullptr) {
        std::free(p);
    }
    std::cout << "fixed resource path completed\n";
    return 0;
}

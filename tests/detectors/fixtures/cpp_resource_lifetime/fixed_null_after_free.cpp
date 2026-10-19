#include <cstdlib>
void fixed_null_after_free() {
    char *p = (char *)malloc(8);
    free(p);
    p = nullptr;
    if (p != nullptr) {
        p[0] = 1;
    }
}

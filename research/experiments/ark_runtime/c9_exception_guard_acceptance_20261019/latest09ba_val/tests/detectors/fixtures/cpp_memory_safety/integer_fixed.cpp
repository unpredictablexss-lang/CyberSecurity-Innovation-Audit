#include <cstdlib>
void integer_fixed(size_t count, size_t size) {
    if (count > SIZE_MAX / size) return;
    size_t bytes = count * size;
    void *dst = malloc(bytes);
}

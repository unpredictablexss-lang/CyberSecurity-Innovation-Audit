#include <cstdlib>
void integer_safe(size_t count, size_t size) {
    size_t bytes = 0;
    if (__builtin_mul_overflow(count, size, &bytes)) return;
    void *dst = malloc(bytes);
}

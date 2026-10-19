#include <cstdlib>
#include <cstring>
void integer_positive(char *src, size_t count, size_t size) {
    size_t bytes = count * size;
    void *dst = malloc(bytes);
    memcpy(dst, src, bytes);
    uint8_t total = 255 + 1;
}

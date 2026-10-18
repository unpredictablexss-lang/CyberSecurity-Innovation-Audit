#include <cstdlib>
#include <cstring>

void safe_malloc(char *src, size_t n)
{
    char *dst = (char *)malloc(n);
    memcpy(dst, src, n);
}

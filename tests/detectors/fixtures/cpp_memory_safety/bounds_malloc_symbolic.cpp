#include <cstdlib>
#include <cstring>

void symbolic_malloc(char *src, size_t n, size_t m)
{
    char *dst = (char *)malloc(n);
    memcpy(dst, src, m);
}

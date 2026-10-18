#include <cstdlib>
#include <cstring>

void symbolic_plus_one_unsafe(size_t n, const char *src)
{
    char *dst = (char *)malloc(n);
    memcpy(dst, src, n + 1);
}

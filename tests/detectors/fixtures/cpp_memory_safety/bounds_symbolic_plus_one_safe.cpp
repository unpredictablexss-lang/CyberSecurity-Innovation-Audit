#include <cstdlib>
#include <cstring>

void symbolic_plus_one_safe(size_t n, const char *src)
{
    char *dst = (char *)malloc(n + 1);
    memcpy(dst, src, n);
}

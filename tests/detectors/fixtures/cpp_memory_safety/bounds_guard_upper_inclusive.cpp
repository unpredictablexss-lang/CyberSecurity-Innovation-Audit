#include <cstring>

void guard_upper_inclusive(unsigned int n, const char *src)
{
    if (n >= 4) return;
    char dst[4];
    memcpy(dst, src, n);
}

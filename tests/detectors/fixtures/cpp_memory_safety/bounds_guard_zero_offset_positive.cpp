#include <cstring>

void zero_offset(unsigned int n, const char *src)
{
    if (n != 0) return;
    char dst[4];
    memcpy(dst, src, n);
    dst[n - 1] = src[0];
}

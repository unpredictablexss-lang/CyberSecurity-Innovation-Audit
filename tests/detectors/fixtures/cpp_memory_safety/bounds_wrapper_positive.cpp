#include <cstring>

void CopyInto(char *dst, const char *src, size_t n)
{
    memcpy(dst, src, n);
}

void wrapper_positive(const char *src)
{
    char dst[4];
    CopyInto(dst, src, 8);
}

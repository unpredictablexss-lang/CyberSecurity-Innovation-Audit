#include <cstring>

void CopyInto(char *dst, const char *src, size_t n)
{
    memcpy(dst, src, n);
}

void wrapper_safe(const char *src)
{
    char dst[8];
    CopyInto(dst, src, sizeof(dst));
}

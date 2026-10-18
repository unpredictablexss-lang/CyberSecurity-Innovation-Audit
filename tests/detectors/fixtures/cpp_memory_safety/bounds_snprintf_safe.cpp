#include <cstdio>

void snprintf_safe(const char *src)
{
    char dst[8];
    snprintf(dst, sizeof(dst), "%s", src);
}

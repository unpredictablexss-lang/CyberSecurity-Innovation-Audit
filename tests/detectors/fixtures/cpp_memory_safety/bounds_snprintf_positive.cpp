#include <cstdio>

void snprintf_positive(const char *src)
{
    char dst[4];
    snprintf(dst, 8, "%s", src);
}

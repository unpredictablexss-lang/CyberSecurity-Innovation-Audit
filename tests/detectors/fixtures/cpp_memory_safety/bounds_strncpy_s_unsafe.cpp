#include <cstring>

void strncpy_s_unsafe(const char *src)
{
    char dst[4];
    strncpy_s(dst, 8, src, 8);
}

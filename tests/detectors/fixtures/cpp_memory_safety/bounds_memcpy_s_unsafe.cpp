#include <cstring>

void memcpy_s_unsafe(const char *src)
{
    char dst[4];
    memcpy_s(dst, 8, src, 8);
}

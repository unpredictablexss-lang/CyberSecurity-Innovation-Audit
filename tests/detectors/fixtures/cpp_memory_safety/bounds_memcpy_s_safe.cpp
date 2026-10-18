#include <cstring>

void memcpy_s_safe(const char *src)
{
    char dst[8];
    memcpy_s(dst, sizeof(dst), src, 8);
}

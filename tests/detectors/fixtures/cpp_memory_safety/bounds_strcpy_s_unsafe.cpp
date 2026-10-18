#include <cstring>

void strcpy_s_unsafe(const char *src)
{
    char dst[4];
    strcpy_s(dst, 8, src);
}

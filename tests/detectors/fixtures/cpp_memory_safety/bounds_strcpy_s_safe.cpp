#include <cstring>

void strcpy_s_safe(const char *src)
{
    char dst[8];
    strcpy_s(dst, sizeof(dst), src);
}

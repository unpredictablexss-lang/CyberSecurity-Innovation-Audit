#include <cstring>

void guard_nullptr_exit(const char *src)
{
    if (src == nullptr) return;
    char dst[4];
    memcpy(dst, src, 4);
}

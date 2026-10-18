#include <cstring>

int Prepare();

void guard_zero_exit(const char *src)
{
    int ret = Prepare();
    if (ret != 0) return;
    char dst[4];
    memcpy(dst, src, 4);
}

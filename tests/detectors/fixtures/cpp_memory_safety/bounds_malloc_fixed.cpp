#include <cstdlib>
#include <cstring>

void fixed_malloc(char *src)
{
    char *dst = (char *)malloc(8);
    memcpy(dst, src, 8);
}

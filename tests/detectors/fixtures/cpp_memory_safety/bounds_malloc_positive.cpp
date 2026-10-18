#include <cstdlib>
#include <cstring>

void positive_malloc(char *src)
{
    char *dst = (char *)malloc(4);
    memcpy(dst, src, 8);
}

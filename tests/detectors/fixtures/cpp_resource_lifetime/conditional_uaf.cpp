#include <cstdlib>

void conditional_uaf(bool cond)
{
    char *p = (char *)malloc(4);
    if (cond) {
        free(p);
    }
    p[0] = 1;
}

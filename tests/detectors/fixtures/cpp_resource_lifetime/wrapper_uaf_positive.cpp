#include <cstdlib>

void ReleaseBuffer(void *p)
{
    free(p);
}

void wrapper_uaf()
{
    char *p = (char *)malloc(4);
    ReleaseBuffer(p);
    p[0] = 1;
}

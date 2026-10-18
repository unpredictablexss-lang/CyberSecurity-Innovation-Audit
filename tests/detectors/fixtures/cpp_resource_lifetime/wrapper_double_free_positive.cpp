#include <cstdlib>

void ReleaseBuffer(void *p)
{
    free(p);
}

void wrapper_double_free()
{
    void *p = malloc(4);
    ReleaseBuffer(p);
    ReleaseBuffer(p);
}

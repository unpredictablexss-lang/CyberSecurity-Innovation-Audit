#include <cstdlib>

void ReleaseBuffer(void *p)
{
    free(p);
}

void wrapper_safe_null()
{
    void *p = malloc(4);
    ReleaseBuffer(p);
    p = nullptr;
    free(p);
}

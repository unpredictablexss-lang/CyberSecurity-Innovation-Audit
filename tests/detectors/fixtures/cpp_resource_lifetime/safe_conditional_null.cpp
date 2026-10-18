#include <cstdlib>

void safe_conditional_null(bool cond)
{
    void *p = malloc(4);
    if (cond) {
        free(p);
        p = nullptr;
    }
    free(p);
}

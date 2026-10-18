#include <cstdlib>

void conditional_double_free(bool cond)
{
    void *p = malloc(4);
    if (cond) {
        free(p);
    }
    free(p);
}

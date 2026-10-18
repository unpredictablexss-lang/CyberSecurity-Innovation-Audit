#include <cstdlib>

void safe_conditional_early_return(bool cond)
{
    void *p = malloc(4);
    if (cond) {
        free(p);
        return;
    }
    free(p);
}

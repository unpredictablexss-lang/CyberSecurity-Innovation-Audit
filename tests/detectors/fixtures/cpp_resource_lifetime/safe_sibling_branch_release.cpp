#include <stdlib.h>

void sibling_branches(int mode)
{
    void *buffer = malloc(4);
    if (mode == 1) {
        free(buffer);
    } else if (mode == 2) {
        *static_cast<int *>(buffer) = 1;
    }
}

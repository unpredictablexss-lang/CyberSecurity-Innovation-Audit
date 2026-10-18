#include <stdlib.h>

void conditional_free_return(void)
{
    void *buffer = malloc(4);
    if (buffer != NULL) {
        free(buffer);
    }
    return;
L_ERR:
    if (buffer != NULL) {
        free(buffer);
    }
}

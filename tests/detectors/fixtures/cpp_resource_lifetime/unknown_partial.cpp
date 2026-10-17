#include <cstdlib>
void unknown_partial() {
    char *p = (char *)malloc(8);
    free(p);

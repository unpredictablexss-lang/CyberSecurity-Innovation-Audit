#include <cstdlib>
void fixed_reallocate() {
    char *p = (char *)malloc(8);
    free(p);
    p = (char *)malloc(16);
    p[0] = 1;
    free(p);
}

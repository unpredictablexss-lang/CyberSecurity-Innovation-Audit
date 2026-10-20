#include <cstdlib>
void unrelated_release(char *other) {
    char *p = (char *)malloc(8);
    free(other);
    p[0] = 1;
    free(p);
}

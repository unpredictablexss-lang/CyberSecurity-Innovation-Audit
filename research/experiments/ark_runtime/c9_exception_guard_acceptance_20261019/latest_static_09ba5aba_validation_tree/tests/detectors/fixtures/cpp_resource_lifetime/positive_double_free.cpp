#include <cstdlib>
void positive_double_free() {
    char *p = (char *)malloc(8);
    free(p);
    free(p);
}

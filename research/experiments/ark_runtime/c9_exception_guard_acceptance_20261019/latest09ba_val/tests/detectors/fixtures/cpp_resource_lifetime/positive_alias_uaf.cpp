#include <cstdlib>
void positive_alias_uaf() {
    char *p = (char *)malloc(8);
    char *alias = p;
    free(p);
    alias[0] = 1;
}

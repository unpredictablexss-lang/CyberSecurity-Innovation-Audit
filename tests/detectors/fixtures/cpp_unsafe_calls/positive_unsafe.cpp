#include <cstdio>
#include <cstring>
void positive(char *dst, char *src, char *fmt) {
    gets(dst);
    strcpy(dst, src);
    sprintf(dst, "%s", src);
    printf(fmt);
    scanf("%s", dst);
}

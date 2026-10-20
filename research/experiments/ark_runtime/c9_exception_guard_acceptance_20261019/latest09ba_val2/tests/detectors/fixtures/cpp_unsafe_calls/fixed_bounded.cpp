#include <cstdio>
#include <cstring>
void fixed(char *dst, unsigned long dstSize, char *src, char *fmt) {
    strcpy_s(dst, dstSize, src);
    snprintf(dst, dstSize, "%s", src);
    printf("%s", fmt);
    scanf("%15s", dst);
}
